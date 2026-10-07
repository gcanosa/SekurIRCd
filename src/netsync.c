#include "netsync.h"

#include "accounts.h"
#include "channel.h"
#include "client.h"
#include "cmd.h"
#include "config.h"
#include "link.h"
#include "log.h"
#include "proto.h"
#include "server.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* --- identity ---------------------------------------------------------------------------------------------- */

static const char B36[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void netsync_default_sid(const char *name, char *out) {
    unsigned long h = 5381;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) h = h * 33 + *p;
    out[0] = (char)('0' + h % 10);
    out[1] = B36[(h / 10) % 36];
    out[2] = B36[(h / 360) % 36];
    out[3] = '\0';
}

netserver_t *netsync_find_sid(server_t *srv, const char *sid) {
    netserver_t *s;
    HASH_FIND_STR(srv->servers, sid, s);
    return s;
}

netserver_t *netsync_find_name(server_t *srv, const char *name) {
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp) if (strcasecmp(s->name, name) == 0) return s;
    return NULL;
}

int netsync_is_behind(const netserver_t *s, const netserver_t *ancestor) {
    for (; s; s = s->uplink) if (s == ancestor) return 1;
    return 0;
}

void netsync_init(server_t *srv) {
    if (srv->self_srv) return;
    netserver_t *me = calloc(1, sizeof *me);
    if (!me) return;
    snprintf(me->name, sizeof me->name, "%s", srv->cfg.server.name);
    if (srv->cfg.server.sid[0]) snprintf(me->sid, sizeof me->sid, "%s", srv->cfg.server.sid);
    else netsync_default_sid(me->name, me->sid);
    snprintf(me->desc, sizeof me->desc, "%s", srv->cfg.server.network);
    HASH_ADD_STR(srv->servers, sid, me);
    srv->self_srv = me;
}

void netsync_free(server_t *srv) {
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp) { HASH_DEL(srv->servers, s); free(s); }
    srv->self_srv = NULL;
}

void netsync_assign_uid(server_t *srv, client_t *cl) {
    if (cl->uid[0] || !srv->self_srv) return;
    unsigned long n = ++srv->uid_counter;
    char tail[7] = "000000";
    for (int i = 5; i >= 0; i--) { tail[i] = B36[n % 36]; n /= 36; }
    snprintf(cl->uid, sizeof cl->uid, "%s%s", srv->self_srv->sid, tail);
    cl->nserver = srv->self_srv;
    srv->self_srv->n_users++;
    HASH_ADD(hh_uid, srv->by_uid, uid, strlen(cl->uid), cl);
}

client_t *netsync_find_uid(server_t *srv, const char *uid) {
    client_t *cl;
    HASH_FIND(hh_uid, srv->by_uid, uid, strlen(uid), cl);
    return cl;
}

const char *netsync_server_name_of(server_t *srv, const client_t *cl) {
    return (cl->nserver && cl->remote) ? cl->nserver->name : srv->cfg.server.name;
}

int netsync_has_links(const server_t *srv) {
    for (const link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc->authenticated && lc->is_server && !lc->closing) return 1;
    return 0;
}

/* --- low-level send helpers ---------------------------------------------------------------------------------- */

static void send_link(link_conn_t *lc, const char *line) {
    if (lc && lc->authenticated && lc->is_server && !lc->closing) link_forward_line(lc, line);
}

/* To every server link except `except` (the one a message arrived on) -- flooding along the tree. */
static void flood(server_t *srv, const link_conn_t *except, const char *line) {
    for (link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc != except) send_link(lc, line);
}

static void route_to(server_t *srv, const netserver_t *dest, const char *line) {
    (void)srv;
    if (dest && dest->route) send_link(dest->route, line);
}

static const char *self_sid(const server_t *srv) { return srv->self_srv->sid; }

/* "[~&@%+]" prefixes for a member rank, all of them, as used in SJOIN member lists. */
static void rank_prefix_all(int rank, char *out) { channel_rank_prefix(rank, 1, out); }

static int rank_from_prefix(const char **p) {
    int rank = 0;
    for (;; (*p)++) {
        switch (**p) {
            case '~': rank |= RANK_OWNER | RANK_OP; break;
            case '&': rank |= RANK_ADMIN | RANK_OP; break;
            case '@': rank |= RANK_OP; break;
            case '%': rank |= RANK_HALFOP; break;
            case '+': rank |= RANK_VOICE; break;
            default: return rank;
        }
    }
}

static const struct { char letter; unsigned bit; } UMODE_MAP[] = {
    {'i', UMODE_I}, {'w', UMODE_W}, {'d', UMODE_D}, {'s', UMODE_S}, {'o', UMODE_O}, {'Z', UMODE_Z}, {'r', UMODE_R}, {'p', UMODE_P},
    {'I', UMODE_HIDEIDLE}, {'H', UMODE_H}, {'q', UMODE_Q}, {'R', UMODE_REGONLY}, {'D', UMODE_NOPM}, {'B', UMODE_B}, {'g', UMODE_G},
};

/* "+iw" (plus 'S' for a service pseudo-client) <-> bits. */
static void umodes_to_string(const client_t *cl, char *out, size_t outsz) {
    size_t n = 0;
    out[n++] = '+';
    for (size_t i = 0; i < sizeof UMODE_MAP / sizeof UMODE_MAP[0] && n + 2 < outsz; i++)
        if (cl->umodes & UMODE_MAP[i].bit) out[n++] = UMODE_MAP[i].letter;
    if (cl->is_service && n + 2 < outsz) out[n++] = 'S';
    out[n] = '\0';
}

static unsigned umodes_from_string(const char *s, int *service) {
    unsigned bits = 0;
    *service = 0;
    for (; *s; s++) {
        if (*s == 'S') { *service = 1; continue; }
        for (size_t i = 0; i < sizeof UMODE_MAP / sizeof UMODE_MAP[0]; i++)
            if (UMODE_MAP[i].letter == *s) bits |= UMODE_MAP[i].bit;
    }
    return bits;
}

/* --- burst ------------------------------------------------------------------------------------------------- */

static void send_uid_line(server_t *srv, link_conn_t *to, const client_t *u) {
    (void)srv;
    char modes[40], hop[8], ts[24], line[1100];
    umodes_to_string(u, modes, sizeof modes);
    snprintf(hop, sizeof hop, "%d", u->nserver ? u->nserver->hop + 1 : 1);
    snprintf(ts, sizeof ts, "%ld", u->nick_ts);
    const char *p[] = {u->nick, hop, ts, modes, u->user, u->host, u->realhost, u->ip, u->uid,
                       u->account[0] ? u->account : "*", u->ident_confirmed ? "1" : "0"};
    irc_build(line, sizeof line, NULL, 0, u->nserver->sid, "UID", p, 11, u->realname);
    send_link(to, line);
    if (u->is_away) {
        irc_build(line, sizeof line, NULL, 0, u->uid, "AWAY", NULL, 0, u->away);
        send_link(to, line);
    }
}

static int server_hop_cmp(const void *a, const void *b) {
    return (*(netserver_t *const *)a)->hop - (*(netserver_t *const *)b)->hop;
}

/* Everything we know that isn't already on `lc`'s side of the network. */
static void send_burst(server_t *srv, link_conn_t *lc) {
    char line[1200];
    /* 1. servers, parents before children */
    netserver_t *list[256];
    int n = 0;
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp)
        if (s != srv->self_srv && s->route != lc && n < 256) list[n++] = s;
    qsort(list, (size_t)n, sizeof list[0], server_hop_cmp);
    for (int i = 0; i < n; i++) {
        char hop[8];
        snprintf(hop, sizeof hop, "%d", list[i]->hop + 1);
        const char *p[] = {list[i]->name, hop, list[i]->sid};
        irc_build(line, sizeof line, NULL, 0, list[i]->uplink->sid, "SERVER", p, 3, list[i]->desc);
        send_link(lc, line);
    }
    /* 2. users */
    client_t *u, *utmp;
    HASH_ITER(hh, srv->users, u, utmp) {
        if (!u->uid[0] || !u->nserver || u->nserver->route == lc) continue;
        send_uid_line(srv, lc, u);
    }
    /* 3. channels: modes, members, lists, topic */
    channel_t *c, *ctmp;
    HASH_ITER(hh, srv->channels, c, ctmp) {
        int theirs = 0, ours = 0;
        member_t *m, *mt;
        HASH_ITER(hh, c->members, m, mt) { if (m->client->nserver && m->client->nserver->route == lc) theirs++; else ours++; }
        if (!ours) continue; /* every member is already on their side -- they have the channel */
        char ts[24], modestr[360];
        snprintf(ts, sizeof ts, "%ld", (long)c->created);
        channel_modes_string(c, modestr, sizeof modestr);
        char *margs[10];
        int nm = 0;
        char *save = NULL;
        for (char *t = strtok_r(modestr, " ", &save); t && nm < 10; t = strtok_r(NULL, " ", &save)) margs[nm++] = t;
        /* members, in chunks that keep each line well under the link line limit */
        char members[600] = "";
        member_t *mm, *mtmp;
        HASH_ITER(hh, c->members, mm, mtmp) {
            if (!mm->client->uid[0] || (mm->client->nserver && mm->client->nserver->route == lc)) continue;
            char tok[24], pre[8];
            rank_prefix_all(mm->rank, pre);
            snprintf(tok, sizeof tok, "%s%s", pre, mm->client->uid);
            if (strlen(members) + strlen(tok) + 2 >= sizeof members) {
                const char *p[14] = {ts, c->name};
                for (int i = 0; i < nm; i++) p[2 + i] = margs[i];
                irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SJOIN", p, 2 + nm, members);
                send_link(lc, line);
                members[0] = '\0';
            }
            if (members[0]) strncat(members, " ", sizeof members - strlen(members) - 1);
            strncat(members, tok, sizeof members - strlen(members) - 1);
        }
        if (members[0]) {
            const char *p[14] = {ts, c->name};
            for (int i = 0; i < nm; i++) p[2 + i] = margs[i];
            irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SJOIN", p, 2 + nm, members);
            send_link(lc, line);
        }
        masklist_t *lists[3] = {&c->bans, &c->exceptions, &c->invex};
        const char *letters[3] = {"b", "e", "I"};
        for (int li = 0; li < 3; li++) {
            char masks[700] = "";
            for (int i = 0; i < lists[li]->n; i++) {
                const char *mk = lists[li]->masks[i];
                if (strlen(masks) + strlen(mk) + 2 >= sizeof masks) {
                    const char *p[] = {ts, c->name, letters[li]};
                    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "BMASK", p, 3, masks);
                    send_link(lc, line);
                    masks[0] = '\0';
                }
                if (masks[0]) strncat(masks, " ", sizeof masks - strlen(masks) - 1);
                strncat(masks, mk, sizeof masks - strlen(masks) - 1);
            }
            if (masks[0]) {
                const char *p[] = {ts, c->name, letters[li]};
                irc_build(line, sizeof line, NULL, 0, self_sid(srv), "BMASK", p, 3, masks);
                send_link(lc, line);
            }
        }
        if (c->topic[0]) {
            char tts[24];
            snprintf(tts, sizeof tts, "%ld", (long)c->topic_time);
            const char *p[] = {c->name, tts, c->topic_setter[0] ? c->topic_setter : "*"};
            irc_build(line, sizeof line, NULL, 0, self_sid(srv), "TB", p, 3, c->topic);
            send_link(lc, line);
        }
        (void)theirs;
    }
    /* 4. the account database (each server also persists its own copy) */
    if (srv->cfg.accounts.enabled) {
        int na = 0;
        const char **names = accounts_all_names(&srv->accounts, &na);
        for (int i = 0; i < na && names; i++) {
            char *json = accounts_record_json(&srv->accounts, names[i]);
            if (!json) continue;
            long long ts = accounts_updated_at(&srv->accounts, names[i]);
            char tsb[24];
            snprintf(tsb, sizeof tsb, "%lld", ts > 0 ? ts : 1);
            char big[3000];
            irc_build(big, sizeof big, NULL, 0, self_sid(srv), "ACCT", (const char *[]){tsb, names[i]}, 2, json);
            send_link(lc, big);
            free(json);
        }
        free(names);
    }
    /* 5. global lines */
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        if (k->line_type[0] != 'G') continue;
        char exp[24];
        snprintf(exp, sizeof exp, "%ld", (long)k->expires_at);
        const char *p[] = {k->mask, k->set_by, exp};
        irc_build(line, sizeof line, NULL, 0, self_sid(srv), "GLINE", p, 3, k->reason);
        send_link(lc, line);
    }
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "EOB", NULL, 0, NULL);
    send_link(lc, line);
}

int netsync_link_up(server_t *srv, link_conn_t *lc, const char *name, const char *sid, const char *desc) {
    if (netsync_find_sid(srv, sid) || netsync_find_name(srv, name)) {
        link_forward_line(lc, "ERROR :Server or SID already exists on this network");
        log_warn("netsync", "refusing link to '%s' (%s): name or SID already on the network", name, sid);
        return -1;
    }
    netserver_t *s = calloc(1, sizeof *s);
    if (!s) return -1;
    snprintf(s->name, sizeof s->name, "%s", name);
    snprintf(s->sid, sizeof s->sid, "%s", sid);
    snprintf(s->desc, sizeof s->desc, "%s", desc ? desc : "");
    s->hop = 1;
    s->uplink = srv->self_srv;
    s->route = lc;
    HASH_ADD_STR(srv->servers, sid, s);
    lc->is_server = 1;
    lc->nserver = s;
    log_info("netsync", "linked with server %s (%s)", name, sid);
    send_burst(srv, lc);
    /* tell the rest of the tree about the new server (its own users arrive when it bursts to us) */
    char line[300], hop[8];
    snprintf(hop, sizeof hop, "%d", 2);
    const char *p[] = {name, hop, sid};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SERVER", p, 3, s->desc);
    flood(srv, lc, line);
    return 0;
}

/* --- receiving: sources and servers --------------------------------------------------------------------- */

/* The server named by `prefix`, provided it really is on `lc`'s side -- a link may only speak for servers behind it. */
static netserver_t *src_server(server_t *srv, link_conn_t *lc, const char *prefix) {
    if (!prefix) return NULL;
    netserver_t *s = netsync_find_sid(srv, prefix);
    if (s && s != srv->self_srv && netsync_is_behind(s, lc->nserver)) return s;
    return NULL;
}

static client_t *src_user(server_t *srv, link_conn_t *lc, const char *prefix) {
    if (!prefix) return NULL;
    client_t *u = netsync_find_uid(srv, prefix);
    if (u && u->remote && u->nserver && netsync_is_behind(u->nserver, lc->nserver)) return u;
    return NULL;
}

static void kill_back(server_t *srv, link_conn_t *lc, const char *uid, const char *reason) {
    char line[300];
    const char *p[] = {uid};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "KILL", p, 1, reason);
    send_link(lc, line);
}

/* Removes `root` and every server behind it, with all their users (QUIT "uplink root" to our local users). */
static void remove_server_tree(server_t *srv, netserver_t *root) {
    char reason[300];
    snprintf(reason, sizeof reason, "%s %s", root->uplink ? root->uplink->name : srv->self_srv->name, root->name);
    client_t *u, *utmp;
    HASH_ITER(hh, srv->users, u, utmp)
        if (u->remote && u->nserver && netsync_is_behind(u->nserver, root)) server_remove_client(srv, u, reason);
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp)
        if (s != srv->self_srv && netsync_is_behind(s, root)) { HASH_DEL(srv->servers, s); free(s); }
}

void netsync_link_down(server_t *srv, link_conn_t *lc, const char *reason) {
    netserver_t *root = lc->nserver;
    if (!root) return;
    lc->nserver = NULL;
    char name[128], sid[SID_LEN + 1];
    snprintf(name, sizeof name, "%s", root->name);
    snprintf(sid, sizeof sid, "%s", root->sid);
    remove_server_tree(srv, root);
    char line[300];
    const char *p[] = {sid};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SQUIT", p, 1, reason ? reason : "Link closed");
    flood(srv, lc, line);
    char snote[240];
    snprintf(snote, sizeof snote, "Netsplit: %s %s", srv->self_srv->name, name);
    server_notify_opers(srv, snote);
}

static void handle_server(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *from = src_server(srv, lc, msg->prefix);
    if (!from && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) from = lc->nserver;
    if (!from || msg->nparams < 4) return;
    const char *name = msg->params[0], *sid = msg->params[2], *desc = msg->params[3];
    int hop = atoi(msg->params[1]);
    if (netsync_find_sid(srv, sid) || netsync_find_name(srv, name)) { /* a loop or a duplicate: refuse the whole link */
        log_error("netsync", "link '%s' introduced %s (%s) which already exists -- dropping the link", lc->peer_name, name, sid);
        link_forward_line(lc, "ERROR :Server loop or duplicate detected");
        link_close(srv, lc);
        return;
    }
    netserver_t *s = calloc(1, sizeof *s);
    if (!s) return;
    snprintf(s->name, sizeof s->name, "%s", name);
    snprintf(s->sid, sizeof s->sid, "%s", sid);
    snprintf(s->desc, sizeof s->desc, "%s", desc);
    s->hop = hop > 0 ? hop : from->hop + 1;
    s->uplink = from;
    s->route = lc;
    HASH_ADD_STR(srv->servers, sid, s);
    char line[300], hopb[8];
    snprintf(hopb, sizeof hopb, "%d", s->hop + 1);
    const char *p[] = {name, hopb, sid};
    irc_build(line, sizeof line, NULL, 0, from->sid, "SERVER", p, 3, desc);
    flood(srv, lc, line);
    char snote[240];
    snprintf(snote, sizeof snote, "Server %s (%s) introduced by %s", name, sid, from->name);
    server_notify_opers(srv, snote);
}

static void handle_squit(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 1) return;
    netserver_t *s = netsync_find_sid(srv, msg->params[0]);
    if (!s || s == srv->self_srv) return;
    if (!netsync_is_behind(s, lc->nserver)) return; /* not ours to remove */
    if (s == lc->nserver) { link_close(srv, lc); return; } /* the peer itself is quitting: tear the link down */
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "SQUIT";
    char sid[SID_LEN + 1];
    snprintf(sid, sizeof sid, "%s", s->sid);
    remove_server_tree(srv, s);
    char line[300];
    const char *p[] = {sid};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SQUIT", p, 1, reason);
    flood(srv, lc, line);
}

/* --- receiving: users --------------------------------------------------------------------------------- */

/* A local user loses a nick collision: free the nick in the table right now (so the winner can take it without two
 * entries sharing a key) and let net.c's teardown close the connection. Its QUIT still reaches everyone. */
static void evict_local_for_collision(server_t *srv, client_t *old) {
    client_t *found;
    HASH_FIND_STR(srv->users, old->casefold_nick, found);
    if (found == old) HASH_DEL(srv->users, old);
    old->casefold_nick[0] = '\0';
    snprintf(old->quit_reason, sizeof old->quit_reason, "Nick collision");
    old->quitting = 1;
}

/* Settles a nick that is already in use when `ts`/`from` wants it. Returns 1 if the newcomer may proceed. */
static int resolve_collision(server_t *srv, link_conn_t *lc, const char *nick, long ts, const char *newcomer_uid) {
    client_t *old = server_find_user(srv, nick);
    if (!old) return 1;
    int newcomer_wins = ts < old->nick_ts, tie = ts == old->nick_ts;
    if (tie || !newcomer_wins) kill_back(srv, lc, newcomer_uid, "Nick collision"); /* newcomer loses (or both do) */
    if (tie || newcomer_wins) {
        if (old->remote) {
            char line[300];
            const char *p[] = {old->uid};
            irc_build(line, sizeof line, NULL, 0, self_sid(srv), "KILL", p, 1, "Nick collision");
            flood(srv, NULL, line);
            server_remove_client(srv, old, "Nick collision");
        } else {
            evict_local_for_collision(srv, old);
        }
    }
    return newcomer_wins && !tie;
}

static void handle_uid(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *from = src_server(srv, lc, msg->prefix);
    if (!from && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) from = lc->nserver;
    if (!from || msg->nparams < 12) return;
    const char *nick = msg->params[0], *modes = msg->params[3], *user = msg->params[4], *host = msg->params[5];
    const char *realhost = msg->params[6], *ip = msg->params[7], *uid = msg->params[8], *account = msg->params[9];
    long ts = atol(msg->params[2]);
    if (!irc_valid_nick(nick, NICKLEN - 1) || strlen(uid) != UID_LEN || netsync_find_uid(srv, uid)) return;
    if (strncmp(uid, from->sid, SID_LEN) != 0) return; /* a server may only create users with its own SID */
    if (!resolve_collision(srv, lc, nick, ts, uid)) return;
    client_t *cl = client_new(-1, srv);
    if (!cl) return;
    cl->remote = 1;
    cl->registered = cl->got_nick = cl->got_user = 1;
    cl->class_idx = -1;
    snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    irc_casefold(cl->casefold_nick, sizeof cl->casefold_nick, nick);
    snprintf(cl->user, sizeof cl->user, "%s", user);
    snprintf(cl->host, sizeof cl->host, "%s", host);
    snprintf(cl->realhost, sizeof cl->realhost, "%s", realhost);
    snprintf(cl->ip, sizeof cl->ip, "%s", ip);
    snprintf(cl->realname, sizeof cl->realname, "%s", msg->params[11]);
    if (strcmp(account, "*") != 0) snprintf(cl->account, sizeof cl->account, "%s", account);
    cl->ident_confirmed = msg->params[10][0] == '1';
    int svc = 0;
    cl->umodes = umodes_from_string(modes, &svc);
    cl->is_service = svc;
    cl->nick_ts = ts;
    cl->signon_time = ts;
    snprintf(cl->uid, sizeof cl->uid, "%s", uid);
    cl->nserver = from;
    from->n_users++;
    HASH_ADD(hh_uid, srv->by_uid, uid, strlen(cl->uid), cl);
    server_add_user(srv, cl);
    server_monitor_notify(srv, cl, 1);
    server_watch_notify(srv, cl, 1);
    /* forward with hop + 1 */
    char line[1100], hopb[8];
    snprintf(hopb, sizeof hopb, "%d", atoi(msg->params[1]) + 1);
    const char *p[] = {nick, hopb, msg->params[2], modes, user, host, realhost, ip, uid, account, msg->params[10]};
    irc_build(line, sizeof line, NULL, 0, from->sid, "UID", p, 11, msg->params[11]);
    flood(srv, lc, line);
}

static void rekey_nick(server_t *srv, client_t *cl, const char *newnick) {
    client_t *found;
    HASH_FIND_STR(srv->users, cl->casefold_nick, found);
    if (found == cl) HASH_DEL(srv->users, cl);
    snprintf(cl->nick, sizeof cl->nick, "%s", newnick);
    irc_casefold(cl->casefold_nick, sizeof cl->casefold_nick, newnick);
    server_add_user(srv, cl);
}

static void handle_nick(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 2) return;
    const char *newnick = msg->params[0];
    long ts = atol(msg->params[1]);
    if (!irc_valid_nick(newnick, NICKLEN - 1)) return;
    client_t *clash = server_find_user(srv, newnick);
    if (clash && clash != u) {
        if (ts < clash->nick_ts) { /* the renamer is older: the holder loses */
            if (clash->remote) {
                char kl[300];
                const char *kp[] = {clash->uid};
                irc_build(kl, sizeof kl, NULL, 0, self_sid(srv), "KILL", kp, 1, "Nick collision");
                flood(srv, NULL, kl);
                server_remove_client(srv, clash, "Nick collision");
            } else evict_local_for_collision(srv, clash);
        } else { /* the renamer loses (or ties): kill it everywhere */
            kill_back(srv, lc, u->uid, "Nick collision");
            char kl[300];
            const char *kp[] = {u->uid};
            irc_build(kl, sizeof kl, NULL, 0, self_sid(srv), "KILL", kp, 1, "Nick collision");
            flood(srv, lc, kl);
            server_remove_client(srv, u, "Nick collision");
            return;
        }
    }
    char prefix[320], line[400];
    client_prefix(u, prefix, sizeof prefix);
    irc_build(line, sizeof line, NULL, 0, prefix, "NICK", NULL, 0, newnick);
    server_send_common_channels(srv, u, line, 0);
    server_monitor_notify(srv, u, 0);
    server_watch_notify(srv, u, 0);
    rekey_nick(srv, u, newnick);
    u->nick_ts = ts;
    server_monitor_notify(srv, u, 1);
    server_watch_notify(srv, u, 1);
    char fl[300];
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "NICK", (const char *[]){newnick, msg->params[1]}, 2, NULL);
    flood(srv, lc, fl);
}

static void handle_quit(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u) return;
    const char *reason = msg->nparams > 0 ? msg->params[msg->nparams - 1] : "";
    char fl[400], uid[UID_LEN + 1];
    snprintf(uid, sizeof uid, "%s", u->uid);
    server_remove_client(srv, u, reason);
    irc_build(fl, sizeof fl, NULL, 0, uid, "QUIT", NULL, 0, reason);
    flood(srv, lc, fl);
}

static void handle_umode(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 1) return;
    int svc;
    u->umodes = umodes_from_string(msg->params[0], &svc);
    if (u->account[0]) u->umodes |= UMODE_R;
    char fl[200];
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "UMODE", (const char *[]){msg->params[0]}, 1, NULL);
    flood(srv, lc, fl);
}

static void handle_away(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u) return;
    const char *text = msg->nparams > 0 ? msg->params[msg->nparams - 1] : "";
    u->is_away = text[0] != '\0';
    snprintf(u->away, sizeof u->away, "%.399s", text);
    char prefix[320], line[500];
    client_prefix(u, prefix, sizeof prefix);
    irc_build(line, sizeof line, NULL, 0, prefix, "AWAY", NULL, 0, u->is_away ? u->away : NULL);
    server_send_common_channels(srv, u, line, CAP_AWAY_NOTIFY);
    server_monitor_extend(srv, u, line, CAP_AWAY_NOTIFY);
    char fl[500];
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "AWAY", NULL, 0, u->is_away ? u->away : "");
    flood(srv, lc, fl);
}

static void handle_chghost(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *s = src_server(srv, lc, msg->prefix);
    if (!s || msg->nparams < 3) return;
    client_t *u = netsync_find_uid(srv, msg->params[0]);
    if (!u || !u->remote || !u->nserver || !netsync_is_behind(u->nserver, lc->nserver)) return;
    char oldprefix[320], line[400];
    client_prefix(u, oldprefix, sizeof oldprefix);
    snprintf(u->user, sizeof u->user, "%s", msg->params[1]);
    snprintf(u->host, sizeof u->host, "%s", msg->params[2]);
    irc_build(line, sizeof line, NULL, 0, oldprefix, "CHGHOST", (const char *[]){u->user, u->host}, 2, NULL);
    server_send_common_channels(srv, u, line, CAP_CHGHOST);
    server_monitor_extend(srv, u, line, CAP_CHGHOST);
    char fl[400];
    const char *p[] = {u->uid, u->user, u->host};
    irc_build(fl, sizeof fl, NULL, 0, s->sid, "CHGHOST", p, 3, NULL);
    flood(srv, lc, fl);
}

static void handle_setname(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 1) return;
    snprintf(u->realname, sizeof u->realname, "%s", msg->params[msg->nparams - 1]);
    char prefix[320], line[500];
    client_prefix(u, prefix, sizeof prefix);
    irc_build(line, sizeof line, NULL, 0, prefix, "SETNAME", NULL, 0, u->realname);
    server_send_common_channels(srv, u, line, CAP_SETNAME);
    server_monitor_extend(srv, u, line, CAP_SETNAME);
    char fl[500];
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "SETNAME", NULL, 0, u->realname);
    flood(srv, lc, fl);
}

static void handle_account(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *s = src_server(srv, lc, msg->prefix);
    if (!s || msg->nparams < 2) return;
    client_t *u = netsync_find_uid(srv, msg->params[0]);
    if (!u || !u->remote || !u->nserver || !netsync_is_behind(u->nserver, lc->nserver)) return;
    const char *acct = msg->params[1];
    char prefix[320], line[400];
    client_prefix(u, prefix, sizeof prefix);
    if (strcmp(acct, "*") == 0) { u->account[0] = '\0'; u->umodes &= ~UMODE_R; }
    else { snprintf(u->account, sizeof u->account, "%s", acct); u->umodes |= UMODE_R; }
    irc_build(line, sizeof line, NULL, 0, prefix, "ACCOUNT", (const char *[]){acct}, 1, NULL);
    server_send_common_channels(srv, u, line, CAP_ACCOUNT_NOTIFY);
    server_monitor_extend(srv, u, line, CAP_ACCOUNT_NOTIFY);
    char fl[300];
    const char *p[] = {u->uid, acct};
    irc_build(fl, sizeof fl, NULL, 0, s->sid, "ACCOUNT", p, 2, NULL);
    flood(srv, lc, fl);
}

static void handle_kill(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 1) return;
    client_t *target = netsync_find_uid(srv, msg->params[0]);
    if (!target) return;
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "Killed";
    if (!target->remote) { /* ours: disconnect it (its QUIT then floods out through server_remove_client) */
        snprintf(target->quit_reason, sizeof target->quit_reason, "Killed (%s)", reason);
        target->quitting = 1;
        return;
    }
    /* someone else's: pass it on toward them, and drop the user here right away so a collision resolves at once */
    char fl[400];
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "KILL", (const char *[]){target->uid}, 1, reason);
    route_to(srv, target->nserver, fl);
    (void)lc;
}

/* --- receiving: channels ---------------------------------------------------------------------------------- */

static void rank_letters(int rank, char *out) {
    size_t n = 0;
    if (rank & RANK_OWNER) out[n++] = 'q';
    if (rank & RANK_ADMIN) out[n++] = 'a';
    if (rank & RANK_OP) out[n++] = 'o';
    if (rank & RANK_HALFOP) out[n++] = 'h';
    if (rank & RANK_VOICE) out[n++] = 'v';
    out[n] = '\0';
}

/* Sends ":source MODE #chan <modes> <args...>" to the channel's local members, 6 changes per line. `ops` is an
 * array of (letter, argument) pairs sharing one sign. */
static void broadcast_rank_modes(channel_t *chan, const char *source, char sign, const char letters[], const char *args[], int n) {
    for (int i = 0; i < n; i += 6) {
        int chunk = n - i < 6 ? n - i : 6;
        char modes[16], line[600];
        modes[0] = sign;
        for (int k = 0; k < chunk; k++) modes[1 + k] = letters[i + k];
        modes[1 + chunk] = '\0';
        const char *p[8] = {chan->name, modes};
        for (int k = 0; k < chunk; k++) p[2 + k] = args[i + k];
        irc_build(line, sizeof line, NULL, 0, source, "MODE", p, 2 + chunk, NULL);
        server_broadcast_channel(chan, line, NULL);
    }
}

/* Sets channel state from a "+modes args..." string directly (no broadcast). replace=1 clears the flags first. */
static void set_state_modes(channel_t *chan, const char *modes, const char **args, int nargs, int replace) {
    if (replace) {
        chan->modes = 0;
        chan->key[0] = '\0';
        chan->limit = chan->flood_lines = chan->flood_secs = chan->jt_joins = chan->jt_secs = 0;
        chan->redirect[0] = '\0';
    }
    int ai = 0;
    for (const char *c = modes; *c; c++) {
        if (*c == '+' || *c == '-') continue;
        unsigned bit = channel_flag_bit(*c);
        if (bit) { chan->modes |= bit; continue; }
        const char *a = ai < nargs ? args[ai++] : NULL;
        if (!a) break;
        switch (*c) {
            case 'k': snprintf(chan->key, sizeof chan->key, "%s", a); chan->modes |= CMODE_K; break;
            case 'l': chan->limit = atoi(a); if (chan->limit > 0) chan->modes |= CMODE_L; break;
            case 'f': { int n, s; if (sscanf(a, "%d:%d", &n, &s) == 2) { chan->flood_lines = n; chan->flood_secs = s; chan->modes |= CMODE_FLOOD; } break; }
            case 'j': { int n, s; if (sscanf(a, "%d:%d", &n, &s) == 2) { chan->jt_joins = n; chan->jt_secs = s; chan->modes |= CMODE_JTHROT; } break; }
            case 'L': snprintf(chan->redirect, sizeof chan->redirect, "%s", a); chan->modes |= CMODE_REDIRECT; break;
        }
    }
}

/* We lost a channel-TS comparison: drop our modes, lists and member ranks, telling our local members. */
static void reset_channel_for_ts(server_t *srv, channel_t *chan) {
    char letters[64];
    const char *args[64];
    int n = 0;
    member_t *m, *tmp;
    for (int pass = 0; pass < 5; pass++) { /* one rank at a time so each -x line is homogeneous */
        static const int bits[5] = {RANK_OWNER, RANK_ADMIN, RANK_OP, RANK_HALFOP, RANK_VOICE};
        static const char ltr[5] = {'q', 'a', 'o', 'h', 'v'};
        n = 0;
        HASH_ITER(hh, chan->members, m, tmp) {
            if ((m->rank & bits[pass]) && n < 64) { letters[n] = ltr[pass]; args[n] = m->client->nick; n++; }
        }
        if (n) broadcast_rank_modes(chan, srv->self_srv->name, '-', letters, args, n);
    }
    HASH_ITER(hh, chan->members, m, tmp) m->rank = 0;
    char flagsoff[40] = "-";
    for (const char *c = "nipstmzrPCTSVQNROMcDuG"; *c; c++)
        if (chan->modes & channel_flag_bit(*c)) strncat(flagsoff, (char[]){*c, 0}, sizeof flagsoff - strlen(flagsoff) - 1);
    char ps[8] = "";
    const char *pargs[4];
    int np = 0;
    if (chan->modes & CMODE_K) { strncat(ps, "k", 7); pargs[np++] = "*"; }
    if (chan->modes & CMODE_L) strncat(ps, "l", 7);
    if (chan->modes & CMODE_FLOOD) strncat(ps, "f", 7);
    if (chan->modes & CMODE_JTHROT) strncat(ps, "j", 7);
    if (chan->modes & CMODE_REDIRECT) strncat(ps, "L", 7);
    if (strlen(flagsoff) > 1 || ps[0]) {
        char modes[60], line[400];
        snprintf(modes, sizeof modes, "%s%s", flagsoff, ps);
        const char *p[8] = {chan->name, modes};
        for (int i = 0; i < np; i++) p[2 + i] = pargs[i];
        irc_build(line, sizeof line, NULL, 0, srv->self_srv->name, "MODE", p, 2 + np, NULL);
        server_broadcast_channel(chan, line, NULL);
    }
    masklist_free(&chan->bans);
    masklist_free(&chan->exceptions);
    masklist_free(&chan->invex);
    chan->bans.gen++; chan->exceptions.gen++; chan->invex.gen++;
}

static void handle_sjoin(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *from = src_server(srv, lc, msg->prefix);
    if (!from && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) from = lc->nserver;
    if (!from || msg->nparams < 4) return;
    long ts = atol(msg->params[0]);
    const char *name = msg->params[1], *modes = msg->params[2];
    const char *members = msg->params[msg->nparams - 1];
    const char *margs[10];
    int nm = 0;
    for (int i = 3; i < msg->nparams - 1 && nm < 10; i++) margs[nm++] = msg->params[i];
    if (!irc_valid_channel(name, 50)) return;

    channel_t *chan = server_find_channel(srv, name);
    int keep_ranks = 1;
    if (!chan) {
        chan = server_get_or_create_channel(srv, name);
        if (!chan) return;
        chan->modes = 0; /* a remote channel: its modes, not our defaults */
        chan->created = ts;
        set_state_modes(chan, modes, margs, nm, 1);
    } else if (ts < chan->created) { /* theirs is older: it wins everything */
        reset_channel_for_ts(srv, chan);
        chan->created = ts;
        set_state_modes(chan, modes, margs, nm, 1);
    } else if (ts == chan->created) { /* same age: merge */
        set_state_modes(chan, modes, margs, nm, 0);
    } else { /* ours is older: their modes are ignored and their members arrive without ranks */
        keep_ranks = 0;
    }

    char letters[64];
    const char *args[64];
    char copy[640];
    snprintf(copy, sizeof copy, "%s", members);
    char *save = NULL;
    struct { client_t *c; int rank; } joined[64];
    int nj = 0;
    for (char *tok = strtok_r(copy, " ", &save); tok && nj < 64; tok = strtok_r(NULL, " ", &save)) {
        const char *p = tok;
        int rank = rank_from_prefix(&p);
        client_t *u = netsync_find_uid(srv, p);
        if (!u || !u->remote) continue;
        if (channel_find_member(chan, u)) continue;
        member_t *m = channel_add_member(chan, u);
        if (!m) continue;
        server_attach_membership(u, chan);
        m->rank = keep_ranks ? rank : 0;
        cmd_announce_join(chan, u);
        joined[nj].c = u;
        joined[nj].rank = m->rank;
        nj++;
    }
    static const int bits[5] = {RANK_OWNER, RANK_ADMIN, RANK_OP, RANK_HALFOP, RANK_VOICE};
    static const char ltr[5] = {'q', 'a', 'o', 'h', 'v'};
    for (int pass = 0; pass < 5; pass++) {
        int n = 0;
        for (int i = 0; i < nj; i++)
            if ((joined[i].rank & bits[pass]) && !(pass == 2 && (joined[i].rank & (RANK_OWNER | RANK_ADMIN)))) { letters[n] = ltr[pass]; args[n] = joined[i].c->nick; n++; }
        if (n) broadcast_rank_modes(chan, from->name, '+', letters, args, n);
    }
    /* forward the original, unchanged -- every server applies the TS rules itself */
    char fl[1200];
    const char *p2[14] = {msg->params[0], name, modes};
    for (int i = 0; i < nm; i++) p2[3 + i] = margs[i];
    irc_build(fl, sizeof fl, NULL, 0, from->sid, "SJOIN", p2, 3 + nm, members);
    flood(srv, lc, fl);
}

static void handle_bmask(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *from = src_server(srv, lc, msg->prefix);
    if (!from && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) from = lc->nserver;
    if (!from || msg->nparams < 4) return;
    channel_t *chan = server_find_channel(srv, msg->params[1]);
    if (!chan) return;
    long ts = atol(msg->params[0]);
    char kind = msg->params[2][0];
    if (ts <= chan->created) { /* their channel is the same age or older: its lists count */
        masklist_t *ml = kind == 'b' ? &chan->bans : kind == 'e' ? &chan->exceptions : kind == 'I' ? &chan->invex : NULL;
        if (ml) {
            char copy[800];
            snprintf(copy, sizeof copy, "%s", msg->params[3]);
            char *save = NULL;
            for (char *m = strtok_r(copy, " ", &save); m; m = strtok_r(NULL, " ", &save)) masklist_add(ml, m);
        }
    }
    char fl[1000];
    const char *p[] = {msg->params[0], msg->params[1], msg->params[2]};
    irc_build(fl, sizeof fl, NULL, 0, from->sid, "BMASK", p, 3, msg->params[3]);
    flood(srv, lc, fl);
}

static void handle_tb(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *from = src_server(srv, lc, msg->prefix);
    if (!from && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) from = lc->nserver;
    if (!from || msg->nparams < 4) return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    if (chan) {
        long ts = atol(msg->params[1]);
        if (!chan->topic[0] || ts < (long)chan->topic_time) {
            snprintf(chan->topic, sizeof chan->topic, "%.*s", TOPIC_MAX_LEN, msg->params[3]);
            snprintf(chan->topic_setter, sizeof chan->topic_setter, "%s", msg->params[2]);
            chan->topic_time = (time_t)ts;
            char line[600];
            const char *p[] = {chan->name};
            irc_build(line, sizeof line, NULL, 0, msg->params[2], "TOPIC", p, 1, chan->topic);
            server_broadcast_channel(chan, line, NULL);
        }
    }
    char fl[700];
    const char *p[] = {msg->params[0], msg->params[1], msg->params[2]};
    irc_build(fl, sizeof fl, NULL, 0, from->sid, "TB", p, 3, msg->params[3]);
    flood(srv, lc, fl);
}

static void handle_join(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 2) return;
    long ts = atol(msg->params[0]);
    const char *name = msg->params[1];
    channel_t *chan = server_find_channel(srv, name);
    if (!chan) {
        chan = server_get_or_create_channel(srv, name);
        if (!chan) return;
        chan->modes = 0;
        chan->created = ts;
    }
    if (!channel_find_member(chan, u)) {
        member_t *m = channel_add_member(chan, u);
        if (m) {
            server_attach_membership(u, chan);
            if ((chan->modes & CMODE_DELAYJOIN) && m->rank == 0) m->hidden = 1;
            cmd_announce_join(chan, u);
        }
    }
    char fl[300];
    const char *p[] = {msg->params[0], name};
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "JOIN", p, 2, NULL);
    flood(srv, lc, fl);
}

static void handle_part(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 1) return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : NULL;
    if (chan) {
        member_t *m = channel_find_member(chan, u);
        if (m) {
            char prefix[320], line[500];
            client_prefix(u, prefix, sizeof prefix);
            const char *p[] = {chan->name};
            irc_build(line, sizeof line, NULL, 0, prefix, "PART", p, 1, reason);
            member_t *pm, *ptmp;
            HASH_ITER(hh, chan->members, pm, ptmp)
                if (channel_member_visible(chan, m, pm)) client_send(pm->client, line);
            channel_remove_member(chan, u);
            server_detach_membership(u, chan);
            server_maybe_drop_channel(srv, chan);
        }
    }
    char fl[500];
    const char *p[] = {msg->params[0]};
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "PART", p, 1, reason);
    flood(srv, lc, fl);
}

static void handle_kick(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 2) return;
    client_t *kicker = src_user(srv, lc, msg->prefix);
    netserver_t *ks = kicker ? NULL : src_server(srv, lc, msg->prefix);
    if (!kicker && !ks) return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    client_t *target = netsync_find_uid(srv, msg->params[1]);
    const char *reason = msg->nparams > 2 ? msg->params[msg->nparams - 1] : "Kicked";
    if (chan && target && channel_find_member(chan, target)) {
        char prefix[320], line[500];
        if (kicker) client_prefix(kicker, prefix, sizeof prefix); else snprintf(prefix, sizeof prefix, "%s", ks->name);
        const char *p[] = {chan->name, target->nick};
        irc_build(line, sizeof line, NULL, 0, prefix, "KICK", p, 2, reason);
        server_broadcast_channel(chan, line, NULL);
        channel_remove_member(chan, target);
        server_detach_membership(target, chan);
        server_maybe_drop_channel(srv, chan);
    }
    char fl[500];
    const char *p[] = {msg->params[0], msg->params[1]};
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "KICK", p, 2, reason);
    flood(srv, lc, fl);
}

static void handle_topic(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    netserver_t *s = u ? NULL : src_server(srv, lc, msg->prefix);
    if ((!u && !s) || msg->nparams < 2) return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    const char *text = msg->params[msg->nparams - 1];
    if (chan) {
        char prefix[320], line[700];
        if (u) client_prefix(u, prefix, sizeof prefix); else snprintf(prefix, sizeof prefix, "%s", s->name);
        snprintf(chan->topic, sizeof chan->topic, "%.*s", TOPIC_MAX_LEN, text);
        snprintf(chan->topic_setter, sizeof chan->topic_setter, "%s", prefix);
        chan->topic_time = time(NULL);
        const char *p[] = {chan->name};
        irc_build(line, sizeof line, NULL, 0, prefix, "TOPIC", p, 1, chan->topic);
        server_broadcast_channel(chan, line, NULL);
    }
    char fl[700];
    const char *p[] = {msg->params[0]};
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "TOPIC", p, 1, text);
    flood(srv, lc, fl);
}

/* :src MODE #chan <modes> [args]  -- args for o/h/v/q/a are UIDs on the wire, nicks for our local members. */
static void handle_mode(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 2) return;
    client_t *u = src_user(srv, lc, msg->prefix);
    netserver_t *s = u ? NULL : src_server(srv, lc, msg->prefix);
    if (!u && !s) return;
    if (msg->params[0][0] != '#') return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    if (chan) {
        char prefix[320];
        if (u) client_prefix(u, prefix, sizeof prefix); else snprintf(prefix, sizeof prefix, "%s", s->name);
        char outflags[64], outparams[8][260];
        size_t of = 0;
        int nout = 0;
        char sign = '+', cursign = 0;
        int ai = 2;
        for (const char *c = msg->params[1]; *c && of + 3 < sizeof outflags && nout < 8; c++) {
            if (*c == '+' || *c == '-') { sign = *c; continue; }
            const char *arg = NULL;
            int takes = strchr("kbeIohvqa", *c) != NULL || (sign == '+' && strchr("lfjL", *c) != NULL);
            if (takes && ai < msg->nparams) arg = msg->params[ai++];
            unsigned bit = channel_flag_bit(*c);
            int emit = 1;
            const char *outarg = NULL;
            char tmpnick[NICKLEN];
            if (bit) {
                if (sign == '+') chan->modes |= bit; else chan->modes &= ~bit;
                if (sign == '-' && bit == CMODE_DELAYJOIN) {
                    member_t *hm, *ht;
                    HASH_ITER(hh, chan->members, hm, ht) if (hm->hidden) channel_reveal_member(chan, hm);
                }
            } else if (*c == 'k') {
                if (sign == '+' && arg) { snprintf(chan->key, sizeof chan->key, "%s", arg); chan->modes |= CMODE_K; outarg = arg; }
                else { chan->key[0] = '\0'; chan->modes &= ~CMODE_K; outarg = "*"; }
            } else if (*c == 'l') {
                if (sign == '+' && arg) { chan->limit = atoi(arg); chan->modes |= CMODE_L; outarg = arg; } else { chan->limit = 0; chan->modes &= ~CMODE_L; }
            } else if (*c == 'f' || *c == 'j') {
                int n, secs;
                if (sign == '+' && arg && sscanf(arg, "%d:%d", &n, &secs) == 2) {
                    if (*c == 'f') { chan->flood_lines = n; chan->flood_secs = secs; chan->modes |= CMODE_FLOOD; }
                    else { chan->jt_joins = n; chan->jt_secs = secs; chan->jt_count = 0; chan->jt_start = 0; chan->modes |= CMODE_JTHROT; }
                    outarg = arg;
                } else if (sign == '-') {
                    if (*c == 'f') { chan->modes &= ~CMODE_FLOOD; chan->flood_lines = chan->flood_secs = 0; }
                    else { chan->modes &= ~CMODE_JTHROT; chan->jt_joins = chan->jt_secs = 0; }
                } else emit = 0;
            } else if (*c == 'L') {
                if (sign == '+' && arg) { snprintf(chan->redirect, sizeof chan->redirect, "%s", arg); chan->modes |= CMODE_REDIRECT; outarg = arg; }
                else { chan->redirect[0] = '\0'; chan->modes &= ~CMODE_REDIRECT; }
            } else if (*c == 'b' || *c == 'e' || *c == 'I') {
                masklist_t *ml = *c == 'b' ? &chan->bans : *c == 'e' ? &chan->exceptions : &chan->invex;
                if (!arg) emit = 0;
                else { emit = (sign == '+' ? masklist_add(ml, arg) : masklist_del(ml, arg)) == 0; outarg = arg; }
            } else if (strchr("ohvqa", *c)) {
                client_t *t = arg ? netsync_find_uid(srv, arg) : NULL;
                member_t *tm = t ? channel_find_member(chan, t) : NULL;
                if (!tm) emit = 0;
                else {
                    int rk = *c == 'o' ? RANK_OP : *c == 'h' ? RANK_HALFOP : *c == 'v' ? RANK_VOICE : *c == 'q' ? RANK_OWNER : RANK_ADMIN;
                    if (sign == '+') {
                        tm->rank |= rk;
                        if (*c == 'q' || *c == 'a') tm->rank |= RANK_OP;
                        if (tm->hidden) channel_reveal_member(chan, tm);
                    } else {
                        tm->rank &= ~rk;
                        if (*c == 'o') tm->rank &= ~(RANK_ADMIN | RANK_OWNER);
                    }
                    snprintf(tmpnick, sizeof tmpnick, "%s", t->nick);
                    outarg = tmpnick;
                }
            } else emit = 0;
            if (!emit) continue;
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = *c;
            if (outarg) snprintf(outparams[nout++], sizeof outparams[0], "%s", outarg);
        }
        outflags[of] = '\0';
        if (of > 1) {
            char line[900];
            const char *p[10] = {chan->name, outflags};
            for (int i = 0; i < nout; i++) p[2 + i] = outparams[i];
            irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p, 2 + nout, NULL);
            server_broadcast_channel(chan, line, NULL);
        }
    }
    char fl[900];
    const char *p[12] = {msg->params[0], msg->params[1]};
    int np = 2;
    for (int i = 2; i < msg->nparams && np < 12; i++) p[np++] = msg->params[i];
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "MODE", p, np, NULL);
    flood(srv, lc, fl);
}

/* --- receiving: messages and the rest ---------------------------------------------------------------------- */

static void fwd_message(server_t *srv, link_conn_t *lc, irc_message_t *msg, const netserver_t *only_dest) {
    char line[1500];
    irc_tag_t tags[IRC_MAX_TAGS];
    for (int i = 0; i < msg->ntags; i++) tags[i] = msg->tags[i];
    const char *p[2] = {msg->params[0], NULL};
    int hastext = msg->nparams > 1;
    irc_build(line, sizeof line, tags, msg->ntags, msg->prefix, msg->command, p, 1, hastext ? msg->params[msg->nparams - 1] : NULL);
    if (only_dest) route_to(srv, only_dest, line); else flood(srv, lc, line);
}

static void handle_message(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *from = src_user(srv, lc, msg->prefix);
    if (!from || msg->nparams < 1) return;
    const char *target = msg->params[0];
    const char *text = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "";
    client_t *tu = strlen(target) == UID_LEN ? netsync_find_uid(srv, target) : NULL;
    if (tu) { /* addressed to one user */
        if (!tu->remote) cmd_deliver_remote_message(srv, from, msg->command, target, text, msg);
        else fwd_message(srv, lc, msg, tu->nserver);
        return;
    }
    cmd_deliver_remote_message(srv, from, msg->command, target, text, msg); /* a channel (maybe @#chan) */
    fwd_message(srv, lc, msg, NULL);
}

static void handle_invite(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *from = src_user(srv, lc, msg->prefix);
    if (!from || msg->nparams < 2) return;
    client_t *target = netsync_find_uid(srv, msg->params[0]);
    channel_t *chan = server_find_channel(srv, msg->params[1]);
    if (target && !target->remote) { /* the invitee is ours: tell them and remember the invite for +i */
        char prefix[320], line[400];
        client_prefix(from, prefix, sizeof prefix);
        irc_build(line, sizeof line, NULL, 0, prefix, "INVITE", (const char *[]){target->nick}, 1, msg->params[1]);
        client_send(target, line);
        if (chan && (chan->modes & CMODE_I)) channel_invite_add(chan, client_invite_key(target));
    }
    if (chan) { /* invite-notify for our ops */
        char prefix[320], nl[400];
        client_prefix(from, prefix, sizeof prefix);
        const char *tn = target ? target->nick : msg->params[0];
        irc_build(nl, sizeof nl, NULL, 0, prefix, "INVITE", (const char *[]){tn, chan->name}, 2, NULL);
        member_t *m, *tmp;
        HASH_ITER(hh, chan->members, m, tmp)
            if (!m->client->remote && m->client != target && (m->rank & (RANK_OP | RANK_HALFOP)) && (m->client->caps & CAP_INVITE_NOTIFY))
                client_send(m->client, nl);
    }
    char fl[300];
    irc_build(fl, sizeof fl, NULL, 0, from->uid, "INVITE", (const char *[]){msg->params[0], msg->params[1]}, 2, NULL);
    flood(srv, lc, fl);
}

static void handle_push(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 2) return;
    client_t *target = netsync_find_uid(srv, msg->params[0]);
    if (!target) return;
    if (!target->remote) { client_send(target, msg->params[msg->nparams - 1]); return; }
    char fl[900];
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "PUSH", (const char *[]){msg->params[0]}, 1, msg->params[msg->nparams - 1]);
    route_to(srv, target->nserver, fl);
    (void)lc;
}

static void handle_wallops(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *from = src_user(srv, lc, msg->prefix);
    if (!from || msg->nparams < 1) return;
    const char *text = msg->params[msg->nparams - 1];
    int globops = strcasecmp(msg->command, "GLOBOPS") == 0;
    char prefix[320], line[600];
    client_prefix(from, prefix, sizeof prefix);
    irc_build(line, sizeof line, NULL, 0, prefix, globops ? "GLOBOPS" : "WALLOPS", NULL, 0, text);
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp)
        if (!u->remote && ((globops && (u->umodes & UMODE_O)) || (!globops && (u->umodes & UMODE_W)))) client_send(u, line);
    char fl[600];
    irc_build(fl, sizeof fl, NULL, 0, from->uid, globops ? "GLOBOPS" : "WALLOPS", NULL, 0, text);
    flood(srv, lc, fl);
}

static void handle_gline(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *s = src_server(srv, lc, msg->prefix);
    if (!s && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) s = lc->nserver;
    if (!s || msg->nparams < 4) return;
    long exp = atol(msg->params[2]);
    long dur = exp > 0 ? exp - (long)time(NULL) : 0;
    if (exp > 0 && dur <= 0) return; /* already expired */
    server_kline_add(srv, msg->params[0], msg->params[3], msg->params[1], "G", dur);
    char rsn[300];
    snprintf(rsn, sizeof rsn, "G-Lined: %s", msg->params[3]);
    server_kline_enforce(srv, msg->params[0], "G", rsn, NULL);
    char fl[600];
    const char *p[] = {msg->params[0], msg->params[1], msg->params[2]};
    irc_build(fl, sizeof fl, NULL, 0, s->sid, "GLINE", p, 3, msg->params[3]);
    flood(srv, lc, fl);
}

static void handle_ungline(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 1) return;
    server_kline_remove(srv, msg->params[0]);
    char fl[300];
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "UNGLINE", (const char *[]){msg->params[0]}, 1, NULL);
    flood(srv, lc, fl);
}

/* :<sid> RSQUIT <sid> :reason -- somebody asked for a server to be squit. Executed by the server directly linked to it;
 * everyone else passes the request along toward it. */
static void handle_rsquit(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (msg->nparams < 1) return;
    netserver_t *s = netsync_find_sid(srv, msg->params[0]);
    if (!s || s == srv->self_srv) return;
    if (s->route && s == s->route->nserver) {
        log_info("netsync", "RSQUIT: closing the link to %s on request", s->name);
        link_close(srv, s->route);
        return;
    }
    char fl[300];
    irc_build(fl, sizeof fl, NULL, 0, msg->prefix, "RSQUIT", (const char *[]){msg->params[0]}, 1, msg->nparams > 1 ? msg->params[msg->nparams - 1] : "SQUIT");
    route_to(srv, s, fl);
    (void)lc;
}

static void handle_acct(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *s = src_server(srv, lc, msg->prefix);
    if (!s && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) s = lc->nserver;
    if (!s || !srv->cfg.accounts.enabled || msg->nparams < 3) return;
    long long ts = atoll(msg->params[0]);
    srv->accounts.applying = 1; /* don't echo it back out through the replication hook */
    int applied = accounts_apply_remote(&srv->accounts, msg->params[1], ts, msg->params[msg->nparams - 1]);
    srv->accounts.applying = 0;
    (void)applied;
    char fl[3000];
    irc_build(fl, sizeof fl, NULL, 0, s->sid, "ACCT", (const char *[]){msg->params[0], msg->params[1]}, 2, msg->params[msg->nparams - 1]);
    flood(srv, lc, fl);
}

static void handle_acctdel(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    netserver_t *s = src_server(srv, lc, msg->prefix);
    if (!s && msg->prefix && lc->nserver && strcmp(msg->prefix, lc->nserver->sid) == 0) s = lc->nserver;
    if (!s || !srv->cfg.accounts.enabled || msg->nparams < 2) return;
    long long ts = atoll(msg->params[0]);
    if (accounts_apply_remote_delete(&srv->accounts, msg->params[1], ts)) {
        for (client_t *c = srv->all_clients; c; c = c->all_next) /* local sessions of a dropped account are logged out */
            if (c->fd >= 0 && c->account[0] && strcasecmp(c->account, msg->params[1]) == 0) server_logout(srv, c);
    }
    char fl[400];
    irc_build(fl, sizeof fl, NULL, 0, s->sid, "ACCTDEL", (const char *[]){msg->params[0], msg->params[1]}, 2, NULL);
    flood(srv, lc, fl);
}

void netsync_account_changed(void *ud, const char *name, long long ts, int deleted) {
    server_t *srv = ud;
    if (!netsync_has_links(srv) || !srv->self_srv) return;
    char tsb[24];
    snprintf(tsb, sizeof tsb, "%lld", ts);
    if (deleted) {
        char line[400];
        irc_build(line, sizeof line, NULL, 0, self_sid(srv), "ACCTDEL", (const char *[]){tsb, name}, 2, NULL);
        flood(srv, NULL, line);
        return;
    }
    char *json = accounts_record_json(&srv->accounts, name);
    if (!json) return;
    char big[3000];
    irc_build(big, sizeof big, NULL, 0, self_sid(srv), "ACCT", (const char *[]){tsb, name}, 2, json);
    free(json);
    flood(srv, NULL, big);
}

static void handle_rename(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    client_t *u = src_user(srv, lc, msg->prefix);
    if (!u || msg->nparams < 2) return;
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    const char *reason = msg->nparams > 2 ? msg->params[msg->nparams - 1] : "No reason";
    if (chan && !server_find_channel(srv, msg->params[1])) cmd_channel_rename_apply(srv, chan, u, msg->params[1], reason);
    char fl[500];
    irc_build(fl, sizeof fl, NULL, 0, u->uid, "RENAME", (const char *[]){msg->params[0], msg->params[1]}, 2, reason);
    flood(srv, lc, fl);
}

void netsync_handle(server_t *srv, link_conn_t *lc, irc_message_t *msg) {
    if (!lc->nserver) return;
    const char *c = msg->command;
    if (!strcmp(c, "SERVER")) handle_server(srv, lc, msg);
    else if (!strcmp(c, "UID")) handle_uid(srv, lc, msg);
    else if (!strcmp(c, "NICK")) handle_nick(srv, lc, msg);
    else if (!strcmp(c, "QUIT")) handle_quit(srv, lc, msg);
    else if (!strcmp(c, "UMODE")) handle_umode(srv, lc, msg);
    else if (!strcmp(c, "AWAY")) handle_away(srv, lc, msg);
    else if (!strcmp(c, "CHGHOST")) handle_chghost(srv, lc, msg);
    else if (!strcmp(c, "SETNAME")) handle_setname(srv, lc, msg);
    else if (!strcmp(c, "ACCOUNT")) handle_account(srv, lc, msg);
    else if (!strcmp(c, "KILL")) handle_kill(srv, lc, msg);
    else if (!strcmp(c, "SQUIT")) handle_squit(srv, lc, msg);
    else if (!strcmp(c, "SJOIN")) handle_sjoin(srv, lc, msg);
    else if (!strcmp(c, "BMASK")) handle_bmask(srv, lc, msg);
    else if (!strcmp(c, "TB")) handle_tb(srv, lc, msg);
    else if (!strcmp(c, "JOIN")) handle_join(srv, lc, msg);
    else if (!strcmp(c, "PART")) handle_part(srv, lc, msg);
    else if (!strcmp(c, "KICK")) handle_kick(srv, lc, msg);
    else if (!strcmp(c, "TOPIC")) handle_topic(srv, lc, msg);
    else if (!strcmp(c, "MODE")) handle_mode(srv, lc, msg);
    else if (!strcmp(c, "PRIVMSG") || !strcmp(c, "NOTICE") || !strcmp(c, "TAGMSG")) handle_message(srv, lc, msg);
    else if (!strcmp(c, "INVITE")) handle_invite(srv, lc, msg);
    else if (!strcmp(c, "PUSH")) handle_push(srv, lc, msg);
    else if (!strcmp(c, "WALLOPS") || !strcmp(c, "GLOBOPS")) handle_wallops(srv, lc, msg);
    else if (!strcmp(c, "GLINE")) handle_gline(srv, lc, msg);
    else if (!strcmp(c, "UNGLINE")) handle_ungline(srv, lc, msg);
    else if (!strcmp(c, "RENAME")) handle_rename(srv, lc, msg);
    else if (!strcmp(c, "RSQUIT")) handle_rsquit(srv, lc, msg);
    else if (!strcmp(c, "ACCT")) handle_acct(srv, lc, msg);
    else if (!strcmp(c, "ACCTDEL")) handle_acctdel(srv, lc, msg);
    else if (!strcmp(c, "EOB")) log_info("netsync", "end of burst from %s", lc->peer_name);
    /* PING/PONG are answered in link.c; anything unknown is ignored (forward compatibility). */
}

/* --- local events going out ---------------------------------------------------------------------------- */

void netsync_introduce_user(server_t *srv, client_t *cl) {
    netsync_assign_uid(srv, cl);
    if (!cl->nick_ts) cl->nick_ts = (long)time(NULL);
    if (!netsync_has_links(srv)) return;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) send_uid_line(srv, lc, cl);
}

void netsync_user_quit(server_t *srv, client_t *cl, const char *reason) {
    if (!cl->uid[0] || cl->remote || !netsync_has_links(srv)) return;
    char line[500];
    irc_build(line, sizeof line, NULL, 0, cl->uid, "QUIT", NULL, 0, reason ? reason : "");
    flood(srv, NULL, line);
}

void netsync_user_nick(server_t *srv, client_t *cl) {
    cl->nick_ts = (long)time(NULL);
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[300], ts[24];
    snprintf(ts, sizeof ts, "%ld", cl->nick_ts);
    const char *p[] = {cl->nick, ts};
    irc_build(line, sizeof line, NULL, 0, cl->uid, "NICK", p, 2, NULL);
    flood(srv, NULL, line);
}

void netsync_user_modes(server_t *srv, client_t *cl) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char modes[40], line[200];
    umodes_to_string(cl, modes, sizeof modes);
    irc_build(line, sizeof line, NULL, 0, cl->uid, "UMODE", (const char *[]){modes}, 1, NULL);
    flood(srv, NULL, line);
}

void netsync_user_away(server_t *srv, client_t *cl) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[500];
    irc_build(line, sizeof line, NULL, 0, cl->uid, "AWAY", NULL, 0, cl->is_away ? cl->away : "");
    flood(srv, NULL, line);
}

void netsync_user_chghost(server_t *srv, client_t *cl) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[400];
    const char *p[] = {cl->uid, cl->user, cl->host};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "CHGHOST", p, 3, NULL);
    flood(srv, NULL, line);
}

void netsync_user_setname(server_t *srv, client_t *cl) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[500];
    irc_build(line, sizeof line, NULL, 0, cl->uid, "SETNAME", NULL, 0, cl->realname);
    flood(srv, NULL, line);
}

void netsync_user_account(server_t *srv, client_t *cl) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[300];
    const char *p[] = {cl->uid, cl->account[0] ? cl->account : "*"};
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "ACCOUNT", p, 2, NULL);
    flood(srv, NULL, line);
}

void netsync_chan_join(server_t *srv, channel_t *chan, client_t *cl, int created) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[900], ts[24];
    snprintf(ts, sizeof ts, "%ld", (long)chan->created);
    if (!created) {
        irc_build(line, sizeof line, NULL, 0, cl->uid, "JOIN", (const char *[]){ts, chan->name}, 2, NULL);
        flood(srv, NULL, line);
        return;
    }
    char modestr[360];
    channel_modes_string(chan, modestr, sizeof modestr);
    const char *p[14] = {ts, chan->name};
    int np = 2;
    char *save = NULL;
    for (char *t = strtok_r(modestr, " ", &save); t && np < 12; t = strtok_r(NULL, " ", &save)) p[np++] = t;
    member_t *m = channel_find_member(chan, cl);
    char tok[24], pre[8];
    rank_prefix_all(m ? m->rank : 0, pre);
    snprintf(tok, sizeof tok, "%s%s", pre, cl->uid);
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "SJOIN", p, np, tok);
    flood(srv, NULL, line);
}

void netsync_chan_part(server_t *srv, channel_t *chan, client_t *cl, const char *reason) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[500];
    irc_build(line, sizeof line, NULL, 0, cl->uid, "PART", (const char *[]){chan->name}, 1, reason);
    flood(srv, NULL, line);
}

void netsync_chan_kick(server_t *srv, channel_t *chan, client_t *kicker, client_t *target, const char *reason) {
    if (!target->uid[0] || !netsync_has_links(srv)) return;
    char line[500];
    const char *src = (kicker && kicker->uid[0]) ? kicker->uid : self_sid(srv);
    irc_build(line, sizeof line, NULL, 0, src, "KICK", (const char *[]){chan->name, target->uid}, 2, reason);
    flood(srv, NULL, line);
}

void netsync_chan_topic(server_t *srv, channel_t *chan, client_t *setter, const char *text) {
    if (!netsync_has_links(srv)) return;
    char line[700];
    const char *src = (setter && setter->uid[0]) ? setter->uid : self_sid(srv);
    irc_build(line, sizeof line, NULL, 0, src, "TOPIC", (const char *[]){chan->name}, 1, text);
    flood(srv, NULL, line);
}

void netsync_chan_mode(server_t *srv, channel_t *chan, client_t *setter, const char *modes, const char **args, int nargs) {
    if (!netsync_has_links(srv)) return;
    char line[900];
    const char *src = (setter && setter->uid[0]) ? setter->uid : self_sid(srv);
    const char *p[14] = {chan->name, modes};
    int np = 2, ai = 0;
    char sign = '+';
    for (const char *c = modes; *c && np < 14; c++) {
        if (*c == '+' || *c == '-') { sign = *c; continue; }
        int takes = strchr("kbeIohvqa", *c) != NULL || (sign == '+' && strchr("lfjL", *c) != NULL);
        if (!takes || ai >= nargs) continue;
        const char *a = args[ai++];
        if (strchr("ohvqa", *c)) { client_t *t = server_find_user(srv, a); if (t && t->uid[0]) a = t->uid; } /* nicks -> UIDs on the wire */
        p[np++] = a;
    }
    irc_build(line, sizeof line, NULL, 0, src, "MODE", p, np, NULL);
    flood(srv, NULL, line);
}

void netsync_chan_rename(server_t *srv, channel_t *chan, client_t *cl, const char *oldname, const char *reason) {
    if (!cl->uid[0] || !netsync_has_links(srv)) return;
    char line[500];
    irc_build(line, sizeof line, NULL, 0, cl->uid, "RENAME", (const char *[]){oldname, chan->name}, 2, reason);
    flood(srv, NULL, line);
}

void netsync_invite(server_t *srv, client_t *from, client_t *target, channel_t *chan) {
    if (!from->uid[0] || !target->uid[0] || !netsync_has_links(srv)) return;
    char line[300];
    irc_build(line, sizeof line, NULL, 0, from->uid, "INVITE", (const char *[]){target->uid, chan->name}, 2, NULL);
    flood(srv, NULL, line);
}

void netsync_message(server_t *srv, client_t *from, const char *verb, const char *target, client_t *remote_target,
                     const char *text, const irc_tag_t *tags, int ntags) {
    if (!from->uid[0] || !netsync_has_links(srv)) return;
    char line[1500];
    const char *wire = remote_target ? remote_target->uid : target;
    irc_build(line, sizeof line, tags, ntags, from->uid, verb, (const char *[]){wire}, 1, text);
    if (remote_target) route_to(srv, remote_target->nserver, line); else flood(srv, NULL, line);
}

void netsync_kill(server_t *srv, client_t *oper, client_t *target, const char *reason) {
    if (!target->remote || !target->nserver) return;
    char line[400];
    irc_build(line, sizeof line, NULL, 0, oper->uid[0] ? oper->uid : self_sid(srv), "KILL", (const char *[]){target->uid}, 1, reason);
    route_to(srv, target->nserver, line);
}

void netsync_wallops(server_t *srv, client_t *from, const char *verb, const char *text) {
    if (!from->uid[0] || !netsync_has_links(srv)) return;
    char line[600];
    irc_build(line, sizeof line, NULL, 0, from->uid, verb, NULL, 0, text);
    flood(srv, NULL, line);
}

void netsync_gline(server_t *srv, const char *mask, const char *setter, long expires, const char *reason) {
    if (!netsync_has_links(srv)) return;
    char line[600], exp[24];
    snprintf(exp, sizeof exp, "%ld", expires);
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "GLINE", (const char *[]){mask, setter, exp}, 3, reason);
    flood(srv, NULL, line);
}

void netsync_ungline(server_t *srv, const char *mask) {
    if (!netsync_has_links(srv)) return;
    char line[300];
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "UNGLINE", (const char *[]){mask}, 1, NULL);
    flood(srv, NULL, line);
}

void netsync_push(server_t *srv, client_t *target, const char *rawline) {
    if (!target->remote || !target->nserver) return;
    char line[900];
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "PUSH", (const char *[]){target->uid}, 1, rawline);
    route_to(srv, target->nserver, line);
}

void netsync_squit_command(server_t *srv, client_t *oper, const char *name, const char *reason) {
    netserver_t *s = netsync_find_name(srv, name);
    if (!s || s == srv->self_srv) { notice_self(srv, oper, "No such server"); return; }
    if (s->route && s == s->route->nserver) { /* a direct link: close it */
        char m[200];
        snprintf(m, sizeof m, "Closed link to %s (%s)", s->name, reason);
        notice_self(srv, oper, m);
        link_close(srv, s->route);
        return;
    }
    /* a server further away: ask the server it hangs off (hop 1 from there) to close that link -- routed, not flooded,
     * because only its own uplink may remove it; the netsplit then propagates normally. */
    char line[300];
    irc_build(line, sizeof line, NULL, 0, self_sid(srv), "RSQUIT", (const char *[]){s->sid}, 1, reason);
    route_to(srv, s, line);
    notice_self(srv, oper, "SQUIT request sent toward that server");
}
