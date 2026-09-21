#include "server.h"
#include "cmd.h"
#include "log.h"
#include "proto.h"
#include "spam.h"
#include "vendor/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* "SekurIRCd-1.0.4(20260921-abc1234)" -- the daemon-name+version+build form wire fields that name
 * the software use (004 MYINFO, 351 VERSION), matching UnrealIRCd/InspIRCd
 * convention. cfg.server.version stays the bare number everywhere else
 * (logging, ADMIN, MOTD %version%, etc). */
void server_software_version(const server_t *srv, char *buf, size_t bufsz) {
    snprintf(buf, bufsz, "SekurIRCd-%s(%s)", srv->cfg.server.version, sekurircd_build);
}

int server_init(server_t *srv, const config_t *cfg) {
    memset(srv, 0, sizeof *srv);
    srv->cfg = *cfg;
    srv->listen_fd = -1;
    srv->tls_listen_fd = -1;
    srv->link_listen_fd = -1;
    srv->start_time = time(NULL);
    server_load_motd(srv);

    char accounts_path[CFG_PATH];
    int has_path = config_accounts_path(&srv->cfg, accounts_path, sizeof accounts_path);
    accounts_init(&srv->accounts, has_path ? accounts_path : NULL);

    server_kline_load(srv);
    spam_reload(srv);
    return 0;
}

static void load_textfile(textfile_t *tf, const char *path) {
    tf->n = 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return; /* missing file -> ERR_NOMOTD / ERR_NORULES on request */
    char line[MOTD_LINE_LEN];
    while (tf->n < MOTD_MAX_LINES && fgets(line, sizeof line, fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        snprintf(tf->lines[tf->n++], MOTD_LINE_LEN, "%s", line);
    }
    fclose(fp);
}

void server_load_motd(server_t *srv) {
    char path[CFG_PATH];
    config_motd_path(&srv->cfg, path, sizeof path);
    load_textfile(&srv->motd, path);
    config_oper_motd_path(&srv->cfg, path, sizeof path);
    load_textfile(&srv->oper_motd, path);
    config_rules_path(&srv->cfg, path, sizeof path);
    load_textfile(&srv->rules, path);
}

int server_rehash(server_t *srv, char *errbuf, size_t errbufsz) {
    if (srv->cfg.path[0] == '\0') {
        snprintf(errbuf, errbufsz, "running on built-in defaults, nothing to reload");
        return -1;
    }
    config_t tmp;
    if (config_load(srv->cfg.path, &tmp, errbuf, errbufsz) != 0) return -1;
    /* bind/port/TLS listeners are not re-bound on rehash (same as Python) --
     * only the config values themselves swap in. */
    srv->cfg = tmp;
    server_load_motd(srv);
    spam_reload(srv);
    return 0;
}

client_t *server_find_user(server_t *srv, const char *nick) {
    char cf[NICKLEN];
    irc_casefold(cf, sizeof cf, nick);
    client_t *cl;
    HASH_FIND_STR(srv->users, cf, cl);
    return cl;
}

channel_t *server_find_channel(server_t *srv, const char *name) {
    char cf[CHAN_NAMELEN];
    irc_casefold(cf, sizeof cf, name);
    channel_t *chan;
    HASH_FIND_STR(srv->channels, cf, chan);
    return chan;
}

channel_t *server_get_or_create_channel(server_t *srv, const char *name) {
    channel_t *chan = server_find_channel(srv, name);
    if (chan) return chan;
    char cf[CHAN_NAMELEN];
    irc_casefold(cf, sizeof cf, name);
    chan = channel_new(name, cf);
    if (!chan) return NULL;
    HASH_ADD_STR(srv->channels, casefold_name, chan);

    for (const char *p = srv->cfg.channels.default_modes; *p; p++) {
        switch (*p) {
            case 'n': chan->modes |= CMODE_N; break;
            case 'i': chan->modes |= CMODE_I; break;
            case 'p': chan->modes |= CMODE_P; break;
            case 't': chan->modes |= CMODE_T; break;
            case 's': chan->modes |= CMODE_S; break;
            case 'm': chan->modes |= CMODE_M; break;
            case 'P': chan->modes |= CMODE_PERM; break;
            case 'C': chan->modes |= CMODE_NOCTCP; break;
            case 'T': chan->modes |= CMODE_NONOTICE; break;
            case 'S': chan->modes |= CMODE_STRIPCOLOR; break;
            case 'V': chan->modes |= CMODE_NOINVITE; break;
            case 'Q': chan->modes |= CMODE_NOKICK; break;
            case 'N': chan->modes |= CMODE_NONICK; break;
            case 'z': chan->modes |= CMODE_Z; break;
            default: break;
        }
    }
    return chan;
}

typedef struct ipcount {
    char ip[64];
    int n;
    UT_hash_handle hh;
} ipcount_t;

int server_ip_count(server_t *srv, const char *ip) {
    ipcount_t *e;
    HASH_FIND_STR(srv->ip_counts, ip, e);
    return e ? e->n : 0;
}

static void ip_count_inc(server_t *srv, const char *ip) {
    ipcount_t *e;
    HASH_FIND_STR(srv->ip_counts, ip, e);
    if (!e) {
        e = calloc(1, sizeof *e);
        if (!e) return; /* the cap just isn't enforced for this one connection */
        snprintf(e->ip, sizeof e->ip, "%s", ip);
        HASH_ADD_STR(srv->ip_counts, ip, e);
    }
    e->n++;
}

static void ip_count_dec(server_t *srv, const char *ip) {
    ipcount_t *e;
    HASH_FIND_STR(srv->ip_counts, ip, e);
    if (!e) return;
    if (--e->n <= 0) { HASH_DEL(srv->ip_counts, e); free(e); }
}

void server_add_connection(server_t *srv, client_t *cl) {
    cl->all_next = srv->all_clients;
    cl->all_prev = NULL;
    if (srv->all_clients) srv->all_clients->all_prev = cl;
    srv->all_clients = cl;
    srv->n_clients++;
    ip_count_inc(srv, cl->ip);
}

static void unlink_connection(server_t *srv, client_t *cl) {
    /* A service pseudo-client (fd == -1, see link.h) was never linked into
     * all_clients in the first place (server_add_connection is only called
     * for a real accepted socket) -- its all_prev/all_next are both NULL
     * from calloc, which is indistinguishable from "the sole entry in the
     * list". Unlinking it anyway would hit the `else` branch below and
     * unconditionally null out srv->all_clients, silently dropping every
     * other connected client from the poll loop. Guard on fd >= 0. */
    if (cl->fd < 0) return;
    if (cl->all_prev) cl->all_prev->all_next = cl->all_next;
    else srv->all_clients = cl->all_next;
    if (cl->all_next) cl->all_next->all_prev = cl->all_prev;
    srv->n_clients--;
    ip_count_dec(srv, cl->ip);
}

void server_add_user(server_t *srv, client_t *cl) {
    HASH_ADD_STR(srv->users, casefold_nick, cl);
    int n = HASH_COUNT(srv->users);
    if (n > srv->max_users_seen) srv->max_users_seen = n;
}

int server_attach_membership(client_t *cl, channel_t *chan) {
    chan_node_t *node = malloc(sizeof *node);
    if (!node) return -1;
    node->chan = chan;
    node->next = cl->channels;
    cl->channels = node;
    return 0;
}

void server_detach_membership(client_t *cl, channel_t *chan) {
    chan_node_t **pp = &cl->channels;
    while (*pp) {
        if ((*pp)->chan == chan) {
            chan_node_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

void server_maybe_drop_channel(server_t *srv, channel_t *chan) {
    if (channel_member_count(chan) > 0) return;
    if (chan->modes & CMODE_PERM) return; /* +P: survives going empty */
    HASH_DEL(srv->channels, chan);
    channel_free(chan);
}

void server_broadcast_channel(channel_t *chan, const char *line, client_t *except) {
    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        if (m->client == except) continue;
        client_send(m->client, line);
    }
}

void server_send_common_channels(server_t *srv, client_t *cl, const char *line, unsigned int cap) {
    uint64_t gen = ++srv->fanout_gen;
    cl->fanout_mark = gen; /* never send to cl itself */
    for (chan_node_t *n = cl->channels; n; n = n->next) {
        member_t *m, *tmp;
        HASH_ITER(hh, n->chan->members, m, tmp) {
            client_t *c = m->client;
            if (c->fanout_mark == gen) continue;
            c->fanout_mark = gen;
            if (cap && !(c->caps & cap)) continue;
            client_send(c, line);
        }
    }
}

static server_t *g_log_srv;

#define SNOTE_MAX 20
#define SNOTE_WINDOW 5.0

static double monotonic_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Every log_write() call in the process passes through here (regardless of
 * tag), unlike server_notify_opers's targeted snotes -- so it needs its own
 * flood guard, same ring-buffer shape as SNOTE_MAX/SNOTE_WINDOW below.
 * Without this, connection-noise log spam (e.g. link listener probes) floods
 * #server-debug at min_level=INFO with no suppression at all. */
static void debug_log_hook(log_level_t level, const char *tag, const char *msg) {
    static int busy; /* a send path that itself logs must not recurse back in */
    static double times[SNOTE_MAX + 1];
    static int head, count, suppressed;
    server_t *srv = g_log_srv;
    if (busy || !srv || !srv->cfg.debug_channel.enabled) return;
    if (level < log_level_from_name(srv->cfg.debug_channel.min_level)) return;
    channel_t *chan = server_find_channel(srv, srv->cfg.debug_channel.name);
    if (!chan) return;

    busy = 1;
    double now = monotonic_now();
    int ringsz = (int)(sizeof times / sizeof times[0]);
    if (count < ringsz) {
        times[(head + count) % ringsz] = now;
        count++;
    } else {
        times[head] = now;
        head = (head + 1) % ringsz;
    }
    while (count > 0 && times[head] < now - SNOTE_WINDOW) {
        head = (head + 1) % ringsz;
        count--;
    }
    if (count > SNOTE_MAX) {
        suppressed++;
        busy = 0;
        return;
    }

    char text[480], line[600];
    if (suppressed) {
        snprintf(text, sizeof text, "[%s] %s: %s (+%d more log line(s) suppressed)",
                  log_level_name(level), tag, msg, suppressed);
        suppressed = 0;
    } else {
        snprintf(text, sizeof text, "[%s] %s: %s", log_level_name(level), tag, msg);
    }
    const char *p[] = {chan->name};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "NOTICE", p, 1, text);
    server_broadcast_channel(chan, line, NULL);
    busy = 0;
}

void server_install_debug_log_hook(server_t *srv) {
    g_log_srv = srv;
    log_set_hook(debug_log_hook);
}

void server_notify_opers(server_t *srv, const char *message) {
    double now = monotonic_now();

    /* Push `now`, evicting the oldest entry first if the ring (sized to
     * SNOTE_MAX+1) is already full -- see server.h's doc comment on why a
     * fixed ring gives the same suppression decision as Python's deque. */
    int ringsz = (int)(sizeof srv->snote_times / sizeof srv->snote_times[0]);
    if (srv->snote_count < ringsz) {
        int tail = (srv->snote_head + srv->snote_count) % ringsz;
        srv->snote_times[tail] = now;
        srv->snote_count++;
    } else {
        srv->snote_times[srv->snote_head] = now;
        srv->snote_head = (srv->snote_head + 1) % ringsz;
    }
    while (srv->snote_count > 0 && srv->snote_times[srv->snote_head] < now - SNOTE_WINDOW) {
        srv->snote_head = (srv->snote_head + 1) % ringsz;
        srv->snote_count--;
    }
    if (srv->snote_count > SNOTE_MAX) {
        srv->snote_suppressed++;
        if (srv->snote_suppressed == 1)
            log_warn("oper", "oper-notice flood guard tripped; suppressing further notices for up to %.0fs", SNOTE_WINDOW);
        return;
    }

    char text[500];
    if (srv->snote_suppressed) {
        snprintf(text, sizeof text, "*** Notice -- %s (+%d more notice(s) were suppressed)", message, srv->snote_suppressed);
        srv->snote_suppressed = 0;
    } else {
        snprintf(text, sizeof text, "*** Notice -- %s", message);
    }
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if ((u->umodes & UMODE_O) && (u->umodes & UMODE_S)) notice_self(srv, u, text);
    }
}

void server_login(server_t *srv, client_t *cl, const char *account) {
    snprintf(cl->account, sizeof cl->account, "%s", account);
    cl->umodes |= UMODE_R;
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char msg[220];
    snprintf(msg, sizeof msg, "You are now logged in as %s", account);
    const char *p[] = {prefix, account};
    client_reply(cl, N_LOGGEDIN, p, 2, msg);

    char line[400];
    const char *pa[] = {account};
    irc_build(line, sizeof line, NULL, 0, prefix, "ACCOUNT", pa, 1, NULL);
    server_send_common_channels(srv, cl, line, CAP_ACCOUNT_NOTIFY);
}

void server_remove_client(server_t *srv, client_t *cl, const char *quit_reason) {
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[512];
    irc_build(line, sizeof line, NULL, 0, prefix, "QUIT", NULL, 0, quit_reason ? quit_reason : "");

    if (cl->registered && !cl->is_service) {
        server_whowas_record(srv, cl->nick, cl->user, cl->host, cl->realname);
        server_monitor_notify(srv, cl, 0);
        server_watch_notify(srv, cl, 0);

        /* ircd-hybrid format, so HOPM-style bots can track exits. */
        char snote[400];
        snprintf(snote, sizeof snote, "Client exiting: %s (%s@%s) [%s] [%s]", cl->nick, cl->user, cl->host,
                 quit_reason ? quit_reason : "", cl->ip);
        server_notify_opers(srv, snote);
    }

    server_send_common_channels(srv, cl, line, 0);
    chan_node_t *n = cl->channels;
    while (n) {
        chan_node_t *next = n->next;
        channel_remove_member(n->chan, cl);
        server_maybe_drop_channel(srv, n->chan);
        free(n);
        n = next;
    }
    cl->channels = NULL;

    if (cl->casefold_nick[0]) {
        client_t *found;
        HASH_FIND_STR(srv->users, cl->casefold_nick, found);
        if (found == cl) HASH_DEL(srv->users, cl);
    }
    unlink_connection(srv, cl);
    client_free(cl);
}

void server_send_isupport(server_t *srv, client_t *cl) {
    char netbuf[CFG_STR + 16];
    snprintf(netbuf, sizeof netbuf, "NETWORK=%s", srv->cfg.server.network);
    char nicklen[32], chanlen[32], topiclen[32];
    snprintf(nicklen, sizeof nicklen, "NICKLEN=%d", srv->cfg.security.max_nick_length);
    snprintf(chanlen, sizeof chanlen, "CHANNELLEN=%d", 50);
    snprintf(topiclen, sizeof topiclen, "TOPICLEN=%d", CHAN_TOPICLEN - 1);

    const char *tokens[] = {
        netbuf, "CHANTYPES=#", "CHANMODES=beI,k,l,imnprstzCNPQSTV", "PREFIX=(ohv)@%+",
        nicklen, chanlen, topiclen, "CASEMAPPING=ascii", "MODES=6",
        "STATUSMSG=@%+", "AWAYLEN=400", "KICKLEN=400",
        "MAXLIST=beI:100", "EXCEPTS=e", "INVEX=I", "MONITOR=100", "WATCH=128", "SILENCE=15",
        "EXTBAN=,a", "ELIST=MNU", "WHOX", "MAXCHANNELS=200", "BOT=B",
    };
    int total = (int)(sizeof tokens / sizeof tokens[0]);
    for (int i = 0; i < total; i += 12) {
        int chunk = total - i < 12 ? total - i : 12;
        client_reply(cl, N_ISUPPORT, tokens + i, chunk, "are supported by this server");
    }
}

void server_send_lusers(server_t *srv, client_t *cl) {
    /* srv->users is local-registered clients only (v1.0.1's link.c doesn't
     * mirror remote users -- see link.h's doc comment), so "network-wide"
     * and "local" counts happen to coincide here; kept as separate n_users/
     * n_local names anyway so this reads the same as the Python original
     * and doesn't need touching if link.c ever grows real mirroring. */
    int n_users = HASH_COUNT(srv->users);
    int n_local = n_users;
    int n_opers = 0, n_invisible = 0;
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if (u->umodes & UMODE_O) n_opers++;
        if (u->umodes & UMODE_I) n_invisible++;
    }
    int n_chans = HASH_COUNT(srv->channels);

    int n_servers = 1;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc->authenticated) n_servers++;

    int n_unknown = 0;
    for (client_t *c = srv->all_clients; c; c = c->all_next)
        if (!c->registered) n_unknown++;

    char msg[160], nbuf[32];
    snprintf(msg, sizeof msg, "There are %d users and %d invisible on %d servers",
             n_users - n_invisible, n_invisible, n_servers);
    client_reply(cl, N_LUSERCLIENT, NULL, 0, msg);

    snprintf(nbuf, sizeof nbuf, "%d", n_opers);
    const char *p1[] = {nbuf};
    client_reply(cl, N_LUSEROP, p1, 1, "IRC Operators online");

    snprintf(nbuf, sizeof nbuf, "%d", n_unknown);
    const char *p0[] = {nbuf};
    client_reply(cl, N_LUSERUNKNOWN, p0, 1, "unknown connection(s)");

    char nbuf2[32];
    snprintf(nbuf2, sizeof nbuf2, "%d", n_chans);
    const char *p2[] = {nbuf2};
    client_reply(cl, N_LUSERCHANNELS, p2, 1, "channels formed");

    snprintf(msg, sizeof msg, "I have %d clients and %d servers", n_local, n_servers);
    client_reply(cl, N_LUSERME, NULL, 0, msg);

    char lbuf[16], mbuf[16];
    snprintf(lbuf, sizeof lbuf, "%d", n_local);
    snprintf(mbuf, sizeof mbuf, "%d", srv->max_users_seen);
    const char *p3[] = {lbuf, mbuf};
    snprintf(msg, sizeof msg, "Current local users: %d  Max: %d", n_local, srv->max_users_seen);
    client_reply(cl, N_LOCALUSERS, p3, 2, msg);

    char gbuf[16];
    snprintf(gbuf, sizeof gbuf, "%d", n_users);
    const char *p4[] = {gbuf, mbuf};
    snprintf(msg, sizeof msg, "Current global users: %d  Max: %d", n_users, srv->max_users_seen);
    client_reply(cl, N_GLOBALUSERS, p4, 2, msg);

    snprintf(msg, sizeof msg, "Highest connection count: %d (%d clients) (%ld connections received)",
             srv->max_users_seen, srv->max_users_seen, srv->total_connections);
    client_reply(cl, N_STATSCONN, NULL, 0, msg);
}

static void send_textfile(client_t *cl, const textfile_t *tf, const char *start, const char *line,
                          const char *end, const char *none, const char *none_txt, const char *title,
                          const char *endtxt) {
    if (tf->n == 0) {
        client_reply(cl, none, NULL, 0, none_txt);
        return;
    }
    client_reply(cl, start, NULL, 0, title);
    char msg[MOTD_LINE_LEN + 4];
    for (int i = 0; i < tf->n; i++) {
        snprintf(msg, sizeof msg, "- %s", tf->lines[i]);
        client_reply(cl, line, NULL, 0, msg);
    }
    client_reply(cl, end, NULL, 0, endtxt);
}

void server_send_motd(server_t *srv, client_t *cl) {
    char title[CFG_STR + 32];
    snprintf(title, sizeof title, "- %s Message of the day - ", srv->cfg.server.name);
    send_textfile(cl, &srv->motd, N_MOTDSTART, N_MOTD, N_ENDOFMOTD, N_NOMOTD, "MOTD File is missing",
                  title, "End of /MOTD command.");
}

void server_send_oper_motd(server_t *srv, client_t *cl) {
    char title[CFG_STR + 32];
    snprintf(title, sizeof title, "- %s Operator message of the day - ", srv->cfg.server.name);
    send_textfile(cl, &srv->oper_motd, N_MOTDSTART, N_MOTD, N_ENDOFMOTD, N_NOMOTD, "OPERMOTD File is missing",
                  title, "End of /OPERMOTD command.");
}

void server_send_rules(server_t *srv, client_t *cl) {
    char title[CFG_STR + 32];
    snprintf(title, sizeof title, "- %s server rules - ", srv->cfg.server.name);
    send_textfile(cl, &srv->rules, N_RULESSTART, N_RULES, N_ENDOFRULES, N_NORULES, "RULES File is missing",
                  title, "End of /RULES command.");
}

void server_send_welcome(server_t *srv, client_t *cl) {
    char msg[768]; /* worst case: CFG_STR network/name/version + NICKLEN + USERLEN + HOSTLEN */
    snprintf(msg, sizeof msg, "Welcome to the %s IRC Network %s!%s@%s",
             srv->cfg.server.network, cl->nick, cl->user, cl->host);
    client_reply(cl, N_WELCOME, NULL, 0, msg);

    snprintf(msg, sizeof msg, "Your host is %s, running version %s",
             srv->cfg.server.name, srv->cfg.server.version);
    client_reply(cl, N_YOURHOST, NULL, 0, msg);

    char created[64];
    struct tm tmv;
    localtime_r(&srv->start_time, &tmv);
    strftime(created, sizeof created, "%a %b %d %Y at %H:%M:%S %Z", &tmv);
    snprintf(msg, sizeof msg, "This server was created %s", created);
    client_reply(cl, N_CREATED, NULL, 0, msg);

    char swver[CFG_STR + 16];
    server_software_version(srv, swver, sizeof swver);
    const char *myinfo[] = {srv->cfg.server.name, swver, "diwsoZrpIHqRD", "beIklnimpstzrovhPCTSVQN"};
    client_reply(cl, N_MYINFO, myinfo, 4, NULL);

    if (cl->ssl) {
        char tlsmsg[128];
        snprintf(tlsmsg, sizeof tlsmsg, "*** You are connected to %s with %s/%s",
                 srv->cfg.server.name, SSL_get_version(cl->ssl), SSL_get_cipher_name(cl->ssl));
        notice_self(srv, cl, tlsmsg);
    }

    /* 042 RPL_YOURID: a connection-local opaque id, not a network-wide UID
     * -- see client_t.your_id's doc comment. */
    const char *idp[] = {cl->your_id};
    client_reply(cl, N_YOURID, idp, 1, "your unique ID");

    server_send_isupport(srv, cl);
    server_send_lusers(srv, cl);
    server_send_motd(srv, cl);

    char modestr[16];
    client_mode_string(cl, modestr, sizeof modestr);
    client_reply(cl, N_UMODEIS, NULL, 0, modestr);
}

/* --- K/G-lines --------------------------------------------------------------- */

static void kline_save(server_t *srv) {
    char path[CFG_PATH];
    if (!config_klines_path(&srv->cfg, path, sizeof path)) return; /* not configured -- in-memory only */

    cJSON *arr = cJSON_CreateArray();
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "mask", k->mask);
        cJSON_AddStringToObject(o, "reason", k->reason);
        cJSON_AddStringToObject(o, "set_by", k->set_by);
        cJSON_AddStringToObject(o, "line_type", k->line_type);
        cJSON_AddNumberToObject(o, "expires_at", (double)k->expires_at);
        cJSON_AddItemToArray(arr, o);
    }
    char *text = cJSON_Print(arr);
    /* sizeof needs room for path + ".tmp" + NUL; at CFG_PATH + 4 a maximal
     * path truncated to "....tm" and renamed over a different file. */
    char tmp[CFG_PATH + 5];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (text) {
        FILE *fp = fopen(tmp, "wb");
        if (fp) { fputs(text, fp); fclose(fp); rename(tmp, path); }
        free(text);
    }
    cJSON_Delete(arr);
}

void server_kline_load(server_t *srv) {
    char path[CFG_PATH];
    if (!config_klines_path(&srv->cfg, path, sizeof path)) return;
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0) { fclose(fp); return; }
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(fp); return; }
    size_t rd = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[rd] = '\0';
    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (!arr) return;

    cJSON *o;
    cJSON_ArrayForEach(o, arr) {
        kline_entry_t *k = calloc(1, sizeof *k);
        cJSON *v;
        if ((v = cJSON_GetObjectItemCaseSensitive(o, "mask")) && cJSON_IsString(v)) snprintf(k->mask, sizeof k->mask, "%s", v->valuestring);
        if ((v = cJSON_GetObjectItemCaseSensitive(o, "reason")) && cJSON_IsString(v)) snprintf(k->reason, sizeof k->reason, "%s", v->valuestring);
        if ((v = cJSON_GetObjectItemCaseSensitive(o, "set_by")) && cJSON_IsString(v)) snprintf(k->set_by, sizeof k->set_by, "%s", v->valuestring);
        if ((v = cJSON_GetObjectItemCaseSensitive(o, "line_type")) && cJSON_IsString(v)) snprintf(k->line_type, sizeof k->line_type, "%s", v->valuestring);
        if ((v = cJSON_GetObjectItemCaseSensitive(o, "expires_at")) && cJSON_IsNumber(v)) k->expires_at = (time_t)v->valuedouble;
        k->next = srv->klines;
        srv->klines = k;
    }
    cJSON_Delete(arr);
}

void server_kline_prune_expired(server_t *srv) {
    time_t now = time(NULL);
    kline_entry_t **pp = &srv->klines;
    int pruned = 0;
    while (*pp) {
        if ((*pp)->expires_at && (*pp)->expires_at <= now) {
            kline_entry_t *dead = *pp;
            char snote[350];
            snprintf(snote, sizeof snote, "Expiring %s-Line '%s' (%s)", dead->line_type, dead->mask, dead->reason);
            server_notify_opers(srv, snote);
            *pp = dead->next;
            free(dead);
            pruned = 1;
        } else {
            pp = &(*pp)->next;
        }
    }
    if (pruned) srv->klines_dirty = 1;
}

void server_kline_flush(server_t *srv) {
    if (!srv->klines_dirty) return;
    srv->klines_dirty = 0;
    kline_save(srv);
}

void server_kline_add(server_t *srv, const char *mask, const char *reason,
                       const char *set_by, const char *line_type, long duration_secs) {
    /* Refresh an existing identical line rather than appending a duplicate.
     * DNSBL verdicts arrive asynchronously, so several clients behind one
     * listed IP each used to append their own entry (and rewrite the whole
     * file), growing the list -- which every accept() then walks. */
    for (kline_entry_t *e = srv->klines; e; e = e->next) {
        if (strcasecmp(e->mask, mask) != 0 || strcmp(e->line_type, line_type) != 0) continue;
        time_t newexp = duration_secs > 0 ? time(NULL) + duration_secs : 0;
        /* 0 means permanent, which outranks any expiry. */
        if (newexp == 0 || e->expires_at == 0) e->expires_at = 0;
        else if (newexp > e->expires_at) e->expires_at = newexp;
        srv->klines_dirty = 1;
        return;
    }
    kline_entry_t *k = calloc(1, sizeof *k);
    if (!k) return;
    snprintf(k->mask, sizeof k->mask, "%s", mask);
    snprintf(k->reason, sizeof k->reason, "%s", reason);
    snprintf(k->set_by, sizeof k->set_by, "%s", set_by);
    snprintf(k->line_type, sizeof k->line_type, "%s", line_type);
    k->expires_at = duration_secs > 0 ? time(NULL) + duration_secs : 0;
    k->next = srv->klines;
    srv->klines = k;
    srv->klines_dirty = 1;

    char snote[400];
    snprintf(snote, sizeof snote, "%s added %s-Line '%s' (%s)", set_by, line_type, mask, reason);
    server_notify_opers(srv, snote);
}

int server_kline_remove(server_t *srv, const char *mask) {
    kline_entry_t **pp = &srv->klines;
    while (*pp) {
        if (strcasecmp((*pp)->mask, mask) == 0) {
            kline_entry_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            srv->klines_dirty = 1;
            char snote[350];
            snprintf(snote, sizeof snote, "removed line on '%s'", mask);
            server_notify_opers(srv, snote);
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}

int server_line_mask_hits(const char *mask, const char *line_type, const char *ip,
                           const char *user, const char *host, int ident_confirmed) {
    if (ip && ip[0] && irc_glob_match(mask, ip)) return 1;
    /* A Z-line is deliberately IP-only: it's the pre-registration ban that
     * connect-flood and DNSBL apply at accept(), before any user/host exists.
     * K and G also match user@host -- which is what /HELP KLINE has always
     * promised, and what an oper typing a hostname mask expects. Until this
     * they matched the IP and nothing else, making K, G and Z three names for
     * exactly the same ban. */
    if (line_type && line_type[0] == 'Z') return 0;
    if (!host || !host[0]) return 0;
    if (irc_host_mask_match(user, host, mask)) return 1;
    /* Try the tilde form too, so an oper needn't know whether the target's
     * ident was identd-confirmed to write a mask that bites. */
    if (user && user[0] && !ident_confirmed && user[0] != '~') {
        char tilde[USERLEN + 2];
        snprintf(tilde, sizeof tilde, "~%s", user);
        if (irc_host_mask_match(tilde, host, mask)) return 1;
    }
    return 0;
}

const char *server_kline_match(server_t *srv, const char *ip, const char *user,
                                const char *host, int ident_confirmed) {
    static char reason_buf[300];
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        if (!server_line_mask_hits(k->mask, k->line_type, ip, user, host, ident_confirmed)) continue;
        snprintf(reason_buf, sizeof reason_buf, "%s-Lined: %s", k->line_type, k->reason);
        return reason_buf;
    }
    return NULL;
}

void server_free_tables(server_t *srv) {
    server_kline_flush(srv);
    spam_free(srv);
    kline_entry_t *k = srv->klines;
    while (k) { kline_entry_t *next = k->next; free(k); k = next; }
    srv->klines = NULL;
    ipcount_t *e, *tmp;
    HASH_ITER(hh, srv->ip_counts, e, tmp) { HASH_DEL(srv->ip_counts, e); free(e); }
}

/* --- WHOWAS -------------------------------------------------------------- */

void server_whowas_record(server_t *srv, const char *nick, const char *user,
                           const char *host, const char *realname) {
    whowas_entry_t *e = &srv->whowas[srv->whowas_head];
    snprintf(e->nick, sizeof e->nick, "%s", nick);
    snprintf(e->user, sizeof e->user, "%s", user);
    snprintf(e->host, sizeof e->host, "%s", host);
    snprintf(e->realname, sizeof e->realname, "%s", realname);
    srv->whowas_head = (srv->whowas_head + 1) % WHOWAS_MAX;
    if (srv->whowas_count < WHOWAS_MAX) srv->whowas_count++;
}

/* --- MONITOR --------------------------------------------------------------- */

void server_monitor_notify(server_t *srv, client_t *cl, int online) {
    char cf[NICKLEN];
    irc_casefold(cf, sizeof cf, cl->nick);
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);

    for (client_t *watcher = srv->all_clients; watcher; watcher = watcher->all_next) {
        if (watcher == cl) continue;
        for (int i = 0; i < watcher->n_monitor; i++) {
            /* ponytail: still O(watchers x list), but the first-byte reject
             * skips ~96% of the strcmps for free. An inverted index keyed by
             * watched nick is the upgrade if a deployment ever has enough
             * watchers x entries for this to show up in a profile. */
            if (watcher->monitor[i][0] != cf[0] || strcmp(watcher->monitor[i], cf) != 0) continue;
            const char *code = online ? N_MONONLINE : N_MONOFFLINE;
            const char *val = online ? prefix : cl->nick;
            client_reply(watcher, code, NULL, 0, val);
            break;
        }
    }
}

/* --- WATCH (legacy pre-MONITOR watch-list, numerics 600-607) --------------- */

void server_watch_notify(server_t *srv, client_t *cl, int online) {
    char cf[NICKLEN];
    irc_casefold(cf, sizeof cf, cl->nick);
    char timebuf[32];
    snprintf(timebuf, sizeof timebuf, "%ld", (long)(online ? cl->signon_time : time(NULL)));

    for (client_t *watcher = srv->all_clients; watcher; watcher = watcher->all_next) {
        if (watcher == cl) continue;
        for (int i = 0; i < watcher->n_watch; i++) {
            if (watcher->watch[i][0] != cf[0] || strcmp(watcher->watch[i], cf) != 0) continue;
            const char *p[] = {cl->nick, cl->user, cl->host, timebuf};
            client_reply(watcher, online ? N_LOGON : N_LOGOFF, p, 4, online ? "logged online" : "logged offline");
            break;
        }
    }
}
