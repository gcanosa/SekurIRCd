#include "server.h"
#include "proto.h"
#include "vendor/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* "SekurIRCd-1.0.1" -- the daemon-name+version form wire fields that name
 * the software use (004 MYINFO, 351 VERSION), matching UnrealIRCd/InspIRCd
 * convention. cfg.server.version stays the bare number everywhere else
 * (logging, ADMIN, MOTD %version%, etc). */
void server_software_version(const server_t *srv, char *buf, size_t bufsz) {
    snprintf(buf, bufsz, "SekurIRCd-%s", srv->cfg.server.version);
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
    return 0;
}

void server_load_motd(server_t *srv) {
    srv->n_motd_lines = 0;
    char path[CFG_PATH];
    config_motd_path(&srv->cfg, path, sizeof path);
    FILE *fp = fopen(path, "r");
    if (!fp) return; /* no MOTD file -> 422 ERR_NOMOTD, same as Python */
    char line[MOTD_LINE_LEN];
    while (srv->n_motd_lines < MOTD_MAX_LINES && fgets(line, sizeof line, fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        snprintf(srv->motd_lines[srv->n_motd_lines], MOTD_LINE_LEN, "%s", line);
        srv->n_motd_lines++;
    }
    fclose(fp);
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
    HASH_ADD_STR(srv->channels, casefold_name, chan);

    for (const char *p = srv->cfg.channels.default_modes; *p; p++) {
        switch (*p) {
            case 'n': chan->modes |= CMODE_N; break;
            case 'i': chan->modes |= CMODE_I; break;
            case 'p': chan->modes |= CMODE_P; break;
            case 't': chan->modes |= CMODE_T; break;
            case 's': chan->modes |= CMODE_S; break;
            case 'm': chan->modes |= CMODE_M; break;
            default: break; /* 'z' (secure-only) lands with TLS in a later phase */
        }
    }
    return chan;
}

void server_add_connection(server_t *srv, client_t *cl) {
    cl->all_next = srv->all_clients;
    cl->all_prev = NULL;
    if (srv->all_clients) srv->all_clients->all_prev = cl;
    srv->all_clients = cl;
    srv->n_clients++;
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
}

void server_add_user(server_t *srv, client_t *cl) {
    HASH_ADD_STR(srv->users, casefold_nick, cl);
    int n = HASH_COUNT(srv->users);
    if (n > srv->max_users_seen) srv->max_users_seen = n;
}

void server_attach_membership(client_t *cl, channel_t *chan) {
    chan_node_t *node = malloc(sizeof *node);
    node->chan = chan;
    node->next = cl->channels;
    cl->channels = node;
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

void server_remove_client(server_t *srv, client_t *cl, const char *quit_reason) {
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[512];
    irc_build(line, sizeof line, NULL, 0, prefix, "QUIT", NULL, 0, quit_reason ? quit_reason : "");

    if (cl->registered && !cl->is_service) {
        server_whowas_record(srv, cl->nick, cl->user, cl->host, cl->realname);
        server_monitor_notify(srv, cl, 0);
    }

    /* Notify each channel-mate at most once even if cl shares several
     * channels with them -- mark via a transient visited flag isn't worth
     * it at v1.0.1 scale; a client seeing one QUIT twice from two shared
     * channels is a real ircd bug class, so dedupe with a small seen-list. */
    client_t *seen[256];
    int n_seen = 0;

    chan_node_t *n = cl->channels;
    while (n) {
        chan_node_t *next = n->next;
        channel_t *chan = n->chan;
        member_t *m, *tmp;
        HASH_ITER(hh, chan->members, m, tmp) {
            if (m->client == cl) continue;
            int dup = 0;
            for (int i = 0; i < n_seen; i++) if (seen[i] == m->client) { dup = 1; break; }
            if (dup) continue;
            client_send(m->client, line);
            if (n_seen < 256) seen[n_seen++] = m->client;
        }
        channel_remove_member(chan, cl);
        server_maybe_drop_channel(srv, chan);
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

static void send_isupport(server_t *srv, client_t *cl) {
    char netbuf[CFG_STR + 16];
    snprintf(netbuf, sizeof netbuf, "NETWORK=%s", srv->cfg.server.network);
    char nicklen[32], chanlen[32], topiclen[32];
    snprintf(nicklen, sizeof nicklen, "NICKLEN=%d", srv->cfg.security.max_nick_length);
    snprintf(chanlen, sizeof chanlen, "CHANNELLEN=%d", 50);
    snprintf(topiclen, sizeof topiclen, "TOPICLEN=%d", CHAN_TOPICLEN - 1);

    const char *tokens[] = {
        netbuf, "CHANTYPES=#", "CHANMODES=beI,k,l,imnprstz", "PREFIX=(ohv)@%+",
        nicklen, chanlen, topiclen, "CASEMAPPING=ascii", "MODES=6",
        "STATUSMSG=@%+", "AWAYLEN=400", "KICKLEN=400",
        "MAXLIST=beI:100", "EXCEPTS=e", "INVEX=I", "MONITOR=100", "SILENCE=15",
        "EXTBAN=,a", "ELIST=MNU",
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

void server_send_motd(server_t *srv, client_t *cl) {
    if (srv->n_motd_lines == 0) {
        client_reply(cl, N_NOMOTD, NULL, 0, "MOTD File is missing");
        return;
    }
    char msg[MOTD_LINE_LEN + 64];
    snprintf(msg, sizeof msg, "- %s Message of the day - ", srv->cfg.server.name);
    client_reply(cl, N_MOTDSTART, NULL, 0, msg);
    for (int i = 0; i < srv->n_motd_lines; i++) {
        snprintf(msg, sizeof msg, "- %s", srv->motd_lines[i]);
        client_reply(cl, N_MOTD, NULL, 0, msg);
    }
    client_reply(cl, N_ENDOFMOTD, NULL, 0, "End of /MOTD command.");
}

void server_send_welcome(server_t *srv, client_t *cl) {
    char msg[512];
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
    const char *myinfo[] = {srv->cfg.server.name, swver, "diwsoZr", "ntimspklbovhzeIr"};
    client_reply(cl, N_MYINFO, myinfo, 4, NULL);

    /* 042 RPL_YOURID: a connection-local opaque id, not a network-wide UID
     * -- see client_t.conn_id's doc comment. */
    char idbuf[32];
    snprintf(idbuf, sizeof idbuf, "%llu", (unsigned long long)cl->conn_id);
    const char *idp[] = {idbuf};
    client_reply(cl, N_YOURID, idp, 1, "your unique ID");

    send_isupport(srv, cl);
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
    char tmp[CFG_PATH + 4];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "wb");
    if (fp) { fputs(text, fp); fclose(fp); rename(tmp, path); }
    free(text);
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
            *pp = dead->next;
            free(dead);
            pruned = 1;
        } else {
            pp = &(*pp)->next;
        }
    }
    if (pruned) kline_save(srv);
}

void server_kline_add(server_t *srv, const char *mask, const char *reason,
                       const char *set_by, const char *line_type, long duration_secs) {
    kline_entry_t *k = calloc(1, sizeof *k);
    snprintf(k->mask, sizeof k->mask, "%s", mask);
    snprintf(k->reason, sizeof k->reason, "%s", reason);
    snprintf(k->set_by, sizeof k->set_by, "%s", set_by);
    snprintf(k->line_type, sizeof k->line_type, "%s", line_type);
    k->expires_at = duration_secs > 0 ? time(NULL) + duration_secs : 0;
    k->next = srv->klines;
    srv->klines = k;
    kline_save(srv);
}

int server_kline_remove(server_t *srv, const char *mask) {
    kline_entry_t **pp = &srv->klines;
    while (*pp) {
        if (strcasecmp((*pp)->mask, mask) == 0) {
            kline_entry_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            kline_save(srv);
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}

const char *server_kline_match(server_t *srv, const char *ip) {
    static char reason_buf[300];
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        if (irc_glob_match(k->mask, ip)) {
            snprintf(reason_buf, sizeof reason_buf, "%s-Lined: %s", k->line_type, k->reason);
            return reason_buf;
        }
    }
    return NULL;
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
            if (strcmp(watcher->monitor[i], cf) != 0) continue;
            const char *code = online ? N_MONONLINE : N_MONOFFLINE;
            const char *val = online ? prefix : cl->nick;
            client_reply(watcher, code, NULL, 0, val);
            break;
        }
    }
}
