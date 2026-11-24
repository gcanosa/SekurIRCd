/* STATS [letter [server|nick]]: the RFC 1459/2812 letters plus the usual modern ircd ones (hybrid/ratbox/Unreal).
 * m u p v are open to everyone (and "l <your own nick>"); the rest need an oper. No letter, or one we don't know,
 * lists what you may ask. A server name, or the nick of a user on another server, makes that server answer. Every
 * request is told to that server's opers ("STATS x requested by ..."), as most ircds do.
 *
 * Letters, upper and lower case alike unless noted:
 *   b DNSBL zones + proxy scanner   c connect blocks (213)   d Z-lines (alias)   e ELINEs   f spam filters
 *   g G-lines   h hub/leaf rules (244/241)   i auth blocks (215)   k K-lines   l links / "l <nick>" (211; L hides IPs)
 *   m commands (212)   o oper blocks (243)   p opers online   P ports (220)   q reserved nicks (217)   s SHUNs
 *   t traffic   u uptime (242/250)   v servers   y classes (218)   z Z-lines   Z memory   ? link traffic
 */
#define _DARWIN_C_SOURCE /* macOS hides struct rusage.ru_maxrss under strict _POSIX_C_SOURCE */
#include "cmd.h"
#include "history.h"
#include "link.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <time.h>

static int is_oper(const client_t *cl) { return (cl->umodes & UMODE_O) != 0; }

/* 249 RPL_STATSDEBUG "<letter> :text", the free-form line hybrid and ratbox use. */
static void dbg(client_t *cl, char letter, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void dbg(client_t *cl, char letter, const char *fmt, ...) {
    char text[480], l[2] = {letter, 0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    client_reply(cl, N_STATSDEBUG, (const char *[]){l}, 1, text);
}

static const char *dur(long s, char *out, size_t sz) {
    if (s < 0) s = 0;
    long d = s / 86400, h = s / 3600 % 24, m = s / 60 % 60;
    if (d) snprintf(out, sz, "%ldd%02ldh%02ldm", d, h, m);
    else if (h) snprintf(out, sz, "%ldh%02ldm", h, m);
    else if (m) snprintf(out, sz, "%ldm%02lds", m, s % 60);
    else snprintf(out, sz, "%lds", s);
    return out;
}

static const char *num(unsigned long long v, char *out, size_t sz) { snprintf(out, sz, "%llu", v); return out; }

/* --- public -------------------------------------------------------------------------------------------------- */

static const server_t *g_sort_srv; /* qsort has no context argument */
static int cmp_cmd(const void *a, const void *b) {
    return strcmp(g_sort_srv->command_counts[*(const int *)a].name, g_sort_srv->command_counts[*(const int *)b].name);
}

/* 212 "<command> <count> <bytes> <remote count>", alphabetical. */
static void st_commands(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)letter; (void)arg;
    int idx[sizeof srv->command_counts / sizeof srv->command_counts[0]], n = srv->n_command_counts;
    for (int i = 0; i < n; i++) idx[i] = i;
    g_sort_srv = srv;
    qsort(idx, (size_t)n, sizeof *idx, cmp_cmd);
    for (int i = 0; i < n; i++) {
        const struct cmd_count *e = &srv->command_counts[idx[i]];
        char c[16], b[24], r[16];
        snprintf(c, sizeof c, "%d", e->count);
        num(e->bytes, b, sizeof b);
        snprintf(r, sizeof r, "%d", e->remote);
        client_reply(cl, N_STATSCOMMANDS, (const char *[]){e->name, c, b, r}, 4, NULL);
    }
}

static void st_uptime(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)letter; (void)arg;
    char buf[64], peak[160];
    cmd_uptime_str(srv, buf, sizeof buf);
    client_reply(cl, N_STATSUPTIME, NULL, 0, buf);
    snprintf(peak, sizeof peak, "Highest connection count: %d (%d clients) (%ld connections received)",
             srv->max_users_seen, srv->max_users_seen, srv->total_connections);
    client_reply(cl, N_STATSCONN, NULL, 0, peak);
}

static void st_opers_online(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    int n = 0;
    time_t now = time(NULL);
    for (client_t *u = srv->users; u; u = u->hh.next) {
        if (u->remote || u->is_service || !is_oper(u) || u->fd < 0) continue;
        if ((u->umodes & UMODE_H) && !OPER_CAN(cl, OPER_PRIV_AUSPEX)) continue; /* +H hides oper status from non-opers */
        char idle[24];
        if ((u->umodes & UMODE_HIDEIDLE) && !OPER_CAN(cl, OPER_PRIV_AUSPEX) && u != cl) snprintf(idle, sizeof idle, "hidden");
        else dur((long)difftime(now, u->last_msg), idle, sizeof idle);
        dbg(cl, letter, "[O] %s (%s@%s) Idle: %s%s", u->nick, u->user, OPER_CAN(cl, OPER_PRIV_AUSPEX) ? u->realhost : u->host, idle,
            u->is_away ? " (away)" : "");
        n++;
    }
    dbg(cl, letter, "%d OPER(s)", n);
}

static void st_servers(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    int n = 0;
    for (netserver_t *s = srv->servers; s; s = s->hh.next) {
        int users = s->n_users;
        if (s == srv->self_srv) { users = 0; for (client_t *u = srv->users; u; u = u->hh.next) users += !u->remote && !u->is_service; }
        dbg(cl, letter, "%s (%s) hops %d, uplink %s, %d user%s", s->name, s->sid, s->hop,
            s->uplink ? s->uplink->name : "-", users, users == 1 ? "" : "s");
        n++;
    }
    dbg(cl, letter, "%d server(s)", n);
}

/* --- ban lines ------------------------------------------------------------------------------------------------- */

static void st_lines(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    char want = letter == 'd' || letter == 'D' ? 'Z' : (char)toupper((unsigned char)letter);
    time_t now = time(NULL);
    int n = 0;
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        if (k->line_type[0] != want) continue;
        char exp[32];
        if (k->expires_at) dur((long)difftime(k->expires_at, now), exp, sizeof exp); else snprintf(exp, sizeof exp, "permanent");
        client_reply(cl, N_STATSKLINE, (const char *[]){k->line_type, k->mask, k->set_by[0] ? k->set_by : "*", exp}, 4, k->reason);
        n++;
    }
    static const char *const NAME[] = {['K'] = "K-line", ['G'] = "G-line", ['Z'] = "Z-line", ['S'] = "SHUN", ['E'] = "ELINE"};
    dbg(cl, letter, "%d %s%s", n, NAME[(unsigned char)want], n == 1 ? "" : "s");
}

/* --- configuration ----------------------------------------------------------------------------------------------- */

static void st_opers(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)letter; (void)arg;
    static const struct { unsigned bit; const char *name; } P[] = {
        {OPER_PRIV_KILL, "kill"}, {OPER_PRIV_KLINE, "kline"}, {OPER_PRIV_SA, "sa"}, {OPER_PRIV_HOST, "host"},
        {OPER_PRIV_WALLOPS, "wallops"}, {OPER_PRIV_REHASH, "rehash"}, {OPER_PRIV_DIE, "die"}, {OPER_PRIV_LINK, "link"},
        {OPER_PRIV_OVERRIDE, "override"}, {OPER_PRIV_AUSPEX, "auspex"}, {OPER_PRIV_IMMUNE, "immune"},
    };
    for (int i = 0; i < srv->cfg.n_operators; i++) {
        const cfg_operator_t *o = &srv->cfg.operators[i];
        char privs[128] = "";
        unsigned bits = o->privs ? o->privs : OPER_PRIV_ALL; /* key absent = everything */
        if ((bits & OPER_PRIV_ALL) == OPER_PRIV_ALL) snprintf(privs, sizeof privs, "all");
        else for (size_t j = 0; j < sizeof P / sizeof *P; j++)
            if (bits & P[j].bit) snprintf(privs + strlen(privs), sizeof privs - strlen(privs), "%s%s", privs[0] ? "," : "", P[j].name);
        if (!privs[0]) snprintf(privs, sizeof privs, "none");
        for (int h = 0; h < (o->n_hosts ? o->n_hosts : 1); h++)
            client_reply(cl, N_STATSOLINE, (const char *[]){"O", o->n_hosts ? o->hosts[h] : "*", "*", o->name}, 4, privs);
    }
}

static link_conn_t *find_link(server_t *srv, const char *name) {
    for (link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc->authenticated && !lc->closing && strcasecmp(lc->peer_name, name) == 0) return lc;
    return NULL;
}

static void st_connect(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    const cfg_links_t *L = &srv->cfg.links;
    for (int i = 0; i < L->n_peers; i++) {
        const cfg_link_peer_t *p = &L->peers[i];
        char port[16], flags[8];
        int f = 0;
        snprintf(port, sizeof port, "%d", p->host[0] ? p->port : L->port);
        if (p->host[0] && L->autoconnect) flags[f++] = 'A'; /* dialled automatically */
        if (p->fingerprint[0]) flags[f++] = 'F';                /* TLS certificate pinned */
        if (find_link(srv, p->name)) flags[f++] = 'L';           /* linked right now */
        if (L->tls) flags[f++] = 'T';
        if (!f) flags[f++] = '-';
        flags[f] = '\0';
        const char *host = p->host[0] ? p->host : p->n_allowed_ips ? p->allowed_ips[0] : "*";
        client_reply(cl, N_STATSCLINE, (const char *[]){"C", host, "*", p->name, port, flags}, 6, NULL);
        for (int j = p->host[0] ? 0 : 1; j < p->n_allowed_ips; j++) /* further addresses a hub-role peer may come from */
            client_reply(cl, N_STATSCLINE, (const char *[]){"C", p->allowed_ips[j], "*", p->name, port, flags}, 6, NULL);
    }
    dbg(cl, letter, "links %s, mode %s, %d connect block%s (flags: A autoconnect, F pinned certificate, L linked, T TLS)",
        L->enabled ? "on" : "off", L->mode, L->n_peers, L->n_peers == 1 ? "" : "s");
}

static void st_hub(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    for (int i = 0; i < srv->cfg.links.n_peers; i++) {
        const cfg_link_peer_t *p = &srv->cfg.links.peers[i];
        if (p->host[0]) client_reply(cl, N_STATSHLINE, (const char *[]){"H", "*", "*", p->name}, 4, NULL); /* we dial it: our hub */
        else client_reply(cl, N_STATSLLINE, (const char *[]){"L", "*", "*", p->name, "*"}, 5, NULL);    /* it dials us */
    }
}

static void st_auth(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    for (int i = 0; i < srv->n_class_tab; i++) {
        const cfg_class_t *c = srv->class_tab[i];
        for (int h = 0; h < c->n_hosts; h++)
            client_reply(cl, N_STATSILINE, (const char *[]){"I", c->hosts[h], "*", c->hosts[h], "0", c->name}, 6, NULL);
    }
    for (int i = 0; i < srv->cfg.n_webirc; i++) {
        const cfg_webirc_t *w = &srv->cfg.webirc[i];
        char cls[CFG_STR + 8];
        snprintf(cls, sizeof cls, "webirc:%s", w->name);
        for (int h = 0; h < w->n_hosts; h++)
            client_reply(cl, N_STATSILINE, (const char *[]){"I", w->hosts[h], "*", w->hosts[h], "0", cls}, 6, NULL);
    }
    client_reply(cl, N_STATSILINE, (const char *[]){"I", "*", "*", "*", "0", "default"}, 6, NULL);
}

static void st_classes(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    char ping[16], max[16], sq[24], cur[16];
    snprintf(ping, sizeof ping, "%d", (int)srv->cfg.security.ping_interval);
    int in_classes = 0;
    for (int i = 0; i < srv->n_class_tab; i++) {
        const cfg_class_t *c = srv->class_tab[i];
        snprintf(max, sizeof max, "%d", c->max_clients ? c->max_clients : srv->cfg.security.max_connections);
        snprintf(sq, sizeof sq, "%d", c->sendq_max ? c->sendq_max : SENDQ_MAX);
        snprintf(cur, sizeof cur, "%d", srv->class_count[i]);
        in_classes += srv->class_count[i];
        client_reply(cl, N_STATSYLINE, (const char *[]){"Y", c->name, ping, "0", max, sq, cur}, 7, NULL);
    }
    snprintf(max, sizeof max, "%d", srv->cfg.security.max_connections);
    snprintf(sq, sizeof sq, "%d", SENDQ_MAX);
    snprintf(cur, sizeof cur, "%d", srv->n_clients - in_classes);
    client_reply(cl, N_STATSYLINE, (const char *[]){"Y", "default", ping, "0", max, sq, cur}, 7, NULL);
    dbg(cl, letter, "Y <class> <ping freq> <connect freq> <max clients> <max sendq> <current> (0 = unlimited)");
}

static void st_ports(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    const char *ws = srv->cfg.websocket.tls ? "wss" : "ws";
    struct { int fd; const char *bind; int port; const char *type; } L[] = {
        {srv->listen_fd, srv->bound_main.bind, srv->bound_main.port, "plain"},
        {srv->tls_listen_fd, srv->bound_tls.bind, srv->bound_tls.port, "tls"},
        {srv->ws_listen_fd, srv->bound_ws.bind, srv->bound_ws.port, ws},
        {srv->link_listen_fd, srv->bound_link.bind, srv->bound_link.port, "link"},
        {srv->l6[L6_MAIN].fd, srv->l6[L6_MAIN].bind, srv->l6[L6_MAIN].port, "plain"},
        {srv->l6[L6_TLS].fd, srv->l6[L6_TLS].bind, srv->l6[L6_TLS].port, "tls"},
        {srv->l6[L6_WS].fd, srv->l6[L6_WS].bind, srv->l6[L6_WS].port, ws},
        {srv->l6[L6_LINK].fd, srv->l6[L6_LINK].bind, srv->l6[L6_LINK].port, "link"},
    };
    for (size_t i = 0; i < sizeof L / sizeof *L; i++) {
        if (L[i].fd < 0) continue;
        char port[16];
        snprintf(port, sizeof port, "%d", L[i].port);
        client_reply(cl, N_STATSPLINE, (const char *[]){"P", port, L[i].type, L[i].bind[0] ? L[i].bind : "*"}, 4, "active");
    }
    for (int i = 0; i < MAX_XL; i++) { /* extra_ports */
        if (srv->xl[i].fd < 0) continue;
        char port[16];
        snprintf(port, sizeof port, "%d", srv->xl[i].port);
        client_reply(cl, N_STATSPLINE, (const char *[]){"P", port, srv->xl[i].tls ? "tls" : "plain", srv->xl[i].bind}, 4, "active");
    }
}

static void st_reserved(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg; (void)letter;
    for (int i = 0; i < srv->cfg.security.n_reserved_nicks; i++)
        client_reply(cl, N_STATSQLINE, (const char *[]){"Q", srv->cfg.security.reserved_nicks[i]}, 2, "Reserved nick");
}

static void st_protection(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    const cfg_protection_t *p = &srv->cfg.protection;
    for (int i = 0; i < p->n_blacklists; i++)
        dbg(cl, letter, "DNSBL %s (%s, %d reply code%s)", p->blacklists[i].zone, p->bl_enabled ? "active" : "off",
            p->blacklists[i].n_replies, p->blacklists[i].n_replies == 1 ? "" : "s");
    dbg(cl, letter, "DNSBL %s, action %s, ban %s, %ld hit%s since start", p->bl_enabled && p->n_blacklists ? "on" : "off",
        p->bl_action[0] ? p->bl_action : "-", p->bl_ban_duration[0] ? p->bl_ban_duration : "permanent", srv->dnsbl_hits,
        srv->dnsbl_hits == 1 ? "" : "s");
    dbg(cl, letter, "proxy scanner %s, %d protocol/port pair%s, action %s, %d exempt mask%s", p->scan_enabled ? "on" : "off",
        p->n_protocols, p->n_protocols == 1 ? "" : "s", p->scan_action[0] ? p->scan_action : "-", p->n_exempt,
        p->n_exempt == 1 ? "" : "s");
}

static void st_filters(server_t *srv, client_t *cl, char letter, const char *arg) { (void)letter; (void)arg; spam_stats(srv, cl); }

/* --- connections and traffic ----------------------------------------------------------------------------------- */

static void link_row(client_t *cl, const char *name, size_t sendq, unsigned long mo, unsigned long long bo, unsigned long mi,
                     unsigned long long bi, long open, long idle) {
    char sq[24], a[24], b[24], c[24], d[24], t[48];
    snprintf(sq, sizeof sq, "%zu", sendq);
    snprintf(a, sizeof a, "%lu", mo); num(bo / 1024, b, sizeof b);
    snprintf(c, sizeof c, "%lu", mi); num(bi / 1024, d, sizeof d);
    snprintf(t, sizeof t, "%ld %ld", open, idle);
    client_reply(cl, N_STATSLINKINFO, (const char *[]){name, sq, a, b, c, d}, 6, t);
}

static void st_links(server_t *srv, client_t *cl, char letter, const char *arg) {
    int show_ip = letter == 'l';
    time_t now = time(NULL);
    client_reply(cl, N_STATSLINKINFO, (const char *[]){"Name", "SendQ", "SendM", "SendKB", "RecvM", "RecvKB"}, 6, "Open_secs Idle_secs");
    if (arg) { /* one local client */
        client_t *u = server_find_user(srv, arg);
        if (!u || u->remote || u->fd < 0) return;
        char name[400];
        snprintf(name, sizeof name, "%s[%s@%s]", u->nick, u->user, show_ip ? u->ip : u->host);
        link_row(cl, name, client_sendq_len(u), u->msgs_out, u->bytes_out, u->msgs_in, u->bytes_in,
                 (long)difftime(now, u->signon_time), (long)difftime(now, u->last_activity));
        return;
    }
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (lc->closing) continue;
        char name[220];
        const char *pn = lc->peer_name[0] ? lc->peer_name : "(unknown)";
        if (show_ip) snprintf(name, sizeof name, "%s[%s]", pn, lc->ip); else snprintf(name, sizeof name, "%s", pn);
        link_row(cl, name, lc->sbuf_len - lc->sbuf_off, lc->msgs_out, lc->bytes_out, lc->msgs_in, lc->bytes_in,
                 (long)difftime(now, lc->connected_at), (long)difftime(now, lc->last_activity));
    }
}

static void st_linktraffic(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    time_t now = time(NULL);
    unsigned long long bi = 0, bo = 0;
    int n = 0;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (lc->closing || !lc->authenticated) continue;
        char up[32];
        dbg(cl, letter, "%s: sent %lu msgs (%llu KB), received %lu msgs (%llu KB), up %s", lc->peer_name, lc->msgs_out,
            lc->bytes_out / 1024, lc->msgs_in, lc->bytes_in / 1024, dur((long)difftime(now, lc->connected_at), up, sizeof up));
        bi += lc->bytes_in; bo += lc->bytes_out; n++;
    }
    dbg(cl, letter, "%d link%s: %llu KB sent, %llu KB received", n, n == 1 ? "" : "s", bo / 1024, bi / 1024);
}

static void st_traffic(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    int local = 0, unreg = 0, svc = 0;
    for (client_t *c = srv->all_clients; c; c = c->all_next) {
        if (!c->registered) unreg++;
        else if (c->is_service) svc++;
        else local++;
    }
    unsigned long long lbi = srv->traffic.ln_in, lbo = srv->traffic.ln_out;
    unsigned long lmi = srv->traffic.ln_min, lmo = srv->traffic.ln_mout;
    int nl = 0;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        lbi += lc->bytes_in; lbo += lc->bytes_out; lmi += lc->msgs_in; lmo += lc->msgs_out;
        nl += lc->authenticated && !lc->closing;
    }
    char up[32];
    dbg(cl, letter, "up %s, %ld connections accepted, %ld refused before registering", dur((long)difftime(time(NULL), srv->start_time), up, sizeof up),
        srv->total_connections, srv->refused_connections);
    dbg(cl, letter, "now: %d local users, %d unregistered, %d detached (always-on), %d service%s, %d link%s", local, unreg,
        srv->n_ghosts, svc, svc == 1 ? "" : "s", nl, nl == 1 ? "" : "s");
    dbg(cl, letter, "clients: sent %lu msgs (%llu KB), received %lu msgs (%llu KB)", srv->traffic.cl_mout,
        srv->traffic.cl_out / 1024, srv->traffic.cl_min, srv->traffic.cl_in / 1024);
    dbg(cl, letter, "servers: sent %lu msgs (%llu KB), received %lu msgs (%llu KB)", lmo, lbo / 1024, lmi, lbi / 1024);
    dbg(cl, letter, "DNSBL hits %ld, spam actions %ld, peak %d users", srv->dnsbl_hits, srv->spam_hits, srv->max_users_seen);
}

static void st_memory(server_t *srv, client_t *cl, char letter, const char *arg) {
    (void)arg;
    int users = (int)HASH_COUNT(srv->users), remote = 0;
    for (client_t *u = srv->users; u; u = u->hh.next) remote += u->remote;
    size_t bufs = 0;
    for (client_t *c = srv->all_clients; c; c = c->all_next) bufs += c->sbuf_cap + c->rbuf_cap + c->ws_in_cap + c->ws_out_cap + c->label_cap;
    int nchan = (int)HASH_COUNT(srv->channels), members = 0;
    for (channel_t *ch = srv->channels; ch; ch = ch->hh.next) members += channel_member_count(ch);
    int nlinks = 0;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) { nlinks++; bufs += lc->sbuf_cap; }
    int nk = 0, nsrv = (int)HASH_COUNT(srv->servers);
    for (kline_entry_t *k = srv->klines; k; k = k->next) nk++;
    int convs = 0; long msgs = 0;
    for (hist_buf_t *h = srv->history; h; h = h->hh.next) { convs++; msgs += h->n; }
    size_t total = (size_t)(srv->n_clients + remote + srv->n_ghosts) * sizeof(client_t) /* live connections + users with none */
                 + (size_t)nchan * sizeof(channel_t) + (size_t)members * sizeof(member_t) + (size_t)nk * sizeof(kline_entry_t)
                 + (size_t)nlinks * sizeof(link_conn_t) + (size_t)nsrv * sizeof(netserver_t) + bufs + sizeof *srv;
    dbg(cl, letter, "users %d (%d remote, %d detached), %d connections, %zu bytes each", users, remote, srv->n_ghosts, srv->n_clients, sizeof(client_t));
    dbg(cl, letter, "channels %d (%zu bytes each), memberships %d (%zu bytes each)", nchan, sizeof(channel_t), members, sizeof(member_t));
    dbg(cl, letter, "send/receive buffers %zu KB, links %d (%zu bytes each), servers %d", bufs / 1024, nlinks, sizeof(link_conn_t), nsrv);
    dbg(cl, letter, "ban lines %d, whowas %d/%d, history %d conversation%s / %ld message%s", nk, srv->whowas_count, srv->cfg.limits.whowas_entries,
        convs, convs == 1 ? "" : "s", msgs, msgs == 1 ? "" : "s");
    struct rusage ru;
    long rss = 0;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
#ifdef __APPLE__
        rss = ru.ru_maxrss / 1024; /* bytes on macOS */
#else
        rss = ru.ru_maxrss;        /* KB on Linux and the BSDs */
#endif
    }
    dbg(cl, letter, "server state ~%zu KB (fixed tables %zu KB), process peak RSS %ld KB", total / 1024, sizeof *srv / 1024, rss);
}

/* --- dispatch ---------------------------------------------------------------------------------------------------- */

typedef void (*stat_fn)(server_t *, client_t *, char, const char *);
static const struct { const char *letters; int oper; stat_fn fn; const char *help; } STATS[] = {
    {"?", 1, st_linktraffic, "traffic per server link"},
    {"bB", 1, st_protection, "DNSBL zones and the proxy scanner"},
    {"cC", 1, st_connect, "connect blocks (links.peers)"},
    {"dD", 1, st_lines, "Z-lines (same as z)"},
    {"eE", 1, st_lines, "ELINEs (ban exemptions)"},
    {"fF", 1, st_filters, "spam filters"},
    {"gG", 1, st_lines, "G-lines"},
    {"hH", 1, st_hub, "hub/leaf rules"},
    {"iI", 1, st_auth, "who may connect (classes, WEBIRC gateways)"},
    {"kK", 1, st_lines, "K-lines"},
    {"lL", 1, st_links, "links, or \"l <nick>\" for one client (L hides IPs)"},
    {"mM", 0, st_commands, "command usage"},
    {"oO", 1, st_opers, "oper blocks"},
    {"p", 0, st_opers_online, "opers online"},
    {"P", 1, st_ports, "listening ports"},
    {"qQ", 1, st_reserved, "reserved nicks"},
    {"sS", 1, st_lines, "SHUNs"},
    {"tT", 1, st_traffic, "connection and traffic totals"},
    {"uU", 0, st_uptime, "uptime and peak connections"},
    {"vV", 0, st_servers, "servers on the network"},
    {"yY", 1, st_classes, "connection classes"},
    {"z", 1, st_lines, "Z-lines"},
    {"Z", 1, st_memory, "memory use"},
};

static void stats_help(client_t *cl) {
    for (size_t i = 0; i < sizeof STATS / sizeof *STATS; i++) {
        if (STATS[i].oper && !is_oper(cl)) continue;
        char line[160];
        snprintf(line, sizeof line, "%-2s - %s", STATS[i].letters, STATS[i].help);
        client_reply(cl, N_STATSHELP, (const char *[]){"*"}, 1, line);
    }
    if (!is_oper(cl)) client_reply(cl, N_STATSHELP, (const char *[]){"*"}, 1, "l  - \"l <your nick>\": your own connection");
}

void cmd_stats(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *letter = msg->nparams > 0 ? msg->params[0] : "";
    const char *target = msg->nparams > 1 && msg->params[1][0] ? msg->params[1] : NULL;
    /* "STATS x <server>" or "STATS x <nick on another server>": that server answers (no further hop once there). */
    if (target && !cl->remote) {
        netserver_t *s = netsync_find_name(srv, target);
        if (s && s != srv->self_srv && is_oper(cl) && netsync_scope_refuse(srv, cl, "STATS of another server")) return;
        if (s && s != srv->self_srv) { netsync_rquery(srv, cl, s, "STATS", (char *[]){(char *)letter}, letter[0] ? 1 : 0); return; }
        if (!s) {
            client_t *u = server_find_user(srv, target);
            if (!u) { client_reply(cl, N_NOSUCHSERVER, (const char *[]){target}, 1, "No such server"); return; }
            if (u->remote && u->nserver && u->nserver != srv->self_srv) {
                if (is_oper(cl) && netsync_scope_refuse(srv, cl, "STATS of another server")) return;
                netsync_rquery(srv, cl, u->nserver, "STATS", (char *[]){(char *)letter, u->nick}, 2);
                return;
            }
        }
    }
    const char *arg = target && !netsync_find_name(srv, target) ? target : NULL; /* a nick, for "l <nick>" */
    const char *pe[] = {letter[0] ? letter : "*"};
    char c = letter[0] && !letter[1] ? letter[0] : 0;
    int found = -1;
    for (size_t i = 0; c && i < sizeof STATS / sizeof *STATS; i++) if (strchr(STATS[i].letters, c)) { found = (int)i; break; }

    /* Own budget (5 per 10s, the rest dropped): a STATS loop must not use up server_notify_opers' shared flood guard and
     * hide the snotes that matter (bans, rejected connections). */
    static time_t win;
    static int used;
    time_t now = time(NULL);
    if (now - win >= 10) { win = now; used = 0; }
    if (used++ < 5) {
        char snote[400];
        snprintf(snote, sizeof snote, "STATS %s requested by %s (%s@%s) [%s]", letter[0] ? letter : "*", cl->nick, cl->user,
                 cl->realhost, cl->remote && cl->nserver ? cl->nserver->name : srv->cfg.server.name);
        server_notify_opers(srv, snote);
    }

    if (found < 0) { stats_help(cl); client_reply(cl, N_ENDOFSTATS, pe, 1, "End of /STATS report"); return; }
    int own = (c == 'l' || c == 'L') && arg && strcasecmp(arg, cl->nick) == 0 && !cl->remote;
    if (STATS[found].oper && !is_oper(cl) && !own) { err_no_privileges(cl); return; }
    if ((c == 'l' || c == 'L') && arg && !own && !is_oper(cl)) { err_no_privileges(cl); return; }
    STATS[found].fn(srv, cl, c, (c == 'l' || c == 'L') ? arg : NULL);
    client_reply(cl, N_ENDOFSTATS, pe, 1, "End of /STATS report");
}
