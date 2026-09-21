#include "protection.h"
#include "cmd.h"
#include "log.h"
#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCAN_BUF      1024 /* sliding window; must exceed the longest target string (200) + one recv */
#define SCAN_KEEP     256  /* bytes kept when the window slides */
#define RECENT_GRACE  15   /* seconds an IP stays "related" after its scan ends: late relayed connections */

enum { ST_CONNECTING, ST_S5_GREET, ST_READING };

struct protection_scan {
    struct protection_scan *next;
    uint32_t ip_be;
    char ip[INET_ADDRSTRLEN];
    int proto, port, fd, state;
    time_t deadline;
    unsigned char buf[SCAN_BUF];
    size_t len, nread;
};

/* --- pure helpers ---------------------------------------------------------- */

long protection_find(const unsigned char *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || m > n) return -1;
    for (size_t i = 0; i + m <= n; i++)
        if (hay[i] == (unsigned char)needle[0] && memcmp(hay + i, needle, m) == 0) return (long)i;
    return -1;
}

void protection_expand(const char *tmpl, const char *ip, const char *t, const char *r, char *out, size_t outsz) {
    size_t o = 0;
    for (const char *c = tmpl; *c && o + 1 < outsz; c++) {
        const char *sub = NULL;
        if (*c == '%' && c[1]) {
            switch (c[1]) {
                case 'i': sub = ip; break;
                case 't': sub = t; break;
                case 'r': case 'p': sub = r; break;
                case '%': sub = "%"; break;
                default: break;
            }
        }
        if (!sub) { out[o++] = *c; continue; }
        c++;
        for (const char *s = sub; *s && o + 1 < outsz; s++) out[o++] = *s;
    }
    out[o] = '\0';
}

size_t protection_probe_bytes(int type, const char *target_ip, int port, int stage,
                              unsigned char *out, size_t cap) {
    struct in_addr ia;
    if (inet_pton(AF_INET, target_ip, &ia) != 1 || cap < 32) return 0;
    const unsigned char *ip = (const unsigned char *)&ia.s_addr;
    unsigned char ph = (unsigned char)(port >> 8), pl = (unsigned char)(port & 0xff);
    int n;
    switch (type) {
        case SCAN_HTTP:
            n = snprintf((char *)out, cap, "CONNECT %s:%d HTTP/1.0\r\n\r\n", target_ip, port);
            return n > 0 && (size_t)n < cap ? (size_t)n : 0;
        case SCAN_HTTPPOST: {
            static const char body[] = "PING :protection\r\n";
            n = snprintf((char *)out, cap,
                         "POST http://%s:%d/ HTTP/1.0\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
                         target_ip, port, (int)(sizeof body - 1), body);
            return n > 0 && (size_t)n < cap ? (size_t)n : 0;
        }
        case SCAN_SOCKS4: { /* VN=4 CD=1 port ip USERID="" NUL */
            unsigned char r[] = {4, 1, ph, pl, ip[0], ip[1], ip[2], ip[3], 0};
            memcpy(out, r, sizeof r);
            return sizeof r;
        }
        case SCAN_SOCKS5:
            if (stage == 0) { unsigned char r[] = {5, 1, 0}; memcpy(out, r, sizeof r); return sizeof r; } /* one method: no auth */
            { unsigned char r[] = {5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], ph, pl}; memcpy(out, r, sizeof r); return sizeof r; }
        default:
            return 0;
    }
}

int protection_bl_match(const cfg_protection_t *p, const int *codes, int n, char *reply, size_t replysz) {
    for (int i = 0; i < p->n_blacklists && i < n; i++) {
        int code = codes[i];
        if (code < 0) continue;
        const cfg_blacklist_t *z = &p->blacklists[i];
        if (z->n_replies == 0) { snprintf(reply, replysz, "reply %d", code); return i; }
        for (int r = 0; r < z->n_replies; r++) {
            int hit = z->bitmask ? (code & z->replies[r].code) != 0 : code == z->replies[r].code;
            if (hit) { snprintf(reply, replysz, "%s", z->replies[r].text); return i; }
        }
        if (z->ban_unknown) { snprintf(reply, replysz, "reply %d", code); return i; }
    }
    return -1;
}

int protection_exempt(const cfg_protection_t *p, const char *ip) {
    for (int i = 0; i < p->n_exempt; i++)
        if (irc_glob_match(p->exempt[i], ip)) return 1;
    return 0;
}

/* --- negative cache / recent table ------------------------------------------ */

static prot_slot_t *slot_for(prot_slot_t *tab, int n, uint32_t ip_be) {
    return &tab[(ip_be * 2654435761u) % (uint32_t)n];
}
static int slot_live(prot_slot_t *tab, int n, uint32_t ip_be, time_t now) {
    prot_slot_t *s = slot_for(tab, n, ip_be);
    return s->ip == ip_be && s->until > now;
}
static void slot_set(prot_slot_t *tab, int n, uint32_t ip_be, time_t until) {
    prot_slot_t *s = slot_for(tab, n, ip_be);
    s->ip = ip_be;
    s->until = until;
}

int protection_negcache_count(struct server *srv) {
    time_t now = time(NULL);
    int c = 0;
    for (int i = 0; i < PROT_NEGCACHE_SLOTS; i++)
        if (srv->prot.negcache[i].until > now) c++;
    return c;
}

/* --- scan lifecycle -------------------------------------------------------- */

static void scan_unlink(struct server *srv, protection_scan_t *s) {
    protection_scan_t **pp = &srv->prot.scans;
    while (*pp && *pp != s) pp = &(*pp)->next;
    if (*pp) { *pp = s->next; srv->prot.n_scans--; }
    if (s->fd >= 0) close(s->fd);
    free(s);
}

static int ip_has_scans(struct server *srv, uint32_t ip_be) {
    for (protection_scan_t *s = srv->prot.scans; s; s = s->next)
        if (s->ip_be == ip_be) return 1;
    return 0;
}

/* Closes one finished-without-a-hit probe; when it was the address's last one,
 * the address is clean: count it and remember it. */
static void scan_done_clean(struct server *srv, protection_scan_t *s, const char *why) {
    const cfg_protection_t *p = &srv->cfg.protection;
    if (p->scan_log_all) log_debug("protection", "%s %s:%d %s", s->ip, config_scan_proto_name(s->proto), s->port, why);
    uint32_t ip_be = s->ip_be;
    scan_unlink(srv, s);
    if (ip_has_scans(srv, ip_be)) return;
    srv->prot.scanned++;
    time_t now = time(NULL);
    slot_set(srv->prot.recent, PROT_RECENT_SLOTS, ip_be, now + RECENT_GRACE);
    if (p->scan_negcache > 0) slot_set(srv->prot.negcache, PROT_NEGCACHE_SLOTS, ip_be, now + p->scan_negcache);
}

static void scan_hit(struct server *srv, protection_scan_t *s) {
    const cfg_protection_t *p = &srv->cfg.protection;
    char ip[INET_ADDRSTRLEN], portstr[8], reason[350];
    uint32_t ip_be = s->ip_be;
    int proto = s->proto, port = s->port;
    snprintf(ip, sizeof ip, "%s", s->ip);
    snprintf(portstr, sizeof portstr, "%d", port);
    protection_expand(p->scan_reason, ip, config_scan_proto_name(proto), portstr, reason, sizeof reason);

    /* One confirmed relay is enough: drop every other probe for this address. */
    protection_scan_t *it = srv->prot.scans;
    while (it) {
        protection_scan_t *next = it->next;
        if (it->ip_be == ip_be) scan_unlink(srv, it);
        it = next;
    }
    srv->prot.hits++;
    srv->prot.scanned++;
    slot_set(srv->prot.recent, PROT_RECENT_SLOTS, ip_be, time(NULL) + RECENT_GRACE);

    long dur = p->scan_ban_duration[0] ? irc_parse_duration(p->scan_ban_duration) : 0;
    if (dur < 0) dur = 0;
    int reject = strcmp(p->scan_action, "reject") == 0;
    if (!reject) server_kline_add(srv, ip, reason, "protection", strcmp(p->scan_action, "kline") == 0 ? "K" : "Z", dur);
    char quit[400];
    snprintf(quit, sizeof quit, reject ? "%s" : "Z-Lined: %s", reason);
    int killed = server_kline_enforce(srv, ip, "Z", quit, NULL);
    log_warn("protection", "%s is an open %s proxy (port %d) -- %s%s, %d client(s) disconnected", ip,
             config_scan_proto_name(proto), port,
             reject ? "rejected" : (strcmp(p->scan_action, "kline") == 0 ? "K-lined" : "Z-lined"),
             reject ? "" : (dur ? " for the configured duration" : " permanently"), killed);
}

int protection_ip_related(struct server *srv, const char *ip) {
    struct in_addr ia;
    if (inet_pton(AF_INET, ip, &ia) != 1) return 0;
    return ip_has_scans(srv, ia.s_addr) ||
           slot_live(srv->prot.recent, PROT_RECENT_SLOTS, ia.s_addr, time(NULL));
}

static int start_probe(struct server *srv, uint32_t ip_be, const char *ip, const cfg_scan_proto_t *pr) {
    const cfg_protection_t *p = &srv->cfg.protection;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (p->scan_bind[0]) {
        struct sockaddr_in b;
        memset(&b, 0, sizeof b);
        b.sin_family = AF_INET;
        inet_pton(AF_INET, p->scan_bind, &b.sin_addr);
        if (bind(fd, (struct sockaddr *)&b, sizeof b) != 0) { close(fd); return 0; }
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be;
    sa.sin_port = htons((uint16_t)pr->port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 && errno != EINPROGRESS) { close(fd); return 0; }

    protection_scan_t *s = calloc(1, sizeof *s);
    if (!s) { close(fd); return 0; }
    s->ip_be = ip_be;
    snprintf(s->ip, sizeof s->ip, "%s", ip);
    s->proto = pr->type;
    s->port = pr->port;
    s->fd = fd;
    s->state = ST_CONNECTING;
    s->deadline = time(NULL) + (time_t)ceil(p->scan_timeout);
    s->next = srv->prot.scans;
    srv->prot.scans = s;
    srv->prot.n_scans++;
    return 1;
}

int protection_scan_start(struct server *srv, const char *ip) {
    const cfg_protection_t *p = &srv->cfg.protection;
    struct in_addr ia;
    if (!p->scan_enabled || p->n_protocols == 0 || inet_pton(AF_INET, ip, &ia) != 1) return 0;
    if (protection_exempt(p, ip)) return 0;
    time_t now = time(NULL);
    if (slot_live(srv->prot.negcache, PROT_NEGCACHE_SLOTS, ia.s_addr, now)) return 0;
    if (ip_has_scans(srv, ia.s_addr)) return 0;
    if (srv->prot.n_scans + p->n_protocols > p->scan_max_concurrent) {
        static time_t last_warn;
        if (now - last_warn >= 60) { /* a flood would otherwise log once per connection */
            last_warn = now;
            log_warn("protection", "scanner at max_concurrent (%d in flight) -- skipping new scans until it drains",
                     srv->prot.n_scans);
        }
        return 0;
    }
    int started = 0;
    for (int i = 0; i < p->n_protocols; i++) started += start_probe(srv, ia.s_addr, ip, &p->protocols[i]);
    if (started && p->scan_log_all) log_debug("protection", "scanning %s with %d probe(s)", ip, started);
    return started;
}

/* --- poll integration ------------------------------------------------------- */

void protection_poll_fill(struct server *srv, struct pollfd *fds, protection_scan_t **fd_scan, int *n) {
    for (protection_scan_t *s = srv->prot.scans; s; s = s->next) {
        fds[*n].fd = s->fd;
        fds[*n].events = s->state == ST_CONNECTING ? POLLOUT : POLLIN;
        fds[*n].revents = 0;
        fd_scan[*n] = s;
        (*n)++;
    }
}

int protection_scan_live(struct server *srv, const protection_scan_t *scan) {
    for (protection_scan_t *s = srv->prot.scans; s; s = s->next)
        if (s == scan) return 1;
    return 0;
}

static void scan_send(protection_scan_t *s, const cfg_protection_t *p, int stage) {
    unsigned char req[512];
    size_t len = protection_probe_bytes(s->proto, p->target_ip, p->target_port, stage, req, sizeof req);
    if (len) (void)send(s->fd, req, len, 0); /* a failure shows up as EOF/error on the next read */
}

void protection_handle(struct server *srv, protection_scan_t *s, short revents) {
    const cfg_protection_t *p = &srv->cfg.protection;
    if (s->state == ST_CONNECTING) {
        if (!(revents & (POLLOUT | POLLERR | POLLHUP))) return;
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            scan_done_clean(srv, s, "connect failed");
            return;
        }
        scan_send(s, p, 0);
        s->state = s->proto == SCAN_SOCKS5 ? ST_S5_GREET : ST_READING;
        return;
    }
    if (!(revents & (POLLIN | POLLERR | POLLHUP))) return;
    unsigned char tmp[512];
    ssize_t n = recv(s->fd, tmp, sizeof tmp, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
        scan_done_clean(srv, s, "read error");
        return;
    }
    if (n == 0) { scan_done_clean(srv, s, "closed"); return; }
    s->nread += (size_t)n;
    if (s->len + (size_t)n > sizeof s->buf) {
        memmove(s->buf, s->buf + s->len - SCAN_KEEP, SCAN_KEEP);
        s->len = SCAN_KEEP;
    }
    memcpy(s->buf + s->len, tmp, (size_t)n);
    s->len += (size_t)n;

    if (s->state == ST_S5_GREET) {
        if (s->len < 2) return;
        if (s->buf[0] != 5 || s->buf[1] != 0) { scan_done_clean(srv, s, "socks5 refused no-auth"); return; }
        memmove(s->buf, s->buf + 2, s->len - 2);
        s->len -= 2;
        scan_send(s, p, 1);
        s->state = ST_READING;
    }
    for (int i = 0; i < p->n_target_strings; i++) {
        if (protection_find(s->buf, s->len, p->target_strings[i]) >= 0) { scan_hit(srv, s); return; }
    }
    if (s->nread >= (size_t)p->scan_max_read) scan_done_clean(srv, s, "max_read reached, no target string");
}

void protection_tick(struct server *srv) {
    time_t now = time(NULL);
    protection_scan_t *s = srv->prot.scans;
    while (s) {
        protection_scan_t *next = s->next;
        if (now >= s->deadline) scan_done_clean(srv, s, "timed out");
        s = next;
    }
}

void protection_free(struct server *srv) {
    while (srv->prot.scans) scan_unlink(srv, srv->prot.scans);
}

/* --- reporting -------------------------------------------------------------- */

static int private_ipv4(const char *ip) {
    unsigned a, b;
    if (sscanf(ip, "%u.%u", &a, &b) != 2) return 0;
    return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
}

void protection_reload(struct server *srv) {
    const cfg_protection_t *p = &srv->cfg.protection;
    char path[CFG_PATH] = "";
    int has_path = config_protection_path(&srv->cfg, path, sizeof path);
    log_info("protection", "bundle: %s | blacklists: %s | scanner: %s | exempt: %d ip mask(s)",
             p->loaded ? path : (has_path ? "no file (using sekurircd.toml)" : "built-in defaults"),
             p->bl_enabled && p->n_blacklists ? "on" : "off",
             p->scan_enabled ? "on" : "off", p->n_exempt);
    if (p->bl_enabled && p->n_blacklists)
        log_info("protection", "blacklists: %d zone(s), action=%s%s%s", p->n_blacklists, p->bl_action,
                 strcmp(p->bl_action, "reject") ? " for " : "",
                 strcmp(p->bl_action, "reject") ? (p->bl_ban_duration[0] ? p->bl_ban_duration : "ever") : "");
    if (p->bl_legacy)
        log_warn("protection", "[dnsbl] in sekurircd.toml is deprecated -- move it to [blacklist] in the Protection bundle file (see config/protection.template.toml)");
    if (p->scan_enabled) {
        char protos[256] = "";
        for (int i = 0; i < p->n_protocols; i++) {
            size_t l = strlen(protos);
            snprintf(protos + l, sizeof protos - l, "%s%s:%d", i ? " " : "", config_scan_proto_name(p->protocols[i].type), p->protocols[i].port);
        }
        log_info("protection", "scanner: %d probe(s) per client [%s], target %s:%d, action=%s, negcache %lds, max %d in flight",
                 p->n_protocols, protos, p->target_ip, p->target_port, p->scan_action, p->scan_negcache, p->scan_max_concurrent);
        if (private_ipv4(p->target_ip))
            log_warn("protection", "scanner.target.ip %s is a private address -- proxies on the internet can't reach it, so no scan will ever confirm. Use this server's public address.", p->target_ip);
    }
}

/* --- /PROTECT ---------------------------------------------------------------- */

void cmd_protect(struct server *srv, struct client *cl, irc_message_t *msg) {
    const cfg_protection_t *p = &srv->cfg.protection;
    char m[400];
    if (msg->nparams >= 1 && strcasecmp(msg->params[0], "SCAN") == 0) {
        struct in_addr ia;
        if (msg->nparams < 2 || inet_pton(AF_INET, msg->params[1], &ia) != 1) {
            notice_self(srv, cl, "Usage: PROTECT SCAN <ipv4-address>");
            return;
        }
        if (!p->scan_enabled) { notice_self(srv, cl, "The proxy scanner is not enabled ([scanner] enabled = true in the Protection bundle file)"); return; }
        /* A manual scan is an explicit request: bypass the negcache. */
        slot_set(srv->prot.negcache, PROT_NEGCACHE_SLOTS, ia.s_addr, 0);
        int n = protection_scan_start(srv, msg->params[1]);
        if (n) {
            snprintf(m, sizeof m, "Scanning %s with %d probe(s)", msg->params[1], n);
            log_info("protection", "%s requested a scan of %s", cl->nick, msg->params[1]);
        } else {
            snprintf(m, sizeof m, "Not scanning %s (exempt, already being scanned, or the scanner is at max_concurrent)", msg->params[1]);
        }
        notice_self(srv, cl, m);
        return;
    }
    char path[CFG_PATH] = "";
    int has_path = config_protection_path(&srv->cfg, path, sizeof path);
    snprintf(m, sizeof m, "Protection bundle: %s", p->loaded ? path : (has_path ? "no file found -- using sekurircd.toml" : "built-in defaults"));
    notice_self(srv, cl, m);
    snprintf(m, sizeof m, "Blacklists: %s, %d zone(s), action %s, %ld listing(s) hit so far",
             p->bl_enabled && p->n_blacklists ? "on" : "off", p->n_blacklists, p->bl_action, srv->dnsbl_hits);
    notice_self(srv, cl, m);
    if (p->scan_enabled)
        snprintf(m, sizeof m, "Scanner: on, %d probe(s)/client, target %s:%d, %d in flight, %ld scanned, %ld open prox%s found, %d negcached",
                 p->n_protocols, p->target_ip, p->target_port, srv->prot.n_scans, srv->prot.scanned,
                 srv->prot.hits, srv->prot.hits == 1 ? "y" : "ies", protection_negcache_count(srv));
    else
        snprintf(m, sizeof m, "Scanner: off");
    notice_self(srv, cl, m);
    const cfg_security_t *sec = &srv->cfg.security;
    snprintf(m, sizeof m, "Connection limits: %d total, %d per IP (0 = unlimited); connect flood %d in %.0fs -> ban %s",
             sec->max_connections, sec->max_connections_per_ip, sec->connect_flood_max, sec->connect_flood_window,
             sec->connect_flood_kline_duration[0] ? sec->connect_flood_kline_duration : "permanent");
    notice_self(srv, cl, m);
    snprintf(m, sizeof m, "Flood guard: %d msgs per %.1fs; spam protection: %s (%ld acted on)",
             sec->flood_max_msgs, sec->flood_window, srv->cfg.spam.enabled ? "on" : "off", srv->spam_hits);
    notice_self(srv, cl, m);
    if (p->n_exempt) {
        snprintf(m, sizeof m, "Exempt: %d IP mask(s)", p->n_exempt);
        notice_self(srv, cl, m);
    }
}
