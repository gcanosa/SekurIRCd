#include "link.h"
#include "channel.h"
#include "cmd.h"
#include "crypto.h"
#include "log.h"
#include "net.h"
#include "proto.h"
#include "server.h"

#include <openssl/err.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* --- TLS (optional, [links] tls=true) --------------------------------------
 * Hub side reuses srv->tls_ctx (the same cert the client-facing TLS listener
 * uses -- config.c requires [tls] enabled whenever [links] tls+mode=hub).
 * Leaf side dials out as a TLS client, honoring tls_insecure_skip_verify;
 * its SSL_CTX is created once, lazily, and freed at shutdown. */

static void sync_ranks_to(server_t *srv, link_conn_t *lc);
static void send_member_line(link_conn_t *lc, const char *cmd, channel_t *chan, client_t *u, int rank);
static ssize_t link_io_read(link_conn_t *lc, void *buf, size_t len) {
    if (!lc->ssl) return read(lc->fd, buf, len);
    ERR_clear_error();
    int n = SSL_read(lc->ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(lc->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

static ssize_t link_io_write(link_conn_t *lc, const void *buf, size_t len) {
    if (!lc->ssl) return write(lc->fd, buf, len);
    ERR_clear_error();
    int n = SSL_write(lc->ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(lc->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

static SSL_CTX *g_leaf_tls_ctx;

/* A certificate is never judged by its chain on a pinned link (or for a hub requesting one): the fingerprint is. */
static int accept_any_cert(int preverify_ok, X509_STORE_CTX *ctx) { (void)preverify_ok; (void)ctx; return 1; }

/* The dialing side presents this server's own [tls] certificate when it has one, so a hub can pin it. Rebuilt after
 * a /REHASH (link_tls_cleanup) to pick up a renewed certificate. */
static SSL_CTX *leaf_tls_ctx(server_t *srv) {
    if (!g_leaf_tls_ctx) {
        g_leaf_tls_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_leaf_tls_ctx) return NULL;
        SSL_CTX_set_default_verify_paths(g_leaf_tls_ctx);
        char cert[CFG_PATH], key[CFG_PATH];
        config_tls_cert_path(&srv->cfg, cert, sizeof cert);
        config_tls_key_path(&srv->cfg, key, sizeof key);
        if (access(cert, R_OK) == 0 && access(key, R_OK) == 0) {
            if (SSL_CTX_use_certificate_chain_file(g_leaf_tls_ctx, cert) != 1 ||
                SSL_CTX_use_PrivateKey_file(g_leaf_tls_ctx, key, SSL_FILETYPE_PEM) != 1) {
                log_warn("link", "could not load %s / %s to present on outgoing links -- dialing without a certificate", cert, key);
                ERR_clear_error();
            }
        }
    }
    return g_leaf_tls_ctx;
}

/* 1 if `lc`'s peer presented the certificate pinned as `want` (lowercase hex). Logs why not. */
static int fingerprint_ok(link_conn_t *lc, const char *name, const char *want) {
    char got[65];
    if (crypto_peer_fingerprint(lc->ssl, got, sizeof got) != 0) {
        log_warn("link", "link '%s' presented no TLS certificate, but its fingerprint is pinned", name);
        return 0;
    }
    if (strcmp(got, want) != 0) {
        log_warn("link", "link '%s' presented certificate sha256:%s, not the pinned sha256:%s", name, got, want);
        return 0;
    }
    return 1;
}

void link_tls_cleanup(void) {
    if (g_leaf_tls_ctx) { SSL_CTX_free(g_leaf_tls_ctx); g_leaf_tls_ctx = NULL; }
}

void link_tls_try_handshake(server_t *srv, link_conn_t *lc) {
    if (lc->tls_sniff) { /* loopback: a TLS ClientHello starts with 0x16, anything else is a plain link (services) */
        unsigned char b;
        ssize_t n = recv(lc->fd, &b, 1, MSG_PEEK);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) { link_close(srv, lc); return; }
        lc->tls_sniff = 0;
        if (b != 0x16) {
            SSL_free(lc->ssl);
            lc->ssl = NULL;
            lc->tls_handshaking = lc->tls_want_write = 0;
            log_info("link", "inbound link from %s (fd=%d) is plain text -- allowed from loopback only", lc->ip, lc->fd);
            return; /* the peeked bytes are still queued: the next poll reads them as link lines */
        }
    }
    ERR_clear_error();
    int rc = SSL_accept(lc->ssl);
    if (rc == 1) {
        lc->tls_handshaking = 0;
        lc->tls_want_write = 0;
        log_info("link", "TLS handshake complete for inbound link (fd=%d): %s/%s",
                  lc->fd, SSL_get_version(lc->ssl), SSL_get_cipher_name(lc->ssl));
        return;
    }
    int err = SSL_get_error(lc->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        lc->tls_want_write = (err == SSL_ERROR_WANT_WRITE); /* see net.c's tls_try_handshake */
        return;
    }
    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
    log_warn("link", "inbound TLS handshake failed (fd=%d): err=%d (%s)", lc->fd, err, errbuf);
    link_close(srv, lc);
}

int link_start_hub(server_t *srv) {
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "leaf") == 0) return -1;
    int fd = net_listen(srv->cfg.links.bind, srv->cfg.links.port);
    if (fd < 0) {
        log_error("link", "could not bind link listener %s:%d", srv->cfg.links.bind, srv->cfg.links.port);
        return -1;
    }
    srv->link_listen_fd = fd;
    log_info("link", "link listener up on %s:%d (hub mode)", srv->cfg.links.bind, srv->cfg.links.port);
    return fd;
}

/* Blocking-with-timeout line I/O, used only during the leaf-dial handshake
 * below (before the fd joins the normal nonblocking poll set) -- goes
 * through lc->ssl when set, same "-1 + errno=EAGAIN means try later"
 * contract as link_io_read/write's nonblocking callers. */
static int read_line_blocking(link_conn_t *lc, char *out, size_t outsz, int timeout_ms) {
    size_t len = 0;
    time_t deadline = time(NULL) + (timeout_ms / 1000) + 1;
    while (time(NULL) < deadline && len + 1 < outsz) {
        char c;
        ssize_t n = link_io_read(lc, &c, 1);
        if (n > 0) {
            if (c == '\n') { out[len] = '\0'; return 0; }
            if (c != '\r') out[len++] = c;
            continue;
        }
        if (n < 0 && errno == EAGAIN) {
            struct pollfd pfd = {.fd = lc->fd, .events = POLLIN};
            if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
            continue;
        }
        return -1; /* EOF or a hard error */
    }
    return -1;
}

static int write_line_blocking(link_conn_t *lc, const char *line) {
    char buf[600];
    int len = snprintf(buf, sizeof buf, "%s\r\n", line);
    if (len < 0 || (size_t)len >= sizeof buf) return -1;
    size_t sent = 0;
    while (sent < (size_t)len) {
        ssize_t n = link_io_write(lc, buf + sent, (size_t)len - sent);
        if (n > 0) { sent += (size_t)n; continue; }
        if (n < 0 && errno == EAGAIN) {
            struct pollfd pfd = {.fd = lc->fd, .events = POLLOUT};
            if (poll(&pfd, 1, 5000) <= 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

/* The whole leaf dial runs inside net.c's one-second tick, so every second
 * it spends blocking is a second no connected client is serviced. A plain
 * blocking connect() meant the OS SYN timeout (~75s) froze the entire server
 * on every reconnect attempt against a dead uplink. Bound it explicitly.
 * ponytail: still blocking, just briefly -- link establishment is rare
 * (startup/reconnect/manual /CONNECT), not a per-request path, so it doesn't
 * need full nonblocking-connect-in-progress handling. Make it a proper state
 * machine in the poll set if these few seconds ever prove too long. */
#define LINK_DIAL_TIMEOUT_MS 2000
#define LINK_HANDSHAKE_TIMEOUT_MS 2000

static int connect_bounded(int fd, const struct sockaddr *sa, socklen_t slen, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    if (connect(fd, sa, slen) != 0) {
        if (errno != EINPROGRESS) return -1;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
        int err = 0;
        socklen_t elen = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) return -1;
    }
    fcntl(fd, F_SETFL, flags); /* the handshake below wants blocking semantics */
    /* ...but bounded: without these a hub that accepts TCP and then stalls
     * (or never finishes TLS) would freeze the whole leaf event loop. */
    struct timeval tv = {.tv_sec = LINK_HANDSHAKE_TIMEOUT_MS / 1000, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return 0;
}

/* IPv4 only unless [server] ipv6 is on; then each address `host` has, in the resolver's order (IPv6 first where it's
 * preferred), until one connects. */
static int dial_uplink(const char *host, int port, int ipv6) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = ipv6 ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portbuf[16];
    snprintf(portbuf, sizeof portbuf, "%d", port);
    if (getaddrinfo(host, portbuf, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0 && connect_bounded(fd, ai->ai_addr, ai->ai_addrlen, LINK_DIAL_TIMEOUT_MS) != 0) { close(fd); fd = -1; }
    }
    freeaddrinfo(res);
    return fd;
}

/* Dials one configured peer (a [[links.peers]] entry with `host`). 0 on success. The handshake briefly blocks (bounded
 * by SO_RCVTIMEO, see connect_bounded); link establishment is rare, not a per-request path. */
static int dial_peer(server_t *srv, int peer_idx) {
    cfg_link_peer_t *up = &srv->cfg.links.peers[peer_idx];
    int fd = dial_uplink(up->host, up->port, srv->cfg.server.ipv6);
    if (fd < 0) {
        log_warn("link", "could not connect to %s:%d", up->host, up->port);
        return -1;
    }

    link_conn_t *lc = calloc(1, sizeof *lc);
    if (!lc) { close(fd); return -1; }
    lc->fd = fd;

    if (srv->cfg.links.tls) {
        SSL_CTX *ctx = leaf_tls_ctx(srv);
        if (!ctx) {
            log_error("link", "TLS setup failed dialing %s:%d", up->host, up->port);
            close(fd); free(lc); return -1;
        }
        lc->ssl = SSL_new(ctx);
        SSL_set_mode(lc->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE); /* the sendq moves/grows between retries */
        SSL_set_fd(lc->ssl, fd);
        char lit[64];
        if (irc_ip_normalize(up->host, lit, sizeof lit) != 0) SSL_set_tlsext_host_name(lc->ssl, up->host); /* SNI (never for an IP literal) */
        if (up->fingerprint[0]) {
            SSL_set_verify(lc->ssl, SSL_VERIFY_PEER, accept_any_cert); /* pinned: checked once connected, below */
        } else if (!srv->cfg.links.tls_insecure_skip_verify) {
            SSL_set_verify(lc->ssl, SSL_VERIFY_PEER, NULL);
            SSL_set1_host(lc->ssl, up->host); /* checked against the cert's SAN/CN, not just chain trust */
        }
        ERR_clear_error();
        if (SSL_connect(lc->ssl) != 1) {
            char errbuf[256];
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
            log_warn("link", "TLS handshake to %s:%d failed: %s", up->host, up->port, errbuf);
            SSL_free(lc->ssl); close(fd); free(lc);
            return -1;
        }
        log_info("link", "TLS established to %s:%d (%s/%s)", up->host, up->port,
                  SSL_get_version(lc->ssl), SSL_get_cipher_name(lc->ssl));
        if (up->fingerprint[0] && !fingerprint_ok(lc, up->name, up->fingerprint)) goto fail; /* before PASS: never hand a password to the wrong server */
    }

    char line[512];
    snprintf(line, sizeof line, "PASS %s", up->password[0] ? up->password : "*"); /* fingerprint-only peer: nothing to send */
    if (write_line_blocking(lc, line) != 0) goto wfail;
    netsync_capab_line(srv, line, sizeof line);
    if (write_line_blocking(lc, line) != 0) goto wfail; /* ask for the state-sync protocol */
    const char *p[] = {srv->cfg.server.name, "1", srv->self_srv->sid};
    irc_build(line, sizeof line, NULL, 0, NULL, "SERVER", p, 3, srv->self_srv->desc);
    if (write_line_blocking(lc, line) != 0) goto wfail;

    char resp[512];
    int got_capab = 0;
    irc_message_t msg;
    for (int tries = 0; ; tries++) { /* the peer may send CAPAB before its SERVER line */
        if (tries >= 4 || read_line_blocking(lc, resp, sizeof resp, LINK_HANDSHAKE_TIMEOUT_MS) != 0) {
            log_warn("link", "peer '%s' did not respond to the handshake", up->name);
            goto fail;
        }
        if (irc_parse_line(resp, &msg) != 0) continue;
        if (strcasecmp(msg.command, "ERROR") == 0) { log_warn("link", "peer '%s' refused the link: %s", up->name, msg.nparams ? msg.params[msg.nparams - 1] : "?"); goto fail; }
        if (strcasecmp(msg.command, "CAPAB") == 0) {
            if (msg.nparams && strstr(msg.params[msg.nparams - 1], "SEKURNET")) {
                got_capab = 1;
                snprintf(lc->peer_capab, sizeof lc->peer_capab, "%s", msg.params[msg.nparams - 1]);
            }
            continue;
        }
        break;
    }
    if (strcasecmp(msg.command, "SERVER") != 0 || msg.nparams < 1 || strcmp(msg.params[0], up->name) != 0) {
        log_warn("link", "peer handshake failed (bad reply or name mismatch)");
        goto fail;
    }
    int server_link = got_capab && msg.nparams >= 4;
    if (server_link && netsync_check_peer(srv, lc, up->name) != 0) {
        write_line_blocking(lc, "ERROR :Incompatible link protocol");
        goto fail;
    }

    net_set_nonblocking(fd);
    lc->authenticated = 1;
    snprintf(lc->peer_name, sizeof lc->peer_name, "%s", up->name);
    lc->created = lc->last_activity = time(NULL);
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "connected to '%s'%s%s", up->name, lc->ssl ? " (TLS)" : "", server_link ? " [state sync]" : "");
    char snote[200];
    snprintf(snote, sizeof snote, "Link with %s established", up->name);
    server_notify_opers(srv, snote);
    if (server_link) {
        char sid[8];
        snprintf(sid, sizeof sid, "%s", msg.params[2]);
        if (netsync_link_up(srv, lc, up->name, sid, msg.params[3]) != 0) { link_close(srv, lc); return -1; }
    }
    /* The handshake read a whole TLS record; whatever followed the peer's SERVER line (the start of its burst) now sits
     * decrypted inside OpenSSL where poll() can't see it -- without this it waited for the next PING. */
    if (lc->ssl && SSL_pending(lc->ssl) > 0) link_handle_readable(srv, lc);
    return 0;

wfail:
    log_warn("link", "write failed sending handshake to %s:%d", up->host, up->port);
fail:
    if (lc->ssl) SSL_free(lc->ssl);
    close(fd);
    free(lc);
    return -1;
}

/* A closing link counts until link_reap removes it: redialing before that is refused by our own "already on the network"
 * check, after the peer has already accepted -- one wasted link up/down on its side. */
static int peer_is_linked(server_t *srv, const cfg_link_peer_t *p) {
    for (link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc->authenticated && strcasecmp(lc->peer_name, p->name) == 0) return 1;
    return 0;
}

/* Dial every dial-out peer that isn't linked yet and whose back-off has run out. `force` ignores the back-off
 * (startup, the CONNECT command). Returns how many links came up. */
int link_dial_peers(server_t *srv, int force, const char *only_name) {
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "hub") == 0) return 0;
    int up_count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < srv->cfg.links.n_peers; i++) {
        cfg_link_peer_t *p = &srv->cfg.links.peers[i];
        if (!p->host[0] || (only_name && strcasecmp(only_name, p->name) != 0) || peer_is_linked(srv, p)) continue;
        if (!force && now < srv->dial[i].next) continue;
        if (dial_peer(srv, i) == 0) {
            srv->dial[i].backoff = srv->cfg.links.reconnect_delay;
            srv->dial[i].next = 0;
            up_count++;
        } else {
            if (srv->dial[i].backoff <= 0) srv->dial[i].backoff = srv->cfg.links.reconnect_delay;
            srv->dial[i].next = now + (time_t)srv->dial[i].backoff;
            srv->dial[i].backoff = srv->dial[i].backoff * 2 > srv->cfg.links.reconnect_delay_max
                                       ? srv->cfg.links.reconnect_delay_max : srv->dial[i].backoff * 2;
        }
    }
    return up_count;
}

void link_leaf_tick(server_t *srv) { if (srv->cfg.links.autoconnect) link_dial_peers(srv, 0, NULL); }

/* ponytail: fixed, not a config knob -- only pre-configured peers (n_peers,
 * checked at handshake time) are ever supposed to reach this listener, so a
 * couple of concurrent connections per IP (reconnect races) is plenty; more
 * than that from one address is noise or a flood, not a legitimate peer. */
#define LINK_MAX_UNAUTH_PER_IP 3
/* Per-IP alone left srv->links itself unbounded, and each link_conn_t is
 * ~8KB of fixed rbuf plus its sendq (link.h) -- an attacker with many source addresses
 * could allocate freely. Only pre-configured peers ever belong here, so a
 * couple of dozen is already far more than any real topology needs. */
#define LINK_MAX_TOTAL 64
/* Hard deadline on a handshake, independent of last_activity: the two-line
 * PASS/SERVER exchange takes milliseconds, and an idle-timeout alone lets an
 * unauthenticated peer hold its slot indefinitely by trickling bytes. */
#define LINK_HANDSHAKE_DEADLINE 30

/* Rate limit on the scrypt verify below (~30ms, run synchronously on the
 * event loop -- link connections are rare enough in practice that offloading
 * it to the worker pool the way client SASL/OPER logins are wasn't worth the
 * added complexity of deferring a link handshake across a job result). Only
 * a connection whose SERVER name matches a configured peer reaches the
 * verify at all, but LINK_MAX_UNAUTH_PER_IP bounds *concurrency*, not rate --
 * a connect/verify/disconnect loop from one IP can otherwise keep the single
 * event-loop thread pinned in scrypt close to 100% of the time. */
#define LINK_VERIFY_MAX    3
#define LINK_VERIFY_WINDOW 10
typedef struct { char ip[64]; time_t window_start; int count; } link_verify_track_t;
static link_verify_track_t g_link_verify_tracks[LINK_MAX_UNAUTH_PER_IP * 8];
#define LINK_VERIFY_SLOTS (int)(sizeof g_link_verify_tracks / sizeof g_link_verify_tracks[0])

static int link_verify_throttled(const char *ip) {
    time_t now = time(NULL);
    int slot = -1, oldest_i = 0;
    time_t oldest = now + 1;
    for (int i = 0; i < LINK_VERIFY_SLOTS; i++) {
        if (strcmp(g_link_verify_tracks[i].ip, ip) == 0) { slot = i; break; }
        time_t ws = g_link_verify_tracks[i].window_start;
        if (!g_link_verify_tracks[i].ip[0]) { oldest_i = i; oldest = 0; }
        else if (ws < oldest) { oldest = ws; oldest_i = i; }
    }
    if (slot < 0) slot = oldest_i;
    link_verify_track_t *t = &g_link_verify_tracks[slot];
    if (strcmp(t->ip, ip) != 0 || now - t->window_start > LINK_VERIFY_WINDOW) {
        snprintf(t->ip, sizeof t->ip, "%s", ip);
        t->window_start = now;
        t->count = 0;
    }
    return ++t->count > LINK_VERIFY_MAX;
}

/* 1 if `ip` matches one of the peer's allowed_ips globs (or it has none). */
static int peer_ip_allowed(const cfg_link_peer_t *p, const char *ip) {
    if (p->n_allowed_ips == 0) return 1;
    for (int j = 0; j < p->n_allowed_ips; j++)
        if (irc_ip_mask_match(p->allowed_ips[j], ip)) return 1;
    return 0;
}

void link_accept(server_t *srv, int listen_fd) {
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    int fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) {
        if (errno == EMFILE || errno == ENFILE) { /* listener stays readable -- don't spin poll() */
            log_error("link", "accept failed: %s -- pausing the listeners for 1s", strerror(errno));
            srv->accept_paused_until = time(NULL) + 1;
        }
        return;
    }

    char ipbuf[64];
    if (irc_sockaddr_ip((struct sockaddr *)&peer, ipbuf, sizeof ipbuf, NULL) != 0) { close(fd); return; }

    /* Same blocklist as the client listener -- a K-lined host shouldn't get
     * a free pass at the link port just because it's a different socket. */
    const char *kline_reason = server_kline_match(srv, ipbuf, NULL, ipbuf, 0);
    if (kline_reason) {
        close(fd);
        log_warn("link", "rejected inbound link from %s: %s", ipbuf, kline_reason);
        return;
    }

    /* Peer IP allowlist (like Unreal/InspIRCd's link{}/<link> host match):
     * if ANY configured peer sets allowed_ips, an incoming connection must
     * match at least one of them across all peers, checked before the
     * SERVER/PASS handshake even starts -- the peer name it'll claim to be
     * isn't known yet. No peer sets allowed_ips (the default) -> unchanged,
     * open behavior, same as before this existed. */
    int all_listed = srv->cfg.links.n_peers > 0, ip_allowed = 0;
    for (int i = 0; i < srv->cfg.links.n_peers; i++) {
        cfg_link_peer_t *p = &srv->cfg.links.peers[i];
        if (p->n_allowed_ips == 0) { all_listed = 0; continue; }
        if (peer_ip_allowed(p, ipbuf)) ip_allowed = 1;
    }
    /* A peer without a list stays reachable from anywhere (back-compat), so
     * the pre-handshake gate only closes when every peer is restricted and
     * none matches. The claimed peer's own list is enforced at SERVER time. */
    if (all_listed && !ip_allowed) {
        close(fd);
        log_warn("link", "rejected inbound link from %s: not in any peer's allowed_ips", ipbuf);
        return;
    }

    int count = 0, total = 0;
    for (link_conn_t *l = srv->links; l; l = l->next) {
        if (l->closing) continue;
        total++;
        if (strcmp(l->ip, ipbuf) == 0) count++;
    }
    if (total >= LINK_MAX_TOTAL) {
        close(fd);
        log_warn("link", "rejected inbound link from %s: already at %d concurrent links", ipbuf, LINK_MAX_TOTAL);
        return;
    }
    if (count >= LINK_MAX_UNAUTH_PER_IP) {
        close(fd);
        log_warn("link", "rejected inbound link from %s: too many concurrent connections from this host", ipbuf);
        return;
    }

    if (srv->cfg.links.tls && !srv->tls_ctx) {
        /* [tls] is required whenever [links] tls+mode=hub (config.c) --
         * reaching here means the cert failed to load at startup (see
         * net.c's tls_setup). Refuse rather than silently accepting the
         * link in cleartext. */
        log_error("link", "rejecting inbound link: [links] tls is enabled but the server's TLS context never initialized");
        close(fd);
        return;
    }

    net_set_nonblocking(fd);
    link_conn_t *lc = calloc(1, sizeof *lc);
    if (!lc) { close(fd); return; }
    lc->fd = fd;
    snprintf(lc->ip, sizeof lc->ip, "%s", ipbuf);
    lc->created = lc->last_activity = time(NULL);
    if (srv->cfg.links.tls) {
        lc->ssl = SSL_new(srv->tls_ctx);
        SSL_set_mode(lc->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_verify(lc->ssl, SSL_VERIFY_PEER, accept_any_cert); /* ask for (never require) the dialer's certificate, for pinning */
        SSL_set_fd(lc->ssl, fd);
        lc->tls_handshaking = 1;
        lc->tls_sniff = strncmp(ipbuf, "127.", 4) == 0 || strcmp(ipbuf, "0::1") == 0; /* the services daemon on this box doesn't speak TLS */
    }
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "inbound link connection accepted from %s (fd=%d)%s", ipbuf, fd, lc->ssl ? " [TLS]" : "");
    if (lc->tls_handshaking) link_tls_try_handshake(srv, lc); /* often completes in the same event as accept() */
}

void link_forward_line(link_conn_t *lc, const char *line) {
    if (lc->closing) return;
    size_t len = strlen(line), need = lc->sbuf_len - lc->sbuf_off + len + 2;
    if (need > LINK_SENDQ_MAX) { /* dropping one line silently desyncs the network; dropping the link resyncs it */
        log_warn("link", "link '%s' sendq exceeded (%zu bytes), closing it", lc->peer_name, need);
        lc->closing = 1;
        return;
    }
    if (lc->sbuf_len + len + 2 > lc->sbuf_cap) {
        if (lc->sbuf_off) { /* reclaim what the socket already took before growing */
            memmove(lc->sbuf, lc->sbuf + lc->sbuf_off, lc->sbuf_len - lc->sbuf_off);
            lc->sbuf_len -= lc->sbuf_off;
            lc->sbuf_off = 0;
        }
        if (lc->sbuf_len + len + 2 > lc->sbuf_cap) {
            size_t cap = lc->sbuf_cap ? lc->sbuf_cap : 16384;
            while (cap < lc->sbuf_len + len + 2) cap *= 2;
            char *nb = realloc(lc->sbuf, cap);
            if (!nb) { log_error("link", "link '%s': out of memory for the sendq, closing it", lc->peer_name); lc->closing = 1; return; }
            lc->sbuf = nb;
            lc->sbuf_cap = cap;
        }
    }
    memcpy(lc->sbuf + lc->sbuf_len, line, len);
    lc->sbuf_len += len;
    lc->sbuf[lc->sbuf_len++] = '\r';
    lc->sbuf[lc->sbuf_len++] = '\n';
}

void link_handle_writable(server_t *srv, link_conn_t *lc) {
    if (lc->sbuf_len == lc->sbuf_off || lc->closing) return;
    ssize_t n = link_io_write(lc, lc->sbuf + lc->sbuf_off, lc->sbuf_len - lc->sbuf_off);
    if (n > 0) {
        lc->sbuf_off += (size_t)n;
        if (lc->sbuf_off == lc->sbuf_len) { /* drained: give a burst-sized buffer back */
            lc->sbuf_off = lc->sbuf_len = 0;
            if (lc->sbuf_cap > 65536) { free(lc->sbuf); lc->sbuf = NULL; lc->sbuf_cap = 0; }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        link_close(srv, lc);
    }
}

void link_close(server_t *srv, link_conn_t *lc) {
    (void)srv;
    lc->closing = 1;
}

void link_reap(server_t *srv) {
    link_conn_t **pp = &srv->links;
    while (*pp) {
        link_conn_t *lc = *pp;
        if (!lc->closing) { pp = &lc->next; continue; }
        *pp = lc->next;
        if (lc->is_server) netsync_link_down(srv, lc, "Link closed");
        for (int b = 0; b < lc->n_bots; b++) {
            log_info("link", "link '%s' lost -- removing service nick '%s'", lc->peer_name, lc->bots[b]->nick);
            server_remove_client(srv, lc->bots[b], "Service disconnected");
        }
        if (lc->sbuf_len > lc->sbuf_off && !lc->tls_handshaking) /* best effort: a parting ERROR tells the peer why */
            (void)link_io_write(lc, lc->sbuf + lc->sbuf_off, lc->sbuf_len - lc->sbuf_off);
        free(lc->sbuf);
        if (lc->ssl) SSL_free(lc->ssl); /* abrupt close, no SSL_shutdown close_notify -- fine for a teardown path */
        if (lc->fd >= 0) close(lc->fd);
        if (lc->peer_name[0]) {
            log_info("link", "link '%s' closed", lc->peer_name);
            char snote[200];
            snprintf(snote, sizeof snote, "Link with %s lost", lc->peer_name);
            server_notify_opers(srv, snote);
        } else {
            log_info("link", "unauthenticated link from %s closed", lc->ip[0] ? lc->ip : "?");
        }
        free(lc);
    }
}

/* The bot a services line acts as: the one its ":nick!user@host" prefix names, else the first one introduced. */
static client_t *link_bot(link_conn_t *lc, const char *prefix) {
    if (prefix) {
        size_t n = strcspn(prefix, "!");
        for (int b = 0; b < lc->n_bots; b++)
            if (strlen(lc->bots[b]->nick) == n && strncasecmp(lc->bots[b]->nick, prefix, n) == 0) return lc->bots[b];
    }
    return lc->service;
}

static void send_svc_user(server_t *srv, link_conn_t *lc, client_t *u, int ev) {
    char line[700];
    if (ev == SVC_EV_USER) {
        const char *p[] = {u->uid, u->nick, u->user, u->realhost, u->ip, u->account[0] ? u->account : "*",
                           u->certfp[0] ? u->certfp : "*", netsync_server_name_of(srv, u)};
        irc_build(line, sizeof line, NULL, 0, NULL, "SVCUSER", p, 8, NULL);
    } else if (ev == SVC_EV_NICK) irc_build(line, sizeof line, NULL, 0, NULL, "SVCNICK", (const char *[]){u->uid, u->nick}, 2, NULL);
    else if (ev == SVC_EV_QUIT) irc_build(line, sizeof line, NULL, 0, NULL, "SVCQUIT", (const char *[]){u->uid}, 1, NULL);
    else irc_build(line, sizeof line, NULL, 0, NULL, "SVCACCOUNT", (const char *[]){u->uid, u->account[0] ? u->account : "*"}, 2, NULL);
    link_forward_line(lc, line);
}

void link_svc_user(server_t *srv, client_t *cl, int ev) {
    if (cl->is_service || !cl->uid[0] || !cl->registered) return;
    for (link_conn_t *lc = srv->links; lc; lc = lc->next)
        if (lc->watch_users && !lc->closing) send_svc_user(srv, lc, cl, ev);
}

/* Returns -1 if `lc` was closed while handling this line, so the caller
 * (link_handle_readable) stops processing further lines from it. */
static int link_process_line(server_t *srv, link_conn_t *lc, char *line) {
    irc_message_t msg;
    if (irc_parse_line(line, &msg) != 0) return 0;

    if (!lc->authenticated) {
        if (strcasecmp(msg.command, "PASS") == 0) {
            if (msg.nparams >= 1) snprintf(lc->pending_pass, sizeof lc->pending_pass, "%s", msg.params[0]);
            return 0;
        }
        if (strcasecmp(msg.command, "CAPAB") == 0) { /* CAPAB :SEKURNET -- the peer wants the state-sync protocol */
            if (msg.nparams >= 1 && strstr(msg.params[msg.nparams - 1], "SEKURNET")) {
                lc->peer_capab_sekurnet = 1;
                snprintf(lc->peer_capab, sizeof lc->peer_capab, "%s", msg.params[msg.nparams - 1]);
            }
            return 0;
        }
        if (strcasecmp(msg.command, "SERVER") == 0) {
            if (msg.nparams < 1) { link_close(srv, lc); return -1; }
            const char *name = msg.params[0];
            cfg_link_peer_t *matched = NULL;
            for (int i = 0; i < srv->cfg.links.n_peers; i++) {
                cfg_link_peer_t *p = &srv->cfg.links.peers[i];
                if (p->host[0]) continue; /* leaf-role entries never accept inbound */
                if (strcmp(p->name, name) == 0) { matched = p; break; }
            }
            int ok = 0;
            if (matched && matched->fingerprint[0] && !fingerprint_ok(lc, name, matched->fingerprint)) {
                matched = NULL; /* fingerprint_ok logged why */
            } else if (matched && matched->password_hash[0] && link_verify_throttled(lc->ip)) {
                log_warn("link", "rejected link handshake from '%s': too many recent password checks from %s", name, lc->ip);
            } else if (matched) {
                ok = matched->password_hash[0] ? crypto_verify_password(lc->pending_pass, matched->password_hash)
                   : matched->password[0]      ? crypto_secure_streq(lc->pending_pass, matched->password)
                                               : 1; /* fingerprint-only: the certificate was the credential */
            }
            if (ok && !peer_ip_allowed(matched, lc->ip)) {
                log_warn("link", "rejected link handshake from '%s': %s is not in that peer's allowed_ips", name, lc->ip);
                ok = 0;
            }
            /* Reject outright if this name is already linked -- matches the
             * Python original's "bad credentials or already linked" check.
             * Without this, a reconnect that races a not-yet-reaped stale
             * connection (dead peer, no FIN seen yet) authenticates a
             * second live link_conn_t for the same name, which then shows
             * up twice in /MAP until the stale one's ping_timeout expires. */
            if (ok) {
                for (link_conn_t *other = srv->links; other; other = other->next) {
                    if (other != lc && other->authenticated && !other->closing && strcasecmp(other->peer_name, name) == 0) {
                        ok = 0;
                        break;
                    }
                }
            }
            if (!ok) {
                log_warn("link", "rejected link handshake from '%s' (bad name/password, or already linked)", name);
                link_close(srv, lc);
                return -1;
            }
            snprintf(lc->peer_name, sizeof lc->peer_name, "%s", name);
            lc->authenticated = 1;
            if (lc->peer_capab_sekurnet && msg.nparams >= 4) { /* a server link: answer in kind, then burst */
                const char *sid = msg.params[2];
                int sid_ok = strlen(sid) == 3 && isdigit((unsigned char)sid[0]);
                for (int k = 1; k < 3 && sid_ok; k++) sid_ok = isdigit((unsigned char)sid[k]) || (sid[k] >= 'A' && sid[k] <= 'Z');
                if (!sid_ok) { link_forward_line(lc, "ERROR :Bad SID"); link_close(srv, lc); return -1; }
                if (netsync_find_sid(srv, sid) || netsync_find_name(srv, name)) { /* refuse before answering, or the dialer thinks it's up */
                    log_warn("netsync", "refusing link to '%s' (%s): name or SID already on the network", name, sid);
                    link_forward_line(lc, "ERROR :Server or SID already exists on this network");
                    link_close(srv, lc);
                    return -1;
                }
                if (netsync_check_peer(srv, lc, name) != 0) { link_forward_line(lc, "ERROR :Incompatible link protocol"); link_close(srv, lc); return -1; }
                char capab[200];
                netsync_capab_line(srv, capab, sizeof capab);
                link_forward_line(lc, capab);
                char me[300];
                const char *mp[] = {srv->cfg.server.name, "1", srv->self_srv->sid};
                irc_build(me, sizeof me, NULL, 0, NULL, "SERVER", mp, 3, srv->self_srv->desc);
                link_forward_line(lc, me);
                log_info("link", "link '%s' authenticated [state sync]", name);
                char sn[200];
                snprintf(sn, sizeof sn, "Link with %s established", name);
                server_notify_opers(srv, sn);
                if (netsync_link_up(srv, lc, name, sid, msg.params[3]) != 0) { link_close(srv, lc); return -1; }
                return 0;
            }
            char resp[300];
            const char *rp[] = {srv->cfg.server.name, "1"};
            irc_build(resp, sizeof resp, NULL, 0, NULL, "SERVER", rp, 2, "sekurircd-c link");
            link_forward_line(lc, resp);
            log_info("link", "link '%s' authenticated", name);
            char snote[200];
            snprintf(snote, sizeof snote, "Link with %s established", name);
            server_notify_opers(srv, snote);
            return 0;
        }
        return 0; /* ignore anything else pre-auth */
    }

    if (lc->is_server) { /* state-sync link: keepalives here, everything else is netsync's (its NICK is a nick change, not a service intro) */
        if (strcasecmp(msg.command, "PING") == 0) { link_forward_line(lc, "PONG"); return 0; }
        if (strcasecmp(msg.command, "PONG") == 0) return 0;
        netsync_handle(srv, lc, &msg);
        return 0;
    }

    if (strcasecmp(msg.command, "NICK") == 0) {
        if (msg.nparams < 4) return 0;
        if (lc->n_bots >= LINK_MAX_BOTS) { log_warn("link", "link '%s' introduced too many service nicks -- ignored", lc->peer_name); return 0; }
        const char *nick = msg.params[0], *user = msg.params[1], *host = msg.params[2];
        const char *realname = msg.params[msg.nparams - 1];
        if (server_find_user(srv, nick)) {
            log_warn("link", "link '%s' introduced nick '%s' which already exists locally -- ignored",
                      lc->peer_name, nick);
            return 0;
        }
        client_t *svc = client_new(-1, srv);
        if (!svc) return 0;
        svc->link_conn = lc;
        svc->is_service = 1;
        svc->ident_confirmed = 1; /* a service's user part is its own, never "~"-marked */
        svc->caps |= CAP_ACCOUNT_TAG; /* PRIVMSGs forwarded to the service carry the sender's account (@account=...) */
        svc->nick_ts = (long)time(NULL);
        svc->registered = 1;
        svc->got_nick = svc->got_user = 1;
        svc->signon_time = svc->last_activity = time(NULL);
        snprintf(svc->nick, sizeof svc->nick, "%s", nick);
        irc_casefold(svc->casefold_nick, sizeof svc->casefold_nick, nick);
        snprintf(svc->user, sizeof svc->user, "%s", user);
        snprintf(svc->host, sizeof svc->host, "%s", host);
        snprintf(svc->realhost, sizeof svc->realhost, "%s", host);
        snprintf(svc->realname, sizeof svc->realname, "%s", realname);
        server_add_user(srv, svc);
        lc->bots[lc->n_bots++] = svc;
        if (!lc->service) { lc->service = svc; sync_ranks_to(srv, lc); } /* the channel service vets the ranks */
        netsync_introduce_user(srv, svc); /* a service nick is a user to the rest of the network too */
        log_info("link", "link '%s' introduced service nick '%s'", lc->peer_name, nick);
        return 0;
    }
    if (strcasecmp(msg.command, "PING") == 0) { link_forward_line(lc, "PONG"); return 0; }
    if (strcasecmp(msg.command, "PONG") == 0) return 0;

    if (strcasecmp(msg.command, "PRIVMSG") == 0 || strcasecmp(msg.command, "NOTICE") == 0) {
        if (msg.nparams < 2) return 0;
        const char *target = msg.params[0];
        client_t *dst = server_find_user(srv, target);
        client_t *svc = link_bot(lc, msg.prefix);
        if (dst && dst->remote && !dst->is_service && svc) { /* a user on another server: relay as the service's own message */
            netsync_message(srv, svc, msg.command, target, dst, msg.params[msg.nparams - 1], NULL, 0);
            return 0;
        }
        if (!dst || dst->fd < 0) return 0; /* no such local user, or it's another service */

        char prefix[320];
        const char *from_nick = svc ? svc->nick : lc->peer_name;
        const char *from_user = svc ? svc->user : lc->peer_name;
        const char *from_host = svc ? svc->host : lc->peer_name;
        irc_prefix_for(prefix, sizeof prefix, from_nick, from_user, from_host);

        char out[700];
        const char *p[] = {target};
        irc_build(out, sizeof out, NULL, 0, prefix, msg.command, p, 1, msg.params[msg.nparams - 1]);
        client_send(dst, out);
        return 0;
    }
    /* From here down: only a link that has already introduced its service
     * identity (NICK) may act as that identity -- these are all "do this
     * AS my service bot" commands. */
    if (!lc->service) return 0;
    client_t *svc = link_bot(lc, msg.prefix);

    if (strcasecmp(msg.command, "SVCWATCH") == 0) { /* the user feed: everyone now, changes from here on */
        lc->watch_users = 1;
        char info[300];
        irc_build(info, sizeof info, NULL, 0, NULL, "SVCINFO", (const char *[]){srv->cfg.server.name}, 1, srv->cfg.server.network);
        link_forward_line(lc, info); /* the network name, for NickServ's mails */
        client_t *u, *tmp;
        HASH_ITER(hh, srv->users, u, tmp) if (u->registered) send_svc_user(srv, lc, u, SVC_EV_USER);
        return 0;
    }
    if (!strcmp(msg.command, "SVSLOGIN") || !strcmp(msg.command, "SVSNICK") || !strcmp(msg.command, "KILL") ||
        !strcmp(msg.command, "SVCSASL") || !strcmp(msg.command, "SVCREGRESULT")) {
        svc_command(srv, svc, &msg);
        return 0;
    }

    if (strcasecmp(msg.command, "JOIN") == 0) {
        if (msg.nparams < 1) return 0;
        cmd_force_join(srv, svc, msg.params[0]);
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        member_t *m = chan ? channel_find_member(chan, svc) : NULL;
        if (m && !(m->rank & RANK_OP)) {
            /* GUARD always holds ops, even joining a channel that already
             * has other members (cmd_force_join only auto-ops the first
             * member into an empty/new channel). */
            m->rank |= RANK_OP;
            char prefix[320];
            client_prefix(svc, prefix, sizeof prefix);
            char modeline[300];
            const char *p[] = {chan->name, "+o", svc->nick};
            irc_build(modeline, sizeof modeline, NULL, 0, prefix, "MODE", p, 3, NULL);
            server_broadcast_channel(chan, modeline, svc);
            netsync_chan_mode(srv, chan, svc, "+o", (const char *[]){svc->nick}, 1); /* the rest of the network sees @ChanServ too */
        }
        return 0;
    }
    if (strcasecmp(msg.command, "PART") == 0) {
        if (msg.nparams < 1) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        if (chan && channel_find_member(chan, svc)) {
            char prefix[320];
            client_prefix(svc, prefix, sizeof prefix);
            char partline[300];
            const char *p[] = {chan->name};
            irc_build(partline, sizeof partline, NULL, 0, prefix, "PART", p, 1, "Guard disabled");
            server_broadcast_channel(chan, partline, NULL);
            netsync_chan_part(srv, chan, svc, "Guard disabled");
            channel_remove_member(chan, svc);
            server_detach_membership(svc, chan);
            server_maybe_drop_channel(srv, chan);
        }
        return 0;
    }
    if (strcasecmp(msg.command, "MODE") == 0) {
        /* Trusted: applied unconditionally, same as any other state-
         * mirroring wire command (see link.h's module doc). Used for
         * ACCESS/IDENTIFY op-grants. */
        if (msg.nparams < 2) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        if (!chan) return 0;
        const char *args[16];
        int nargs = 0;
        for (int i = 2; i < msg.nparams && nargs < 16; i++) args[nargs++] = msg.params[i];
        cmd_apply_channel_mode(srv, svc, chan, msg.params[1], args, nargs, 1);
        return 0;
    }
    if (strcasecmp(msg.command, "TOPIC") == 0) {
        /* Trusted: used for TOPICLOCK restore. Was entirely unhandled --
         * chanserv had no way to actually set a channel's topic over the
         * link, only observe it (see process_line's TOPIC case). */
        if (msg.nparams < 1) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        if (!chan) return 0;
        const char *newtopic = msg.nparams > 1 ? msg.params[msg.nparams - 1] : "";
        snprintf(chan->topic, sizeof chan->topic, "%s", newtopic);
        client_prefix(svc, chan->topic_setter, sizeof chan->topic_setter);
        chan->topic_time = time(NULL);
        char prefix[320];
        client_prefix(svc, prefix, sizeof prefix);
        char line[600];
        const char *p[] = {chan->name};
        irc_build(line, sizeof line, NULL, 0, prefix, "TOPIC", p, 1, chan->topic);
        server_broadcast_channel(chan, line, NULL);
        netsync_chan_topic(srv, chan, svc, chan->topic);
        return 0;
    }
    if (strcasecmp(msg.command, "KICK") == 0) {
        /* Trusted: used for AKICK enforcement. */
        if (msg.nparams < 2) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        client_t *target = server_find_user(srv, msg.params[1]);
        if (!chan || !target || !channel_find_member(chan, target)) return 0;
        const char *reason = msg.nparams > 2 ? msg.params[msg.nparams - 1] : "Kicked";
        char prefix[320];
        client_prefix(svc, prefix, sizeof prefix);
        char kickline[500];
        const char *p[] = {chan->name, target->nick};
        irc_build(kickline, sizeof kickline, NULL, 0, prefix, "KICK", p, 2, reason);
        server_broadcast_channel(chan, kickline, NULL);
        netsync_chan_kick(srv, chan, svc, target, reason);
        channel_remove_member(chan, target);
        server_detach_membership(target, chan);
        server_maybe_drop_channel(srv, chan);
        return 0;
    }
    if (strcasecmp(msg.command, "INVITE") == 0) {
        /* Trusted: ChanServ's INVITE command. Unlike a real client's
         * /INVITE (cmd_chan.c's cmd_invite), no membership/op check --
         * that's the whole point of routing it through the password- or
         * ACCESS-gated service command instead. */
        if (msg.nparams < 2) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        client_t *target = server_find_user(srv, msg.params[1]);
        if (!chan || !target) return 0;
        channel_invite_add(chan, client_invite_key(target));
        char prefix[320];
        client_prefix(svc, prefix, sizeof prefix);
        char line[300];
        const char *p[] = {target->nick};
        irc_build(line, sizeof line, NULL, 0, prefix, "INVITE", p, 1, chan->name);
        client_send(target, line);
        netsync_invite(srv, svc, target, chan);
        return 0;
    }
    if (strcasecmp(msg.command, "UNBAN") == 0) {
        /* Trusted: removes every ban mask (structural +b, not a quiet m:/
         * ~m: -- see channel.c) currently matching `nick`'s real identity
         * (host, realhost, ip or account) from `chan`, one MODE -b per
         * removed mask (simplest correct framing; UNBAN is not a hot path). */
        if (msg.nparams < 2) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        client_t *target = server_find_user(srv, msg.params[1]);
        if (!chan || !target) return 0;
        char prefix[320];
        client_prefix(svc, prefix, sizeof prefix);
        for (int i = chan->bans.n - 1; i >= 0; i--) {
            char mask[256];
            snprintf(mask, sizeof mask, "%s", chan->bans.masks[i]);
            channel_set_ban_extra(NULL); /* AKICK cleanup: no stale client context for ~r/~z/~j */
            int hit = channel_mask_hit(mask, target->nick, target->user, target->host, target->account, target->ident_confirmed) ||
                      channel_mask_hit(mask, target->nick, target->user, target->realhost, target->account, target->ident_confirmed) ||
                      channel_mask_hit(mask, target->nick, target->user, target->ip, target->account, target->ident_confirmed);
            if (!hit) continue;
            masklist_del(&chan->bans, mask);
            char line[400];
            const char *p[] = {chan->name, "-b", mask};
            irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p, 3, NULL);
            server_broadcast_channel(chan, line, NULL);
            netsync_chan_mode(srv, chan, svc, "-b", (const char *[]){mask}, 1); /* lifted network-wide, not just here */
        }
        return 0;
    }
    if (strcasecmp(msg.command, "WHOISUSER") == 0) {
        /* Real (realhost/account/ident_confirmed) identity of a nick, for
         * SUCCESSOR CLAIM -- matching against the PRIVMSG prefix instead
         * (the cloaked display host under host_masking) meant a hostmask
         * successor could never claim, and an "=account" successor never
         * matched at all (it went through irc_mask_match, which doesn't
         * know about the "=" account syntax). "*" fields mean not found. */
        if (msg.nparams < 1) return 0;
        client_t *target = server_find_user(srv, msg.params[0]);
        char reply[400];
        if (target) {
            const char *rp[] = {msg.params[0], target->user, target->realhost,
                                 target->account[0] ? target->account : "*",
                                 target->ident_confirmed ? "1" : "0"};
            irc_build(reply, sizeof reply, NULL, 0, NULL, "WHOISUSERREPLY", rp, 5, NULL);
        } else {
            const char *rp[] = {msg.params[0], "*", "*", "*", "0"};
            irc_build(reply, sizeof reply, NULL, 0, NULL, "WHOISUSERREPLY", rp, 5, NULL);
        }
        link_forward_line(lc, reply);
        return 0;
    }
    if (strcasecmp(msg.command, "WHOISCHAN") == 0) {
        /* Synchronous-ish rank query -- lets chanserv check "is this nick
         * an op in that channel" (REGISTER's requirement) without needing
         * a full membership mirror. */
        if (msg.nparams < 2) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        client_t *target = chan ? server_find_user(srv, msg.params[1]) : NULL;
        member_t *m = target ? channel_find_member(chan, target) : NULL;
        const char *rank = "none";
        if (m) rank = (m->rank & RANK_OP) ? "o" : (m->rank & RANK_HALFOP) ? "h" : (m->rank & RANK_VOICE) ? "v" : "none";
        char reply[300];
        const char *rp[] = {msg.params[0], msg.params[1], rank};
        irc_build(reply, sizeof reply, NULL, 0, NULL, "WHOISCHANREPLY", rp, 3, NULL);
        link_forward_line(lc, reply);
        return 0;
    }
    if (strcasecmp(msg.command, "SVCMEMBERS") == 0) {
        /* The live topic, then every current member's real identity + ranks, so a ChanServ setting change (ACCESS,
         * AKICK, RESTRICTED, SECUREOPS, FOUNDER, TOPICLOCK) takes effect without anyone rejoining. */
        if (msg.nparams < 1) return 0;
        channel_t *chan = server_find_channel(srv, msg.params[0]);
        if (!chan) return 0;
        char tline[600];
        irc_build(tline, sizeof tline, NULL, 0, NULL, "SVCTOPIC", (const char *[]){chan->name}, 1, chan->topic);
        link_forward_line(lc, tline);
        member_t *m, *mtmp;
        HASH_ITER(hh, chan->members, m, mtmp)
            if (!m->client->is_service) send_member_line(lc, "SVCMEMBER", chan, m->client, m->rank);
        return 0;
    }
    /* SQUIT or anything else unrecognized: ignored, same "log, never spam
     * back" policy as the client-facing dispatcher. */
    return 0;
}

/* <cmd> <chan> <nick> <user> <realhost> <account|*> <ident 0|1> <ranks qaohv, or "-" for none>. SVCSYNC (ranked
 * members only, for ChanServ to vet) and SVCMEMBER (every member, answering SVCMEMBERS) share this shape. */
static void send_member_line(link_conn_t *lc, const char *cmd, channel_t *chan, client_t *u, int rank) {
    char ranks[8] = "";
    if (rank & RANK_OWNER) strcat(ranks, "q");
    if (rank & RANK_ADMIN) strcat(ranks, "a");
    if (rank & RANK_OP) strcat(ranks, "o");
    if (rank & RANK_HALFOP) strcat(ranks, "h");
    if (rank & RANK_VOICE) strcat(ranks, "v");
    if (!ranks[0]) strcpy(ranks, "-");
    char line[500];
    const char *p[] = {chan->name, u->nick, u->user, u->realhost, u->account[0] ? u->account : "*", u->ident_confirmed ? "1" : "0", ranks};
    irc_build(line, sizeof line, NULL, 0, NULL, cmd, p, 7, NULL);
    link_forward_line(lc, line);
}

static void send_svcsync(link_conn_t *lc, channel_t *chan, client_t *u, int rank) {
    if (rank & (RANK_OWNER | RANK_ADMIN | RANK_OP | RANK_HALFOP | RANK_VOICE)) send_member_line(lc, "SVCSYNC", chan, u, rank);
}

/* A new service link: let it vet every rank already handed out while it was away. */
static void sync_ranks_to(server_t *srv, link_conn_t *lc) {
    channel_t *chan, *ctmp;
    HASH_ITER(hh, srv->channels, chan, ctmp) {
        member_t *m, *mtmp;
        HASH_ITER(hh, chan->members, m, mtmp)
            if (!m->client->is_service) send_svcsync(lc, chan, m->client, m->rank);
    }
}

/* A channel just appeared (created by a local JOIN, or by a remote SJOIN/JOIN): services restore +r/MLOCK/GUARD on it. */
void link_notify_channel_new(server_t *srv, channel_t *chan, client_t *creator) {
    char line[300];
    const char *p[] = {chan->name};
    irc_build(line, sizeof line, NULL, 0, NULL, "SVCNEW", p, 1, NULL);
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (!lc->service || lc->closing || !lc->authenticated) continue;
        link_forward_line(lc, line);
        member_t *m = creator ? channel_find_member(chan, creator) : NULL;
        if (m) send_svcsync(lc, chan, creator, m->rank);
    }
}

void link_notify_channel_join(channel_t *chan, client_t *joiner) {
    if (channel_member_count(chan) == 1 && joiner->srv && !joiner->remote) link_notify_channel_new(joiner->srv, chan, joiner);
    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        client_t *svc = m->client;
        if (svc == joiner || !svc->is_service || !svc->link_conn) continue;
        char line[500];
        /* realhost, not the cloak: the services link is trusted, and a
         * random per-connection cloak could never match an ACCESS/AKICK mask. */
        /* The 6th field is ident_confirmed: without it ChanServ can't know
         * whether to tilde-prefix the ident when matching ACCESS/AKICK masks,
         * and silently mismatches every ident-confirmed user. */
        const char *p[] = {chan->name, joiner->nick, joiner->user, joiner->realhost,
                            joiner->account[0] ? joiner->account : "*",
                            joiner->ident_confirmed ? "1" : "0"};
        irc_build(line, sizeof line, NULL, 0, NULL, "SVCJOIN", p, 6, NULL);
        link_forward_line(svc->link_conn, line);
    }
}

/* Returns 1 to keep going (caller should check SSL_pending again), 0 once
 * this pass genuinely has nothing left to read. */
static int link_handle_readable_once(server_t *srv, link_conn_t *lc) {
    char tmp[4096];
    ssize_t n = link_io_read(lc, tmp, sizeof tmp);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (n <= 0) { link_close(srv, lc); return 0; }
    lc->last_activity = time(NULL);
    /* Enforces the *configured* links.max_line_length (validated at load
     * time to be <= LINK_BUF, see config.c), not just the raw buffer
     * capacity -- a smaller configured value now actually cuts lines
     * shorter instead of being silently ignored. */
    if (lc->rbuf_len + (size_t)n >= (size_t)LINK_BUF) { /* raw capacity; the per-line limit is checked below */
        log_warn("link", "link '%s' line too long, dropping connection", lc->peer_name);
        link_close(srv, lc);
        return 0;
    }
    memcpy(lc->rbuf + lc->rbuf_len, tmp, (size_t)n);
    lc->rbuf_len += (size_t)n;

    size_t start = 0;
    for (size_t i = 0; i < lc->rbuf_len; i++) {
        if (lc->rbuf[i] != '\n') continue;
        size_t end = i;
        if (end > start && lc->rbuf[end - 1] == '\r') end--;
        if (end - start >= (size_t)srv->cfg.links.max_line_length) { /* one line, not the whole read -- several short lines may arrive together */
            log_warn("link", "link '%s' line too long, dropping connection", lc->peer_name);
            link_close(srv, lc);
            return 0;
        }
        lc->rbuf[end] = '\0';
        if (link_process_line(srv, lc, lc->rbuf + start) < 0) return 0; /* closing -- drop the rest */
        start = i + 1;
    }
    memmove(lc->rbuf, lc->rbuf + start, lc->rbuf_len - start);
    lc->rbuf_len -= start;
    if (lc->rbuf_len >= (size_t)srv->cfg.links.max_line_length) { /* unterminated partial line already too long */
        log_warn("link", "link '%s' line too long, dropping connection", lc->peer_name);
        link_close(srv, lc);
        return 0;
    }
    return 1;
}

/* A TLS record can hold more plaintext than one read drains; the rest sits
 * decrypted inside OpenSSL where poll() can't see it (same reasoning as
 * net.c's read_client) -- keep reading while SSL_pending says so. */
void link_handle_readable(server_t *srv, link_conn_t *lc) {
    if (lc->closing) return;
    while (link_handle_readable_once(srv, lc) && lc->ssl && !lc->closing && SSL_pending(lc->ssl) > 0) {}
}

void link_tick(server_t *srv) {
    time_t now = time(NULL);
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (lc->closing) continue;
        double idle = difftime(now, lc->last_activity);
        if (!lc->authenticated) {
            /* A handshake is two lines; an idle unauthenticated socket is
             * just holding an fd open. The absolute deadline matters as much
             * as the idle one: trickling bytes keeps last_activity fresh
             * forever without ever completing the exchange. */
            if (idle > srv->cfg.links.ping_interval ||
                difftime(now, lc->created) > LINK_HANDSHAKE_DEADLINE) {
                log_warn("link", "unauthenticated link connection (fd=%d) timed out", lc->fd);
                link_close(srv, lc);
            }
        } else if (idle > srv->cfg.links.ping_timeout) {
            log_warn("link", "link '%s' timed out", lc->peer_name);
            link_close(srv, lc);
        } else if (idle > srv->cfg.links.ping_interval && difftime(now, lc->last_ping) >= srv->cfg.links.ping_interval) {
            lc->last_ping = now; /* one PING per interval, not one per tick */
            link_forward_line(lc, "PING");
        }
    }
}
