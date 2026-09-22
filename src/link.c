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
#include <time.h>
#include <unistd.h>

/* --- TLS (optional, [links] tls=true) --------------------------------------
 * Hub side reuses srv->tls_ctx (the same cert the client-facing TLS listener
 * uses -- config.c requires [tls] enabled whenever [links] tls+mode=hub).
 * Leaf side dials out as a TLS client, honoring tls_insecure_skip_verify;
 * its SSL_CTX is created once, lazily, and freed at shutdown. */

static ssize_t link_io_read(link_conn_t *lc, void *buf, size_t len) {
    if (!lc->ssl) return read(lc->fd, buf, len);
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
    int n = SSL_write(lc->ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(lc->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

static SSL_CTX *g_leaf_tls_ctx;

static SSL_CTX *leaf_tls_ctx(void) {
    if (!g_leaf_tls_ctx) {
        g_leaf_tls_ctx = SSL_CTX_new(TLS_client_method());
        if (g_leaf_tls_ctx) SSL_CTX_set_default_verify_paths(g_leaf_tls_ctx);
    }
    return g_leaf_tls_ctx;
}

void link_tls_cleanup(void) {
    if (g_leaf_tls_ctx) { SSL_CTX_free(g_leaf_tls_ctx); g_leaf_tls_ctx = NULL; }
}

void link_tls_try_handshake(server_t *srv, link_conn_t *lc) {
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
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "hub") != 0) return -1;
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
    return 0;
}

static int dial_uplink(const char *host, int port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portbuf[16];
    snprintf(portbuf, sizeof portbuf, "%d", port);
    if (getaddrinfo(host, portbuf, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    int rc = connect_bounded(fd, res->ai_addr, res->ai_addrlen, LINK_DIAL_TIMEOUT_MS);
    freeaddrinfo(res);
    if (rc != 0) { close(fd); return -1; }
    return fd;
}

int link_connect_leaf(server_t *srv) {
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "leaf") != 0) return -1;
    if (srv->cfg.links.n_peers < 1) return -1;
    cfg_link_peer_t *up = &srv->cfg.links.peers[0];

    int fd = dial_uplink(up->host, up->port);
    if (fd < 0) {
        log_warn("link", "could not connect to uplink %s:%d", up->host, up->port);
        return -1;
    }

    link_conn_t *lc = calloc(1, sizeof *lc);
    if (!lc) { close(fd); return -1; }
    lc->fd = fd;

    if (srv->cfg.links.tls) {
        SSL_CTX *ctx = leaf_tls_ctx();
        if (!ctx) {
            log_error("link", "TLS setup failed dialing uplink %s:%d", up->host, up->port);
            close(fd); free(lc); return -1;
        }
        lc->ssl = SSL_new(ctx);
        SSL_set_fd(lc->ssl, fd);
        if (!srv->cfg.links.tls_insecure_skip_verify) {
            SSL_set_verify(lc->ssl, SSL_VERIFY_PEER, NULL);
            SSL_set1_host(lc->ssl, up->host); /* checked against the cert's SAN/CN, not just chain trust */
        }
        if (SSL_connect(lc->ssl) != 1) {
            char errbuf[256];
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
            log_warn("link", "TLS handshake to uplink %s:%d failed: %s", up->host, up->port, errbuf);
            SSL_free(lc->ssl); close(fd); free(lc);
            return -1;
        }
        log_info("link", "TLS established to uplink %s:%d (%s/%s)", up->host, up->port,
                  SSL_get_version(lc->ssl), SSL_get_cipher_name(lc->ssl));
    }

    char line[512];
    snprintf(line, sizeof line, "PASS %s", up->password);
    if (write_line_blocking(lc, line) != 0) {
        log_warn("link", "write failed sending handshake to uplink %s:%d", up->host, up->port);
        goto fail;
    }
    const char *p[] = {srv->cfg.server.name, "1"};
    irc_build(line, sizeof line, NULL, 0, NULL, "SERVER", p, 2, "sekurircd-c link");
    if (write_line_blocking(lc, line) != 0) {
        log_warn("link", "write failed sending handshake to uplink %s:%d", up->host, up->port);
        goto fail;
    }

    char resp[512];
    if (read_line_blocking(lc, resp, sizeof resp, LINK_HANDSHAKE_TIMEOUT_MS) != 0) {
        log_warn("link", "uplink '%s' did not respond to the handshake", up->name);
        goto fail;
    }
    irc_message_t msg;
    if (irc_parse_line(resp, &msg) != 0 || strcasecmp(msg.command, "SERVER") != 0 ||
        msg.nparams < 1 || strcmp(msg.params[0], up->name) != 0) {
        log_warn("link", "uplink handshake failed (bad reply or name mismatch)");
        goto fail;
    }

    net_set_nonblocking(fd);
    lc->authenticated = 1;
    snprintf(lc->peer_name, sizeof lc->peer_name, "%s", up->name);
    lc->created = lc->last_activity = time(NULL);
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "connected to uplink '%s'%s", up->name, lc->ssl ? " (TLS)" : "");
    char snote[200];
    snprintf(snote, sizeof snote, "Link with %s established", up->name);
    server_notify_opers(srv, snote);
    return 0;

fail:
    if (lc->ssl) SSL_free(lc->ssl);
    close(fd);
    free(lc);
    return -1;
}

void link_leaf_tick(server_t *srv) {
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "leaf") != 0) return;
    if (srv->links) return; /* already connected (or connecting) */
    time_t now = time(NULL);
    if (now < srv->leaf_next_attempt) return;

    if (link_connect_leaf(srv) == 0) {
        srv->leaf_backoff = srv->cfg.links.reconnect_delay;
    } else {
        if (srv->leaf_backoff <= 0) srv->leaf_backoff = srv->cfg.links.reconnect_delay;
        srv->leaf_next_attempt = now + (time_t)srv->leaf_backoff;
        srv->leaf_backoff = srv->leaf_backoff * 2 > srv->cfg.links.reconnect_delay_max
                                ? srv->cfg.links.reconnect_delay_max : srv->leaf_backoff * 2;
    }
}

/* ponytail: fixed, not a config knob -- only pre-configured peers (n_peers,
 * checked at handshake time) are ever supposed to reach this listener, so a
 * couple of concurrent connections per IP (reconnect races) is plenty; more
 * than that from one address is noise or a flood, not a legitimate peer. */
#define LINK_MAX_UNAUTH_PER_IP 3
/* Per-IP alone left srv->links itself unbounded, and each link_conn_t is
 * ~40KB of fixed rbuf+sbuf (link.h) -- an attacker with many source addresses
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

void link_accept(server_t *srv) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    int fd = accept(srv->link_listen_fd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) return;

    char ipbuf[64];
    inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof ipbuf);

    /* Same blocklist as the client listener -- a K-lined host shouldn't get
     * a free pass at the link port just because it's a different socket. */
    const char *kline_reason = server_kline_match(srv, ipbuf, NULL, ipbuf, 0);
    if (kline_reason) {
        close(fd);
        log_warn("link", "rejected inbound link from %s: %s", ipbuf, kline_reason);
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
        SSL_set_fd(lc->ssl, fd);
        lc->tls_handshaking = 1;
    }
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "inbound link connection accepted from %s (fd=%d)%s", ipbuf, fd, lc->ssl ? " [TLS]" : "");
    if (lc->tls_handshaking) link_tls_try_handshake(srv, lc); /* often completes in the same event as accept() */
}

void link_forward_line(link_conn_t *lc, const char *line) {
    if (lc->closing) return;
    size_t len = strlen(line);
    if (lc->sbuf_len + len + 2 >= sizeof lc->sbuf) {
        log_warn("link", "link '%s' sendq overflow, dropping a line", lc->peer_name);
        return;
    }
    memcpy(lc->sbuf + lc->sbuf_len, line, len);
    lc->sbuf_len += len;
    lc->sbuf[lc->sbuf_len++] = '\r';
    lc->sbuf[lc->sbuf_len++] = '\n';
}

void link_handle_writable(server_t *srv, link_conn_t *lc) {
    if (lc->sbuf_len == 0 || lc->closing) return;
    ssize_t n = link_io_write(lc, lc->sbuf, lc->sbuf_len);
    if (n > 0) {
        memmove(lc->sbuf, lc->sbuf + n, lc->sbuf_len - (size_t)n);
        lc->sbuf_len -= (size_t)n;
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
        if (lc->service) {
            log_info("link", "link '%s' lost -- removing service nick '%s'", lc->peer_name, lc->service->nick);
            server_remove_client(srv, lc->service, "Service disconnected");
        }
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
            if (matched && matched->password_hash[0] && link_verify_throttled(lc->ip)) {
                log_warn("link", "rejected link handshake from '%s': too many recent password checks from %s", name, lc->ip);
            } else if (matched) {
                ok = matched->password_hash[0]
                    ? crypto_verify_password(lc->pending_pass, matched->password_hash)
                    : crypto_secure_streq(lc->pending_pass, matched->password);
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

    if (strcasecmp(msg.command, "NICK") == 0) {
        if (msg.nparams < 4) return 0;
        if (lc->service) {
            /* One service identity per link: a second NICK would orphan the
             * first pseudo-client (never removed on link loss, dangling
             * link_conn pointer) -- ignore it. */
            log_warn("link", "link '%s' sent a second NICK -- ignored", lc->peer_name);
            return 0;
        }
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
        lc->service = svc;
        log_info("link", "link '%s' introduced service nick '%s'", lc->peer_name, nick);
        return 0;
    }
    if (strcasecmp(msg.command, "PING") == 0) { link_forward_line(lc, "PONG"); return 0; }
    if (strcasecmp(msg.command, "PONG") == 0) return 0;

    if (strcasecmp(msg.command, "PRIVMSG") == 0 || strcasecmp(msg.command, "NOTICE") == 0) {
        if (msg.nparams < 2) return 0;
        const char *target = msg.params[0];
        client_t *dst = server_find_user(srv, target);
        if (!dst || dst->fd < 0) return 0; /* no such local user, or it's another service */

        char prefix[320];
        client_t *svc = lc->service;
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
    client_t *svc = lc->service;

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
        channel_remove_member(chan, target);
        server_detach_membership(target, chan);
        server_maybe_drop_channel(srv, chan);
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
    /* SQUIT or anything else unrecognized: ignored, same "log, never spam
     * back" policy as the client-facing dispatcher. */
    return 0;
}

void link_notify_channel_join(channel_t *chan, client_t *joiner) {
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
    if (lc->rbuf_len + (size_t)n >= (size_t)srv->cfg.links.max_line_length) {
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
        lc->rbuf[end] = '\0';
        if (link_process_line(srv, lc, lc->rbuf + start) < 0) return 0; /* closing -- drop the rest */
        start = i + 1;
    }
    memmove(lc->rbuf, lc->rbuf + start, lc->rbuf_len - start);
    lc->rbuf_len -= start;
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
        } else if (idle > srv->cfg.links.ping_interval) {
            link_forward_line(lc, "PING");
        }
    }
}
