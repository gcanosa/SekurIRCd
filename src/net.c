/* poll() event loop. Ported (reduced scope for v1.0.1) from server.py's
 * _handle/_read_loop: accept, line-buffered read with the max_line_length/
 * max_params/flood-guard choke point, write-buffered send, and a 1-second
 * tick for PING/timeout, link keepalive, and rehash/shutdown signals.
 *
 * Single-threaded, non-blocking, no locking -- same reasoning as the
 * Python daemon's single asyncio event loop: only one thread ever touches
 * srv->users/srv->channels/srv->links.
 */
#include "net.h"
#include "cmd.h"
#include "config.h"
#include "crypto.h"
#include "link.h"
#include "log.h"
#include "server.h"
#include "worker.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_term = 0;
static volatile sig_atomic_t g_hup = 0;

static void on_term(int sig) { (void)sig; g_term = 1; }
static void on_hup(int sig) { (void)sig; g_hup = 1; }

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    struct sigaction sh;
    memset(&sh, 0, sizeof sh);
    sh.sa_handler = on_hup;
    sigaction(SIGHUP, &sh, NULL);

    signal(SIGPIPE, SIG_IGN); /* a write() to a half-closed socket must not kill the daemon */
}

int net_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int net_listen(const char *bind_addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!bind_addr || strcmp(bind_addr, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 128) < 0) { close(fd); return -1; }
    net_set_nonblocking(fd);
    return fd;
}

/* --- TLS ([tls], user mode +Z, channel mode +z) --------------------------- */

static SSL_CTX *tls_setup(server_t *srv) {
    if (!srv->cfg.tls.enabled) return NULL;
    char cert[CFG_PATH], key[CFG_PATH];
    config_tls_cert_path(&srv->cfg, cert, sizeof cert);
    config_tls_key_path(&srv->cfg, key, sizeof key);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { log_error("tls", "SSL_CTX_new failed"); return NULL; }
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
        log_error("tls", "could not load cert/key (%s / %s): %s", cert, key, errbuf);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_error("tls", "certificate/private key mismatch (%s / %s)", cert, key);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* Drives (or re-drives) SSL_accept() until it completes or genuinely needs
 * to wait for more I/O. On success, grants +Z (see client.h's UMODE_Z). */
static void tls_try_handshake(client_t *cl) {
    int rc = SSL_accept(cl->ssl);
    if (rc == 1) {
        cl->tls_handshaking = 0;
        cl->umodes |= UMODE_Z;
        log_info("net", "TLS handshake complete for %s (fd=%d)", cl->ip, cl->fd);
        return;
    }
    int err = SSL_get_error(cl->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return; /* retry on next poll event */
    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
    log_warn("tls", "handshake failed for %s: err=%d (%s)", cl->ip, err, errbuf);
    cl->quitting = 1;
    snprintf(cl->quit_reason, sizeof cl->quit_reason, "TLS handshake failed");
}

/* Read/write that transparently go through OpenSSL for a TLS client, with
 * the same "-1 + errno=EAGAIN means try later" contract callers already
 * expect from a plain read(2)/write(2). */
static ssize_t io_read(client_t *cl, void *buf, size_t len) {
    if (!cl->ssl) return read(cl->fd, buf, len);
    int n = SSL_read(cl->ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(cl->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

static ssize_t io_write(client_t *cl, const void *buf, size_t len) {
    if (!cl->ssl) return write(cl->fd, buf, len);
    int n = SSL_write(cl->ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(cl->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

/* --- accept ----------------------------------------------------------------- */

static client_t *accept_common(server_t *srv, int listen_fd) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    int fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) return NULL;
    srv->total_connections++;

    if (srv->cfg.security.max_connections > 0 && srv->n_clients >= srv->cfg.security.max_connections) {
        const char *msg = "ERROR :Too many connections\r\n";
        write(fd, msg, strlen(msg));
        close(fd);
        return NULL;
    }
    net_set_nonblocking(fd);

    char ipbuf[64];
    inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof ipbuf);
    const char *kline_reason = server_kline_match(srv, ipbuf);
    if (kline_reason) {
        char err[350];
        snprintf(err, sizeof err, "ERROR :Closing Link: %s (%s)\r\n", ipbuf, kline_reason);
        write(fd, err, strlen(err));
        close(fd);
        log_info("net", "refused %s: %s", ipbuf, kline_reason);
        return NULL;
    }

    client_t *cl = client_new(fd, srv);
    snprintf(cl->ip, sizeof cl->ip, "%s", ipbuf);
    cl->port = ntohs(peer.sin_port);
    snprintf(cl->realhost, sizeof cl->realhost, "%s", ipbuf);

    if (srv->cfg.security.max_connections_per_ip > 0) {
        int count = 0;
        for (client_t *c = srv->all_clients; c; c = c->all_next)
            if (strcmp(c->ip, cl->ip) == 0) count++;
        if (count >= srv->cfg.security.max_connections_per_ip) {
            const char *msg = "ERROR :Too many connections from your host\r\n";
            write(fd, msg, strlen(msg));
            close(fd);
            client_free(cl);
            return NULL;
        }
    }

    if (srv->cfg.security.host_masking) {
        char token[64];
        crypto_random_hex(token, sizeof token, srv->cfg.security.host_masking_token_bytes);
        char network[CFG_STR];
        irc_casefold(network, sizeof network, srv->cfg.server.network);
        for (char *p = network; *p; p++) if (*p == ' ') *p = '-';
        config_format_cloak(srv->cfg.security.host_masking_format, token, network, cl->host, sizeof cl->host);
    } else {
        snprintf(cl->host, sizeof cl->host, "%s", ipbuf);
    }

    cl->conn_id = ++srv->next_conn_id;

    if (srv->cfg.dnsbl.enabled && srv->cfg.dnsbl.n_zones > 0) {
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_DNSBL;
        j.conn_id = cl->conn_id;
        snprintf(j.ip, sizeof j.ip, "%s", ipbuf);
        j.timeout = srv->cfg.dnsbl.timeout;
        j.n_zones = srv->cfg.dnsbl.n_zones < WORKER_MAX_ZONES ? srv->cfg.dnsbl.n_zones : WORKER_MAX_ZONES;
        for (int i = 0; i < j.n_zones; i++) snprintf(j.zones[i], sizeof j.zones[0], "%s", srv->cfg.dnsbl.zones[i]);
        cl->dnsbl_pending = 1;
        worker_submit(&j);
    }
    if (srv->cfg.security.rdns_enabled && !srv->cfg.security.host_masking) {
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_RDNS;
        j.conn_id = cl->conn_id;
        snprintf(j.ip, sizeof j.ip, "%s", ipbuf);
        j.timeout = srv->cfg.security.rdns_timeout;
        cl->rdns_pending = 1;
        worker_submit(&j);
    }
    if (srv->cfg.security.ident_enabled) {
        struct sockaddr_in local;
        socklen_t llen = sizeof local;
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_IDENT;
        j.conn_id = cl->conn_id;
        snprintf(j.ip, sizeof j.ip, "%s", ipbuf);
        j.remote_port = cl->port;
        j.local_port = (getsockname(fd, (struct sockaddr *)&local, &llen) == 0) ? ntohs(local.sin_port) : 0;
        j.timeout = srv->cfg.security.ident_timeout;
        cl->ident_pending = 1;
        worker_submit(&j);
    }

    server_add_connection(srv, cl);
    return cl;
}

static void accept_client(server_t *srv) {
    client_t *cl = accept_common(srv, srv->listen_fd);
    if (!cl) return;
    log_info("net", "connection from %s:%d (fd=%d)", cl->ip, cl->port, cl->fd);
}

static void accept_tls_client(server_t *srv) {
    client_t *cl = accept_common(srv, srv->tls_listen_fd);
    if (!cl) return;
    cl->ssl = SSL_new(srv->tls_ctx);
    SSL_set_fd(cl->ssl, cl->fd);
    cl->tls_handshaking = 1;
    log_info("net", "TLS connection from %s:%d (fd=%d)", cl->ip, cl->port, cl->fd);
    tls_try_handshake(cl); /* often completes (or fails) in the same event as accept() */
}

static void close_client(server_t *srv, client_t *cl) {
    log_info("net", "disconnecting %s (%s): %s", cl->nick[0] ? cl->nick : "*", cl->ip, cl->quit_reason);
    int fd = cl->fd;
    server_remove_client(srv, cl, cl->quit_reason[0] ? cl->quit_reason : "Client Quit");
    if (fd >= 0) close(fd);
}

/* Reads from `cl`, splits complete lines, and dispatches each through the
 * max_line_length/max_params/flood-guard choke point -- the C equivalent of
 * server._read_loop's per-line validation before commands.handle. */
static void read_client(server_t *srv, client_t *cl) {
    char tmp[4096];
    ssize_t n = io_read(cl, tmp, sizeof tmp);
    if (n == 0) { cl->quitting = 1; snprintf(cl->quit_reason, sizeof cl->quit_reason, "Remote host closed the connection"); return; }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
        cl->quitting = 1;
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Read error");
        return;
    }
    cl->last_activity = time(NULL);
    cl->ping_sent = 0;

    size_t maxlen = (size_t)srv->cfg.security.max_line_length + 2; /* +CRLF slack */
    if (cl->rbuf_len + (size_t)n + 1 > cl->rbuf_cap) {
        size_t newcap = cl->rbuf_cap;
        while (newcap < cl->rbuf_len + (size_t)n + 1) newcap *= 2;
        if (newcap > RECVQ_MAX) {
            cl->quitting = 1;
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "Input line too long");
            return;
        }
        char *nb = realloc(cl->rbuf, newcap);
        if (!nb) { cl->quitting = 1; return; }
        cl->rbuf = nb;
        cl->rbuf_cap = newcap;
    }
    memcpy(cl->rbuf + cl->rbuf_len, tmp, (size_t)n);
    cl->rbuf_len += (size_t)n;

    size_t start = 0;
    for (size_t i = 0; i < cl->rbuf_len; i++) {
        if (cl->rbuf[i] != '\n') continue;
        size_t end = i;
        if (end > start && cl->rbuf[end - 1] == '\r') end--;
        size_t linelen = end - start;
        cl->rbuf[end] = '\0';
        char *line = cl->rbuf + start;
        start = i + 1;

        if (cl->quitting) continue; /* a prior line this same read already ended the connection */
        if (linelen > maxlen) {
            client_reply(cl, N_INPUTTOOLONG, NULL, 0, "Input line was too long");
            continue;
        }
        if (!client_flood_ok(cl, srv->cfg.security.flood_max_msgs, srv->cfg.security.flood_window)) {
            cl->quitting = 1;
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "Excess Flood");
            continue;
        }
        irc_message_t msg;
        if (irc_parse_line(line, &msg) != 0) continue;
        if (msg.nparams > srv->cfg.security.max_params) msg.nparams = srv->cfg.security.max_params;
        cmd_dispatch(srv, cl, &msg);
    }
    if (start > 0) {
        memmove(cl->rbuf, cl->rbuf + start, cl->rbuf_len - start);
        cl->rbuf_len -= start;
    }
}

static void write_client(client_t *cl) {
    if (cl->sbuf_len == 0) return;
    ssize_t n = io_write(cl, cl->sbuf, cl->sbuf_len);
    if (n > 0) {
        memmove(cl->sbuf, cl->sbuf + n, cl->sbuf_len - (size_t)n);
        cl->sbuf_len -= (size_t)n;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        cl->quitting = 1;
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Write error");
    }
}

static client_t *find_by_conn_id(server_t *srv, uint64_t conn_id) {
    for (client_t *c = srv->all_clients; c; c = c->all_next)
        if (c->conn_id == conn_id) return c;
    return NULL; /* the connection is already gone -- drop the result */
}

/* Drains worker.c's completed rDNS/ident/DNSBL jobs and applies each to the
 * client it belongs to (if still connected). Called every loop iteration,
 * not just on the 1-second tick, so a DNSBL verdict doesn't sit around
 * withholding POLLIN longer than the lookup itself took. */
static void drain_worker_results(server_t *srv) {
    job_result_t results[32];
    int n = worker_poll_results(results, 32);
    for (int i = 0; i < n; i++) {
        job_result_t *r = &results[i];
        client_t *cl = find_by_conn_id(srv, r->conn_id);
        if (!cl) continue;

        if (r->type == JOB_RDNS) {
            cl->rdns_pending = 0;
            if (r->success) snprintf(cl->host, sizeof cl->host, "%s", r->text);
            cmd_send_welcome_if_ready(srv, cl);
        } else if (r->type == JOB_IDENT) {
            cl->ident_pending = 0;
            if (r->success) {
                cl->ident_confirmed = 1;
                snprintf(cl->user, sizeof cl->user, "%s", r->text);
            }
            cmd_send_welcome_if_ready(srv, cl);
        } else if (r->type == JOB_DNSBL) {
            cl->dnsbl_pending = 0;
            if (r->success) {
                char reason[350];
                if (srv->cfg.dnsbl.lookup_url[0]) {
                    char urlbuf[350];
                    const char *p = strstr(srv->cfg.dnsbl.lookup_url, "{ip}");
                    if (p) snprintf(urlbuf, sizeof urlbuf, "%.*s%s%s", (int)(p - srv->cfg.dnsbl.lookup_url),
                                      srv->cfg.dnsbl.lookup_url, cl->ip, p + 4);
                    else snprintf(urlbuf, sizeof urlbuf, "%s", srv->cfg.dnsbl.lookup_url);
                    snprintf(reason, sizeof reason, "Proxy/Drone detected (%s). Check %s for details.", r->text, urlbuf);
                } else {
                    snprintf(reason, sizeof reason, "Proxy/Drone detected (%s)", r->text);
                }
                if (strcmp(srv->cfg.dnsbl.action, "kline") == 0) {
                    long dur = srv->cfg.dnsbl.kline_duration[0] ? irc_parse_duration(srv->cfg.dnsbl.kline_duration) : 0;
                    if (dur < 0) dur = 0;
                    server_kline_add(srv, cl->ip, reason, "dnsbl", "K", dur);
                }
                snprintf(cl->quit_reason, sizeof cl->quit_reason, "%s", reason);
                cl->quitting = 1;
                log_info("dnsbl", "%s listed in %s -- %s", cl->ip, r->text,
                          strcmp(srv->cfg.dnsbl.action, "kline") == 0 ? "K-lined" : "rejected");
            }
            /* not listed: POLLIN resumes next poll() build, nothing else to do */
        }
    }
}

/* PING/timeout for client connections + the link keepalive tick. */
static void tick(server_t *srv) {
    time_t now = time(NULL);
    for (client_t *cl = srv->all_clients; cl; cl = cl->all_next) {
        if (cl->fd < 0 || cl->quitting) continue; /* service pseudo-clients have no timeout of their own */
        double idle = difftime(now, cl->last_activity);
        if (idle > srv->cfg.security.ping_timeout) {
            cl->quitting = 1;
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "Ping timeout: %d seconds", (int)idle);
        } else if (!cl->ping_sent && idle > srv->cfg.security.ping_interval) {
            char line[200];
            snprintf(line, sizeof line, "PING :%s", srv->cfg.server.name);
            client_send(cl, line);
            cl->ping_sent = 1;
        }
    }
    link_tick(srv);
    link_leaf_tick(srv);
    server_kline_prune_expired(srv);
}

int net_run(server_t *srv) {
    install_signal_handlers();
    worker_pool_start();

    srv->listen_fd = net_listen(srv->cfg.server.bind, srv->cfg.server.port);
    if (srv->listen_fd < 0) {
        log_error("net", "could not bind %s:%d", srv->cfg.server.bind, srv->cfg.server.port);
        return -1;
    }
    log_info("net", "listening on %s:%d", srv->cfg.server.bind, srv->cfg.server.port);

    if (srv->cfg.tls.enabled) {
        srv->tls_ctx = tls_setup(srv);
        if (srv->tls_ctx) {
            srv->tls_listen_fd = net_listen(srv->cfg.server.bind, srv->cfg.tls.port);
            if (srv->tls_listen_fd < 0) {
                log_error("tls", "could not bind %s:%d -- TLS listener disabled",
                           srv->cfg.server.bind, srv->cfg.tls.port);
                SSL_CTX_free(srv->tls_ctx);
                srv->tls_ctx = NULL;
            } else {
                log_info("tls", "listening on %s:%d", srv->cfg.server.bind, srv->cfg.tls.port);
            }
        }
    }
    link_start_hub(srv);
    if (srv->cfg.links.enabled && strcmp(srv->cfg.links.mode, "leaf") == 0) {
        if (link_connect_leaf(srv) == 0) {
            srv->leaf_backoff = srv->cfg.links.reconnect_delay;
        } else {
            srv->leaf_backoff = srv->cfg.links.reconnect_delay;
            srv->leaf_next_attempt = time(NULL) + (time_t)srv->leaf_backoff;
        }
    }

    time_t last_tick = time(NULL);

    while (!srv->shutdown_requested) {
        if (g_term) { srv->shutdown_requested = 1; break; }
        if (g_hup) {
            g_hup = 0;
            char err[256];
            if (server_rehash(srv, err, sizeof err) == 0) log_info("net", "rehashed config");
            else log_error("net", "rehash failed: %s", err);
        }

        int nfds = 3 + srv->n_clients;
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) nfds++;
        struct pollfd *fds = calloc((size_t)nfds, sizeof *fds);
        client_t **fd_client = calloc((size_t)nfds, sizeof *fd_client);
        link_conn_t **fd_link = calloc((size_t)nfds, sizeof *fd_link);
        int n = 0;

        fds[n].fd = srv->listen_fd; fds[n].events = POLLIN; n++;
        int link_listen_idx = -1;
        if (srv->link_listen_fd >= 0) {
            link_listen_idx = n;
            fds[n].fd = srv->link_listen_fd; fds[n].events = POLLIN; n++;
        }
        int tls_listen_idx = -1;
        if (srv->tls_listen_fd >= 0) {
            tls_listen_idx = n;
            fds[n].fd = srv->tls_listen_fd; fds[n].events = POLLIN; n++;
        }
        for (client_t *cl = srv->all_clients; cl; cl = cl->all_next) {
            if (cl->fd < 0) continue;
            fds[n].fd = cl->fd;
            /* A pending DNSBL verdict withholds POLLIN entirely: the client
             * exists (a listed IP might still be disconnected below), but
             * nothing it sends is dispatched until the lookup resolves. */
            fds[n].events = (cl->dnsbl_pending ? 0 : POLLIN) | ((cl->sbuf_len > 0 || cl->tls_handshaking) ? POLLOUT : 0);
            fd_client[n] = cl;
            n++;
        }
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
            fds[n].fd = lc->fd;
            fds[n].events = POLLIN | (lc->sbuf_len > 0 ? POLLOUT : 0);
            fd_link[n] = lc;
            n++;
        }

        int rc = poll(fds, (nfds_t)n, 1000);
        if (rc < 0 && errno != EINTR) {
            log_error("net", "poll() failed: %s", strerror(errno));
            free(fds); free(fd_client); free(fd_link);
            break;
        }
        if (rc > 0) {
            if (fds[0].revents & POLLIN) accept_client(srv);
            if (link_listen_idx >= 0 && (fds[link_listen_idx].revents & POLLIN)) link_accept(srv);
            if (tls_listen_idx >= 0 && (fds[tls_listen_idx].revents & POLLIN)) accept_tls_client(srv);

            for (int i = 0; i < n; i++) {
                if (fd_client[i]) {
                    client_t *cl = fd_client[i];
                    if (fds[i].revents & (POLLHUP | POLLERR)) {
                        cl->quitting = 1;
                        if (!cl->quit_reason[0]) snprintf(cl->quit_reason, sizeof cl->quit_reason, "Connection reset");
                        continue;
                    }
                    if (cl->tls_handshaking) {
                        if (fds[i].revents & (POLLIN | POLLOUT)) tls_try_handshake(cl);
                        continue;
                    }
                    if (fds[i].revents & POLLIN) read_client(srv, cl);
                    if (!cl->quitting && (fds[i].revents & POLLOUT)) write_client(cl);
                } else if (fd_link[i]) {
                    link_conn_t *lc = fd_link[i];
                    if (fds[i].revents & (POLLHUP | POLLERR)) { link_close(srv, lc); continue; }
                    if (fds[i].revents & POLLIN) link_handle_readable(srv, lc);
                    if (fds[i].revents & POLLOUT) link_handle_writable(lc);
                }
            }
        }
        free(fds); free(fd_client); free(fd_link);

        drain_worker_results(srv);

        time_t now = time(NULL);
        if (now != last_tick) { tick(srv); last_tick = now; }

        /* Deferred teardown: only now, after every fd this iteration has
         * been serviced, do we actually close/free a quitting client -- see
         * client.h's comment on why no handler ever frees one inline. */
        client_t *cl = srv->all_clients;
        while (cl) {
            client_t *next = cl->all_next;
            if (cl->quitting) close_client(srv, cl);
            cl = next;
        }
    }

    log_info("net", "shutting down");
    client_t *cl = srv->all_clients;
    while (cl) {
        client_t *next = cl->all_next;
        if (cl->fd >= 0) {
            const char *msg = "ERROR :Server shutting down\r\n";
            io_write(cl, msg, strlen(msg));
            close(cl->fd);
        }
        client_free(cl);
        cl = next;
    }
    srv->all_clients = NULL;

    channel_t *chan, *chan_tmp;
    HASH_ITER(hh, srv->channels, chan, chan_tmp) {
        HASH_DEL(srv->channels, chan);
        channel_free(chan);
    }

    /* A service pseudo-client (fd == -1) is deliberately never linked into
     * all_clients (see unlink_connection's comment), so the sweep above
     * never frees one -- free it here, reachable via its owning link_conn_t. */
    link_conn_t *lc = srv->links;
    while (lc) {
        link_conn_t *next = lc->next;
        if (lc->service) client_free(lc->service);
        if (lc->fd >= 0) close(lc->fd);
        free(lc);
        lc = next;
    }
    srv->links = NULL;
    /* Every client_t is freed above (all_clients sweep + service pseudo-
     * clients via their link_conn_t), but uthash keeps its OWN internal
     * bucket-array bookkeeping attached to the head pointer -- a plain
     * `srv->users = NULL` would leak that. HASH_CLEAR frees it and nulls
     * the head; it never touches the (already-freed) entries themselves. */
    HASH_CLEAR(hh, srv->users);

    if (srv->listen_fd >= 0) close(srv->listen_fd);
    if (srv->link_listen_fd >= 0) close(srv->link_listen_fd);
    if (srv->tls_listen_fd >= 0) close(srv->tls_listen_fd);
    if (srv->tls_ctx) SSL_CTX_free(srv->tls_ctx);
    accounts_free(&srv->accounts);
    worker_pool_stop();
    return 0;
}
