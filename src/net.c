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

/* Reads RSS (KB) and %CPU for `pid` by shelling out to `ps` -- portable
 * across macOS/Linux, unlike parsing /proc (which macOS doesn't have).
 * Returns 0 on success, -1 if `pid` doesn't exist or ps didn't report it. */
int proc_stats(pid_t pid, double *cpu_pct, long *rss_kb) {
    char cmd[64];
    snprintf(cmd, sizeof cmd, "ps -o rss=,%%cpu= -p %d 2>/dev/null", (int)pid);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    long rss = 0;
    double cpu = 0;
    int got = fscanf(p, "%ld %lf", &rss, &cpu);
    pclose(p);
    if (got != 2) return -1;
    *rss_kb = rss;
    *cpu_pct = cpu;
    return 0;
}

/* Periodic "users/channels/connections + ircd & chanserv CPU/mem" snote,
 * gated by [debug_channel] stats_interval -- logged at INFO so it rides the
 * same log_hook relay into the debug channel as everything else (see
 * server_install_debug_log_hook). */
static void emit_stats_snote(server_t *srv) {
    int n_chans = 0, n_reg_chans = 0;
    channel_t *ch, *chtmp;
    HASH_ITER(hh, srv->channels, ch, chtmp) {
        n_chans++;
        if (ch->modes & CMODE_R) n_reg_chans++;
    }

    int n_klines = 0, n_glines = 0, n_zlines = 0, n_dnsbl_active = 0, n_scan_active = 0;
    for (kline_entry_t *k = srv->klines; k; k = k->next) {
        if (k->line_type[0] == 'K') n_klines++;
        else if (k->line_type[0] == 'Z') n_zlines++;
        else n_glines++;
        if (strcmp(k->set_by, "dnsbl") == 0) n_dnsbl_active++;
        else if (strcmp(k->set_by, "protection") == 0) n_scan_active++;
    }

    double ircd_cpu = 0;
    long ircd_rss = 0;
    proc_stats(getpid(), &ircd_cpu, &ircd_rss);

    char chanserv_part[160] = "";
    if (srv->cfg.debug_channel.chanserv_pidfile[0]) {
        FILE *pf = fopen(srv->cfg.debug_channel.chanserv_pidfile, "r");
        int cs_pid = 0;
        if (pf) {
            if (fscanf(pf, "%d", &cs_pid) != 1) cs_pid = 0;
            fclose(pf);
        } else {
            /* Most common cause: chanserv_pidfile is a relative path and this
             * process's cwd (its own WorkingDirectory, e.g. under systemd)
             * isn't chanserv's -- the two daemons can have different
             * WorkingDirectory= and the pidfile then never resolves. Use an
             * absolute path matching chanserv's actual --pidfile/PIDFile=. */
            snprintf(chanserv_part, sizeof chanserv_part,
                      ", chanserv: not running (pidfile %s not found -- check for a relative path)",
                      srv->cfg.debug_channel.chanserv_pidfile);
        }
        if (cs_pid > 0) {
            double cs_cpu = 0;
            long cs_rss = 0;
            if (kill((pid_t)cs_pid, 0) == 0 && proc_stats((pid_t)cs_pid, &cs_cpu, &cs_rss) == 0) {
                snprintf(chanserv_part, sizeof chanserv_part, ", chanserv cpu=%.1f%% mem=%ldMB", cs_cpu, cs_rss / 1024);
            } else if (errno == ESRCH) {
                snprintf(chanserv_part, sizeof chanserv_part, ", chanserv: not running (stale pidfile, pid %d)", cs_pid);
            } else {
                snprintf(chanserv_part, sizeof chanserv_part, ", chanserv: pid %d unreachable (%s)", cs_pid, strerror(errno));
            }
        } else if (!chanserv_part[0]) {
            snprintf(chanserv_part, sizeof chanserv_part, ", chanserv: not running (empty/invalid pidfile)");
        }
    }

    char scan_part[160] = "";
    if (srv->cfg.protection.scan_enabled)
        snprintf(scan_part, sizeof scan_part, ", proxy scanner: scanned=%ld proxies=%ld in-flight=%d negcache=%d",
                 srv->prot.scanned, srv->prot.hits, srv->prot.n_scans, protection_negcache_count(srv));
    log_info("stats", "users=%d (peak %d), channels=%d (%d registered), connections=%ld total, "
              "lines active=%d K/%d G/%d Z (%d from DNSBL, %d from scanner), dnsbl hits=%ld total%s, ircd cpu=%.1f%% mem=%ldMB%s",
              HASH_COUNT(srv->users), srv->max_users_seen, n_chans, n_reg_chans, srv->total_connections,
              n_klines, n_glines, n_zlines, n_dnsbl_active, n_scan_active, srv->dnsbl_hits, scan_part,
              ircd_cpu, ircd_rss / 1024, chanserv_part);
}

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

/* SASL EXTERNAL (cmd_reg.c) identifies a client by matching its certificate's
 * fingerprint against one bound to an account via /CERT ADD -- not by chain-
 * of-trust, so any certificate (self-signed, expired, whatever) is accepted
 * at the TLS layer; only /CERT ADD's account binding decides who it is. */
static int tls_accept_any_client_cert(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok; (void)ctx;
    return 1;
}

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
    /* PARTIAL_WRITE + ACCEPT_MOVING_WRITE_BUFFER: write_client retries a
     * WANT_WRITE with a sendq that may have grown/been realloc'd since --
     * without these OpenSSL fails that retry ("bad write retry") and the
     * client is dropped with "Write error" under any backpressure.
     * RELEASE_BUFFERS: idle TLS connections don't pin ~34KB of I/O buffers. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                          SSL_MODE_RELEASE_BUFFERS);
    /* SSL_VERIFY_PEER alone (no _FAIL_IF_NO_PEER_CERT) *requests* a client
     * certificate without requiring one -- a client with no cert still
     * connects normally, just can't use SASL EXTERNAL. */
    if (srv->cfg.tls.request_client_cert)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, tls_accept_any_client_cert);
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

/* Per-IP connect-rate tracking: max_connections_per_ip only bounds
 * *concurrent* sockets, so a scanner that connects and resets in
 * milliseconds (TLS probes, port scanners) never trips it. Fixed slot
 * table, same eviction tradeoff as chanserv.c's fail_slot password-fail
 * table -- a full table evicts by hash instead of tracking every possible
 * IP forever. */
#define CONNECT_FLOOD_SLOTS 256
typedef struct { char ip[64]; time_t window_start; int count; } connect_track_t;
static connect_track_t g_connect_tracks[CONNECT_FLOOD_SLOTS];

/* Returns 1 once `ip` exceeds security.connect_flood_max connects within
 * security.connect_flood_window seconds. */
int net_connect_flood_hit(const cfg_security_t *sec, const char *ip) {
    if (sec->connect_flood_max <= 0) return 0;
    time_t now = time(NULL);
    int slot = -1;
    for (int i = 0; i < CONNECT_FLOOD_SLOTS; i++) {
        if (strcmp(g_connect_tracks[i].ip, ip) == 0) { slot = i; break; }
    }
    if (slot < 0) slot = (int)((unsigned long)now % CONNECT_FLOOD_SLOTS);
    connect_track_t *t = &g_connect_tracks[slot];
    if (strcmp(t->ip, ip) != 0 || now - t->window_start > sec->connect_flood_window) {
        snprintf(t->ip, sizeof t->ip, "%s", ip);
        t->window_start = now;
        t->count = 1;
        return 0;
    }
    t->count++;
    return t->count > sec->connect_flood_max;
}

/* errno from the last accept() that failed -- accept_clients needs to tell
 * "backlog drained" (EAGAIN) apart from "out of descriptors" (EMFILE), and
 * the work accept_common does after a successful accept would clobber it. */
static int g_accept_errno;

static client_t *accept_common(server_t *srv, int listen_fd) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    int fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) { g_accept_errno = errno; return NULL; }
    g_accept_errno = 0;
    srv->total_connections++;

    char ipbuf[64];
    inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof ipbuf);

    if (srv->cfg.security.max_connections > 0 && srv->n_clients >= srv->cfg.security.max_connections) {
        const char *msg = "ERROR :Too many connections\r\n";
        if (write(fd, msg, strlen(msg)) < 0) { /* best effort; peer may already be gone */ }
        close(fd);
        char snote[200];
        snprintf(snote, sizeof snote, "Rejected connection from %s: Server is full", ipbuf);
        server_notify_opers(srv, snote);
        return NULL;
    }
    net_set_nonblocking(fd);

    /* Accept time: no USER/ident/rDNS yet, so only the IP and the raw host
     * are known. A hostname K-line is re-checked once registration
     * completes -- see cmd_send_welcome_if_ready. */
    const char *kline_reason = server_kline_match(srv, ipbuf, NULL, ipbuf, 0);
    if (kline_reason) {
        char err[350];
        snprintf(err, sizeof err, "ERROR :Closing Link: %s (%s)\r\n", ipbuf, kline_reason);
        if (write(fd, err, strlen(err)) < 0) { /* best effort; peer may already be gone */ }
        close(fd);
        log_warn("net", "refused %s: %s", ipbuf, kline_reason);
        char snote[400];
        snprintf(snote, sizeof snote, "Rejected connection from %s: %s", ipbuf, kline_reason);
        server_notify_opers(srv, snote);
        return NULL;
    }

    /* A scan probe relays back to our own listener from the address being
     * scanned; that connection is ours, not a flood, and needs no second
     * DNSBL lookup or scan. */
    int scan_related = protection_ip_related(srv, ipbuf);

    if (!scan_related && net_connect_flood_hit(&srv->cfg.security, ipbuf)) {
        long dur = srv->cfg.security.connect_flood_kline_duration[0]
            ? irc_parse_duration(srv->cfg.security.connect_flood_kline_duration) : 0;
        if (dur < 0) dur = 0;
        server_kline_add(srv, ipbuf, "Connecting too fast (connect flood protection)",
                          "connect-flood", "Z", dur); /* pure-IP pre-registration ban; itself calls server_notify_opers */
        const char *msg = "ERROR :Closing Link: reconnecting too fast\r\n";
        if (write(fd, msg, strlen(msg)) < 0) { /* best effort; peer may already be gone */ }
        close(fd);
        return NULL;
    }

    client_t *cl = client_new(fd, srv);
    if (!cl) { close(fd); return NULL; }
    snprintf(cl->ip, sizeof cl->ip, "%s", ipbuf);
    cl->port = ntohs(peer.sin_port);
    snprintf(cl->realhost, sizeof cl->realhost, "%s", ipbuf);

    if (!scan_related && srv->cfg.security.max_connections_per_ip > 0) {
        /* O(1): server_add_connection/unlink_connection keep this exact.
         * Walking all_clients here cost O(connections) on every accept(),
         * times ACCEPT_BURST per poll wakeup, exactly when under a flood. */
        int count = server_ip_count(srv, cl->ip);
        if (count >= srv->cfg.security.max_connections_per_ip) {
            const char *msg = "ERROR :Too many connections from your host\r\n";
            if (write(fd, msg, strlen(msg)) < 0) { /* best effort; peer may already be gone */ }
            close(fd);
            client_free(cl);
            char snote[200];
            snprintf(snote, sizeof snote, "Rejected connection from %s: Too many connections from your host", ipbuf);
            server_notify_opers(srv, snote);
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
    crypto_random_hex(cl->your_id, sizeof cl->your_id, 8);

    const cfg_protection_t *prot = &srv->cfg.protection;
    int exempt = protection_exempt(prot, ipbuf);
    if (prot->bl_enabled && prot->n_blacklists > 0 && !exempt && !scan_related) {
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_DNSBL;
        j.conn_id = cl->conn_id;
        snprintf(j.ip, sizeof j.ip, "%s", ipbuf);
        j.timeout = prot->bl_timeout;
        j.n_zones = prot->n_blacklists < WORKER_MAX_ZONES ? prot->n_blacklists : WORKER_MAX_ZONES;
        for (int i = 0; i < j.n_zones; i++) snprintf(j.zones[i], sizeof j.zones[0], "%s", prot->blacklists[i].zone);
        cl->dnsbl_pending = 1;
        /* Queue full: proceed without the verdict rather than leaving POLLIN
         * withheld until the 30-second rescue tick. */
        if (worker_submit(&j) != 0) cl->dnsbl_pending = 0;
    }
    if (srv->cfg.security.rdns_enabled && !srv->cfg.security.host_masking) {
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_RDNS;
        j.conn_id = cl->conn_id;
        snprintf(j.ip, sizeof j.ip, "%s", ipbuf);
        j.timeout = srv->cfg.security.rdns_timeout;
        cl->rdns_pending = 1;
        if (worker_submit(&j) != 0) cl->rdns_pending = 0;
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
        if (worker_submit(&j) != 0) cl->ident_pending = 0;
    }

    server_add_connection(srv, cl);

    /* The standard first line every ircd sends. Besides being what clients
     * expect, it is the default string the proxy scanner watches for coming
     * back through a relay (protection.template.toml [scanner.target]). */
    char banner[300];
    const char *bp[] = {"AUTH"};
    irc_build(banner, sizeof banner, NULL, 0, srv->cfg.server.name, "NOTICE", bp, 1, "*** Looking up your hostname");
    client_send(cl, banner);

    if (!scan_related && !exempt) protection_scan_start(srv, ipbuf);
    return cl;
}

/* Drains the listener's backlog (bounded per tick so a connect flood can't
 * starve existing clients) instead of taking one connection per poll(). */
#define ACCEPT_BURST 64

static void accept_clients(server_t *srv, int listen_fd, int tls) {
    for (int i = 0; i < ACCEPT_BURST; i++) {
        long before = srv->total_connections;
        client_t *cl = accept_common(srv, listen_fd);
        if (!cl) {
            if (srv->total_connections == before) {
                /* accept() itself failed. EAGAIN just means the backlog is
                 * drained. EMFILE/ENFILE means we're out of descriptors --
                 * and the listener stays readable, so simply returning would
                 * make poll() fire again immediately, forever, pegging a core
                 * until a client happened to disconnect. Stop polling the
                 * listeners for a moment instead. */
                if (g_accept_errno == EMFILE || g_accept_errno == ENFILE) {
                    log_error("net", "accept failed: %s -- pausing the listeners for 1s",
                              strerror(g_accept_errno));
                    srv->accept_paused_until = time(NULL) + 1;
                }
                return;
            }
            continue; /* refused (limit/K-line) -- keep draining */
        }
        if (!tls) {
            log_debug("net", "connection from %s:%d (fd=%d)", cl->ip, cl->port, cl->fd);
            continue;
        }
        cl->ssl = SSL_new(srv->tls_ctx);
        if (!cl->ssl || SSL_set_fd(cl->ssl, cl->fd) != 1) {
            cl->quitting = 1;
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "TLS setup failed");
            continue;
        }
        cl->tls_handshaking = 1;
        log_debug("net", "TLS connection from %s:%d (fd=%d)", cl->ip, cl->port, cl->fd);
        tls_try_handshake(cl); /* often completes (or fails) in the same event as accept() */
    }
}

static void write_client(client_t *cl);

static void close_client(server_t *srv, client_t *cl) {
    /* Unregistered clients are almost always scanners/health-checks that
     * connect and reset before sending NICK/USER -- routine noise, not worth
     * a #server-debug notice. A client that made it to a nick is real. */
    log_write(cl->nick[0] ? LOG_INFO : LOG_DEBUG, "net", "disconnecting %s (%s): %s",
              cl->nick[0] ? cl->nick : "*", cl->ip, cl->quit_reason);
    int fd = cl->fd;
    if (fd >= 0 && !cl->tls_handshaking) write_client(cl); /* best effort: ERROR/flood notice etc. */
    server_remove_client(srv, cl, cl->quit_reason[0] ? cl->quit_reason : "Client Quit");
    if (fd >= 0) close(fd);
}

/* Reads from `cl`, splits complete lines, and dispatches each through the
 * max_line_length/max_params/flood-guard choke point -- the C equivalent of
 * server._read_loop's per-line validation before commands.handle. */
static int read_client_once(server_t *srv, client_t *cl) {
    char tmp[4096];
    ssize_t n = io_read(cl, tmp, sizeof tmp);
    if (n == 0) { cl->quitting = 1; snprintf(cl->quit_reason, sizeof cl->quit_reason, "Remote host closed the connection"); return 0; }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        cl->quitting = 1;
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Read error");
        return 0;
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
            return 0;
        }
        char *nb = realloc(cl->rbuf, newcap);
        if (!nb) { cl->quitting = 1; return 0; }
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
            client_reply(cl, N_UNKNOWNERROR, NULL, 0, "flood; disconnecting");
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
    return 1;
}

/* A TLS record can hold more plaintext than one read takes; the rest sits
 * decrypted inside OpenSSL where poll() can't see it, so keep reading while
 * SSL_pending says so -- otherwise those lines stall until the peer happens
 * to send more bytes. */
static void read_client(server_t *srv, client_t *cl) {
    while (read_client_once(srv, cl) && cl->ssl && !cl->quitting && !cl->dnsbl_pending &&
           SSL_pending(cl->ssl) > 0) {}
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
    int n;
    worker_drain_wake();
    while ((n = worker_poll_results(results, 32)) > 0) {
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
                char replytext[CFG_STR];
                int bi = r->success ? protection_bl_match(&srv->cfg.protection, r->zone_code, WORKER_MAX_ZONES,
                                                          replytext, sizeof replytext) : -1;
                if (bi >= 0) {
                    const cfg_protection_t *pp = &srv->cfg.protection;
                    const cfg_blacklist_t *z = &pp->blacklists[bi];
                    srv->dnsbl_hits++;
                    char reason[350];
                    protection_expand(z->reason, cl->ip, z->zone, replytext, reason, sizeof reason);
                    int reject = strcmp(pp->bl_action, "reject") == 0;
                    if (!reject) {
                        long dur = pp->bl_ban_duration[0] ? irc_parse_duration(pp->bl_ban_duration) : 0;
                        if (dur < 0) dur = 0;
                        int as_k = strcmp(pp->bl_action, "kline") == 0;
                        server_kline_add(srv, cl->ip, reason, "dnsbl", as_k ? "K" : "Z", dur); /* IP-only ban; itself calls server_notify_opers */
                    } else {
                        char snote[400];
                        snprintf(snote, sizeof snote, "Rejected connection from %s: %s", cl->ip, reason);
                        server_notify_opers(srv, snote);
                    }
                    /* Everyone else already connected from this address goes too. */
                    char quit[400];
                    snprintf(quit, sizeof quit, reject ? "%s" : "Z-Lined: %s", reason);
                    server_kline_enforce(srv, cl->ip, "Z", quit, cl);
                    snprintf(cl->quit_reason, sizeof cl->quit_reason, "%s", reason);
                    cl->quitting = 1;
                    log_warn("dnsbl", "%s listed in %s (%s) -- %s", cl->ip, z->zone, replytext,
                             reject ? "rejected" : strcmp(pp->bl_action, "kline") == 0 ? "K-lined" : "Z-lined");
                }
                /* not listed: POLLIN resumes next poll() build, nothing else to do */
            } else if (r->type == JOB_SASL || r->type == JOB_HASH) {
                if (r->purpose == AUTH_SASL || r->purpose == AUTH_REGISTER)
                    cmd_finish_auth(srv, cl, r->purpose == AUTH_REGISTER, r->success, r->text);
                else
                    cmd_finish_privileged_auth(srv, cl, r->purpose, r->success);
            }
        }
    }
}

/* Unregistered connections get this long to finish NICK/USER(/CAP/SASL)
 * -- otherwise an idle socket holds an fd for the full ping_timeout.
 * ponytail: fixed, make it a [security] key if 60s ever proves wrong. */
#define REGISTRATION_TIMEOUT 60

/* PING/timeout for client connections + the link keepalive tick. */
static void tick(server_t *srv) {
    time_t now = time(NULL);
    for (client_t *cl = srv->all_clients; cl; cl = cl->all_next) {
        if (cl->fd < 0 || cl->quitting) continue; /* service pseudo-clients have no timeout of their own */
        double age = difftime(now, cl->signon_time);
        /* Worker results can be lost (full result ring) or stuck on a hung
         * resolver: never let a pending lookup gate a client forever. */
        if ((cl->rdns_pending || cl->ident_pending || cl->dnsbl_pending) && age > 30) {
            log_warn("net", "lookup for %s never finished -- continuing without it", cl->ip);
            cl->rdns_pending = cl->ident_pending = cl->dnsbl_pending = 0;
            cmd_send_welcome_if_ready(srv, cl);
        }
        /* Same rescue for a scrypt job whose result was lost (full result
         * ring). Without it auth_pending stays set for the rest of the
         * connection's life and every later SASL/REGISTER/OPER/DIE/RESTART
         * short-circuits on it -- the connection can never authenticate
         * again. Timed from when the job was submitted, not from signon:
         * an /OPER can happen hours in. */
        if (cl->auth_pending && difftime(now, cl->auth_started) > 30) {
            log_warn("net", "auth job for %s never finished -- releasing the connection", cl->ip);
            cl->auth_pending = 0;
            notice_self(srv, cl, "Your login timed out on the server side -- please try again.");
        }
        double idle = difftime(now, cl->last_activity);
        if (!cl->registered && age > REGISTRATION_TIMEOUT) {
            cl->quitting = 1;
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "Registration timeout");
        } else if (idle > srv->cfg.security.ping_timeout) {
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
    protection_tick(srv);
    server_kline_prune_expired(srv);
    server_kline_flush(srv); /* batched: see server_kline_flush */

    if (srv->cfg.debug_channel.stats_interval > 0) {
        static time_t last_stats = 0;
        if (last_stats == 0 || difftime(now, last_stats) >= srv->cfg.debug_channel.stats_interval) {
            emit_stats_snote(srv);
            last_stats = now;
        }
    }
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

    server_install_debug_log_hook(srv);
    time_t last_tick = time(NULL);

    /* pollfd set reused across iterations (grown, never shrunk).
     * ponytail: poll() is O(connections) per wakeup; kqueue/epoll is the
     * upgrade if this ever serves thousands of concurrent clients. */
    struct pollfd *fds = NULL;
    client_t **fd_client = NULL;
    link_conn_t **fd_link = NULL;
    protection_scan_t **fd_scan = NULL;
    size_t fds_cap = 0;

    while (!srv->shutdown_requested) {
        if (g_term) { srv->shutdown_requested = 1; break; }
        if (g_hup) {
            g_hup = 0;
            char err[256];
            if (server_rehash(srv, err, sizeof err) == 0) log_info("net", "rehashed config");
            else log_error("net", "rehash failed: %s", err);
        }

        size_t nfds = 4 + (size_t)srv->n_clients;
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) nfds++;
        nfds += (size_t)srv->prot.n_scans;
        if (nfds > fds_cap) {
            size_t cap = nfds * 2;
            struct pollfd *nf = realloc(fds, cap * sizeof *fds);
            if (nf) fds = nf;
            client_t **nc = realloc(fd_client, cap * sizeof *fd_client);
            if (nc) fd_client = nc;
            link_conn_t **nl = realloc(fd_link, cap * sizeof *fd_link);
            if (nl) fd_link = nl;
            protection_scan_t **ns = realloc(fd_scan, cap * sizeof *fd_scan);
            if (ns) fd_scan = ns;
            if (!nf || !nc || !nl || !ns) { log_critical("net", "out of memory growing poll set"); break; }
            fds_cap = cap;
        }
        memset(fd_client, 0, nfds * sizeof *fd_client);
        memset(fd_link, 0, nfds * sizeof *fd_link);
        memset(fd_scan, 0, nfds * sizeof *fd_scan);
        int n = 0;

        /* While paused (see accept_clients' EMFILE handling) the listeners
         * stay in the set but ask for no events, so an un-acceptable
         * connection can't spin the loop. */
        short listen_events = (srv->accept_paused_until > time(NULL)) ? 0 : POLLIN;
        fds[n].fd = srv->listen_fd; fds[n].events = listen_events; fds[n].revents = 0; n++;
        int wake_idx = -1;
        if (worker_wake_fd() >= 0) {
            wake_idx = n;
            fds[n].fd = worker_wake_fd(); fds[n].events = POLLIN; fds[n].revents = 0; n++;
        }
        int link_listen_idx = -1;
        if (srv->link_listen_fd >= 0) {
            link_listen_idx = n;
            fds[n].fd = srv->link_listen_fd; fds[n].events = listen_events; fds[n].revents = 0; n++;
        }
        int tls_listen_idx = -1;
        if (srv->tls_listen_fd >= 0) {
            tls_listen_idx = n;
            fds[n].fd = srv->tls_listen_fd; fds[n].events = listen_events; fds[n].revents = 0; n++;
        }
        for (client_t *cl = srv->all_clients; cl; cl = cl->all_next) {
            if (cl->fd < 0 || cl->quitting) continue;
            /* Flush now rather than waiting a whole extra poll() round for
             * POLLOUT: most replies fit the socket buffer immediately. */
            if (cl->sbuf_len > 0 && !cl->tls_handshaking) write_client(cl);
            if (cl->quitting) continue;
            fds[n].fd = cl->fd;
            /* A pending DNSBL verdict withholds POLLIN entirely: the client
             * exists (a listed IP might still be disconnected below), but
             * nothing it sends is dispatched until the lookup resolves. */
            fds[n].events = (cl->dnsbl_pending ? 0 : POLLIN) | ((cl->sbuf_len > 0 || cl->tls_handshaking) ? POLLOUT : 0);
            fds[n].revents = 0;
            fd_client[n] = cl;
            n++;
        }
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
            if (lc->closing) continue;
            if (lc->sbuf_len > 0 && !lc->tls_handshaking) link_handle_writable(srv, lc);
            if (lc->closing) continue;
            fds[n].fd = lc->fd;
            fds[n].events = POLLIN | ((lc->sbuf_len > 0 || lc->tls_handshaking) ? POLLOUT : 0);
            fds[n].revents = 0;
            fd_link[n] = lc;
            n++;
        }

        protection_poll_fill(srv, fds, fd_scan, &n);

        /* Anything already marked for teardown (e.g. a write error in the
         * flush above) shouldn't wait out a full poll timeout. */
        int timeout = 1000;
        for (client_t *cl = srv->all_clients; cl; cl = cl->all_next)
            if (cl->quitting) { timeout = 0; break; }
        for (link_conn_t *lc = srv->links; lc && timeout; lc = lc->next)
            if (lc->closing) timeout = 0;

        int rc = poll(fds, (nfds_t)n, timeout);
        if (rc < 0 && errno != EINTR) {
            log_error("net", "poll() failed: %s", strerror(errno));
            break;
        }
        if (rc > 0) {
            if (fds[0].revents & POLLIN) accept_clients(srv, srv->listen_fd, 0);
            if (link_listen_idx >= 0 && (fds[link_listen_idx].revents & POLLIN)) link_accept(srv);
            if (tls_listen_idx >= 0 && (fds[tls_listen_idx].revents & POLLIN)) accept_clients(srv, srv->tls_listen_fd, 1);

            for (int i = 0; i < n; i++) {
                if (fd_client[i]) {
                    client_t *cl = fd_client[i];
                    if (cl->quitting) continue;
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
                } else if (fd_scan[i]) {
                    /* A hit frees every probe for that address (protection.c),
                     * so later slots of this same address may already be gone. */
                    if (fds[i].revents && protection_scan_live(srv, fd_scan[i])) protection_handle(srv, fd_scan[i], fds[i].revents);
                } else if (fd_link[i]) {
                    link_conn_t *lc = fd_link[i];
                    if (lc->closing) continue;
                    if (fds[i].revents & (POLLHUP | POLLERR)) { link_close(srv, lc); continue; }
                    if (lc->tls_handshaking) {
                        if (fds[i].revents & (POLLIN | POLLOUT)) link_tls_try_handshake(srv, lc);
                        continue;
                    }
                    if (fds[i].revents & POLLIN) link_handle_readable(srv, lc);
                    if (fds[i].revents & POLLOUT) link_handle_writable(srv, lc);
                }
            }
        }

        if (wake_idx < 0 || rc <= 0 || (fds[wake_idx].revents & POLLIN)) drain_worker_results(srv);

        time_t now = time(NULL);
        if (now != last_tick) { tick(srv); last_tick = now; }

        /* Deferred teardown: only now, after every fd this iteration has
         * been serviced, do we actually free a closing link or close/free a
         * quitting client -- see client.h's comment on why no handler ever
         * frees one inline. */
        link_reap(srv);
        client_t *cl = srv->all_clients;
        while (cl) {
            client_t *next = cl->all_next;
            if (cl->quitting) close_client(srv, cl);
            cl = next;
        }
    }
    free(fds); free(fd_client); free(fd_link); free(fd_scan);
    log_set_hook(NULL);

    log_info("net", "shutting down");
    client_t *cl = srv->all_clients;
    while (cl) {
        client_t *next = cl->all_next;
        if (cl->fd >= 0) {
            /* Flush whatever's already queued first -- e.g. a DIE/RESTART
             * snotice queued this same loop iteration, after which the
             * `while (!shutdown_requested)` loop exits without ever
             * reaching the normal per-iteration flush. */
            if (!cl->tls_handshaking) write_client(cl);
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
    server_free_tables(srv);

    if (srv->listen_fd >= 0) close(srv->listen_fd);
    if (srv->link_listen_fd >= 0) close(srv->link_listen_fd);
    if (srv->tls_listen_fd >= 0) close(srv->tls_listen_fd);
    if (srv->tls_ctx) SSL_CTX_free(srv->tls_ctx);
    link_tls_cleanup();
    accounts_free(&srv->accounts);
    worker_pool_stop();
    return 0;
}
