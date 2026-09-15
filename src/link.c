#include "link.h"
#include "channel.h"
#include "cmd.h"
#include "crypto.h"
#include "log.h"
#include "net.h"
#include "proto.h"
#include "server.h"

#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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

/* Blocking-with-timeout read of one line, used only during the leaf-dial
 * handshake below (before the fd joins the normal nonblocking poll set). */
static int read_line_blocking_fd(int fd, char *out, size_t outsz, int timeout_ms) {
    size_t len = 0;
    time_t deadline = time(NULL) + (timeout_ms / 1000) + 1;
    while (time(NULL) < deadline && len + 1 < outsz) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) return -1;
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') { out[len] = '\0'; return 0; }
        if (c != '\r') out[len++] = c;
    }
    return -1;
}

/* ponytail: a plain blocking connect() (bounded by the OS's own SYN
 * timeout) -- link establishment is rare (startup/reconnect/manual
 * /CONNECT), not a per-request path, so this doesn't need full
 * nonblocking-connect-in-progress handling like the client listeners do. */
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
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
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

    char line[512];
    snprintf(line, sizeof line, "PASS %s", up->password);
    write(fd, line, strlen(line));
    write(fd, "\r\n", 2);
    const char *p[] = {srv->cfg.server.name, "1"};
    irc_build(line, sizeof line, NULL, 0, NULL, "SERVER", p, 2, "sekurircd-c link");
    write(fd, line, strlen(line));
    write(fd, "\r\n", 2);

    char resp[512];
    if (read_line_blocking_fd(fd, resp, sizeof resp, 5000) != 0) {
        log_warn("link", "uplink '%s' did not respond to the handshake", up->name);
        close(fd);
        return -1;
    }
    irc_message_t msg;
    if (irc_parse_line(resp, &msg) != 0 || strcasecmp(msg.command, "SERVER") != 0 ||
        msg.nparams < 1 || strcmp(msg.params[0], up->name) != 0) {
        log_warn("link", "uplink handshake failed (bad reply or name mismatch)");
        close(fd);
        return -1;
    }

    net_set_nonblocking(fd);
    link_conn_t *lc = calloc(1, sizeof *lc);
    lc->fd = fd;
    lc->authenticated = 1;
    snprintf(lc->peer_name, sizeof lc->peer_name, "%s", up->name);
    lc->last_activity = time(NULL);
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "connected to uplink '%s'", up->name);
    return 0;
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

void link_accept(server_t *srv) {
    int fd = accept(srv->link_listen_fd, NULL, NULL);
    if (fd < 0) return;
    net_set_nonblocking(fd);
    link_conn_t *lc = calloc(1, sizeof *lc);
    lc->fd = fd;
    lc->last_activity = time(NULL);
    lc->next = srv->links;
    srv->links = lc;
    log_info("link", "inbound link connection accepted (fd=%d)", fd);
}

void link_forward_line(link_conn_t *lc, const char *line) {
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

void link_handle_writable(link_conn_t *lc) {
    if (lc->sbuf_len == 0) return;
    ssize_t n = write(lc->fd, lc->sbuf, lc->sbuf_len);
    if (n > 0) {
        memmove(lc->sbuf, lc->sbuf + n, lc->sbuf_len - (size_t)n);
        lc->sbuf_len -= (size_t)n;
    }
}

void link_close(server_t *srv, link_conn_t *lc) {
    link_conn_t **pp = &srv->links;
    while (*pp) {
        if (*pp == lc) { *pp = lc->next; break; }
        pp = &(*pp)->next;
    }
    if (lc->service) {
        log_info("link", "link '%s' lost -- removing service nick '%s'", lc->peer_name, lc->service->nick);
        server_remove_client(srv, lc->service, "Service disconnected");
    }
    if (lc->fd >= 0) close(lc->fd);
    log_info("link", "link '%s' closed", lc->peer_name[0] ? lc->peer_name : "(unauthenticated)");
    free(lc);
}

/* Returns -1 if `lc` was closed (and freed) while handling this line, so the
 * caller (link_handle_readable) must stop touching it immediately. */
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
            if (matched) {
                ok = matched->password_hash[0]
                    ? crypto_verify_password(lc->pending_pass, matched->password_hash)
                    : (strcmp(lc->pending_pass, matched->password) == 0);
            }
            /* Reject outright if this name is already linked -- matches the
             * Python original's "bad credentials or already linked" check.
             * Without this, a reconnect that races a not-yet-reaped stale
             * connection (dead peer, no FIN seen yet) authenticates a
             * second live link_conn_t for the same name, which then shows
             * up twice in /MAP until the stale one's ping_timeout expires. */
            if (ok) {
                for (link_conn_t *other = srv->links; other; other = other->next) {
                    if (other != lc && other->authenticated && strcasecmp(other->peer_name, name) == 0) {
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
            return 0;
        }
        return 0; /* ignore anything else pre-auth */
    }

    if (strcasecmp(msg.command, "NICK") == 0) {
        if (msg.nparams < 4) return 0;
        const char *nick = msg.params[0], *user = msg.params[1], *host = msg.params[2];
        const char *realname = msg.params[msg.nparams - 1];
        if (server_find_user(srv, nick)) {
            log_warn("link", "link '%s' introduced nick '%s' which already exists locally -- ignored",
                      lc->peer_name, nick);
            return 0;
        }
        client_t *svc = client_new(-1, srv);
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
        const char *p[] = {chan->name, joiner->nick, joiner->user, joiner->host,
                            joiner->account[0] ? joiner->account : "*"};
        irc_build(line, sizeof line, NULL, 0, NULL, "SVCJOIN", p, 5, NULL);
        link_forward_line(svc->link_conn, line);
    }
}

void link_handle_readable(server_t *srv, link_conn_t *lc) {
    char tmp[4096];
    ssize_t n = read(lc->fd, tmp, sizeof tmp);
    if (n <= 0) { link_close(srv, lc); return; }
    lc->last_activity = time(NULL);
    if (lc->rbuf_len + (size_t)n >= sizeof lc->rbuf) {
        log_warn("link", "link '%s' line too long, dropping connection", lc->peer_name);
        link_close(srv, lc);
        return;
    }
    memcpy(lc->rbuf + lc->rbuf_len, tmp, (size_t)n);
    lc->rbuf_len += (size_t)n;

    size_t start = 0;
    for (size_t i = 0; i < lc->rbuf_len; i++) {
        if (lc->rbuf[i] != '\n') continue;
        size_t end = i;
        if (end > start && lc->rbuf[end - 1] == '\r') end--;
        lc->rbuf[end] = '\0';
        if (link_process_line(srv, lc, lc->rbuf + start) < 0) return; /* lc freed */
        start = i + 1;
    }
    memmove(lc->rbuf, lc->rbuf + start, lc->rbuf_len - start);
    lc->rbuf_len -= start;
}

void link_tick(server_t *srv) {
    time_t now = time(NULL);
    link_conn_t *lc = srv->links;
    while (lc) {
        link_conn_t *next = lc->next;
        if (lc->authenticated) {
            double idle = difftime(now, lc->last_activity);
            if (idle > srv->cfg.links.ping_timeout) {
                log_warn("link", "link '%s' timed out", lc->peer_name);
                link_close(srv, lc);
            } else if (idle > srv->cfg.links.ping_interval) {
                link_forward_line(lc, "PING");
            }
        }
        lc = next;
    }
}
