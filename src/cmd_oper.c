/* Oper commands: OPER, KILL, WALLOPS, REHASH, DIE, RESTART, VHOST, CHGHOST,
 * SETHOST, KLINE/GLINE/UNKLINE/UNGLINE, SQUIT.
 * Ported from commands.py's cmd_oper/cmd_kill/etc.
 *
 * Every quit/removal path here only marks a client `quitting` and sets
 * `quit_reason` -- the actual teardown (QUIT broadcast, hash removal, fd
 * close, free) happens once, at the end of a poll tick in net.c, so a
 * command handler can never leave another part of the loop holding a
 * dangling client_t* in the same iteration. */
#include "cmd.h"
#include "crypto.h"
#include "link.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define MAX_OPER_FAILS 3

void cmd_oper(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *name = msg->params[0];
    const char *password = msg->params[1];

    if (cl->umodes & UMODE_O) {
        notice_self(srv, cl, "You are already an IRC operator");
        return;
    }

    for (int i = 0; i < srv->cfg.n_operators; i++) {
        cfg_operator_t *op = &srv->cfg.operators[i];
        if (strcasecmp(op->name, name) != 0) continue;

        int pw_ok = op->password_hash[0]
            ? crypto_verify_password(password, op->password_hash)
            : (strcmp(password, op->password) == 0);

        int host_ok = 0;
        for (int j = 0; j < op->n_hosts; j++) {
            if (irc_host_mask_match(cl->user, cl->ip, op->hosts[j])) { host_ok = 1; break; }
        }
        if (!host_ok) break; /* wrong host: same "no O-lines" reply as wrong name, never leaks which */

        if (!pw_ok) {
            cl->oper_fails++;
            if (cl->oper_fails >= MAX_OPER_FAILS) {
                snprintf(cl->quit_reason, sizeof cl->quit_reason, "Too many failed OPER attempts");
                cl->quitting = 1;
                log_warn("oper", "%s disconnected: too many failed OPER attempts", cl->nick);
                return;
            }
            client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Password incorrect");
            return;
        }

        cl->oper_fails = 0;
        cl->umodes |= UMODE_O | UMODE_S | UMODE_W;
        snprintf(cl->oper_name, sizeof cl->oper_name, "%s", op->name);

        char prefix[320];
        client_prefix(cl, prefix, sizeof prefix);
        char line[200];
        const char *p2[] = {cl->nick, "+osw"};
        irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p2, 2, NULL);
        client_send(cl, line);
        client_reply(cl, N_YOUREOPER, NULL, 0, "You are now an IRC operator");

        if (srv->cfg.security.oper_auto_join[0]) cmd_force_join(srv, cl, srv->cfg.security.oper_auto_join);
        log_info("oper", "%s OPER'd as %s", cl->nick, name);
        return;
    }
    client_reply(cl, N_NOOPERHOST, NULL, 0, "No O-lines for your host");
}

/* Optional extra password gate for /DIE and /RESTART, independent of the
 * /OPER password already required to reach them. No password configured ->
 * gate passes (being an oper is enough, matching classic ircds). */
static int check_extra_password(const char *plain, const char *hashed, const char *given) {
    if (hashed[0]) return crypto_verify_password(given, hashed);
    if (plain[0]) return strcmp(plain, given) == 0;
    return 1;
}

void cmd_kill(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *target_nick = msg->params[0];
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "No reason given";
    client_t *target = server_find_user(srv, target_nick);
    if (!target) { err_no_such_nick(cl, target_nick); return; }

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char killmsg[400];
    const char *pk[] = {target->nick};
    irc_build(killmsg, sizeof killmsg, NULL, 0, prefix, "KILL", pk, 1, reason);
    client_send(target, killmsg);

    snprintf(target->quit_reason, sizeof target->quit_reason, "Killed (%s (%s))", cl->nick, reason);
    target->quitting = 1;
    log_info("oper", "%s KILLed %s: %s", cl->nick, target->nick, reason);
}

void cmd_wallops(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *text = msg->params[msg->nparams - 1];
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[600];
    irc_build(line, sizeof line, NULL, 0, prefix, "WALLOPS", NULL, 0, text);
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if (u->umodes & UMODE_W) client_send(u, line);
    }
}

void cmd_rehash(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    char err[256];
    if (server_rehash(srv, err, sizeof err) == 0) {
        client_reply(cl, N_REHASHING, NULL, 0, "Rehashing");
        log_info("oper", "%s rehashed config from %s", cl->nick, srv->cfg.path);
    } else {
        char m[400];
        snprintf(m, sizeof m, "Rehash failed: %s", err);
        notice_self(srv, cl, m);
    }
}

void cmd_die(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *given = msg->nparams > 0 ? msg->params[0] : "";
    if (!check_extra_password(srv->cfg.security.die_password, srv->cfg.security.die_password_hash, given)) {
        client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Password incorrect");
        return;
    }
    log_warn("oper", "%s issued DIE -- server shutting down", cl->nick);
    srv->shutdown_requested = 1;
}

void cmd_restart(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *given = msg->nparams > 0 ? msg->params[0] : "";
    if (!check_extra_password(srv->cfg.security.restart_password, srv->cfg.security.restart_password_hash, given)) {
        client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Password incorrect");
        return;
    }
    log_warn("oper", "%s issued RESTART -- server restarting", cl->nick);
    srv->restart_requested = 1;
    srv->shutdown_requested = 1;
}

/* --- host masking: VHOST / CHGHOST / SETHOST -------------------------------- */

static int may_use_vhost(client_t *cl, cfg_vhost_t *v) {
    if (cl->umodes & UMODE_O) return 1;
    for (int i = 0; i < v->n_allowed_hosts; i++)
        if (irc_host_mask_match(cl->user, cl->ip, v->allowed_hosts[i])) return 1;
    return 0;
}

/* IRCv3 chghost: only delivered to `cl` itself and channel-mates that
 * negotiated the cap. */
static void broadcast_chghost(client_t *cl, const char *old_prefix) {
    char line[400];
    const char *p[] = {cl->user, cl->host};
    irc_build(line, sizeof line, NULL, 0, old_prefix, "CHGHOST", p, 2, NULL);
    if (cl->caps & CAP_CHGHOST) client_send(cl, line);
    client_t *seen[256]; int n_seen = 0;
    for (chan_node_t *n = cl->channels; n; n = n->next) {
        member_t *m, *tmp;
        HASH_ITER(hh, n->chan->members, m, tmp) {
            if (m->client == cl || !(m->client->caps & CAP_CHGHOST)) continue;
            int dup = 0;
            for (int i = 0; i < n_seen; i++) if (seen[i] == m->client) { dup = 1; break; }
            if (dup) continue;
            client_send(m->client, line);
            if (n_seen < 256) seen[n_seen++] = m->client;
        }
    }
}

void cmd_vhost(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1) {
        char list[600] = "";
        for (int i = 0; i < srv->cfg.n_vhosts; i++) {
            if (!may_use_vhost(cl, &srv->cfg.vhosts[i])) continue;
            if (list[0]) strncat(list, ", ", sizeof list - strlen(list) - 1);
            strncat(list, srv->cfg.vhosts[i].host, sizeof list - strlen(list) - 1);
        }
        notice_self(srv, cl, list[0] ? list : "No vhosts are available to you");
        return;
    }
    const char *requested = msg->params[0];
    if (strcasecmp(requested, "off") == 0 || strcasecmp(requested, "none") == 0) {
        char old_prefix[320];
        client_prefix(cl, old_prefix, sizeof old_prefix);
        snprintf(cl->host, sizeof cl->host, "%s", cl->realhost);
        broadcast_chghost(cl, old_prefix);
        char m[300]; snprintf(m, sizeof m, "vhost cleared; host is now %s", cl->host);
        notice_self(srv, cl, m);
        return;
    }
    cfg_vhost_t *match = NULL;
    for (int i = 0; i < srv->cfg.n_vhosts; i++)
        if (strcasecmp(srv->cfg.vhosts[i].host, requested) == 0) { match = &srv->cfg.vhosts[i]; break; }
    if (!match) { char m[300]; snprintf(m, sizeof m, "No such vhost: %s", requested); notice_self(srv, cl, m); return; }
    if (!may_use_vhost(cl, match)) { notice_self(srv, cl, "You are not permitted to use that vhost"); return; }
    char old_prefix[320];
    client_prefix(cl, old_prefix, sizeof old_prefix);
    snprintf(cl->host, sizeof cl->host, "%s", match->host);
    broadcast_chghost(cl, old_prefix);
    char m[300]; snprintf(m, sizeof m, "vhost set to %s", match->host);
    notice_self(srv, cl, m);
    log_info("oper", "%s activated vhost %s", cl->nick, match->host);
}

void cmd_chghost(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
    const char *new_host = msg->params[1];
    if (!irc_valid_host(new_host)) {
        char m[300]; snprintf(m, sizeof m, "Invalid hostname: %s", new_host);
        notice_self(srv, cl, m);
        return;
    }
    char old_prefix[320];
    client_prefix(target, old_prefix, sizeof old_prefix);
    snprintf(target->host, sizeof target->host, "%s", new_host);
    broadcast_chghost(target, old_prefix);
    char m[300]; snprintf(m, sizeof m, "%s's host is now %s", target->nick, new_host);
    notice_self(srv, cl, m);
    log_info("oper", "%s used CHGHOST on %s -> %s", cl->nick, target->nick, new_host);
}

void cmd_sethost(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *requested = msg->params[0];
    char old_prefix[320];
    client_prefix(cl, old_prefix, sizeof old_prefix);
    if (strcasecmp(requested, "off") == 0 || strcasecmp(requested, "none") == 0) {
        snprintf(cl->host, sizeof cl->host, "%s", cl->realhost);
        broadcast_chghost(cl, old_prefix);
        char m[300]; snprintf(m, sizeof m, "host cleared; host is now %s", cl->host);
        notice_self(srv, cl, m);
        return;
    }
    if (!irc_valid_host(requested)) {
        char m[300]; snprintf(m, sizeof m, "Invalid hostname: %s", requested);
        notice_self(srv, cl, m);
        return;
    }
    snprintf(cl->host, sizeof cl->host, "%s", requested);
    broadcast_chghost(cl, old_prefix);
    char m[300]; snprintf(m, sizeof m, "host is now %s", requested);
    notice_self(srv, cl, m);
    log_info("oper", "%s set own host via SETHOST -> %s", cl->nick, requested);
}

/* --- K/G-lines --------------------------------------------------------------- */

static void line_common(server_t *srv, client_t *cl, irc_message_t *msg, const char *line_type) {
    server_kline_prune_expired(srv);
    if (msg->nparams < 1) {
        int any = 0;
        time_t now = time(NULL);
        for (kline_entry_t *k = srv->klines; k; k = k->next) {
            any = 1;
            char m[500];
            if (k->expires_at) snprintf(m, sizeof m, "%s-line %s (by %s, expires in %llds): %s",
                                          k->line_type, k->mask, k->set_by, (long long)(k->expires_at - now), k->reason);
            else snprintf(m, sizeof m, "%s-line %s (by %s, permanent): %s", k->line_type, k->mask, k->set_by, k->reason);
            notice_self(srv, cl, m);
        }
        if (!any) notice_self(srv, cl, "No active K/G-lines");
        return;
    }
    char mask[256];
    snprintf(mask, sizeof mask, "%s", msg->params[0]);
    char *at = strrchr(mask, '@');
    char maskbuf[256];
    snprintf(maskbuf, sizeof maskbuf, "%s", at ? at + 1 : mask);
    if (strcmp(maskbuf, "*") == 0) {
        notice_self(srv, cl, "Refusing to add a line matching every address (mask '*')");
        return;
    }
    long duration = 0;
    int argi = 1;
    if (argi < msg->nparams) {
        long d = irc_parse_duration(msg->params[argi]);
        if (d >= 0) { duration = d; argi++; }
    }
    const char *reason = argi < msg->nparams ? msg->params[argi] : "No reason given";
    server_kline_add(srv, maskbuf, reason, cl->nick, line_type, duration);

    char m[400];
    if (duration) snprintf(m, sizeof m, "%s-line added: %s (%s) [expires in %lds]", line_type, maskbuf, reason, duration);
    else snprintf(m, sizeof m, "%s-line added: %s (%s) [permanent]", line_type, maskbuf, reason);
    notice_self(srv, cl, m);
    if (irc_glob_match(maskbuf, cl->ip))
        notice_self(srv, cl, "Warning: this mask matches your own address -- you won't be able to reconnect from it while it's active");

    /* enforce: disconnect anyone already connected who matches, except the
     * oper setting the line (even if their own address matches). */
    int matched = 0;
    for (client_t *c = srv->all_clients; c; c = c->all_next) {
        if (c == cl || c->fd < 0 || c->quitting) continue;
        if (!irc_glob_match(maskbuf, c->ip)) continue;
        char reasonbuf[300];
        snprintf(reasonbuf, sizeof reasonbuf, "%s-Lined: %s", line_type, reason);
        snprintf(c->quit_reason, sizeof c->quit_reason, "%s", reasonbuf);
        c->quitting = 1;
        matched++;
    }
    if (matched) log_info("oper", "%s %sLINE disconnected %d client(s) matching %s", cl->nick, line_type, matched, maskbuf);
}

void cmd_kline(server_t *srv, client_t *cl, irc_message_t *msg) { line_common(srv, cl, msg, "K"); }
void cmd_gline(server_t *srv, client_t *cl, irc_message_t *msg) { line_common(srv, cl, msg, "G"); }

static void unline_common(server_t *srv, client_t *cl, const char *mask) {
    if (server_kline_remove(srv, mask)) {
        char m[300]; snprintf(m, sizeof m, "Removed line: %s", mask);
        notice_self(srv, cl, m);
    } else {
        char m[300]; snprintf(m, sizeof m, "No such line: %s", mask);
        notice_self(srv, cl, m);
    }
}
void cmd_unkline(server_t *srv, client_t *cl, irc_message_t *msg) { unline_common(srv, cl, msg->params[0]); }
void cmd_ungline(server_t *srv, client_t *cl, irc_message_t *msg) { unline_common(srv, cl, msg->params[0]); }

/* --- SQUIT (closes any link, hub or leaf side) / CONNECT (leaf-mode manual
 * dial, see link.c's link_connect_leaf). ------------------------------------ */

void cmd_squit(server_t *srv, client_t *cl, irc_message_t *msg) {
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (strcasecmp(lc->peer_name, msg->params[0]) != 0) continue;
        const char *reason = msg->nparams > 1 ? msg->params[1] : "Requested";
        char m[300]; snprintf(m, sizeof m, "Closed link to %s (%s)", lc->peer_name, reason);
        notice_self(srv, cl, m);
        log_info("oper", "%s SQUIT %s: %s", cl->nick, lc->peer_name, reason);
        link_close(srv, lc);
        return;
    }
    char m[300]; snprintf(m, sizeof m, "No such link: %s", msg->params[0]);
    notice_self(srv, cl, m);
}

void cmd_connect(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    if (!srv->cfg.links.enabled || strcmp(srv->cfg.links.mode, "leaf") != 0) {
        notice_self(srv, cl, "This server is not configured in leaf link mode");
        return;
    }
    if (srv->links) {
        notice_self(srv, cl, "Already connected to an uplink");
        return;
    }
    if (link_connect_leaf(srv) == 0) {
        srv->leaf_backoff = srv->cfg.links.reconnect_delay;
        notice_self(srv, cl, "Connected to uplink");
        log_info("oper", "%s CONNECT: uplink established", cl->nick);
    } else {
        notice_self(srv, cl, "Could not connect to uplink (see server log)");
    }
}
