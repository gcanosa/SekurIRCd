/* Oper commands: OPER, KILL, WALLOPS, REHASH, DIE, RESTART, VHOST, CHGHOST,
 * SETHOST, KLINE/GLINE/ZLINE/UNKLINE/UNGLINE/UNZLINE, SQUIT.
 * Ported from commands.py's cmd_oper/cmd_kill/etc.
 *
 * Every quit/removal path here only marks a client `quitting` and sets
 * `quit_reason` -- the actual teardown (QUIT broadcast, hash removal, fd
 * close, free) happens once, at the end of a poll tick in net.c, so a
 * command handler can never leave another part of the loop holding a
 * dangling client_t* in the same iteration. */
#include "cmd.h"
#include "link.h"
#include "log.h"
#include "worker.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define MAX_OPER_FAILS 3

static void broadcast_chghost(server_t *srv, client_t *cl, const char *old_prefix);

/* Applies (or refuses) the OPER grant once the password is known good or
 * bad -- shared by the plaintext-password path (checked inline, cheap) and
 * cmd_finish_privileged_auth's AUTH_OPER case (checked on a worker). */
static void finish_oper(server_t *srv, client_t *cl, const char *op_name, int pw_ok) {
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
    snprintf(cl->oper_name, sizeof cl->oper_name, "%s", op_name);

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);

    if (srv->cfg.security.oper_host_masking) {
        char network[CFG_STR];
        irc_casefold(network, sizeof network, srv->cfg.server.network);
        for (char *p = network; *p; p++) if (*p == ' ') *p = '-';
        char masked[CFG_STR];
        if (config_format_cloak(srv->cfg.security.oper_host_format, "", network, masked, sizeof masked) == 0) {
            snprintf(cl->host, sizeof cl->host, "%s", masked);
            broadcast_chghost(srv, cl, prefix);
            client_prefix(cl, prefix, sizeof prefix);
        }
    }

    char line[200];
    const char *p2[] = {cl->nick, "+osw"};
    irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p2, 2, NULL);
    client_send(cl, line);
    client_reply(cl, N_YOUREOPER, NULL, 0, "You are now an IRC operator");

    if (srv->cfg.security.oper_auto_join[0]) cmd_force_join(srv, cl, srv->cfg.security.oper_auto_join);
    log_info("oper", "%s OPER'd as %s", cl->nick, op_name);
}

void cmd_oper(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *name = msg->params[0];
    const char *password = msg->params[1];

    if (cl->umodes & UMODE_O) {
        notice_self(srv, cl, "You are already an IRC operator");
        return;
    }
    if (cl->auth_pending) {
        client_reply(cl, N_NOOPERHOST, NULL, 0, "Another login is already in progress -- try again shortly");
        return;
    }

    for (int i = 0; i < srv->cfg.n_operators; i++) {
        cfg_operator_t *op = &srv->cfg.operators[i];
        if (strcasecmp(op->name, name) != 0) continue;

        int host_ok = 0;
        for (int j = 0; j < op->n_hosts; j++) {
            if (irc_host_mask_match(cl->user, cl->ip, op->hosts[j])) { host_ok = 1; break; }
        }
        if (!host_ok) break; /* wrong host: same "no O-lines" reply as wrong name, never leaks which */

        if (op->password_hash[0]) {
            /* scrypt verify is ~30ms -- run it on a worker so hammering
             * /OPER (or a legitimate login) never stalls the event loop.
             * finish_oper (above) applies the result once it's back. */
            job_t j; memset(&j, 0, sizeof j);
            j.type = JOB_SASL;
            j.purpose = AUTH_OPER;
            j.conn_id = cl->conn_id;
            snprintf(j.secret, sizeof j.secret, "%s", password);
            snprintf(j.hash, sizeof j.hash, "%s", op->password_hash);
            snprintf(cl->pending_account, sizeof cl->pending_account, "%s", op->name);
            cl->auth_pending = 1;
            worker_submit(&j);
            OPENSSL_cleanse(j.secret, sizeof j.secret);
            return;
        }

        finish_oper(srv, cl, op->name, strcmp(password, op->password) == 0);
        return;
    }
    client_reply(cl, N_NOOPERHOST, NULL, 0, "No O-lines for your host");
}

/* Optional extra password gate for /DIE and /RESTART, independent of the
 * /OPER password already required to reach them. No password configured ->
 * gate passes (being an oper is enough, matching classic ircds). Only the
 * plaintext case is checked here -- a configured hash routes through the
 * worker pool instead (see cmd_die/cmd_restart). */
static int check_extra_password(const char *plain, const char *given) {
    return plain[0] ? strcmp(plain, given) == 0 : 1;
}

void cmd_kill(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *target_nick = msg->params[0];
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "No reason given";
    client_t *target = server_find_user(srv, target_nick);
    if (!target) { err_no_such_nick(cl, target_nick); return; }
    if (target->fd < 0) {
        /* A service pseudo-client isn't in net.c's teardown sweep -- marking
         * it quitting would just silently mute it forever. SQUIT its link. */
        const char *p[] = {target->nick};
        client_reply(cl, N_CANTKILLSERVER, p, 1, "You may not kill a service -- SQUIT its link instead");
        return;
    }

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

/* Applies the DIE/RESTART action once the extra password (if any) is known
 * good or bad -- shared by the plaintext-password path (checked inline,
 * cheap) and cmd_finish_privileged_auth's AUTH_DIE/AUTH_RESTART cases
 * (checked on a worker). */
static void finish_die_or_restart(server_t *srv, client_t *cl, int is_restart, int pw_ok) {
    if (!pw_ok) {
        client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Password incorrect");
        return;
    }
    char snote[128];
    if (is_restart) {
        log_warn("oper", "%s issued RESTART -- server restarting", cl->nick);
        snprintf(snote, sizeof snote, "Server restarting (RESTART by %s)", cl->nick);
        srv->restart_requested = 1;
    } else {
        log_warn("oper", "%s issued DIE -- server shutting down", cl->nick);
        snprintf(snote, sizeof snote, "Server terminating (DIE by %s)", cl->nick);
    }
    server_notify_opers(srv, snote);
    srv->shutdown_requested = 1;
}

/* Submits `given` for a worker scrypt verify against `hash` -- shared by
 * cmd_die/cmd_restart when a hashed extra password is configured. */
static void submit_privileged_check(client_t *cl, const char *given, const char *hash, auth_purpose_t purpose) {
    job_t j; memset(&j, 0, sizeof j);
    j.type = JOB_SASL;
    j.purpose = purpose;
    j.conn_id = cl->conn_id;
    snprintf(j.secret, sizeof j.secret, "%s", given);
    snprintf(j.hash, sizeof j.hash, "%s", hash);
    cl->auth_pending = 1;
    worker_submit(&j);
    OPENSSL_cleanse(j.secret, sizeof j.secret);
}

void cmd_die(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *given = msg->nparams > 0 ? msg->params[0] : "";
    if (srv->cfg.security.die_password_hash[0]) {
        if (cl->auth_pending) {
            client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Another login is already in progress -- try again shortly");
            return;
        }
        submit_privileged_check(cl, given, srv->cfg.security.die_password_hash, AUTH_DIE);
        return;
    }
    finish_die_or_restart(srv, cl, 0, check_extra_password(srv->cfg.security.die_password, given));
}

void cmd_restart(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *given = msg->nparams > 0 ? msg->params[0] : "";
    if (srv->cfg.security.restart_password_hash[0]) {
        if (cl->auth_pending) {
            client_reply(cl, N_PASSWDMISMATCH, NULL, 0, "Another login is already in progress -- try again shortly");
            return;
        }
        submit_privileged_check(cl, given, srv->cfg.security.restart_password_hash, AUTH_RESTART);
        return;
    }
    finish_die_or_restart(srv, cl, 1, check_extra_password(srv->cfg.security.restart_password, given));
}

/* net.c: apply a finished JOB_SASL for AUTH_OPER/AUTH_DIE/AUTH_RESTART --
 * see cmd.h's doc comment. AUTH_SASL/AUTH_REGISTER never reach here (net.c
 * routes those to cmd_finish_auth in cmd_reg.c instead). */
void cmd_finish_privileged_auth(server_t *srv, client_t *cl, int purpose, int success) {
    cl->auth_pending = 0;
    switch ((auth_purpose_t)purpose) {
        case AUTH_OPER:    finish_oper(srv, cl, cl->pending_account, success); break;
        case AUTH_DIE:     finish_die_or_restart(srv, cl, 0, success); break;
        case AUTH_RESTART: finish_die_or_restart(srv, cl, 1, success); break;
        default: break;
    }
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
static void broadcast_chghost(server_t *srv, client_t *cl, const char *old_prefix) {
    char line[400];
    const char *p[] = {cl->user, cl->host};
    irc_build(line, sizeof line, NULL, 0, old_prefix, "CHGHOST", p, 2, NULL);
    if (cl->caps & CAP_CHGHOST) client_send(cl, line);
    server_send_common_channels(srv, cl, line, CAP_CHGHOST);
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
        broadcast_chghost(srv, cl, old_prefix);
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
    broadcast_chghost(srv, cl, old_prefix);
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
    broadcast_chghost(srv, target, old_prefix);
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
        broadcast_chghost(srv, cl, old_prefix);
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
    broadcast_chghost(srv, cl, old_prefix);
    char m[300]; snprintf(m, sizeof m, "host is now %s", requested);
    notice_self(srv, cl, m);
    log_info("oper", "%s set own host via SETHOST -> %s", cl->nick, requested);
}

/* --- K/G-lines --------------------------------------------------------------- */

/* "YYYY-MM-DD HH:MM:SS UTC", easier to read at a glance than a raw
 * epoch/duration when an oper is scanning a K/G-line list or add notice. */
static void format_expiry(time_t t, char *out, size_t outsz) {
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, outsz, "%Y-%m-%d %H:%M:%S UTC", &tmv);
}

static void line_common(server_t *srv, client_t *cl, irc_message_t *msg, const char *line_type) {
    server_kline_prune_expired(srv);
    if (msg->nparams < 1) {
        int any = 0;
        for (kline_entry_t *k = srv->klines; k; k = k->next) {
            any = 1;
            char m[500];
            if (k->expires_at) {
                char exp[32];
                format_expiry(k->expires_at, exp, sizeof exp);
                snprintf(m, sizeof m, "%s-line %s (by %s, expires %s): %s",
                         k->line_type, k->mask, k->set_by, exp, k->reason);
            } else snprintf(m, sizeof m, "%s-line %s (by %s, permanent): %s", k->line_type, k->mask, k->set_by, k->reason);
            notice_self(srv, cl, m);
        }
        if (!any) notice_self(srv, cl, "No active K/G/Z-lines");
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
    if (duration) {
        char exp[32];
        format_expiry(time(NULL) + duration, exp, sizeof exp);
        snprintf(m, sizeof m, "%s-line added: %s (%s) [expires %s]", line_type, maskbuf, reason, exp);
    } else snprintf(m, sizeof m, "%s-line added: %s (%s) [permanent]", line_type, maskbuf, reason);
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
void cmd_zline(server_t *srv, client_t *cl, irc_message_t *msg) { line_common(srv, cl, msg, "Z"); }

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
void cmd_unzline(server_t *srv, client_t *cl, irc_message_t *msg) { unline_common(srv, cl, msg->params[0]); }

/* --- SQUIT (closes any link, hub or leaf side) / CONNECT (leaf-mode manual
 * dial, see link.c's link_connect_leaf). ------------------------------------ */

void cmd_squit(server_t *srv, client_t *cl, irc_message_t *msg) {
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (lc->closing || strcasecmp(lc->peer_name, msg->params[0]) != 0) continue;
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
