/* Informational commands: VERSION, TIME, MOTD, LUSERS, ADMIN, UPTIME, STATS,
 * TRACE, SERVLIST, SQUERY. Ported from commands.py's cmd_version/etc. */
#include "cmd.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

void cmd_version(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    char swver[CFG_STR + 16];
    server_software_version(srv, swver, sizeof swver);
    const char *p[] = {swver, srv->cfg.server.name};
    client_reply(cl, N_VERSION, p, 2, "SekurIRCd (C port)");
}

void cmd_time(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char buf[64];
    strftime(buf, sizeof buf, "%A %B %d %Y -- %H:%M:%S %Z", &tmv);
    const char *p[] = {srv->cfg.server.name};
    client_reply(cl, N_TIME, p, 1, buf);
}

void cmd_motd(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_motd(srv, cl); }
void cmd_lusers(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_lusers(srv, cl); }

void cmd_admin(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    char msgbuf[128];
    snprintf(msgbuf, sizeof msgbuf, "Administrative info about %s", srv->cfg.server.name);
    client_reply(cl, N_ADMINME, NULL, 0, msgbuf);
    client_reply(cl, N_ADMINLOC1, NULL, 0, srv->cfg.admin.location1[0] ? srv->cfg.admin.location1 : "Not configured");
    client_reply(cl, N_ADMINLOC2, NULL, 0, srv->cfg.admin.location2[0] ? srv->cfg.admin.location2 : "Not configured");
    client_reply(cl, N_ADMINEMAIL, NULL, 0, srv->cfg.admin.email[0] ? srv->cfg.admin.email : "Not configured");
}

static void uptime_str(server_t *srv, char *out, size_t outsz) {
    long up = (long)difftime(time(NULL), srv->start_time);
    long d = up / 86400; up %= 86400;
    long h = up / 3600; up %= 3600;
    long m = up / 60; long s = up % 60;
    snprintf(out, outsz, "Server Up %ld days %02ld:%02ld:%02ld", d, h, m, s);
}

void cmd_uptime(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    char buf[64];
    uptime_str(srv, buf, sizeof buf);
    client_reply(cl, N_STATSUPTIME, NULL, 0, buf);
}

void cmd_stats(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *letter = msg->nparams > 0 ? msg->params[0] : "";
    if (strcmp(letter, "m") == 0) {
        for (int i = 0; i < srv->n_command_counts; i++) {
            char cnt[16]; snprintf(cnt, sizeof cnt, "%d", srv->command_counts[i].count);
            const char *p[] = {srv->command_counts[i].name, cnt};
            client_reply(cl, N_STATSCOMMANDS, p, 2, NULL);
        }
    } else if (strcmp(letter, "u") == 0) {
        char buf[64];
        uptime_str(srv, buf, sizeof buf);
        client_reply(cl, N_STATSUPTIME, NULL, 0, buf);
    } else if (strcmp(letter, "o") == 0) {
        if (!(cl->umodes & UMODE_O)) { err_no_privileges(cl); return; }
        for (int i = 0; i < srv->cfg.n_operators; i++) {
            const char *p[] = {"O", "*", srv->cfg.operators[i].name};
            client_reply(cl, N_STATSOLINE, p, 3, "0");
        }
    }
    const char *pe[] = {letter[0] ? letter : "*"};
    client_reply(cl, N_ENDOFSTATS, pe, 1, "End of /STATS report");
}

void cmd_trace(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    if (cl->umodes & UMODE_O) {
        for (client_t *c = srv->all_clients; c; c = c->all_next) {
            if (!c->registered) continue;
            const char *numeric = (c->umodes & UMODE_O) ? N_TRACEOPERATOR : N_TRACEUSER;
            long idle = (long)difftime(time(NULL), c->last_activity);
            char idlebuf[16]; snprintf(idlebuf, sizeof idlebuf, "%ld", idle);
            char prefix[320]; client_prefix(c, prefix, sizeof prefix);
            const char *p[] = {"Client", prefix, idlebuf};
            client_reply(cl, numeric, p, 3, NULL);
        }
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
            if (!lc->authenticated) continue;
            const char *p[] = {"Server", "0", srv->cfg.server.name, lc->peer_name};
            client_reply(cl, N_TRACESERVER, p, 4, NULL);
        }
    } else {
        long idle = (long)difftime(time(NULL), cl->last_activity);
        char idlebuf[16]; snprintf(idlebuf, sizeof idlebuf, "%ld", idle);
        char prefix[320]; client_prefix(cl, prefix, sizeof prefix);
        const char *p[] = {"Client", prefix, idlebuf};
        client_reply(cl, N_TRACEUSER, p, 3, NULL);
    }
    const char *pe[] = {srv->cfg.server.name, srv->cfg.server.version};
    client_reply(cl, N_TRACEEND, pe, 2, "End of TRACE");
}

void cmd_servlist(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *mask = msg->nparams > 0 ? msg->params[0] : "*";
    const char *type_mask = msg->nparams > 1 ? msg->params[1] : "*";
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if (!u->is_service) continue;
        char cf[NICKLEN], mcf[NICKLEN];
        irc_casefold(cf, sizeof cf, u->nick);
        irc_casefold(mcf, sizeof mcf, mask);
        if (!irc_glob_match(mcf, cf)) continue;
        const char *p[] = {u->nick, srv->cfg.server.name, type_mask, "0", "0"};
        client_reply(cl, N_SERVLIST, p, 5, u->realname);
    }
    const char *pe[] = {mask, type_mask};
    client_reply(cl, N_SERVLISTEND, pe, 2, "End of service listing");
}

void cmd_squery(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target || !target->is_service) {
        const char *p[] = {msg->params[0]};
        client_reply(cl, N_NOSUCHNICK, p, 1, "No such service");
        return;
    }
    char textbuf[420];
    snprintf(textbuf, sizeof textbuf, "%.*s", srv->cfg.messages.max_message_length, msg->params[1]);
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    const char *p2[] = {msg->params[0]};
    irc_build(line, sizeof line, NULL, 0, prefix, "PRIVMSG", p2, 1, textbuf);
    client_send(target, line);
}
