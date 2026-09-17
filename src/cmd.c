#include "cmd.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Commands an unregistered connection may send (matches commands.py's
 * _REGISTRATION_COMMANDS). Everything else gets 451 ERR_NOTREGISTERED. */
static const char *REGISTRATION_COMMANDS[] = {
    "NICK", "USER", "PASS", "CAP", "PING", "PONG", "QUIT", "AUTHENTICATE",
};

static int is_registration_command(const char *cmd) {
    for (size_t i = 0; i < sizeof REGISTRATION_COMMANDS / sizeof REGISTRATION_COMMANDS[0]; i++)
        if (strcasecmp(cmd, REGISTRATION_COMMANDS[i]) == 0) return 1;
    return 0;
}

static const cmd_entry_t DISPATCH[] = {
    {"NICK", cmd_nick, 0, 0, 0},
    {"USER", cmd_user, 4, 0, 0},
    {"PASS", cmd_pass, 0, 0, 0},
    {"CAP", cmd_cap, 1, 0, 0},
    {"PING", cmd_ping, 0, 0, 0},
    {"PONG", cmd_pong, 0, 0, 0},
    {"QUIT", cmd_quit, 0, 0, 0},
    {"AUTHENTICATE", cmd_authenticate, 1, 0, 0},
    {"REGISTER", cmd_register, 2, 1, 0},
    {"CERT", cmd_cert, 1, 1, 0},

    {"JOIN", cmd_join, 1, 1, 0},
    {"PART", cmd_part, 1, 1, 0},
    {"TOPIC", cmd_topic, 1, 1, 0},
    {"NAMES", cmd_names, 0, 1, 0},
    {"LIST", cmd_list, 0, 1, 0},
    {"KICK", cmd_kick, 2, 1, 0},
    {"MODE", cmd_mode, 1, 1, 0},
    {"INVITE", cmd_invite, 2, 1, 0},
    {"KNOCK", cmd_knock, 1, 1, 0},
    {"LINKS", cmd_links, 0, 1, 0},
    {"MAP", cmd_map, 0, 1, 0},
    {"SAJOIN", cmd_sajoin, 2, 1, 1},
    {"SAPART", cmd_sapart, 2, 1, 1},
    {"SAMODE", cmd_samode, 2, 1, 1},

    {"PRIVMSG", cmd_privmsg, 1, 1, 0},
    {"NOTICE", cmd_notice, 1, 1, 0},
    {"WHOIS", cmd_whois, 1, 1, 0},
    {"WHO", cmd_who, 0, 1, 0},
    {"WHOWAS", cmd_whowas, 1, 1, 0},
    {"AWAY", cmd_away, 0, 1, 0},
    {"SETNAME", cmd_setname, 1, 1, 0},
    {"USERHOST", cmd_userhost, 1, 1, 0},
    {"ISON", cmd_ison, 1, 1, 0},
    {"MONITOR", cmd_monitor, 1, 1, 0},
    {"WATCH", cmd_watch, 1, 1, 0},
    {"SILENCE", cmd_silence, 0, 1, 0},
    {"GLOB", cmd_glob, 1, 1, 0},

    {"OPER", cmd_oper, 2, 1, 0},
    {"KILL", cmd_kill, 1, 1, 1},
    {"WALLOPS", cmd_wallops, 1, 1, 1},
    {"REHASH", cmd_rehash, 0, 1, 1},
    {"DIE", cmd_die, 0, 1, 1},
    {"RESTART", cmd_restart, 0, 1, 1},
    {"VHOST", cmd_vhost, 0, 1, 0},
    {"CHGHOST", cmd_chghost, 2, 1, 1},
    {"SETHOST", cmd_sethost, 1, 1, 1},
    {"KLINE", cmd_kline, 0, 1, 1},
    {"GLINE", cmd_gline, 0, 1, 1},
    {"ZLINE", cmd_zline, 0, 1, 1},
    {"UNKLINE", cmd_unkline, 1, 1, 1},
    {"UNGLINE", cmd_ungline, 1, 1, 1},
    {"UNZLINE", cmd_unzline, 1, 1, 1},
    {"SQUIT", cmd_squit, 1, 1, 1},
    {"CONNECT", cmd_connect, 0, 1, 1},
    {"STATS", cmd_stats, 0, 1, 0},
    {"TRACE", cmd_trace, 0, 1, 0},
    {"SERVLIST", cmd_servlist, 0, 1, 0},
    {"SQUERY", cmd_squery, 2, 1, 0},

    {"VERSION", cmd_version, 0, 1, 0},
    {"TIME", cmd_time, 0, 1, 0},
    {"INFO", cmd_info, 0, 1, 0},
    {"HELP", cmd_help, 0, 1, 0},
    {"MOTD", cmd_motd, 0, 1, 0},
    {"LUSERS", cmd_lusers, 0, 1, 0},
    {"UPTIME", cmd_uptime, 0, 1, 0},
    {"ADMIN", cmd_admin, 0, 1, 0},
};
#define N_DISPATCH (int)(sizeof DISPATCH / sizeof DISPATCH[0])

void err_need_more_params(client_t *cl, const char *cmdname) {
    const char *p[] = {cmdname};
    client_reply(cl, N_NEEDMOREPARAMS, p, 1, "Not enough parameters");
}

void err_no_such_nick(client_t *cl, const char *nick) {
    const char *p[] = {nick};
    client_reply(cl, N_NOSUCHNICK, p, 1, "No such nick/channel");
}

void err_no_such_channel(client_t *cl, const char *chan) {
    const char *p[] = {chan};
    client_reply(cl, N_NOSUCHCHANNEL, p, 1, "No such channel");
}

void err_not_registered(client_t *cl) {
    client_reply(cl, N_NOTREGISTERED, NULL, 0, "You have not registered");
}

void err_no_privileges(client_t *cl) {
    client_reply(cl, N_NOPRIVILEGES, NULL, 0, "Permission Denied- You're not an IRC operator");
}

void err_not_channel_op(client_t *cl, const char *chan) {
    const char *p[] = {chan};
    client_reply(cl, N_NOTCHANNELOP, p, 1, "You're not channel operator");
}

void notice_self(server_t *srv, client_t *cl, const char *text) {
    char line[500];
    const char *p[] = {cl->nick[0] ? cl->nick : "*"};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "NOTICE", p, 1, text);
    client_send(cl, line);
}

void cmd_send_welcome_if_ready(server_t *srv, client_t *cl) {
    if (cl->registered || !cl->got_nick || !cl->got_user || cl->cap_negotiating) return;
    if (cl->rdns_pending || cl->ident_pending) return; /* net.c's worker-result tick retries this once they clear */
    cl->registered = 1;

    /* Must land before server_send_welcome: its post-MOTD RPL_UMODEIS line
     * (and RFC 221 in general) is supposed to reflect the modes the client
     * actually ends up with, not a snapshot taken before these apply. */
    for (const char *p = srv->cfg.security.default_user_modes; *p; p++) {
        switch (*p) {
            case 'i': cl->umodes |= UMODE_I; break;
            case 'w': cl->umodes |= UMODE_W; break;
            case 'd': cl->umodes |= UMODE_D; break;
            case 's': cl->umodes |= UMODE_S; break;
            default: break;
        }
    }

    char snote[300];
    snprintf(snote, sizeof snote, "Client connecting: %s (%s@%s) [%s]", cl->nick, cl->user, cl->host, cl->ip);
    server_notify_opers(srv, snote);

    server_send_welcome(srv, cl);
    server_monitor_notify(srv, cl, 1);
    server_watch_notify(srv, cl, 1);

    for (int i = 0; i < srv->cfg.channels.n_auto_join; i++)
        cmd_force_join(srv, cl, srv->cfg.channels.auto_join[i]);
}

void cmd_dispatch(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (!cl->registered && !is_registration_command(msg->command)) {
        err_not_registered(cl);
        return;
    }
    for (int i = 0; i < N_DISPATCH; i++) {
        if (strcasecmp(DISPATCH[i].name, msg->command) != 0) continue;
        if (msg->nparams < DISPATCH[i].min_params) {
            err_need_more_params(cl, msg->command);
            return;
        }
        if (DISPATCH[i].oper_only && !(cl->umodes & UMODE_O)) {
            err_no_privileges(cl);
            return;
        }
        for (int c = 0; c < srv->n_command_counts; c++) {
            if (strcasecmp(srv->command_counts[c].name, msg->command) == 0) {
                srv->command_counts[c].count++;
                goto counted;
            }
        }
        if (srv->n_command_counts < 64) {
            snprintf(srv->command_counts[srv->n_command_counts].name,
                     sizeof srv->command_counts[0].name, "%s", msg->command);
            srv->command_counts[srv->n_command_counts].count = 1;
            srv->n_command_counts++;
        }
counted:
        DISPATCH[i].handler(srv, cl, msg);
        return;
    }
    /* Unknown/unimplemented command: silently ignore pre-registration probes
     * (matches commands.py), otherwise 421. */
    if (cl->registered) {
        const char *p[] = {msg->command};
        client_reply(cl, N_UNKNOWNCOMMAND, p, 1, "Unknown command");
    }
}
