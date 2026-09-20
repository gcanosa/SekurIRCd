/* Informational commands: VERSION, TIME, MOTD, LUSERS, ADMIN, UPTIME, STATS,
 * TRACE, SERVLIST, SQUERY. Ported from commands.py's cmd_version/etc. */
#include "cmd.h"
#include "link.h"

#include <ctype.h>
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
void cmd_rules(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_rules(srv, cl); }
void cmd_opermotd(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_oper_motd(srv, cl); }
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
    if (d > 0) snprintf(out, outsz, "Server Up %ld day%s %02ld:%02ld:%02ld", d, d == 1 ? "" : "s", h, m, s);
    else snprintf(out, outsz, "Server Up %02ld:%02ld:%02ld", h, m, s);
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
    } else if (strcasecmp(letter, "k") == 0 || strcasecmp(letter, "g") == 0 || strcasecmp(letter, "z") == 0) {
        if (!(cl->umodes & UMODE_O)) { err_no_privileges(cl); return; }
        char want = (char)toupper((unsigned char)letter[0]);
        for (kline_entry_t *k = srv->klines; k; k = k->next) {
            if (k->line_type[0] != want) continue;
            const char *p[] = {k->line_type, k->mask};
            client_reply(cl, N_STATSKLINE, p, 2, k->reason);
        }
    } else if (strcmp(letter, "l") == 0) {
        if (!(cl->umodes & UMODE_O)) { err_no_privileges(cl); return; }
        for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
            long idle = (long)difftime(time(NULL), lc->last_activity);
            char idlebuf[16]; snprintf(idlebuf, sizeof idlebuf, "%ld", idle);
            char sq[16]; snprintf(sq, sizeof sq, "%zu", lc->sbuf_len);
            const char *name = lc->peer_name[0] ? lc->peer_name : lc->ip;
            const char *p[] = {name, sq, idlebuf};
            client_reply(cl, N_STATSLINKINFO, p, 3, NULL);
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
    char mcf[NICKLEN];
    irc_casefold(mcf, sizeof mcf, mask); /* loop-invariant */
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if (!u->is_service) continue;
        char cf[NICKLEN];
        irc_casefold(cf, sizeof cf, u->nick);
        if (!irc_glob_match(mcf, cf)) continue;
        const char *p[] = {u->nick, srv->cfg.server.name, type_mask, "0", "0"};
        client_reply(cl, N_SERVLIST, p, 5, u->realname);
    }
    const char *pe[] = {mask, type_mask};
    client_reply(cl, N_SERVLISTEND, pe, 2, "End of service listing");
}

void cmd_info(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    char line1[CFG_STR + 64];
    snprintf(line1, sizeof line1, "%s is powered by SekurIRCd %s.",
             srv->cfg.server.network, srv->cfg.server.version);
    client_reply(cl, N_INFO, NULL, 0, line1);
    client_reply(cl, N_INFO, NULL, 0, "A lightweight, secure IRC daemon.");
    client_reply(cl, N_ENDOFINFO, NULL, 0, "End of /INFO list.");
}

/* Per-command `/HELP <command>` detail: one syntax line plus a short
 * description, ported from commands.py's _COMMAND_HELP. */
typedef struct { const char *cmd; const char *lines[3]; } help_entry_t;

static const help_entry_t HELP_TABLE[] = {
    {"NICK", {"NICK <nickname>", "Change your nickname."}},
    {"USER", {"USER <user> <mode> <unused> :<realname>",
              "Sent once during registration, right after NICK -- not meant to be typed by hand."}},
    {"JOIN", {"JOIN <channel>[,<channel2>...] [key[,key2...]]",
              "Join one or more channels, creating any that don't exist yet."}},
    {"PART", {"PART <channel>[,<channel2>...] [:reason]", "Leave one or more channels."}},
    {"PRIVMSG", {"PRIVMSG <target> :<text>",
                 "Message a nick or channel. Prefix a channel target with @/%/+ (STATUSMSG) to reach only that rank or higher."}},
    {"NOTICE", {"NOTICE <target> :<text>", "Like PRIVMSG, but must never trigger an automated reply."}},
    {"TOPIC", {"TOPIC <channel> [:<topic>]",
               "With no topic, shows the current one. An explicit empty topic (\"TOPIC #c :\") clears it."}},
    {"NAMES", {"NAMES <channel>", "List a channel's members."}},
    {"WHO", {"WHO <channel|nick> [%<fields>[,<token>]]",
             "List matching users. The %fields form (WHOX) selects custom columns: t c u i h s n f d l a r."}},
    {"WHOIS", {"WHOIS <nick>", "Show detailed information about a user."}},
    {"WHOWAS", {"WHOWAS <nick> [count]",
                "Show recent nick/user/host records for someone who has since quit or changed nick."}},
    {"AWAY", {"AWAY [:<message>]", "Mark yourself away, or (no argument) clear it."}},
    {"SETNAME", {"SETNAME :<realname>", "Change your realname without reconnecting (IRCv3 setname)."}},
    {"MODE", {"MODE <channel|nick> [modestring [args...]]", "Query or change channel/user modes."}},
    {"OPER", {"OPER <name> <password>", "Become an IRC operator using a configured [[operators]] login."}},
    {"INVITE", {"INVITE <nick> <channel>", "Invite a user to a channel, bypassing +i once."}},
    {"KNOCK", {"KNOCK <channel>", "Ask channel ops for an invite to a +i/+k channel."}},
    {"LIST", {"LIST [<param1,param2,...>]",
              "List channels; each param is an exact name or an ELIST search condition (>n, <n, or a glob)."}},
    {"LINKS", {"LINKS", "Show the servers linked to this network."}},
    {"MAP", {"MAP", "Show an ASCII-tree view of the linked network."}},
    {"KICK", {"KICK <channel> <nick> [:reason]", "Remove a member from a channel. Requires chanop, halfop, or server-oper."}},
    {"KILL", {"KILL <nick> [:reason]", "Disconnect a user from the network. Server-oper only."}},
    {"KLINE", {"KLINE [<mask> [<duration>] [:reason]]",
               "List, or add, a ban. <mask> may be an IP glob (203.0.113.*), a host glob "
               "(*.example.com), or user@host. No argument lists all active K/G/Z-lines. Server-oper only."}},
    {"GLINE", {"GLINE [<mask> [<duration>] [:reason]]", "Same as KLINE. Server-oper only."}},
    {"ZLINE", {"ZLINE [<mask> [<duration>] [:reason]]",
               "Like KLINE, but matched at connect time against the IP only -- it cannot see a "
               "hostname, and is what DNSBL/connect-flood bans use. Server-oper only."}},
    {"UNKLINE", {"UNKLINE <mask>", "Remove a K-line. Server-oper only."}},
    {"UNGLINE", {"UNGLINE <mask>", "Remove a G-line. Server-oper only."}},
    {"UNZLINE", {"UNZLINE <mask>", "Remove a Z-line. Server-oper only."}},
    {"GLOB", {"GLOB <pattern>", "Non-standard: glob-match nicknames server-wide."}},
    {"WALLOPS", {"WALLOPS :<text>", "Message every user with mode +w set. Server-oper only."}},
    {"SILENCE", {"SILENCE [(+|-)mask ...]", "Manage your ignore list for private messages; no argument lists it."}},
    {"USERHOST", {"USERHOST <nick> [nick...]", "Show host/away/oper info for up to 5 nicks."}},
    {"ISON", {"ISON <nick> [nick...]", "Check which of the given nicks are currently online."}},
    {"MONITOR", {"MONITOR + nick[,nick...] | - nick[,...] | C | L | S",
                 "IRCv3 efficient online/offline watch list -- the modern alternative to polling ISON."}},
    {"WATCH", {"WATCH +nick | -nick | C | L | S [...]",
               "Legacy pre-MONITOR watch list (one +/-nick or C/L/S per argument). Prefer MONITOR."}},
    {"REHASH", {"REHASH", "Reload the config file live. Server-oper only."}},
    {"DIE", {"DIE [password]", "Shut the server down. Server-oper only."}},
    {"RESTART", {"RESTART [password]", "Shut the server down and restart it in place. Server-oper only."}},
    {"STATS", {"STATS <letter>", "m = command usage, u = uptime, o = operators, k/g/z = K/G/Z-lines, l = links (all oper-only except m/u)."}},
    {"LUSERS", {"LUSERS", "Re-send the user/server counts sent at registration."}},
    {"UPTIME", {"UPTIME", "Non-standard: show server uptime."}},
    {"ADMIN", {"ADMIN", "Show administrative contact info from [admin]."}},
    {"VHOST", {"VHOST [<host>|off]", "Non-standard: activate a configured virtual host, or clear it (\"off\")."}},
    {"CHGHOST", {"CHGHOST <nick> <new-host>",
                 "Non-standard, server-oper only: force-set another local user's displayed host."}},
    {"SETHOST", {"SETHOST <host>|off", "Non-standard, server-oper only: set your own displayed host to any value, or clear it (\"off\")."}},
    {"SAJOIN", {"SAJOIN <nick> <channel>[,<channel2>...]",
                "Non-standard, server-oper only: force a local user into one or more channels, bypassing +i/+k/+l/+b/+z."}},
    {"SAPART", {"SAPART <nick> <channel>[,<channel2>...] [:reason]",
                "Non-standard, server-oper only: force a local user out of one or more channels."}},
    {"SAMODE", {"SAMODE <channel> <modestring> [args...]",
                "Non-standard, server-oper only: force a channel-mode change, bypassing membership and op/halfop requirements."}},
    {"CONNECT", {"CONNECT <peer name>", "Server-oper only: establish a configured outbound server link on demand."}},
    {"SQUIT", {"SQUIT <peer name> [:reason]", "Server-oper only: drop a server link."}},
    {"TRACE", {"TRACE", "Show connected clients (and, for a server-oper, linked servers)."}},
    {"SERVLIST", {"SERVLIST [<mask> [<type>]]", "List services pseudo-users (e.g. ChanServ) currently online."}},
    {"SQUERY", {"SQUERY <servicename> <text>", "Like PRIVMSG, but the target must be a services pseudo-user."}},
    {"REGISTER", {"REGISTER <account> <password>",
                  "Non-standard: create a self-service account and log in as it. Only available when the "
                  "server has [accounts] enabled -- ask a server operator if this fails."}},
    {"AUTHENTICATE", {"AUTHENTICATE PLAIN|EXTERNAL",
                       "SASL login to an existing account -- normally sent by your client automatically "
                       "during connection setup, not typed by hand. EXTERNAL logs in via a TLS client "
                       "certificate bound with /CERT ADD, instead of a password."}},
    {"CERT", {"CERT ADD|DEL|INFO",
              "Non-standard: bind (ADD), clear (DEL), or show (INFO) the TLS client certificate fingerprint "
              "SASL EXTERNAL logs your account in with. Requires being logged in and connected with a "
              "certificate ([tls] request_client_cert must be enabled server-side)."}},
    {"CAP", {"CAP LS|REQ|END|LIST", "IRCv3 capability negotiation -- normally handled by your client, not typed by hand."}},
    {"PING", {"PING <token>", "Request a PONG from the server."}},
    {"QUIT", {"QUIT [:reason]", "Disconnect from the server."}},
    {"VERSION", {"VERSION", "Show the server's software version."}},
    {"TIME", {"TIME", "Show the server's current time."}},
    {"INFO", {"INFO", "Show general information about the server software."}},
    {"MOTD", {"MOTD", "Show the message of the day."}},
    {"RULES", {"RULES", "Show the network rules."}},
    {"OPERMOTD", {"OPERMOTD", "Show the operator message of the day. Server-oper only."}},
    {"HELP", {"HELP [command]", "Show this general summary, or detailed usage for one command."}},
};

static const char *GENERAL_HELP[] = {
    "SekurIRCd commands: NICK USER JOIN PART QUIT PRIVMSG NOTICE TOPIC NAMES",
    "WHO WHOIS WHOWAS AWAY SETNAME MODE OPER INVITE KNOCK LIST LINKS MAP KICK",
    "KILL MONITOR WATCH SILENCE USERHOST ISON WALLOPS ADMIN LUSERS STATS VERSION",
    "TIME INFO MOTD RULES OPERMOTD REHASH VHOST CHGHOST SETHOST SAJOIN SAPART SAMODE CONNECT",
    "SQUIT TRACE SERVLIST SQUERY REGISTER AUTHENTICATE CERT.",
    "Type /HELP <command> for that command's usage and parameters.",
};

void cmd_help(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)srv;
    const char *topic = msg->nparams > 0 ? msg->params[0] : "*";
    const char *p[] = {topic};

    if (strcmp(topic, "*") != 0) {
        for (size_t i = 0; i < sizeof HELP_TABLE / sizeof HELP_TABLE[0]; i++) {
            if (strcasecmp(HELP_TABLE[i].cmd, topic) != 0) continue;
            client_reply(cl, N_HELPSTART, p, 1, "Help");
            for (int j = 0; j < 3 && HELP_TABLE[i].lines[j]; j++)
                client_reply(cl, N_HELPTXT, p, 1, HELP_TABLE[i].lines[j]);
            client_reply(cl, N_ENDOFHELP, p, 1, "End of /HELP");
            return;
        }
        client_reply(cl, N_HELPNOTFOUND, p, 1, "No help available on this topic");
        return;
    }

    client_reply(cl, N_HELPSTART, p, 1, "Help");
    for (size_t i = 0; i < sizeof GENERAL_HELP / sizeof GENERAL_HELP[0]; i++)
        client_reply(cl, N_HELPTXT, p, 1, GENERAL_HELP[i]);
    client_reply(cl, N_ENDOFHELP, p, 1, "End of /HELP");
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
