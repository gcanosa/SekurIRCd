/* Informational commands: VERSION, TIME, MOTD, LUSERS, ADMIN, UPTIME, STATS,
 * TRACE, SERVLIST, SQUERY (STATS is cmd_stats.c). Ported from commands.py's cmd_version/etc. */
#include "cmd.h"
#include "link.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* "VERSION <server>" (TIME, ADMIN, MOTD, INFO too) naming another server on the network: that server answers. */
static int asked_elsewhere(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1 || cl->remote) return 0;
    netserver_t *s = netsync_find_name(srv, msg->params[0]);
    if (!s || s == srv->self_srv) return 0;
    netsync_rquery(srv, cl, s, msg->command, NULL, 0);
    return 1;
}

void cmd_version(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (asked_elsewhere(srv, cl, msg)) return;
    /* ircu/solanum style: "351 <nick> <version>(<build>). <server> :<flags>",
     * then the 005 lines. The flags are the optional features switched on
     * here: A accounts/SASL (services online), D DNSBL, L server links, P proxy scanner (Protection bundle), S spam protection,
     * T TLS listener ("-" when none). */
    char swver[CFG_STR + 48];
    server_software_version(srv, swver, sizeof swver);
    size_t vl = strlen(swver);
    swver[vl] = '.'; swver[vl + 1] = '\0'; /* room reserved by the +48 above */
    char flags[8];
    int n = 0;
    if (services_agent(srv)) flags[n++] = 'A'; /* account services reachable */
    if (srv->cfg.protection.bl_enabled && srv->cfg.protection.n_blacklists) flags[n++] = 'D';
    if (srv->cfg.protection.scan_enabled) flags[n++] = 'P';
    if (srv->cfg.links.enabled) flags[n++] = 'L';
    if (srv->cfg.spam.enabled) flags[n++] = 'S';
    if (srv->cfg.tls.enabled) flags[n++] = 'T';
    if (!n) flags[n++] = '-';
    flags[n] = '\0';
    const char *p[] = {swver, srv->cfg.server.name};
    client_reply(cl, N_VERSION, p, 2, flags);
    server_send_isupport(srv, cl);
}

void cmd_time(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (asked_elsewhere(srv, cl, msg)) return;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char buf[64];
    strftime(buf, sizeof buf, "%A %B %d %Y -- %H:%M:%S %Z", &tmv);
    const char *p[] = {srv->cfg.server.name};
    client_reply(cl, N_TIME, p, 1, buf);
}

void cmd_motd(server_t *srv, client_t *cl, irc_message_t *msg) { if (!asked_elsewhere(srv, cl, msg)) server_send_motd(srv, cl, 0); }
void cmd_rules(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_rules(srv, cl); }
void cmd_opermotd(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_oper_motd(srv, cl); }
void cmd_lusers(server_t *srv, client_t *cl, irc_message_t *msg) { (void)msg; server_send_lusers(srv, cl); }

void cmd_admin(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (asked_elsewhere(srv, cl, msg)) return;
    char msgbuf[128];
    snprintf(msgbuf, sizeof msgbuf, "Administrative info about %s", srv->cfg.server.name);
    client_reply(cl, N_ADMINME, NULL, 0, msgbuf);
    client_reply(cl, N_ADMINLOC1, NULL, 0, srv->cfg.admin.location1[0] ? srv->cfg.admin.location1 : "Not configured");
    client_reply(cl, N_ADMINLOC2, NULL, 0, srv->cfg.admin.location2[0] ? srv->cfg.admin.location2 : "Not configured");
    client_reply(cl, N_ADMINEMAIL, NULL, 0, srv->cfg.admin.email[0] ? srv->cfg.admin.email : "Not configured");
}

void cmd_uptime_str(server_t *srv, char *out, size_t outsz) {
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
    cmd_uptime_str(srv, buf, sizeof buf);
    client_reply(cl, N_STATSUPTIME, NULL, 0, buf);
}

void cmd_trace(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    if (OPER_CAN(cl, OPER_PRIV_AUSPEX)) {
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
    if (asked_elsewhere(srv, cl, msg)) return;
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
    {"PASS", {"PASS [<account>:]<password>",
              "Sent before NICK/USER: logs you into that account (or the one named like your nick) -- for clients without SASL."}},
    {"JOIN", {"JOIN <channel>[,<channel2>...] [key[,key2...]]",
              "Join one or more channels, creating any that don't exist yet. JOIN 0 leaves every channel."}},
    {"PART", {"PART <channel>[,<channel2>...] [:reason]", "Leave one or more channels."}},
    {"PRIVMSG", {"PRIVMSG <target>[,<target>...] :<text>",
                 "Message nicks or channels (up to 4 targets). Prefix a channel target with ~/&/@/%/+ (STATUSMSG) to reach only that rank or higher."}},
    {"NOTICE", {"NOTICE <target>[,<target>...] :<text>", "Like PRIVMSG, but must never trigger an automated reply."}},
    {"REDACT", {"REDACT <target> <msgid> [:reason]",
                "Take back a message still in history: your own, or anyone's in a channel you operate. Clients with draft/message-redaction hide it."}},
    {"TOPIC", {"TOPIC <channel> [:<topic>]",
               "With no topic, shows the current one. An explicit empty topic (\"TOPIC #c :\") clears it."}},
    {"NAMES", {"NAMES <channel>", "List a channel's members."}},
    {"WHO", {"WHO <channel|nick|mask> [o][%<fields>[,<token>]]",
             "List matching users. A mask globs nick, user, host, server and realname (0 = everyone); 'o' keeps only opers; "
             "+i users show only if you share a channel. The %fields form (WHOX) selects columns: t c u i h s n f d l a r."}},
    {"WHOIS", {"WHOIS [<nick|server>] <nick>", "Show detailed information about a user. With two arguments the user's own server answers, so idle time shows for users on other servers too."}},
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
    {"MAP", {"MAP", "Show the linked servers as a tree, each with its users and share of the network."}},
    {"KICK", {"KICK <channel> <nick> [:reason]", "Remove a member from a channel. Requires chanop, halfop, or server-oper."}},
    {"KILL", {"KILL <nick> [:reason]", "Disconnect a user from the network. Server-oper only."}},
    {"KLINE", {"KLINE [<mask> [<duration>] [:reason]]",
               "List, or add, a ban. <mask> may be an IP glob (203.0.113.*), a CIDR range (203.0.113.0/24, "
               "2001:db8::/32 -- write an IPv6 one starting with ':' as 0::...), a host glob (*.example.com), "
               "or user@host. No argument lists all active K/G/Z-lines. Server-oper only."}},
    {"GLINE", {"GLINE [<mask> [<duration>] [:reason]]", "Same as KLINE, but network-wide: every linked server applies it. Server-oper only."}},
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
    {"GLOBOPS", {"GLOBOPS :<text>", "IRC operators only: message every online operator."}},
    {"CHGIDENT", {"CHGIDENT <nick> <ident>", "IRC operators only: change a user's ident."}},
    {"SANICK", {"SANICK <nick> <newnick>", "IRC operators only: force a nick change."}},
    {"SHUN", {"SHUN [<mask> [duration] [reason]]", "IRC operators only: silently drop a connected user's messages (no disconnect), on every linked server. Needs UNSHUN to lift."}},
    {"ELINE", {"ELINE [<mask> [duration] [reason]]", "IRC operators only: exempt a mask from K/G-lines. On a whole address (IP, glob or CIDR such as 2001:db8::/64) it also exempts it from Z-lines, the connect-flood throttle, the per-IP connection cap, the DNSBL and the proxy scanner."}},
    {"CLASS", {"CLASS [LIST] | ADD [GLOBAL] <name> <host,host,...> [max_clients=N] [max_per_ip=N] [sendq_max=N] [flood_max_msgs=N] [flood_window=S] | DEL <name>",
               "IRC operators only: connection classes, limits for some addresses (IP globs or CIDR ranges). GLOBAL publishes the class to every linked server, each of which applies it to its own connections. A class from the config file is changed there."}},
    {"DEFCON", {"DEFCON [<5|4|3|2|1> [duration]]", "IRC operators only: tighten this server against an attack. 4 halves the connect rate and allows two connections per address; 3 also needs a login (SASL) to connect; 2 also needs TLS; 1 takes no new connections. 5 is normal; an ELINE'd address is never held to it. A duration (30m) puts the level back by itself. No argument shows the level."}},
    {"QLINE", {"QLINE [<nickmask> [duration] [reason]]", "IRC operators only: refuse nicknames matching a glob (evil*), on every linked server; no argument lists them. Users already on keep their nick. UNQLINE lifts one."}},
    {"RESV", {"RESV [<#channelmask> [duration] [reason]]", "IRC operators only: refuse JOINs to channel names matching a glob (#warez*), on every linked server; no argument lists them. UNRESV lifts one."}},
    {"XLINE", {"XLINE [<realnamemask> [duration] [reason]]", "IRC operators only: refuse connections whose realname matches a glob (an underscore stands for a space: buy_cheap_*), on every linked server; no argument lists them. UNXLINE lifts one."}},
    {"ACCEPT", {"ACCEPT [nick[,-nick,...]]", "Caller-ID (+g): allow/remove nicks that may message you; no argument lists them."}},
    {"LOCOPS", {"LOCOPS :<text>", "IRC operators only: message the operators on this server."}},
    {"OPERWALL", {"OPERWALL :<text>", "IRC operators only: same as GLOBOPS."}},
    {"TESTLINE", {"TESTLINE <nick|user@host|ip>", "IRC operators only: show which K/G/Z/SHUN/ELINE lines match that address."}},
    {"RENAME", {"RENAME <old> <new> [:reason]", "Rename a channel you operate (not a registered one), keeping members, modes and topic."}},
    {"USERIP", {"USERIP <nick> [nick...]", "IRC operators only: like USERHOST but shows the real IP address."}},
    {"ISON", {"ISON <nick> [nick...]", "Check which of the given nicks are currently online."}},
    {"MONITOR", {"MONITOR + nick[,nick...] | - nick[,...] | C | L | S",
                 "IRCv3 efficient online/offline watch list -- the modern alternative to polling ISON."}},
    {"WATCH", {"WATCH +nick | -nick | C | L | S [...]",
               "Legacy pre-MONITOR watch list (one +/-nick or C/L/S per argument). Prefer MONITOR."}},
    {"SPAMFILTER", {"SPAMFILTER [LIST] | ADD <targets> <block|warn|kill|zline|hide|shun> <duration|-> <reason_with_underscores> <regex> | DEL <n>",
                    "Server-oper only: manage the [spam] regex content filters (targets: p c n N a q P t)."}},
    {"PROTECT", {"PROTECT [SCAN <ipv4>]",
                 "Server-oper only: show the Protection bundle status (blacklists, proxy scanner, limits), or SCAN an address now."}},
    {"REHASH", {"REHASH [<server>|*]", "Reload the config file live: this server, another one, or every server (*). Opers on every server are told. Server-oper only."}},
    {"DIE", {"DIE [password]", "Shut the server down. Server-oper only."}},
    {"RESTART", {"RESTART [password]", "Shut the server down and restart it in place. Server-oper only."}},
    {"STATS", {"STATS [<letter> [<server>|<nick>]]", "Anyone: m commands, u uptime, p opers online, v servers, l <your nick>. Opers also: b c d e f g h i k l L o P q s t y z Z ?.",
               "STATS with no letter lists what you may ask. A server name, or a nick on another server, makes that server answer."}},
    {"LUSERS", {"LUSERS", "Re-send the user/server counts sent at registration."}},
    {"UPTIME", {"UPTIME", "Non-standard: show server uptime."}},
    {"ADMIN", {"ADMIN [<server>]", "Show administrative contact info from [admin] (of another linked server, if named)."}},
    {"VHOST", {"VHOST [<host> [<password>]|off]", "Non-standard: list the virtual hosts you may use, wear one (some need their password), or clear it (\"off\"). Yours are this server's [[vhosts]] and the ones your account was given (NickServ VHOST).",
               "Opers with the host privilege: VHOST ADD|DEL <account> <host> and VHOST LIST <account> give an account vhosts to choose from, on every server."}},
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
    {"REGISTER", {"REGISTER <account> <password> | REGISTER <account|*> <email|*> <password>",
                  "Create a self-service account and log in as it (the second form is IRCv3 "
                  "draft/account-registration; * means your nick). Also: /msg NickServ REGISTER <password> "
                  "and /msg NickServ IDENTIFY [account] <password>. Handled by NickServ in the network's "
                  "services -- unavailable while they are down."}},
    {"VERIFY", {"VERIFY <account> <code>",
                "Finish a registration that needs its email confirmed: the code was mailed to the address given to "
                "REGISTER. The account works, and you are logged in, once it matches. Also: /msg NickServ VERIFY <code>."}},
    {"NS", {"NS <command> [args...]",
            "Shorthand for /msg NickServ <command> (also NICKSERV); CS and CHANSERV do the same for ChanServ. "
            "/NS HELP lists the NickServ commands: REGISTER, IDENTIFY, GHOST, REGAIN, RESETPASS, GROUP, SET, DROP and more."}},
    {"AUTHENTICATE", {"AUTHENTICATE PLAIN|SCRAM-SHA-256|EXTERNAL",
                       "SASL login to an existing account -- normally sent by your client automatically "
                       "during connection setup, not typed by hand. EXTERNAL logs in via a TLS client "
                       "certificate bound with /msg NickServ CERT ADD, instead of a password."}},
    {"CERT", {"CERT ADD|DEL|INFO",
              "Shorthand for /msg NickServ CERT: bind (ADD), clear (DEL), or show (INFO) the TLS client certificate fingerprint "
              "SASL EXTERNAL logs your account in with. Requires being logged in and connected with a "
              "certificate ([tls] request_client_cert must be enabled server-side)."}},
    {"CAP", {"CAP LS|REQ|END|LIST", "IRCv3 capability negotiation -- normally handled by your client, not typed by hand."}},
    {"PING", {"PING <token>", "Request a PONG from the server."}},
    {"QUIT", {"QUIT [:reason]", "Disconnect from the server."}},
    {"VERSION", {"VERSION [<server>]", "Show the server's software version and build, its optional-feature flags (A accounts, D dnsbl, L links, P proxy scanner, S spam, T tls), and the 005 ISUPPORT tokens."}},
    {"TIME", {"TIME [<server>]", "Show the server's current time."}},
    {"INFO", {"INFO [<server>]", "Show general information about the server software."}},
    {"MOTD", {"MOTD [<server>]", "Show the message of the day."}},
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
    if (target->remote) { netsync_message(srv, cl, "PRIVMSG", target->nick, target, textbuf, NULL, 0); return; } /* services linked elsewhere */
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    const char *p2[] = {msg->params[0]};
    irc_build(line, sizeof line, NULL, 0, prefix, "PRIVMSG", p2, 1, textbuf);
    client_send(target, line);
}
