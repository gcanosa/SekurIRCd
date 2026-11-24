#include "cmd.h"
#include "log.h"
#include "net.h"
#include "protection.h"
#include "xline.h"
#include "classes.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Commands an unregistered connection may send (matches commands.py's
 * _REGISTRATION_COMMANDS). Everything else gets 451 ERR_NOTREGISTERED. */
static const char *REGISTRATION_COMMANDS[] = {
    "NICK", "USER", "PASS", "CAP", "PING", "PONG", "QUIT", "AUTHENTICATE", "WEBIRC", "AWAY", "ISUPPORT",
};

static int is_registration_command(const char *cmd) {
    for (size_t i = 0; i < sizeof REGISTRATION_COMMANDS / sizeof REGISTRATION_COMMANDS[0]; i++)
        if (strcasecmp(cmd, REGISTRATION_COMMANDS[i]) == 0) return 1;
    return 0;
}

/* Which OPER_PRIV_* class an oper-only command belongs to (0 = no class: any oper may use it). */
static unsigned command_priv(const char *c) {
    static const struct { const char *cmd; unsigned priv; } MAP[] = {
        {"KILL", OPER_PRIV_KILL},
        {"KLINE", OPER_PRIV_KLINE}, {"SHUN", OPER_PRIV_KLINE}, {"UNSHUN", OPER_PRIV_KLINE}, {"ELINE", OPER_PRIV_KLINE}, {"UNELINE", OPER_PRIV_KLINE}, {"GLINE", OPER_PRIV_KLINE}, {"ZLINE", OPER_PRIV_KLINE},
        {"UNKLINE", OPER_PRIV_KLINE}, {"UNGLINE", OPER_PRIV_KLINE}, {"UNZLINE", OPER_PRIV_KLINE},
        {"DEFCON", OPER_PRIV_KLINE}, {"CLASS", OPER_PRIV_KLINE}, {"QLINE", OPER_PRIV_KLINE}, {"UNQLINE", OPER_PRIV_KLINE}, {"RESV", OPER_PRIV_KLINE}, {"UNRESV", OPER_PRIV_KLINE}, {"XLINE", OPER_PRIV_KLINE}, {"UNXLINE", OPER_PRIV_KLINE},
        {"SPAMFILTER", OPER_PRIV_KLINE}, {"TESTLINE", OPER_PRIV_KLINE}, {"PROTECT", OPER_PRIV_KLINE},
        {"SAJOIN", OPER_PRIV_SA}, {"SAPART", OPER_PRIV_SA}, {"SAMODE", OPER_PRIV_SA}, {"SANICK", OPER_PRIV_SA},
        {"CHGHOST", OPER_PRIV_HOST}, {"SETHOST", OPER_PRIV_HOST}, {"CHGIDENT", OPER_PRIV_HOST}, {"USERIP", OPER_PRIV_HOST},
        {"WALLOPS", OPER_PRIV_WALLOPS}, {"GLOBOPS", OPER_PRIV_WALLOPS}, {"OPERWALL", OPER_PRIV_WALLOPS}, {"LOCOPS", OPER_PRIV_WALLOPS},
        {"REHASH", OPER_PRIV_REHASH},
        {"DIE", OPER_PRIV_DIE}, {"RESTART", OPER_PRIV_DIE},
        {"SQUIT", OPER_PRIV_LINK}, {"CONNECT", OPER_PRIV_LINK},
    };
    for (size_t i = 0; i < sizeof MAP / sizeof MAP[0]; i++) if (strcasecmp(MAP[i].cmd, c) == 0) return MAP[i].priv;
    return 0;
}

static const cmd_entry_t DISPATCH[] = {
    {"NICK", cmd_nick, 0, 0, 0},
    {"USER", cmd_user, 4, 0, 0},
    {"PASS", cmd_pass, 0, 0, 0},
    {"WEBIRC", cmd_webirc, 4, 0, 0},
    {"TAGMSG", cmd_tagmsg, 1, 1, 0},
    {"RENAME", cmd_rename, 2, 1, 0},
    {"BATCH", cmd_batch, 1, 1, 0},
    {"MARKREAD", cmd_markread, 1, 1, 0},
    {"REDACT", cmd_redact, 2, 1, 0},
    {"ACCEPT", cmd_accept, 0, 1, 0},
    {"CHATHISTORY", cmd_chathistory, 2, 1, 0},
    {"USERIP", cmd_userip, 1, 1, 1},
    {"SHUN", cmd_shun, 0, 1, 1},
    {"UNSHUN", cmd_unshun, 1, 1, 1},
    {"ELINE", cmd_eline, 0, 1, 1},
    {"DEFCON", cmd_defcon, 0, 1, 1},
    {"CLASS", cmd_class, 0, 1, 1},
    {"QLINE", cmd_qline, 0, 1, 1},
    {"UNQLINE", cmd_unqline, 1, 1, 1},
    {"RESV", cmd_resv, 0, 1, 1},
    {"UNRESV", cmd_unresv, 1, 1, 1},
    {"XLINE", cmd_xline, 0, 1, 1},
    {"UNXLINE", cmd_unxline, 1, 1, 1},
    {"UNELINE", cmd_uneline, 1, 1, 1},
    {"GLOBOPS", cmd_globops, 1, 1, 1},
    {"OPERWALL", cmd_globops, 1, 1, 1},
    {"LOCOPS", cmd_locops, 1, 1, 1},
    {"TESTLINE", cmd_testline, 1, 1, 1},
    {"CHGIDENT", cmd_chgident, 2, 1, 1},
    {"SANICK", cmd_sanick, 2, 1, 1},
    {"CAP", cmd_cap, 1, 0, 0},
    {"ISUPPORT", cmd_isupport, 0, 0, 0},
    {"PING", cmd_ping, 0, 0, 0},
    {"PONG", cmd_pong, 0, 0, 0},
    {"QUIT", cmd_quit, 0, 0, 0},
    {"AUTHENTICATE", cmd_authenticate, 1, 0, 0},
    {"REGISTER", cmd_register, 2, 1, 0},
    {"VERIFY", cmd_verify, 2, 1, 0},
    {"CERT", cmd_cert, 1, 1, 0},
    {"NS", cmd_service_alias, 1, 1, 0},
    {"NICKSERV", cmd_service_alias, 1, 1, 0},
    {"CS", cmd_service_alias, 1, 1, 0},
    {"CHANSERV", cmd_service_alias, 1, 1, 0},

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

    {"OPER", cmd_oper, 1, 1, 0}, /* a certfp-only login needs no password */
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
    {"SPAMFILTER", cmd_spamfilter, 0, 1, 1},
    {"PROTECT", cmd_protect, 0, 1, 1},
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
    {"RULES", cmd_rules, 0, 1, 0},
    {"OPERMOTD", cmd_opermotd, 0, 1, 1},
    {"LUSERS", cmd_lusers, 0, 1, 0},
    {"UPTIME", cmd_uptime, 0, 1, 0},
    {"ADMIN", cmd_admin, 0, 1, 0},
};
#define N_DISPATCH (int)(sizeof DISPATCH / sizeof DISPATCH[0])
_Static_assert(sizeof DISPATCH / sizeof DISPATCH[0] <= sizeof ((server_t *)0)->command_counts / sizeof ((server_t *)0)->command_counts[0],
               "STATS m: grow server_t.command_counts");

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
    if (cl->rdns_pending || cl->ident_pending || cl->auth_pending) return; /* net.c's worker-result tick retries this once they clear */
    if (cmd_pass_login(srv, cl)) return; /* PASS login now in flight: same hold as a SASL one */

    /* Only now are user/host final (USER, identd and rDNS have all landed),
     * so this is the first point a hostname K/G-line can be evaluated at all
     * -- the accept-time check only ever had the IP. */
    const char *kl = server_kline_match(srv, cl->ip, cl->user, cl->realhost, cl->ident_confirmed, cl->cloak);
    if (kl) {
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "%s", kl);
        client_mark_quit(cl);
        char snote[400];
        snprintf(snote, sizeof snote, "Rejected connection from %s (%s@%s): %s",
                 cl->ip, cl->user, cl->realhost, kl);
        server_notify_opers(srv, snote);
        return;
    }
    int defcon = server_defcon(srv);
    if (defcon <= 3 && !server_eline_ip(srv, cl->ip)) { /* DEFCON 3: log in (SASL) to connect; 2: and over TLS */
        const char *why = defcon <= 2 && !cl->ssl ? "only TLS connections are taken right now" : !cl->account[0] ? "only logged-in users (SASL) are taken right now" : NULL;
        if (why) {
            char err[300];
            snprintf(err, sizeof err, "ERROR :Closing Link: %s (DEFCON %d)", why, defcon);
            client_send(cl, err);
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "%s (DEFCON %d)", why, defcon);
            client_mark_quit(cl);
            return;
        }
    }
    const char *xl = xline_match(srv, 'X', cl->realname); /* an X-line: the realname is the thing banned */
    if (xl) {
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "X-Lined: %s", xl);
        char err[400];
        snprintf(err, sizeof err, "ERROR :Closing Link: %s (X-Lined: %s)", cl->ip, xl);
        client_send(cl, err);
        client_mark_quit(cl);
        char snote[400];
        snprintf(snote, sizeof snote, "Rejected connection from %s (%s@%s): X-Lined: %s", cl->ip, cl->user, cl->realhost, xl);
        server_notify_opers(srv, snote);
        return;
    }
    if (net_takeover(srv, cl)) return; /* always-on: resumed the account's kept session instead of joining as new */
    cl->registered = 1;

    /* Must land before server_send_welcome: its post-MOTD RPL_UMODEIS line
     * (and RFC 221 in general) is supposed to reflect the modes the client
     * actually ends up with, not a snapshot taken before these apply. */
    for (const char *p = srv->cfg.security.default_user_modes; *p; p++) cl->umodes |= client_umode_bit(*p);

    char snote[300];
    snprintf(snote, sizeof snote, "Client connecting: %s (%s@%s) [%s] {users}", cl->nick, cl->user, cl->realhost[0] ? cl->realhost : cl->host, cl->ip);
    server_notify_opers(srv, snote);

    if (!cl->certfp[0]) client_cert_fingerprint(cl, cl->certfp, sizeof cl->certfp);
    server_send_welcome(srv, cl);
    netsync_introduce_user(srv, cl); /* the rest of the network (and services' user feed) learns about them */
    server_monitor_notify(srv, cl, 1);
    server_watch_notify(srv, cl, 1);

    for (int i = 0; i < srv->cfg.channels.n_auto_join; i++)
        cmd_force_join(srv, cl, srv->cfg.channels.auto_join[i]);
    net_resume_rejoin(srv, cl); /* always-on resumed from another server: its channels and ranks */
}

/* DISPATCH indices sorted by command name, so lookup is a bsearch instead of ~90 strcasecmps per line. */
static int g_sorted[N_DISPATCH];
static int g_sorted_ready;

static int cmp_dispatch_idx(const void *a, const void *b) {
    return strcasecmp(DISPATCH[*(const int *)a].name, DISPATCH[*(const int *)b].name);
}

static int cmp_key_idx(const void *key, const void *elem) {
    return strcasecmp((const char *)key, DISPATCH[*(const int *)elem].name);
}

static int find_dispatch(const char *cmd) {
    if (!g_sorted_ready) {
        for (int i = 0; i < N_DISPATCH; i++) g_sorted[i] = i;
        qsort(g_sorted, N_DISPATCH, sizeof g_sorted[0], cmp_dispatch_idx);
        g_sorted_ready = 1;
    }
    int *hit = bsearch(cmd, g_sorted, N_DISPATCH, sizeof g_sorted[0], cmp_key_idx);
    return hit ? *hit : -1;
}

static void dispatch_inner(server_t *srv, client_t *cl, irc_message_t *msg);

/* [flood] command_limits: true (and RPL_TRYAGAIN sent) when `cl` has run `command` more than its limit allows in the window.
 * Opers and unregistered connections are never limited. */
static int cmd_rate_limited(server_t *srv, client_t *cl, const char *command) {
    const cfg_security_t *sec = &srv->cfg.security;
    if (sec->n_cmd_limits == 0 || !cl->registered || (cl->umodes & UMODE_O)) return 0;
    for (int j = 0; j < sec->n_cmd_limits; j++) {
        if (strcasecmp(sec->cmd_limits[j].name, command) != 0) continue;
        time_t now = time(NULL);
        if (cl->cmd_rate[j].start == 0 || difftime(now, cl->cmd_rate[j].start) >= sec->cmd_limits[j].window) {
            cl->cmd_rate[j].start = now;
            cl->cmd_rate[j].count = 0;
        }
        if (++cl->cmd_rate[j].count <= sec->cmd_limits[j].max) return 0;
        const char *p[] = {command};
        client_reply(cl, N_TRYAGAIN, p, 1, "Please wait a while and try again.");
        return 1;
    }
    return 0;
}

/* The audit log: what an oper ran. Read-only lookups and secrets stay out of it. */
static void audit_oper_command(client_t *cl, const irc_message_t *msg) {
    static const char *const QUIET[] = {"TESTLINE", "TRACE", "STATS", "LINKS", "MAP"};
    for (size_t k = 0; k < sizeof QUIET / sizeof QUIET[0]; k++) if (strcasecmp(msg->command, QUIET[k]) == 0) return;
    int secret = strcasecmp(msg->command, "DIE") == 0 || strcasecmp(msg->command, "RESTART") == 0; /* their parameter is a password */
    char args[400] = "";
    for (int k = 0; k < msg->nparams && !secret; k++) {
        size_t l = strlen(args);
        const char *a = msg->params[k];
        int trailing = k == msg->nparams - 1 && (!*a || *a == ':' || strchr(a, ' '));
        snprintf(args + l, sizeof args - l, " %s%s", trailing ? ":" : "", a);
    }
    log_audit("%s!%s@%s%s%s %s%s", cl->nick, client_ident(cl), cl->realhost[0] ? cl->realhost : cl->host, cl->remote ? " on " : "",
              cl->remote ? netsync_server_name_of(cl->srv, cl) : "", msg->command, secret ? " <redacted>" : args);
}

void cmd_count_remote(server_t *srv, const char *name) {
    int n = srv->n_command_counts;
    for (int c = 0; c < n; c++)
        if (strcasecmp(srv->command_counts[c].name, name) == 0) { srv->command_counts[c].remote++; return; }
    if (n >= (int)(sizeof srv->command_counts / sizeof srv->command_counts[0])) return;
    snprintf(srv->command_counts[n].name, sizeof srv->command_counts[n].name, "%s", name);
    for (char *p = srv->command_counts[n].name; *p; p++) *p = (char)toupper((unsigned char)*p);
    srv->command_counts[n].count = 0; srv->command_counts[n].bytes = 0; srv->command_counts[n].remote = 1;
    srv->n_command_counts++;
}

/* labeled-response wrapper: a message carrying @label=... from a client that negotiated labeled-response
 * (+batch) gets its replies labeled -- see client_label_begin/end. */
void cmd_dispatch(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *label = NULL;
    if ((cl->caps & CAP_LABELED_RESPONSE) && (cl->caps & CAP_BATCH))
        for (int i = 0; i < msg->ntags; i++)
            if (strcmp(msg->tags[i].key, "label") == 0 && msg->tags[i].val[0] && strlen(msg->tags[i].val) < 64) { label = msg->tags[i].val; break; }
    if (label) client_label_begin(cl, label);
    dispatch_inner(srv, cl, msg);
    if (label) client_label_end(cl);
}

static void dispatch_inner(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (!cl->registered && !is_registration_command(msg->command)) {
        err_not_registered(cl);
        return;
    }
    if (cl->registered && !OPER_CAN(cl, OPER_PRIV_IMMUNE) && server_is_shunned(srv, cl)) {
        /* SHUN: only harmless/informational commands still work; everything else is silently dropped. */
        static const char *ALLOWED[] = {"PING", "PONG", "QUIT", "PART", "MOTD", "VERSION", "TIME", "LUSERS", "HELP", "ADMIN", "INFO", "CAP", "RULES"};
        int ok = 0;
        for (size_t a = 0; a < sizeof ALLOWED / sizeof ALLOWED[0]; a++) if (strcasecmp(msg->command, ALLOWED[a]) == 0) { ok = 1; break; }
        if (!ok) return;
    }
    int i = find_dispatch(msg->command);
    if (i >= 0) {
        if (msg->nparams < DISPATCH[i].min_params) {
            err_need_more_params(cl, msg->command);
            return;
        }
        if (DISPATCH[i].oper_only && !(cl->umodes & UMODE_O)) {
            err_no_privileges(cl);
            return;
        }
        unsigned need = DISPATCH[i].oper_only ? command_priv(msg->command) : 0;
        if (need && !(cl->oper_privs & need)) { /* an oper whose login lacks this command's privilege class */
            err_no_privileges(cl);
            return;
        }
        /* STATS m counters: slot per dispatch entry (revalidated, since a slot index from another server instance can be stale). */
        static int count_slot[N_DISPATCH];
        static int slots_init;
        if (!slots_init) { for (int k = 0; k < N_DISPATCH; k++) count_slot[k] = -1; slots_init = 1; }
        int cs = count_slot[i];
        if (cs < 0 || cs >= srv->n_command_counts || strcmp(srv->command_counts[cs].name, DISPATCH[i].name) != 0) {
            cs = -1;
            for (int c = 0; c < srv->n_command_counts; c++)
                if (strcmp(srv->command_counts[c].name, DISPATCH[i].name) == 0) { cs = c; break; }
            if (cs < 0 && srv->n_command_counts < (int)(sizeof srv->command_counts / sizeof srv->command_counts[0])) {
                cs = srv->n_command_counts++;
                snprintf(srv->command_counts[cs].name, sizeof srv->command_counts[0].name, "%s", DISPATCH[i].name);
                srv->command_counts[cs].count = 0;
            }
            count_slot[i] = cs;
        }
        if (cs >= 0) {
            srv->command_counts[cs].count++;
            size_t b = strlen(msg->command) + 2; /* the line as sent, less tags: command, " param"s, CRLF */
            for (int k = 0; k < msg->nparams; k++) b += strlen(msg->params[k]) + 1;
            srv->command_counts[cs].bytes += b;
        }
        if (cmd_rate_limited(srv, cl, DISPATCH[i].name)) return;
        if (DISPATCH[i].oper_only && log_audit_enabled()) audit_oper_command(cl, msg); /* before: DIE and RESTART never return */
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
