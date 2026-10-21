/* Registration: NICK, USER, PASS, CAP, PING, PONG, QUIT, plus the relay to account services (AUTHENTICATE, REGISTER,
 * CERT, and the services -> user commands in svc_command). Accounts themselves live in the services daemon. */
#include "cmd.h"
#include "crypto.h"
#include "log.h"
#include "net.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char *sasl_mechs(server_t *srv);

void cmd_nick(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1) {
        client_reply(cl, N_NONICKNAMEGIVEN, NULL, 0, "No nickname given");
        return;
    }
    const char *newnick = msg->params[0];
    if (!irc_valid_nick(newnick, srv->cfg.security.max_nick_length)) {
        const char *p[] = {newnick};
        client_reply(cl, N_ERRONEUSNICKNAME, p, 1, "Erroneous nickname");
        return;
    }
    char cf[NICKLEN];
    irc_casefold(cf, sizeof cf, newnick);

    if (!cl->is_service) {
        for (int i = 0; i < srv->cfg.security.n_reserved_nicks; i++) {
            char rcf[CFG_STR];
            irc_casefold(rcf, sizeof rcf, srv->cfg.security.reserved_nicks[i]);
            if (strcmp(rcf, cf) == 0) {
                const char *p[] = {newnick};
                client_reply(cl, N_UNAVAILRESOURCE, p, 1, "Nickname is reserved");
                return;
            }
        }
    }

    client_t *existing = server_find_user(srv, newnick);
    if (existing && existing != cl) {
        const char *p[] = {newnick};
        client_reply(cl, N_NICKNAMEINUSE, p, 1, "Nickname is already in use");
        return;
    }

    if (!cl->registered) {
        if (cl->got_nick) {
            /* re-keying a pre-registration NICK change (client changed its
             * mind before USER completed) -- drop the old hash entry first. */
            client_t *found;
            HASH_FIND_STR(srv->users, cl->casefold_nick, found);
            if (found == cl) HASH_DEL(srv->users, cl);
        }
        snprintf(cl->nick, sizeof cl->nick, "%s", newnick);
        snprintf(cl->casefold_nick, sizeof cl->casefold_nick, "%s", cf);
        cl->got_nick = 1;
        server_add_user(srv, cl);
        cmd_send_welcome_if_ready(srv, cl);
        return;
    }

    if (strcmp(cl->nick, newnick) == 0) return; /* identical nick: nothing to announce */

    if (strcmp(cl->casefold_nick, cf) == 0) {
        /* case-only change: no collision, no re-key needed by identity (the
         * hash key is the casefold form, unchanged) -- but it must still be
         * announced like any other NICK. Silently rewriting cl->nick left
         * the client's own display case out of sync with itself and with
         * everyone else's view, permanently, with no way to notice. */
        char prefix[320];
        client_prefix(cl, prefix, sizeof prefix);
        char line[400];
        irc_build(line, sizeof line, NULL, 0, prefix, "NICK", NULL, 0, newnick);
        client_send(cl, line);
        server_send_common_channels(srv, cl, line, 0);
        snprintf(cl->nick, sizeof cl->nick, "%s", newnick);
        netsync_user_nick(srv, cl);
        return;
    }

    if (!(cl->umodes & UMODE_O)) {
        for (chan_node_t *n = cl->channels; n; n = n->next) {
            channel_t *chan = n->chan;
            if (!(chan->modes & CMODE_NONICK)) continue;
            member_t *me = channel_find_member(chan, cl);
            if (me && (me->rank & (RANK_OP | RANK_HALFOP))) continue;
            const char *p[] = {chan->name};
            client_reply(cl, N_CANTCHANGENICK, p, 1, "Can not change nickname while on channel (+N)");
            return;
        }
    }

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[400];
    irc_build(line, sizeof line, NULL, 0, prefix, "NICK", NULL, 0, newnick);

    client_send(cl, line);
    server_send_common_channels(srv, cl, line, 0);
    server_monitor_notify(srv, cl, 0); /* MONITOR: old nick went offline, new one online below */
    server_watch_notify(srv, cl, 0);

    HASH_DEL(srv->users, cl);
    snprintf(cl->nick, sizeof cl->nick, "%s", newnick);
    snprintf(cl->casefold_nick, sizeof cl->casefold_nick, "%s", cf);
    server_add_user(srv, cl);
    server_monitor_notify(srv, cl, 1);
    server_watch_notify(srv, cl, 1);
    netsync_user_nick(srv, cl);
}

void cmd_user(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (cl->registered) {
        client_reply(cl, N_ALREADYREGISTERED, NULL, 0, "You may not reregister");
        return;
    }
    /* Clients send the OS login name by default (irssi, WeeChat, HexChat), and "john.doe" or "Jöhn" are normal there:
     * keep the characters an ident may hold and truncate, as other ircds do, instead of refusing the connection. */
    char user[USERLEN];
    size_t ul = 0;
    for (const char *s = msg->params[0]; *s && ul + 1 < sizeof user && (int)ul < srv->cfg.security.max_nick_length; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || c == '_' || (c == '-' && ul > 0)) user[ul++] = (char)c;
    }
    user[ul] = '\0';
    if (!ul) snprintf(user, sizeof user, "user");
    const char *realname = msg->params[msg->nparams - 1];
    /* An identd that already answered is authoritative -- confirmed ident
     * overrides whatever the client itself claims in USER, same convention
     * every ircd follows. */
    if (!cl->ident_confirmed) snprintf(cl->user, sizeof cl->user, "%s", user);
    snprintf(cl->realname, sizeof cl->realname, "%s", realname);
    cl->got_user = 1;
    cmd_send_welcome_if_ready(srv, cl);
}

/* `tokens302` goes to clients that negotiated CAP 302 (cap values allowed), `tokens` to the rest (bare names). */
static void cap_notify_send(server_t *srv, const char *verb, const char *tokens302, const char *tokens, unsigned drop_bit) {
    for (client_t *c = srv->all_clients; c; c = c->all_next) {
        if (c->fd < 0 || c->quitting || !(c->caps & CAP_CAP_NOTIFY)) continue;
        char line[500];
        const char *p[] = {c->nick[0] ? c->nick : "*", verb};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "CAP", p, 2, c->cap_version >= 302 ? tokens302 : tokens);
        client_send(c, line);
        if (drop_bit) c->caps &= ~drop_bit; /* a removed cap is no longer in effect */
    }
}

/* SASL/REGISTER follow account services being reachable (cmd_services_tick), chathistory follows the config. */
void cmd_cap_notify_changes(server_t *srv, int old_accounts, int old_history) {
    int accounts = services_agent(srv) != NULL, history = srv->cfg.messages.history_size > 0;
    if (accounts != old_accounts) {
        if (accounts) {
            char t302[160];
            snprintf(t302, sizeof t302, "sasl=%s draft/account-registration=custom-account-name", sasl_mechs(srv));
            cap_notify_send(srv, "NEW", t302, "sasl draft/account-registration", 0);
        } else {
            cap_notify_send(srv, "DEL", "sasl draft/account-registration", "sasl draft/account-registration", 0);
        }
    }
    if (history != old_history) {
        if (history) cap_notify_send(srv, "NEW", "draft/chathistory", "draft/chathistory", 0);
        else cap_notify_send(srv, "DEL", "draft/chathistory", "draft/chathistory", CAP_CHATHISTORY);
    }
}

/* A trusted intermediary (WEBIRC gateway or PROXY-protocol load balancer)
 * says the connection's real address is `ip`. Rewrites ip/realhost/host,
 * drops the lookups already started against the intermediary's address, and
 * re-checks K-lines. Returns -1 (and queues a disconnect) on junk. */
int client_apply_real_address(server_t *srv, client_t *cl, const char *ip, const char *hostname) {
    struct in_addr a4; struct in6_addr a6;
    if (strlen(ip) >= sizeof cl->ip || (inet_pton(AF_INET, ip, &a4) != 1 && inet_pton(AF_INET6, ip, &a6) != 1)) {
        log_warn("net", "trusted intermediary sent an invalid IP '%s'", ip);
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Invalid forwarded address");
        cl->quitting = 1;
        return -1;
    }
    snprintf(cl->ip, sizeof cl->ip, "%s", ip);
    /* The intermediary vouches for the hostname; fall back to the IP if it's junk or just the IP again. */
    snprintf(cl->realhost, sizeof cl->realhost, "%s", (hostname && irc_valid_host(hostname) && strcmp(hostname, ip) != 0) ? hostname : ip);
    net_reset_host(srv, cl);
    if (net_assign_class(srv, cl) != 0) { /* the real address belongs to a full class */
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Too many connections in your class");
        cl->quitting = 1;
        return -1;
    }
    cl->webirc = 1; /* "address supplied by a trusted intermediary": also makes net.c ignore the DNSBL result for the old address */
    cl->rdns_pending = cl->ident_pending = cl->dnsbl_pending = 0;
    const char *kl = server_kline_match(srv, cl->ip, NULL, cl->realhost, 0);
    if (kl) {
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "%s", kl);
        cl->quitting = 1;
        return -1;
    }
    return 0;
}

/* WEBIRC <password> <gateway> <hostname> <ip> [:flags] -- a trusted web
 * gateway (matched by source IP *and* password, see [[webirc]]) tells us the
 * real client's address. Only valid before registration. */
void cmd_webirc(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (cl->registered || cl->webirc || cl->got_user) return;
    const cfg_webirc_t *match = NULL;
    for (int i = 0; i < srv->cfg.n_webirc && !match; i++) {
        const cfg_webirc_t *w = &srv->cfg.webirc[i];
        int host_ok = 0;
        for (int j = 0; j < w->n_hosts; j++) if (irc_glob_match(w->hosts[j], cl->ip)) { host_ok = 1; break; }
        if (host_ok && crypto_secure_streq(msg->params[0], w->password)) match = w;
    }
    if (!match) {
        log_warn("webirc", "rejected WEBIRC from %s (no matching [[webirc]] host+password)", cl->ip);
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "WEBIRC: not authorized");
        cl->quitting = 1;
        return;
    }
    if (client_apply_real_address(srv, cl, msg->params[3], msg->params[2]) == 0)
        log_info("webirc", "gateway %s: client is %s (%s)", match->name[0] ? match->name : "?", cl->ip, cl->realhost);
}

/* Mirrors commands._CAP_ATTRS -- every cap this server can grant via CAP
 * REQ/LS, besides "sasl" (config-gated separately, see cmd_cap below). */
static const struct { const char *name; unsigned int bit; } CAP_ATTRS[] = {
    {"away-notify", CAP_AWAY_NOTIFY},
    {"multi-prefix", CAP_MULTI_PREFIX},
    {"userhost-in-names", CAP_USERHOST_IN_NAMES},
    {"setname", CAP_SETNAME},
    {"chghost", CAP_CHGHOST},
    {"account-notify", CAP_ACCOUNT_NOTIFY},
    {"extended-join", CAP_EXTENDED_JOIN},
    {"echo-message", CAP_ECHO_MESSAGE},
    {"message-tags", CAP_MESSAGE_TAGS},
    {"server-time", CAP_SERVER_TIME},
    {"account-tag", CAP_ACCOUNT_TAG},
    {"invite-notify", CAP_INVITE_NOTIFY},
    {"standard-replies", CAP_STANDARD_REPLIES},
    {"cap-notify", CAP_CAP_NOTIFY},
    {"batch", CAP_BATCH},
    {"labeled-response", CAP_LABELED_RESPONSE},
    {"draft/no-implicit-names", CAP_NO_IMPLICIT_NAMES},
    {"draft/pre-away", CAP_PRE_AWAY},
    {"extended-monitor", CAP_EXTENDED_MONITOR},
    {"draft/channel-rename", CAP_CHANNEL_RENAME},
    {"draft/multiline", CAP_MULTILINE},
    {"draft/read-marker", CAP_READ_MARKER},
    {"draft/chathistory", CAP_CHATHISTORY},
};
#define N_CAP_ATTRS (int)(sizeof CAP_ATTRS / sizeof CAP_ATTRS[0])

#define MAX_CAP_TOKENS 40
#define CAP_TOKEN_LEN 96

/* The tokens a CAP LS shows `cl`. Values ("sasl=PLAIN", sts=...) and `sts`
 * itself are only sent to clients that asked for version 302 -- an older
 * client must see bare names. "sasl" (if config-gated on) carries its
 * mechanism list as a value, like upstream's `f"{c}=PLAIN" if c == "sasl"`. */
static int supported_cap_tokens(server_t *srv, client_t *cl, char tok[][CAP_TOKEN_LEN]) {
    int n = 0, v302 = cl->cap_version >= 302;
    for (int i = 0; i < N_CAP_ATTRS && n < MAX_CAP_TOKENS; i++) {
        if (CAP_ATTRS[i].bit == CAP_CHATHISTORY && srv->cfg.messages.history_size <= 0) continue; /* history off */
        if (CAP_ATTRS[i].bit == CAP_MULTILINE && v302) snprintf(tok[n++], CAP_TOKEN_LEN, "draft/multiline=max-bytes=%d,max-lines=%d", 4096, 24);
        else snprintf(tok[n++], CAP_TOKEN_LEN, "%s", CAP_ATTRS[i].name);
    }
    if (services_agent(srv) && n + 2 <= MAX_CAP_TOKENS) { /* accounts live in services: offered while they are reachable */
        if (v302) snprintf(tok[n++], CAP_TOKEN_LEN, "sasl=%s", sasl_mechs(srv));
        else snprintf(tok[n++], CAP_TOKEN_LEN, "sasl");
        /* custom-account-name: the account needn't match the nick; no before-connect (REGISTER needs a registered connection) */
        snprintf(tok[n++], CAP_TOKEN_LEN, "%s", v302 ? "draft/account-registration=custom-account-name" : "draft/account-registration");
    }
    /* IRCv3 STS: a plaintext connection is told to switch to the TLS port
     * and pin that for sts_duration seconds; an already-TLS connection just
     * gets the duration (no port= -- it has nothing to redirect to). */
    if (v302 && srv->cfg.tls.enabled && srv->cfg.tls.sts_duration > 0 && n < MAX_CAP_TOKENS) {
        if (cl->umodes & UMODE_Z) snprintf(tok[n++], CAP_TOKEN_LEN, "sts=duration=%d", srv->cfg.tls.sts_duration);
        else snprintf(tok[n++], CAP_TOKEN_LEN, "sts=port=%d,duration=%d", srv->cfg.tls.port, srv->cfg.tls.sts_duration);
    }
    return n;
}

/* Sends "CAP <nick> <sub> [*] :tokens", splitting across lines so none can
 * overflow 512 bytes; every line but the last carries the "*" continuation
 * marker (IRCv3 multi-line LS/LIST). */
static void send_cap_lines(server_t *srv, client_t *cl, const char *sub, char tok[][CAP_TOKEN_LEN], int n) {
    const char *target = cl->nick[0] ? cl->nick : "*";
    int i = 0;
    do {
        char caps[420];
        caps[0] = '\0';
        size_t len = 0;
        while (i < n) {
            size_t tl = strlen(tok[i]);
            if (len && len + 1 + tl >= sizeof caps) break;
            if (len) caps[len++] = ' ';
            memcpy(caps + len, tok[i], tl);
            len += tl;
            caps[len] = '\0';
            i++;
        }
        char line[600];
        const char *p3[] = {target, sub, "*"};
        const char *p2[] = {target, sub};
        int more = i < n;
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "CAP", more ? p3 : p2, more ? 3 : 2, caps);
        client_send(cl, line);
    } while (i < n);
}

void cmd_cap(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *sub = msg->params[0];
    const char *target = cl->nick[0] ? cl->nick : "*";

    if (strcasecmp(sub, "LS") == 0 || strcasecmp(sub, "LIST") == 0) {
        cl->cap_negotiating = 1;
        char tok[MAX_CAP_TOKENS][CAP_TOKEN_LEN];
        int n = 0;
        if (strcasecmp(sub, "LS") == 0) {
            if (msg->nparams > 1 && atoi(msg->params[1]) >= 302) {
                if (cl->cap_version < 302) cl->cap_version = atoi(msg->params[1]);
                cl->caps |= CAP_CAP_NOTIFY; /* 302 implicitly enables cap-notify */
            }
            n = supported_cap_tokens(srv, cl, tok);
        } else {
            for (int i = 0; i < N_CAP_ATTRS && n < MAX_CAP_TOKENS; i++)
                if (cl->caps & CAP_ATTRS[i].bit) snprintf(tok[n++], CAP_TOKEN_LEN, "%s", CAP_ATTRS[i].name);
        }
        send_cap_lines(srv, cl, strcasecmp(sub, "LS") == 0 ? "LS" : "LIST", tok, n);
    } else if (strcasecmp(sub, "REQ") == 0) {
        /* All-or-nothing (IRCv3): ACK only if every requested token (minus
         * an optional leading '-') names a cap we grant. */
        const char *requested = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "";
        /* Up to a whole line: gamja/Kiwi/Halloy request everything they know in one REQ, which is ~360 bytes here. */
        int ok = requested[0] != '\0' && strlen(requested) < 512; /* longer would be truncated yet ACKed in full */
        if (!cl->registered) cl->cap_negotiating = 1; /* IRCv3: a REQ also holds registration until CAP END */
        char buf[512];
        snprintf(buf, sizeof buf, "%s", requested);
        if (ok) {
            char probe[512];
            snprintf(probe, sizeof probe, "%s", requested);
            char *save = NULL;
            for (char *tok = strtok_r(probe, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
                const char *name = tok[0] == '-' ? tok + 1 : tok;
                int known = ((strcasecmp(name, "sasl") == 0 || strcasecmp(name, "draft/account-registration") == 0) &&
                             services_agent(srv) != NULL);
                for (int i = 0; !known && i < N_CAP_ATTRS; i++)
                    if (strcasecmp(name, CAP_ATTRS[i].name) == 0 && !(CAP_ATTRS[i].bit == CAP_CHATHISTORY && srv->cfg.messages.history_size <= 0)) known = 1;
                if (!known) { ok = 0; break; }
            }
        }
        if (ok) {
            char *save = NULL;
            for (char *tok = strtok_r(buf, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
                int grant = tok[0] != '-';
                const char *name = grant ? tok : tok + 1;
                for (int i = 0; i < N_CAP_ATTRS; i++) {
                    if (strcasecmp(name, CAP_ATTRS[i].name) != 0) continue;
                    if (grant) cl->caps |= CAP_ATTRS[i].bit; else cl->caps &= ~CAP_ATTRS[i].bit;
                }
            }
        }
        char line[700];
        const char *p[] = {target, ok ? "ACK" : "NAK"};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "CAP", p, 2, requested);
        client_send(cl, line);
    } else if (strcasecmp(sub, "END") == 0) {
        cl->cap_negotiating = 0;
        cmd_send_welcome_if_ready(srv, cl);
    }
    /* CAP NEW/DEL/ACK from a client are meaningless server-side; ignored. */
}

void cmd_ping(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *token = msg->nparams > 0 ? msg->params[msg->nparams - 1] : srv->cfg.server.name;
    char line[400];
    const char *p[] = {srv->cfg.server.name};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "PONG", p, 1, token);
    client_send(cl, line);
    cl->last_activity = time(NULL);
}

void cmd_pong(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)srv; (void)msg;
    cl->ping_sent = 0;
    cl->last_activity = time(NULL);
}

void cmd_quit(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *reason = msg->nparams > 0 ? msg->params[msg->nparams - 1] : "Client Quit";
    int spammy = spam_check_text(srv, cl, SPAM_T_QUIT, reason);
    if (cl->quitting) return; /* a spam rule already disconnected them with its own reason */
    if (spammy) reason = "Client Quit";
    snprintf(cl->quit_reason, sizeof cl->quit_reason, "Quit: %s", reason);
    cl->quitting = 1;
}

/* Hex-encodes the SHA-256 fingerprint of `cl`'s TLS client certificate into `out` (>= 65 bytes). -1 if this isn't a TLS
 * connection or no certificate was presented ([tls] request_client_cert = true is needed for that). Set on the client at
 * registration (cl->certfp) and handed to services, which back SASL EXTERNAL and NickServ CERT with it. */
int client_cert_fingerprint(client_t *cl, char *out, size_t outsz) {
    return crypto_peer_fingerprint(cl->ssl, out, outsz);
}

/* Per-IP failed-login throttle, applied before anything is relayed to services (they keep their own too), so a flood of
 * guesses from one address stops here instead of crossing the network. Fixed slots, oldest evicted. */
#define AUTH_FAIL_SLOTS  256
#define AUTH_FAIL_MAX    5
#define AUTH_FAIL_WINDOW 60
typedef struct { char ip[64]; time_t window_start; int count; } auth_fail_track_t;
static auth_fail_track_t g_auth_fail_tracks[AUTH_FAIL_SLOTS];

static int auth_fail_throttled(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < AUTH_FAIL_SLOTS; i++) {
        auth_fail_track_t *t = &g_auth_fail_tracks[i];
        if (strcmp(t->ip, ip) != 0) continue;
        return now - t->window_start <= AUTH_FAIL_WINDOW && t->count >= AUTH_FAIL_MAX;
    }
    return 0;
}

static void auth_fail_record(const char *ip) {
    time_t now = time(NULL);
    int slot = -1, oldest_i = 0;
    time_t oldest = now + 1;
    for (int i = 0; i < AUTH_FAIL_SLOTS; i++) {
        if (strcmp(g_auth_fail_tracks[i].ip, ip) == 0) { slot = i; break; }
        time_t ws = g_auth_fail_tracks[i].window_start;
        if (!g_auth_fail_tracks[i].ip[0]) { oldest_i = i; oldest = 0; }
        else if (ws < oldest) { oldest = ws; oldest_i = i; }
    }
    if (slot < 0) slot = oldest_i;
    auth_fail_track_t *t = &g_auth_fail_tracks[slot];
    if (strcmp(t->ip, ip) != 0 || now - t->window_start > AUTH_FAIL_WINDOW) {
        snprintf(t->ip, sizeof t->ip, "%s", ip);
        t->window_start = now;
        t->count = 0;
    }
    t->count++;
}

/* --- account services (the services daemon's NickServ) ------------------------------------------------------------
 * Accounts, SASL and REGISTER all live in services; this server only relays. Lines for services go to the NickServ
 * pseudo-client -- over its link if it is ours, else through netsync toward the server it sits on. Their answers come
 * back through svc_command (from the services link or relayed). A connection is named by its client id
 * "<sid>.<conn_id>" (it may not have a UID yet), which also tells a relaying server where to deliver the answer. */

client_t *services_agent(server_t *srv) {
    client_t *a = server_find_user(srv, "NickServ");
    return a && a->is_service ? a : NULL;
}

static void client_id(server_t *srv, const client_t *cl, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.%llu", srv->self_srv->sid, (unsigned long long)cl->conn_id);
}

static void to_services(server_t *srv, const char *line) {
    client_t *a = services_agent(srv);
    if (!a) return;
    if (a->link_conn) link_forward_line(a->link_conn, line);
    else netsync_svcrelay(srv, a->uid, line);
}

static const char *sasl_mechs(server_t *srv) {
    /* EXTERNAL only works if the TLS listener asks for client certificates */
    return srv->cfg.tls.enabled && srv->cfg.tls.request_client_cert ? "PLAIN,SCRAM-SHA-256,EXTERNAL" : "PLAIN,SCRAM-SHA-256";
}

#define SASL_TIMEOUT 20 /* services that don't answer by then: 904 */

static void sasl_end(client_t *cl) {
    cl->sasl_mech[0] = '\0';
    cl->sasl_started = 0;
}

static void sasl_start(server_t *srv, client_t *cl, const char *mech) {
    char cid[40], line[300];
    client_id(srv, cl, cid, sizeof cid);
    snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "%s", mech);
    cl->sasl_started = time(NULL);
    char fp[72];
    if (!cl->certfp[0] && client_cert_fingerprint(cl, fp, sizeof fp) == 0) snprintf(cl->certfp, sizeof cl->certfp, "%s", fp);
    irc_build(line, sizeof line, NULL, 0, NULL, "SVCSASL",
              (const char *[]){cid, "S", mech, cl->certfp[0] ? cl->certfp : "*", cl->ip}, 5, NULL);
    to_services(srv, line);
}

static void sasl_data(server_t *srv, client_t *cl, const char *kind, const char *data) {
    char cid[40], line[600];
    client_id(srv, cl, cid, sizeof cid);
    irc_build(line, sizeof line, NULL, 0, NULL, "SVCSASL", (const char *[]){cid, kind, data}, 3, NULL);
    to_services(srv, line);
}

/* SASL: the mechanism exchange runs in services; this relays each AUTHENTICATE and turns the outcome into numerics.
 * Deliberately no multi-line (400-byte chunk) continuation -- none of PLAIN/SCRAM/EXTERNAL needs it in practice. */
void cmd_authenticate(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *token = msg->params[0];
    if (!cl->sasl_mech[0]) {
        if (cl->account[0]) { client_reply(cl, N_SASLALREADY, NULL, 0, "You have already authenticated using SASL"); return; }
        int known = strcasecmp(token, "PLAIN") == 0 || strcasecmp(token, "SCRAM-SHA-256") == 0 || strcasecmp(token, "EXTERNAL") == 0;
        if (!services_agent(srv) || auth_fail_throttled(cl->ip)) { client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed"); return; }
        if (!known) {
            const char *p[] = {sasl_mechs(srv)}; /* 908 first: tells a client that guessed wrong what exists */
            client_reply(cl, N_SASLMECHS, p, 1, "are available SASL mechanisms");
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        char mech[16];
        snprintf(mech, sizeof mech, "%s", token);
        for (char *c = mech; *c; c++) *c = (char)toupper((unsigned char)*c);
        cl->auth_style = AUTH_STYLE_LEGACY;
        sasl_start(srv, cl, mech);
        char line[64];
        irc_build(line, sizeof line, NULL, 0, NULL, "AUTHENTICATE", (const char *[]){"+"}, 1, NULL);
        client_send(cl, line);
        return;
    }
    if (strcmp(token, "*") == 0) {
        sasl_data(srv, cl, "D", "A");
        sasl_end(cl);
        client_reply(cl, N_SASLABORTED, NULL, 0, "SASL authentication aborted");
        return;
    }
    if (strlen(token) > 400) {
        sasl_data(srv, cl, "D", "A");
        sasl_end(cl);
        client_reply(cl, N_SASLTOOLONG, NULL, 0, "SASL message too long");
        return;
    }
    sasl_data(srv, cl, "C", token);
}

/* PASS doubles as an account login for clients without SASL (mIRC, bouncers): "PASS account:password", or "PASS password"
 * for the account named like the nick. Tried at welcome time as a PLAIN exchange with services; registration waits for
 * it the way it waits for an in-flight SASL login. */
void cmd_pass(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)srv;
    if (cl->registered || msg->nparams < 1) return;
    client_auth_set(cl, AUTHTMP_PASS, msg->params[msg->nparams - 1]);
}

int cmd_pass_login(server_t *srv, client_t *cl) {
    if (!client_auth_get(cl, AUTHTMP_PASS)[0]) return 0;
    char pass[256];
    snprintf(pass, sizeof pass, "%s", client_auth_get(cl, AUTHTMP_PASS));
    client_auth_clear(cl, AUTHTMP_PASS);
    if (cl->account[0] || cl->sasl_mech[0]) { OPENSSL_cleanse(pass, sizeof pass); return 0; } /* SASL already did it */
    if (!services_agent(srv) || auth_fail_throttled(cl->ip)) {
        OPENSSL_cleanse(pass, sizeof pass);
        notice_self(srv, cl, "PASS login unavailable right now (account services offline, or too many attempts) -- continuing unidentified");
        return 0;
    }
    char *colon = strchr(pass, ':');
    const char *account = colon ? pass : cl->nick, *password = colon ? colon + 1 : pass;
    if (colon) *colon = '\0';
    unsigned char blob[400];
    int bl = snprintf((char *)blob, sizeof blob, "%s%c%s%c%s", account, 0, account, 0, password);
    char b64[600];
    int ok = bl > 0 && (size_t)bl < sizeof blob && (size_t)bl < 290 && account[0] && password[0];
    if (ok) EVP_EncodeBlock((unsigned char *)b64, blob, bl);
    OPENSSL_cleanse(pass, sizeof pass);
    OPENSSL_cleanse(blob, sizeof blob);
    if (!ok) { notice_self(srv, cl, "PASS login refused (malformed) -- continuing unidentified"); return 0; }
    cl->auth_style = AUTH_STYLE_PASS;
    cl->auth_pending = 1;
    sasl_start(srv, cl, "PLAIN");
    sasl_data(srv, cl, "C", b64);
    OPENSSL_cleanse(b64, sizeof b64);
    return 1;
}

/* IRCv3 standard-replies FAIL for clients that negotiated it, a NOTICE otherwise. */
static void send_fail(server_t *srv, client_t *cl, const char *cmd, const char *code, const char *desc) {
    if (cl->caps & CAP_STANDARD_REPLIES) {
        char line[500];
        const char *p[] = {cmd, code};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 2, desc);
        client_send(cl, line);
    } else {
        notice_self(srv, cl, desc);
    }
}

/* A few registrations per connection, spaced out (services also throttle per IP and cap the total). */
#define REGISTER_MAX_PER_CONNECTION 3
#define REGISTER_COOLDOWN 10

/*   REGISTER <account> <password>               legacy form
 *   REGISTER <account|*> <email|*> <password>   draft/account-registration ("*" account = the current nick) */
void cmd_register(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *account = msg->params[0], *password = msg->params[1], *email = "*";
    int style = AUTH_STYLE_LEGACY;
    if (msg->nparams >= 3) {
        style = AUTH_STYLE_DRAFT;
        email = msg->params[1];
        password = msg->params[2];
        if (strcmp(account, "*") == 0) account = cl->nick;
    }
    if (!password[0]) { err_need_more_params(cl, "REGISTER"); return; }
    if (!services_agent(srv)) { send_fail(srv, cl, "REGISTER", "TEMPORARILY_UNAVAILABLE", "Account services are unavailable right now -- try again later"); return; }
    if (cl->account[0]) { send_fail(srv, cl, "REGISTER", "ALREADY_AUTHENTICATED", "You are already logged in to an account"); return; }
    time_t now = time(NULL);
    if (cl->register_attempts >= REGISTER_MAX_PER_CONNECTION) {
        send_fail(srv, cl, "REGISTER", "REG_UNAVAILABLE", "Too many registrations on this connection -- reconnect to register another account");
        return;
    }
    if (cl->register_last && difftime(now, cl->register_last) < REGISTER_COOLDOWN) {
        send_fail(srv, cl, "REGISTER", "TEMPORARILY_UNAVAILABLE", "You are registering too fast -- wait a few seconds and try again");
        return;
    }
    cl->register_last = now;
    cl->register_attempts++;
    cl->auth_style = style;
    char cid[40], line[600];
    client_id(srv, cl, cid, sizeof cid);
    irc_build(line, sizeof line, NULL, 0, NULL, "SVCREGISTER", (const char *[]){cid, cl->ip, account, email}, 4, password);
    to_services(srv, line);
}

/* CERT ADD|DEL|INFO -- kept as shorthand for /msg NickServ CERT ..., which owns certificate fingerprints now. */
void cmd_cert(server_t *srv, client_t *cl, irc_message_t *msg) {
    char text[64];
    snprintf(text, sizeof text, "CERT %s", msg->params[0]);
    irc_message_t m;
    memset(&m, 0, sizeof m);
    m.command = "PRIVMSG";
    m.params[0] = "NickServ";
    m.params[1] = text;
    m.nparams = 2;
    cmd_privmsg(srv, cl, &m);
}

/* A SASL session finished (services said D S|F, or it timed out). */
static void sasl_finish(server_t *srv, client_t *cl, int success) {
    int style = cl->auth_style;
    sasl_end(cl);
    cl->auth_style = AUTH_STYLE_LEGACY;
    if (!success) auth_fail_record(cl->ip);
    if (style == AUTH_STYLE_PASS) {
        cl->auth_pending = 0;
        if (success) { char m[200]; snprintf(m, sizeof m, "You are now identified for %s", cl->account); notice_self(srv, cl, m); }
        else notice_self(srv, cl, "PASS login failed: invalid account or password -- continuing unidentified");
        cmd_send_welcome_if_ready(srv, cl);
        return;
    }
    if (success) client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
    else client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
}

/* Once a second (net.c): services that never answered, and the SASL cap following services coming and going. */
void cmd_services_tick(server_t *srv, time_t now) {
    for (client_t *cl = srv->all_clients; cl; cl = cl->all_next)
        if (cl->fd >= 0 && cl->sasl_mech[0] && cl->sasl_started && now - cl->sasl_started > SASL_TIMEOUT) {
            log_warn("sasl", "account services did not answer for %s -- failing the login", cl->ip);
            sasl_finish(srv, cl, 0);
        }
    int online = services_agent(srv) != NULL;
    if (online != srv->services_online) {
        srv->services_online = online;
        cmd_cap_notify_changes(srv, !online, srv->cfg.messages.history_size > 0);
        log_info("services", "account services %s", online ? "available" : "unavailable -- SASL/REGISTER off until they return");
    }
}

/* The local client a services line is about: "<sid>.<conn_id>" (a connection, maybe not registered yet), a UID, or a
 * nick. NULL if it isn't ours; *route then names where to relay it ("" = nowhere: unknown). */
static client_t *svc_target(server_t *srv, const char *id, char *route, size_t routesz) {
    route[0] = '\0';
    const char *dot = strchr(id, '.');
    if (dot) {
        if ((size_t)(dot - id) == strlen(srv->self_srv->sid) && strncmp(id, srv->self_srv->sid, (size_t)(dot - id)) == 0)
            return server_find_by_conn_id(srv, strtoull(dot + 1, NULL, 10));
        snprintf(route, routesz, "%s", id); /* another server's connection: relayed by its SID */
        return NULL;
    }
    client_t *c = strlen(id) == UID_LEN ? netsync_find_uid(srv, id) : NULL;
    if (!c) c = server_find_user(srv, id);
    if (!c || c->is_service) return NULL;
    if (c->remote) { snprintf(route, routesz, "%s", c->uid); return NULL; }
    return c;
}

/* A line from services (its own link, or relayed by netsync): SVSLOGIN, SVSNICK, KILL, SVCSASL, SVCREGRESULT. Every one
 * names its target first; one that isn't ours is passed on toward its server. `svc` is the bot it came from (NULL when
 * relayed -- the sending services' server already checked that). */
void svc_command(server_t *srv, client_t *svc, irc_message_t *msg) {
    if (msg->nparams < 1) return;
    char route[64];
    client_t *cl = svc_target(srv, msg->params[0], route, sizeof route);
    if (!cl) {
        if (!route[0]) return;
        char line[900];
        irc_build(line, sizeof line, NULL, 0, NULL, msg->command, (const char **)msg->params, msg->nparams - 1,
                  msg->params[msg->nparams - 1]);
        netsync_svcrelay(srv, route, line);
        return;
    }
    const char *c = msg->command;
    if (!strcmp(c, "SVSLOGIN") && msg->nparams >= 2) {
        if (strcmp(msg->params[1], "*") == 0) { if (cl->account[0]) server_logout(srv, cl); return; }
        cl->acct_created = msg->nparams > 2 ? atol(msg->params[2]) : 0;
        snprintf(cl->acct_created_for, sizeof cl->acct_created_for, "%s", msg->params[1]);
        server_login(srv, cl, msg->params[1]);
        log_info("sasl", "%s logged in as %s", cl->nick[0] ? cl->nick : cl->ip, msg->params[1]);
    } else if (!strcmp(c, "SVSNICK") && msg->nparams >= 2) {
        if (cl->registered) force_nick_change(srv, cl, msg->params[1]);
    } else if (!strcmp(c, "KILL")) {
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Killed (%s (%s))", svc ? svc->nick : "NickServ",
                 msg->nparams > 1 ? msg->params[msg->nparams - 1] : "");
        cl->quitting = 1;
    } else if (!strcmp(c, "SVCSASL") && msg->nparams >= 3) {
        if (!cl->sasl_mech[0]) return; /* aborted or timed out meanwhile */
        if (!strcmp(msg->params[1], "C")) {
            char line[600];
            irc_build(line, sizeof line, NULL, 0, NULL, "AUTHENTICATE", (const char *[]){msg->params[2]}, 1, NULL);
            client_send(cl, line);
        } else if (!strcmp(msg->params[1], "D")) sasl_finish(srv, cl, !strcmp(msg->params[2], "S"));
    } else if (!strcmp(c, "SVCREGRESULT") && msg->nparams >= 5) {
        int style = cl->auth_style;
        cl->auth_style = AUTH_STYLE_LEGACY;
        const char *text = msg->params[msg->nparams - 1];
        if (strcmp(msg->params[1], "SUCCESS") != 0) { send_fail(srv, cl, "REGISTER", msg->params[2], text); return; }
        if (style == AUTH_STYLE_DRAFT) {
            char line[500];
            irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "REGISTER", (const char *[]){"SUCCESS", msg->params[3]}, 2, text);
            client_send(cl, line);
        } else notice_self(srv, cl, text);
        log_info("main", "%s registered account %s", cl->nick, msg->params[3]);
    }
}
