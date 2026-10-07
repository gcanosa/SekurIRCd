/* Registration: NICK, USER, PASS, CAP, PING, PONG, QUIT, AUTHENTICATE, REGISTER.
 * Ported (reduced scope) from commands.py's cmd_nick/cmd_user/cmd_cap/
 * cmd_authenticate/cmd_register. */
#include "accounts.h"
#include "cmd.h"
#include "crypto.h"
#include "log.h"
#include "net.h"
#include "scram.h"
#include "worker.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static int valid_email(const char *e);
static void ns_begin_email(server_t *srv, client_t *cl, const char *email);

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
    nick_enforce_check(srv, cl);
}

void cmd_user(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (cl->registered) {
        client_reply(cl, N_ALREADYREGISTERED, NULL, 0, "You may not reregister");
        return;
    }
    const char *user = msg->params[0];
    const char *realname = msg->params[msg->nparams - 1];
    if (!irc_valid_user(user, srv->cfg.security.max_nick_length)) {
        client_send(cl, "NOTICE * :Invalid username");
        cl->quitting = 1;
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "Invalid username");
        return;
    }
    /* An identd that already answered is authoritative -- confirmed ident
     * overrides whatever the client itself claims in USER, same convention
     * every ircd follows. */
    if (!cl->ident_confirmed) snprintf(cl->user, sizeof cl->user, "%s", user);
    snprintf(cl->realname, sizeof cl->realname, "%s", realname);
    cl->got_user = 1;
    cmd_send_welcome_if_ready(srv, cl);
}

void cmd_pass(server_t *srv, client_t *cl, irc_message_t *msg) {
    /* v1.0.1 has no server-wide connect password (only [[operators]] logins)
     * -- accepted and ignored, same as most ircds do for a client that sends
     * one unprompted. */
    (void)srv; (void)cl; (void)msg;
}

static void cap_notify_send(server_t *srv, const char *verb, const char *tokens, unsigned drop_bit) {
    for (client_t *c = srv->all_clients; c; c = c->all_next) {
        if (c->fd < 0 || c->quitting || !(c->caps & CAP_CAP_NOTIFY)) continue;
        char line[500];
        const char *p[] = {c->nick[0] ? c->nick : "*", verb};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "CAP", p, 2, tokens);
        client_send(c, line);
        if (drop_bit) c->caps &= ~drop_bit; /* a removed cap is no longer in effect */
    }
}

void cmd_cap_notify_changes(server_t *srv, int old_accounts, int old_history) {
    int accounts = srv->cfg.accounts.enabled, history = srv->cfg.messages.history_size > 0;
    if (accounts != old_accounts) {
        if (accounts) cap_notify_send(srv, "NEW", "sasl=PLAIN,SCRAM-SHA-256 draft/account-registration=custom-account-name", 0);
        else cap_notify_send(srv, "DEL", "sasl draft/account-registration", 0);
    }
    if (history != old_history) {
        if (history) cap_notify_send(srv, "NEW", "draft/chathistory", 0);
        else cap_notify_send(srv, "DEL", "draft/chathistory", CAP_CHATHISTORY);
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
    if (srv->cfg.accounts.enabled && n + 2 <= MAX_CAP_TOKENS) {
        /* EXTERNAL only ever succeeds if the TLS listener actually asks
         * clients for a certificate -- otherwise cl->ssl never has a peer
         * cert to match, so don't advertise a mechanism that can't work. */
        int external_possible = srv->cfg.tls.enabled && srv->cfg.tls.request_client_cert;
        if (v302) snprintf(tok[n++], CAP_TOKEN_LEN, "%s", external_possible ? "sasl=PLAIN,SCRAM-SHA-256,EXTERNAL" : "sasl=PLAIN,SCRAM-SHA-256");
        else snprintf(tok[n++], CAP_TOKEN_LEN, "sasl");
        /* No before-connect (REGISTER needs a registered connection) and no
         * email-required (email is accepted but not stored/verified);
         * custom-account-name because the account needn't match the nick. */
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
        int ok = requested[0] != '\0' && strlen(requested) < 256; /* longer would be truncated yet ACKed in full */
        if (!cl->registered) cl->cap_negotiating = 1; /* IRCv3: a REQ also holds registration until CAP END */
        char buf[256];
        snprintf(buf, sizeof buf, "%s", requested);
        if (ok) {
            char probe[256];
            snprintf(probe, sizeof probe, "%s", requested);
            char *save = NULL;
            for (char *tok = strtok_r(probe, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
                const char *name = tok[0] == '-' ? tok + 1 : tok;
                int known = ((strcasecmp(name, "sasl") == 0 || strcasecmp(name, "draft/account-registration") == 0) &&
                             srv->cfg.accounts.enabled);
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
        char line[512];
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

/* base64-decode `in` (must be a full 4-char-aligned blob, padding included)
 * into `out` (capacity `outcap`), stripping '=' padding from the reported
 * length. Uses OpenSSL's EVP_DecodeBlock rather than hand-rolling base64. */
static int b64_decode(const char *in, unsigned char *out, size_t outcap, int *outlen) {
    size_t inlen = strlen(in);
    if (inlen == 0 || inlen % 4 != 0) return -1;
    if (inlen / 4 * 3 > outcap) return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)inlen);
    if (n < 0) return -1;
    int pad = 0;
    if (in[inlen - 1] == '=') pad++;
    if (inlen >= 2 && in[inlen - 2] == '=') pad++;
    *outlen = n - pad;
    return 0;
}

/* Hex-encodes the SHA-256 fingerprint of `cl`'s TLS client certificate into
 * `out` (>= 65 bytes: 32 bytes * 2 hex chars + NUL). Returns -1 if this isn't
 * a TLS connection or the client didn't present a certificate -- SASL
 * EXTERNAL needs [tls] request_client_cert = true for the latter to ever be
 * possible. Backs both SASL EXTERNAL (cmd_authenticate) and /CERT ADD. */
static int peer_cert_fingerprint(client_t *cl, char *out, size_t outsz) {
    if (!cl->ssl) return -1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509 *cert = SSL_get1_peer_certificate(cl->ssl);
#else
    X509 *cert = SSL_get_peer_certificate(cl->ssl);
#endif
    if (!cert) return -1;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int digest_ok = X509_digest(cert, EVP_sha256(), digest, &dlen);
    X509_free(cert);
    /* Without this check a failed digest left dlen == 0, the hex loop below
     * never ran, and `out` went back to the caller uninitialized -- an
     * unterminated stack buffer used as a credential. */
    if (digest_ok != 1 || dlen == 0) return -1;
    if (outsz < (size_t)dlen * 2 + 1) return -1;
    for (unsigned int i = 0; i < dlen; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
    return 0;
}

/* Per-IP failed-login throttle for SASL/NickServ IDENTIFY -- both go through
 * start_plain_login below, before *and* after registration. Same fixed-slot
 * eviction shape as net.c's connect-flood table: a full table evicts the
 * oldest entry rather than tracking every IP forever. Without this, an
 * unlimited number of connections (or nick changes on one) can each grind
 * through the account/password space at whatever rate the worker pool keeps
 * up with -- there was no failure counter at all, only "one attempt in
 * flight per connection". */
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

/* A precomputed scrypt hash for a password nobody knows, used in place of a
 * real account's hash when `authcid` doesn't exist -- so an unknown account
 * still costs a full ~30ms verify instead of failing instantly, closing the
 * timing side-channel that let a client tell "no such account" apart from
 * "wrong password" by how fast the reply came back. Computed once, lazily
 * (itself a ~30ms scrypt hash, off the hot path). */
static const char *auth_decoy_hash(void) {
    static char buf[160];
    static int ready;
    if (!ready) { crypto_hash_password("sekurircd-timing-decoy, not a real password", buf, sizeof buf); ready = 1; }
    return buf;
}

/* Starts a password check for `authcid` on a worker (scrypt is ~30ms, so it
 * never runs on the event loop; net.c applies the result via
 * cmd_finish_auth). Shared by SASL PLAIN and NickServ IDENTIFY. One in flight
 * per connection bounds the queue. 0 = submitted, -1 = refused (too many
 * recent failures from this IP, one already pending, or worker queue full)
 * -- the caller words the failure for its own protocol. */
static int start_plain_login(server_t *srv, client_t *cl, const char *authcid, const char *passwd, int style) {
    if (cl->auth_pending || auth_fail_throttled(cl->ip)) return -1;
    const char *owner_acct = accounts_owner_of_nick(&srv->accounts, authcid);
    if (owner_acct) authcid = owner_acct; /* logging in as a grouped nick means its account */
    const char *hash = accounts_hash(&srv->accounts, authcid);
    int unknown = !hash;
    if (unknown) hash = auth_decoy_hash();
    job_t j; memset(&j, 0, sizeof j);
    j.type = JOB_SASL;
    j.purpose = AUTH_SASL;
    j.conn_id = cl->conn_id;
    snprintf(j.secret, sizeof j.secret, "%s", passwd);
    snprintf(j.hash, sizeof j.hash, "%s", hash);
    /* Never record an account name the store doesn't have -- cmd_finish_auth
     * would otherwise log in as it in the (cryptographically negligible, but
     * not worth relying on) case the decoy hash ever matched. */
    snprintf(cl->pending_account, sizeof cl->pending_account, "%s", unknown ? "" : authcid);
    /* An account made before SCRAM existed has no verifier; the password is in hand now, so derive one (stored only if this login succeeds). */
    cl->pending_scram[0] = '\0';
    if (!unknown && !accounts_scram(&srv->accounts, authcid)) {
        scram_verifier_t sv;
        if (scram_make_verifier(passwd, &sv) == 0) scram_verifier_to_string(&sv, cl->pending_scram, sizeof cl->pending_scram);
    }
    cl->auth_style = style;
    cl->auth_pending = 1;
    cl->auth_started = time(NULL);
    j.gen = ++cl->auth_gen;
    int rc = worker_submit(&j);
    OPENSSL_cleanse(j.secret, sizeof j.secret);
    if (rc != 0) { cl->auth_pending = 0; return -1; }
    return 0;
}

/* --- SASL SCRAM-SHA-256 ------------------------------------------------------
 * Three client messages: client-first, client-final, then an empty "+" after
 * the server-final. The password never reaches the server (and no scrypt job is
 * needed): the stored verifier is enough to check the proof. */
struct scram_sess {
    char account[64];
    char first_bare[300];   /* client-first-message-bare */
    char server_first[300];
    scram_verifier_t v;
    int step;               /* 0 = expecting client-first, 1 = client-final, 2 = expecting the final "+" */
};

static void authenticate_send(client_t *cl, const char *data) {
    char line[500];
    const char *p[] = {data};
    irc_build(line, sizeof line, NULL, 0, NULL, "AUTHENTICATE", p, 1, NULL);
    client_send(cl, line);
}

static void scram_fail(client_t *cl) {
    auth_fail_record(cl->ip);
    free(cl->scram);
    cl->scram = NULL;
    cl->sasl_mech[0] = '\0';
    client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
}

/* Pulls "k=value" out of a comma-separated SCRAM attribute list. */
static int scram_attr(const char *msg, char key, char *out, size_t outsz) {
    for (const char *p = msg; *p; ) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len >= 2 && p[0] == key && p[1] == '=') {
            if (len - 2 >= outsz) return 0;
            memcpy(out, p + 2, len - 2);
            out[len - 2] = '\0';
            return 1;
        }
        p = end ? end + 1 : p + len;
    }
    return 0;
}

static void scram_step(server_t *srv, client_t *cl, const char *token) {
    struct scram_sess *s = cl->scram;
    if (!s) { /* first client message arrives with a fresh session */
        if (auth_fail_throttled(cl->ip)) { scram_fail(cl); return; }
        s = cl->scram = calloc(1, sizeof *s);
        if (!s) { cl->sasl_mech[0] = '\0'; return; }
    }
    if (strlen(token) > 400) { scram_fail(cl); return; }
    unsigned char raw[320];
    char msg[320];
    if (strcmp(token, "+") == 0) { raw[0] = '\0'; msg[0] = '\0'; }
    else {
        int n = scram_b64_decode(token, raw, sizeof raw - 1);
        if (n < 0) { scram_fail(cl); return; }
        memcpy(msg, raw, (size_t)n);
        msg[n] = '\0';
    }

    if (s->step == 0) { /* client-first: "n,,n=<user>,r=<cnonce>" */
        if (strncmp(msg, "n,,", 3) != 0 && strncmp(msg, "y,,", 3) != 0) { scram_fail(cl); return; } /* no channel binding */
        const char *bare = msg + 3;
        char user[64], cnonce[96];
        if (!scram_attr(bare, 'n', user, sizeof user) || !scram_attr(bare, 'r', cnonce, sizeof cnonce) || strchr(user, '=')) { scram_fail(cl); return; }
        const char *stored = accounts_scram(&srv->accounts, user);
        if (!stored || scram_verifier_from_string(stored, &s->v) != 0) { scram_fail(cl); return; } /* unknown account, or no verifier yet (log in with PLAIN once) */
        snprintf(s->account, sizeof s->account, "%s", accounts_display_name(&srv->accounts, user));
        snprintf(s->first_bare, sizeof s->first_bare, "%s", bare);
        char snonce[24], saltb[64];
        crypto_random_hex(snonce, sizeof snonce, 11);
        scram_b64_encode(s->v.salt, (size_t)s->v.saltlen, saltb, sizeof saltb);
        snprintf(s->server_first, sizeof s->server_first, "r=%s%s,s=%s,i=%d", cnonce, snonce, saltb, s->v.iter);
        char out[500];
        if (scram_b64_encode((const unsigned char *)s->server_first, strlen(s->server_first), out, sizeof out) < 0) { scram_fail(cl); return; }
        s->step = 1;
        snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "SCRAM-SHA-256"); /* exchange continues */
        authenticate_send(cl, out);
        return;
    }
    if (s->step == 1) { /* client-final: "c=biws,r=<nonce>,p=<proof>" */
        char chan[16], nonce[200], proofb[64];
        if (!scram_attr(msg, 'c', chan, sizeof chan) || (strcmp(chan, "biws") != 0 && strcmp(chan, "eSws") != 0) ||
            !scram_attr(msg, 'r', nonce, sizeof nonce) || !scram_attr(msg, 'p', proofb, sizeof proofb)) { scram_fail(cl); return; }
        char expect_nonce[200];
        if (!scram_attr(s->server_first, 'r', expect_nonce, sizeof expect_nonce) || strcmp(nonce, expect_nonce) != 0) { scram_fail(cl); return; }
        const char *pp = strstr(msg, ",p=");
        unsigned char proof[64];
        if (!pp || scram_b64_decode(proofb, proof, sizeof proof) != SCRAM_KEYLEN) { scram_fail(cl); return; }
        char authmsg[900];
        snprintf(authmsg, sizeof authmsg, "%s,%s,%.*s", s->first_bare, s->server_first, (int)(pp - msg), msg);
        unsigned char sig[SCRAM_KEYLEN];
        if (!scram_check_proof(&s->v, authmsg, proof, sig)) { scram_fail(cl); return; }
        char sigb[64], final[100], out[200];
        scram_b64_encode(sig, SCRAM_KEYLEN, sigb, sizeof sigb);
        snprintf(final, sizeof final, "v=%s", sigb);
        scram_b64_encode((const unsigned char *)final, strlen(final), out, sizeof out);
        s->step = 2;
        snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "SCRAM-SHA-256");
        authenticate_send(cl, out);
        return;
    }
    /* step 2: the client's empty "+" acknowledging the server signature */
    char account[64];
    snprintf(account, sizeof account, "%s", s->account);
    free(cl->scram);
    cl->scram = NULL;
    server_login(srv, cl, account);
    client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
    log_info("sasl", "%s authenticated as %s via SCRAM-SHA-256", cl->nick, account);
}

/* SASL PLAIN and EXTERNAL -- the universal minimum every SASL-capable client
 * already supports, plus certificate-based login for one that presented a
 * TLS client cert bound to an account via /CERT ADD. Ported (PLAIN) from
 * commands.cmd_authenticate. Deliberately doesn't support the multi-line
 * ("400-byte chunks, a final short/empty line") form of the spec -- neither
 * mechanism's blob ever needs it in practice. */
void cmd_authenticate(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *token = msg->params[0];

    if (!cl->sasl_mech[0]) {
        if (cl->account[0]) {
            client_reply(cl, N_SASLALREADY, NULL, 0, "You have already authenticated using SASL");
            return;
        }
        int is_plain = strcasecmp(token, "PLAIN") == 0;
        int is_external = strcasecmp(token, "EXTERNAL") == 0;
        int is_scram = strcasecmp(token, "SCRAM-SHA-256") == 0;
        if (!srv->cfg.accounts.enabled) {
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        if (!is_plain && !is_external && !is_scram) {
            /* 908 before 904: a bare "failed" gives a client that guessed the
             * wrong mechanism no way to discover which ones exist. */
            int external_possible = srv->cfg.tls.enabled && srv->cfg.tls.request_client_cert;
            const char *mechs[] = {external_possible ? "PLAIN,SCRAM-SHA-256,EXTERNAL" : "PLAIN,SCRAM-SHA-256"};
            client_reply(cl, N_SASLMECHS, mechs, 1, "are available SASL mechanisms");
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "%s", is_plain ? "PLAIN" : is_scram ? "SCRAM-SHA-256" : "EXTERNAL");
        free(cl->scram); /* a fresh attempt starts a fresh exchange */
        cl->scram = NULL;
        const char *p[] = {"+"};
        char line[64];
        irc_build(line, sizeof line, NULL, 0, NULL, "AUTHENTICATE", p, 1, NULL);
        client_send(cl, line);
        return;
    }

    char mech[16];
    snprintf(mech, sizeof mech, "%s", cl->sasl_mech);
    cl->sasl_mech[0] = '\0';

    if (strcmp(token, "*") == 0) {
        free(cl->scram);
        cl->scram = NULL;
        client_reply(cl, N_SASLABORTED, NULL, 0, "SASL authentication aborted");
        return;
    }

    if (strcmp(mech, "SCRAM-SHA-256") == 0) {
        scram_step(srv, cl, token);
        return;
    }

    if (strcmp(mech, "EXTERNAL") == 0) {
        /* Identity comes entirely from the TLS certificate already on this
         * connection -- the continuation blob is just an (ignored) optional
         * authzid, same as PLAIN's. */
        char fp[65];
        const char *account;
        if (peer_cert_fingerprint(cl, fp, sizeof fp) != 0 ||
            !(account = accounts_find_by_fingerprint(&srv->accounts, fp))) {
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        server_login(srv, cl, account);
        client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
        log_info("sasl", "%s authenticated as %s via EXTERNAL", cl->nick, account);
        return;
    }

    /* 400 bytes is the IRCv3 AUTHENTICATE chunk size; this server doesn't
     * implement the multi-line continuation form, so anything longer can be
     * named as such instead of reported as a generic failure. */
    if (strlen(token) > 400) {
        client_reply(cl, N_SASLTOOLONG, NULL, 0, "SASL message too long");
        return;
    }
    unsigned char blob[600];
    int blen = 0;
    if (b64_decode(token, blob, sizeof blob, &blen) != 0 || blen < 0) {
        client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
        return;
    }
    /* authzid \0 authcid \0 passwd -- authzid is ignored, same as upstream. */
    unsigned char *end = blob + blen;
    unsigned char *nul1 = memchr(blob, '\0', (size_t)(end - blob));
    unsigned char *authcid_start = nul1 ? nul1 + 1 : NULL;
    unsigned char *nul2 = authcid_start ? memchr(authcid_start, '\0', (size_t)(end - authcid_start)) : NULL;
    if (!nul1 || !nul2) {
        client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
        return;
    }
    size_t authcid_len = (size_t)(nul2 - authcid_start);
    unsigned char *pw_start = nul2 + 1;
    size_t pw_len = (size_t)(end - pw_start);
    if (authcid_len == 0 || authcid_len >= NICKLEN || pw_len == 0 || pw_len >= 256) {
        client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
        return;
    }
    char authcid[NICKLEN], passwd[256];
    memcpy(authcid, authcid_start, authcid_len);
    authcid[authcid_len] = '\0';
    memcpy(passwd, pw_start, pw_len);
    passwd[pw_len] = '\0';

    int rc = strcmp(mech, "PLAIN") == 0 ? start_plain_login(srv, cl, authcid, passwd, AUTH_STYLE_LEGACY) : -1;
    OPENSSL_cleanse(passwd, sizeof passwd);
    if (rc != 0) client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
}

/* IRCv3 standard-replies: a structured FAIL for a command with no natural
 * legacy-numeric equivalent, only for clients that negotiated the cap --
 * everyone else gets the existing plain NOTICE fallback. */
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

/* Self-service account registration is unauthenticated account creation, so
 * it gets the same kind of throttle chanserv's password checks do: a few per
 * connection, spaced out, on top of [accounts] max_accounts for the store as
 * a whole. */
#define REGISTER_MAX_PER_CONNECTION 3
#define REGISTER_COOLDOWN 10

/* NickServ-style reply: a NOTICE from a virtual "NickServ" -- there's no real
 * services pseudo-client behind it (accounts live in core, see accounts.h). */
static void ns_say(server_t *srv, client_t *cl, const char *text) {
    char line[500];
    char prefix[160];
    snprintf(prefix, sizeof prefix, "NickServ!NickServ@%s", srv->cfg.server.name);
    const char *p[] = {cl->nick[0] ? cl->nick : "*"};
    irc_build(line, sizeof line, NULL, 0, prefix, "NOTICE", p, 1, text);
    client_send(cl, line);
}

/* Failure reply in whichever dialect the request came in. */
static void reg_fail(server_t *srv, client_t *cl, int style, const char *code, const char *desc) {
    if (style == AUTH_STYLE_NICKSERV) ns_say(srv, cl, desc);
    else send_fail(srv, cl, "REGISTER", code, desc);
}

/* Validates and starts an account registration; the hash runs on a worker and
 * cmd_finish_auth completes it. Shared by /REGISTER (both forms) and
 * NickServ REGISTER. */
static void start_register(server_t *srv, client_t *cl, const char *account, const char *password, int style) {
    if (!srv->cfg.accounts.enabled) {
        reg_fail(srv, cl, style, "REG_UNAVAILABLE", "Account registration is not enabled on this server");
        return;
    }
    if (cl->account[0]) {
        reg_fail(srv, cl, style, "ALREADY_AUTHENTICATED", "You are already logged in to an account");
        return;
    }
    if (!irc_valid_user(account, 30)) {
        char m[200];
        snprintf(m, sizeof m, "%s is not a valid account name", account);
        reg_fail(srv, cl, style, "BAD_ACCOUNT_NAME", m);
        return;
    }
    if (accounts_exists(&srv->accounts, account)) {
        char m[200];
        snprintf(m, sizeof m, "Account %s already exists", account);
        reg_fail(srv, cl, style, "ACCOUNT_EXISTS", m);
        return;
    }
    if (strlen(password) >= sizeof ((job_t *)0)->secret) {
        reg_fail(srv, cl, style, "BAD_PASSWORD", "Password is too long");
        return;
    }
    if (cl->auth_pending) {
        reg_fail(srv, cl, style, "TEMPORARILY_UNAVAILABLE", "Another login/registration is still in progress");
        return;
    }
    /* auth_pending only bounds concurrency, not the total: without these,
     * one connection could create accounts in a loop, each one rewriting the
     * whole accounts file. */
    if (srv->cfg.accounts.max_accounts > 0 &&
        accounts_count(&srv->accounts) >= srv->cfg.accounts.max_accounts) {
        reg_fail(srv, cl, style, "REG_UNAVAILABLE",
                 "This server has reached its account limit -- ask a server operator");
        return;
    }
    time_t now = time(NULL);
    if (cl->register_attempts >= REGISTER_MAX_PER_CONNECTION) {
        reg_fail(srv, cl, style, "REG_UNAVAILABLE",
                 "Too many registrations on this connection -- reconnect to register another account");
        return;
    }
    if (cl->register_last && difftime(now, cl->register_last) < REGISTER_COOLDOWN) {
        reg_fail(srv, cl, style, "TEMPORARILY_UNAVAILABLE",
                 "You are registering too fast -- wait a few seconds and try again");
        return;
    }
    cl->register_last = now;
    cl->register_attempts++;
    /* Hash on a worker (scrypt, ~30ms); net.c finishes via cmd_finish_auth. */
    job_t j; memset(&j, 0, sizeof j);
    j.type = JOB_HASH;
    j.purpose = AUTH_REGISTER;
    j.conn_id = cl->conn_id;
    snprintf(j.secret, sizeof j.secret, "%s", password);
    snprintf(cl->pending_account, sizeof cl->pending_account, "%s", account);
    cl->pending_scram[0] = '\0';
    { scram_verifier_t sv; if (scram_make_verifier(password, &sv) == 0) scram_verifier_to_string(&sv, cl->pending_scram, sizeof cl->pending_scram); }
    cl->auth_style = style;
    cl->auth_pending = 1;
    cl->auth_started = time(NULL);
    j.gen = ++cl->auth_gen;
    if (worker_submit(&j) != 0) {
        cl->auth_pending = 0;
        reg_fail(srv, cl, style, "TEMPORARILY_UNAVAILABLE", "Server is busy -- try again shortly");
    }
    OPENSSL_cleanse(j.secret, sizeof j.secret);
}

/* Self-service account registration -- not RFC/IRCv3-final, matching this
 * daemon's "accounts live in core" design (see accounts.h). Two forms:
 *   REGISTER <account> <password>               legacy, this daemon's own
 *   REGISTER <account|*> <email|*> <password>   draft/account-registration
 * where "*" for the account means the current nick. The email is accepted
 * but neither stored nor verified. */
void cmd_register(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *account = msg->params[0];
    const char *password = msg->params[1];
    int style = AUTH_STYLE_LEGACY;
    if (msg->nparams >= 3) {
        style = AUTH_STYLE_DRAFT;
        password = msg->params[2];
        snprintf(cl->pending_email, sizeof cl->pending_email, "%s", strcmp(msg->params[1], "*") != 0 && valid_email(msg->params[1]) ? msg->params[1] : "");
        if (strcmp(account, "*") == 0) account = cl->nick;
    }
    if (!password[0]) { err_need_more_params(cl, "REGISTER"); return; }
    start_register(srv, cl, account, password, style);
}

/* --- email, verification codes ------------------------------------------------ */

static int valid_email(const char *e) {
    size_t n = strlen(e);
    if (n < 3 || n > 120 || e[0] == '-' || e[0] == '@') return 0;
    int at = 0;
    for (const char *p = e; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '@') { if (++at > 1) return 0; continue; }
        if (!(isalnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-')) return 0; /* never a shell metacharacter, space or '/' */
    }
    return at == 1 && e[n - 1] != '@';
}

/* Runs `cmd addr code account network` fully detached (double fork, so no zombie and nothing to wait on), no shell. */
static void spawn_email_command(const char *cmd, const char *addr, const char *code, const char *account, const char *network) {
    pid_t p1 = fork();
    if (p1 < 0) return;
    if (p1 == 0) {
        if (fork() == 0) {
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }
            execl(cmd, cmd, addr, code, account, network, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
    waitpid(p1, NULL, 0);
}

/* The account's owner has asked to use `email`: send a code (if email_command is set) or just store it. */
static void ns_begin_email(server_t *srv, client_t *cl, const char *email) {
    if (!valid_email(email)) { ns_say(srv, cl, "That does not look like a valid email address"); return; }
    if (!srv->cfg.accounts.email_command[0]) {
        accounts_set_email(&srv->accounts, cl->account, email, 0);
        ns_say(srv, cl, "Email saved (this server does not verify addresses)");
        return;
    }
    char code[12];
    crypto_random_hex(code, sizeof code, 4);
    accounts_set_pending_email(&srv->accounts, cl->account, email, code, (long)time(NULL) + 3600);
    spawn_email_command(srv->cfg.accounts.email_command, email, code, cl->account, srv->cfg.server.network);
    ns_say(srv, cl, "A verification code was sent -- finish with /msg NickServ VERIFY <code> within an hour");
}

/* Disconnect-free logout of every session on `account` (used when it is dropped). */
static void logout_all_sessions(server_t *srv, const char *account) {
    for (client_t *c = srv->all_clients; c; c = c->all_next)
        if (c->fd >= 0 && c->account[0] && strcasecmp(c->account, account) == 0) server_logout(srv, c);
}

/* NickServ SET PASSWORD / DROP need scrypt (worker thread): this is the second half, called from net.c. */
void cmd_finish_account_op(server_t *srv, client_t *cl, int purpose, int success, const char *text) {
    cl->auth_pending = 0;
    switch ((auth_purpose_t)purpose) {
    case AUTH_PASSWD_VERIFY: {
        if (!success) {
            auth_fail_record(cl->ip);
            ns_say(srv, cl, "Current password incorrect");
            OPENSSL_cleanse(cl->pending_newpw, sizeof cl->pending_newpw);
            return;
        }
        job_t j; memset(&j, 0, sizeof j);
        j.type = JOB_HASH;
        j.purpose = AUTH_PASSWD_HASH;
        j.conn_id = cl->conn_id;
        snprintf(j.secret, sizeof j.secret, "%s", cl->pending_newpw);
        OPENSSL_cleanse(cl->pending_newpw, sizeof cl->pending_newpw);
        cl->auth_pending = 1;
        cl->auth_started = time(NULL);
        j.gen = ++cl->auth_gen;
        int rc = worker_submit(&j);
        OPENSSL_cleanse(j.secret, sizeof j.secret);
        if (rc != 0) { cl->auth_pending = 0; ns_say(srv, cl, "Server busy -- try again"); }
        return;
    }
    case AUTH_PASSWD_HASH:
        if (!success || !cl->account[0]) { ns_say(srv, cl, "Could not change the password -- try again"); return; }
        accounts_set_hash(&srv->accounts, cl->account, text);
        if (cl->pending_scram[0]) accounts_set_scram(&srv->accounts, cl->account, cl->pending_scram);
        cl->pending_scram[0] = '\0';
        ns_say(srv, cl, "Password changed");
        log_info("nickserv", "%s changed the password of %s", cl->nick, cl->account);
        return;
    case AUTH_DROP_VERIFY: {
        if (!success) { auth_fail_record(cl->ip); ns_say(srv, cl, "Password incorrect -- account NOT dropped"); return; }
        char account[64];
        snprintf(account, sizeof account, "%s", cl->account);
        logout_all_sessions(srv, account);
        accounts_drop(&srv->accounts, account);
        ns_say(srv, cl, "Your account has been dropped");
        log_info("nickserv", "account %s dropped by %s", account, cl->nick);
        return;
    }
    default: return;
    }
}

/* Submits the scrypt verification of `password` against the logged-in account's stored hash. */
static int ns_verify_own_password(server_t *srv, client_t *cl, const char *password, auth_purpose_t purpose) {
    if (cl->auth_pending || auth_fail_throttled(cl->ip)) return -1;
    const char *hash = accounts_hash(&srv->accounts, cl->account);
    if (!hash) return -1;
    job_t j; memset(&j, 0, sizeof j);
    j.type = JOB_SASL;
    j.purpose = purpose;
    j.conn_id = cl->conn_id;
    snprintf(j.secret, sizeof j.secret, "%s", password);
    snprintf(j.hash, sizeof j.hash, "%s", hash);
    cl->auth_pending = 1;
    cl->auth_started = time(NULL);
    j.gen = ++cl->auth_gen;
    int rc = worker_submit(&j);
    OPENSSL_cleanse(j.secret, sizeof j.secret);
    if (rc != 0) { cl->auth_pending = 0; return -1; }
    return 0;
}

/* PRIVMSG to "NickServ" when no real user by that name exists (see
 * cmd_user.c send_msg). Maps the familiar commands onto the same account code
 * as /REGISTER and SASL: the account name is the current nick, as with Anope
 * and Atheme. */
void nickserv_message(server_t *srv, client_t *cl, const char *text) {
    char buf[420];
    snprintf(buf, sizeof buf, "%s", text);
    char *save = NULL;
    char *cmd = strtok_r(buf, " ", &save);
    char *a = cmd ? strtok_r(NULL, " ", &save) : NULL;
    char *b = cmd ? strtok_r(NULL, " ", &save) : NULL;
    char *c3 = cmd ? strtok_r(NULL, " ", &save) : NULL;

    if (!srv->cfg.accounts.enabled) {
        ns_say(srv, cl, "Accounts are not enabled on this server");
    } else if (cmd && strcasecmp(cmd, "REGISTER") == 0) {
        /* REGISTER <password> [email] */
        if (!a) ns_say(srv, cl, "Syntax: REGISTER <password> [email]");
        else {
            snprintf(cl->pending_email, sizeof cl->pending_email, "%s", b && valid_email(b) ? b : "");
            start_register(srv, cl, cl->nick, a, AUTH_STYLE_NICKSERV);
        }
    } else if (cmd && (strcasecmp(cmd, "IDENTIFY") == 0 || strcasecmp(cmd, "ID") == 0)) {
        /* IDENTIFY [account] <password> */
        const char *account = b ? a : cl->nick;
        const char *owner = accounts_owner_of_nick(&srv->accounts, account); /* a grouped nick identifies its account */
        if (owner) account = owner;
        const char *password = b ? b : a;
        if (!password) ns_say(srv, cl, "Syntax: IDENTIFY [account] <password>");
        else if (cl->account[0]) ns_say(srv, cl, "You are already identified");
        else if (start_plain_login(srv, cl, account, password, AUTH_STYLE_NICKSERV) != 0)
            ns_say(srv, cl, "Invalid account or password");
    } else if (cmd && strcasecmp(cmd, "GHOST") == 0) {
        /* GHOST <nick>: you must be identified as the account that owns <nick> (the account named
         * <nick>, or the same account as that session) -- then that session is disconnected. */
        client_t *t = a ? server_find_user(srv, a) : NULL;
        if (!a) ns_say(srv, cl, "Syntax: GHOST <nick>");
        else if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!t || !t->registered || t == cl) ns_say(srv, cl, "No such nick (or that is you)");
        else if (!(accounts_owner_of_nick(&srv->accounts, a) && strcasecmp(cl->account, accounts_owner_of_nick(&srv->accounts, a)) == 0) &&
                 strcasecmp(cl->account, t->account) != 0)
            ns_say(srv, cl, "You do not own that nickname");
        else {
            snprintf(t->quit_reason, sizeof t->quit_reason, "Killed (GHOST command used by %s)", cl->nick);
            t->quitting = 1;
            ns_say(srv, cl, "Ghost session disconnected");
            log_info("nickserv", "%s ghosted %s", cl->nick, a);
        }
    } else if (cmd && strcasecmp(cmd, "LOGOUT") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You are not identified");
        else server_logout(srv, cl);
    } else if (cmd && strcasecmp(cmd, "INFO") == 0) {
        const char *who = a ? accounts_owner_of_nick(&srv->accounts, a) : (cl->account[0] ? cl->account : NULL);
        if (!who) { ns_say(srv, cl, a ? "No such account" : "You are not identified -- INFO <account>"); }
        else {
            char m[300];
            snprintf(m, sizeof m, "Account %s, registered %ld", who, accounts_created_at(&srv->accounts, who));
            ns_say(srv, cl, m);
            int self = cl->account[0] && strcasecmp(cl->account, who) == 0;
            if (self) { /* the owner also sees their email and grouped nicks */
                const char *em = accounts_email(&srv->accounts, who);
                snprintf(m, sizeof m, "Email: %s%s", em ? em : "(none)", em ? (accounts_email_verified(&srv->accounts, who) ? " (verified)" : " (unverified)") : "");
                ns_say(srv, cl, m);
                int gn = accounts_group_count(&srv->accounts, who);
                if (gn) {
                    char list[250] = "";
                    for (int i = 0; i < gn; i++) { strncat(list, i ? ", " : "", sizeof list - strlen(list) - 1); strncat(list, accounts_group_nick(&srv->accounts, who, i), sizeof list - strlen(list) - 1); }
                    snprintf(m, sizeof m, "Grouped nicks: %s", list);
                    ns_say(srv, cl, m);
                }
            }
        }
    } else if (cmd && strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "PASSWORD") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!b || !c3) ns_say(srv, cl, "Syntax: SET PASSWORD <current> <new>");
        else if (strlen(c3) < 6 || strlen(c3) >= 200) ns_say(srv, cl, "The new password must be 6-199 characters");
        else {
            snprintf(cl->pending_newpw, sizeof cl->pending_newpw, "%s", c3);
            cl->pending_scram[0] = '\0';
            { scram_verifier_t sv; if (scram_make_verifier(c3, &sv) == 0) scram_verifier_to_string(&sv, cl->pending_scram, sizeof cl->pending_scram); }
            if (ns_verify_own_password(srv, cl, b, AUTH_PASSWD_VERIFY) != 0) {
                OPENSSL_cleanse(cl->pending_newpw, sizeof cl->pending_newpw);
                ns_say(srv, cl, "Could not start the password change -- try again shortly");
            }
        }
    } else if (cmd && strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "EMAIL") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!b) ns_say(srv, cl, "Syntax: SET EMAIL <address>");
        else ns_begin_email(srv, cl, b);
    } else if (cmd && strcasecmp(cmd, "VERIFY") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!a) ns_say(srv, cl, "Syntax: VERIFY <code>");
        else if (accounts_check_verify(&srv->accounts, cl->account, a)) ns_say(srv, cl, "Email verified");
        else ns_say(srv, cl, "That code is wrong or has expired");
    } else if (cmd && strcasecmp(cmd, "DROP") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!a) ns_say(srv, cl, "Syntax: DROP <password> -- permanently deletes your account");
        else if (ns_verify_own_password(srv, cl, a, AUTH_DROP_VERIFY) != 0) ns_say(srv, cl, "Could not start that -- try again shortly");
    } else if (cmd && strcasecmp(cmd, "GROUP") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (accounts_group_add(&srv->accounts, cl->account, cl->nick) != 0)
            ns_say(srv, cl, "That nick is already registered/grouped, or your group is full (10 nicks)");
        else { char m[200]; snprintf(m, sizeof m, "%s is now part of account %s", cl->nick, cl->account); ns_say(srv, cl, m); }
    } else if (cmd && strcasecmp(cmd, "UNGROUP") == 0) {
        if (!cl->account[0]) ns_say(srv, cl, "You must IDENTIFY first");
        else if (!a || accounts_group_del(&srv->accounts, cl->account, a) != 0) ns_say(srv, cl, "Syntax: UNGROUP <nick> (a nick in your group)");
        else ns_say(srv, cl, "Nick removed from your account");
    } else {
        ns_say(srv, cl, "Commands: REGISTER <password> [email], IDENTIFY [account] <password>, LOGOUT, INFO [account], "
                        "SET PASSWORD <old> <new>, SET EMAIL <address>, VERIFY <code>, GROUP, UNGROUP <nick>, GHOST <nick>, DROP <password>");
    }
    OPENSSL_cleanse(buf, sizeof buf);
}

/* ``/CERT ADD|DEL|INFO`` -- binds (or clears, or reports) the SASL EXTERNAL
 * certificate fingerprint on the caller's own account, taken from whatever
 * TLS client certificate this connection is currently presenting (see
 * peer_cert_fingerprint above; requires [tls] request_client_cert = true).
 * Not RFC/IRCv3 -- same "no NickServ required" self-service design as
 * /REGISTER. */
void cmd_cert(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *sub = msg->params[0];
    if (!srv->cfg.accounts.enabled) {
        send_fail(srv, cl, "CERT", "CERT_UNAVAILABLE", "Accounts are not enabled on this server");
        return;
    }
    if (!cl->account[0]) {
        send_fail(srv, cl, "CERT", "ACCOUNT_REQUIRED", "You must be logged in (SASL or /REGISTER) to manage a certificate fingerprint");
        return;
    }

    if (strcasecmp(sub, "ADD") == 0) {
        char fp[65];
        if (peer_cert_fingerprint(cl, fp, sizeof fp) != 0) {
            send_fail(srv, cl, "CERT", "CERT_REQUIRED", "Your connection isn't presenting a TLS client certificate");
            return;
        }
        accounts_set_fingerprint(&srv->accounts, cl->account, fp);
        char m[200];
        snprintf(m, sizeof m, "Certificate fingerprint %s bound to %s -- SASL EXTERNAL will now log this connection in", fp, cl->account);
        notice_self(srv, cl, m);
        log_info("sasl", "%s bound a certificate fingerprint to account %s", cl->nick, cl->account);
    } else if (strcasecmp(sub, "DEL") == 0) {
        accounts_set_fingerprint(&srv->accounts, cl->account, NULL);
        notice_self(srv, cl, "Certificate fingerprint removed -- SASL EXTERNAL is now disabled for this account");
    } else if (strcasecmp(sub, "INFO") == 0) {
        const char *fp = accounts_fingerprint(&srv->accounts, cl->account);
        if (fp) {
            char m[120];
            snprintf(m, sizeof m, "Certificate fingerprint on file: %s", fp);
            notice_self(srv, cl, m);
        } else {
            notice_self(srv, cl, "No certificate fingerprint is on file for this account");
        }
    } else {
        send_fail(srv, cl, "CERT", "UNKNOWN_SUBCOMMAND", "Syntax: CERT ADD|DEL|INFO");
    }
}

void cmd_finish_auth(server_t *srv, client_t *cl, int is_register, int success, const char *hash) {
    cl->auth_pending = 0;
    int style = cl->auth_style;
    cl->auth_style = AUTH_STYLE_LEGACY;
    const char *account = cl->pending_account;
    if (!is_register) {
        if (success) {
            account = accounts_display_name(&srv->accounts, account); /* stored case, not whatever was typed */
            if (cl->pending_scram[0] && !accounts_scram(&srv->accounts, account)) accounts_set_scram(&srv->accounts, account, cl->pending_scram);
            cl->pending_scram[0] = '\0';
            server_login(srv, cl, account);
            if (style == AUTH_STYLE_NICKSERV) {
                char m[200];
                snprintf(m, sizeof m, "You are now identified for %s", account);
                ns_say(srv, cl, m);
            } else {
                client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
            }
            log_info("sasl", "%s authenticated as %s", cl->nick, account);
        } else {
            auth_fail_record(cl->ip);
            if (style == AUTH_STYLE_NICKSERV) ns_say(srv, cl, "Invalid account or password");
            else client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
        }
        return;
    }
    if (!success) { reg_fail(srv, cl, style, "TEMPORARILY_UNAVAILABLE", "Internal error hashing password -- try again"); return; }
    if (accounts_exists(&srv->accounts, account)) { /* lost a race with another REGISTER */
        char m[200];
        snprintf(m, sizeof m, "Account %s already exists", account);
        reg_fail(srv, cl, style, "ACCOUNT_EXISTS", m);
        return;
    }
    accounts_register_hashed(&srv->accounts, account, hash);
    if (cl->pending_scram[0]) accounts_set_scram(&srv->accounts, account, cl->pending_scram);
    cl->pending_scram[0] = '\0';
    char reg_email[160];
    snprintf(reg_email, sizeof reg_email, "%s", cl->pending_email);
    cl->pending_email[0] = '\0';
    server_login(srv, cl, account);
    char m[200];
    snprintf(m, sizeof m, "Account %s registered -- you are now logged in as it", account);
    if (style == AUTH_STYLE_NICKSERV) {
        ns_say(srv, cl, m);
    } else if (style == AUTH_STYLE_DRAFT) {
        char line[500];
        const char *p[] = {"SUCCESS", account};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "REGISTER", p, 2, m);
        client_send(cl, line);
    } else {
        notice_self(srv, cl, m);
    }
    log_info("main", "%s registered account %s", cl->nick, account);
    if (reg_email[0]) ns_begin_email(srv, cl, reg_email);
}

/* --- nick ownership enforcement ([accounts] enforce_nicks) ------------------ */

/* Called when a registered client's nick has just been set (welcome, NICK): starts the identify countdown if the nick is a registered account. */
void nick_enforce_check(server_t *srv, client_t *cl) {
    cl->enforce_deadline = 0;
    if (!srv->cfg.accounts.enabled || !srv->cfg.accounts.enforce_nicks || cl->is_service || !cl->registered) return;
    const char *owner = accounts_owner_of_nick(&srv->accounts, cl->nick); /* the account named so, or whose group holds it */
    if (!owner) return;
    snprintf(cl->enforce_owner, sizeof cl->enforce_owner, "%s", owner);
    if (cl->account[0] && strcasecmp(cl->account, owner) == 0) return; /* already logged in as the owner */
    cl->enforce_deadline = time(NULL) + srv->cfg.accounts.enforce_grace;
    char m[300];
    snprintf(m, sizeof m, "This nickname is registered. Log in (SASL, or /msg NickServ IDENTIFY <password>) within %d seconds "
                          "or you will be renamed.", srv->cfg.accounts.enforce_grace);
    ns_say(srv, cl, m);
}

/* Once a second from net.c's tick: rename anyone whose grace ran out. */
void nick_enforce_tick(server_t *srv, time_t now) {
    for (client_t *cl = srv->all_clients; cl; cl = cl->all_next) {
        if (!cl->enforce_deadline || cl->quitting) continue;
        if (cl->account[0] && strcasecmp(cl->account, cl->enforce_owner) == 0) { cl->enforce_deadline = 0; continue; }
        if (now < cl->enforce_deadline) continue;
        cl->enforce_deadline = 0;
        char guest[NICKLEN];
        for (int tries = 0; tries < 20; tries++) {
            char rh[9];
            crypto_random_hex(rh, sizeof rh, 4);
            snprintf(guest, sizeof guest, "Guest%u", 10000 + (unsigned)(strtoul(rh, NULL, 16) % 90000));
            if (!server_find_user(srv, guest)) break;
        }
        ns_say(srv, cl, "You did not identify in time -- changing your nickname.");
        force_nick_change(srv, cl, guest);
    }
}
