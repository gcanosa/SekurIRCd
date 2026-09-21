/* Registration: NICK, USER, PASS, CAP, PING, PONG, QUIT, AUTHENTICATE, REGISTER.
 * Ported (reduced scope) from commands.py's cmd_nick/cmd_user/cmd_cap/
 * cmd_authenticate/cmd_register. */
#include "accounts.h"
#include "cmd.h"
#include "log.h"
#include "worker.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

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

    if (strcmp(cl->casefold_nick, cf) == 0) {
        /* case-only change: no collision, no re-key needed by identity,
         * but the hash key IS the casefold form, so still safe to skip. */
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
};
#define N_CAP_ATTRS (int)(sizeof CAP_ATTRS / sizeof CAP_ATTRS[0])

/* Builds the space-separated "CAP LS" token list into `out`. "sasl" (if
 * config-gated on) carries its mechanism list as a value, like upstream's
 * `f"{c}=PLAIN" if c == "sasl" else c`. */
static void render_supported_caps(server_t *srv, char *out, size_t outsz) {
    out[0] = '\0';
    for (int i = 0; i < N_CAP_ATTRS; i++) {
        if (out[0]) strncat(out, " ", outsz - strlen(out) - 1);
        strncat(out, CAP_ATTRS[i].name, outsz - strlen(out) - 1);
    }
    if (srv->cfg.accounts.enabled) {
        if (out[0]) strncat(out, " ", outsz - strlen(out) - 1);
        /* EXTERNAL only ever succeeds if the TLS listener actually asks
         * clients for a certificate -- otherwise cl->ssl never has a peer
         * cert to match, so don't advertise a mechanism that can't work. */
        int external_possible = srv->cfg.tls.enabled && srv->cfg.tls.request_client_cert;
        strncat(out, external_possible ? "sasl=PLAIN,EXTERNAL" : "sasl=PLAIN", outsz - strlen(out) - 1);
        /* No before-connect (REGISTER needs a registered connection) and no
         * email-required (email is accepted but not stored/verified);
         * custom-account-name because the account needn't match the nick. */
        strncat(out, " draft/account-registration=custom-account-name", outsz - strlen(out) - 1);
    }
}

void cmd_cap(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *sub = msg->params[0];
    const char *target = cl->nick[0] ? cl->nick : "*";

    if (strcasecmp(sub, "LS") == 0 || strcasecmp(sub, "LIST") == 0) {
        cl->cap_negotiating = 1;
        char caps[512];
        if (strcasecmp(sub, "LS") == 0) render_supported_caps(srv, caps, sizeof caps);
        else caps[0] = '\0'; /* CAP LIST: caps already granted -- rendered below */
        if (strcasecmp(sub, "LIST") == 0) {
            for (int i = 0; i < N_CAP_ATTRS; i++) {
                if (!(cl->caps & CAP_ATTRS[i].bit)) continue;
                if (caps[0]) strncat(caps, " ", sizeof caps - strlen(caps) - 1);
                strncat(caps, CAP_ATTRS[i].name, sizeof caps - strlen(caps) - 1);
            }
        }
        char line[600];
        const char *p[] = {target, strcasecmp(sub, "LS") == 0 ? "LS" : "LIST"};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "CAP", p, 2, caps);
        client_send(cl, line);
    } else if (strcasecmp(sub, "REQ") == 0) {
        /* All-or-nothing (IRCv3): ACK only if every requested token (minus
         * an optional leading '-') names a cap we grant. */
        const char *requested = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "";
        int ok = requested[0] != '\0';
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
                    if (strcasecmp(name, CAP_ATTRS[i].name) == 0) known = 1;
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

/* Starts a password check for `authcid` on a worker (scrypt is ~30ms, so it
 * never runs on the event loop; net.c applies the result via
 * cmd_finish_auth). Shared by SASL PLAIN and NickServ IDENTIFY. One in flight
 * per connection bounds the queue. 0 = submitted, -1 = refused (unknown
 * account, one already pending, or worker queue full) -- the caller words the
 * failure for its own protocol. */
static int start_plain_login(server_t *srv, client_t *cl, const char *authcid, const char *passwd, int style) {
    const char *hash = accounts_hash(&srv->accounts, authcid);
    if (!hash || cl->auth_pending) return -1;
    job_t j; memset(&j, 0, sizeof j);
    j.type = JOB_SASL;
    j.purpose = AUTH_SASL;
    j.conn_id = cl->conn_id;
    snprintf(j.secret, sizeof j.secret, "%s", passwd);
    snprintf(j.hash, sizeof j.hash, "%s", hash);
    snprintf(cl->pending_account, sizeof cl->pending_account, "%s", authcid);
    cl->auth_style = style;
    cl->auth_pending = 1;
    cl->auth_started = time(NULL);
    int rc = worker_submit(&j);
    OPENSSL_cleanse(j.secret, sizeof j.secret);
    if (rc != 0) { cl->auth_pending = 0; return -1; }
    return 0;
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
        if (!srv->cfg.accounts.enabled) {
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        if (!is_plain && !is_external) {
            /* 908 before 904: a bare "failed" gives a client that guessed the
             * wrong mechanism no way to discover which ones exist. */
            int external_possible = srv->cfg.tls.enabled && srv->cfg.tls.request_client_cert;
            const char *mechs[] = {external_possible ? "PLAIN,EXTERNAL" : "PLAIN"};
            client_reply(cl, N_SASLMECHS, mechs, 1, "are available SASL mechanisms");
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "%s", is_plain ? "PLAIN" : "EXTERNAL");
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
        client_reply(cl, N_SASLABORTED, NULL, 0, "SASL authentication aborted");
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
    cl->auth_style = style;
    cl->auth_pending = 1;
    cl->auth_started = time(NULL);
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
        if (strcmp(account, "*") == 0) account = cl->nick;
    }
    if (!password[0]) { err_need_more_params(cl, "REGISTER"); return; }
    start_register(srv, cl, account, password, style);
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

    if (!srv->cfg.accounts.enabled) {
        ns_say(srv, cl, "Accounts are not enabled on this server");
    } else if (cmd && strcasecmp(cmd, "REGISTER") == 0) {
        /* REGISTER <password> [email] -- email ignored, see cmd_register. */
        if (!a) ns_say(srv, cl, "Syntax: REGISTER <password> [email]");
        else start_register(srv, cl, cl->nick, a, AUTH_STYLE_NICKSERV);
    } else if (cmd && (strcasecmp(cmd, "IDENTIFY") == 0 || strcasecmp(cmd, "ID") == 0)) {
        /* IDENTIFY [account] <password> */
        const char *account = b ? a : cl->nick;
        const char *password = b ? b : a;
        if (!password) ns_say(srv, cl, "Syntax: IDENTIFY [account] <password>");
        else if (cl->account[0]) ns_say(srv, cl, "You are already identified");
        else if (start_plain_login(srv, cl, account, password, AUTH_STYLE_NICKSERV) != 0)
            ns_say(srv, cl, "Invalid account or password");
    } else {
        ns_say(srv, cl, "Commands: REGISTER <password> [email], IDENTIFY [account] <password>");
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
            server_login(srv, cl, account);
            if (style == AUTH_STYLE_NICKSERV) {
                char m[200];
                snprintf(m, sizeof m, "You are now identified for %s", account);
                ns_say(srv, cl, m);
            } else {
                client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
            }
            log_info("sasl", "%s authenticated as %s", cl->nick, account);
        } else if (style == AUTH_STYLE_NICKSERV) {
            ns_say(srv, cl, "Invalid account or password");
        } else {
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
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
}
