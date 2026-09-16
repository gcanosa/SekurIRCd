/* Registration: NICK, USER, PASS, CAP, PING, PONG, QUIT, AUTHENTICATE, REGISTER.
 * Ported (reduced scope) from commands.py's cmd_nick/cmd_user/cmd_cap/
 * cmd_authenticate/cmd_register. */
#include "accounts.h"
#include "cmd.h"
#include "log.h"

#include <openssl/evp.h>

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

    client_t *seen[256];
    int n_seen = 0;
    client_send(cl, line);
    seen[n_seen++] = cl;
    for (chan_node_t *n = cl->channels; n; n = n->next) {
        member_t *m, *tmp;
        HASH_ITER(hh, n->chan->members, m, tmp) {
            int dup = 0;
            for (int i = 0; i < n_seen; i++) if (seen[i] == m->client) { dup = 1; break; }
            if (dup) continue;
            client_send(m->client, line);
            if (n_seen < 256) seen[n_seen++] = m->client;
        }
    }

    HASH_DEL(srv->users, cl);
    snprintf(cl->nick, sizeof cl->nick, "%s", newnick);
    snprintf(cl->casefold_nick, sizeof cl->casefold_nick, "%s", cf);
    server_add_user(srv, cl);
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
        strncat(out, "sasl=PLAIN", outsz - strlen(out) - 1);
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
                int known = (strcasecmp(name, "sasl") == 0 && srv->cfg.accounts.enabled);
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
    (void)srv;
    const char *reason = msg->nparams > 0 ? msg->params[msg->nparams - 1] : "Client Quit";
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

/* SASL PLAIN only -- the universal minimum every SASL-capable client already
 * supports (ported from commands.cmd_authenticate). Deliberately doesn't
 * support the multi-line ("400-byte chunks, a final short/empty line") form
 * of the spec -- a PLAIN blob never needs it in practice. */
void cmd_authenticate(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *token = msg->params[0];

    if (!cl->sasl_mech[0]) {
        if (strcasecmp(token, "PLAIN") != 0 || !srv->cfg.accounts.enabled) {
            client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
            return;
        }
        snprintf(cl->sasl_mech, sizeof cl->sasl_mech, "PLAIN");
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

    if (strcmp(mech, "PLAIN") == 0 && accounts_verify(&srv->accounts, authcid, passwd)) {
        snprintf(cl->account, sizeof cl->account, "%s", authcid);
        cl->umodes |= UMODE_R;
        char prefix[320];
        client_prefix(cl, prefix, sizeof prefix);
        char loggedin_msg[220];
        snprintf(loggedin_msg, sizeof loggedin_msg, "You are now logged in as %s", authcid);
        const char *p2[] = {prefix, authcid};
        client_reply(cl, N_LOGGEDIN, p2, 2, loggedin_msg);
        client_reply(cl, N_SASLSUCCESS, NULL, 0, "SASL authentication successful");
        log_info("sasl", "%s authenticated as %s", cl->nick, authcid);
    } else {
        client_reply(cl, N_SASLFAIL, NULL, 0, "SASL authentication failed");
    }
}

/* Self-service account registration (``/REGISTER <account> <password>``) --
 * not RFC/IRCv3, matching this daemon's "accounts live in core, no NickServ
 * required" design (see accounts.h). Ported from commands.cmd_register,
 * simplified to a plain NOTICE for every outcome (no standard-replies/FAIL
 * cap in this port yet). */
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

void cmd_register(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (!srv->cfg.accounts.enabled) {
        send_fail(srv, cl, "REGISTER", "REG_UNAVAILABLE", "Account registration is not enabled on this server");
        return;
    }
    const char *account = msg->params[0];
    const char *password = msg->params[1];
    if (!password[0]) { err_need_more_params(cl, "REGISTER"); return; }
    if (!irc_valid_user(account, 30)) {
        char m[200];
        snprintf(m, sizeof m, "%s is not a valid account name", account);
        send_fail(srv, cl, "REGISTER", "BAD_ACCOUNT_NAME", m);
        return;
    }
    if (accounts_exists(&srv->accounts, account)) {
        char m[200];
        snprintf(m, sizeof m, "Account %s already exists", account);
        send_fail(srv, cl, "REGISTER", "ACCOUNT_EXISTS", m);
        return;
    }
    accounts_register(&srv->accounts, account, password);
    snprintf(cl->account, sizeof cl->account, "%s", account);
    cl->umodes |= UMODE_R;
    char m[200];
    snprintf(m, sizeof m, "Account %s registered -- you are now logged in as it", account);
    notice_self(srv, cl, m);
    log_info("main", "%s registered account %s", cl->nick, account);
}
