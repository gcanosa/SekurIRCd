/* Messaging and lookups: PRIVMSG, NOTICE, WHOIS, WHO, WHOWAS, AWAY, SETNAME,
 * USERHOST, ISON, MONITOR, SILENCE, GLOB. Ported from commands.py. */
#include "cmd.h"
#include "history.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* True if `cl` is silencing `from` (any of cl->silence masks hits from's
 * nick!user@host) -- matches commands.py's Client.is_silencing. */
int client_is_silencing(client_t *cl, client_t *from) {
    for (int i = 0; i < cl->n_silence; i++)
        if (irc_mask_match(from->nick, from->user, from->host, cl->silence[i], from->ident_confirmed)) return 1;
    return 0;
}

/* IRCv3 account-tag: `rcpt` gets `acct_tagged` if it negotiated the cap and
 * the sender has an account to report, else the plain `line`. */
/* One rendering of a message per tag combination: [0] plain, [1] +account,
 * [2] +bot, [3] both. Only the ones the sender needs are built. */
#define LINE_SZ 1200

/* The '*' oper flag in WHO/WHOX/USERHOST/GLOB: honours +H (hidden oper) the
 * same way WHOIS does -- shown only to opers and to the user themself. */
static int visible_oper(const client_t *u, const client_t *viewer) {
    if (!(u->umodes & UMODE_O)) return 0;
    return !(u->umodes & UMODE_H) || u == viewer || (viewer->umodes & UMODE_O);
}

/* Tags a PRIVMSG/NOTICE/TAGMSG carries to a message-tags recipient: bot,
 * msgid, and the sender's client-only (+) tags. Rendered once per message,
 * not once per recipient. */
#define MAX_CLIENT_TAGS 8
typedef struct {
    char msgid[48];
    irc_tag_t ct[MAX_CLIENT_TAGS];
    int nct;
    int tagmsg; /* TAGMSG: only message-tags recipients get it */
} msg_extra_t;

static void build_lines(char lines[4][LINE_SZ], client_t *from, const char *prefix, const char *verb,
                        const char **p, const char *text, const msg_extra_t *x) {
    irc_build(lines[0], LINE_SZ, NULL, 0, prefix, verb, p, 1, text);
    int acct = from->account[0] != '\0', bot = (from->umodes & UMODE_B) != 0;
    irc_tag_t ta = {"account", from->account};
    irc_tag_t mt[1 + 1 + MAX_CLIENT_TAGS + 1]; /* [account,] bot, msgid, client tags */
    int n = 0;
    if (acct) mt[n++] = ta;
    if (bot) mt[n++] = (irc_tag_t){"bot", ""};
    mt[n++] = (irc_tag_t){"msgid", x->msgid};
    for (int i = 0; i < x->nct; i++) mt[n++] = x->ct[i];
    if (acct) irc_build(lines[1], LINE_SZ, &ta, 1, prefix, verb, p, 1, text);
    irc_build(lines[2], LINE_SZ, mt + (acct ? 1 : 0), n - (acct ? 1 : 0), prefix, verb, p, 1, text);
    if (acct) irc_build(lines[3], LINE_SZ, mt, n, prefix, verb, p, 1, text);
}

/* --- draft/multiline ----------------------------------------------------------
 * A client sends BATCH +ref draft/multiline <target>, PRIVMSG/NOTICE lines tagged @batch=ref (an optional
 * draft/multiline-concat tag glues a line onto the previous one), then BATCH -ref. The whole thing is checked
 * and delivered as ONE message: recipients with the cap get it as a batch, everyone else gets plain lines. */
#define ML_MAX_LINES 24
#define ML_MAX_BYTES 4096
typedef struct ml_state {
    char ref[32];
    char target[72];
    char verb[8];
    int n, bytes;
    int concat[ML_MAX_LINES];
    char text[ML_MAX_LINES][420];
} ml_state_t;

static const ml_state_t *g_ml; /* set around send_msg for a finished batch: deliver() then fans it out multiline-aware */
static void censor_text(const server_t *srv, char *text);
static void strip_formatting(char *dst, size_t dstsz, const char *src);

static void deliver_ml(client_t *rcpt, client_t *from, const msg_extra_t *x) {
    const ml_state_t *ml = g_ml;
    server_t *srv = from->srv;
    char prefix[320];
    client_prefix(from, prefix, sizeof prefix);
    channel_t *chan = ml->target[0] == '#' ? server_find_channel(srv, ml->target) : NULL;
    int strip = chan && (chan->modes & CMODE_STRIPCOLOR), censor = chan && (chan->modes & CMODE_CENSOR);
    const char *tp[] = {ml->target};
    char line[1200], txt[420], tmp[420];
    if ((rcpt->caps & CAP_MULTILINE) && (rcpt->caps & CAP_BATCH)) {
        static unsigned long seq = 0;
        char bid[24], plus[28], minus[28];
        snprintf(bid, sizeof bid, "ml%lu", ++seq);
        snprintf(plus, sizeof plus, "+%s", bid);
        snprintf(minus, sizeof minus, "-%s", bid);
        irc_tag_t st[3];
        int nst = 0;
        if (from->account[0] && (rcpt->caps & CAP_ACCOUNT_TAG)) st[nst++] = (irc_tag_t){"account", from->account};
        st[nst++] = (irc_tag_t){"msgid", x->msgid};
        const char *bp[] = {plus, "draft/multiline", ml->target};
        irc_build(line, sizeof line, st, nst, prefix, "BATCH", bp, 3, NULL);
        client_send(rcpt, line);
        for (int i = 0; i < ml->n; i++) {
            snprintf(txt, sizeof txt, "%s", ml->text[i]);
            if (strip) { strip_formatting(tmp, sizeof tmp, txt); snprintf(txt, sizeof txt, "%s", tmp); }
            if (censor) censor_text(srv, txt);
            irc_tag_t lt[2];
            int nlt = 0;
            lt[nlt++] = (irc_tag_t){"batch", bid};
            if (ml->concat[i]) lt[nlt++] = (irc_tag_t){"draft/multiline-concat", ""};
            irc_build(line, sizeof line, lt, nlt, prefix, ml->verb, tp, 1, txt);
            client_send(rcpt, line);
        }
        const char *ep[] = {minus};
        irc_build(line, sizeof line, NULL, 0, prefix, "BATCH", ep, 1, NULL);
        client_send(rcpt, line);
        return;
    }
    /* No multiline cap: concat fragments are glued into one line, every other line is its own message. */
    char cur[420] = "";
    int first = 1;
    for (int i = 0; i <= ml->n; i++) {
        int boundary = i == ml->n || !ml->concat[i];
        if (boundary && (i > 0)) {
            snprintf(txt, sizeof txt, "%s", cur);
            if (strip) { strip_formatting(tmp, sizeof tmp, txt); snprintf(txt, sizeof txt, "%s", tmp); }
            if (censor) censor_text(srv, txt);
            msg_extra_t xi = *x;
            if (!first) server_next_msgid(srv, xi.msgid, sizeof xi.msgid);
            first = 0;
            char one[4][LINE_SZ];
            build_lines(one, from, prefix, ml->verb, tp, txt, &xi);
            int m = (rcpt->caps & CAP_MESSAGE_TAGS) != 0;
            int k = ((from->account[0] && (rcpt->caps & CAP_ACCOUNT_TAG)) ? 1 : 0) | (m ? 2 : 0);
            client_send(rcpt, one[k]);
            cur[0] = '\0';
        }
        if (i < ml->n) {
            size_t l = strlen(cur);
            snprintf(cur + l, sizeof cur - l, "%s", ml->text[i]);
        }
    }
}

/* account tag needs account-tag; bot/msgid/client tags need message-tags. */
static void deliver(client_t *rcpt, client_t *from, char lines[4][LINE_SZ], const msg_extra_t *x) {
    if (g_ml) { deliver_ml(rcpt, from, x); return; }
    int m = (rcpt->caps & CAP_MESSAGE_TAGS) != 0;
    if (x->tagmsg && !m) return;
    int i = ((from->account[0] && (rcpt->caps & CAP_ACCOUNT_TAG)) ? 1 : 0) | (m ? 2 : 0);
    client_send(rcpt, lines[i]);
}

/* +S: drop mIRC colour (\x03[fg[,bg]]) and the other single-byte formatting
 * controls (bold/underline/reverse/italic/strikethrough/monospace/reset). */
static void strip_formatting(char *dst, size_t dstsz, const char *src) {
    size_t di = 0;
    for (const char *p = src; *p && di + 1 < dstsz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == 0x02 || c == 0x0F || c == 0x11 || c == 0x16 || c == 0x1D || c == 0x1E || c == 0x1F) continue;
        if (c == 0x03) {
            for (int n = 0; n < 2 && isdigit((unsigned char)p[1]); n++) p++;
            if (p[1] == ',') { p++; for (int n = 0; n < 2 && isdigit((unsigned char)p[1]); n++) p++; }
            continue;
        }
        dst[di++] = (char)c;
    }
    dst[di] = '\0';
}

/* CTCP other than ACTION (/me) -- what +C (channel) and +d (user) block. */
static int is_blocked_ctcp(const char *text) {
    return text[0] == '\x01' && strncmp(text + 1, "ACTION", 6) != 0;
}

/* +c: any of the same bytes strip_formatting above removes. Unlike +S
 * (which silently strips and still delivers), +c rejects the message
 * outright -- same distinction real ircds draw between "block colour" and
 * "strip colour". */
static int has_formatting(const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == 0x02 || *p == 0x0F || *p == 0x11 || *p == 0x16 || *p == 0x1D || *p == 0x1E || *p == 0x1F || *p == 0x03)
            return 1;
    }
    return 0;
}

/* +f: remove `victim` from `chan` with a server-sourced KICK. */
static void flood_kick(server_t *srv, channel_t *chan, client_t *victim) {
    char line[400];
    const char *p[] = {chan->name, victim->nick};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "KICK", p, 2, "Channel flood (+f)");
    server_broadcast_channel(chan, line, NULL); /* the victim is still a member, so they see it too */
    channel_remove_member(chan, victim);
    server_detach_membership(victim, chan);
    server_maybe_drop_channel(srv, chan); /* chan may be freed -- don't touch it after this */
}

/* The sender's client-only tags (+key[=value]) that are safe to relay: bounded count/size. */
static void collect_client_tags(const irc_message_t *msg, msg_extra_t *x) {
    size_t total = 0;
    for (int i = 0; i < msg->ntags && x->nct < MAX_CLIENT_TAGS; i++) {
        const char *k = msg->tags[i].key, *v = msg->tags[i].val ? msg->tags[i].val : "";
        if (k[0] != '+' || !k[1] || strlen(k) > 64 || strlen(v) > 128) continue;
        int ok = 1;
        for (const char *c = k + 1; *c; c++)
            if (!(isalnum((unsigned char)*c) || *c == '-' || *c == '/' || *c == '.')) { ok = 0; break; }
        if (!ok || total + strlen(k) + strlen(v) + 2 > 400) continue;
        total += strlen(k) + strlen(v) + 2;
        x->ct[x->nct++] = msg->tags[i];
    }
}

/* strcasestr isn't in -std=c11/POSIX 2008, so a small portable one. */
static char *find_nocase(char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (; *hay; hay++) if (strncasecmp(hay, needle, nl) == 0) return hay;
    return NULL;
}

/* +G: star out every configured censor word (case-insensitive substring), in place. */
static void censor_text(const server_t *srv, char *text) {
    for (int i = 0; i < srv->cfg.messages.n_censor_words; i++) {
        const char *w = srv->cfg.messages.censor_words[i];
        size_t wl = strlen(w);
        if (wl == 0) continue;
        for (char *p = text; (p = find_nocase(p, w)) != NULL; p += wl) memset(p, '*', wl);
    }
}

static void send_msg(server_t *srv, client_t *cl, irc_message_t *msg, const char *verb, int is_notice) {
    const char *target = msg->params[0];
    int is_tagmsg = strcmp(verb, "TAGMSG") == 0;
    msg_extra_t x = {.tagmsg = is_tagmsg};
    server_next_msgid(srv, x.msgid, sizeof x.msgid);
    collect_client_tags(msg, &x);
    if (is_tagmsg) {
        /* IRCv3 message-tags: TAGMSG is only meaningful from a client that negotiated it, and without any
         * relayable (+) tag there is nothing to send. */
        if (!(cl->caps & CAP_MESSAGE_TAGS) || x.nct == 0) return;
    } else if (msg->nparams < 2) {
        if (!is_notice) client_reply(cl, N_NOTEXTTOSEND, NULL, 0, "No text to send");
        return;
    }
    /* Flood guard is enforced once, per-line, in net.c before dispatch --
     * same choke-point architecture as server._read_loop in the Python
     * daemon (see CLAUDE.md's "Security invariants to preserve"). */
    char textbuf[420];
    if (is_tagmsg) textbuf[0] = '\0';
    else snprintf(textbuf, sizeof textbuf, "%.*s", srv->cfg.messages.max_message_length, msg->params[msg->nparams - 1]);

    if (!is_tagmsg && spam_check_message(srv, cl, target, textbuf, is_notice)) return;

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char lines[4][LINE_SZ];

    /* STATUSMSG (ISUPPORT STATUSMSG=~&@%+): "~#chan"/"&#chan"/"@#chan"/"%#chan"/"+#chan"
     * delivers only to members holding at least that rank. */
    char status_prefix = '\0';
    const char *chan_target = target;
    if ((target[0] == '~' || target[0] == '&' || target[0] == '@' || target[0] == '%' || target[0] == '+') && target[1] == '#') {
        status_prefix = target[0];
        chan_target = target + 1;
    }
    const char *p[] = {target};
    int delivered = 0;

    if (chan_target[0] == '#') {
        channel_t *chan = server_find_channel(srv, chan_target);
        if (!chan) {
            if (!is_notice) err_no_such_channel(cl, chan_target);
            return;
        }
        member_t *m = channel_find_member(chan, cl);
        int privileged = (m && (m->rank & (RANK_OP | RANK_HALFOP | RANK_VOICE))) || (cl->umodes & UMODE_O);

        if ((chan->modes & CMODE_NOCTCP) && is_blocked_ctcp(textbuf) && !privileged) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+C)"); }
            return;
        }
        if (is_notice && (chan->modes & CMODE_NONOTICE) && !privileged) return;

        if (!m && (chan->modes & CMODE_N) && !(cl->umodes & UMODE_O)) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel"); }
            return;
        }
        if ((chan->modes & CMODE_M) && !privileged) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+m)"); }
            return;
        }
        if ((chan->modes & CMODE_MODREG) && !privileged && !cl->account[0]) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+M, registered users only)"); }
            return;
        }
        if ((chan->modes & CMODE_NOCOLOR) && !privileged && has_formatting(textbuf)) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+c, no colour/formatting)"); }
            return;
        }
        int is_banned = 0, is_quieted = 0;
        ban_extra_t bx = {cl->realname, (cl->umodes & UMODE_Z) != 0, cl};
        channel_set_ban_extra(&bx);
        if (chan->bans.n > 0)
            channel_ban_state(chan, m, cl->nick, cl->user, cl->host, cl->realhost, cl->ip, cl->account, cl->ident_confirmed,
                              &is_banned, &is_quieted);
        if (!(m && (m->rank & RANK_OP)) && !(cl->umodes & UMODE_O) && is_banned) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+b)"); }
            return;
        }
        if (!privileged && is_quieted) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (quieted)"); }
            return;
        }
        if ((chan->modes & CMODE_FLOOD) && chan->flood_lines > 0 && m && !privileged) {
            time_t now = time(NULL);
            if (now - m->fl_start >= chan->flood_secs) { m->fl_start = now; m->fl_count = 0; }
            if (++m->fl_count > chan->flood_lines) { /* +f: kick the flooder; ops/halfops/voice/opers are exempt */
                flood_kick(srv, chan, cl);
                return;
            }
        }
        char stripbuf[420];
        const char *outtext = textbuf;
        if (chan->modes & CMODE_STRIPCOLOR) { strip_formatting(stripbuf, sizeof stripbuf, textbuf); outtext = stripbuf; }

        char censored[420];
        if ((chan->modes & CMODE_CENSOR) && !is_tagmsg) {
            snprintf(censored, sizeof censored, "%s", outtext);
            censor_text(srv, censored);
            outtext = censored;
        }
        if (m && m->hidden) channel_reveal_member(chan, m); /* +D: speaking reveals you */
        build_lines(lines, cl, prefix, verb, p, is_tagmsg ? NULL : outtext, &x);

        member_t *mm, *tmp;
        if (status_prefix) {
            /* "at least that rank": ~ owner(5) & admin(4) @ op(3) % halfop(2) + voice(1) -- channel_rank_level's scale */
            int min_level = (status_prefix == '~') ? 5 : (status_prefix == '&') ? 4 : (status_prefix == '@') ? 3 : (status_prefix == '%') ? 2 : 1;
            HASH_ITER(hh, chan->members, mm, tmp) {
                if (mm->client == cl) continue;
                if ((chan->modes & CMODE_AUDITORIUM) && m && !channel_member_visible(chan, m, mm)) continue;
                if (channel_rank_level(mm->rank) >= min_level) deliver(mm->client, cl, lines, &x);
            }
            return; /* STATUSMSG has no echo-message in upstream either */
        }

        HASH_ITER(hh, chan->members, mm, tmp) {
            if (mm->client == cl) continue;
            /* +u: an unranked member's words reach only members who can see them (ranked members) */
            if ((chan->modes & CMODE_AUDITORIUM) && m && !channel_member_visible(chan, m, mm)) continue;
            deliver(mm->client, cl, lines, &x);
        }
        if (!is_tagmsg && srv->cfg.messages.history_size > 0) {
            hist_entry_t h;
            memset(&h, 0, sizeof h);
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            snprintf(h.msgid, sizeof h.msgid, "%s", x.msgid);
            h.ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            snprintf(h.sender, sizeof h.sender, "%s", prefix);
            snprintf(h.account, sizeof h.account, "%s", cl->account);
            snprintf(h.verb, sizeof h.verb, "%s", verb);
            snprintf(h.target, sizeof h.target, "%s", chan->name);
            snprintf(h.text, sizeof h.text, "%s", outtext);
            char hkey[160];
            history_key_channel(hkey, sizeof hkey, chan->name);
            history_add(srv, hkey, srv->cfg.messages.history_size, &h);
        }
        delivered = 1;
    } else {
        client_t *dst = server_find_user(srv, target);
        /* A connection that only sent NICK (not USER/welcome yet) holds its
         * nick in srv->users for up to REGISTRATION_TIMEOUT -- it isn't a
         * real, reachable user yet, so treat it as "no such nick" rather
         * than letting messages queue into a socket that may never even
         * finish registering (or reconnect and hold a different identity
         * under the same nick). */
        if (dst && !dst->registered) dst = NULL;
        if (!dst && !is_notice && strcasecmp(target, "NickServ") == 0) {
            nickserv_message(srv, cl, textbuf); /* virtual NickServ -- see cmd_reg.c */
            return;
        }
        if (!dst) {
            if (!is_notice) err_no_such_nick(cl, target);
            return;
        }
        if (client_is_silencing(dst, cl)) return; /* dropped without telling the sender */
        if ((dst->umodes & UMODE_D) && is_blocked_ctcp(textbuf)) return; /* +d: suppress CTCP */
        if ((dst->umodes & UMODE_NOPM) && !(cl->umodes & UMODE_O) && cl != dst) {
            const char *pe[] = {dst->nick};
            if (!is_notice) client_reply(cl, N_NONONREG, pe, 1, "is not accepting private messages");
            return;
        }
        if ((dst->umodes & UMODE_REGONLY) && !cl->account[0] && !(cl->umodes & UMODE_O) && cl != dst) {
            const char *pe[] = {dst->nick};
            if (!is_notice) client_reply(cl, N_NONONREG, pe, 1, "is only accepting messages from registered users");
            return;
        }
        if ((dst->umodes & UMODE_G) && cl != dst && !(cl->umodes & UMODE_O) && !cl->is_service) {
            char scf[NICKLEN];
            irc_casefold(scf, sizeof scf, cl->nick);
            int allowed = 0;
            for (int ai = 0; ai < dst->n_accept && !allowed; ai++) {
                if (dst->accept[ai].account[0]) allowed = cl->account[0] && strcasecmp(dst->accept[ai].account, cl->account) == 0;
                else if (dst->accept[ai].conn_id) allowed = dst->accept[ai].conn_id == cl->conn_id;
                else allowed = strcmp(dst->accept[ai].nick, scf) == 0; /* nobody was on that nick when it was added */
            }
            if (!allowed) {
                if (!is_notice) { /* caller-ID: tell both sides once in a while, deliver nothing */
                    const char *pe[] = {dst->nick};
                    client_reply(cl, N_TARGUMODEG, pe, 1, "is in +g mode (server-side ignore).");
                    time_t now = time(NULL);
                    if (now - dst->last_cid_notice >= 60) {
                        dst->last_cid_notice = now;
                        char who[320];
                        snprintf(who, sizeof who, "%s!%s@%s", cl->nick, cl->user, cl->host);
                        const char *pw[] = {who};
                        client_reply(dst, N_UMODEGMSG, pw, 1, "is messaging you, and you are umode +g.");
                        client_reply(cl, N_TARGNOTIFY, pe, 1, "has been informed that you messaged them.");
                    }
                }
                return;
            }
        }
        if (!is_notice && dst->is_away) {
            const char *pa[] = {dst->nick};
            client_reply(cl, N_AWAY, pa, 1, dst->away);
        }
        build_lines(lines, cl, prefix, verb, p, is_tagmsg ? NULL : textbuf, &x);
        deliver(dst, cl, lines, &x);
        delivered = 1;
        /* Private-message history, only between two logged-in accounts (so each side can ask for it by account). */
        if (!is_tagmsg && srv->cfg.messages.history_size > 0 && srv->cfg.messages.history_dm &&
            cl->account[0] && dst->account[0] && cl != dst) {
            hist_entry_t h;
            memset(&h, 0, sizeof h);
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            snprintf(h.msgid, sizeof h.msgid, "%s", x.msgid);
            h.ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            snprintf(h.sender, sizeof h.sender, "%s", prefix);
            snprintf(h.account, sizeof h.account, "%s", cl->account);
            snprintf(h.verb, sizeof h.verb, "%s", verb);
            snprintf(h.target, sizeof h.target, "%s", dst->nick);
            snprintf(h.text, sizeof h.text, "%s", textbuf);
            char hkey[160];
            history_key_dm(hkey, sizeof hkey, cl->account, dst->account);
            history_add(srv, hkey, srv->cfg.messages.history_size, &h);
        }
    }
    /* IRCv3 echo-message: the sender gets its own message back too, once
     * delivery actually happened. */
    if (delivered && (cl->caps & CAP_ECHO_MESSAGE)) deliver(cl, cl, lines, &x);
}

static void batch_fail(server_t *srv, client_t *cl, const char *code, const char *ref, const char *desc) {
    char line[400];
    const char *p[] = {"BATCH", code, ref};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 3, desc);
    client_send(cl, line);
}

/* A PRIVMSG/NOTICE carrying @batch=<ref> of the client's open multiline batch is collected, not sent.
 * Returns 1 if it was consumed. */
static int ml_collect(server_t *srv, client_t *cl, irc_message_t *msg, const char *verb) {
    const char *ref = NULL;
    int concat = 0;
    for (int i = 0; i < msg->ntags; i++) {
        if (strcmp(msg->tags[i].key, "batch") == 0) ref = msg->tags[i].val;
        else if (strcmp(msg->tags[i].key, "draft/multiline-concat") == 0) concat = 1;
    }
    if (!ref) return 0;
    ml_state_t *ml = cl->ml;
    if (!ml || strcmp(ml->ref, ref) != 0) { batch_fail(srv, cl, "INVALID_REFTAG", ref, "No such open batch"); return 1; }
    char tcf[72], mcf[72];
    irc_casefold(tcf, sizeof tcf, ml->target);
    irc_casefold(mcf, sizeof mcf, msg->nparams > 0 ? msg->params[0] : "");
    const char *text = msg->nparams > 1 ? msg->params[msg->nparams - 1] : "";
    if (strcmp(tcf, mcf) != 0) { batch_fail(srv, cl, "MULTILINE_INVALID_TARGET", ml->ref, "Line target differs from the batch target"); goto cancel; }
    if (ml->n == 0) snprintf(ml->verb, sizeof ml->verb, "%s", verb);
    else if (strcmp(ml->verb, verb) != 0) { batch_fail(srv, cl, "MULTILINE_INVALID", ml->ref, "Mixed PRIVMSG and NOTICE in one batch"); goto cancel; }
    if (ml->n >= ML_MAX_LINES) { batch_fail(srv, cl, "MULTILINE_MAX_LINES", ml->ref, "Too many lines"); goto cancel; }
    if (ml->n == 0 && concat) { batch_fail(srv, cl, "MULTILINE_INVALID", ml->ref, "The first line cannot be a concat"); goto cancel; }
    if (!concat && text[0] == '\0') { batch_fail(srv, cl, "MULTILINE_INVALID", ml->ref, "Blank lines are not allowed"); goto cancel; }
    if (ml->bytes + (int)strlen(text) > ML_MAX_BYTES) { batch_fail(srv, cl, "MULTILINE_MAX_BYTES", ml->ref, "Batch too large"); goto cancel; }
    snprintf(ml->text[ml->n], sizeof ml->text[0], "%.*s", srv->cfg.messages.max_message_length, text);
    ml->concat[ml->n] = concat;
    ml->bytes += (int)strlen(ml->text[ml->n]);
    ml->n++;
    return 1;
cancel:
    free(cl->ml);
    cl->ml = NULL;
    return 1;
}

void cmd_privmsg(server_t *srv, client_t *cl, irc_message_t *msg) { if (!ml_collect(srv, cl, msg, "PRIVMSG")) send_msg(srv, cl, msg, "PRIVMSG", 0); }
void cmd_notice(server_t *srv, client_t *cl, irc_message_t *msg) { if (!ml_collect(srv, cl, msg, "NOTICE")) send_msg(srv, cl, msg, "NOTICE", 1); }

/* BATCH +ref draft/multiline <target>  ...  BATCH -ref */
void cmd_batch(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *r = msg->params[0];
    if (!(cl->caps & CAP_MULTILINE) || !(cl->caps & CAP_BATCH)) { batch_fail(srv, cl, "INVALID", r, "Negotiate batch and draft/multiline first"); return; }
    if (r[0] == '+') {
        if (msg->nparams < 3 || strcasecmp(msg->params[1], "draft/multiline") != 0) { batch_fail(srv, cl, "UNKNOWN_TYPE", r + 1, "Only draft/multiline batches are accepted"); return; }
        if (cl->ml) { batch_fail(srv, cl, "TOO_MANY", r + 1, "Finish the open batch first"); return; }
        if (strlen(r + 1) >= sizeof cl->ml->ref || strlen(msg->params[2]) >= sizeof cl->ml->target) { batch_fail(srv, cl, "INVALID", r + 1, "Reference or target too long"); return; }
        cl->ml = calloc(1, sizeof *cl->ml);
        if (!cl->ml) return;
        snprintf(cl->ml->ref, sizeof cl->ml->ref, "%s", r + 1);
        snprintf(cl->ml->target, sizeof cl->ml->target, "%s", msg->params[2]);
        return;
    }
    if (r[0] != '-' || !cl->ml || strcmp(cl->ml->ref, r + 1) != 0) { batch_fail(srv, cl, "INVALID_REFTAG", r[0] ? r + 1 : r, "No such open batch"); return; }
    ml_state_t *ml = cl->ml;
    cl->ml = NULL; /* ours to free below, whatever happens */
    int all_concat = 1;
    for (int i = 0; i < ml->n; i++) if (!ml->concat[i]) all_concat = 0;
    if (ml->n == 0 || all_concat) { batch_fail(srv, cl, "MULTILINE_INVALID", ml->ref, "Empty batch"); free(ml); return; }
    /* One synthetic message for the ordinary send path: all the usual checks (+n/+m/bans/flood/spam/...) run once on the
     * joined text, then deliver() fans the batch out through g_ml. */
    char joined[420] = "";
    for (int i = 0; i < ml->n; i++) {
        if (i && !ml->concat[i]) strncat(joined, " ", sizeof joined - strlen(joined) - 1);
        strncat(joined, ml->text[i], sizeof joined - strlen(joined) - 1);
    }
    irc_message_t synth;
    memset(&synth, 0, sizeof synth);
    synth.command = (char *)ml->verb;
    synth.params[0] = ml->target;
    synth.params[1] = joined;
    synth.nparams = 2;
    g_ml = ml;
    send_msg(srv, cl, &synth, ml->verb, strcmp(ml->verb, "NOTICE") == 0);
    g_ml = NULL;
    free(ml);
}
void cmd_tagmsg(server_t *srv, client_t *cl, irc_message_t *msg) { send_msg(srv, cl, msg, "TAGMSG", 1); }

static void whois_one(server_t *srv, client_t *cl, const char *nick) {
    client_t *target = server_find_user(srv, nick);
    if (target && !target->registered) target = NULL; /* not yet USER/welcomed -- see send_msg's dst check */
    if (!target) {
        err_no_such_nick(cl, nick);
        const char *pe[] = {nick};
        client_reply(cl, N_ENDOFWHOIS, pe, 1, "End of /WHOIS list.");
        return;
    }
    const char *p1[] = {target->nick, target->user, target->host};
    client_reply(cl, N_WHOISUSER, p1, 3, target->realname);

    const char *p2[] = {target->nick, srv->cfg.server.name};
    client_reply(cl, N_WHOISSERVER, p2, 2, srv->cfg.server.network);

    int self_or_oper = (cl == target) || (cl->umodes & UMODE_O);
    if ((target->umodes & UMODE_O) && (!(target->umodes & UMODE_H) || self_or_oper)) {
        const char *p3[] = {target->nick};
        client_reply(cl, N_WHOISOPERATOR, p3, 1, "is an IRC operator");
    }
    if (target->umodes & UMODE_B) {
        const char *p3b[] = {target->nick};
        char m[200];
        snprintf(m, sizeof m, "is a Bot on %s", srv->cfg.server.network);
        client_reply(cl, N_WHOISBOT, p3b, 1, m);
    }
    if (target->umodes & UMODE_Z) {
        const char *p3z[] = {target->nick};
        client_reply(cl, N_WHOISSECURE, p3z, 1, "is using a secure connection");
    }
    if (target->account[0]) {
        const char *p3a[] = {target->nick, target->account};
        client_reply(cl, N_WHOISACCOUNT, p3a, 2, "is logged in as");
    }
    if (target->is_away) {
        const char *pa[] = {target->nick};
        client_reply(cl, N_AWAY, pa, 1, target->away);
    }
    if (strcmp(target->host, target->realhost) != 0 && ((cl->umodes & UMODE_O) || cl == target)) {
        char m[300];
        snprintf(m, sizeof m, "is actually connecting from %s", target->realhost);
        const char *p3h[] = {target->nick};
        client_reply(cl, N_WHOISHOST, p3h, 1, m);
    }

    char chanbuf[1024] = "";
    size_t cp = 0;
    if (!(target->umodes & UMODE_P) || self_or_oper) {
        for (chan_node_t *n = target->channels; n; n = n->next) {
            if ((n->chan->modes & (CMODE_S | CMODE_P)) && !channel_find_member(n->chan, cl)) continue;
            member_t *m = channel_find_member(n->chan, target);
            char rankch[8];
            channel_rank_prefix(m ? m->rank : 0, 0, rankch);
            char entry[80];
            snprintf(entry, sizeof entry, "%s%s%s", cp ? " " : "", rankch, n->chan->name);
            size_t el = strlen(entry);
            if (cp + el < sizeof chanbuf) { memcpy(chanbuf + cp, entry, el); cp += el; chanbuf[cp] = '\0'; }
        }
    }
    if (cp > 0) {
        const char *p4[] = {target->nick};
        client_reply(cl, N_WHOISCHANNELS, p4, 1, chanbuf);
    }

    if (!(target->umodes & UMODE_HIDEIDLE) || self_or_oper) {
        long idle = (long)difftime(time(NULL), target->last_activity);
        char idlebuf[32], signonbuf[32];
        snprintf(idlebuf, sizeof idlebuf, "%ld", idle);
        snprintf(signonbuf, sizeof signonbuf, "%ld", (long)target->signon_time);
        const char *p5[] = {target->nick, idlebuf, signonbuf};
        client_reply(cl, N_WHOISIDLE, p5, 3, "seconds idle, signon time");
    }

    const char *pe[] = {target->nick};
    client_reply(cl, N_ENDOFWHOIS, pe, 1, "End of /WHOIS list.");
}

void cmd_whois(server_t *srv, client_t *cl, irc_message_t *msg) {
    char list[600];
    snprintf(list, sizeof list, "%s", msg->params[msg->nparams - 1]);
    char *save = NULL;
    char *tok = strtok_r(list, ",", &save);
    while (tok) { whois_one(srv, cl, tok); tok = strtok_r(NULL, ",", &save); }
}

static void who_rank_flags(int rank, int multi, char *out) { channel_rank_prefix(rank, multi, out); }

/* WHOX (ISUPPORT WHOX) field value for one letter -- matches commands.py's
 * _whox_value. `chan` is NULL for a bare-nick WHO with no channel context. */
static const char *whox_value(char letter, client_t *u, channel_t *chan, client_t *cl,
                               const char *token, char *scratch, size_t scratchsz) {
    switch (letter) {
    case 't': return token;
    case 'c': return chan ? chan->name : "*";
    case 'u': return u->user;
    case 'i': return ((cl->umodes & UMODE_O) || u == cl) ? u->ip : "255.255.255.255";
    case 'h': return u->host;
    case 's': return cl->srv->cfg.server.name;
    case 'n': return u->nick;
    case 'f': {
        int multi = cl->caps & CAP_MULTI_PREFIX;
        member_t *m = chan ? channel_find_member(chan, u) : NULL;
        char rankch[8];
        who_rank_flags(m ? m->rank : 0, multi, rankch);
        snprintf(scratch, scratchsz, "%s%s%s%s", u->is_away ? "G" : "H", visible_oper(u, cl) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "", rankch);
        return scratch;
    }
    case 'd': return "0";
    case 'o': return "0"; /* oplevel: not tracked */
    case 'l': {
        long idle = (long)difftime(time(NULL), u->last_activity);
        snprintf(scratch, scratchsz, "%ld", idle);
        return scratch;
    }
    case 'a': return u->account[0] ? u->account : "0";
    default: return "";
    }
}

static void send_whox_reply(client_t *cl, const char *fields, const char *token,
                             client_t *u, channel_t *chan) {
    const char *p[16];
    char scratch[16][32];
    int nscratch = 0, np = 0;
    const char *trailing = NULL;
    p[np++] = cl->nick;
    /* WHOX replies always carry the fields in this fixed order, whatever
     * order the client listed them in the request. */
    for (const char *f = "tcuihsnfdlaor"; *f && np < 16 && nscratch < 16; f++) {
        if (!strchr(fields, *f)) continue;
        if (*f == 'r') { trailing = u->realname; continue; }
        p[np++] = whox_value(*f, u, chan, cl, token, scratch[nscratch], sizeof scratch[nscratch]);
        nscratch++;
    }
    client_reply(cl, N_WHOSPCRPL, p + 1, np - 1, trailing);
}

static void send_who_classic(client_t *cl, client_t *u, channel_t *chan, int multi) {
    char rankch[8];
    member_t *m = chan ? channel_find_member(chan, u) : NULL;
    who_rank_flags(m ? m->rank : 0, multi, rankch);
    char flags[10];
    snprintf(flags, sizeof flags, "%s%s%s%s", u->is_away ? "G" : "H", visible_oper(u, cl) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "", rankch);
    const char *p[] = {chan ? chan->name : "*", u->user, u->host, cl->srv->cfg.server.name, u->nick, flags};
    char trailing[600];
    snprintf(trailing, sizeof trailing, "0 %s", u->realname);
    client_reply(cl, N_WHOREPLY, p, 6, trailing);
}

void cmd_who(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1 || !msg->params[0][0]) {
        const char *p[] = {"WHO"};
        client_reply(cl, N_NEEDMOREPARAMS, p, 1, "Not enough parameters");
        return;
    }
    const char *target = msg->params[0];
    int multi = cl->caps & CAP_MULTI_PREFIX;

    const char *whox_fields = NULL;
    char whox_token[64] = "";
    char fieldbuf[32];
    if (msg->nparams > 1 && msg->params[1][0] == '%') {
        char *comma = strchr(msg->params[1] + 1, ',');
        if (comma) {
            size_t flen = (size_t)(comma - (msg->params[1] + 1));
            if (flen >= sizeof fieldbuf) flen = sizeof fieldbuf - 1;
            memcpy(fieldbuf, msg->params[1] + 1, flen);
            fieldbuf[flen] = '\0';
            whox_fields = fieldbuf;
            snprintf(whox_token, sizeof whox_token, "%s", comma + 1);
        } else {
            whox_fields = msg->params[1] + 1;
        }
    }

    if (target[0] == '#' || target[0] == '&') {
        channel_t *chan = server_find_channel(srv, target);
        if (!chan) {
            const char *p[] = {target};
            client_reply(cl, N_NOSUCHCHANNEL, p, 1, "No such channel");
            return;
        }
        if ((chan->modes & (CMODE_S | CMODE_P)) && !channel_find_member(chan, cl)) {
            const char *pe[] = {target};
            client_reply(cl, N_ENDOFWHO, pe, 1, "End of /WHO list.");
            return;
        }
        member_t *m, *tmp;
        member_t *viewer = channel_find_member(chan, cl);
        HASH_ITER(hh, chan->members, m, tmp) {
            if (!channel_member_visible(chan, m, viewer)) continue; /* +D hidden / +u audience */
            if (whox_fields) send_whox_reply(cl, whox_fields, whox_token, m->client, chan);
            else send_who_classic(cl, m->client, chan, multi);
        }
    } else {
        client_t *u = server_find_user(srv, target);
        if (!u) {
            const char *p[] = {target};
            client_reply(cl, N_NOSUCHNICK, p, 1, "No such nick/channel");
            client_reply(cl, N_ENDOFWHO, p, 1, "End of /WHO list.");
            return;
        }
        /* Exactly one reply per user: the first channel the asker can see them in, else "*". */
        channel_t *shown = NULL;
        for (chan_node_t *n = u->channels; n; n = n->next) {
            channel_t *chan = n->chan;
            if ((chan->modes & (CMODE_S | CMODE_P)) && !channel_find_member(chan, cl)) continue;
            shown = chan;
            break;
        }
        if (whox_fields) send_whox_reply(cl, whox_fields, whox_token, u, shown);
        else send_who_classic(cl, u, shown, multi);
    }
    const char *pe[] = {target};
    client_reply(cl, N_ENDOFWHO, pe, 1, "End of /WHO list.");
}

/* IRCv3 away-notify: tell channel-mates that negotiated it, at most once
 * each even if `cl` shares several channels with them. */
static void broadcast_away(server_t *srv, client_t *cl) {
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    irc_build(line, sizeof line, NULL, 0, prefix, "AWAY", NULL, 0, cl->is_away ? cl->away : NULL);
    server_send_common_channels(srv, cl, line, CAP_AWAY_NOTIFY);
    server_monitor_extend(srv, cl, line, CAP_AWAY_NOTIFY);
}

void cmd_away(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (!cl->registered) { /* draft/pre-away: set the status quietly before registration finishes */
        if (!(cl->caps & CAP_PRE_AWAY)) { err_not_registered(cl); return; }
        if (msg->nparams < 1 || msg->params[0][0] == '\0' || strcmp(msg->params[0], "*") == 0) { cl->is_away = 0; cl->away[0] = '\0'; }
        else { cl->is_away = 1; snprintf(cl->away, sizeof cl->away, "%.399s", msg->params[msg->nparams - 1]); }
        return;
    }
    if (msg->nparams < 1 || msg->params[0][0] == '\0') {
        cl->is_away = 0;
        cl->away[0] = '\0';
        client_reply(cl, N_UNAWAY, NULL, 0, "You are no longer marked as being away");
    } else {
        if (spam_check_text(srv, cl, SPAM_T_AWAY, msg->params[msg->nparams - 1])) return;
        cl->is_away = 1;
        snprintf(cl->away, sizeof cl->away, "%.399s", msg->params[msg->nparams - 1]);
        client_reply(cl, N_NOWAWAY, NULL, 0, "You have been marked as being away");
    }
    broadcast_away(srv, cl);
}

void cmd_whowas(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *nick = msg->params[0];
    int count = (msg->nparams > 1 && isdigit((unsigned char)msg->params[1][0])) ? atoi(msg->params[1]) : -1;
    int shown = 0;
    /* newest first, matching upstream's reversed(server.whowas) */
    for (int i = 0; i < srv->whowas_count; i++) {
        int idx = ((srv->whowas_head - 1 - i) % WHOWAS_MAX + WHOWAS_MAX) % WHOWAS_MAX;
        whowas_entry_t *w = &srv->whowas[idx];
        if (strcasecmp(w->nick, nick) != 0) continue;
        const char *p[] = {w->nick, w->user, w->host, "*"};
        client_reply(cl, N_WHOWASUSER, p, 4, w->realname);
        shown++;
        if (count > 0 && shown >= count) break;
    }
    if (!shown) {
        const char *p[] = {nick};
        client_reply(cl, N_WASNOSUCHNICK, p, 1, "There was no such nickname");
    }
    const char *pe[] = {nick};
    client_reply(cl, N_ENDOFWHOWAS, pe, 1, "End of WHOWAS");
}

void cmd_setname(server_t *srv, client_t *cl, irc_message_t *msg) {
    snprintf(cl->realname, sizeof cl->realname, "%.390s", msg->params[0]);

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    irc_build(line, sizeof line, NULL, 0, prefix, "SETNAME", NULL, 0, cl->realname);

    if (cl->caps & CAP_SETNAME) client_send(cl, line);
    server_send_common_channels(srv, cl, line, CAP_SETNAME);
    server_monitor_extend(srv, cl, line, CAP_SETNAME);
}

/* Registered user by nick -- a connection that has only sent NICK must not
 * show up as online (PRIVMSG/WHOIS already filter these out). */
static client_t *find_registered(server_t *srv, const char *nick) {
    client_t *u = server_find_user(srv, nick);
    return (u && u->registered) ? u : NULL;
}

/* Calls fn for every space-separated nick across all parameters, so both
 * "ISON a b c" and "ISON :a b c" work. */
static void each_nick(irc_message_t *msg, int max, void (*fn)(const char *nick, void *ctx), void *ctx) {
    int n = 0;
    for (int i = 0; i < msg->nparams; i++) {
        char buf[600];
        snprintf(buf, sizeof buf, "%s", msg->params[i]);
        char *save = NULL;
        for (char *t = strtok_r(buf, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
            if (max && n >= max) return;
            n++;
            fn(t, ctx);
        }
    }
}

typedef struct { server_t *srv; client_t *cl; char out[500]; } nick_scan_t;

static void userhost_one(const char *nick, void *ctx) {
    nick_scan_t *sc = ctx;
    client_t *u = find_registered(sc->srv, nick);
    if (!u) return;
    char entry[300];
    snprintf(entry, sizeof entry, "%s%s%s=%c%s@%s", sc->out[0] ? " " : "", u->nick,
             visible_oper(u, sc->cl) ? "*" : "", u->is_away ? '-' : '+', u->user, u->host);
    strncat(sc->out, entry, sizeof sc->out - strlen(sc->out) - 1);
}

void cmd_userhost(server_t *srv, client_t *cl, irc_message_t *msg) {
    nick_scan_t sc = {.srv = srv, .cl = cl};
    each_nick(msg, 5, userhost_one, &sc);
    client_reply(cl, N_USERHOST, NULL, 0, sc.out);
}

/* USERIP (oper-only): like USERHOST but with the real IP -- for abuse handling. */
static void userip_one(const char *nick, void *ctx) {
    nick_scan_t *sc = ctx;
    client_t *u = find_registered(sc->srv, nick);
    if (!u) return;
    char entry[300];
    snprintf(entry, sizeof entry, "%s%s%s=%c%s@%s", sc->out[0] ? " " : "", u->nick,
             (u->umodes & UMODE_O) ? "*" : "", u->is_away ? '-' : '+', u->user, u->ip);
    strncat(sc->out, entry, sizeof sc->out - strlen(sc->out) - 1);
}

void cmd_userip(server_t *srv, client_t *cl, irc_message_t *msg) {
    nick_scan_t sc = {.srv = srv, .cl = cl};
    each_nick(msg, 5, userip_one, &sc);
    client_reply(cl, N_USERIP, NULL, 0, sc.out);
}

static void ison_one(const char *nick, void *ctx) {
    nick_scan_t *sc = ctx;
    if (!find_registered(sc->srv, nick)) return;
    if (sc->out[0]) strncat(sc->out, " ", sizeof sc->out - strlen(sc->out) - 1);
    strncat(sc->out, nick, sizeof sc->out - strlen(sc->out) - 1);
}

void cmd_ison(server_t *srv, client_t *cl, irc_message_t *msg) {
    nick_scan_t sc = {.srv = srv, .cl = cl};
    each_nick(msg, 0, ison_one, &sc);
    client_reply(cl, N_ISON, NULL, 0, sc.out);
}

#define MAX_MONITOR 100

static void monitor_discard(client_t *cl, const char *cf) {
    for (int i = 0; i < cl->n_monitor; i++) {
        if (strcmp(cl->monitor[i], cf) == 0) {
            memmove(cl->monitor[i], cl->monitor[i + 1], (size_t)(cl->n_monitor - i - 1) * sizeof cl->monitor[0]);
            cl->n_monitor--;
            return;
        }
    }
}

static void monitor_impl(server_t *srv, client_t *cl, irc_message_t *msg) {
    char sub[8];
    snprintf(sub, sizeof sub, "%s", msg->params[0]);
    for (char *c = sub; *c; c++) *c = (char)toupper((unsigned char)*c);

    if (strcmp(sub, "+") == 0 || strcmp(sub, "-") == 0) {
        if (msg->nparams < 2) { err_need_more_params(cl, "MONITOR"); return; }
        char targets[600];
        snprintf(targets, sizeof targets, "%s", msg->params[1]);
        char *save = NULL;
        if (strcmp(sub, "-") == 0) {
            for (char *t = strtok_r(targets, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
                char cf[NICKLEN]; irc_casefold(cf, sizeof cf, t);
                monitor_discard(cl, cf);
            }
            return;
        }
        char online[600] = "", offline[600] = "";
        for (char *t = strtok_r(targets, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
            if (cl->n_monitor >= MAX_MONITOR) {
                char nbuf[8]; snprintf(nbuf, sizeof nbuf, "%d", MAX_MONITOR);
                const char *p[] = {nbuf, t};
                client_reply(cl, N_MONLISTFULL, p, 2, "Monitor list is full");
                break;
            }
            char cf[NICKLEN]; irc_casefold(cf, sizeof cf, t);
            int dup = 0;
            for (int i = 0; i < cl->n_monitor; i++) if (strcmp(cl->monitor[i], cf) == 0) { dup = 1; break; }
            if (!dup) { snprintf(cl->monitor[cl->n_monitor], NICKLEN, "%s", cf); cl->n_monitor++; }
            client_t *u = server_find_user(srv, t);
            char *dstbuf = u ? online : offline;
            if (dstbuf[0]) strncat(dstbuf, ",", sizeof online - strlen(dstbuf) - 1);
            if (u) { char pfx[320]; client_prefix(u, pfx, sizeof pfx); strncat(online, pfx, sizeof online - strlen(online) - 1); }
            else strncat(offline, t, sizeof offline - strlen(offline) - 1);
        }
        if (online[0]) client_reply(cl, N_MONONLINE, NULL, 0, online);
        if (offline[0]) client_reply(cl, N_MONOFFLINE, NULL, 0, offline);
    } else if (strcmp(sub, "C") == 0) {
        cl->n_monitor = 0;
    } else if (strcmp(sub, "L") == 0) {
        if (cl->n_monitor > 0) {
            char out[600] = "";
            for (int i = 0; i < cl->n_monitor; i++) {
                if (out[0]) strncat(out, ",", sizeof out - strlen(out) - 1);
                strncat(out, cl->monitor[i], sizeof out - strlen(out) - 1);
            }
            client_reply(cl, N_MONLIST, NULL, 0, out);
        }
        client_reply(cl, N_ENDOFMONLIST, NULL, 0, "End of MONITOR list");
    } else if (strcmp(sub, "S") == 0) {
        char online[600] = "", offline[600] = "";
        for (int i = 0; i < cl->n_monitor; i++) {
            client_t *u = server_find_user(srv, cl->monitor[i]);
            if (u) {
                char pfx[320]; client_prefix(u, pfx, sizeof pfx);
                if (online[0]) strncat(online, ",", sizeof online - strlen(online) - 1);
                strncat(online, pfx, sizeof online - strlen(online) - 1);
            } else {
                if (offline[0]) strncat(offline, ",", sizeof offline - strlen(offline) - 1);
                strncat(offline, cl->monitor[i], sizeof offline - strlen(offline) - 1);
            }
        }
        if (online[0]) client_reply(cl, N_MONONLINE, NULL, 0, online);
        if (offline[0]) client_reply(cl, N_MONOFFLINE, NULL, 0, offline);
    }
}

#define MAX_WATCH 128

static void watch_discard(client_t *cl, const char *cf) {
    for (int i = 0; i < cl->n_watch; i++) {
        if (strcmp(cl->watch[i], cf) == 0) {
            memmove(cl->watch[i], cl->watch[i + 1], (size_t)(cl->n_watch - i - 1) * sizeof cl->watch[0]);
            cl->n_watch--;
            return;
        }
    }
}

/* Legacy pre-MONITOR watch list: unlike MONITOR's single comma-separated
 * argument, each WATCH parameter is its own +nick/-nick token (or a bare
 * C/L/S letter), and a single command line may mix several of these. */
static void watch_impl(server_t *srv, client_t *cl, irc_message_t *msg) {
    for (int pi = 0; pi < msg->nparams; pi++) {
        const char *tok = msg->params[pi];
        if (tok[0] == '+' || tok[0] == '-') {
            char cf[NICKLEN]; irc_casefold(cf, sizeof cf, tok + 1);
            if (!cf[0]) continue;
            if (tok[0] == '-') {
                watch_discard(cl, cf);
                const char *p[] = {tok + 1, "*", "*", "0"};
                client_reply(cl, N_WATCHOFF, p, 4, "stopped watching");
                continue;
            }
            int dup = 0;
            for (int i = 0; i < cl->n_watch; i++) if (strcmp(cl->watch[i], cf) == 0) { dup = 1; break; }
            if (!dup) {
                if (cl->n_watch >= MAX_WATCH) continue;
                snprintf(cl->watch[cl->n_watch], NICKLEN, "%s", cf);
                cl->n_watch++;
            }
            client_t *u = server_find_user(srv, tok + 1);
            char timebuf[32];
            if (u) {
                snprintf(timebuf, sizeof timebuf, "%ld", (long)u->signon_time);
                const char *p[] = {u->nick, u->user, u->host, timebuf};
                client_reply(cl, N_NOWON, p, 4, "is online");
            } else {
                snprintf(timebuf, sizeof timebuf, "%ld", 0L);
                const char *p[] = {tok + 1, "*", "*", timebuf};
                client_reply(cl, N_NOWOFF, p, 4, "is offline");
            }
        } else if (strcasecmp(tok, "C") == 0) {
            cl->n_watch = 0;
        } else if (strcasecmp(tok, "L") == 0) {
            for (int i = 0; i < cl->n_watch; i++) {
                client_t *u = server_find_user(srv, cl->watch[i]);
                char timebuf[32];
                if (u) {
                    snprintf(timebuf, sizeof timebuf, "%ld", (long)u->signon_time);
                    const char *p[] = {u->nick, u->user, u->host, timebuf};
                    client_reply(cl, N_NOWON, p, 4, "is online");
                } else {
                    const char *p[] = {cl->watch[i], "*", "*", "0"};
                    client_reply(cl, N_NOWOFF, p, 4, "is offline");
                }
            }
            client_reply(cl, N_ENDOFWATCHLIST, NULL, 0, "End of WATCH L");
        } else if (strcasecmp(tok, "S") == 0) {
            char nbuf[8]; snprintf(nbuf, sizeof nbuf, "%d", cl->n_watch);
            char msgbuf[64]; snprintf(msgbuf, sizeof msgbuf, "You have %d and are on %d WATCH entries", cl->n_watch, cl->n_watch);
            client_reply(cl, N_WATCHSTAT, NULL, 0, msgbuf);
            for (int i = 0; i < cl->n_watch; i++) {
                client_t *u = server_find_user(srv, cl->watch[i]);
                if (!u) continue;
                char timebuf[32]; snprintf(timebuf, sizeof timebuf, "%ld", (long)u->signon_time);
                const char *p[] = {u->nick, u->user, u->host, timebuf};
                client_reply(cl, N_NOWON, p, 4, "is online");
            }
            client_reply(cl, N_ENDOFWATCHLIST, NULL, 0, "End of WATCH S");
        }
    }
}

#define MAX_SILENCE 15

void cmd_silence(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)srv;
    if (msg->nparams < 1) {
        for (int i = 0; i < cl->n_silence; i++) {
            const char *p[] = {cl->silence[i]};
            client_reply(cl, N_SILELIST, p, 1, NULL);
        }
        client_reply(cl, N_ENDOFSILELIST, NULL, 0, "End of SILENCE list");
        return;
    }
    for (int i = 0; i < msg->nparams; i++) {
        const char *entry = msg->params[i];
        if (entry[0] == '-') {
            for (int j = 0; j < cl->n_silence; j++) {
                if (strcasecmp(cl->silence[j], entry + 1) == 0) {
                    memmove(cl->silence[j], cl->silence[j + 1], (size_t)(cl->n_silence - j - 1) * sizeof cl->silence[0]);
                    cl->n_silence--;
                    break;
                }
            }
        } else if (cl->n_silence < MAX_SILENCE) {
            const char *mask = entry[0] == '+' ? entry + 1 : entry;
            snprintf(cl->silence[cl->n_silence], sizeof cl->silence[0], "%s", mask);
            cl->n_silence++;
        }
        /* else: silently refuse past the cap, same as +b/+e/+I past CHAN_MAX_MASKLIST */
    }
}

void cmd_glob(server_t *srv, client_t *cl, irc_message_t *msg) {
    char pattern[NICKLEN];
    irc_casefold(pattern, sizeof pattern, msg->params[0]);
    client_t *u, *tmp;
    HASH_ITER(hh, srv->users, u, tmp) {
        if (!u->registered) continue;
        char cf[NICKLEN]; irc_casefold(cf, sizeof cf, u->nick);
        if (!irc_glob_match(pattern, cf)) continue;
        if ((u->umodes & UMODE_I) && !(cl->umodes & UMODE_O) && u != cl) {
            /* +i: hidden from a server-wide search unless a channel is shared */
            int shared = 0;
            for (chan_node_t *a = u->channels; a && !shared; a = a->next)
                for (chan_node_t *b = cl->channels; b; b = b->next)
                    if (a->chan == b->chan) { shared = 1; break; }
            if (!shared) continue;
        }
        char flags[8];
        snprintf(flags, sizeof flags, "%s%s%s", u->is_away ? "G" : "H", visible_oper(u, cl) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "");
        const char *p[] = {"*", u->user, u->host, srv->cfg.server.name, u->nick, flags};
        char trailing[600];
        snprintf(trailing, sizeof trailing, "0 %s", u->realname);
        client_reply(cl, N_WHOREPLY, p, 6, trailing);
    }
    const char *pe[] = {msg->params[0]};
    client_reply(cl, N_ENDOFWHO, pe, 1, "End of /GLOB list.");
}

/* --- CHATHISTORY (draft/chathistory) -------------------------------------- */

static void chathistory_fail(server_t *srv, client_t *cl, const char *code, const char *ctx, const char *desc) {
    char line[400];
    const char *p[] = {"CHATHISTORY", code, ctx};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 3, desc);
    client_send(cl, line);
}

/* Positions of a reference in a conversation: `before` = index of the first entry not strictly older than it,
 * `after` = index of the first entry strictly newer. "msgid=X" pins both to that entry; "timestamp=T" counts by
 * time. Returns 0 on a malformed/unknown reference. */
static int history_ref(const hist_buf_t *b, const char *ref, int *before, int *after) {
    if (strncmp(ref, "msgid=", 6) == 0) {
        for (int i = 0; i < b->n; i++) {
            if (strcmp(hist_buf_at(b, i)->msgid, ref + 6) == 0) { *before = i; *after = i + 1; return 1; }
        }
        return 0;
    }
    if (strncmp(ref, "timestamp=", 10) == 0) {
        long long ms = irc_parse_iso8601_ms(ref + 10);
        if (ms < 0) return 0;
        int bi = 0, ai = 0;
        for (int i = 0; i < b->n; i++) {
            long long e = hist_buf_at(b, i)->ms;
            if (e < ms) bi++;
            if (e <= ms) ai++;
        }
        *before = bi; *after = ai;
        return 1;
    }
    return 0;
}

#define CHATHISTORY_MAX 100

/* Sends "BATCH +id <type> [arg]" and returns the batch id (static, valid until the next call). */
static const char *batch_open(server_t *srv, client_t *cl, const char *type, const char *arg) {
    static unsigned long seq = 0;
    static char bid[24];
    char start[40], line[300];
    snprintf(bid, sizeof bid, "ch%lu", ++seq);
    snprintf(start, sizeof start, "+%s", bid);
    const char *bp[] = {start, type, arg};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "BATCH", bp, arg ? 3 : 2, NULL);
    client_send(cl, line);
    return bid;
}

static void batch_close(server_t *srv, client_t *cl, const char *bid) {
    char end[40], line[200];
    snprintf(end, sizeof end, "-%s", bid);
    const char *ep[] = {end};
    irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "BATCH", ep, 1, NULL);
    client_send(cl, line);
}

/* CHATHISTORY TARGETS <ts> <ts> <limit>: conversations (channels you are in, DM partners) with their newest message
 * time inside the window, newest first. */
static void chathistory_targets(server_t *srv, client_t *cl, irc_message_t *msg) {
    long long t1 = msg->nparams > 1 && strncmp(msg->params[1], "timestamp=", 10) == 0 ? irc_parse_iso8601_ms(msg->params[1] + 10) : -1;
    long long t2 = msg->nparams > 2 && strncmp(msg->params[2], "timestamp=", 10) == 0 ? irc_parse_iso8601_ms(msg->params[2] + 10) : -1;
    int limit = msg->nparams > 3 ? atoi(msg->params[3]) : 0;
    if (t1 < 0 || t2 < 0 || limit < 1) { chathistory_fail(srv, cl, "INVALID_PARAMS", "TARGETS", "Invalid timestamps or limit"); return; }
    if (limit > CHATHISTORY_MAX) limit = CHATHISTORY_MAX;
    long long lo = t1 < t2 ? t1 : t2, hi = t1 < t2 ? t2 : t1;
    typedef struct { char name[72]; long long ms; } tgt_t;
    tgt_t found[CHATHISTORY_MAX * 2];
    int nf = 0;
    for (chan_node_t *n = cl->channels; n && nf < CHATHISTORY_MAX * 2; n = n->next) {
        char key[160];
        history_key_channel(key, sizeof key, n->chan->name);
        hist_buf_t *b = history_get(srv, key);
        if (b && b->n && b->last_ms >= lo && b->last_ms <= hi) { snprintf(found[nf].name, sizeof found[nf].name, "%s", n->chan->name); found[nf++].ms = b->last_ms; }
    }
    if (cl->account[0]) {
        char mine[72];
        irc_casefold(mine, sizeof mine, cl->account);
        hist_buf_t *b, *tmp;
        HASH_ITER(hh, srv->history, b, tmp) {
            if (!history_key_is_dm(b->key) || !b->n || b->last_ms < lo || b->last_ms > hi || nf >= CHATHISTORY_MAX * 2) continue;
            char k[160], *a = k + 1, *sep;
            snprintf(k, sizeof k, "%s", b->key);
            sep = strchr(a, '\x01');
            if (!sep) continue;
            *sep = '\0';
            const char *other = strcmp(a, mine) == 0 ? sep + 1 : strcmp(sep + 1, mine) == 0 ? a : NULL;
            if (!other) continue;
            snprintf(found[nf].name, sizeof found[nf].name, "%s", other);
            found[nf++].ms = b->last_ms;
        }
    }
    for (int i = 0; i < nf; i++) /* newest first */
        for (int j = i + 1; j < nf; j++)
            if (found[j].ms > found[i].ms) { tgt_t t = found[i]; found[i] = found[j]; found[j] = t; }
    const char *bid = batch_open(srv, cl, "draft/chathistory-targets", NULL);
    for (int i = 0; i < nf && i < limit; i++) {
        char ts[40], line[300], val[48];
        irc_iso8601_from_ms(ts, sizeof ts, found[i].ms);
        snprintf(val, sizeof val, "timestamp=%s", ts);
        irc_tag_t bt = {"batch", bid};
        const char *p[] = {"TARGETS", found[i].name, val};
        irc_build(line, sizeof line, &bt, 1, srv->cfg.server.name, "CHATHISTORY", p, 3, NULL);
        client_send(cl, line);
    }
    batch_close(srv, cl, bid);
}

void cmd_chathistory(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (!(cl->caps & CAP_CHATHISTORY) || !(cl->caps & CAP_BATCH) || srv->cfg.messages.history_size <= 0) return;
    const char *sub = msg->params[0];
    if (strcasecmp(sub, "TARGETS") == 0) { chathistory_targets(srv, cl, msg); return; }
    int nneed = strcasecmp(sub, "BETWEEN") == 0 ? 5 : 4; /* sub target ref [ref2] limit */
    if (msg->nparams < nneed) { chathistory_fail(srv, cl, "NEED_MORE_PARAMS", sub, "Missing parameters"); return; }
    const char *target = msg->params[1];

    /* Which conversation? A channel you are in (or any, as an oper), or a private chat with another account. */
    char key[160];
    const hist_buf_t *b = NULL;
    const char *shown = target;
    if (target[0] == '#') {
        channel_t *chan = server_find_channel(srv, target);
        if (!chan || !(channel_find_member(chan, cl) || (cl->umodes & UMODE_O))) {
            chathistory_fail(srv, cl, "INVALID_TARGET", target, "Messages could not be retrieved"); /* same answer for "no such" and "not on it" */
            return;
        }
        history_key_channel(key, sizeof key, chan->name);
        shown = chan->name;
    } else {
        if (!cl->account[0] || !srv->cfg.messages.history_dm) { chathistory_fail(srv, cl, "INVALID_TARGET", target, "Messages could not be retrieved"); return; }
        client_t *other = server_find_user(srv, target);
        const char *oacct = (other && other->registered && other->account[0]) ? other->account : (accounts_exists(&srv->accounts, target) ? target : NULL);
        if (!oacct) { chathistory_fail(srv, cl, "INVALID_TARGET", target, "Messages could not be retrieved"); return; }
        history_key_dm(key, sizeof key, cl->account, oacct);
    }
    b = history_get(srv, key);
    static const hist_buf_t empty = {0};
    if (!b) b = &empty;

    int limit = atoi(msg->params[nneed - 1]);
    if (limit < 1) { chathistory_fail(srv, cl, "INVALID_PARAMS", sub, "Invalid limit"); return; }
    if (limit > CHATHISTORY_MAX) limit = CHATHISTORY_MAX;
    int n = b->n, lo = 0, hi = n;
    int b1 = 0, a1 = 0, b2 = 0, a2 = 0;
    const char *ref = msg->params[2];
    int is_star = strcmp(ref, "*") == 0;
    if (strcasecmp(sub, "LATEST") == 0) {
        if (!is_star && !history_ref(b, ref, &b1, &a1)) { chathistory_fail(srv, cl, "INVALID_PARAMS", ref, "Invalid reference"); return; }
        lo = is_star ? 0 : a1;
        if (n - lo > limit) lo = n - limit;
    } else if (strcasecmp(sub, "BEFORE") == 0) {
        if (!history_ref(b, ref, &b1, &a1)) { chathistory_fail(srv, cl, "INVALID_PARAMS", ref, "Invalid reference"); return; }
        hi = b1; lo = hi - limit < 0 ? 0 : hi - limit;
    } else if (strcasecmp(sub, "AFTER") == 0) {
        if (!history_ref(b, ref, &b1, &a1)) { chathistory_fail(srv, cl, "INVALID_PARAMS", ref, "Invalid reference"); return; }
        lo = a1; hi = lo + limit > n ? n : lo + limit;
    } else if (strcasecmp(sub, "AROUND") == 0) {
        if (!history_ref(b, ref, &b1, &a1)) { chathistory_fail(srv, cl, "INVALID_PARAMS", ref, "Invalid reference"); return; }
        int half = limit / 2;
        lo = b1 - half < 0 ? 0 : b1 - half;
        hi = b1 + (limit - half) > n ? n : b1 + (limit - half);
    } else if (strcasecmp(sub, "BETWEEN") == 0) {
        if (!history_ref(b, ref, &b1, &a1) || !history_ref(b, msg->params[3], &b2, &a2)) {
            chathistory_fail(srv, cl, "INVALID_PARAMS", sub, "Invalid reference"); return;
        }
        if (b1 > b2) { int t = a1; a1 = a2; a2 = t; t = b1; b1 = b2; b2 = t; } /* either order */
        lo = a1; hi = b2;
        if (hi - lo > limit) hi = lo + limit;
    } else {
        chathistory_fail(srv, cl, "INVALID_PARAMS", sub, "Unknown subcommand");
        return;
    }
    if (hi < lo) hi = lo;

    const char *bid = batch_open(srv, cl, "chathistory", shown);
    char line[1100];
    for (int i = lo; i < hi; i++) {
        const hist_entry_t *e = hist_buf_at(b, i);
        char ts[40];
        irc_iso8601_from_ms(ts, sizeof ts, e->ms);
        irc_tag_t tags[4];
        int nt = 0;
        tags[nt++] = (irc_tag_t){"batch", bid};
        tags[nt++] = (irc_tag_t){"time", ts};
        tags[nt++] = (irc_tag_t){"msgid", e->msgid};
        if (e->account[0] && (cl->caps & CAP_ACCOUNT_TAG)) tags[nt++] = (irc_tag_t){"account", e->account};
        const char *mp[] = {target[0] == '#' ? shown : e->target};
        irc_build(line, sizeof line, tags, nt, e->sender, e->verb, mp, 1, e->text);
        client_send(cl, line);
    }
    batch_close(srv, cl, bid);
}

/* srv->n_watchers counts clients with a non-empty MONITOR/WATCH list, so
 * server_monitor_notify/server_watch_notify can return at once (they otherwise
 * walk every connection on every connect, quit and nick change). */
static void refresh_watcher_flag(server_t *srv, client_t *cl) {
    int now = cl->n_monitor > 0 || cl->n_watch > 0;
    if (now != cl->is_watcher) { srv->n_watchers += now ? 1 : -1; cl->is_watcher = now; }
}

void cmd_monitor(server_t *srv, client_t *cl, irc_message_t *msg) { monitor_impl(srv, cl, msg); refresh_watcher_flag(srv, cl); }
void cmd_watch(server_t *srv, client_t *cl, irc_message_t *msg) { watch_impl(srv, cl, msg); refresh_watcher_flag(srv, cl); }

/* ACCEPT [nick[,nick...]] -- caller-ID (+g) allow list. "-nick" removes, "*" or no argument lists. */
void cmd_accept(server_t *srv, client_t *cl, irc_message_t *msg) {
    char list[400];
    snprintf(list, sizeof list, "%s", msg->nparams > 0 ? msg->params[0] : "*");
    char *save = NULL;
    for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (strcmp(tok, "*") == 0) {
            for (int i = 0; i < cl->n_accept; i++) {
                const char *p[] = {cl->accept[i].nick};
                client_reply(cl, N_ACCEPTLIST, p, 1, NULL);
            }
            client_reply(cl, N_ENDOFACCEPT, NULL, 0, "End of /ACCEPT list");
            continue;
        }
        int del = tok[0] == '-';
        const char *nick = del ? tok + 1 : tok;
        if (!irc_valid_nick(nick, NICKLEN - 1)) { const char *p[] = {nick}; client_reply(cl, N_ERRONEUSNICKNAME, p, 1, "Erroneous nickname"); continue; }
        char cf[NICKLEN];
        irc_casefold(cf, sizeof cf, nick);
        int at = -1;
        for (int i = 0; i < cl->n_accept; i++) if (strcmp(cl->accept[i].nick, cf) == 0) { at = i; break; }
        if (del) {
            if (at < 0) { client_reply(cl, N_ACCEPTNOT, NULL, 0, "is not on your accept list"); continue; }
            memmove(&cl->accept[at], &cl->accept[at + 1], (size_t)(cl->n_accept - at - 1) * sizeof cl->accept[0]);
            cl->n_accept--;
        } else {
            if (at >= 0) { client_reply(cl, N_ACCEPTEXIST, NULL, 0, "is already on your accept list"); continue; }
            if (cl->n_accept >= (int)(sizeof cl->accept / sizeof cl->accept[0])) { client_reply(cl, N_ACCEPTFULL, NULL, 0, "Accept list is full"); continue; }
            /* Bind to the person currently using the nick (see client.h), not just the string. */
            client_t *who = server_find_user(srv, nick);
            int k = cl->n_accept++;
            snprintf(cl->accept[k].nick, NICKLEN, "%s", cf);
            cl->accept[k].account[0] = '\0';
            cl->accept[k].conn_id = 0;
            if (who && who->registered && !who->is_service) {
                if (who->account[0]) snprintf(cl->accept[k].account, sizeof cl->accept[k].account, "%s", who->account);
                else cl->accept[k].conn_id = who->conn_id;
            }
        }
    }
}

/* --- MARKREAD (draft/read-marker) --------------------------------------------- */

static void send_marker(client_t *to, const char *target, long long ms) {
    char line[300], val[80], ts[40];
    if (ms > 0) { irc_iso8601_from_ms(ts, sizeof ts, ms); snprintf(val, sizeof val, "timestamp=%s", ts); }
    else snprintf(val, sizeof val, "timestamp=*");
    const char *p[] = {target, val};
    irc_build(line, sizeof line, NULL, 0, to->srv->cfg.server.name, "MARKREAD", p, 2, NULL);
    client_send(to, line);
}

/* MARKREAD <target> [timestamp=<ISO>]: query or advance your read position in a channel/DM; every session of the
 * same account that negotiated the cap is told, so clients stay in sync. */
void cmd_markread(server_t *srv, client_t *cl, irc_message_t *msg) {
    char line[300];
    const char *target = msg->params[0];
    if (!(cl->caps & CAP_READ_MARKER)) return;
    if (!cl->account[0]) {
        const char *p[] = {"MARKREAD", "ACCOUNT_REQUIRED", target};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 3, "You must be logged in to use read markers");
        client_send(cl, line);
        return;
    }
    int is_chan = target[0] == '#';
    channel_t *chan = is_chan ? server_find_channel(srv, target) : NULL;
    if (is_chan ? (!chan || !channel_find_member(chan, cl)) : !irc_valid_nick(target, NICKLEN - 1)) {
        const char *p[] = {"MARKREAD", "INVALID_PARAMS", target};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 3, "Invalid target");
        client_send(cl, line);
        return;
    }
    if (msg->nparams < 2) { send_marker(cl, is_chan ? chan->name : target, server_marker_get(srv, cl->account, target)); return; }
    long long ms = strncmp(msg->params[1], "timestamp=", 10) == 0 ? irc_parse_iso8601_ms(msg->params[1] + 10) : -1;
    if (ms < 0) {
        const char *p[] = {"MARKREAD", "INVALID_PARAMS", msg->params[1]};
        irc_build(line, sizeof line, NULL, 0, srv->cfg.server.name, "FAIL", p, 3, "Invalid timestamp");
        client_send(cl, line);
        return;
    }
    long long stored = server_marker_set(srv, cl->account, target, ms);
    for (client_t *c = srv->all_clients; c; c = c->all_next)
        if (c->fd >= 0 && !c->quitting && (c->caps & CAP_READ_MARKER) && c->account[0] && strcasecmp(c->account, cl->account) == 0)
            send_marker(c, is_chan ? chan->name : target, stored);
}
