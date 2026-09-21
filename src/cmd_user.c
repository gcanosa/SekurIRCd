/* Messaging and lookups: PRIVMSG, NOTICE, WHOIS, WHO, WHOWAS, AWAY, SETNAME,
 * USERHOST, ISON, MONITOR, SILENCE, GLOB. Ported from commands.py. */
#include "cmd.h"

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
#define LINE_SZ 760
static void build_lines(char lines[4][LINE_SZ], client_t *from, const char *prefix, const char *verb,
                        const char **p, const char *text) {
    irc_build(lines[0], LINE_SZ, NULL, 0, prefix, verb, p, 1, text);
    int acct = from->account[0] != '\0', bot = (from->umodes & UMODE_B) != 0;
    irc_tag_t ta = {"account", from->account}, tb = {"bot", ""};
    if (acct) irc_build(lines[1], LINE_SZ, &ta, 1, prefix, verb, p, 1, text);
    if (bot) irc_build(lines[2], LINE_SZ, &tb, 1, prefix, verb, p, 1, text);
    if (acct && bot) { irc_tag_t both[] = {ta, tb}; irc_build(lines[3], LINE_SZ, both, 2, prefix, verb, p, 1, text); }
}

/* account tag needs account-tag; the IRCv3 bot tag needs message-tags. */
static void deliver(client_t *rcpt, client_t *from, char lines[4][LINE_SZ]) {
    int i = ((from->account[0] && (rcpt->caps & CAP_ACCOUNT_TAG)) ? 1 : 0) |
            (((from->umodes & UMODE_B) && (rcpt->caps & CAP_MESSAGE_TAGS)) ? 2 : 0);
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

static void send_msg(server_t *srv, client_t *cl, irc_message_t *msg, const char *verb, int is_notice) {
    const char *target = msg->params[0];
    if (msg->nparams < 2) {
        if (!is_notice) client_reply(cl, N_NOTEXTTOSEND, NULL, 0, "No text to send");
        return;
    }
    /* Flood guard is enforced once, per-line, in net.c before dispatch --
     * same choke-point architecture as server._read_loop in the Python
     * daemon (see CLAUDE.md's "Security invariants to preserve"). */
    char textbuf[420];
    snprintf(textbuf, sizeof textbuf, "%.*s", srv->cfg.messages.max_message_length, msg->params[msg->nparams - 1]);

    if (spam_check_message(srv, cl, target, textbuf, is_notice)) return;

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char lines[4][LINE_SZ];

    /* STATUSMSG (ISUPPORT STATUSMSG=@%+): "@#chan"/"%#chan"/"+#chan"
     * delivers only to members holding at least that rank. */
    char status_prefix = '\0';
    const char *chan_target = target;
    if ((target[0] == '@' || target[0] == '%' || target[0] == '+') && target[1] == '#') {
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
        if (!(m && (m->rank & RANK_OP)) && !(cl->umodes & UMODE_O) &&
            channel_is_banned(chan, cl->nick, cl->user, cl->host, cl->account, cl->ident_confirmed)) {
            if (!is_notice) { const char *pe[] = {target}; client_reply(cl, N_CANNOTSENDTOCHAN, pe, 1, "Cannot send to channel (+b)"); }
            return;
        }
        char stripbuf[420];
        const char *outtext = textbuf;
        if (chan->modes & CMODE_STRIPCOLOR) { strip_formatting(stripbuf, sizeof stripbuf, textbuf); outtext = stripbuf; }

        build_lines(lines, cl, prefix, verb, p, outtext);

        member_t *mm, *tmp;
        if (status_prefix) {
            int min_rank = (status_prefix == '@') ? RANK_OP : (status_prefix == '%') ? RANK_HALFOP : RANK_VOICE;
            HASH_ITER(hh, chan->members, mm, tmp) {
                if (mm->client == cl) continue;
                int rank = mm->rank;
                int has_it = (min_rank == RANK_OP) ? (rank & RANK_OP)
                           : (min_rank == RANK_HALFOP) ? (rank & (RANK_OP | RANK_HALFOP))
                           : (rank & (RANK_OP | RANK_HALFOP | RANK_VOICE));
                if (has_it) deliver(mm->client, cl, lines);
            }
            return; /* STATUSMSG has no echo-message in upstream either */
        }

        HASH_ITER(hh, chan->members, mm, tmp) {
            if (mm->client == cl) continue;
            deliver(mm->client, cl, lines);
        }
        delivered = 1;
    } else {
        client_t *dst = server_find_user(srv, target);
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
            client_reply(cl, N_NONONREG, pe, 1, "is not accepting private messages");
            return;
        }
        if ((dst->umodes & UMODE_REGONLY) && !cl->account[0] && !(cl->umodes & UMODE_O) && cl != dst) {
            const char *pe[] = {dst->nick};
            client_reply(cl, N_NONONREG, pe, 1, "is only accepting messages from registered users");
            return;
        }
        if (!is_notice && dst->is_away) {
            const char *pa[] = {dst->nick};
            client_reply(cl, N_AWAY, pa, 1, dst->away);
        }
        build_lines(lines, cl, prefix, verb, p, textbuf);
        deliver(dst, cl, lines);
        delivered = 1;
    }
    /* IRCv3 echo-message: the sender gets its own message back too, once
     * delivery actually happened. */
    if (delivered && (cl->caps & CAP_ECHO_MESSAGE)) deliver(cl, cl, lines);
}

void cmd_privmsg(server_t *srv, client_t *cl, irc_message_t *msg) { send_msg(srv, cl, msg, "PRIVMSG", 0); }
void cmd_notice(server_t *srv, client_t *cl, irc_message_t *msg) { send_msg(srv, cl, msg, "NOTICE", 1); }

static void whois_one(server_t *srv, client_t *cl, const char *nick) {
    client_t *target = server_find_user(srv, nick);
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
            const char *rankch = (m && (m->rank & RANK_OP)) ? "@" : (m && (m->rank & RANK_HALFOP)) ? "%" : (m && (m->rank & RANK_VOICE)) ? "+" : "";
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

static void who_rank_flags(int rank, int multi, char *out) {
    if (multi) {
        if (rank & RANK_OP) *out++ = '@';
        if (rank & RANK_HALFOP) *out++ = '%';
        if (rank & RANK_VOICE) *out++ = '+';
    } else if (rank & RANK_OP) *out++ = '@';
    else if (rank & RANK_HALFOP) *out++ = '%';
    else if (rank & RANK_VOICE) *out++ = '+';
    *out = '\0';
}

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
        char rankch[4];
        who_rank_flags(m ? m->rank : 0, multi, rankch);
        snprintf(scratch, scratchsz, "%s%s%s%s", u->is_away ? "G" : "H", (u->umodes & UMODE_O) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "", rankch);
        return scratch;
    }
    case 'd': return "0";
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
    for (const char *f = fields; *f && np < 16 && nscratch < 16; f++) {
        if (*f == 'r') { trailing = u->realname; continue; }
        p[np++] = whox_value(*f, u, chan, cl, token, scratch[nscratch], sizeof scratch[nscratch]);
        nscratch++;
    }
    client_reply(cl, N_WHOSPCRPL, p + 1, np - 1, trailing);
}

static void send_who_classic(client_t *cl, client_t *u, channel_t *chan, int multi) {
    char rankch[4];
    member_t *m = chan ? channel_find_member(chan, u) : NULL;
    who_rank_flags(m ? m->rank : 0, multi, rankch);
    char flags[10];
    snprintf(flags, sizeof flags, "%s%s%s%s", u->is_away ? "G" : "H", (u->umodes & UMODE_O) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "", rankch);
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
        HASH_ITER(hh, chan->members, m, tmp) {
            if (whox_fields) send_whox_reply(cl, whox_fields, whox_token, m->client, chan);
            else send_who_classic(cl, m->client, chan, multi);
        }
    } else {
        client_t *u = server_find_user(srv, target);
        if (!u) {
            const char *p[] = {target};
            client_reply(cl, N_NOSUCHNICK, p, 1, "No such nick/channel");
            return;
        }
        for (chan_node_t *n = u->channels; n; n = n->next) {
            channel_t *chan = n->chan;
            if ((chan->modes & (CMODE_S | CMODE_P)) && !channel_find_member(chan, cl)) continue;
            if (whox_fields) send_whox_reply(cl, whox_fields, whox_token, u, chan);
            else send_who_classic(cl, u, chan, multi);
        }
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
}

void cmd_away(server_t *srv, client_t *cl, irc_message_t *msg) {
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
}

void cmd_userhost(server_t *srv, client_t *cl, irc_message_t *msg) {
    char out[500] = "";
    for (int i = 0; i < msg->nparams && i < 5; i++) {
        client_t *u = server_find_user(srv, msg->params[i]);
        if (!u) continue;
        char entry[300];
        snprintf(entry, sizeof entry, "%s%s%s=%c%s@%s", out[0] ? " " : "", u->nick,
                 (u->umodes & UMODE_O) ? "*" : "", u->is_away ? '-' : '+', u->user, u->host);
        strncat(out, entry, sizeof out - strlen(out) - 1);
    }
    client_reply(cl, N_USERHOST, NULL, 0, out);
}

void cmd_ison(server_t *srv, client_t *cl, irc_message_t *msg) {
    char out[500] = "";
    for (int i = 0; i < msg->nparams; i++) {
        if (!server_find_user(srv, msg->params[i])) continue;
        if (out[0]) strncat(out, " ", sizeof out - strlen(out) - 1);
        strncat(out, msg->params[i], sizeof out - strlen(out) - 1);
    }
    client_reply(cl, N_ISON, NULL, 0, out);
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

void cmd_monitor(server_t *srv, client_t *cl, irc_message_t *msg) {
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
void cmd_watch(server_t *srv, client_t *cl, irc_message_t *msg) {
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
        snprintf(flags, sizeof flags, "%s%s%s", u->is_away ? "G" : "H", (u->umodes & UMODE_O) ? "*" : "", (u->umodes & UMODE_B) ? "B" : "");
        const char *p[] = {"*", u->user, u->host, srv->cfg.server.name, u->nick, flags};
        char trailing[600];
        snprintf(trailing, sizeof trailing, "0 %s", u->realname);
        client_reply(cl, N_WHOREPLY, p, 6, trailing);
    }
    const char *pe[] = {msg->params[0]};
    client_reply(cl, N_ENDOFWHO, pe, 1, "End of /GLOB list.");
}
