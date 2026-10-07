/* Channels: JOIN, PART, TOPIC, NAMES, LIST, KICK, MODE, INVITE, KNOCK,
 * LINKS, MAP, SAJOIN, SAPART, SAMODE. Ported from commands.py's channel
 * handlers. Not yet ported: STATUSMSG delivery lives in cmd_user.c
 * (PRIVMSG/NOTICE); EXTBAN a: lives in channel.c's mask matcher. */
#include "cmd.h"
#include "link.h"
#include "log.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define MAX_CHANNELS_PER_CLIENT 200

#define invite_key_of(c) client_invite_key(c)

static void send_names(client_t *cl, channel_t *chan) {
    char line[400]; /* + ":server 353 nick = #chan :" must stay under 512 */
    size_t pos = 0;
    line[0] = '\0';
    const char *chantype = "=";
    if (chan->modes & CMODE_S) chantype = "@"; /* secret wins over private */
    else if (chan->modes & CMODE_P) chantype = "*";

    int multi = cl->caps & CAP_MULTI_PREFIX;
    int userhost = cl->caps & CAP_USERHOST_IN_NAMES;

    member_t *m, *tmp;
    member_t *viewer = channel_find_member(chan, cl);
    HASH_ITER(hh, chan->members, m, tmp) {
        if (!channel_member_visible(chan, m, viewer)) continue; /* +D not yet revealed / +u unranked */
        char nickbuf[NICKLEN + HOSTLEN + 8];
        char rankch[8];
        channel_rank_prefix(m->rank, multi, rankch);
        if (userhost) snprintf(nickbuf, sizeof nickbuf, "%s%s!%s@%s", rankch, m->client->nick, m->client->user, m->client->host);
        else snprintf(nickbuf, sizeof nickbuf, "%s%s", rankch, m->client->nick);
        size_t nl = strlen(nickbuf);
        if (pos + nl + 1 >= sizeof line - 1) {
            const char *p[] = {chantype, chan->name};
            client_reply(cl, N_NAMEREPLY, p, 2, line);
            pos = 0;
            line[0] = '\0';
        }
        if (pos > 0) line[pos++] = ' ';
        memcpy(line + pos, nickbuf, nl);
        pos += nl;
        line[pos] = '\0';
    }
    const char *p[] = {chantype, chan->name};
    client_reply(cl, N_NAMEREPLY, p, 2, line);
    const char *pe[] = {chan->name};
    client_reply(cl, N_ENDOFNAMES, pe, 1, "End of /NAMES list.");
}

static void send_join_burst(client_t *cl, channel_t *chan);

void cmd_announce_join(channel_t *chan, client_t *cl) {
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);

    /* IRCv3 extended-join: JOIN carries the account (or "*") and realname
     * for members that negotiated it; everyone else gets the plain form. */
    char plain_join[400], ext_join[600];
    const char *p1[] = {chan->name};
    irc_build(plain_join, sizeof plain_join, NULL, 0, prefix, "JOIN", p1, 1, NULL);
    const char *p2[] = {chan->name, cl->account[0] ? cl->account : "*"};
    irc_build(ext_join, sizeof ext_join, NULL, 0, prefix, "JOIN", p2, 2, cl->realname);

    char account_line[300];
    const char *p3[] = {cl->account};
    irc_build(account_line, sizeof account_line, NULL, 0, prefix, "ACCOUNT", p3, 1, NULL);

    member_t *m, *tmp;
    member_t *subject = channel_find_member(chan, cl);
    HASH_ITER(hh, chan->members, m, tmp) {
        if (subject && !channel_member_visible(chan, subject, m)) continue; /* +D hidden / +u audience: this member isn't told */
        client_send(m->client, (m->client->caps & CAP_EXTENDED_JOIN) ? ext_join : plain_join);
        /* account-notify's own ACCOUNT line would just duplicate what
         * extended-join already embedded in JOIN -- skip it for those. */
        if (cl->account[0] && (m->client->caps & CAP_ACCOUNT_NOTIFY) && !(m->client->caps & CAP_EXTENDED_JOIN))
            client_send(m->client, account_line);
    }
    link_notify_channel_join(chan, cl);
    send_join_burst(cl, chan);
}

/* Topic + (unless draft/no-implicit-names) the member list: what a client gets right after joining. */
static void send_join_burst(client_t *cl, channel_t *chan) {
    if ((cl->caps & CAP_READ_MARKER) && cl->account[0]) { /* draft/read-marker: where this account stopped reading here */
        long long ms = server_marker_get(cl->srv, cl->account, chan->name);
        char line[300], val[80], ts[40];
        if (ms > 0) { irc_iso8601_from_ms(ts, sizeof ts, ms); snprintf(val, sizeof val, "timestamp=%s", ts); }
        else snprintf(val, sizeof val, "timestamp=*");
        const char *p[] = {chan->name, val};
        irc_build(line, sizeof line, NULL, 0, cl->srv->cfg.server.name, "MARKREAD", p, 2, NULL);
        client_send(cl, line);
    }
    if (chan->topic[0]) {
        const char *pt[] = {chan->name};
        client_reply(cl, N_TOPIC, pt, 1, chan->topic);
        char tbuf[32];
        snprintf(tbuf, sizeof tbuf, "%ld", (long)chan->topic_time);
        const char *p3[] = {chan->name, chan->topic_setter, tbuf};
        client_reply(cl, N_TOPICWHOTIME, p3, 3, NULL);
    } else {
        const char *pt[] = {chan->name};
        client_reply(cl, N_NOTOPIC, pt, 1, "No topic is set");
    }
    if (!(cl->caps & CAP_NO_IMPLICIT_NAMES)) send_names(cl, chan); /* draft/no-implicit-names: client will ask itself */
}

/* +D: the member has spoken (or been given a rank): tell everyone who can now see them that they joined. */
void channel_reveal_member(channel_t *chan, member_t *m) {
    if (!m->hidden) return;
    m->hidden = 0;
    client_t *cl = m->client;
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char plain[400], ext[600];
    const char *p1[] = {chan->name};
    irc_build(plain, sizeof plain, NULL, 0, prefix, "JOIN", p1, 1, NULL);
    const char *p2[] = {chan->name, cl->account[0] ? cl->account : "*"};
    irc_build(ext, sizeof ext, NULL, 0, prefix, "JOIN", p2, 2, cl->realname);
    member_t *r, *tmp;
    HASH_ITER(hh, chan->members, r, tmp) {
        if (r == m || !channel_member_visible(chan, m, r)) continue; /* the member already saw their own join */
        client_send(r->client, (r->client->caps & CAP_EXTENDED_JOIN) ? ext : plain);
    }
}

static int n_channels_of(client_t *cl) {
    int n = 0;
    for (chan_node_t *n2 = cl->channels; n2; n2 = n2->next) n++;
    return n;
}

void cmd_force_join(server_t *srv, client_t *cl, const char *chan_name) {
    if (!irc_valid_channel(chan_name, 50)) return;
    channel_t *existing = server_find_channel(srv, chan_name);
    int is_new = (existing == NULL);
    channel_t *chan = existing ? existing : server_get_or_create_channel(srv, chan_name);
    if (!chan) return;
    if (channel_find_member(chan, cl)) return;
    member_t *m = channel_add_member(chan, cl);
    if (!m) { server_maybe_drop_channel(srv, chan); return; }
    /* Only op on actually creating the channel, matching do_join_one --
     * "first member currently present" also fired for the first (re)join of
     * an existing, previously-emptied +P channel, handing ops to whoever
     * happened to reconnect first rather than nobody, as a normal JOIN of
     * the same channel would. */
    if (is_new) m->rank |= RANK_OP;
    if (server_attach_membership(cl, chan) != 0) {
        channel_remove_member(chan, cl);
        server_maybe_drop_channel(srv, chan);
        return;
    }
    cmd_announce_join(chan, cl);
    netsync_chan_join(srv, chan, cl, is_new);
}

static void do_join_one(server_t *srv, client_t *cl, const char *chan_name, const char *key);

/* +L: a JOIN refused because the channel is full (+l) or invite-only (+i) is forwarded to the +L target instead.
 * One hop only -- the target's own +L isn't followed, so two channels can't bounce a user around forever. */
static int g_redirect_depth;
static int try_redirect(server_t *srv, client_t *cl, channel_t *chan) {
    if (!(chan->modes & CMODE_REDIRECT) || !chan->redirect[0] || g_redirect_depth) return 0;
    char target[CHAN_NAMELEN];
    snprintf(target, sizeof target, "%s", chan->redirect);
    const char *p[] = {chan->name, target};
    client_reply(cl, N_LINKCHANNEL, p, 2, "Forwarding to another channel");
    g_redirect_depth = 1;
    do_join_one(srv, cl, target, NULL);
    g_redirect_depth = 0;
    return 1;
}

static void do_join_one(server_t *srv, client_t *cl, const char *chan_name, const char *key) {
    if (!irc_valid_channel(chan_name, 50)) {
        err_no_such_channel(cl, chan_name);
        return;
    }
    if (srv->cfg.debug_channel.enabled && !(cl->umodes & UMODE_O)) {
        char cf1[CHAN_NAMELEN], cf2[CHAN_NAMELEN];
        irc_casefold(cf1, sizeof cf1, chan_name);
        irc_casefold(cf2, sizeof cf2, srv->cfg.debug_channel.name);
        if (strcmp(cf1, cf2) == 0) { err_no_such_channel(cl, chan_name); return; }
    }
    channel_t *chan = server_find_channel(srv, chan_name);
    if (chan && channel_find_member(chan, cl)) {
        const char *p[] = {chan->name};
        client_reply(cl, N_USERONCHANNEL, p, 1, "You're already on that channel");
        return;
    }
    if (n_channels_of(cl) >= MAX_CHANNELS_PER_CLIENT && !(cl->umodes & UMODE_O)) {
        const char *p[] = {chan_name};
        client_reply(cl, N_TOOMANYCHANNELS, p, 1, "You have joined too many channels");
        return;
    }
    int is_new = (chan == NULL);

    if (is_new) {
        if (srv->cfg.channels.restrict_creation && !(cl->umodes & UMODE_O)) {
            int allowed = 0;
            for (int i = 0; i < srv->cfg.channels.n_allowed_channels; i++) {
                if (strcasecmp(srv->cfg.channels.allowed_channels[i], chan_name) == 0) { allowed = 1; break; }
            }
            if (!allowed) { err_no_such_channel(cl, chan_name); return; }
        }
        chan = server_get_or_create_channel(srv, chan_name);
        if (!chan) { err_no_such_channel(cl, chan_name); return; }
    } else if (!(cl->umodes & UMODE_O)) {
        ban_extra_t bx = {cl->realname, (cl->umodes & UMODE_Z) != 0, cl};
        channel_set_ban_extra(&bx); /* for ~r/~z/~j in +b/+e/+I */
        if ((chan->modes & CMODE_I) && !channel_is_invited(chan, invite_key_of(cl), cl->nick, cl->user, cl->host, cl->account, cl->ident_confirmed)) {
            const char *p[] = {chan->name};
            if (try_redirect(srv, cl, chan)) return;
            client_reply(cl, N_INVITEONLYCHAN, p, 1, "Cannot join channel (+i)");
            return;
        }
        if ((chan->modes & CMODE_K) && chan->key[0] && (!key || strcmp(key, chan->key) != 0)) {
            const char *p[] = {chan->name};
            client_reply(cl, N_NOCHANNELKEY, p, 1, "Cannot join channel (+k)");
            return;
        }
        if ((chan->modes & CMODE_L) && chan->limit > 0 && channel_member_count(chan) >= chan->limit) {
            const char *p[] = {chan->name};
            if (try_redirect(srv, cl, chan)) return;
            client_reply(cl, N_CHANNELISFULL, p, 1, "Cannot join channel (+l)");
            return;
        }
        if (channel_is_banned(chan, cl->nick, cl->user, cl->host, cl->realhost, cl->ip, cl->account, cl->ident_confirmed)) {
            const char *p[] = {chan->name};
            client_reply(cl, N_BANNED, p, 1, "Cannot join channel (+b)");
            return;
        }
        if ((chan->modes & CMODE_Z) && !(cl->umodes & UMODE_Z)) {
            const char *p[] = {chan->name};
            client_reply(cl, N_SECUREONLYCHAN, p, 1, "Cannot join channel (+z, requires a secure connection)");
            return;
        }
        if ((chan->modes & CMODE_REGONLY) && !cl->account[0]) {
            const char *p[] = {chan->name};
            client_reply(cl, N_NEEDREGGEDNICK, p, 1, "Cannot join channel (+R, requires a registered account)");
            return;
        }
        if (chan->modes & CMODE_OPERONLY) { /* already past the UMODE_O bypass above, so this branch means not-oper */
            const char *p[] = {chan->name};
            client_reply(cl, N_NEEDREGGEDNICK, p, 1, "Cannot join channel (+O, IRC operators only)");
            return;
        }
        if ((chan->modes & CMODE_JTHROT) && chan->jt_joins > 0) {
            time_t now = time(NULL);
            if (now - chan->jt_start >= chan->jt_secs) { chan->jt_start = now; chan->jt_count = 0; }
            if (++chan->jt_count > chan->jt_joins) { /* attempts count too, so a retry loop can't slip through */
                const char *p[] = {chan->name};
                client_reply(cl, N_CHANNELISFULL, p, 1, "Cannot join channel (+j, joining too fast -- try again shortly)");
                return;
            }
        }
    }

    member_t *m = channel_add_member(chan, cl);
    if (!m) { server_maybe_drop_channel(srv, chan); err_no_such_channel(cl, chan_name); return; }
    if (is_new) m->rank |= RANK_OP;
    if ((chan->modes & CMODE_DELAYJOIN) && m->rank == 0) m->hidden = 1; /* +D: invisible until they speak */
    channel_invite_remove(chan, invite_key_of(cl));
    if (server_attach_membership(cl, chan) != 0) {
        channel_remove_member(chan, cl);
        server_maybe_drop_channel(srv, chan);
        err_no_such_channel(cl, chan_name);
        return;
    }
    cmd_announce_join(chan, cl);
    netsync_chan_join(srv, chan, cl, is_new);
}

void cmd_join(server_t *srv, client_t *cl, irc_message_t *msg) {
    char chanlist[600];
    snprintf(chanlist, sizeof chanlist, "%s", msg->params[0]);
    char keylist[600];
    keylist[0] = '\0';
    if (msg->nparams > 1) snprintf(keylist, sizeof keylist, "%s", msg->params[1]);

    char *chan_save = NULL, *key_save = NULL;
    char *chan_tok = strtok_r(chanlist, ",", &chan_save);
    char *key_tok = keylist[0] ? strtok_r(keylist, ",", &key_save) : NULL;
    while (chan_tok) {
        do_join_one(srv, cl, chan_tok, key_tok);
        chan_tok = strtok_r(NULL, ",", &chan_save);
        if (key_tok) key_tok = strtok_r(NULL, ",", &key_save);
    }
}

void cmd_part(server_t *srv, client_t *cl, irc_message_t *msg) {
    char chanlist[600];
    snprintf(chanlist, sizeof chanlist, "%s", msg->params[0]);
    const char *reason = msg->nparams > 1 ? msg->params[msg->nparams - 1] : NULL;
    if (reason && spam_check_text(srv, cl, SPAM_T_PART, reason)) reason = NULL;

    char *save = NULL;
    char *tok = strtok_r(chanlist, ",", &save);
    while (tok) {
        channel_t *chan = server_find_channel(srv, tok);
        member_t *m = chan ? channel_find_member(chan, cl) : NULL;
        if (!chan || !m) {
            const char *p[] = {tok};
            client_reply(cl, N_NOTONCHANNEL, p, 1, "You're not on that channel");
        } else {
            char prefix[320];
            client_prefix(cl, prefix, sizeof prefix);
            char line[510];
            const char *p[] = {chan->name};
            irc_build(line, sizeof line, NULL, 0, prefix, "PART", p, 1, reason);
            netsync_chan_part(srv, chan, cl, reason);
            { /* only members who could see them in the channel see them leave (+D hidden, +u audience) */
                member_t *pm, *ptmp;
                HASH_ITER(hh, chan->members, pm, ptmp)
                    if (channel_member_visible(chan, m, pm)) client_send(pm->client, line);
            }
            channel_remove_member(chan, cl);
            server_detach_membership(cl, chan);
            server_maybe_drop_channel(srv, chan);
            log_info("chan", "%s left %s", cl->nick, tok);
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

/* RENAME <old> <new> [:reason] (draft/channel-rename): a chanop renames a live channel, keeping members, modes,
 * bans and topic. Clients that negotiated the cap get a RENAME; the rest see themselves part and rejoin. */
void cmd_rename(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *oldname = msg->params[0], *newname = msg->params[1];
    const char *reason = msg->nparams > 2 ? msg->params[msg->nparams - 1] : "No reason";
    channel_t *chan = server_find_channel(srv, oldname);
    if (!chan) { err_no_such_channel(cl, oldname); return; }
    member_t *me = channel_find_member(chan, cl);
    if (!me && !(cl->umodes & UMODE_O)) { const char *p[] = {chan->name}; client_reply(cl, N_NOTONCHANNEL, p, 1, "You're not on that channel"); return; }
    if (!(cl->umodes & UMODE_O) && !(me->rank & (RANK_OP | RANK_HALFOP))) { err_not_channel_op(cl, chan->name); return; }
    char fail[300];
    const char *fp[] = {"RENAME", NULL, chan->name, newname};
    const char *code = NULL, *desc = NULL;
    char ncf[CHAN_NAMELEN];
    irc_casefold(ncf, sizeof ncf, newname);
    channel_t *clash = irc_valid_channel(newname, 50) ? server_find_channel(srv, newname) : NULL;
    if (!irc_valid_channel(newname, 50)) { code = "CANNOT_RENAME"; desc = "That is not a valid channel name"; }
    else if (clash && clash != chan) { code = "CHANNEL_NAME_IN_USE"; desc = "A channel with that name already exists"; }
    else if (chan->modes & CMODE_R) { code = "CANNOT_RENAME"; desc = "A registered channel can't be renamed"; }
    else if (srv->cfg.debug_channel.enabled) {
        char dcf[CHAN_NAMELEN];
        irc_casefold(dcf, sizeof dcf, srv->cfg.debug_channel.name);
        if (strcmp(dcf, ncf) == 0) { code = "CANNOT_RENAME"; desc = "That name is reserved"; }
    }
    if (code) {
        fp[1] = code;
        irc_build(fail, sizeof fail, NULL, 0, srv->cfg.server.name, "FAIL", fp, 4, desc);
        client_send(cl, fail);
        return;
    }
    char old_display[CHAN_NAMELEN];
    snprintf(old_display, sizeof old_display, "%s", chan->name);
    cmd_channel_rename_apply(srv, chan, cl, newname, reason);
    netsync_chan_rename(srv, chan, cl, old_display, reason);
    log_info("chan", "%s renamed %s to %s", cl->nick, old_display, newname);
}

/* The rename itself, shared by the local RENAME command and one arriving from another server: rekey the channel and
 * tell its LOCAL members (RENAME for clients with the cap, a part+join for the rest). */
void cmd_channel_rename_apply(server_t *srv, channel_t *chan, client_t *by, const char *newname, const char *reason) {
    char ncf[CHAN_NAMELEN];
    irc_casefold(ncf, sizeof ncf, newname);
    char old_display[CHAN_NAMELEN];
    snprintf(old_display, sizeof old_display, "%s", chan->name);
    client_t *cl = by;
    char prefix[320], rename_line[500];
    client_prefix(cl, prefix, sizeof prefix);
    const char *rp[] = {old_display, newname};
    irc_build(rename_line, sizeof rename_line, NULL, 0, prefix, "RENAME", rp, 2, reason);

    HASH_DEL(srv->channels, chan);
    snprintf(chan->name, sizeof chan->name, "%s", newname);
    snprintf(chan->casefold_name, sizeof chan->casefold_name, "%s", ncf);
    HASH_ADD_STR(srv->channels, casefold_name, chan);

    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        if (m->client->remote) continue;
        if (m->client->caps & CAP_CHANNEL_RENAME) { client_send(m->client, rename_line); continue; }
        char mp[320], part[500], join[400];
        client_prefix(m->client, mp, sizeof mp);
        const char *pp[] = {old_display};
        irc_build(part, sizeof part, NULL, 0, mp, "PART", pp, 1, reason);
        const char *jp[] = {chan->name};
        irc_build(join, sizeof join, NULL, 0, mp, "JOIN", jp, 1, NULL);
        client_send(m->client, part);
        client_send(m->client, join);
        send_join_burst(m->client, chan);
    }
}

/* --- SAJOIN / SAPART (oper-only overrides) ---------------------------------- */

void cmd_sajoin(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
    if (target->remote) { notice_self(srv, cl, "That user is on another server -- SAJOIN works on local users only"); return; }
    char joined[600] = "";
    char chanlist[600];
    snprintf(chanlist, sizeof chanlist, "%s", msg->params[1]);
    char *save = NULL;
    for (char *tok = strtok_r(chanlist, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!irc_valid_channel(tok, 50)) continue;
        channel_t *existing = server_find_channel(srv, tok);
        if (existing && channel_find_member(existing, target)) continue;
        cmd_force_join(srv, target, tok);
        if (joined[0]) strncat(joined, ", ", sizeof joined - strlen(joined) - 1);
        strncat(joined, tok, sizeof joined - strlen(joined) - 1);
    }
    if (joined[0]) {
        char m[700];
        snprintf(m, sizeof m, "%s joined: %s", target->nick, joined);
        notice_self(srv, cl, m);
        log_info("chan", "%s SAJOINed %s to %s", cl->nick, target->nick, joined);
        char snote[800];
        snprintf(snote, sizeof snote, "%s used SAJOIN to put %s in %s", cl->nick, target->nick, joined);
        server_notify_opers(srv, snote);
    }
}

void cmd_sapart(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
    if (target->remote) { notice_self(srv, cl, "That user is on another server -- SAPART works on local users only"); return; }
    const char *reason = msg->nparams > 2 ? msg->params[2] : cl->nick;
    char parted[600] = "";
    char chanlist[600];
    snprintf(chanlist, sizeof chanlist, "%s", msg->params[1]);
    char *save = NULL;
    for (char *tok = strtok_r(chanlist, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        channel_t *chan = server_find_channel(srv, tok);
        if (!chan || !channel_find_member(chan, target)) continue;
        char prefix[320];
        client_prefix(target, prefix, sizeof prefix);
        char line[500];
        const char *p[] = {chan->name};
        irc_build(line, sizeof line, NULL, 0, prefix, "PART", p, 1, reason);
        server_broadcast_channel(chan, line, NULL);
        netsync_chan_part(srv, chan, target, reason);
        char chan_name_buf[CHAN_NAMELEN];
        snprintf(chan_name_buf, sizeof chan_name_buf, "%s", chan->name); /* chan may be freed below */
        channel_remove_member(chan, target);
        server_detach_membership(target, chan);
        server_maybe_drop_channel(srv, chan);
        if (parted[0]) strncat(parted, ", ", sizeof parted - strlen(parted) - 1);
        strncat(parted, chan_name_buf, sizeof parted - strlen(parted) - 1);
    }
    if (parted[0]) {
        char m[700];
        snprintf(m, sizeof m, "%s parted: %s", target->nick, parted);
        notice_self(srv, cl, m);
        log_info("chan", "%s SAPARTed %s from %s", cl->nick, target->nick, parted);
        char snote[800];
        snprintf(snote, sizeof snote, "%s used SAPART to remove %s from %s", cl->nick, target->nick, parted);
        server_notify_opers(srv, snote);
    }
}

void cmd_topic(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *chan_name = msg->params[0];
    channel_t *chan = server_find_channel(srv, chan_name);
    if (!chan) { err_no_such_channel(cl, chan_name); return; }
    member_t *m = channel_find_member(chan, cl);
    if (!m) {
        const char *p[] = {chan->name};
        client_reply(cl, N_NOTONCHANNEL, p, 1, "You're not on that channel");
        return;
    }

    if (msg->nparams < 2) {
        if (chan->topic[0]) {
            const char *p[] = {chan->name};
            client_reply(cl, N_TOPIC, p, 1, chan->topic);
            char tbuf[32];
            snprintf(tbuf, sizeof tbuf, "%ld", (long)chan->topic_time);
            const char *p3[] = {chan->name, chan->topic_setter, tbuf};
            client_reply(cl, N_TOPICWHOTIME, p3, 3, NULL);
        } else {
            const char *p[] = {chan->name};
            client_reply(cl, N_NOTOPIC, p, 1, "No topic is set");
        }
        return;
    }

    if ((chan->modes & CMODE_T) && !channel_has_ops(chan, cl) && !(cl->umodes & UMODE_O)) {
        err_not_channel_op(cl, chan->name);
        return;
    }
    const char *newtopic = msg->params[msg->nparams - 1];
    if (spam_check_text(srv, cl, SPAM_T_TOPIC, newtopic)) return;
    snprintf(chan->topic, TOPIC_MAX_LEN + 1, "%s", newtopic); /* TOPICLEN: longer would overflow the broadcast line */
    client_prefix(cl, chan->topic_setter, sizeof chan->topic_setter);
    chan->topic_time = time(NULL);

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[510];
    const char *p[] = {chan->name};
    irc_build(line, sizeof line, NULL, 0, prefix, "TOPIC", p, 1, chan->topic);
    server_broadcast_channel(chan, line, NULL);
    netsync_chan_topic(srv, chan, cl, chan->topic);
}

void cmd_names(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1) {
        const char *star[] = {"*"};
        client_reply(cl, N_ENDOFNAMES, star, 1, "End of /NAMES list.");
        return;
    }
    char chanlist[600];
    snprintf(chanlist, sizeof chanlist, "%s", msg->params[0]);
    char *save = NULL;
    char *tok = strtok_r(chanlist, ",", &save);
    while (tok) {
        channel_t *chan = server_find_channel(srv, tok);
        if (chan) {
            if ((chan->modes & (CMODE_S | CMODE_P)) && !channel_find_member(chan, cl)) {
                const char *pe[] = {chan->name};
                client_reply(cl, N_ENDOFNAMES, pe, 1, "End of /NAMES list.");
            } else {
                send_names(cl, chan);
            }
        } else {
            const char *pe[] = {tok};
            client_reply(cl, N_ENDOFNAMES, pe, 1, "End of /NAMES list.");
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

void cmd_list(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_reply(cl, N_LISTSTART, NULL, 0, "Channel :Users  Name");

    int have_wanted = 0;
    char wanted[32][CHAN_NAMELEN];
    int n_wanted = 0;
    char masks[32][CHAN_NAMELEN];
    int n_masks = 0;
    char neg_masks[32][CHAN_NAMELEN]; /* ELIST 'N': !mask excludes a match */
    int n_neg = 0;
    int min_users = -1, max_users = -1;

    if (msg->nparams > 0 && msg->params[0][0]) {
        char buf[600];
        snprintf(buf, sizeof buf, "%s", msg->params[0]);
        char *save = NULL;
        for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (!tok[0]) continue;
            int negate = tok[0] == '!' && tok[1];
            const char *body = negate ? tok + 1 : tok;
            /* A '#'-led token is only an exact channel name if it has no
             * glob characters -- "#*linux*" is a pattern (ELIST 'M'), not a
             * request for a literal channel named "#*linux*". */
            int is_pattern = strchr(body, '*') || strchr(body, '?');
            if (!negate && tok[0] == '>' && isdigit((unsigned char)tok[1])) min_users = atoi(tok + 1);
            else if (!negate && tok[0] == '<' && isdigit((unsigned char)tok[1])) max_users = atoi(tok + 1);
            else if (negate) { if (n_neg < 32) { irc_casefold(neg_masks[n_neg], CHAN_NAMELEN, body); n_neg++; } }
            else if (body[0] == '#' && !is_pattern) { if (n_wanted < 32) { irc_casefold(wanted[n_wanted], CHAN_NAMELEN, body); n_wanted++; have_wanted = 1; } }
            else { if (n_masks < 32) { irc_casefold(masks[n_masks], CHAN_NAMELEN, body); n_masks++; } }
        }
    }

    channel_t *c, *tmp;
    HASH_ITER(hh, srv->channels, c, tmp) {
        if (have_wanted) {
            int hit = 0;
            for (int i = 0; i < n_wanted; i++) if (strcmp(wanted[i], c->casefold_name) == 0) { hit = 1; break; }
            if (!hit) continue;
        }
        if (n_masks > 0) {
            int hit = 0;
            for (int i = 0; i < n_masks; i++) if (irc_glob_match(masks[i], c->casefold_name)) { hit = 1; break; }
            if (!hit) continue;
        }
        if (n_neg > 0) {
            int excluded = 0;
            for (int i = 0; i < n_neg; i++) if (irc_glob_match(neg_masks[i], c->casefold_name)) { excluded = 1; break; }
            if (excluded) continue;
        }
        int count = channel_member_count(c);
        if (min_users >= 0 && count <= min_users) continue;
        if (max_users >= 0 && count >= max_users) continue;
        int is_member = channel_find_member(c, cl) != NULL;
        if ((c->modes & CMODE_S) && !is_member) continue;
        char cnt[16];
        snprintf(cnt, sizeof cnt, "%d", count);
        if ((c->modes & CMODE_P) && !is_member) {
            const char *p[] = {"*", cnt};
            client_reply(cl, N_LIST, p, 2, "");
            continue;
        }
        const char *p[] = {c->name, cnt};
        client_reply(cl, N_LIST, p, 2, c->topic);
    }
    client_reply(cl, N_LISTEND, NULL, 0, "End of /LIST");
}

void cmd_links(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp) {
        const char *p[] = {s->name, s->uplink ? s->uplink->name : srv->cfg.server.name};
        char m[200];
        snprintf(m, sizeof m, "%d %s", s->hop, s->desc);
        client_reply(cl, N_LINKS, p, 2, m);
    }
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) { /* plain (service) links aren't in the server table */
        if (!lc->authenticated || lc->is_server) continue;
        const char *p[] = {lc->peer_name, srv->cfg.server.name};
        char m[128]; snprintf(m, sizeof m, "1 %s", lc->peer_name);
        client_reply(cl, N_LINKS, p, 2, m);
    }
    const char *pe[] = {"*"};
    client_reply(cl, N_ENDOFLINKS, pe, 1, "End of /LINKS list.");
}

/* /MAP as a tree: each server indented under the one it hangs off, with its user count. */
static void map_subtree(server_t *srv, client_t *cl, const netserver_t *node, int depth) {
    char m[200], pad[64] = "";
    for (int i = 0; i < depth && i < 20; i++) strncat(pad, i == depth - 1 ? "|-- " : "    ", sizeof pad - strlen(pad) - 1);
    snprintf(m, sizeof m, "%s%s (%d users)", pad, node->name, node->n_users);
    client_reply(cl, N_MAP, NULL, 0, m);
    netserver_t *s, *tmp;
    HASH_ITER(hh, srv->servers, s, tmp)
        if (s->uplink == node) map_subtree(srv, cl, s, depth + 1);
}

void cmd_map(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    if (srv->self_srv) map_subtree(srv, cl, srv->self_srv, 0);
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) { /* service links */
        if (!lc->authenticated || lc->is_server) continue;
        char m[160]; snprintf(m, sizeof m, "|-- %s", lc->peer_name);
        client_reply(cl, N_MAP, NULL, 0, m);
    }
    client_reply(cl, N_MAPEND, NULL, 0, "End of /MAP");
}

void cmd_invite(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target || !target->registered) { err_no_such_nick(cl, msg->params[0]); return; }
    const char *chan_name = msg->params[1];
    /* An INVITE for a channel that doesn't exist still delivers its second
     * parameter verbatim to the target. Unvalidated, that made INVITE an
     * arbitrary-text channel to any nick on the server, around /SILENCE, +D
     * and +R -- all of which PRIVMSG enforces. Validate the name, and apply
     * the same three checks. */
    if (!irc_valid_channel(chan_name, 50)) { err_no_such_channel(cl, chan_name); return; }
    if (client_is_silencing(target, cl)) return; /* dropped without telling the sender, as PRIVMSG does */
    if ((target->umodes & UMODE_NOPM) && !(cl->umodes & UMODE_O) && cl != target) {
        const char *pe[] = {target->nick};
        client_reply(cl, N_NONONREG, pe, 1, "is not accepting private messages");
        return;
    }
    if ((target->umodes & UMODE_REGONLY) && !cl->account[0] && !(cl->umodes & UMODE_O) && cl != target) {
        const char *pe[] = {target->nick};
        client_reply(cl, N_NONONREG, pe, 1, "is only accepting messages from registered users");
        return;
    }
    channel_t *chan = server_find_channel(srv, chan_name);
    if (chan) {
        member_t *me = channel_find_member(chan, cl);
        if (!me) {
            const char *p[] = {chan->name};
            client_reply(cl, N_NOTONCHANNEL, p, 1, "You're not on that channel");
            return;
        }
        if (channel_find_member(chan, target)) {
            const char *p[] = {target->nick, chan->name};
            client_reply(cl, N_USERONCHANNEL, p, 2, "is already on channel");
            return;
        }
        if ((chan->modes & CMODE_I) && !channel_has_ops(chan, cl) && !(cl->umodes & UMODE_O)) {
            err_not_channel_op(cl, chan->name);
            return;
        }
        if ((chan->modes & CMODE_NOINVITE) && !channel_has_ops(chan, cl) && !(cl->umodes & UMODE_O)) {
            err_not_channel_op(cl, chan->name);
            return;
        }
        if (chan->modes & CMODE_I) channel_invite_add(chan, invite_key_of(target)); /* only meaningful under +i -- don't let -i channels burn the 64 slots */
        chan_name = chan->name;
    }
    const char *p[] = {target->nick, chan_name};
    client_reply(cl, N_INVITING, p, 2, NULL);
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[300];
    const char *pt[] = {target->nick};
    irc_build(line, sizeof line, NULL, 0, prefix, "INVITE", pt, 1, chan_name);
    client_send(target, line);
    if (chan) netsync_invite(srv, cl, target, chan); /* other servers deliver it to a remote invitee and remember it for +i */

    /* IRCv3 invite-notify: every other op (not the inviter, not the
     * invitee -- they already got the INVITE above) that negotiated it. */
    if (chan) {
        char notify_line[300];
        const char *pn[] = {target->nick, chan->name};
        irc_build(notify_line, sizeof notify_line, NULL, 0, prefix, "INVITE", pn, 2, NULL);
        member_t *m, *tmp;
        HASH_ITER(hh, chan->members, m, tmp) {
            if (m->client == cl || m->client == target) continue;
            if ((m->rank & (RANK_OP | RANK_HALFOP)) && (m->client->caps & CAP_INVITE_NOTIFY))
                client_send(m->client, notify_line);
        }
    }
    log_info("chan", "%s invited %s to %s", cl->nick, target->nick, chan_name);
}

void cmd_knock(server_t *srv, client_t *cl, irc_message_t *msg) {
    channel_t *chan = server_find_channel(srv, msg->params[0]);
    if (!chan) { err_no_such_channel(cl, msg->params[0]); return; }
    if (channel_find_member(chan, cl)) {
        const char *p[] = {chan->name};
        client_reply(cl, N_KNOCKONCHAN, p, 1, "You are already on that channel");
        return;
    }
    if (!(chan->modes & (CMODE_I | CMODE_K))) {
        const char *p[] = {chan->name};
        client_reply(cl, N_CHANOPEN, p, 1, "Channel is open");
        return;
    }
    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        if (!(m->rank & RANK_OP)) continue;
        const char *p[] = {chan->name, prefix};
        client_reply(m->client, N_KNOCK, p, 2, "has asked for an invite");
    }
    const char *pd[] = {chan->name};
    client_reply(cl, N_KNOCKDLVR, pd, 1, "Your KNOCK has been delivered");
    log_info("chan", "%s knocked on %s", cl->nick, chan->name);
}

void cmd_kick(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *chan_name = msg->params[0];
    const char *target_nick = msg->params[1];
    const char *reason = msg->nparams > 2 ? msg->params[msg->nparams - 1] : cl->nick;

    channel_t *chan = server_find_channel(srv, chan_name);
    if (!chan) { err_no_such_channel(cl, chan_name); return; }
    member_t *me = channel_find_member(chan, cl);
    if (!me) {
        const char *p[] = {chan->name};
        client_reply(cl, N_NOTONCHANNEL, p, 1, "You're not on that channel");
        return;
    }
    if (!(me->rank & (RANK_OP | RANK_HALFOP)) && !(cl->umodes & UMODE_O)) { err_not_channel_op(cl, chan->name); return; }
    if ((chan->modes & CMODE_NOKICK) && !(cl->umodes & UMODE_O)) { err_not_channel_op(cl, chan->name); return; }

    client_t *target = server_find_user(srv, target_nick);
    member_t *tm = target ? channel_find_member(chan, target) : NULL;
    if (!tm) {
        const char *p[] = {target_nick, chan->name};
        client_reply(cl, N_USERNOTINCHANNEL, p, 2, "They aren't on that channel");
        return;
    }
    if ((target->umodes & UMODE_Q) && !(cl->umodes & UMODE_O)) { err_not_channel_op(cl, chan->name); return; }
    /* a halfop (not full op/oper) may only kick "downward" */
    if ((me->rank & RANK_HALFOP) && !(me->rank & RANK_OP) && !(cl->umodes & UMODE_O) && (tm->rank & (RANK_OP | RANK_HALFOP))) {
        err_not_channel_op(cl, chan->name);
        return;
    }
    /* owners and admins can't be kicked by someone more junior */
    if (!(cl->umodes & UMODE_O) && channel_rank_level(tm->rank) > channel_rank_level(me->rank)) {
        err_not_channel_op(cl, chan->name);
        return;
    }

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    const char *p[] = {chan->name, target->nick};
    irc_build(line, sizeof line, NULL, 0, prefix, "KICK", p, 2, reason);
    server_broadcast_channel(chan, line, NULL);
    netsync_chan_kick(srv, chan, cl, target, reason);

    /* server_maybe_drop_channel frees chan once it's empty (e.g. the kicker
     * kicking themself from a channel they're alone in) -- log using the
     * name captured before that, not chan->name after. */
    char chan_name_buf[CHAN_NAMELEN];
    snprintf(chan_name_buf, sizeof chan_name_buf, "%s", chan->name);
    channel_remove_member(chan, target);
    server_detach_membership(target, chan);
    server_maybe_drop_channel(srv, chan);
    log_info("chan", "%s kicked %s from %s: %s", cl->nick, target->nick, chan_name_buf, reason);
}

/* --- MODE --------------------------------------------------------------- */

static void cmd_mode_user(server_t *srv, client_t *cl, irc_message_t *msg, const char *target) {
    char cf[NICKLEN];
    irc_casefold(cf, sizeof cf, target);
    if (strcmp(cf, cl->casefold_nick) != 0) {
        client_reply(cl, N_USERSDONTMATCH, NULL, 0, "Cannot change mode for other users");
        return;
    }
    if (msg->nparams < 2) {
        char modestr[24];
        client_mode_string(cl, modestr, sizeof modestr);
        client_reply(cl, N_UMODEIS, NULL, 0, modestr);
        return;
    }

    char sign = '+';
    char applied[32] = "+";
    size_t ap = 1;
    char cursign = '+'; /* applied[] is pre-seeded with '+', so the first
                          * mode must not re-print the sign */
    /* each accepted letter appends at most 2 bytes (sign + letter) */
    for (const char *p = msg->params[1]; *p && ap + 3 <= sizeof applied; p++) {
        char c = *p;
        if (c == '+' || c == '-') { sign = c; continue; }
        unsigned int bit = 0;
        if (c == 'o') {
            if (sign == '-') bit = UMODE_O; /* +o only via /OPER, never MODE */
            else continue;
        } else if (c == 'i') bit = UMODE_I;
        else if (c == 'w') bit = UMODE_W;
        else if (c == 'd') bit = UMODE_D;
        else if (c == 's') bit = UMODE_S;
        else if (c == 'p') bit = UMODE_P;
        else if (c == 'I') bit = UMODE_HIDEIDLE;
        else if (c == 'q') { if (cl->umodes & UMODE_O) bit = UMODE_Q; else continue; } /* q: unkickable -- oper-only settable, like H */
        else if (c == 'R') bit = UMODE_REGONLY;
        else if (c == 'D') bit = UMODE_NOPM;
        else if (c == 'B') bit = UMODE_B;
        else if (c == 'g') bit = UMODE_G;
        else if (c == 'H') { if (cl->umodes & UMODE_O) bit = UMODE_H; else continue; }
        else continue;
        if (sign == '+') cl->umodes |= bit; else cl->umodes &= ~bit;
        if (c == 'o' && sign == '-') { /* de-opered: drop the oper-only modes too */
            cl->umodes &= ~(UMODE_Q | UMODE_H);
            cl->oper_name[0] = '\0';
            cl->oper_privs = 0;
        }
        if (cursign != sign) { applied[ap++] = sign; cursign = sign; }
        applied[ap++] = c;
    }
    applied[ap] = '\0';
    if (ap <= 1) return;

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[200];
    const char *p2[] = {cl->nick, applied};
    irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p2, 2, NULL);
    client_send(cl, line);
    netsync_user_modes(srv, cl);
}

/* Shared by /MODE (is_full_op reflects the caller's real rank) and /SAMODE
 * (always full_op=1 -- that command's whole point is bypassing the rank
 * gate). Halfop may only toggle v/b/e/I; everything else needs full op/oper. */
/* "<n>:<secs>" for +f/+j -- n in 1..100, secs in 1..600, nothing trailing. */
static int parse_rate(const char *s, int *n, int *secs) {
    char *e1, *e2;
    long a = strtol(s, &e1, 10);
    if (e1 == s || *e1 != ':') return 0;
    long b = strtol(e1 + 1, &e2, 10);
    if (e2 == e1 + 1 || *e2) return 0;
    if (a < 1 || a > 100 || b < 1 || b > 600) return 0;
    *n = (int)a; *secs = (int)b;
    return 1;
}

#define MAX_MODE_PARAMS 6 /* advertised as MODES=6 in ISUPPORT */

void cmd_apply_channel_mode(server_t *srv, client_t *cl, channel_t *chan,
                             const char *modestring, const char **args, int nargs, int is_full_op) {
    int argi = 0;
    char sign = '+';
    char outflags[64];
    size_t of = 0;
    char cursign = 0;
    char outparams[16][256];
    int n_outparams = 0;

    for (const char *pch = modestring; *pch; pch++) {
        /* Bounds check FIRST: several branches below end in `continue`, so a
         * check at the bottom of the loop is simply not reached by them --
         * an argument-free flag letter (the `flagbit` branch) then appends
         * to outflags[] unboundedly, and "MODE #c +nnnn...", 500 letters
         * long, smashes the stack. Every write below appends at most a sign
         * plus a letter, so leaving 2 bytes plus the NUL is sufficient. */
        if (of + 2 >= sizeof outflags || n_outparams >= MAX_MODE_PARAMS) break; /* == ISUPPORT MODES= */
        char c = *pch;
        if (c == '+' || c == '-') { sign = c; continue; }

        if (c == 'r' && !cl->is_service) {
            const char *p[] = {chan->name};
            client_reply(cl, N_NOTCHANNELOP, p, 1, "Mode +r is set by services only");
            continue;
        }
        if (c == 'P' && sign == '+' && !cl->is_service && !(cl->umodes & UMODE_O)) {
            /* +P keeps an empty channel alive forever; for anyone who can create
             * a channel that is an unbounded memory sink. */
            const char *p[] = {chan->name};
            client_reply(cl, N_NOTCHANNELOP, p, 1, "Mode +P is set by operators only");
            continue;
        }
        int is_halfop_mode = (c == 'v' || c == 'b' || c == 'e' || c == 'I');
        if (!is_full_op && !is_halfop_mode && c != 'r') {
            err_not_channel_op(cl, chan->name);
            continue;
        }

        unsigned int flagbit = 0;
        switch (c) {
            case 'n': flagbit = CMODE_N; break;
            case 'i': flagbit = CMODE_I; break;
            case 'p': flagbit = CMODE_P; break;
            case 't': flagbit = CMODE_T; break;
            case 's': flagbit = CMODE_S; break;
            case 'm': flagbit = CMODE_M; break;
            case 'z': flagbit = CMODE_Z; break;
            case 'r': flagbit = CMODE_R; break;
            case 'P': flagbit = CMODE_PERM; break;
            case 'C': flagbit = CMODE_NOCTCP; break;
            case 'T': flagbit = CMODE_NONOTICE; break;
            case 'S': flagbit = CMODE_STRIPCOLOR; break;
            case 'V': flagbit = CMODE_NOINVITE; break;
            case 'Q': flagbit = CMODE_NOKICK; break;
            case 'N': flagbit = CMODE_NONICK; break;
            case 'R': flagbit = CMODE_REGONLY; break;
            case 'O': flagbit = CMODE_OPERONLY; break;
            case 'M': flagbit = CMODE_MODREG; break;
            case 'c': flagbit = CMODE_NOCOLOR; break;
            case 'D': flagbit = CMODE_DELAYJOIN; break;
            case 'u': flagbit = CMODE_AUDITORIUM; break;
            case 'G': flagbit = CMODE_CENSOR; break;
            default: break;
        }
        if (flagbit) {
            if (sign == '+') chan->modes |= flagbit; else chan->modes &= ~flagbit;
            if (sign == '-' && flagbit == CMODE_DELAYJOIN) { /* -D: everyone still hidden becomes visible */
                member_t *hm, *htmp;
                HASH_ITER(hh, chan->members, hm, htmp) if (hm->hidden) channel_reveal_member(chan, hm);
            }
            if (sign == '-' && flagbit == CMODE_AUDITORIUM) { /* -u: announce the members the audience couldn't see */
                /* nothing to replay: they were always in NAMES for ranked viewers; ordinary members just start seeing each other
                 * on their next NAMES/WHO. */
            }
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            continue;
        }

        if (c == 'L') { /* redirect target */
            if (sign == '+') {
                if (argi >= nargs) continue;
                const char *target = args[argi++];
                char tcf[CHAN_NAMELEN], ccf[CHAN_NAMELEN];
                irc_casefold(tcf, sizeof tcf, target);
                irc_casefold(ccf, sizeof ccf, chan->name);
                if (!irc_valid_channel(target, 50) || strcmp(tcf, ccf) == 0) { /* junk, or a channel forwarding to itself */
                    err_no_such_channel(cl, target);
                    continue;
                }
                chan->modes |= CMODE_REDIRECT;
                snprintf(chan->redirect, sizeof chan->redirect, "%s", target);
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'L';
                snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", target);
            } else {
                chan->modes &= ~CMODE_REDIRECT;
                chan->redirect[0] = '\0';
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'L';
            }
        } else if (c == 'f' || c == 'j') {
            int is_f = c == 'f';
            if (sign == '+') {
                if (argi >= nargs) continue;
                int n, secs;
                if (!parse_rate(args[argi], &n, &secs)) { argi++; continue; } /* malformed "lines:secs": consume, ignore */
                if (is_f) { chan->modes |= CMODE_FLOOD; chan->flood_lines = n; chan->flood_secs = secs; }
                else { chan->modes |= CMODE_JTHROT; chan->jt_joins = n; chan->jt_secs = secs; chan->jt_count = 0; chan->jt_start = 0; }
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = c;
                snprintf(outparams[n_outparams++], sizeof outparams[0], "%d:%d", n, secs);
                argi++;
            } else {
                if (is_f) { chan->modes &= ~CMODE_FLOOD; chan->flood_lines = chan->flood_secs = 0; }
                else { chan->modes &= ~CMODE_JTHROT; chan->jt_joins = chan->jt_secs = 0; }
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = c;
            }
        } else if (c == 'k') {
            if (sign == '+') {
                if (argi >= nargs) continue;
                if (strchr(args[argi], ' ')) { argi++; continue; } /* a spaced key desyncs every client's parser -- still consume the arg */
                snprintf(chan->key, sizeof chan->key, "%s", args[argi]);
                chan->modes |= CMODE_K;
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'k';
                snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", args[argi]);
                argi++;
            } else {
                if (argi < nargs) argi++; /* "-k <key>": the key arg is consumed, not shifted onto the next mode */
                chan->modes &= ~CMODE_K;
                chan->key[0] = '\0';
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'k';
            }
        } else if (c == 'l') {
            if (sign == '+') {
                if (argi >= nargs) continue;
                char *endp;
                long lim = strtol(args[argi], &endp, 10);
                if (endp == args[argi] || *endp || lim < 1 || lim > INT_MAX) { argi++; continue; } /* not a positive number: consume, ignore */
                chan->limit = (int)lim;
                chan->modes |= CMODE_L;
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'l';
                snprintf(outparams[n_outparams++], sizeof outparams[0], "%ld", lim);
                argi++;
            } else {
                chan->modes &= ~CMODE_L;
                chan->limit = 0;
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'l';
            }
        } else if (c == 'o' || c == 'h' || c == 'v' || c == 'q' || c == 'a') {
            if (argi >= nargs) continue;
            client_t *target = server_find_user(srv, args[argi]);
            member_t *tm = target ? channel_find_member(chan, target) : NULL;
            if (!target) { err_no_such_nick(cl, args[argi]); argi++; continue; }
            if (!tm) {
                const char *pe[] = {target->nick, chan->name};
                client_reply(cl, N_USERNOTINCHANNEL, pe, 2, "They aren't on that channel");
                argi++; continue;
            }
            /* Who may touch whom: owners/admins are protected -- the setter must be at least as senior as the
             * target (opers and services always are), and only an owner may grant +q, only owner/admin +a.
             * A user may always drop their own prefix. */
            member_t *setter = channel_find_member(chan, cl);
            int setter_lvl = ((cl->umodes & UMODE_O) || cl->is_service) ? 99 : setter ? channel_rank_level(setter->rank) : 0;
            int need = (c == 'q') ? 5 : (c == 'a') ? 4 : 0;
            int target_lvl = channel_rank_level(tm->rank);
            int self_drop = (target == cl && sign == '-');
            if (!self_drop && (setter_lvl < need || (sign == '-' && target_lvl > setter_lvl))) {
                const char *pe[] = {chan->name};
                client_reply(cl, N_NOTCHANNELOP, pe, 1, "You are not senior enough to change that user's status");
                argi++; continue;
            }
            int rank = (c == 'o') ? RANK_OP : (c == 'h') ? RANK_HALFOP : (c == 'v') ? RANK_VOICE : (c == 'q') ? RANK_OWNER : RANK_ADMIN;
            if (sign == '+') {
                tm->rank |= rank;
                if (c == 'q' || c == 'a') tm->rank |= RANK_OP; /* owner/admin are ops too -- every op check keeps working */
                if (tm->hidden) channel_reveal_member(chan, tm); /* a ranked member can't stay hidden */
            } else {
                tm->rank &= ~rank;
                if (c == 'o') tm->rank &= ~(RANK_ADMIN | RANK_OWNER); /* -o is a full demotion */
            }
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", target->nick);
            argi++;
        } else if (c == 'b' || c == 'e' || c == 'I') {
            if (argi >= nargs) continue;
            if (strchr(args[argi], ' ')) { argi++; continue; } /* see the +k note above -- still consume the arg */
            const char *mask = args[argi];
            masklist_t *ml = (c == 'b') ? &chan->bans : (c == 'e') ? &chan->exceptions : &chan->invex;
            int changed;
            if (sign == '+') {
                if (ml->n >= CHAN_MAX_MASKLIST) {
                    const char *pe[] = {chan->name, mask};
                    client_reply(cl, N_BANLISTFULL, pe, 2, "Channel list is full");
                    argi++; continue;
                }
                changed = masklist_add(ml, mask) == 0;
            } else changed = masklist_del(ml, mask) == 0;
            if (!changed) { argi++; continue; } /* duplicate add / absent remove: nothing to announce */
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", mask);
            argi++;
        } else {
            char letterbuf[2] = {c, '\0'};
            const char *p[] = {chan->name, letterbuf};
            client_reply(cl, N_UNKNOWNMODE, p, 2, "is unknown mode char to me");
        }
    }
    outflags[of] = '\0';
    if (of <= 1) return;

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    const char *outp[18];
    outp[0] = chan->name;
    outp[1] = outflags;
    int total = 2;
    for (int i = 0; i < n_outparams && total < 18; i++) outp[total++] = outparams[i];
    char line[510];
    if (irc_build(line, sizeof line, NULL, 0, prefix, "MODE", outp, total, NULL) >= 0)
        server_broadcast_channel(chan, line, NULL);
    { /* the rest of the network gets the same change (rank-mode arguments travel as UIDs) */
        const char *wire_args[8];
        for (int i = 0; i < n_outparams && i < 8; i++) wire_args[i] = outparams[i];
        netsync_chan_mode(srv, chan, cl, outflags, wire_args, n_outparams < 8 ? n_outparams : 8);
    }
    log_info("chan", "%s set %s %s", cl->nick, chan->name, outflags);
}

static void reply_masklist(client_t *cl, channel_t *chan, char letter) {
    masklist_t *ml = (letter == 'b') ? &chan->bans : (letter == 'e') ? &chan->exceptions : &chan->invex;
    const char *list_n = (letter == 'b') ? N_BANLIST : (letter == 'e') ? N_EXCEPTLIST : N_INVEXLIST;
    const char *end_n = (letter == 'b') ? N_ENDOFBANLIST : (letter == 'e') ? N_ENDOFEXCEPTLIST : N_ENDOFINVEXLIST;
    for (int i = 0; i < ml->n; i++) {
        const char *p[] = {chan->name, ml->masks[i]};
        client_reply(cl, list_n, p, 2, NULL);
    }
    const char *pe[] = {chan->name};
    const char *desc = (letter == 'b') ? "End of channel ban list" : (letter == 'e') ? "End of channel exception list" : "End of channel invite exception list";
    client_reply(cl, end_n, pe, 1, desc);
}

static void cmd_mode_channel(server_t *srv, client_t *cl, irc_message_t *msg, const char *chan_name) {
    channel_t *chan = server_find_channel(srv, chan_name);
    if (!chan) { err_no_such_channel(cl, chan_name); return; }

    if (msg->nparams < 2) {
        char modestr[360];
        channel_modes_string(chan, modestr, sizeof modestr);
        if ((chan->modes & CMODE_K) && !(channel_find_member(chan, cl) || (cl->umodes & UMODE_O))) {
            /* redact the key from a non-member query */
            char *space = strchr(modestr, ' ');
            if (space) { *(space + 1) = '*'; *(space + 2) = '\0'; }
        }
        /* "+kl key 5": the flag letters and each argument are separate parameters on the wire */
        const char *p[2 + 8] = {chan->name};
        int np = 1;
        char *save = NULL;
        for (char *t = strtok_r(modestr, " ", &save); t && np < 10; t = strtok_r(NULL, " ", &save)) p[np++] = t;
        client_reply(cl, N_CHANNELMODEIS, p, np, NULL);
        char tbuf[32];
        snprintf(tbuf, sizeof tbuf, "%ld", (long)chan->created);
        const char *p2[] = {chan->name, tbuf};
        client_reply(cl, N_CREATIONTIME, p2, 2, NULL);
        return;
    }

    const char *modestring = msg->params[1];
    char bare[4]; snprintf(bare, sizeof bare, "%s", modestring);
    char *lp = bare;
    while (*lp == '+' || *lp == '-') lp++;
    if ((strcmp(lp, "b") == 0 || strcmp(lp, "e") == 0 || strcmp(lp, "I") == 0) && msg->nparams < 3) {
        reply_masklist(cl, chan, lp[0]);
        return;
    }

    member_t *me = channel_find_member(chan, cl);
    int has_rank = me && (me->rank & (RANK_OP | RANK_HALFOP));
    if (!has_rank && !(cl->umodes & UMODE_O)) { err_not_channel_op(cl, chan->name); return; }

    int is_full_op = (cl->umodes & UMODE_O) || (me && (me->rank & RANK_OP));
    const char *args[16];
    int nargs = 0;
    for (int i = 2; i < msg->nparams && nargs < 16; i++) args[nargs++] = msg->params[i];
    cmd_apply_channel_mode(srv, cl, chan, modestring, args, nargs, is_full_op);
}

void cmd_mode(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *target = msg->params[0];
    if (target[0] == '#') cmd_mode_channel(srv, cl, msg, target);
    else cmd_mode_user(srv, cl, msg, target);
}

void cmd_samode(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *chan_name = msg->params[0];
    if (chan_name[0] != '#') { err_no_such_channel(cl, chan_name); return; }
    channel_t *chan = server_find_channel(srv, chan_name);
    if (!chan) { err_no_such_channel(cl, chan_name); return; }
    const char *args[16];
    int nargs = 0;
    for (int i = 2; i < msg->nparams && nargs < 16; i++) args[nargs++] = msg->params[i];
    cmd_apply_channel_mode(srv, cl, chan, msg->params[1], args, nargs, 1);
    log_info("chan", "%s SAMODEd %s: %s", cl->nick, chan->name, msg->params[1]);
    char snote[400];
    snprintf(snote, sizeof snote, "%s used SAMODE on %s: %s", cl->nick, chan->name, msg->params[1]);
    server_notify_opers(srv, snote);
}
