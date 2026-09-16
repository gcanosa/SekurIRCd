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
#include <string.h>
#include <strings.h>
#include <time.h>

#define MAX_CHANNELS_PER_CLIENT 200

static void send_names(client_t *cl, channel_t *chan) {
    char line[480];
    size_t pos = 0;
    line[0] = '\0';
    const char *chantype = "=";
    if (chan->modes & CMODE_P) chantype = "*";
    else if (chan->modes & CMODE_S) chantype = "@";

    int multi = cl->caps & CAP_MULTI_PREFIX;
    int userhost = cl->caps & CAP_USERHOST_IN_NAMES;

    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        char nickbuf[NICKLEN + HOSTLEN + 8];
        char rankch[4] = "";
        size_t rp = 0;
        if (multi) {
            if (m->rank & RANK_OP) rankch[rp++] = '@';
            if (m->rank & RANK_HALFOP) rankch[rp++] = '%';
            if (m->rank & RANK_VOICE) rankch[rp++] = '+';
        } else {
            if (m->rank & RANK_OP) rankch[rp++] = '@';
            else if (m->rank & RANK_HALFOP) rankch[rp++] = '%';
            else if (m->rank & RANK_VOICE) rankch[rp++] = '+';
        }
        rankch[rp] = '\0';
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

static void announce_join(channel_t *chan, client_t *cl) {
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
    HASH_ITER(hh, chan->members, m, tmp) {
        client_send(m->client, (m->client->caps & CAP_EXTENDED_JOIN) ? ext_join : plain_join);
        /* account-notify's own ACCOUNT line would just duplicate what
         * extended-join already embedded in JOIN -- skip it for those. */
        if (cl->account[0] && (m->client->caps & CAP_ACCOUNT_NOTIFY) && !(m->client->caps & CAP_EXTENDED_JOIN))
            client_send(m->client, account_line);
    }
    link_notify_channel_join(chan, cl);

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
    send_names(cl, chan);
}

static int n_channels_of(client_t *cl) {
    int n = 0;
    for (chan_node_t *n2 = cl->channels; n2; n2 = n2->next) n++;
    return n;
}

void cmd_force_join(server_t *srv, client_t *cl, const char *chan_name) {
    if (!irc_valid_channel(chan_name, 50)) return;
    channel_t *chan = server_get_or_create_channel(srv, chan_name);
    if (channel_find_member(chan, cl)) return;
    member_t *m = channel_add_member(chan, cl);
    if (channel_member_count(chan) == 1) m->rank |= RANK_OP;
    server_attach_membership(cl, chan);
    announce_join(chan, cl);
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
    } else if (!(cl->umodes & UMODE_O)) {
        if ((chan->modes & CMODE_I) && !channel_is_invited(chan, cl->nick, cl->user, cl->host, cl->account)) {
            const char *p[] = {chan->name};
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
            client_reply(cl, N_CHANNELISFULL, p, 1, "Cannot join channel (+l)");
            return;
        }
        if (channel_is_banned(chan, cl->nick, cl->user, cl->host, cl->account)) {
            const char *p[] = {chan->name};
            client_reply(cl, N_BANNED, p, 1, "Cannot join channel (+b)");
            return;
        }
        if ((chan->modes & CMODE_Z) && !(cl->umodes & UMODE_Z)) {
            const char *p[] = {chan->name};
            client_reply(cl, N_SECUREONLYCHAN, p, 1, "Cannot join channel (+z, requires a secure connection)");
            return;
        }
    }

    member_t *m = channel_add_member(chan, cl);
    if (is_new) m->rank |= RANK_OP;
    char cf[64];
    irc_casefold(cf, sizeof cf, cl->nick);
    channel_invite_remove(chan, cf);
    server_attach_membership(cl, chan);
    announce_join(chan, cl);
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
            char line[500];
            const char *p[] = {chan->name};
            irc_build(line, sizeof line, NULL, 0, prefix, "PART", p, 1, reason);
            server_broadcast_channel(chan, line, NULL);
            channel_remove_member(chan, cl);
            server_detach_membership(cl, chan);
            server_maybe_drop_channel(srv, chan);
            log_info("chan", "%s left %s", cl->nick, tok);
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

/* --- SAJOIN / SAPART (oper-only overrides) ---------------------------------- */

void cmd_sajoin(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
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
    }
}

void cmd_sapart(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
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
        channel_remove_member(chan, target);
        server_detach_membership(target, chan);
        server_maybe_drop_channel(srv, chan);
        if (parted[0]) strncat(parted, ", ", sizeof parted - strlen(parted) - 1);
        strncat(parted, chan->name, sizeof parted - strlen(parted) - 1);
    }
    if (parted[0]) {
        char m[700];
        snprintf(m, sizeof m, "%s parted: %s", target->nick, parted);
        notice_self(srv, cl, m);
        log_info("chan", "%s SAPARTed %s from %s", cl->nick, target->nick, parted);
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
    snprintf(chan->topic, sizeof chan->topic, "%s", newtopic);
    client_prefix(cl, chan->topic_setter, sizeof chan->topic_setter);
    chan->topic_time = time(NULL);

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[600];
    const char *p[] = {chan->name};
    irc_build(line, sizeof line, NULL, 0, prefix, "TOPIC", p, 1, chan->topic);
    server_broadcast_channel(chan, line, NULL);
}

void cmd_names(server_t *srv, client_t *cl, irc_message_t *msg) {
    if (msg->nparams < 1) {
        client_reply(cl, N_ENDOFNAMES, NULL, 0, "End of /NAMES list.");
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
    int min_users = -1, max_users = -1;

    if (msg->nparams > 0 && msg->params[0][0]) {
        char buf[600];
        snprintf(buf, sizeof buf, "%s", msg->params[0]);
        char *save = NULL;
        for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (!tok[0]) continue;
            if (tok[0] == '>' && isdigit((unsigned char)tok[1])) min_users = atoi(tok + 1);
            else if (tok[0] == '<' && isdigit((unsigned char)tok[1])) max_users = atoi(tok + 1);
            else if (tok[0] == '#') { if (n_wanted < 32) { irc_casefold(wanted[n_wanted], CHAN_NAMELEN, tok); n_wanted++; have_wanted = 1; } }
            else { if (n_masks < 32) { irc_casefold(masks[n_masks], CHAN_NAMELEN, tok); n_masks++; } }
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
    const char *p0[] = {srv->cfg.server.name, srv->cfg.server.name};
    char m0[64]; snprintf(m0, sizeof m0, "0 %s", srv->cfg.server.name);
    client_reply(cl, N_LINKS, p0, 2, m0);
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (!lc->authenticated) continue;
        const char *p[] = {lc->peer_name, srv->cfg.server.name};
        char m[128]; snprintf(m, sizeof m, "1 %s", lc->peer_name);
        client_reply(cl, N_LINKS, p, 2, m);
    }
    const char *pe[] = {"*"};
    client_reply(cl, N_ENDOFLINKS, pe, 1, "End of /LINKS list.");
}

void cmd_map(server_t *srv, client_t *cl, irc_message_t *msg) {
    (void)msg;
    client_reply(cl, N_MAP, NULL, 0, srv->cfg.server.name);
    for (link_conn_t *lc = srv->links; lc; lc = lc->next) {
        if (!lc->authenticated) continue;
        char m[160]; snprintf(m, sizeof m, " |-- %s", lc->peer_name);
        client_reply(cl, N_MAP, NULL, 0, m);
    }
    client_reply(cl, N_MAPEND, NULL, 0, "End of /MAP");
}

void cmd_invite(server_t *srv, client_t *cl, irc_message_t *msg) {
    client_t *target = server_find_user(srv, msg->params[0]);
    if (!target) { err_no_such_nick(cl, msg->params[0]); return; }
    const char *chan_name = msg->params[1];
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
        char cf[64];
        irc_casefold(cf, sizeof cf, target->nick);
        channel_invite_add(chan, cf);
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

    char prefix[320];
    client_prefix(cl, prefix, sizeof prefix);
    char line[500];
    const char *p[] = {chan->name, target->nick};
    irc_build(line, sizeof line, NULL, 0, prefix, "KICK", p, 2, reason);
    server_broadcast_channel(chan, line, NULL);

    channel_remove_member(chan, target);
    server_detach_membership(target, chan);
    server_maybe_drop_channel(srv, chan);
    log_info("chan", "%s kicked %s from %s: %s", cl->nick, target->nick, chan->name, reason);
}

/* --- MODE --------------------------------------------------------------- */

static void cmd_mode_user(client_t *cl, irc_message_t *msg, const char *target) {
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
        else if (c == 'q') bit = UMODE_Q;
        else if (c == 'R') bit = UMODE_REGONLY;
        else if (c == 'D') bit = UMODE_NOPM;
        else if (c == 'H') { if (cl->umodes & UMODE_O) bit = UMODE_H; else continue; }
        else continue;
        if (sign == '+') cl->umodes |= bit; else cl->umodes &= ~bit;
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
}

/* Shared by /MODE (is_full_op reflects the caller's real rank) and /SAMODE
 * (always full_op=1 -- that command's whole point is bypassing the rank
 * gate). Halfop may only toggle v/b/e/I; everything else needs full op/oper. */
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
        char c = *pch;
        if (c == '+' || c == '-') { sign = c; continue; }

        if (c == 'r' && !cl->is_service) {
            const char *p[] = {chan->name};
            client_reply(cl, N_NOTCHANNELOP, p, 1, "Mode +r is set by services only");
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
            default: break;
        }
        if (flagbit) {
            if (sign == '+') chan->modes |= flagbit; else chan->modes &= ~flagbit;
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            continue;
        }

        if (c == 'k') {
            if (sign == '+') {
                if (argi >= nargs) continue;
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
                chan->limit = atoi(args[argi]);
                chan->modes |= CMODE_L;
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'l';
                snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", args[argi]);
                argi++;
            } else {
                chan->modes &= ~CMODE_L;
                chan->limit = 0;
                if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
                outflags[of++] = 'l';
            }
        } else if (c == 'o' || c == 'h' || c == 'v') {
            if (argi >= nargs) continue;
            client_t *target = server_find_user(srv, args[argi]);
            member_t *tm = target ? channel_find_member(chan, target) : NULL;
            if (!tm) { argi++; continue; }
            int rank = (c == 'o') ? RANK_OP : (c == 'h') ? RANK_HALFOP : RANK_VOICE;
            if (sign == '+') tm->rank |= rank; else tm->rank &= ~rank;
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", target->nick);
            argi++;
        } else if (c == 'b' || c == 'e' || c == 'I') {
            if (argi >= nargs) continue;
            const char *mask = args[argi];
            masklist_t *ml = (c == 'b') ? &chan->bans : (c == 'e') ? &chan->exceptions : &chan->invex;
            if (sign == '+') masklist_add(ml, mask); else masklist_del(ml, mask);
            if (cursign != sign) { outflags[of++] = sign; cursign = sign; }
            outflags[of++] = c;
            snprintf(outparams[n_outparams++], sizeof outparams[0], "%s", mask);
            argi++;
        } else {
            char letterbuf[2] = {c, '\0'};
            const char *p[] = {chan->name, letterbuf};
            client_reply(cl, N_UNKNOWNMODE, p, 2, "is unknown mode char to me");
        }
        if (of >= sizeof outflags - 2 || n_outparams >= 15) break; /* defensive */
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
    char line[600];
    irc_build(line, sizeof line, NULL, 0, prefix, "MODE", outp, total, NULL);
    server_broadcast_channel(chan, line, NULL);
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
        char modestr[160];
        channel_modes_string(chan, modestr, sizeof modestr);
        if ((chan->modes & CMODE_K) && !(channel_find_member(chan, cl) || (cl->umodes & UMODE_O))) {
            /* redact the key from a non-member query */
            char *space = strchr(modestr, ' ');
            if (space) { *(space + 1) = '*'; *(space + 2) = '\0'; }
        }
        const char *p[] = {chan->name, modestr};
        client_reply(cl, N_CHANNELMODEIS, p, 2, NULL);
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
    else cmd_mode_user(cl, msg, target);
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
}
