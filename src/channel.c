#include "channel.h"
#include "client.h"
#include "proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

channel_t *channel_new(const char *name, const char *casefold_name) {
    channel_t *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    snprintf(c->name, sizeof c->name, "%s", name);
    snprintf(c->casefold_name, sizeof c->casefold_name, "%s", casefold_name);
    c->created = time(NULL);
    return c;
}

void channel_free(channel_t *chan) {
    member_t *m, *tmp;
    HASH_ITER(hh, chan->members, m, tmp) {
        HASH_DEL(chan->members, m);
        free(m);
    }
    free(chan);
}

member_t *channel_find_member(channel_t *chan, struct client *cl) {
    member_t *m;
    HASH_FIND_PTR(chan->members, &cl, m);
    return m;
}

member_t *channel_add_member(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    if (m) return m;
    m = calloc(1, sizeof *m);
    m->client = cl;
    HASH_ADD_PTR(chan->members, client, m);
    return m;
}

void channel_remove_member(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    if (!m) return;
    HASH_DEL(chan->members, m);
    free(m);
}

int channel_member_count(channel_t *chan) { return HASH_COUNT(chan->members); }

int channel_is_op(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    return m && (m->rank & RANK_OP);
}

int channel_is_halfop(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    return m && (m->rank & RANK_HALFOP);
}

int channel_has_ops(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    return m && (m->rank & (RANK_OP | RANK_HALFOP));
}

int channel_is_voice(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    return m && (m->rank & RANK_VOICE);
}

int channel_mask_hit(const char *mask, const char *nick, const char *user,
                      const char *host, const char *account) {
    if (strncasecmp(mask, "a:", 2) == 0) {
        if (!account || !account[0]) return 0; /* EXTBAN a: never matches a logged-out user */
        return irc_glob_match(mask + 2, account);
    }
    return irc_mask_match(nick, user, host, mask);
}

int channel_is_banned(channel_t *chan, const char *nick, const char *user,
                       const char *host, const char *account) {
    int banned = 0;
    for (int i = 0; i < chan->bans.n && !banned; i++)
        if (channel_mask_hit(chan->bans.masks[i], nick, user, host, account)) banned = 1;
    if (!banned) return 0;
    for (int i = 0; i < chan->exceptions.n; i++)
        if (channel_mask_hit(chan->exceptions.masks[i], nick, user, host, account)) return 0;
    return 1;
}

int channel_is_invited(channel_t *chan, const char *nick, const char *user,
                        const char *host, const char *account) {
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    for (int i = 0; i < chan->n_invited; i++)
        if (strcmp(chan->invited[i], cf) == 0) return 1;
    for (int i = 0; i < chan->invex.n; i++)
        if (channel_mask_hit(chan->invex.masks[i], nick, user, host, account)) return 1;
    return 0;
}

int masklist_add(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++)
        if (strcasecmp(ml->masks[i], mask) == 0) return -1;
    if (ml->n >= CHAN_MAX_MASKLIST) return -1;
    snprintf(ml->masks[ml->n], sizeof ml->masks[0], "%s", mask);
    ml->n++;
    return 0;
}

int masklist_del(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++) {
        if (strcasecmp(ml->masks[i], mask) == 0) {
            memmove(ml->masks[i], ml->masks[i + 1], (size_t)(ml->n - i - 1) * sizeof ml->masks[0]);
            ml->n--;
            return 0;
        }
    }
    return -1;
}

void channel_invite_add(channel_t *chan, const char *casefold_nick) {
    for (int i = 0; i < chan->n_invited; i++)
        if (strcmp(chan->invited[i], casefold_nick) == 0) return;
    if (chan->n_invited >= CHAN_MAX_INVITED) return; /* ponytail: capped, see channel.h */
    snprintf(chan->invited[chan->n_invited], sizeof chan->invited[0], "%s", casefold_nick);
    chan->n_invited++;
}

void channel_invite_remove(channel_t *chan, const char *casefold_nick) {
    for (int i = 0; i < chan->n_invited; i++) {
        if (strcmp(chan->invited[i], casefold_nick) == 0) {
            memmove(chan->invited[i], chan->invited[i + 1],
                    (size_t)(chan->n_invited - i - 1) * sizeof chan->invited[0]);
            chan->n_invited--;
            return;
        }
    }
}

void channel_modes_string(channel_t *chan, char *out, size_t outsz) {
    char flags[24] = "+";
    char args[128] = "";
    size_t fp = 1;
    if (chan->modes & CMODE_N) flags[fp++] = 'n';
    if (chan->modes & CMODE_I) flags[fp++] = 'i';
    if (chan->modes & CMODE_P) flags[fp++] = 'p';
    if (chan->modes & CMODE_T) flags[fp++] = 't';
    if (chan->modes & CMODE_S) flags[fp++] = 's';
    if (chan->modes & CMODE_M) flags[fp++] = 'm';
    if (chan->modes & CMODE_Z) flags[fp++] = 'z';
    if (chan->modes & CMODE_R) flags[fp++] = 'r';
    if (chan->modes & CMODE_PERM) flags[fp++] = 'P';
    if (chan->modes & CMODE_NOCTCP) flags[fp++] = 'C';
    if (chan->modes & CMODE_NONOTICE) flags[fp++] = 'T';
    if (chan->modes & CMODE_STRIPCOLOR) flags[fp++] = 'S';
    if (chan->modes & CMODE_NOINVITE) flags[fp++] = 'V';
    if (chan->modes & CMODE_NOKICK) flags[fp++] = 'Q';
    if (chan->modes & CMODE_NONICK) flags[fp++] = 'N';
    if ((chan->modes & CMODE_K) && chan->key[0]) {
        flags[fp++] = 'k';
        snprintf(args, sizeof args, " %s", chan->key);
    }
    if ((chan->modes & CMODE_L) && chan->limit > 0) {
        flags[fp++] = 'l';
        char lbuf[32];
        snprintf(lbuf, sizeof lbuf, " %d", chan->limit);
        strncat(args, lbuf, sizeof args - strlen(args) - 1);
    }
    flags[fp] = '\0';
    snprintf(out, outsz, "%s%s", flags, args);
}
