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
    masklist_free(&chan->bans);
    masklist_free(&chan->exceptions);
    masklist_free(&chan->invex);
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
    if (!m) return NULL;
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
                      const char *host, const char *account, int ident_confirmed) {
    if (mask[0] == '~') mask++; /* EXTBAN=~,am -- the "~" prefix form is an alias for the bare one below */
    if (strncasecmp(mask, "a:", 2) == 0) {
        if (!account || !account[0]) return 0; /* EXTBAN a: never matches a logged-out user */
        return irc_glob_match(mask + 2, account);
    }
    return irc_mask_match(nick, user, host, mask, ident_confirmed);
}

/* True if `mask` is the quiet extban (m:/~m:) rather than a structural ban --
 * channel_is_banned skips these (they don't block JOIN, only speaking; see
 * channel_is_quieted), and MODE +b/-b still adds/removes them normally
 * since they share the same list and MAXLIST cap as an ordinary ban. */
static int is_quiet_mask(const char *mask) {
    if (mask[0] == '~') mask++;
    return strncasecmp(mask, "m:", 2) == 0;
}

/* True if `mask` hits any of host/realhost/ip (see channel_is_banned's doc). */
static int mask_hit_any_host(const char *mask, const char *nick, const char *user,
                              const char *host, const char *realhost, const char *ip,
                              const char *account, int ident_confirmed) {
    if (channel_mask_hit(mask, nick, user, host, account, ident_confirmed)) return 1;
    if (strcmp(realhost, host) != 0 && channel_mask_hit(mask, nick, user, realhost, account, ident_confirmed)) return 1;
    if (strcmp(ip, host) != 0 && strcmp(ip, realhost) != 0 && channel_mask_hit(mask, nick, user, ip, account, ident_confirmed)) return 1;
    return 0;
}

int channel_is_quieted(channel_t *chan, const char *nick, const char *user,
                        const char *host, const char *realhost, const char *ip,
                        const char *account, int ident_confirmed) {
    for (int i = 0; i < chan->bans.n; i++) {
        const char *mask = chan->bans.masks[i];
        if (!is_quiet_mask(mask)) continue;
        const char *m = mask[0] == '~' ? mask + 3 : mask + 2; /* skip "m:"/"~m:" */
        if (mask_hit_any_host(m, nick, user, host, realhost, ip, account, ident_confirmed)) return 1;
    }
    return 0;
}

int channel_is_banned(channel_t *chan, const char *nick, const char *user,
                       const char *host, const char *realhost, const char *ip,
                       const char *account, int ident_confirmed) {
    int banned = 0;
    for (int i = 0; i < chan->bans.n && !banned; i++) {
        if (is_quiet_mask(chan->bans.masks[i])) continue; /* quiet, not a JOIN-blocking ban */
        if (mask_hit_any_host(chan->bans.masks[i], nick, user, host, realhost, ip, account, ident_confirmed)) banned = 1;
    }
    if (!banned) return 0;
    for (int i = 0; i < chan->exceptions.n; i++)
        if (mask_hit_any_host(chan->exceptions.masks[i], nick, user, host, realhost, ip, account, ident_confirmed)) return 0;
    return 1;
}

int channel_is_invited(channel_t *chan, const char *invite_key, const char *nick, const char *user,
                        const char *host, const char *account, int ident_confirmed) {
    for (int i = 0; i < chan->n_invited; i++)
        if (strcmp(chan->invited[i], invite_key) == 0) return 1;
    for (int i = 0; i < chan->invex.n; i++)
        if (channel_mask_hit(chan->invex.masks[i], nick, user, host, account, ident_confirmed)) return 1;
    return 0;
}

int masklist_add(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++)
        if (strcasecmp(ml->masks[i], mask) == 0) return -1;
    if (ml->n >= CHAN_MAX_MASKLIST) return -1;
    if (!ml->masks) {
        ml->masks = calloc(CHAN_MAX_MASKLIST, sizeof ml->masks[0]);
        if (!ml->masks) return -1;
    }
    snprintf(ml->masks[ml->n], sizeof ml->masks[0], "%s", mask);
    ml->n++;
    ml->gen++;
    return 0;
}

void masklist_free(masklist_t *ml) {
    free(ml->masks);
    ml->masks = NULL;
    ml->n = 0;
}

void channel_ban_state(channel_t *chan, member_t *m, const char *nick, const char *user,
                       const char *host, const char *realhost, const char *ip,
                       const char *account, int ident_confirmed, int *banned, int *quieted) {
    /* FNV-1a over everything the mask matchers look at: a few dozen bytes,
     * versus up to ~100 globs x 3 hosts per ban list. */
    unsigned h = 2166136261u;
    const char *parts[] = {nick, user, host, realhost, ip, account};
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++) {
        for (const unsigned char *p = (const unsigned char *)parts[i]; *p; p++) h = (h ^ *p) * 16777619u;
        h = (h ^ 0xffu) * 16777619u; /* field separator */
    }
    h = (h ^ (unsigned)ident_confirmed) * 16777619u;
    unsigned lists_gen = chan->bans.gen + chan->exceptions.gen;
    if (m && m->cache_valid && m->cache_lists_gen == lists_gen && m->cache_ident_hash == h) {
        *banned = m->cache_banned; *quieted = m->cache_quieted;
        return;
    }
    *banned = channel_is_banned(chan, nick, user, host, realhost, ip, account, ident_confirmed);
    *quieted = channel_is_quieted(chan, nick, user, host, realhost, ip, account, ident_confirmed);
    if (m) {
        m->cache_valid = 1; m->cache_lists_gen = lists_gen; m->cache_ident_hash = h;
        m->cache_banned = (unsigned char)*banned; m->cache_quieted = (unsigned char)*quieted;
    }
}

int masklist_del(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++) {
        if (strcasecmp(ml->masks[i], mask) == 0) {
            memmove(ml->masks[i], ml->masks[i + 1], (size_t)(ml->n - i - 1) * sizeof ml->masks[0]);
            ml->n--;
            ml->gen++;
            return 0;
        }
    }
    return -1;
}

void channel_invite_add(channel_t *chan, const char *casefold_nick) {
    for (int i = 0; i < chan->n_invited; i++)
        if (strcmp(chan->invited[i], casefold_nick) == 0) return;
    if (chan->n_invited >= CHAN_MAX_INVITED) { /* full: evict the oldest -- stale entries of quit invitees would otherwise block new invites forever */
        memmove(chan->invited[0], chan->invited[1], (size_t)(CHAN_MAX_INVITED - 1) * sizeof chan->invited[0]);
        chan->n_invited--;
    }
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
    char flags[32] = "+";
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
    if (chan->modes & CMODE_REGONLY) flags[fp++] = 'R';
    if (chan->modes & CMODE_OPERONLY) flags[fp++] = 'O';
    if (chan->modes & CMODE_MODREG) flags[fp++] = 'M';
    if (chan->modes & CMODE_NOCOLOR) flags[fp++] = 'c';
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
    if ((chan->modes & CMODE_FLOOD) && chan->flood_lines > 0) {
        flags[fp++] = 'f';
        char b[32]; snprintf(b, sizeof b, " %d:%d", chan->flood_lines, chan->flood_secs);
        strncat(args, b, sizeof args - strlen(args) - 1);
    }
    if ((chan->modes & CMODE_JTHROT) && chan->jt_joins > 0) {
        flags[fp++] = 'j';
        char b[32]; snprintf(b, sizeof b, " %d:%d", chan->jt_joins, chan->jt_secs);
        strncat(args, b, sizeof args - strlen(args) - 1);
    }
    flags[fp] = '\0';
    snprintf(out, outsz, "%s%s", flags, args);
}
