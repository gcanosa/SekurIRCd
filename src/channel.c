#include "channel.h"
#include "client.h"
#include "proto.h"

#include <ctype.h>
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
    free(chan->fp);
    free(chan->invited);
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

int channel_has_ops(channel_t *chan, struct client *cl) {
    member_t *m = channel_find_member(chan, cl);
    return m && (m->rank & (RANK_OP | RANK_HALFOP));
}

static const ban_extra_t *g_extra;
static ban_extra_t g_extra_copy;
static char g_extra_realname[256];

/* Copies `x` (the caller's is usually on its stack); NULL clears. The copied
 * `cl` pointer is dropped by server_remove_client so it can't dangle. */
void channel_set_ban_extra(const ban_extra_t *x) {
    if (!x) { g_extra = NULL; return; }
    snprintf(g_extra_realname, sizeof g_extra_realname, "%s", x->realname ? x->realname : "");
    g_extra_copy = *x;
    g_extra_copy.realname = g_extra_realname;
    g_extra = &g_extra_copy;
}

void channel_forget_ban_extra_for(const struct client *cl) {
    if (g_extra && g_extra->cl == cl) g_extra = NULL;
}

int channel_member_visible(const channel_t *chan, const member_t *subject, const member_t *viewer) {
    if (subject == viewer) return 1;
    if (subject->hidden) return 0;
    if (chan->modes & CMODE_AUDITORIUM) {
        if (subject->rank & (RANK_VOICE | RANK_HALFOP | RANK_OP)) return 1;
        return viewer && (viewer->rank & (RANK_HALFOP | RANK_OP));
    }
    return 1;
}

void channel_rank_prefix(int rank, int multi, char *out) {
    static const struct { int bit; char ch; } P[] = {{RANK_OWNER, '~'}, {RANK_ADMIN, '&'}, {RANK_OP, '@'}, {RANK_HALFOP, '%'}, {RANK_VOICE, '+'}};
    size_t n = 0;
    for (size_t i = 0; i < sizeof P / sizeof P[0]; i++) {
        if (!(rank & P[i].bit)) continue;
        out[n++] = P[i].ch;
        if (!multi) break;
    }
    out[n] = '\0';
}

int channel_rank_level(int rank) {
    return (rank & RANK_OWNER) ? 5 : (rank & RANK_ADMIN) ? 4 : (rank & RANK_OP) ? 3 : (rank & RANK_HALFOP) ? 2 : (rank & RANK_VOICE) ? 1 : 0;
}

/* A ~t:<mins>:<mask> timed entry matches as its inner mask; anything else is returned as is. */
static const char *mask_body(const char *mask) {
    if (strncasecmp(mask, "~t:", 3) != 0) return mask;
    const char *p = mask + 3;
    while (*p >= '0' && *p <= '9') p++;
    return (p > mask + 3 && *p == ':') ? p + 1 : mask;
}

int channel_mask_expired(const masklist_t *ml, int i, time_t now) {
    const char *m = ml->masks[i];
    if (mask_body(m) == m || !ml->set_at) return 0;
    return now >= ml->set_at[i] + (time_t)atol(m + 3) * 60;
}

int channel_mask_hit(const char *mask, const char *nick, const char *user,
                      const char *host, const char *account, int ident_confirmed) {
    mask = mask_body(mask);
    if (mask[0] == '~') mask++; /* EXTBAN=~,am -- the "~" prefix form is an alias for the bare one below */
    if (strncasecmp(mask, "f:", 2) == 0) { /* ~f:#chan:<mask> matches as <mask> (a channel name holds no ':') */
        const char *c = strchr(mask + 2, ':');
        if (!c) return 0;
        return channel_mask_hit(c + 1, nick, user, host, account, ident_confirmed);
    }
    if (strncasecmp(mask, "a:", 2) == 0) {
        if (!account || !account[0]) return 0; /* EXTBAN a: never matches a logged-out user */
        return irc_glob_match(mask + 2, account);
    }
    if (strncasecmp(mask, "r:", 2) == 0) { /* realname glob */
        return g_extra && g_extra->realname && irc_glob_match(mask + 2, g_extra->realname);
    }
    if (strcasecmp(mask, "z") == 0) return g_extra && g_extra->secure; /* anyone on a TLS connection */
    if (strncmp(mask, "S:", 2) == 0) { /* TLS client certificate fingerprint, colons optional */
        if (!g_extra || !g_extra->cl || !g_extra->cl->certfp[0]) return 0;
        const char *a = mask + 2, *b = g_extra->cl->certfp;
        for (;;) {
            while (*a == ':') a++;
            while (*b == ':') b++;
            if (!*a || !*b) return !*a && !*b;
            if (tolower((unsigned char)*a++) != tolower((unsigned char)*b++)) return 0;
        }
    }
    if (strncasecmp(mask, "j:", 2) == 0) { /* member of the named channel */
        if (!g_extra || !g_extra->cl) return 0;
        char cf[CHAN_NAMELEN];
        irc_casefold(cf, sizeof cf, mask + 2);
        for (const chan_node_t *n = g_extra->cl->channels; n; n = n->next)
            if (strcmp(n->chan->casefold_name, cf) == 0) return 1;
        return 0;
    }
    return irc_mask_match(nick, user, host, mask, ident_confirmed);
}

/* True if `mask` is the quiet extban (m:/~m:) rather than a structural ban --
 * channel_is_banned skips these (they don't block JOIN, only speaking; see
 * channel_is_quieted), and MODE +b/-b still adds/removes them normally
 * since they share the same list and MAXLIST cap as an ordinary ban. */
static int is_quiet_mask(const char *mask) { /* also ~n: -- an action ban, not a JOIN-blocking one */
    mask = mask_body(mask);
    if (mask[0] == '~') mask++;
    return strncasecmp(mask, "m:", 2) == 0 || strncasecmp(mask, "n:", 2) == 0;
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

/* Any "[~]<letter>:<mask>" action ban in +b that hits the user. */
static int action_ban_hit(channel_t *chan, char letter, const char *nick, const char *user, const char *host,
                          const char *realhost, const char *ip, const char *account, int ident_confirmed) {
    for (int i = 0; i < chan->bans.n; i++) {
        const char *mask = mask_body(chan->bans.masks[i]);
        const char *e = mask[0] == '~' ? mask + 1 : mask;
        if (tolower((unsigned char)e[0]) != letter || e[1] != ':') continue;
        if (mask_hit_any_host(e + 2, nick, user, host, realhost, ip, account, ident_confirmed)) return 1;
    }
    return 0;
}

int channel_is_quieted(channel_t *chan, const char *nick, const char *user,
                        const char *host, const char *realhost, const char *ip,
                        const char *account, int ident_confirmed) {
    return action_ban_hit(chan, 'm', nick, user, host, realhost, ip, account, ident_confirmed);
}

int channel_is_nickbanned(channel_t *chan, const char *nick, const char *user,
                          const char *host, const char *realhost, const char *ip,
                          const char *account, int ident_confirmed) {
    return action_ban_hit(chan, 'n', nick, user, host, realhost, ip, account, ident_confirmed);
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

int channel_ban_forward(channel_t *chan, const char *nick, const char *user, const char *host, const char *realhost,
                        const char *ip, const char *account, int ident_confirmed, char *out, size_t outsz) {
    for (int i = 0; i < chan->bans.n; i++) {
        const char *m = mask_body(chan->bans.masks[i]);
        if (strncasecmp(m, "~f:", 3) != 0) continue;
        const char *c = strchr(m + 3, ':');
        if (!c || !mask_hit_any_host(m, nick, user, host, realhost, ip, account, ident_confirmed)) continue;
        snprintf(out, outsz, "%.*s", (int)(c - (m + 3)), m + 3);
        return 1;
    }
    return 0;
}

int channel_is_invited(channel_t *chan, const char *invite_key, const char *nick, const char *user,
                        const char *host, const char *account, int ident_confirmed) {
    for (int i = 0; i < chan->n_invited; i++)
        if (strcmp(chan->invited[i], invite_key) == 0) return 1;
    for (int i = 0; i < chan->invex.n; i++)
        if (channel_mask_hit(chan->invex.masks[i], nick, user, host, account, ident_confirmed)) return 1;
    return 0;
}

/* The canonical form of a +b/+e/+I mask, as UnrealIRCd and hybrid store it, so a ban typed as a bare host or user@host
 * actually matches (a mask with no '!' or '@' is otherwise compared against the nick alone) and -b finds it again:
 * "1.2.3.4" or "2001:db8::/32" -> "*!*@...", "bob" -> "bob!*@*", "u@h" -> "*!u@h", "n!u" -> "n!u@*". UnrealIRCd 6
 * named extbans (~account: ~quiet: ~q: ~realname: ~channel: ~c:) become our letters; other extbans are kept as given. */
void channel_normalize_mask(const char *in, char *out, size_t outsz) {
    static const struct { const char *from, *to; } X[] = {
        {"account:", "a:"}, {"quiet:", "m:"}, {"q:", "m:"}, {"realname:", "r:"}, {"channel:", "j:"}, {"c:", "j:"}, {"nickchange:", "n:"}, {"certfp:", "S:"}, {"time:", "t:"}, {"forward:", "f:"}};
    if (in[0] == '~') {
        for (size_t i = 0; i < sizeof X / sizeof X[0]; i++) {
            size_t l = strlen(X[i].from);
            if (strncasecmp(in + 1, X[i].from, l) != 0) continue;
            char tmp[256];
            snprintf(tmp, sizeof tmp, "~%s%s", X[i].to, in + 1 + l);
            channel_normalize_mask(tmp, out, outsz);
            return;
        }
    }
    if (strncasecmp(in, "~t:", 3) == 0 && mask_body(in) != in) { /* ~t:<mins>:<mask>: normalise the mask inside */
        const char *body = mask_body(in);
        char inner[256];
        channel_normalize_mask(body, inner, sizeof inner);
        snprintf(out, outsz, "~t:%ld:%s", atol(in + 3), inner);
        return;
    }
    if (strncasecmp(in, "~f:", 3) == 0 && strchr(in + 3, ':')) { /* ~f:#chan:<mask>: normalise the mask */
        const char *c = strchr(in + 3, ':');
        char inner[256];
        channel_normalize_mask(c + 1, inner, sizeof inner);
        snprintf(out, outsz, "~f:%.*s:%s", (int)(c - (in + 3)), in + 3, inner);
        return;
    }
    const char *e = in[0] == '~' ? in + 1 : in;
    if (strncasecmp(e, "m:", 2) == 0 || strncasecmp(e, "n:", 2) == 0) { /* quiet / no nick change: the mask inside is an ordinary one */
        char inner[256];
        channel_normalize_mask(e + 2, inner, sizeof inner);
        snprintf(out, outsz, "%.*s%c:%s", (int)(e - in), in, e[0], inner);
        return;
    }
    if (in[0] == '~' || (e[0] && e[1] == ':' && strchr("arjAJR", e[0])) || strcasecmp(e, "z") == 0) {
        snprintf(out, outsz, "%s", in); /* another extban, or a legacy bare one (a:, r:, j:, z) */
        return;
    }
    int bang = strchr(in, '!') != NULL, at = strchr(in, '@') != NULL;
    if (bang && at) snprintf(out, outsz, "%s", in);
    else if (at) snprintf(out, outsz, "*!%s", in);
    else if (bang) snprintf(out, outsz, "%s@*", in);
    else if (strpbrk(in, ".:/")) snprintf(out, outsz, "*!*@%s", in);
    else snprintf(out, outsz, "%s!*@*", in);
}

int masklist_add(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++)
        if (strcasecmp(ml->masks[i], mask) == 0) return -1;
    if (ml->n >= CHAN_MAX_MASKLIST) return -1;
    if (!ml->masks) {
        ml->masks = calloc(CHAN_MAX_MASKLIST, sizeof ml->masks[0]);
        ml->set_at = calloc(CHAN_MAX_MASKLIST, sizeof ml->set_at[0]);
        ml->set_by = calloc(CHAN_MAX_MASKLIST, sizeof ml->set_by[0]);
        if (!ml->masks || !ml->set_at || !ml->set_by) { masklist_free(ml); return -1; }
    }
    snprintf(ml->masks[ml->n], sizeof ml->masks[0], "%s", mask);
    ml->set_at[ml->n] = time(NULL);
    ml->set_by[ml->n][0] = '\0';
    ml->n++;
    ml->gen++;
    const char *b = mask_body(mask);
    if (strncasecmp(b[0] == '~' ? b + 1 : b, "j:", 2) == 0) ml->dynamic = 1;
    return 0;
}

void masklist_free(masklist_t *ml) {
    free(ml->masks);
    free(ml->set_at);
    free(ml->set_by);
    ml->masks = NULL;
    ml->set_at = NULL;
    ml->set_by = NULL;
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
    if (g_extra) { /* ~r / ~z depend on these too */
        for (const unsigned char *p = (const unsigned char *)(g_extra->realname ? g_extra->realname : ""); *p; p++) h = (h ^ *p) * 16777619u;
        h = (h ^ (unsigned)g_extra->secure) * 16777619u;
    }
    unsigned lists_gen = chan->bans.gen + chan->exceptions.gen;
    int dynamic = chan->bans.dynamic || chan->exceptions.dynamic; /* ~j: verdicts can change with no list/identity change */
    if (m && !dynamic && m->cache_valid && m->cache_lists_gen == lists_gen && m->cache_ident_hash == h) {
        *banned = m->cache_banned; *quieted = m->cache_quieted;
        return;
    }
    *banned = channel_is_banned(chan, nick, user, host, realhost, ip, account, ident_confirmed);
    *quieted = channel_is_quieted(chan, nick, user, host, realhost, ip, account, ident_confirmed);
    if (m && !dynamic) {
        m->cache_valid = 1; m->cache_lists_gen = lists_gen; m->cache_ident_hash = h;
        m->cache_banned = (unsigned char)*banned; m->cache_quieted = (unsigned char)*quieted;
    }
}

int masklist_del(masklist_t *ml, const char *mask) {
    for (int i = 0; i < ml->n; i++) {
        if (strcasecmp(ml->masks[i], mask) == 0) {
            memmove(ml->masks[i], ml->masks[i + 1], (size_t)(ml->n - i - 1) * sizeof ml->masks[0]);
            memmove(&ml->set_at[i], &ml->set_at[i + 1], (size_t)(ml->n - i - 1) * sizeof ml->set_at[0]);
            memmove(ml->set_by[i], ml->set_by[i + 1], (size_t)(ml->n - i - 1) * sizeof ml->set_by[0]);
            ml->n--;
            ml->gen++;
            if (ml->n == 0) ml->dynamic = 0;
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
    char (*grown)[64] = client_list_grow(chan->invited, chan->n_invited, sizeof *grown);
    if (!grown) return; /* out of memory: the invite is simply not remembered, like one past the cap */
    chan->invited = grown;
    snprintf(chan->invited[chan->n_invited], sizeof chan->invited[0], "%s", casefold_nick);
    chan->n_invited++;
}

void channel_invite_remove(channel_t *chan, const char *casefold_nick) {
    for (int i = 0; i < chan->n_invited; i++) {
        if (strcmp(chan->invited[i], casefold_nick) == 0) {
            memmove(chan->invited[i], chan->invited[i + 1],
                    (size_t)(chan->n_invited - i - 1) * sizeof chan->invited[0]);
            chan->n_invited--;
            chan->invited = client_list_idle(chan->invited, chan->n_invited);
            return;
        }
    }
}

unsigned int channel_flag_bit(char c) {
    switch (c) {
        case 'n': return CMODE_N; case 'i': return CMODE_I; case 'p': return CMODE_P; case 't': return CMODE_T;
        case 's': return CMODE_S; case 'm': return CMODE_M; case 'z': return CMODE_Z; case 'r': return CMODE_R;
        case 'P': return CMODE_PERM; case 'C': return CMODE_NOCTCP; case 'T': return CMODE_NONOTICE; case 'S': return CMODE_STRIPCOLOR;
        case 'V': return CMODE_NOINVITE; case 'Q': return CMODE_NOKICK; case 'N': return CMODE_NONICK; case 'R': return CMODE_REGONLY;
        case 'O': return CMODE_OPERONLY; case 'M': return CMODE_MODREG; case 'c': return CMODE_NOCOLOR; case 'D': return CMODE_DELAYJOIN;
        case 'u': return CMODE_AUDITORIUM; case 'G': return CMODE_CENSOR; case 'K': return CMODE_NOKNOCK;
        default: return 0;
    }
}

void channel_modes_string(channel_t *chan, char *out, size_t outsz) {
    char flags[40] = "+";
    char args[256] = "";
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
    if (chan->modes & CMODE_DELAYJOIN) flags[fp++] = 'D';
    if (chan->modes & CMODE_AUDITORIUM) flags[fp++] = 'u';
    if (chan->modes & CMODE_CENSOR) flags[fp++] = 'G';
    if (chan->modes & CMODE_NOKNOCK) flags[fp++] = 'K';
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
    if ((chan->modes & CMODE_REDIRECT) && chan->redirect[0]) {
        flags[fp++] = 'L';
        char b[CHAN_NAMELEN + 2]; snprintf(b, sizeof b, " %s", chan->redirect);
        strncat(args, b, sizeof args - strlen(args) - 1);
    }
    if (chan->modes & CMODE_FLOOD) {
        flags[fp++] = 'f';
        char b[100] = " ";
        channel_flood_param(chan, b + 1, sizeof b - 1);
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

/* --- +f ------------------------------------------------------------------------------------------------------ */

void channel_clear_flood(channel_t *chan) {
    chan->modes &= ~CMODE_FLOOD;
    chan->flood_lines = chan->flood_secs = 0;
    free(chan->fp);
    chan->fp = NULL;
}

void channel_flood_param(const channel_t *chan, char *out, size_t outsz) {
    if (chan->fp) snprintf(out, outsz, "%s", chan->fp->spec);
    else snprintf(out, outsz, "%d:%d", chan->flood_lines, chan->flood_secs);
}

/* "<lines>:<secs>" (ours) or UnrealIRCd's "[5c#C15,10j#R,3k,20m#M10,4n,7t#b,3r#d]:15". Unknown types are dropped from
 * the stored form; actions outside UnrealIRCd's list for that type make the whole parameter invalid. */
int channel_set_flood(channel_t *chan, const char *param) {
    static const char *defaults = "CiKmNkk";        /* per FP_TYPES */
    static const char *allowed[] = {"CmM", "iR", "K", "mM", "N", "kb", "kbd"};
    if (param[0] != '[') {
        char *e1, *e2;
        long a = strtol(param, &e1, 10);
        if (e1 == param || *e1 != ':') return -1;
        long b = strtol(e1 + 1, &e2, 10);
        if (e2 == e1 + 1 || *e2 || a < 1 || a > 100 || b < 1 || b > 600) return -1;
        channel_clear_flood(chan);
        chan->flood_lines = (int)a; chan->flood_secs = (int)b;
        chan->modes |= CMODE_FLOOD;
        return 0;
    }
    const char *close = strstr(param, "]:");
    if (!close) return -1;
    char *e;
    long secs = strtol(close + 2, &e, 10);
    if (e == close + 2 || *e || secs < 1 || secs > 999) return -1;
    floodprot_t f = {0};
    size_t sp = 0;
    f.spec[sp++] = '[';
    int any = 0;
    for (const char *p = param + 1; p < close;) {
        char *ne;
        long n = strtol(p, &ne, 10);
        if (ne == p || n < 1 || n > 999 || ne >= close) return -1;
        char type = *ne++;
        char action = 0;
        long mins = 0;
        if (ne < close && *ne == '#') {
            action = ne[1];
            ne += 2;
            if (ne > close) return -1;
            if (ne < close && *ne >= '0' && *ne <= '9') { mins = strtol(ne, &ne, 10); if (mins > 999) return -1; }
        }
        if (ne < close && *ne != ',') return -1;
        p = ne < close ? ne + 1 : ne;
        const char *t = strchr(FP_TYPES, type);
        if (!t || !type) continue; /* a type we don't know: ignore it */
        int i = (int)(t - FP_TYPES);
        if (!action) action = defaults[i];
        if (!strchr(allowed[i], action)) return -1;
        f.limit[i] = (int)n; f.action[i] = action; f.unset_mins[i] = (int)mins;
        char item[24];
        if (action == defaults[i] && !mins) snprintf(item, sizeof item, "%s%ld%c", any ? "," : "", n, type);
        else if (mins) snprintf(item, sizeof item, "%s%ld%c#%c%ld", any ? "," : "", n, type, action, mins);
        else snprintf(item, sizeof item, "%s%ld%c#%c", any ? "," : "", n, type, action);
        if (sp + strlen(item) + 8 >= sizeof f.spec) return -1;
        memcpy(f.spec + sp, item, strlen(item)); sp += strlen(item);
        any = 1;
    }
    if (!any) return -1;
    snprintf(f.spec + sp, sizeof f.spec - sp, "]:%ld", secs);
    floodprot_t *nf = malloc(sizeof *nf);
    if (!nf) return -1;
    *nf = f;
    channel_clear_flood(chan);
    chan->fp = nf;
    chan->flood_lines = f.limit[5]; /* t: the per-user text limit the PRIVMSG path already enforces */
    chan->flood_secs = (int)secs;
    chan->modes |= CMODE_FLOOD;
    return 0;
}
