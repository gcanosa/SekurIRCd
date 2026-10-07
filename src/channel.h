/* Per-channel state. Ported from sekurircd/src/sekurircd/channel.py:
 * members, topic, and a mode data model. Implements the argument-free flags
 * (n/i/p/t/s/m/z), o(p)/h(alfop)/v(oice) per-member rank, k (key) and l
 * (limit), and the three mask lists b/e/I (ban / exception / invite-
 * exception), with EXTBAN "a:<account>" support in the mask matcher.
 */
#ifndef SEKURIRCD_CHANNEL_H
#define SEKURIRCD_CHANNEL_H

#include "vendor/uthash.h"

#include <stddef.h>
#include <time.h>

struct client;

#define CHAN_NAMELEN 64
#define CHAN_TOPICLEN 512
#define TOPIC_MAX_LEN 307 /* advertised TOPICLEN, enforced in cmd_topic: prefix (<=~125) + TOPIC cmd + channel + topic must fit one 512-byte line */
#define CHAN_KEYLEN 64
#define CHAN_MAX_MASKLIST 100  /* matches the ballpark real ircds advertise */
#define CHAN_MAX_INVITED 64    /* ponytail: capped, unlike upstream's unbounded set;
                                 * an invite past this cap is simply not remembered */

#define RANK_VOICE  0x1
#define RANK_HALFOP 0x2
#define RANK_OP     0x4
#define RANK_ADMIN  0x8  /* a: protected -- implies op (RANK_OP is always set alongside) */
#define RANK_OWNER  0x10 /* q: channel owner -- implies op, outranks admin */

#define CMODE_N 0x001 /* no external messages */
#define CMODE_I 0x002 /* invite-only */
#define CMODE_P 0x004 /* private */
#define CMODE_T 0x008 /* topic settable by ops only */
#define CMODE_S 0x010 /* secret (hidden from LIST) */
#define CMODE_M 0x020 /* moderated */
#define CMODE_K 0x040 /* keyed */
#define CMODE_L 0x080 /* limited */
#define CMODE_Z 0x100 /* secure-only: only TLS clients (or opers) may JOIN */
#define CMODE_R 0x200 /* registered with services -- set/cleared by a trusted
                        * service link only, see cmd_apply_channel_mode */
#define CMODE_PERM       0x400  /* P: channel survives going empty */
#define CMODE_NOCTCP     0x800  /* C: block CTCP to the channel */
#define CMODE_NONOTICE   0x1000 /* T: block NOTICE to the channel */
#define CMODE_STRIPCOLOR 0x2000 /* S: strip mIRC colour/formatting from messages */
#define CMODE_NOINVITE   0x4000 /* V: /INVITE disabled */
#define CMODE_NOKICK     0x8000 /* Q: /KICK disabled except for IRCOps */
#define CMODE_NONICK     0x10000 /* N: members may not change nickname */
#define CMODE_REGONLY    0x20000 /* R: only users with an account (+r) may JOIN */
#define CMODE_OPERONLY   0x40000 /* O: only IRC operators may JOIN */
#define CMODE_MODREG     0x80000 /* M: only voice+/an account/an oper may speak */
#define CMODE_FLOOD      0x200000 /* f <lines>:<secs>: kick a non-privileged member who exceeds the message rate */
#define CMODE_JTHROT     0x400000 /* j <joins>:<secs>: refuse JOINs once the channel-wide join rate is exceeded */
#define CMODE_REDIRECT   0x800000  /* L <#chan>: a JOIN refused by +l (full) or +i is forwarded to that channel */
#define CMODE_DELAYJOIN  0x1000000 /* D: a joiner stays invisible until they speak (or get a rank) */
#define CMODE_AUDITORIUM 0x2000000 /* u: ordinary members are visible only to ranked members (and themselves) */
#define CMODE_CENSOR     0x4000000 /* G: configured bad words in messages are starred out */
#define CMODE_NOCOLOR    0x100000 /* c: reject (not just strip) a message containing colour/formatting codes */

typedef struct member {
    struct client *client;
    int rank; /* RANK_OP | RANK_HALFOP | RANK_VOICE */
    /* channel_ban_state() cache: the verdict holds while the channel's ban/
     * exception lists and the client's identity are unchanged. */
    int hidden;                       /* +D: joined but not yet revealed -- see channel_member_visible */
    time_t fl_start;                  /* +f window start for this member */
    int fl_count;
    unsigned cache_lists_gen, cache_ident_hash;
    unsigned char cache_valid, cache_banned, cache_quieted;
    UT_hash_handle hh; /* keyed by the client pointer itself */
} member_t;

typedef struct {
    char (*masks)[256]; /* allocated on the first add -- most channels never have a ban, and
                         * three inline 100x256 lists made every channel ~80 KB */
    int n;
    unsigned gen;       /* bumped on every add/del; invalidates member_t's cached ban verdict */
    int dynamic;        /* holds a ~j: extban, whose verdict depends on other channels -> never cached */
} masklist_t;

/* One remembered PRIVMSG/NOTICE (CHATHISTORY). Fixed-size so a ring of them is one allocation. */
typedef struct {
    char msgid[48];
    long long ms;       /* epoch milliseconds */
    char sender[160];   /* nick!user@host at send time */
    char account[32];
    char verb[8];       /* "PRIVMSG" / "NOTICE" */
    char text[420];
} hist_entry_t;

typedef struct channel {
    char name[CHAN_NAMELEN];          /* display case */
    char casefold_name[CHAN_NAMELEN]; /* hash key */
    char topic[CHAN_TOPICLEN];
    char topic_setter[128];           /* nick!user@host that last set it */
    time_t topic_time;
    time_t created;
    unsigned int modes;               /* CMODE_* bitmask */
    char key[CHAN_KEYLEN];            /* +k value, "" if unset */
    int limit;                        /* +l value, 0 if unset */
    char redirect[CHAN_NAMELEN];      /* +L target */
    int flood_lines, flood_secs;      /* +f */
    int jt_joins, jt_secs;            /* +j */
    int jt_count;                     /* joins seen in the current +j window */
    time_t jt_start;
    masklist_t bans;                  /* +b */
    masklist_t exceptions;            /* +e */
    masklist_t invex;                 /* +I */
    char invited[CHAN_MAX_INVITED][64]; /* client_invite_key()s /INVITE has admitted past +i */
    int n_invited;
    hist_entry_t *hist;               /* ring, allocated on the first remembered message */
    int hist_cap, hist_head, hist_n;  /* capacity, index of the oldest entry, entries held */
    member_t *members;                /* uthash, keyed by client ptr */
    UT_hash_handle hh;                /* server->channels, keyed by casefold_name */
} channel_t;

channel_t *channel_new(const char *name, const char *casefold_name);
void channel_free(channel_t *chan);

member_t *channel_find_member(channel_t *chan, struct client *cl);
member_t *channel_add_member(channel_t *chan, struct client *cl); /* NULL on allocation failure */
void channel_remove_member(channel_t *chan, struct client *cl);
int channel_member_count(channel_t *chan);

int channel_is_op(channel_t *chan, struct client *cl);
int channel_is_halfop(channel_t *chan, struct client *cl);
int channel_has_ops(channel_t *chan, struct client *cl); /* op OR halfop */
int channel_is_voice(channel_t *chan, struct client *cl);

/* Mask matcher shared by ban/exception/invex/VHOST-style checks: a mask
 * starting with "a:" matches by SASL account (empty account never matches);
 * anything else is a plain nick!user@host glob (irc_mask_match). */
int channel_mask_hit(const char *mask, const char *nick, const char *user,
                      const char *host, const char *account, int ident_confirmed);
/* True if the m:/~m: quiet extban hits (see channel.c) -- blocks speaking,
 * not JOIN, unlike a structural +b. Not affected by +e (exceptions are for
 * structural bans; a chanop removes a specific quiet with -b instead). */
int channel_is_quieted(channel_t *chan, const char *nick, const char *user,
                        const char *host, const char *realhost, const char *ip,
                        const char *account, int ident_confirmed);
/* True if banned (+b hit) and not exempted (+e hit). Checked against `host`
 * (the displayed/possibly-cloaked host) AND `realhost`/`ip` -- a mask
 * written against the real hostname or bare IP must still catch a client
 * whose displayed host is a random per-connection cloak (host_masking), and
 * vice versa. Pass realhost/ip == host if unavailable (never NULL). */
int channel_is_banned(channel_t *chan, const char *nick, const char *user,
                       const char *host, const char *realhost, const char *ip,
                       const char *account, int ident_confirmed);
/* `invite_key` is client_invite_key(): invites are keyed by connection, not nick,
 * so a quit invitee's nick can't be taken over to use the invite.
 * True if past +i via an exact INVITE (channel_invite_add) or an +I mask hit. */
int channel_is_invited(channel_t *chan, const char *invite_key, const char *nick, const char *user,
                        const char *host, const char *account, int ident_confirmed);

/* Extra facts the ~r (realname), ~z (secure connection) and ~j:#chan (member of
 * another channel) extbans match on. Set by the caller around a ban/exception/
 * invex check (single-threaded -- a plain global is enough); NULL = those
 * extbans simply don't match. */
typedef struct {
    const char *realname;
    int secure;
    const struct client *cl; /* for ~j: its channel list */
} ban_extra_t;
void channel_set_ban_extra(const ban_extra_t *x);
void channel_forget_ban_extra_for(const struct client *cl); /* call when a client is freed */

/* Banned (JOIN-blocking, after exceptions) and quieted verdicts for a member,
 * cached on `m` -- PRIVMSG used to walk every mask three times per message. */
void channel_ban_state(channel_t *chan, member_t *m, const char *nick, const char *user,
                       const char *host, const char *realhost, const char *ip,
                       const char *account, int ident_confirmed, int *banned, int *quieted);
/* The status prefix characters for `rank` (all of them, "~&@%+" order, when `multi`; else only the highest). `out` needs 6 bytes. */
void channel_rank_prefix(int rank, int multi, char *out);
/* 0 none, 1 voice, 2 halfop, 3 op, 4 admin, 5 owner -- who may act on whom. */
int channel_rank_level(int rank);

/* May `viewer` (NULL = a non-member) see that `subject` is in the channel? False for a not-yet-revealed +D member,
 * and under +u for an unranked member seen by an unranked viewer. A member always sees themself. */
int channel_member_visible(const channel_t *chan, const member_t *subject, const member_t *viewer);

/* Remember a message (no-op when cap <= 0). Oldest entries fall off. */
void channel_history_add(channel_t *chan, int cap, const char *msgid, long long ms, const char *sender,
                         const char *account, const char *verb, const char *text);
/* i-th oldest remembered entry (0 = oldest), or NULL. */
const hist_entry_t *channel_history_at(const channel_t *chan, int i);
void masklist_free(masklist_t *ml);
int masklist_add(masklist_t *ml, const char *mask); /* 0 ok, -1 dup/full */
int masklist_del(masklist_t *ml, const char *mask); /* 0 removed, -1 not found */

void channel_invite_add(channel_t *chan, const char *casefold_nick);
void channel_invite_remove(channel_t *chan, const char *casefold_nick); /* called on JOIN */

/* Render the channel's current modes as a MODE-line string, e.g. "+ntk key"
 * (key/limit only included when set). Writes into `out`. */
void channel_modes_string(channel_t *chan, char *out, size_t outsz);

#endif /* SEKURIRCD_CHANNEL_H */
