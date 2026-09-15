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
#define CHAN_KEYLEN 64
#define CHAN_MAX_MASKLIST 100  /* matches the ballpark real ircds advertise */
#define CHAN_MAX_INVITED 64    /* ponytail: capped, unlike upstream's unbounded set;
                                 * an invite past this cap is simply not remembered */

#define RANK_VOICE  0x1
#define RANK_HALFOP 0x2
#define RANK_OP     0x4

#define CMODE_N 0x001 /* no external messages */
#define CMODE_I 0x002 /* invite-only */
#define CMODE_P 0x004 /* private */
#define CMODE_T 0x008 /* topic settable by ops only */
#define CMODE_S 0x010 /* secret (hidden from LIST) */
#define CMODE_M 0x020 /* moderated */
#define CMODE_K 0x040 /* keyed */
#define CMODE_L 0x080 /* limited */
#define CMODE_Z 0x100 /* secure-only: only TLS clients (or opers) may JOIN */

typedef struct member {
    struct client *client;
    int rank; /* RANK_OP | RANK_HALFOP | RANK_VOICE */
    UT_hash_handle hh; /* keyed by the client pointer itself */
} member_t;

typedef struct {
    char masks[CHAN_MAX_MASKLIST][256];
    int n;
} masklist_t;

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
    masklist_t bans;                  /* +b */
    masklist_t exceptions;            /* +e */
    masklist_t invex;                 /* +I */
    char invited[CHAN_MAX_INVITED][64]; /* casefolded nicks /INVITE has admitted past +i */
    int n_invited;
    member_t *members;                /* uthash, keyed by client ptr */
    UT_hash_handle hh;                /* server->channels, keyed by casefold_name */
} channel_t;

channel_t *channel_new(const char *name, const char *casefold_name);
void channel_free(channel_t *chan);

member_t *channel_find_member(channel_t *chan, struct client *cl);
member_t *channel_add_member(channel_t *chan, struct client *cl);
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
                      const char *host, const char *account);
/* True if banned (+b hit) and not exempted (+e hit). */
int channel_is_banned(channel_t *chan, const char *nick, const char *user,
                       const char *host, const char *account);
/* True if past +i via an exact INVITE (channel_invite_add) or an +I mask hit. */
int channel_is_invited(channel_t *chan, const char *nick, const char *user,
                        const char *host, const char *account);

int masklist_add(masklist_t *ml, const char *mask); /* 0 ok, -1 dup/full */
int masklist_del(masklist_t *ml, const char *mask); /* 0 removed, -1 not found */

void channel_invite_add(channel_t *chan, const char *casefold_nick);
void channel_invite_remove(channel_t *chan, const char *casefold_nick); /* called on JOIN */

/* Render the channel's current modes as a MODE-line string, e.g. "+ntk key"
 * (key/limit only included when set). Writes into `out`. */
void channel_modes_string(channel_t *chan, char *out, size_t outsz);

#endif /* SEKURIRCD_CHANNEL_H */
