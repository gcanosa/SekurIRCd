/* Multi-server networking ("netsync"): a tree of linked sekurircd servers that share users, channels and state.
 *
 * Topology: a tree. Every server has a name and a 3-character SID; every user has a network-unique UID
 * (SID + 6 chars). A message from one server floods along the tree (each server forwards what it receives on
 * link L to every other server link); a message for one user is routed toward that user's server.
 *
 * The wire protocol (newline-delimited IRC lines, see proto.c) is spoken only on links that negotiated it with
 * "CAPAB :SEKURNET" during the handshake. Links without it (ChanServ and other service links, or a peer that
 * predates this) behave exactly as before: authenticated, no state sync.
 *
 *   handshake   PASS <secret> / CAPAB :SEKURNET / SERVER <name> <hop> <sid> :<desc>   (both directions)
 *   burst       :<sid> SERVER <name> <hop> <sid> :<desc>               one per server behind the sender
 *               :<sid> UID <nick> <hop> <nickts> <+modes> <user> <host> <realhost> <ip> <uid> <account|*> <identd 0|1> :<realname>
 *               :<uid> AWAY :<msg>                                      for away users
 *               :<sid> SJOIN <chants> <#chan> <+modes> [args] :<[~&@%+]uid ...>
 *               :<sid> BMASK <chants> <#chan> <b|e|I> :<mask mask ...>
 *               :<sid> TB <#chan> <topicts> <setter> :<topic>
 *               :<sid> GLINE <mask> <setter> <expires|0> :<reason>
 *               :<sid> EOB
 *   runtime     :<uid> NICK <newnick> <ts>       :<uid> QUIT :<reason>        :<uid> JOIN <chants> <#chan>
 *               :<uid> PART <#chan> :<reason>    :<uid> KICK <#chan> <uid> :<reason>
 *               :<uid> TOPIC <#chan> :<text>     :<uid> MODE <#chan> <modes> [args]   :<uid> UMODE <+modes>
 *               [@tags] :<uid> PRIVMSG|NOTICE|TAGMSG <target> [:text]     (target: uid, #chan, or @#chan etc.)
 *               :<uid> INVITE <uid> <#chan>      :<uid> AWAY [:msg]           :<uid> SETNAME :<realname>
 *               :<sid> CHGHOST <uid> <user> <host>   :<sid> ACCOUNT <uid> <account|*>
 *               :<uid> KILL <uid> :<reason>      :<sid> SQUIT <sid> :<reason>
 *               :<sid> PUSH <uid> :<raw line>    (deliver a reply/notice to a user on the receiving server)
 *               :<uid> WALLOPS|GLOBOPS :<text>   :<uid> RENAME <#old> <#new> :<reason>
 *               :<sid> GLINE ... / UNGLINE <mask>
 * Channel state converges by timestamp (TS6-style): the older channel wins; the younger side drops its modes and
 * strips its members' ranks. A nick collision is settled by nick timestamp (older wins, a tie kills both).
 */
#ifndef SEKURIRCD_NETSYNC_H
#define SEKURIRCD_NETSYNC_H

#include "proto.h"
#include "vendor/uthash.h"

#include <stddef.h>
#include <time.h>

struct server;
struct client;
struct channel;
struct link_conn;

#define SID_LEN 3
#define UID_LEN 9

typedef struct netserver {
    char name[128];
    char sid[SID_LEN + 1];
    char desc[128];
    int hop;                       /* links away from us (0 = us) */
    struct netserver *uplink;      /* next server toward us; NULL for ourselves */
    struct link_conn *route;       /* the local link that leads there; NULL for ourselves */
    int n_users;
    UT_hash_handle hh;             /* srv->servers, keyed by sid */
} netserver_t;

/* --- table / identity ------------------------------------------------------------------------------- */
void netsync_init(struct server *srv);                 /* creates the self entry; call after the config is loaded */
void netsync_free(struct server *srv);
netserver_t *netsync_find_sid(struct server *srv, const char *sid);
netserver_t *netsync_find_name(struct server *srv, const char *name);
/* Is `s` equal to, or behind (in the tree), `ancestor`? */
int netsync_is_behind(const netserver_t *s, const netserver_t *ancestor);
/* Give a just-registered local client its UID (and index it). Idempotent. */
void netsync_assign_uid(struct server *srv, struct client *cl);
struct client *netsync_find_uid(struct server *srv, const char *uid);
/* Derived SID for a server name when [server] sid is unset. */
void netsync_default_sid(const char *name, char *out /* >= SID_LEN+1 */);
/* The server name a client lives on (ours for local clients). */
const char *netsync_server_name_of(struct server *srv, const struct client *cl);

/* --- links ------------------------------------------------------------------------------------------ */
/* Handshake finished on `lc` with a SEKURNET peer `name`/`sid`/`desc` (hop = 1): register it, send our burst.
 * Returns 0, or -1 (after sending an ERROR) if the name or SID is already on the network. */
int netsync_link_up(struct server *srv, struct link_conn *lc, const char *name, const char *sid, const char *desc);
/* The link is gone (or was SQUIT): remove the servers and users behind it. */
void netsync_link_down(struct server *srv, struct link_conn *lc, const char *reason);
/* One line from a SEKURNET link, already parsed. */
void netsync_handle(struct server *srv, struct link_conn *lc, irc_message_t *msg);
int netsync_has_links(const struct server *srv);

/* --- local events -> the rest of the network (all no-ops without server links) ---------------------- */
void netsync_introduce_user(struct server *srv, struct client *cl);              /* registration complete */
void netsync_user_quit(struct server *srv, struct client *cl, const char *reason);
void netsync_user_nick(struct server *srv, struct client *cl);                   /* after the nick changed */
void netsync_user_modes(struct server *srv, struct client *cl);                  /* current umodes */
void netsync_user_away(struct server *srv, struct client *cl);
void netsync_user_chghost(struct server *srv, struct client *cl);                /* user/host changed */
void netsync_user_setname(struct server *srv, struct client *cl);
void netsync_user_account(struct server *srv, struct client *cl);                /* login/logout */
void netsync_chan_join(struct server *srv, struct channel *chan, struct client *cl, int created);
void netsync_chan_part(struct server *srv, struct channel *chan, struct client *cl, const char *reason);
void netsync_chan_kick(struct server *srv, struct channel *chan, struct client *kicker, struct client *target, const char *reason);
void netsync_chan_topic(struct server *srv, struct channel *chan, struct client *setter, const char *text);
void netsync_chan_mode(struct server *srv, struct channel *chan, struct client *setter, const char *modes, const char **args, int nargs);
void netsync_chan_rename(struct server *srv, struct channel *chan, struct client *cl, const char *oldname, const char *reason);
void netsync_invite(struct server *srv, struct client *from, struct client *target, struct channel *chan);
/* PRIVMSG/NOTICE/TAGMSG: `target` is as typed (#chan, @#chan, or a nick -> sent as the target's UID if remote). `tags` is
 * a ready "@k=v;k2=v2" string or "" . A target that is a local user needs no relay (returns without sending). */
void netsync_message(struct server *srv, struct client *from, const char *verb, const char *target,
                     struct client *remote_target, const char *text, const irc_tag_t *tags, int ntags);
void netsync_kill(struct server *srv, struct client *oper, struct client *target, const char *reason);
void netsync_wallops(struct server *srv, struct client *from, const char *verb, const char *text); /* WALLOPS / GLOBOPS */
void netsync_gline(struct server *srv, const char *mask, const char *setter, long expires, const char *reason);
void netsync_ungline(struct server *srv, const char *mask);
/* Reply/notice for a user on another server. */
void netsync_push(struct server *srv, struct client *target, const char *line);

/* --- remote -> local application, implemented in cmd_*.c ---------------------------------------------- */
void cmd_deliver_remote_message(struct server *srv, struct client *from, const char *verb, const char *target,
                                const char *text, const irc_message_t *tags);
void netsync_squit_command(struct server *srv, struct client *oper, const char *name, const char *reason);

#endif
