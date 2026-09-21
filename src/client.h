/* Per-connection state. Ported (reduced scope for v1.0.1) from
 * sekurircd/src/sekurircd/client.py: nick/user/registration status, a
 * sliding-window flood guard, and the raw send/reply to the socket. Owns its
 * own read/write buffers -- net.c drives the actual poll()/read()/write().
 */
#ifndef SEKURIRCD_CLIENT_H
#define SEKURIRCD_CLIENT_H

#include "vendor/uthash.h"

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

struct channel;
struct server;
struct link_conn;

#define SPAM_TRACK  32          /* spam.c: recent sends remembered per client */
#define NICKLEN     64
#define USERLEN     64
#define HOSTLEN     256
#define REALNAMELEN 512
#define SENDQ_MAX   (1 << 20)   /* 1 MiB, then disconnect: "SendQ exceeded" */
#define RECVQ_MAX   (1 << 16)   /* defensive cap on an unterminated partial line */

/* self-togglable via MODE, same letters as security.default_user_modes */
#define UMODE_I 0x01
#define UMODE_W 0x02
#define UMODE_D 0x04  /* d: suppress CTCP (except ACTION) in private messages */
#define UMODE_S 0x08  /* receive server notices */
#define UMODE_O 0x10  /* oper -- only /OPER may set this */
#define UMODE_Z 0x20  /* Z: secure (TLS) connection -- server-set only */
#define UMODE_R 0x40  /* identified to an account (SASL or /REGISTER) -- server-set only */
#define UMODE_P        0x80   /* p: hide channel list in /WHOIS */
#define UMODE_HIDEIDLE 0x100  /* I: hide idle time in /WHOIS */
#define UMODE_H        0x200  /* H: hide oper status from non-opers -- oper-only settable */
#define UMODE_Q        0x400  /* q: unkickable from channels except by IRCOps */
#define UMODE_REGONLY  0x800  /* R: only accept PMs from identified (registered-account) users */
#define UMODE_NOPM     0x1000 /* D: accept PMs from nobody except IRCOps */

typedef struct chan_node {
    struct channel *chan;
    struct chan_node *next;
} chan_node_t;

#define AUTH_STYLE_LEGACY 0   /* SASL numerics / plain /REGISTER notice */
#define AUTH_STYLE_NICKSERV 1 /* NOTICE from NickServ */
#define AUTH_STYLE_DRAFT 2    /* draft/account-registration REGISTER SUCCESS */

typedef struct client {
    int fd;                       /* -1 for a service pseudo-client (see link.h) */
    struct link_conn *link_conn;  /* non-NULL iff fd == -1: where to forward client_send() */
    SSL *ssl;                     /* non-NULL for a TLS connection (see net.c's TLS listener) */
    int tls_handshaking;          /* SSL_accept() hasn't completed yet */
    int quitting;                /* marked for removal at end of this poll tick */
    char quit_reason[256];

    char ip[64];
    int port;
    char host[HOSTLEN];       /* displayed host */
    char realhost[HOSTLEN];   /* actual resolved/connecting host, for oper WHOIS */

    char nick[NICKLEN];
    char casefold_nick[NICKLEN];
    char user[USERLEN];
    char realname[REALNAMELEN];
    unsigned int umodes;

    int got_nick, got_user;
    int cap_negotiating;  /* true between "CAP LS" and "CAP END" */
    int registered;       /* welcome burst already sent */

    char oper_name[64];   /* "" if not opered */
    int is_service;       /* introduced by a trusted link as a service bot (chanserv) */
    char account[64];     /* "" if not logged in (SASL or /REGISTER) -- see accounts.h */
    char sasl_mech[16];   /* "" outside an AUTHENTICATE exchange; "PLAIN" mid-exchange */
    int oper_fails;       /* consecutive failed /OPER attempts -- see cmd_oper.c _MAX_OPER_FAILS */

    char monitor[100][NICKLEN]; /* /MONITOR watch list, casefolded nicks -- MAX_MONITOR */
    int n_monitor;
    char watch[128][NICKLEN];   /* legacy /WATCH list, casefolded nicks -- MAX_WATCH */
    int n_watch;
    char silence[15][256];      /* /SILENCE mask list -- _MAX_SILENCE */
    int n_silence;

    unsigned int caps; /* CAP_* bitmask -- see cmd_reg.c's CAP_ATTRS table */

    uint64_t conn_id;      /* stable identity for a worker.c job result, immune to fd reuse */
    char your_id[18];      /* random hex shown as 042 RPL_YOURID -- conn_id is sequential, would leak connection count/order */
    int rdns_pending;       /* reverse-DNS lookup in flight -- gates welcome */
    int ident_pending;      /* RFC 1413 ident query in flight -- gates welcome */
    int dnsbl_pending;      /* DNSBL zone lookup in flight -- gates ALL dispatch, not just welcome */
    int ident_confirmed;    /* an identd answered -- cl->user is authoritative, no "~" prefix */
    int auth_pending;       /* SASL verify / REGISTER hash running on a worker (scrypt is ~30ms) */
    time_t auth_started;    /* when auth_pending was set -- net.c's tick clears a result that never came back */
    char pending_account[64];
    int auth_style;         /* AUTH_STYLE_*: how to word the result of the pending login/register */
    int register_attempts;  /* /REGISTER is unauthenticated account creation: cap it per connection */
    time_t register_last;

    uint64_t fanout_mark;   /* server_send_common_channels dedupe stamp */

    int is_away;
    char away[400];

    time_t signon_time;
    time_t last_activity;   /* last line received */
    int ping_sent;          /* a PING is outstanding, awaiting PONG */

    time_t flood_window_start;
    int flood_count;

    /* Spam protection (spam.c): recent (target, text) sends, deduped per pair. */
    struct { uint32_t tgt, txt; time_t at; } spam_ring[SPAM_TRACK];
    int spam_head;

    chan_node_t *channels;

    char *rbuf; size_t rbuf_len, rbuf_cap;
    char *sbuf; size_t sbuf_len, sbuf_cap;

    struct server *srv;

    /* server->all_clients doubly-linked list -- EVERY live connection,
     * registered or not, so net.c can build the poll() set without walking
     * the (nick-keyed, so nick-less-until-NICK) users hash. */
    struct client *all_next, *all_prev;

    UT_hash_handle hh; /* server->users, keyed by casefold_nick (once NICK is known) */
} client_t;

client_t *client_new(int fd, struct server *srv);
void client_free(client_t *cl);

/* Compute the display prefix "nick!~user@host" (or "nick@host" pre-USER). */
void client_prefix(const client_t *cl, char *out, size_t outsz);
/* "+iwZ" etc -- the self-togglable/server-set umode letters currently on
 * cl, same set cmd_mode_user's bare query and the post-MOTD RPL_UMODEIS
 * (server_send_welcome) both report. */
void client_mode_string(const client_t *cl, char *out, size_t outsz);

/* Queue a raw line (no CRLF) for sending; appends CRLF, grows sbuf, and marks
 * `cl` quitting with "SendQ exceeded" if it would exceed SENDQ_MAX. */
void client_send(client_t *cl, const char *line);

/* Build+queue a numeric reply: ":<server> <code> <nick> <params...> :<trailing>". */
void client_reply(client_t *cl, const char *code, const char **params, int nparams, const char *trailing);

/* True if this connection may send another message right now, updating the
 * sliding window as a side effect (same semantics as Client.flood_ok). */
int client_flood_ok(client_t *cl, int max_msgs, double window_seconds);

#endif /* SEKURIRCD_CLIENT_H */
