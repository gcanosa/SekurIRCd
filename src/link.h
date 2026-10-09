/* Server-to-server linking. Newline-delimited IRC lines (proto.c). One listener accepts both ChanServ-style service
 * links and real server links; a peer that sends "CAPAB :SEKURNET" before SERVER is a server (see netsync.h for the
 * state-sharing protocol: UIDs, bursts, SJOIN/TS, netsplits). Servers form a tree and may be many: `links.mode`
 * "hub" accepts, "leaf" dials its configured peers, "both" does both; every [[links.peers]] entry with a host is
 * dialled (with backoff) unless links.autoconnect is false.
 *
 * Handshake: dialer sends "PASS <secret>", (CAPAB), "SERVER <name> <proto> :<desc>"; the acceptor verifies the peer
 * against [[links.peers]] (name + password/password_hash, allowed_ips) and replies in kind, then bursts.
 * A service link then speaks:
 *   NICK <nick> <user> <host> :<realname>   -- introduce a service pseudo-client
 *   PRIVMSG/NOTICE <target> :<text>         -- literal IRC lines, relayed verbatim
 *   PING / PONG                             -- keepalive
 * A pseudo-client (client_t with fd == -1) forwards client_send() over its link_conn's socket (see client.c).
 */
#ifndef SEKURIRCD_LINK_H
#define SEKURIRCD_LINK_H

#include <openssl/ssl.h>

#include <stddef.h>
#include <time.h>

struct server;
struct client;
struct channel;

#define LINK_BUF 8192

typedef struct link_conn {
    int fd;
    char ip[64];             /* peer address, captured at accept() -- used for K-line/per-IP checks and logging */
    char peer_name[128];
    char pending_pass[256]; /* PASS seen, waiting for the following SERVER line */
    int authenticated;
    int closing;            /* link_close() called -- freed by link_reap() at end of loop tick */
    SSL *ssl;                /* non-NULL iff [links] tls=true for this connection */
    int tls_handshaking;    /* hub side only: SSL_accept() hasn't completed yet (leaf side
                              * blocks through its handshake in link_connect_leaf, see there) */
    int tls_want_write;     /* last SSL_accept() said WANT_WRITE -- see net.c's tls_try_handshake */
    time_t last_ping;        /* when link_tick last sent a keepalive PING */
    char rbuf[LINK_BUF];
    size_t rbuf_len;
    char sbuf[LINK_BUF * 4];
    size_t sbuf_len;
    time_t created;         /* absolute deadline for the handshake -- an unauthenticated
                              * peer can otherwise hold the slot forever just by
                              * sending junk, since that keeps last_activity fresh */
    time_t last_activity;
    struct client *service; /* the pseudo-client this link introduced, or NULL */
    int is_server;          /* negotiated the SEKURNET state-sync protocol (see netsync.h); else a plain/service link */
    int peer_capab_sekurnet; /* acceptor side: the dialer sent CAPAB :SEKURNET before SERVER */
    struct netserver *nserver; /* is_server: the directly linked server's table entry */
    struct link_conn *next;
} link_conn_t;

/* Start the hub link listener if [links] enabled+mode=hub; returns the fd
 * (also stored on srv) or -1 if links aren't enabled (not an error). */
int link_start_hub(struct server *srv);

/* Leaf mode: dial the single configured uplink peer (PASS/SERVER
 * handshake, briefly blocking -- link establishment is rare, not a
 * per-request path, see link.c's dial_uplink comment). On success, the new
 * authenticated link_conn_t joins srv->links (so /LINKS, /SQUIT, and the
 * existing ping/timeout tick all just work). Returns 0 on success, -1 on
 * failure (logged; net.c's leaf reconnect tick retries with backoff).
 * ponytail: no user/channel state mirroring over this link (see the plan)
 * -- two sekurircd nodes linked this way authenticate and stay connected,
 * but don't yet share users/channels the way the original Python design
 * did; that scope was dropped from the start of this port. */
int link_dial_peers(struct server *srv, int force, const char *only_name);

/* net.c's periodic tick for leaf mode: reconnects with backoff
 * (links.reconnect_delay doubling to reconnect_delay_max) whenever there's
 * no currently-authenticated uplink. No-op unless mode=leaf+enabled. */
void link_leaf_tick(struct server *srv); /* dials any due dial-out peer */

/* net.c integration: accept a new inbound link connection. */
void link_accept(struct server *srv);
/* net.c integration, hub side, lc->tls_handshaking only: drives (or re-drives)
 * SSL_accept() until it completes or genuinely needs to wait for more I/O
 * (mirrors net.c's own tls_try_handshake for client connections). */
void link_tls_try_handshake(struct server *srv, link_conn_t *lc);
/* net.c integration: fd is readable -- read, parse complete lines, dispatch. */
void link_handle_readable(struct server *srv, link_conn_t *lc);
/* net.c integration: fd is writable and lc->sbuf_len > 0 -- flush it. */
void link_handle_writable(struct server *srv, link_conn_t *lc);
/* Mark a link for teardown (peer gone, error, SQUIT). Safe to call from
 * anywhere, any number of times: nothing is freed until link_reap(), so a
 * caller still holding `lc` (net.c's poll array, a handler) never touches
 * freed memory. */
void link_close(struct server *srv, link_conn_t *lc);
/* net.c, end of each loop iteration: free every closing link, removing its
 * service pseudo-client (if any) from the users registry and channels. */
void link_reap(struct server *srv);
/* net.c integration: periodic tick -- ping timeout. */
void link_tick(struct server *srv);
/* net.c, at shutdown: frees the lazily-created client-side SSL_CTX used to
 * dial a TLS hub in leaf mode (link_connect_leaf). No-op if links.tls was
 * never used (mode=hub, or leaf without tls). */
void link_tls_cleanup(void);

/* client_send()'s hook for a service pseudo-client: forward an already-built
 * IRC line verbatim to this link's peer. */
void link_forward_line(link_conn_t *lc, const char *line);

/* Ported (scoped) from Python's full-mirror _on_join: tells a services link
 * about `joiner` entering `chan`, but only if that link's own service
 * pseudo-client is CURRENTLY a member of `chan` (i.e. a GUARDed, registered
 * channel) -- narrower than upstream's "every join, everywhere", but the
 * only case ChanServ (ACCESS/AKICK) actually needs, so it doesn't require
 * full network-wide state mirroring to work. Called from cmd_chan.c right
 * after a JOIN is announced locally. */
void link_notify_channel_join(struct channel *chan, struct client *joiner);
void link_notify_channel_new(struct server *srv, struct channel *chan, struct client *creator);

#endif /* SEKURIRCD_LINK_H */
