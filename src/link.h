/* Server-to-server linking. Newline-delimited IRC lines (proto.c). One listener accepts both ChanServ-style service
 * links and real server links; a peer that sends "CAPAB :SEKURNET" before SERVER is a server (see netsync.h for the
 * state-sharing protocol: UIDs, bursts, SJOIN/TS, netsplits). Servers form a tree and may be many: `links.mode`
 * "hub" accepts, "leaf" dials its configured peers, "both" does both; every [[links.peers]] entry with a host is
 * dialled (with backoff) unless links.autoconnect is false.
 *
 * Handshake: dialer sends "PASS <secret>", (CAPAB), "SERVER <name> <proto> :<desc>"; the acceptor verifies the peer
 * against [[links.peers]] (name + password/password_hash, allowed_ips) and replies in kind, then bursts.
 * A service link then speaks:
 *   NICK <nick> <user> <host> :<realname>   -- introduce a service pseudo-client (up to LINK_MAX_BOTS; a later line
 *                                              acts as the bot its ":nick!user@host" prefix names, else the first)
 *   SVCWATCH USERS                          -- subscribe to the user feed (link_svc_user)
 *   SVSLOGIN/SVSNICK/KILL/SVCSASL/SVCREGRESULT <id> ...  -- account services (cmd_reg.c's svc_command)
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
#define LINK_MAX_BOTS 4
#define LINK_SENDQ_MAX (16u * 1024 * 1024) /* a peer this far behind is dead or desynced: drop the link, it relinks and rebursts */

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
    int tls_sniff;          /* loopback peer on a TLS link listener: not yet known whether it speaks TLS (link_tls_try_handshake) */
    time_t last_ping;        /* when link_tick last sent a keepalive PING */
    char rbuf[LINK_BUF];
    size_t rbuf_len;
    char *sbuf;              /* send queue, grown on demand (a burst to a new peer can be megabytes), freed when drained */
    size_t sbuf_len, sbuf_off, sbuf_cap; /* queued bytes are sbuf[sbuf_off .. sbuf_len) */
    time_t created;         /* absolute deadline for the handshake -- an unauthenticated
                              * peer can otherwise hold the slot forever just by
                              * sending junk, since that keeps last_activity fresh */
    time_t last_activity;
    struct client *service; /* the first pseudo-client this link introduced (ChanServ), or NULL -- the default actor */
    struct client *bots[LINK_MAX_BOTS]; /* every one it introduced (a services daemon hosts ChanServ + NickServ) */
    int n_bots;
    int watch_users;        /* sent SVCWATCH USERS: gets the network's users and their changes (NickServ) */
    int is_server;          /* negotiated the SEKURNET state-sync protocol (see netsync.h); else a plain/service link */
    int peer_capab_sekurnet; /* acceptor side: the dialer sent CAPAB :SEKURNET before SERVER */
    char peer_capab[200];    /* the peer's CAPAB text ("SEKURNET PROTO=n MINPROTO=n VERSION=..."), see netsync_check_peer */
    struct netserver *nserver; /* is_server: the directly linked server's table entry */
    struct link_conn *next;
} link_conn_t;

/* Start the hub link listener if [links] enabled+mode=hub; returns the fd
 * (also stored on srv) or -1 if links aren't enabled (not an error). */
int link_start_hub(struct server *srv);

/* Dial every [[links.peers]] entry with a `host` that isn't linked yet (PASS/CAPAB/SERVER handshake, briefly blocking --
 * link establishment is rare, see link.c's dial_peer). `force` ignores the reconnect backoff; `only_name` limits it to
 * one peer (/CONNECT). An authenticated link joins srv->links. Returns how many links came up. */
int link_dial_peers(struct server *srv, int force, const char *only_name);

/* net.c's periodic tick for leaf mode: reconnects with backoff
 * (links.reconnect_delay doubling to reconnect_delay_max) whenever there's
 * no currently-authenticated uplink. No-op unless mode=leaf+enabled. */
void link_leaf_tick(struct server *srv); /* dials any due dial-out peer */

/* net.c integration: accept a new inbound link connection. */
void link_accept(struct server *srv, int listen_fd); /* the IPv4 listener or its IPv6 twin */
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

/* The services user feed (links with watch_users): SVCUSER <uid> <nick> <user> <realhost> <ip> <account|*> <certfp|*>
 * <server> on connect/update, SVCNICK <uid> <nick>, SVCQUIT <uid>, SVCACCOUNT <uid> <account|*>. Service bots are skipped. */
enum { SVC_EV_USER, SVC_EV_NICK, SVC_EV_QUIT, SVC_EV_ACCOUNT };
void link_svc_user(struct server *srv, struct client *cl, int ev);

#endif /* SEKURIRCD_LINK_H */
