/* Global server state and registries. Ported (reduced scope for v1.0.1) from
 * sekurircd/src/sekurircd/server.py: the users/channels registries, the
 * registration/welcome sequence, MOTD delivery, and broadcast helpers.
 * Single-threaded poll() loop (net.c) drives everything here -- no locking,
 * same reasoning as the Python daemon's single asyncio event loop.
 */
#ifndef SEKURIRCD_SERVER_H
#define SEKURIRCD_SERVER_H

#include "accounts.h"
#include "channel.h"
#include "client.h"
#include "config.h"
#include "link.h"

#include <signal.h>
#include <time.h>

#define MOTD_MAX_LINES 200
#define MOTD_LINE_LEN  400
#define WHOWAS_MAX     200

typedef struct {
    char nick[NICKLEN], user[USERLEN], host[HOSTLEN], realname[REALNAMELEN];
} whowas_entry_t;

typedef struct kline_entry {
    char mask[256];      /* IP or hostname glob (see server_kline_add) */
    char reason[256];
    char set_by[128];
    char line_type[2];   /* "K" or "G" -- both enforced identically in v1.0.1 */
    time_t expires_at;   /* 0 = permanent */
    struct kline_entry *next;
} kline_entry_t;

typedef struct server {
    config_t cfg;
    int listen_fd;
    int tls_listen_fd;  /* -1 unless [tls] enabled (see net.c's TLS listener) */
    SSL_CTX *tls_ctx;
    int link_listen_fd; /* -1 unless [links] enabled + mode=hub (see link.h) */
    link_conn_t *links;  /* linked list of connected/pending link peers */
    double leaf_backoff;    /* leaf mode: current reconnect delay (doubles to reconnect_delay_max) */
    time_t leaf_next_attempt; /* leaf mode: 0 = try on the next tick */
    time_t start_time;

    client_t *users;        /* uthash, keyed by casefold_nick (registered clients) */
    channel_t *channels;    /* uthash, keyed by casefold_name */
    account_store_t accounts;
    client_t *all_clients;  /* doubly-linked list, EVERY live connection (net.c's poll set) */
    int n_clients;          /* includes not-yet-registered connections */
    uint64_t next_conn_id;  /* monotonic; see client_t.conn_id / worker.h */
    int max_users_seen;     /* peak of HASH_COUNT(users), for LOCALUSERS/GLOBALUSERS/STATSCONN */
    long total_connections; /* every accept(), regardless of whether it registered */
    time_t accept_paused_until; /* fd exhaustion: stop polling the listeners until then (see net.c) */
    long dnsbl_hits;        /* every connection a configured DNSBL zone listed, kline'd or just rejected */

    char motd_lines[MOTD_MAX_LINES][MOTD_LINE_LEN];
    int n_motd_lines;

    whowas_entry_t whowas[WHOWAS_MAX]; /* ring buffer */
    int whowas_head;                   /* next slot to write */
    int whowas_count;                  /* how many slots are valid (<= WHOWAS_MAX) */

    kline_entry_t *klines;
    int klines_dirty;       /* a write is pending -- net.c's tick flushes it (see server_kline_flush) */

    /* Exact concurrent-connection count per IP, maintained by
     * server_add_connection/unlink_connection -- replaces walking every
     * client on each accept() to enforce max_connections_per_ip. */
    struct ipcount *ip_counts;

    /* STATS m: per-command invocation counts. Linear array, fine at this
     * daemon's scale (a few dozen distinct command names). */
    struct { char name[32]; int count; } command_counts[64];
    int n_command_counts;

    uint64_t fanout_gen;   /* see server_send_common_channels */

    /* server_notify_opers()'s own flood guard -- see that function's doc
     * comment. Fixed-size ring, unlike Python's unbounded deque, but the
     * ring is sized to the same threshold so the suppression decision
     * matches exactly. */
    double snote_times[21];
    int snote_head, snote_count, snote_suppressed;

    volatile sig_atomic_t shutdown_requested;
    volatile sig_atomic_t rehash_requested;
    int restart_requested; /* DIE vs RESTART -- main.c execv's on exit if set */
} server_t;

/* "SekurIRCd-<version>" -- daemon-name+version form for wire fields that
 * must name the software (004 MYINFO, 351 VERSION). buf must hold at least
 * strlen("SekurIRCd-") + sizeof(cfg.server.version). */
void server_software_version(const server_t *srv, char *buf, size_t bufsz);

int server_init(server_t *srv, const config_t *cfg);
void server_load_motd(server_t *srv);
int server_rehash(server_t *srv, char *errbuf, size_t errbufsz);

client_t *server_find_user(server_t *srv, const char *nick);
channel_t *server_find_channel(server_t *srv, const char *name);
channel_t *server_get_or_create_channel(server_t *srv, const char *name); /* NULL on allocation failure */

/* Link a freshly-accepted connection into srv->all_clients (net.c's poll
 * set) -- called once, right after client_new. */
void server_add_connection(server_t *srv, client_t *cl);
/* Concurrent connections currently held by `ip` (max_connections_per_ip). */
int server_ip_count(server_t *srv, const char *ip);
/* Writes the K-line file if anything changed since the last flush. Called
 * from net.c's one-second tick: a connect flood or a DNSBL burst would
 * otherwise re-serialize and rewrite the whole list once per event. */
void server_kline_flush(server_t *srv);
/* Shutdown only: flush a pending K-line write and free the K-line list and
 * the per-IP counter table (the client sweep at shutdown frees clients
 * directly, bypassing unlink_connection's decrement). */
void server_free_tables(server_t *srv);
/* Register `cl` (casefold_nick already set) into srv->users. */
void server_add_user(server_t *srv, client_t *cl);
/* Tear down `cl`: broadcast QUIT to every channel-mate, leave every channel,
 * remove from srv->users and srv->all_clients, and free it. Does NOT close
 * cl->fd or touch net.c's pollfd array -- the caller (net.c, at the end of
 * a poll tick) owns the socket lifecycle. Safe to call exactly once per
 * client. */
void server_remove_client(server_t *srv, client_t *cl, const char *quit_reason);

/* Send 001-005 + LUSERS + MOTD, matching server._send_welcome's order. */
void server_send_welcome(server_t *srv, client_t *cl);
void server_send_motd(server_t *srv, client_t *cl);
void server_send_lusers(server_t *srv, client_t *cl);

/* Broadcast `line` (already built, no CRLF) to every member of `chan` except
 * `except` (may be NULL). */
void server_broadcast_channel(channel_t *chan, const char *line, client_t *except);
/* Send `line` once to every client sharing a channel with `cl` (not `cl`
 * itself), de-duplicated across all of cl's channels via a per-client
 * generation stamp -- O(total memberships), no seen-list cap. If `cap` is
 * nonzero, only recipients that negotiated that CAP_* bit get it. Used for
 * QUIT/NICK/AWAY/SETNAME/CHGHOST/ACCOUNT fan-out. */
void server_send_common_channels(server_t *srv, client_t *cl, const char *line, unsigned int cap);

/* log.c hook: relays log lines at/above [debug_channel] min_level as server
 * NOTICEs to [debug_channel] name. Installed by net_run. */
void server_install_debug_log_hook(server_t *srv);

/* Log `cl` in as `account` (+r, 900) and tell channel-mates with
 * account-notify. Shared by SASL and /REGISTER. */
void server_login(server_t *srv, client_t *cl, const char *account);

/* A server notice ("*** Notice -- <message>") to every currently-connected
 * oper with user mode +s set -- client connects, K/G-line add/remove/expiry,
 * a connection getting refused (limit/K-line/DNSBL), and DIE/RESTART. Ported
 * from Python's Server.notify_opers, including its own sliding-window flood
 * guard (at most 20 delivered in any 5s window; anything past that is
 * silently dropped with a one-line log warning and folded into the next
 * delivered notice's "(+N more notice(s) were suppressed)" suffix). */
void server_notify_opers(server_t *srv, const char *message);

/* Link `cl`'s channels list to include `chan` (does NOT touch chan->members
 * -- pair with channel_add_member). Shared by cmd_chan.c's JOIN paths and
 * link.c's trusted GUARD JOIN from a services link. */
/* Records `chan` in cl->channels. Returns -1 if the node couldn't be
 * allocated, in which case the caller must undo the channel-side join. */
int server_attach_membership(client_t *cl, channel_t *chan);
/* Inverse of server_attach_membership (does NOT touch chan->members --
 * pair with channel_remove_member). */
void server_detach_membership(client_t *cl, channel_t *chan);

/* Drop a channel from the registry (and free it) once it has zero members
 * and isn't otherwise persistent (v1.0.1 has no +P/registered-channel
 * persistence yet). */
void server_maybe_drop_channel(server_t *srv, channel_t *chan);

/* K/G-lines -- persisted to [security] klines_file if set (see
 * config_klines_path), in-memory only otherwise. Both line types are
 * enforced identically (matches Python's KlineEntry: "K" vs "G" is cosmetic
 * bookkeeping, not different enforcement). */
void server_kline_load(server_t *srv);
void server_kline_prune_expired(server_t *srv);
/* duration_secs == 0 means permanent. Always (re)saves. */
void server_kline_add(server_t *srv, const char *mask, const char *reason,
                       const char *set_by, const char *line_type, long duration_secs);
/* Returns 1 and removes+saves, or 0 if no line matched `mask` exactly. */
int server_kline_remove(server_t *srv, const char *mask);
/* First matching line's reason (K-Lined: <reason>), or NULL if `ip` isn't
 * listed. Does NOT prune expired lines itself -- call server_kline_prune_expired
 * periodically (net.c's tick). */
/* True if `mask` (of the given line type) hits this connection. Z matches the
 * IP alone; K and G also match user@host, in both the bare and tilde-prefixed
 * ident spellings. */
int server_line_mask_hits(const char *mask, const char *line_type, const char *ip,
                           const char *user, const char *host, int ident_confirmed);
const char *server_kline_match(server_t *srv, const char *ip, const char *user,
                                const char *host, int ident_confirmed);

/* Records nick/user/host/realname into the WHOWAS ring buffer -- called
 * from server_remove_client right before a client is freed. */
void server_whowas_record(server_t *srv, const char *nick, const char *user,
                           const char *host, const char *realname);

/* Removes `cl` from every other client's /MONITOR list and notifies
 * watchers of the online/offline transition (server->all_clients scan --
 * no separate reverse index, fine at this daemon's expected scale). Called
 * from cmd_nick (online) and server_remove_client (offline). */
void server_monitor_notify(server_t *srv, client_t *cl, int online);

/* Same as server_monitor_notify but for the legacy /WATCH list (600 RPL_LOGON /
 * 601 RPL_LOGOFF instead of MONITOR's 730/731) -- called from the same hook
 * points. */
void server_watch_notify(server_t *srv, client_t *cl, int online);

#endif /* SEKURIRCD_SERVER_H */
