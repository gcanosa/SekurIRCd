/* Protection bundle: the optional abuse-protection layer (config/protection.toml).
 *
 * This module owns the two pieces that are new state rather than plain
 * config: the DNSBL blacklist policy (per-zone reply codes) and the active
 * open-proxy scanner. On connect it tries to relay through the client's own
 * address -- HTTP CONNECT, HTTP POST, SOCKS4, SOCKS5 -- back to this server's
 * public address; if the connect banner comes back through, the address is an
 * open proxy and gets banned. Scans are non-blocking sockets driven by the
 * same poll() loop as everything else (net.c), never the worker pool: a
 * 10-second probe would park one of only four worker threads.
 *
 * Off unless [scanner] enabled = true. Connection caps, the connect-flood
 * throttle, the per-client flood guard and [spam] also live in the bundle's
 * config file, but those are plain cfg.security.* / cfg.spam.* overlays (see
 * config.h) and need nothing from here.
 */
#ifndef SEKURIRCD_PROTECTION_H
#define SEKURIRCD_PROTECTION_H

#include "config.h"
#include "proto.h"

#include <poll.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct server;
struct client;
typedef struct protection_scan protection_scan_t;

#define PROT_NEGCACHE_SLOTS 1024
#define PROT_RECENT_SLOTS   64

typedef struct { uint32_t ip; time_t until; } prot_slot_t;

typedef struct {
    protection_scan_t *scans; /* in-flight probe sockets */
    int n_scans;
    long scanned;             /* addresses that finished a scan, clean or not */
    long hits;                /* open proxies confirmed */
    /* Direct-mapped: a collision just evicts, costing one redundant rescan.
     * ponytail: fixed tables, no LRU -- bump the slot counts if a network
     * ever sees thousands of distinct connecting IPs per negcache window. */
    prot_slot_t negcache[PROT_NEGCACHE_SLOTS];
    prot_slot_t recent[PROT_RECENT_SLOTS];
} protection_state_t;

/* One-line summaries into the log (-> #server-debug); startup and /REHASH. */
void protection_reload(struct server *srv);
void protection_free(struct server *srv);

/* IP matches an [exempt] glob: never DNSBL-checked or scanned. */
int protection_exempt(const cfg_protection_t *p, const char *ip);
/* True while `ip` is being scanned (or just was): the relayed probe
 * connections that come back to our listener must not trip the connect-flood
 * throttle, the per-IP cap, or trigger a scan of their own. */
int protection_ip_related(struct server *srv, const char *ip);
/* Begin scanning `ip` (all configured protocols). Returns the number of
 * probes started; 0 if disabled, exempt, negcached, already scanning, or over
 * scanner.max_concurrent. */
int protection_scan_start(struct server *srv, const char *ip);

/* Poll-loop hooks (net.c). fill appends this module's fds at fds[*n..] and
 * their scan pointers at fd_scan[*n..]. */
void protection_poll_fill(struct server *srv, struct pollfd *fds, protection_scan_t **fd_scan, int *n);
/* False once a scan has been freed (a hit frees all probes for its address, so
 * a poll-result slot for a sibling probe can outlive it within one iteration). */
int protection_scan_live(struct server *srv, const protection_scan_t *scan);
void protection_handle(struct server *srv, protection_scan_t *scan, short revents);
void protection_tick(struct server *srv);
int protection_negcache_count(struct server *srv);

/* Pure helpers (unit-tested). */
/* First blacklist (config order) whose listing bans: returns its index and the
 * matched reply text, or -1. codes[i] is zone i's reply octet, -1 = not listed. */
int protection_bl_match(const cfg_protection_t *p, const int *codes, int n, char *reply, size_t replysz);
/* %i -> ip, %t -> t, %r / %p -> r ("%%" -> "%"). */
void protection_expand(const char *tmpl, const char *ip, const char *t, const char *r, char *out, size_t outsz);
/* Builds the bytes a probe writes: stage 0 is the first write, stage 1 is
 * SOCKS5's connect request (sent after the method reply). Returns the length,
 * 0 on a bad target. */
size_t protection_probe_bytes(int type, const char *target_ip, int port, int stage,
                              unsigned char *out, size_t cap);
/* Offset of `needle` in `hay` (binary-safe), or -1. */
long protection_find(const unsigned char *hay, size_t n, const char *needle);

/* /PROTECT [SCAN <ip>] -- server-oper only. */
void cmd_protect(struct server *srv, struct client *cl, irc_message_t *msg);

#endif
