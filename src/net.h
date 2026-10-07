/* poll() event loop: listener setup and the main run loop. */
#ifndef SEKURIRCD_NET_H
#define SEKURIRCD_NET_H

#include "config.h"

#include <sys/types.h>

struct server;
struct client;

/* CPU%/RSS(KB) for `pid` via `ps` -- see net.c for why not /proc.
 * Returns 0 on success, -1 if `pid` doesn't exist. */
int proc_stats(pid_t pid, double *cpu_pct, long *rss_kb);

/* Bind+listen a nonblocking TCP socket. IPv4 only in v1.0.1 (matches the
 * "0.0.0.0"/"127.0.0.1" defaults in the config template) -- returns the fd,
 * or -1 on error. */
int net_listen(const char *bind_addr, int port);
int net_set_nonblocking(int fd);

/* Per-IP connect-rate throttle used by accept_common -- exposed (non-static)
 * only so tests/unit.c can exercise it directly. Returns 1 once `ip` exceeds
 * sec->connect_flood_max connects within sec->connect_flood_window seconds. */
int net_connect_flood_hit(const cfg_security_t *sec, const char *ip);

/* Runs until srv->shutdown_requested. Returns 0 normally. */
/* Restores the client's default displayed host (cloak if host_masking, else
 * realhost) -- for VHOST/SETHOST "off". Caller broadcasts the CHGHOST. */
/* [[classes]]: put `cl` in the first class whose hosts match its IP (releasing any earlier one).
 * Returns -1, leaving it in no class, if that class is already full. */
int net_assign_class(struct server *srv, struct client *cl);
void net_release_class(struct server *srv, struct client *cl);
void net_reclass_all(struct server *srv); /* after a rehash changed the class list */
void net_reset_host(struct server *srv, struct client *cl);
/* After a rehash: rebind any listener whose bind/port changed, open/close listeners that were enabled/disabled,
 * and reload the TLS certificate. A bind failure keeps the old listener (logged) -- never leaves it dead. */
void net_apply_listeners(struct server *srv);
int net_run(struct server *srv);

#endif /* SEKURIRCD_NET_H */
