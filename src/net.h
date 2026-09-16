/* poll() event loop: listener setup and the main run loop. */
#ifndef SEKURIRCD_NET_H
#define SEKURIRCD_NET_H

#include <sys/types.h>

struct server;

/* CPU%/RSS(KB) for `pid` via `ps` -- see net.c for why not /proc.
 * Returns 0 on success, -1 if `pid` doesn't exist. */
int proc_stats(pid_t pid, double *cpu_pct, long *rss_kb);

/* Bind+listen a nonblocking TCP socket. IPv4 only in v1.0.1 (matches the
 * "0.0.0.0"/"127.0.0.1" defaults in the config template) -- returns the fd,
 * or -1 on error. */
int net_listen(const char *bind_addr, int port);
int net_set_nonblocking(int fd);

/* Runs until srv->shutdown_requested. Returns 0 normally. */
int net_run(struct server *srv);

#endif /* SEKURIRCD_NET_H */
