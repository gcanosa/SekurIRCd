/* A tiny pthread worker pool for the three blocking lookups this daemon
 * needs off the event loop: reverse DNS, RFC 1413 ident, and DNSBL zone
 * queries. Jobs carry a `conn_id` (not a pointer) so a result for a
 * connection that's already gone is safely dropped by the poll loop's own
 * lookup, never by touching freed memory from a worker thread.
 *
 * ponytail: no per-job timeout enforcement inside the worker (getnameinfo/
 * gethostbyname/ident's own socket timeout are the only bounds) -- a stuck
 * DNS resolver ties up one of N_WORKERS threads, never the event loop.
 * Bump N_WORKERS (worker.c) if that's ever observed to matter.
 */
#ifndef SEKURIRCD_WORKER_H
#define SEKURIRCD_WORKER_H

#include <stdint.h>

typedef enum { JOB_RDNS, JOB_IDENT, JOB_DNSBL } job_type_t;

#define WORKER_MAX_ZONES 16

typedef struct {
    job_type_t type;
    uint64_t conn_id;
    char ip[64];
    int remote_port;   /* ident only: the client's own TCP port */
    int local_port;     /* ident only: our side's TCP port */
    double timeout;
    char zones[WORKER_MAX_ZONES][256]; /* dnsbl only */
    int n_zones;
} job_t;

typedef struct {
    job_type_t type;
    uint64_t conn_id;
    int success;     /* 1 = got a usable result (hostname / ident / listed-zone) */
    char text[256];
} job_result_t;

void worker_pool_start(void);
void worker_pool_stop(void); /* joins all threads; call once, at shutdown */
void worker_submit(const job_t *job);
/* Drains up to `max` completed results into `out` (main thread only). */
int worker_poll_results(job_result_t *out, int max);

#endif /* SEKURIRCD_WORKER_H */
