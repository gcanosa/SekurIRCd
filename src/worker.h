/* A tiny pthread worker pool for the blocking work this daemon keeps off
 * the event loop: reverse DNS, RFC 1413 ident, DNSBL zone queries, and
 * scrypt password verify/hash for SASL and /REGISTER. Jobs carry a `conn_id` (not a pointer) so a result for a
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

typedef enum { JOB_RDNS, JOB_IDENT, JOB_DNSBL, JOB_SASL, JOB_HASH } job_type_t;

/* What a JOB_SASL/JOB_HASH result is *for* -- the worker itself doesn't
 * care (same scrypt verify/hash either way), this just tells net.c which
 * cmd_*.c completion function to call. Carried through job_t -> job_result_t
 * untouched. */
typedef enum { AUTH_SASL, AUTH_REGISTER, AUTH_OPER, AUTH_DIE, AUTH_RESTART } auth_purpose_t;

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
    char secret[256];  /* sasl/hash: plaintext password (cleansed after use) */
    char hash[256];    /* sasl only: stored scrypt string to verify against */
    auth_purpose_t purpose; /* sasl/hash only */
} job_t;

typedef struct {
    job_type_t type;
    uint64_t conn_id;
    int success;     /* 1 = got a usable result (hostname / ident / listed-zone) */
    char text[256];  /* hostname / ident / listed zone / (JOB_HASH) new scrypt string */
    auth_purpose_t purpose; /* sasl/hash only, copied through from job_t */
} job_result_t;

void worker_pool_start(void);
/* Read end of a nonblocking self-pipe that becomes readable whenever a
 * result is ready -- net.c polls it so results apply immediately instead of
 * on the next 1-second poll timeout. Drain it before worker_poll_results. */
int worker_wake_fd(void);
void worker_drain_wake(void);
void worker_pool_stop(void); /* joins all threads; call once, at shutdown */
void worker_submit(const job_t *job);
/* Drains up to `max` completed results into `out` (main thread only). */
int worker_poll_results(job_result_t *out, int max);

#endif /* SEKURIRCD_WORKER_H */
