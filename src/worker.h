/* A tiny pthread worker pool for the blocking work this daemon keeps off
 * the event loop: reverse DNS, RFC 1413 ident, DNSBL zone queries, and
 * scrypt password verify/hash for SASL and /REGISTER. Jobs carry a `conn_id` (not a pointer) so a result for a
 * connection that's already gone is safely dropped by the poll loop's own
 * lookup, never by touching freed memory from a worker thread.
 *
 * Every job type is bounded by its configured timeout: ident uses a
 * non-blocking connect plus SO_RCVTIMEO, and the two resolver jobs run their
 * blocking getaddrinfo/getnameinfo on a detached helper thread the worker
 * waits on with a deadline (see worker.c's dns_with_timeout for why there is
 * no portable timeout knob to use instead). A stuck resolver therefore ties
 * up neither the event loop nor a pool thread beyond that timeout.
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
    char text[256];  /* hostname / ident / first listed zone / (JOB_HASH) new scrypt string */
    int zone_code[WORKER_MAX_ZONES]; /* JOB_DNSBL: per submitted zone, the answer's last octet, or -1 = not listed */
    auth_purpose_t purpose; /* sasl/hash only, copied through from job_t */
} job_result_t;

void worker_pool_start(void);
/* Read end of a nonblocking self-pipe that becomes readable whenever a
 * result is ready -- net.c polls it so results apply immediately instead of
 * on the next 1-second poll timeout. Drain it before worker_poll_results. */
int worker_wake_fd(void);
void worker_drain_wake(void);
void worker_pool_stop(void); /* joins all threads; call once, at shutdown */
/* Queues a job. Returns 0 on success, -1 if the queue is at capacity (or the
 * allocation failed) -- the caller must then clear whatever *_pending flag it
 * set, so the connection isn't left waiting on a result that will never come.
 * JOB_SASL/JOB_HASH are queued ahead of the slower DNS jobs. */
int worker_submit(const job_t *job);
/* Drains up to `max` completed results into `out` (main thread only). */
int worker_poll_results(job_result_t *out, int max);

#endif /* SEKURIRCD_WORKER_H */
