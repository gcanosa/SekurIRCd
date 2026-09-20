#include "worker.h"
#include "crypto.h"
#include "proto.h"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define N_WORKERS 4
#define RESULT_RING 256
/* Bound on queued-but-not-yet-run jobs. Every accepted connection can enqueue
 * up to three (rDNS + ident + DNSBL), so a resolver having a bad day used to
 * let this grow without limit. Past the cap, submit fails and the caller
 * clears its own *_pending flag, so the client proceeds immediately instead
 * of waiting out net.c's 30-second rescue. */
#define QUEUE_MAX 4096

typedef struct qnode {
    job_t job;
    struct qnode *next;
} qnode_t;

static pthread_mutex_t g_qmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_qcond = PTHREAD_COND_INITIALIZER;
static qnode_t *g_qhead = NULL, *g_qtail = NULL;
static int g_qlen = 0;
static volatile int g_running = 0;
static pthread_t g_threads[N_WORKERS];
static int g_nthreads = 0;

static pthread_mutex_t g_rmutex = PTHREAD_MUTEX_INITIALIZER;
static job_result_t g_results[RESULT_RING];
static int g_result_head = 0, g_result_tail = 0;
static int g_wake[2] = {-1, -1};

int worker_wake_fd(void) { return g_wake[0]; }

void worker_drain_wake(void) {
    char buf[64];
    while (read(g_wake[0], buf, sizeof buf) > 0) {}
}

static void push_result(const job_result_t *r) {
    pthread_mutex_lock(&g_rmutex);
    int next = (g_result_tail + 1) % RESULT_RING;
    if (next != g_result_head) { /* ring full: drop -- the client's own timeout tick will move on */
        g_results[g_result_tail] = *r;
        g_result_tail = next;
    }
    pthread_mutex_unlock(&g_rmutex);
    if (write(g_wake[1], "", 1) < 0) { /* EAGAIN: pipe already full of wakeups -- fine */ }
}

int worker_poll_results(job_result_t *out, int max) {
    int n = 0;
    pthread_mutex_lock(&g_rmutex);
    while (g_result_head != g_result_tail && n < max) {
        out[n++] = g_results[g_result_head];
        g_result_head = (g_result_head + 1) % RESULT_RING;
    }
    pthread_mutex_unlock(&g_rmutex);
    return n;
}

static int do_rdns(const char *ip, char *out, size_t outsz) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return 0;
    char host[256];
    /* NI_NAMEREQD: fail (rather than fall back to the numeric IP) when
     * there's no PTR record -- "not found" must look like "not found". */
    if (getnameinfo((struct sockaddr *)&sa, sizeof sa, host, sizeof host, NULL, 0, NI_NAMEREQD) != 0) return 0;
    /* The PTR record is controlled by whoever owns the IP block: reject
     * junk characters and require forward confirmation (the name must
     * resolve back to this IP), or anyone could claim e.g. staff.example. */
    if (!irc_valid_host(host)) return 0;
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    int confirmed = 0;
    for (ai = res; ai && !confirmed; ai = ai->ai_next)
        confirmed = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr == sa.sin_addr.s_addr;
    freeaddrinfo(res);
    if (!confirmed) return 0;
    snprintf(out, outsz, "%s", host);
    return 1;
}

/* Standard reversed-octet DNSBL query convention (Spamhaus/SORBS/etc). */
static int do_dnsbl(const job_t *j, char *out, size_t outsz) {
    unsigned int a, b, c, d;
    if (sscanf(j->ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    for (int i = 0; i < j->n_zones; i++) {
        char query[300];
        snprintf(query, sizeof query, "%u.%u.%u.%u.%s", d, c, b, a, j->zones[i]);
        /* getaddrinfo, not gethostbyname: this runs on N_WORKERS threads at
         * once and gethostbyname returns a shared static buffer. */
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        if (getaddrinfo(query, NULL, &hints, &res) == 0) {
            freeaddrinfo(res);
            snprintf(out, outsz, "%s", j->zones[i]);
            return 1;
        }
    }
    return 0;
}

/* --- bounded resolver calls ------------------------------------------------
 *
 * getaddrinfo/getnameinfo have no timeout knob that works on both glibc and
 * macOS's libinfo (glibc's per-thread _res isn't honored by macOS at all), so
 * dnsbl.timeout / security.rdns_timeout used to be parsed, range-checked, and
 * then silently ignored -- a resolver that never answered parked one of the
 * N_WORKERS threads for as long as it felt like.
 *
 * Run the blocking call on a detached helper thread and wait on a timed
 * condvar instead: the worker gives up after exactly the configured timeout
 * and goes back to the queue, while the helper finishes (or doesn't) on its
 * own time. The shared block is refcounted because either side can be last to
 * let go of it. */
typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int done;
    int refs;
    job_t job;
    int success;
    char text[256];
} dns_call_t;

static void dns_call_release(dns_call_t *c) {
    pthread_mutex_lock(&c->mu);
    int last = (--c->refs == 0);
    pthread_mutex_unlock(&c->mu);
    if (last) {
        pthread_mutex_destroy(&c->mu);
        pthread_cond_destroy(&c->cv);
        free(c);
    }
}

static void *dns_call_main(void *arg) {
    dns_call_t *c = (dns_call_t *)arg;
    char text[256] = "";
    int ok = (c->job.type == JOB_RDNS) ? do_rdns(c->job.ip, text, sizeof text)
                                        : do_dnsbl(&c->job, text, sizeof text);
    pthread_mutex_lock(&c->mu);
    c->success = ok;
    memcpy(c->text, text, sizeof text);
    c->done = 1;
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mu);
    dns_call_release(c);
    return NULL;
}

/* Runs `job`'s resolver lookup under a hard deadline. Returns 1 with the
 * answer in `out` if it finished in time, 0 on timeout, failure, or if the
 * helper thread couldn't be started. */
static int dns_with_timeout(const job_t *job, char *out, size_t outsz) {
    double timeout = job->timeout > 0 ? job->timeout : 5.0;
    dns_call_t *c = calloc(1, sizeof *c);
    if (!c) return 0;
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->job = *job;
    c->refs = 2; /* this thread, plus the helper */

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, &attr, dns_call_main, c);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        c->refs = 1; /* no helper to hold the second reference */
        dns_call_release(c);
        return 0;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    time_t whole = (time_t)timeout;
    deadline.tv_sec += whole;
    deadline.tv_nsec += (long)((timeout - (double)whole) * 1e9);
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    int success = 0;
    pthread_mutex_lock(&c->mu);
    while (!c->done) {
        if (pthread_cond_timedwait(&c->cv, &c->mu, &deadline) == ETIMEDOUT) break;
    }
    if (c->done) {
        success = c->success;
        snprintf(out, outsz, "%s", c->text);
    }
    pthread_mutex_unlock(&c->mu);
    dns_call_release(c);
    return success;
}

/* connect(2) ignores SO_SNDTIMEO/SO_RCVTIMEO, so an ident probe to a
 * blackholed client address used to park a worker thread for the OS SYN
 * timeout (~75s on both Linux and macOS) -- four of those wedged the entire
 * pool, including every scrypt verify. Non-blocking connect + poll gives the
 * configured ident_timeout real teeth. Leaves the fd blocking on success, so
 * SO_RCVTIMEO still bounds the read that follows. */
static int connect_with_timeout(int fd, const struct sockaddr *sa, socklen_t slen, double timeout) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    if (connect(fd, sa, slen) != 0) {
        if (errno != EINPROGRESS) return -1;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int ms = (int)(timeout * 1000);
        if (ms < 1) ms = 1;
        if (poll(&pfd, 1, ms) <= 0) return -1;
        int err = 0;
        socklen_t elen = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) return -1;
    }
    fcntl(fd, F_SETFL, flags);
    return 0;
}

/* RFC 1413: connect to the client's own IP on port 113, ask
 * "<remote_port>,<local_port>", parse "...:USERID:...:<name>" from the reply. */
static int do_ident(const char *ip, int remote_port, int local_port, double timeout, char *out, size_t outsz) {
    if (timeout <= 0) timeout = 3.0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct timeval tv;
    tv.tv_sec = (long)timeout;
    tv.tv_usec = (long)((timeout - (double)tv.tv_sec) * 1e6);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(113);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return 0; }
    if (connect_with_timeout(fd, (struct sockaddr *)&sa, sizeof sa, timeout) != 0) { close(fd); return 0; }

    char req[64];
    snprintf(req, sizeof req, "%d,%d\r\n", remote_port, local_port);
    if (write(fd, req, strlen(req)) < 0) { close(fd); return 0; }

    char resp[256] = {0};
    ssize_t n = read(fd, resp, sizeof resp - 1);
    close(fd);
    if (n <= 0) return 0;

    /* "<ports> : USERID : <os> : <name>" -- anything else (ERROR, garbage)
     * is not an answer. */
    if (!strstr(resp, "USERID")) return 0;
    char *p = strrchr(resp, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;
    char *end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    *end = '\0';
    /* The remote end picks this string; it lands in nick!user@host, so it
     * must pass the same validation a USER command would. */
    if (!irc_valid_user(p, 32)) return 0;
    snprintf(out, outsz, "%s", p);
    return 1;
}

static void *worker_main(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_qmutex);
        while (g_running && !g_qhead) pthread_cond_wait(&g_qcond, &g_qmutex);
        if (!g_running && !g_qhead) { pthread_mutex_unlock(&g_qmutex); break; }
        qnode_t *node = g_qhead;
        if (node) {
            g_qhead = node->next;
            if (!g_qhead) g_qtail = NULL;
            g_qlen--;
        }
        pthread_mutex_unlock(&g_qmutex);
        if (!node) continue;

        job_result_t r;
        memset(&r, 0, sizeof r);
        r.type = node->job.type;
        r.conn_id = node->job.conn_id;
        r.purpose = node->job.purpose;
        switch (node->job.type) {
            case JOB_RDNS:
            case JOB_DNSBL:
                r.success = dns_with_timeout(&node->job, r.text, sizeof r.text);
                break;
            case JOB_IDENT:
                r.success = do_ident(node->job.ip, node->job.remote_port, node->job.local_port,
                                       node->job.timeout, r.text, sizeof r.text);
                break;
            case JOB_SASL:
                r.success = crypto_verify_password(node->job.secret, node->job.hash);
                break;
            case JOB_HASH:
                r.success = crypto_hash_password(node->job.secret, r.text, sizeof r.text) == 0;
                break;
        }
        OPENSSL_cleanse(node->job.secret, sizeof node->job.secret);
        push_result(&r);
        free(node);
    }
    return NULL;
}

void worker_pool_start(void) {
    if (pipe(g_wake) == 0) {
        for (int i = 0; i < 2; i++) {
            fcntl(g_wake[i], F_SETFL, fcntl(g_wake[i], F_GETFL, 0) | O_NONBLOCK);
            fcntl(g_wake[i], F_SETFD, FD_CLOEXEC);
        }
    }
    g_running = 1;
    /* Track how many actually started: joining an uninitialized pthread_t in
     * worker_pool_stop is undefined behaviour. */
    g_nthreads = 0;
    for (int i = 0; i < N_WORKERS; i++)
        if (pthread_create(&g_threads[g_nthreads], NULL, worker_main, NULL) == 0) g_nthreads++;
}

void worker_pool_stop(void) {
    pthread_mutex_lock(&g_qmutex);
    g_running = 0;
    pthread_cond_broadcast(&g_qcond);
    pthread_mutex_unlock(&g_qmutex);
    for (int i = 0; i < g_nthreads; i++) pthread_join(g_threads[i], NULL);
    g_nthreads = 0;
    while (g_qhead) {
        qnode_t *n = g_qhead;
        g_qhead = n->next;
        OPENSSL_cleanse(n->job.secret, sizeof n->job.secret);
        free(n);
    }
    g_qtail = NULL;
    g_qlen = 0;
    for (int i = 0; i < 2; i++) if (g_wake[i] >= 0) { close(g_wake[i]); g_wake[i] = -1; }
}

int worker_submit(const job_t *job) {
    /* Auth (scrypt, ~30ms, with a user actively waiting on it) jumps the
     * queue ahead of the DNS jobs, each of which can sit for its full
     * resolver timeout -- otherwise a burst of new connections parks every
     * login behind their lookups. */
    int is_auth = (job->type == JOB_SASL || job->type == JOB_HASH);
    pthread_mutex_lock(&g_qmutex);
    if (g_qlen >= QUEUE_MAX) { pthread_mutex_unlock(&g_qmutex); return -1; }
    qnode_t *node = malloc(sizeof *node);
    if (!node) { pthread_mutex_unlock(&g_qmutex); return -1; }
    node->job = *job;
    node->next = NULL;
    if (is_auth) {
        node->next = g_qhead;
        g_qhead = node;
        if (!g_qtail) g_qtail = node;
    } else {
        if (g_qtail) g_qtail->next = node; else g_qhead = node;
        g_qtail = node;
    }
    g_qlen++;
    pthread_cond_signal(&g_qcond);
    pthread_mutex_unlock(&g_qmutex);
    return 0;
}
