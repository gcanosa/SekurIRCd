#include "worker.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define N_WORKERS 4
#define RESULT_RING 256

typedef struct qnode {
    job_t job;
    struct qnode *next;
} qnode_t;

static pthread_mutex_t g_qmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_qcond = PTHREAD_COND_INITIALIZER;
static qnode_t *g_qhead = NULL, *g_qtail = NULL;
static volatile int g_running = 0;
static pthread_t g_threads[N_WORKERS];

static pthread_mutex_t g_rmutex = PTHREAD_MUTEX_INITIALIZER;
static job_result_t g_results[RESULT_RING];
static int g_result_head = 0, g_result_tail = 0;

static void push_result(const job_result_t *r) {
    pthread_mutex_lock(&g_rmutex);
    int next = (g_result_tail + 1) % RESULT_RING;
    if (next != g_result_head) { /* ring full: drop -- the client's own timeout tick will move on */
        g_results[g_result_tail] = *r;
        g_result_tail = next;
    }
    pthread_mutex_unlock(&g_rmutex);
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
    snprintf(out, outsz, "%s", host);
    return 1;
}

/* RFC 1413: connect to the client's own IP on port 113, ask
 * "<remote_port>,<local_port>", parse "...:USERID:...:<name>" from the reply. */
static int do_ident(const char *ip, int remote_port, int local_port, double timeout, char *out, size_t outsz) {
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
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return 0; }

    char req[64];
    snprintf(req, sizeof req, "%d,%d\r\n", remote_port, local_port);
    if (write(fd, req, strlen(req)) < 0) { close(fd); return 0; }

    char resp[256] = {0};
    ssize_t n = read(fd, resp, sizeof resp - 1);
    close(fd);
    if (n <= 0) return 0;

    char *p = strrchr(resp, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;
    char *end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    *end = '\0';
    if (!*p) return 0;
    snprintf(out, outsz, "%s", p);
    return 1;
}

/* Standard reversed-octet DNSBL query convention (Spamhaus/SORBS/etc). */
static int do_dnsbl(const job_t *j, char *out, size_t outsz) {
    unsigned int a, b, c, d;
    if (sscanf(j->ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    for (int i = 0; i < j->n_zones; i++) {
        char query[300];
        snprintf(query, sizeof query, "%u.%u.%u.%u.%s", d, c, b, a, j->zones[i]);
        struct hostent *he = gethostbyname(query);
        if (he) { snprintf(out, outsz, "%s", j->zones[i]); return 1; }
    }
    return 0;
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
        }
        pthread_mutex_unlock(&g_qmutex);
        if (!node) continue;

        job_result_t r;
        memset(&r, 0, sizeof r);
        r.type = node->job.type;
        r.conn_id = node->job.conn_id;
        switch (node->job.type) {
            case JOB_RDNS:
                r.success = do_rdns(node->job.ip, r.text, sizeof r.text);
                break;
            case JOB_IDENT:
                r.success = do_ident(node->job.ip, node->job.remote_port, node->job.local_port,
                                       node->job.timeout, r.text, sizeof r.text);
                break;
            case JOB_DNSBL:
                r.success = do_dnsbl(&node->job, r.text, sizeof r.text);
                break;
        }
        push_result(&r);
        free(node);
    }
    return NULL;
}

void worker_pool_start(void) {
    g_running = 1;
    for (int i = 0; i < N_WORKERS; i++) pthread_create(&g_threads[i], NULL, worker_main, NULL);
}

void worker_pool_stop(void) {
    pthread_mutex_lock(&g_qmutex);
    g_running = 0;
    pthread_cond_broadcast(&g_qcond);
    pthread_mutex_unlock(&g_qmutex);
    for (int i = 0; i < N_WORKERS; i++) pthread_join(g_threads[i], NULL);
    while (g_qhead) {
        qnode_t *n = g_qhead;
        g_qhead = n->next;
        free(n);
    }
}

void worker_submit(const job_t *job) {
    qnode_t *node = malloc(sizeof *node);
    node->job = *job;
    node->next = NULL;
    pthread_mutex_lock(&g_qmutex);
    if (g_qtail) g_qtail->next = node; else g_qhead = node;
    g_qtail = node;
    pthread_cond_signal(&g_qcond);
    pthread_mutex_unlock(&g_qmutex);
}
