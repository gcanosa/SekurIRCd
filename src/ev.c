#include "ev.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define M_R   1u
#define M_W   2u
#define M_REG 4u /* known to the backend (epoll needs ADD vs MOD) */

#if !defined(EV_FORCE_POLL) && defined(__linux__)
/* ------------------------------------------------------------------------------------------------------------ epoll */
#include <sys/epoll.h>

static int g_ep = -1;

int ev_init(void) { g_ep = epoll_create1(EPOLL_CLOEXEC); return g_ep < 0 ? -1 : 0; }
void ev_shutdown(void) { if (g_ep >= 0) close(g_ep); g_ep = -1; }
const char *ev_backend(void) { return "epoll"; }

void ev_set(int fd, void *udata, int want_r, int want_w, unsigned char *mask) {
    unsigned want = (want_r ? M_R : 0) | (want_w ? M_W : 0);
    if ((*mask & M_REG) && (*mask & (M_R | M_W)) == want) return;
    struct epoll_event e = {.events = (want_r ? EPOLLIN : 0) | (want_w ? EPOLLOUT : 0), .data.ptr = udata};
    int op = (*mask & M_REG) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(g_ep, op, fd, &e) != 0 && op == EPOLL_CTL_ADD && errno == EEXIST) epoll_ctl(g_ep, EPOLL_CTL_MOD, fd, &e);
    *mask = (unsigned char)(want | M_REG);
}

void ev_forget(int fd, unsigned char *mask) {
    if (*mask & M_REG) epoll_ctl(g_ep, EPOLL_CTL_DEL, fd, NULL);
    *mask = 0;
}

int ev_wait(ev_event_t *out, int max, int timeout_ms) {
    struct epoll_event evs[256];
    if (max > 256) max = 256;
    int n = epoll_wait(g_ep, evs, max, timeout_ms);
    if (n < 0) return errno == EINTR ? 0 : -1;
    for (int i = 0; i < n; i++) {
        out[i].udata = evs[i].data.ptr;
        out[i].r = (evs[i].events & EPOLLIN) != 0;
        out[i].w = (evs[i].events & EPOLLOUT) != 0;
        out[i].hup = (evs[i].events & (EPOLLHUP | EPOLLERR)) != 0;
    }
    return n;
}

#elif !defined(EV_FORCE_POLL) && (defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__))
/* ----------------------------------------------------------------------------------------------------------- kqueue */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>

static int g_kq = -1;

int ev_init(void) {
    g_kq = kqueue();
    if (g_kq < 0) return -1;
    fcntl(g_kq, F_SETFD, FD_CLOEXEC);
    return 0;
}
void ev_shutdown(void) { if (g_kq >= 0) close(g_kq); g_kq = -1; }
const char *ev_backend(void) { return "kqueue"; }

/* Changes are applied at once, not batched into the next kevent(): a batched change could outlive its fd (closed
 * and reused by accept() before the flush) and attach to the new socket with the old owner's pointer. */
void ev_set(int fd, void *udata, int want_r, int want_w, unsigned char *mask) {
    unsigned cur = *mask & (M_R | M_W), want = (want_r ? M_R : 0) | (want_w ? M_W : 0);
    if ((*mask & M_REG) && cur == want) return;
    struct kevent ch[2];
    int n = 0;
    /* cur is 0 for a new fd, so only the wanted filters get added (nothing to delete yet). */
    if ((want & M_R) != (cur & M_R)) EV_SET(&ch[n++], fd, EVFILT_READ, (want & M_R) ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, udata);
    if ((want & M_W) != (cur & M_W)) EV_SET(&ch[n++], fd, EVFILT_WRITE, (want & M_W) ? EV_ADD | EV_ENABLE : EV_DELETE, 0, 0, udata);
    if (n) (void)kevent(g_kq, ch, n, NULL, 0, NULL); /* no eventlist: a failed change is just dropped */
    *mask = (unsigned char)(want | M_REG);
}

void ev_forget(int fd, unsigned char *mask) { (void)fd; *mask = 0; } /* close() drops an fd's knotes */

int ev_wait(ev_event_t *out, int max, int timeout_ms) {
    struct kevent evs[256];
    if (max > 256) max = 256;
    struct timespec ts = {timeout_ms / 1000, (long)(timeout_ms % 1000) * 1000000L};
    int n = kevent(g_kq, NULL, 0, evs, max, timeout_ms < 0 ? NULL : &ts);
    if (n < 0) return errno == EINTR ? 0 : -1;
    int k = 0;
    for (int i = 0; i < n; i++) {
        if (evs[i].flags & EV_ERROR) continue;
        out[k].udata = evs[i].udata;
        out[k].r = evs[i].filter == EVFILT_READ;
        out[k].w = evs[i].filter == EVFILT_WRITE;
        /* EV_EOF on a read filter still has data to read, and the read that returns 0 reports the close -- like
         * POLLIN on a half-closed socket. On the write side nothing more can be sent. */
        out[k].hup = evs[i].filter == EVFILT_WRITE && (evs[i].flags & EV_EOF);
        k++;
    }
    return k;
}

#else
/* ------------------------------------------------------------------------------------------- poll() (portable) */
/* ponytail: O(highest fd) per wait, the old loop's cost; only for systems without kqueue/epoll. */
#include <poll.h>

typedef struct { void *udata; short events; } slot_t;
static slot_t *g_slots;
static int g_cap;
static struct pollfd *g_pfd;
static int g_pcap;

int ev_init(void) { return 0; }
void ev_shutdown(void) { free(g_slots); free(g_pfd); g_slots = NULL; g_pfd = NULL; g_cap = g_pcap = 0; }
const char *ev_backend(void) { return "poll"; }

void ev_set(int fd, void *udata, int want_r, int want_w, unsigned char *mask) {
    if (fd < 0) return;
    if (fd >= g_cap) {
        int nc = g_cap ? g_cap : 64;
        while (nc <= fd) nc *= 2;
        slot_t *ns = realloc(g_slots, (size_t)nc * sizeof *ns);
        if (!ns) return;
        memset(ns + g_cap, 0, (size_t)(nc - g_cap) * sizeof *ns);
        g_slots = ns;
        g_cap = nc;
    }
    g_slots[fd].udata = udata;
    g_slots[fd].events = (short)((want_r ? POLLIN : 0) | (want_w ? POLLOUT : 0) | 0x4000); /* 0x4000: in use */
    *mask = (unsigned char)((want_r ? M_R : 0) | (want_w ? M_W : 0) | M_REG);
}

void ev_forget(int fd, unsigned char *mask) {
    if (fd >= 0 && fd < g_cap) memset(&g_slots[fd], 0, sizeof g_slots[fd]);
    *mask = 0;
}

int ev_wait(ev_event_t *out, int max, int timeout_ms) {
    if (g_pcap < g_cap) {
        struct pollfd *np = realloc(g_pfd, (size_t)g_cap * sizeof *np);
        if (!np) return -1;
        g_pfd = np;
        g_pcap = g_cap;
    }
    int n = 0;
    for (int fd = 0; fd < g_cap; fd++) {
        if (!g_slots[fd].events) continue;
        g_pfd[n].fd = fd;
        g_pfd[n].events = (short)(g_slots[fd].events & (POLLIN | POLLOUT));
        g_pfd[n].revents = 0;
        n++;
    }
    int rc = poll(g_pfd, (nfds_t)n, timeout_ms);
    if (rc < 0) return errno == EINTR ? 0 : -1;
    int k = 0;
    for (int i = 0; i < n && k < max; i++) {
        short re = g_pfd[i].revents;
        if (!re) continue;
        out[k].udata = g_slots[g_pfd[i].fd].udata;
        out[k].r = (re & POLLIN) != 0;
        out[k].w = (re & POLLOUT) != 0;
        out[k].hup = (re & (POLLHUP | POLLERR | POLLNVAL)) != 0;
        k++;
    }
    return k;
}
#endif
