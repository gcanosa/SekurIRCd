/* Readiness backend for net.c's event loop: kqueue (macOS/BSD), epoll (Linux), poll() anywhere else.
 * Interest is registered once per fd and changed only when it changes (each owner caches it in an ev mask byte),
 * so a wakeup costs O(ready fds) instead of O(connections). Level-triggered everywhere, same as the old poll() loop. */
#ifndef SEKURIRCD_EV_H
#define SEKURIRCD_EV_H

typedef struct {
    void *udata;
    unsigned char r, w, hup; /* readable, writable, hangup/error */
} ev_event_t;

int ev_init(void);          /* 0 ok, -1 (errno) */
void ev_shutdown(void);
const char *ev_backend(void);

/* Make `fd`'s interest read/write as asked. *mask is the caller's cached state (0 for an fd never registered); a call
 * that changes nothing makes no syscall. udata comes back with each event. */
void ev_set(int fd, void *udata, int want_r, int want_w, unsigned char *mask);
/* Before closing a registered fd. */
void ev_forget(int fd, unsigned char *mask);

/* Waits up to timeout_ms (-1 = forever). Returns the number of events stored in out (0 on timeout/EINTR), -1 on error. */
int ev_wait(ev_event_t *out, int max, int timeout_ms);

#endif
