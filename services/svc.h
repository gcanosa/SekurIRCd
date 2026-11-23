/* Shared between the services core (chanserv.c: link, config, main loop, ChanServ) and nickserv.c. */
#ifndef SEKURIRCD_SVC_H
#define SEKURIRCD_SVC_H

#include "../src/proto.h"
#include "../src/tomlx.h"

#include <stddef.h>
#include <sys/types.h>

#define SERVICES_VERSION "1.5.0"

/* chanserv.c: queue one line for the hub. */
void svc_queue_line(const char *line);
/* chanserv.c: a user left the network / changed nick (from the user feed, which sees every user, not only the ones in
 * channels ChanServ sits in) -- IDENTIFY / auto-mode state is per nick and must not pass to whoever takes it next. */
void cs_user_quit(const char *nick);
void cs_user_nick(const char *old_nick, const char *new_nick);
/* A user just logged in: give them their ACCESS modes in the registered channels they are already in. */
void cs_user_login(const char *nick);
/* NickServ LISTCHANS: cb(channel, "founder" or the ACCESS level) for each registered channel whose founder is `account`
 * or that has an =account ACCESS entry for it. */
void cs_account_chans(const char *account, void (*cb)(const char *chan, const char *level, void *ctx), void *ctx);

/* nickserv.c -------------------------------------------------------------------------------------------------- */
/* [nickserv] from services.toml (`config_path` resolves relative paths). -1 + err on a bad value. */
int ns_config(toml_node_t *raw, const char *config_path, char *err, size_t errsz);
void *ns_save(void);                                      /* rehash: a copy of the NickServ settings */
void ns_restore(void *old);                               /* rehash refused: put them back (frees old) */
void ns_rehashed(void *old, char *kept, size_t keptsz);   /* rehash done: keep what needs a restart, named in kept (frees old) */
int ns_enabled(void);
/* Load the account database. -1 + err if it exists but can't be read (never starts empty over it). */
int ns_start(char *err, size_t errsz);
/* A new link session: introduce NickServ, ask for the user feed, forget the old session's users. */
void ns_session_start(void);
/* A PRIVMSG addressed to NickServ. 1 if `target` is NickServ (handled). */
int ns_privmsg(const char *target, const char *from_nick, const char *text);
/* SVCUSER/SVCNICK/SVCQUIT/SVCACCOUNT/SVCSASL/SVCREGISTER. 1 if it was one of those. The user feed is tracked even
 * with NickServ disabled (ChanServ needs its QUIT/NICK). */
int ns_event(irc_message_t *msg);
/* The services account `nick` is logged in to, or NULL (unknown nick / not logged in). */
const char *ns_account_of(const char *nick);
void ns_tick(void);    /* once a second: enforcement deadlines, SASL timeouts, store flush */
void ns_shutdown(void); /* flush and free */
int ns_account_count(void); /* registered accounts, -1 with NickServ off */

/* chanserv.c: HELP for a service. One entry per command: '|'-separated names ("SET MLOCK|MLOCK"), a one-line summary
 * for the command list, and the detailed text ('\n' between lines). HELP alone lists the commands; HELP <cmd> [sub]
 * shows the entry, or every entry under it ("HELP SET"). admin entries only show when `admin`. */
typedef struct { const char *names, *summary, *text; int admin; } svc_help_t;
void svc_help(const char *svc, const char *intro, const svc_help_t *t, size_t n, const char *args, int admin,
              void (*out)(const char *to, const char *line), const char *to);

/* chanserv.c: registered channels. */
int cs_registered_count(void);
/* An account was dropped (DROP, FDROP, expiry): it is no channel's founder, access entry or successor any more, so whoever
 * registers that name next inherits nothing. Returns how many channels changed. */
int cs_account_dropped(const char *account);

/* tlslink.c -- TLS on the link to the hub ([link] tls = true), so services can run on another machine than the hub. */
struct ssl_st;
typedef struct {
    int enabled;
    int require; /* [link] require_tls: never send a password in plain text to a hub on another machine */
    char fingerprint[65]; /* pin the hub's certificate (lowercase hex SHA-256); "" = verify it against ca_file / the system CAs */
    char ca_file[512];
    char cert[512], key[512]; /* a client certificate for the hub to pin; both or neither */
} svc_tls_cfg_t;
int svc_tls_cfg_equal(const svc_tls_cfg_t *a, const svc_tls_cfg_t *b);
/* TLS client handshake on the connected, blocking `fd` to `host`. NULL (fd untouched) on failure or a certificate that
 * isn't the hub's -- before any password is sent. */
struct ssl_st *svc_tls_connect(int fd, const char *host, const svc_tls_cfg_t *c);
ssize_t svc_tls_read(struct ssl_st *ssl, void *buf, size_t len);        /* read(2) semantics; EAGAIN = would block */
ssize_t svc_tls_write(struct ssl_st *ssl, const void *buf, size_t len); /* write(2) semantics */
int svc_tls_pending(struct ssl_st *ssl);                                /* decrypted bytes already buffered: poll() can't see them */
void svc_tls_close(struct ssl_st *ssl);

/* stats.c -- the stats collector (stats/stats.toml [collector]); every call is a no-op while it's off. */
void st_config(const char *services_config_path); /* finds stats.toml (beside it, or ../stats/); re-read on change */
void st_started(void);
void st_stopping(void);
void st_session_start(void); /* hub link up: ask for the feed */
void st_session_end(void);
void st_tick(void);          /* once a second */
int st_event(irc_message_t *msg); /* SVCSTAT*: 1 if it was one */

#endif
