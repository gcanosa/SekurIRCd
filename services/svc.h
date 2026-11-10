/* Shared between the services core (chanserv.c: link, config, main loop, ChanServ) and nickserv.c. */
#ifndef SEKURIRCD_SVC_H
#define SEKURIRCD_SVC_H

#include "../src/proto.h"
#include "../src/vendor/toml.h"

#include <stddef.h>

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
int ns_config(toml_table_t *raw, const char *config_path, char *err, size_t errsz);
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

#endif
