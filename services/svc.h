/* Shared between the services core (chanserv.c: link, config, main loop, ChanServ) and nickserv.c. */
#ifndef SEKURIRCD_SVC_H
#define SEKURIRCD_SVC_H

#include "../src/proto.h"
#include "../src/vendor/toml.h"

#include <stddef.h>

#define SERVICES_VERSION "1.4.0"

/* chanserv.c: queue one line for the hub. */
void svc_queue_line(const char *line);

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
/* SVCUSER/SVCNICK/SVCQUIT/SVCACCOUNT/SVCSASL/SVCREGISTER. 1 if it was one of those. */
int ns_event(irc_message_t *msg);
void ns_tick(void);    /* once a second: enforcement deadlines, SASL timeouts, store flush */
void ns_shutdown(void); /* flush and free */

#endif
