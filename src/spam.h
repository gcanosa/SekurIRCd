/* Spam protection: content filters (regex rules, see config/spamfilters.conf),
 * a new-connection PM restriction, and per-client recipient/repeat limits.
 * Master switch: [spam] enabled. Everything here is a no-op when it's off.
 * Rules and limits apply to local clients only; each server in a link
 * enforces its own copy of the filters file. */
#ifndef SEKURIRCD_SPAM_H
#define SEKURIRCD_SPAM_H

#include "client.h"
#include "proto.h"
#include "server.h"

/* What a rule is matched against (bit set per rule; letters in the file). */
#define SPAM_T_PRIVMSG_USER 0x01 /* p: PRIVMSG to a user */
#define SPAM_T_PRIVMSG_CHAN 0x02 /* c: PRIVMSG to a channel */
#define SPAM_T_NOTICE_USER  0x04 /* n: NOTICE to a user */
#define SPAM_T_NOTICE_CHAN  0x08 /* N: NOTICE to a channel */
#define SPAM_T_AWAY         0x10 /* a: AWAY message */
#define SPAM_T_QUIT         0x20 /* q: QUIT reason */
#define SPAM_T_PART         0x40 /* P: PART reason */
#define SPAM_T_TOPIC        0x80 /* t: TOPIC text */

/* Parses a target-letter string ("pcn") into a SPAM_T_* mask; 0 if empty or
 * it contains an unknown letter. */
unsigned spam_parse_targets(const char *s);

/* (Re)load [spam] filters_file into srv->spam_filters. Called at startup and
 * from server_rehash. Does nothing to the in-memory list when filters_file is
 * "" (rules added with SPAMFILTER ADD then live in memory only). */
void spam_reload(server_t *srv);
void spam_free(server_t *srv);

/* PRIVMSG/NOTICE gate. Returns 1 if the message must be dropped (the sender
 * has already been told, or disconnected); 0 to deliver it. `target` is the
 * raw command target (nick, #chan, or @#chan). `text` is the message body. */
int spam_check_message(server_t *srv, client_t *cl, const char *target,
                       const char *text, int is_notice);

/* Content filter for the non-message kinds (SPAM_T_AWAY/QUIT/PART/TOPIC).
 * Returns 1 if the text should be discarded by the caller. */
int spam_check_text(server_t *srv, client_t *cl, unsigned kind, const char *text);

/* Records one (target, text) send in cl's ring and reports how many distinct
 * targets were messaged and how many distinct targets got this same text
 * within the last `window` seconds. Exposed for the unit test. */
void spam_track(client_t *cl, const char *target, const char *text, time_t now,
                long window, int *distinct_targets, int *same_text_targets);

/* SPAMFILTER [LIST] | ADD <targets> <action> <duration|-> <reason> :<regex>
 *          | DEL <n> (server-oper only). */
void cmd_spamfilter(server_t *srv, client_t *cl, irc_message_t *msg);

#endif
