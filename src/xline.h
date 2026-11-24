/* Q-lines (nickname masks), RESVs (channel-name masks) and X-lines (realname masks): bans on what a name looks like, set by opers,
 * kept network-wide and across restarts. One list, three types:
 *   'Q' nick glob     refused at NICK  (a registered oper is exempt)
 *   'R' channel glob  refused at JOIN  (an oper with the override privilege is exempt; nobody already in is removed)
 *   'X' realname glob refused at registration; an underscore in the mask stands for a space
 * They live in xlines.json next to klines.json (none: memory only), a file the older servers never read, and travel between
 * servers as `:<sid> XLN <Q|R|X> <mask> <setter> <expires> :<reason>` / `:<sid> UNXLN <type> <mask>`, which an older server
 * ignores -- it simply enforces none of them. */
#ifndef SEKURIRCD_XLINE_H
#define SEKURIRCD_XLINE_H

#include "cmd.h"

typedef struct xline {
    char type;           /* 'Q', 'R' or 'X' */
    char mask[256];
    char reason[256];
    char set_by[128];
    time_t expires_at;   /* 0 = permanent */
    struct xline *next;
} xline_t;

void xline_load(server_t *srv);
void xline_flush(server_t *srv); /* save, if anything changed since the last save */
void xline_free(server_t *srv);
/* 1 = a new line, 0 = an existing one refreshed (the later expiry wins; permanent outranks any expiry) */
int xline_add(server_t *srv, char type, const char *mask, const char *reason, const char *set_by, time_t expires_at);
int xline_remove(server_t *srv, char type, const char *mask); /* 1 if it was there */
/* The reason of the first live line of `type` that matches `subject` (case-insensitive), or NULL. */
const char *xline_match(server_t *srv, char type, const char *subject);

void cmd_qline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_unqline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_resv(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_unresv(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_xline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_unxline(server_t *srv, client_t *cl, irc_message_t *msg);

#endif
