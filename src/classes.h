/* Connection classes, one table per server: the [[classes]] of the config file, the classes an oper added with CLASS ADD (kept in
 * classes.json next to the config), and the global classes other servers published. The first class whose hosts match a
 * client's address is the client's (config, then runtime, then other servers' -- so a leaf can't undo the hub's).
 *
 * A class is global when it says scope = "global" in the file, or was added with CLASS ADD GLOBAL: its owner publishes it to every
 * linked server (`:<sid> CLASS CLEAR` then `:<sid> CLASS ADD :<definition>`, the whole set again at each change and in each
 * link burst, like global spam filters), and each server applies it to ITS OWN connections: max_clients and max_per_ip are counted
 * per server, not network-wide. A server that sets [links] accept_global_classes = false keeps to its own. An older server
 * ignores the CLASS verb, so it just keeps the classes it was configured with. */
#ifndef SEKURIRCD_CLASSES_H
#define SEKURIRCD_CLASSES_H

#include "cmd.h"

#define SRV_MAX_CLASSES 64 /* the whole table: config + runtime + received */

typedef struct sclass {
    cfg_class_t c;
    char origin[8];      /* "" = ours; a received class: the SID of the server that published it */
    struct sclass *next;
} sclass_t;

void classes_load(server_t *srv);   /* classes.json -> srv->rt_classes (server start) */
void classes_free(server_t *srv);
/* Rebuild srv->class_tab from the config, the runtime list and the received sets. net_reclass_all (net.c) calls it first: every
 * change is followed by that, because the table's indexes are what clients carry. */
void classes_rebuild(server_t *srv);
void classes_burst(server_t *srv, link_conn_t *lc);  /* a new link: our global set, then every set we hold from others */
void classes_publish(server_t *srv);                 /* our global set to every link (after a change or a rehash) */
/* From a server's CLASS line: CLEAR drops everything `origin` published, ADD takes one definition. */
void classes_net_receive(server_t *srv, const char *origin, const char *verb, const char *rule);
void classes_global_del(server_t *srv, const char *name, const char *by); /* a DEL routed to us, the owner */

void cmd_class(server_t *srv, client_t *cl, irc_message_t *msg);

#endif
