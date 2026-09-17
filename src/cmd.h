/* Command dispatch. Ported (reduced scope for v1.0.1 -- see the plan) from
 * sekurircd/src/sekurircd/commands.py: one handler per IRC verb, looked up
 * in a dispatch table, with a registration gate enforced before dispatch.
 */
#ifndef SEKURIRCD_CMD_H
#define SEKURIRCD_CMD_H

#include "client.h"
#include "proto.h"
#include "server.h"

typedef void (*cmd_handler_t)(server_t *srv, client_t *cl, irc_message_t *msg);

typedef struct {
    const char *name;
    cmd_handler_t handler;
    int min_params;
    int needs_registration;
    int oper_only;
} cmd_entry_t;

/* Entry point called once per parsed line -- enforces the registration gate
 * (only NICK/USER/PASS/CAP/PING/QUIT/PONG before registration completes),
 * min_params, and oper_only, then calls the handler. */
void cmd_dispatch(server_t *srv, client_t *cl, irc_message_t *msg);

/* Shared helpers used across cmd_*.c */
void cmd_send_welcome_if_ready(server_t *srv, client_t *cl);
void err_need_more_params(client_t *cl, const char *cmdname);
void err_no_such_nick(client_t *cl, const char *nick);
void err_no_such_channel(client_t *cl, const char *chan);
void err_not_registered(client_t *cl);
void err_no_privileges(client_t *cl);
void err_not_channel_op(client_t *cl, const char *chan);
/* A system NOTICE to `cl` itself, from the server (not from another user) --
 * matches commands._notice_self. */
void notice_self(server_t *srv, client_t *cl, const char *text);

/* Registration handlers (cmd_reg.c) */
void cmd_nick(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_user(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_pass(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_cap(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_ping(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_pong(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_quit(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_authenticate(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_register(server_t *srv, client_t *cl, irc_message_t *msg);
/* net.c: apply a finished JOB_SASL (is_register=0) / JOB_HASH (is_register=1,
 * `hash` = the new scrypt string) for cl->pending_account. */
void cmd_finish_auth(server_t *srv, client_t *cl, int is_register, int success, const char *hash);
/* net.c: apply a finished JOB_SASL for AUTH_OPER/AUTH_DIE/AUTH_RESTART
 * (cmd_oper.c) -- `purpose` is an auth_purpose_t (worker.h), passed as int
 * so this header doesn't need to pull in worker.h. */
void cmd_finish_privileged_auth(server_t *srv, client_t *cl, int purpose, int success);

/* Channel handlers (cmd_chan.c) */
void cmd_join(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_part(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_topic(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_names(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_list(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_kick(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_mode(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_invite(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_knock(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_links(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_map(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_sajoin(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_sapart(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_samode(server_t *srv, client_t *cl, irc_message_t *msg);
/* Parses+applies a MODE modestring to `chan`, broadcasting the result.
 * `is_full_op` gates non-halfop-safe letters. Exposed (not static) so
 * link.c can apply a trusted services link's MODE (ACCESS/IDENTIFY
 * op-grants) through the same one implementation. */
void cmd_apply_channel_mode(server_t *srv, client_t *cl, channel_t *chan,
                             const char *modestring, const char **args, int nargs, int is_full_op);
/* Unconditional JOIN with no key/limit/ban/invite checks -- used for
 * [channels] auto_join (same "bypass the usual join gate" role as
 * commands.force_join in the Python daemon). */
void cmd_force_join(server_t *srv, client_t *cl, const char *chan_name);

/* User handlers (cmd_user.c) */
void cmd_privmsg(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_notice(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_whois(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_who(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_whowas(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_away(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_setname(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_userhost(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_ison(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_monitor(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_watch(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_silence(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_glob(server_t *srv, client_t *cl, irc_message_t *msg);

/* Oper handlers (cmd_oper.c) */
void cmd_oper(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_kill(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_wallops(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_rehash(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_die(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_restart(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_vhost(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_chghost(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_sethost(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_kline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_gline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_zline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_unkline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_ungline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_unzline(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_squit(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_connect(server_t *srv, client_t *cl, irc_message_t *msg);

/* Info handlers (cmd_info.c) */
void cmd_version(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_time(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_motd(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_lusers(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_uptime(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_admin(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_stats(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_trace(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_servlist(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_squery(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_info(server_t *srv, client_t *cl, irc_message_t *msg);
void cmd_help(server_t *srv, client_t *cl, irc_message_t *msg);

#endif /* SEKURIRCD_CMD_H */
