/* TOML config loading/validation. Ported from sekurircd/src/sekurircd/config.py --
 * same keys, same defaults, same validation rules and error messages, so the
 * existing config/sekurircd.template.toml (and any deployment's copy of it)
 * loads unchanged. See that file's own comments for the "why" of each knob.
 *
 * Path resolution (unchanged from Python):
 *   [messages] motd, [security] klines_file, [accounts] store_file,
 *   [tls] cert_file/key_file -> resolved against the CONFIG FILE's directory
 *   [logging] directory      -> resolved against the current working directory
 * Both also accept absolute paths, used verbatim.
 *
 * Fixed-size arrays/strings throughout (no malloc) -- a human edits this file
 * by hand, so generous compile-time caps (below) are simpler and safe.
 * ponytail: fixed caps, bump the #defines if a real deployment ever needs more.
 */
#ifndef SEKURIRCD_CONFIG_H
#define SEKURIRCD_CONFIG_H

#include <stddef.h>

#define CFG_STR   256   /* names, network names, single hostnames/nicks */
#define CFG_PATH  512   /* filesystem paths */
#define CFG_MASK  256   /* ident@host / host masks */

#define CFG_MAX_RESERVED_NICKS   64
#define CFG_MAX_OPERATORS        64
#define CFG_MAX_HOSTS_PER_OPER   16
#define CFG_MAX_VHOSTS           64
#define CFG_MAX_HOSTS_PER_VHOST  16
#define CFG_MAX_ALLOWED_CHANNELS 64
#define CFG_MAX_AUTO_JOIN        32
#define CFG_MAX_DNSBL_ZONES      16
#define CFG_MAX_LINK_PEERS       32

typedef struct {
    char name[CFG_STR];
    char network[CFG_STR];
    char version[CFG_STR];
    char bind[CFG_STR];
    int port;
} cfg_server_t;

typedef struct {
    int max_line_length;
    int max_params;
    int max_nick_length;
    int flood_max_msgs;
    double flood_window;
    double ping_interval;
    double ping_timeout;
    int host_masking;
    char host_masking_format[CFG_STR];
    int host_masking_token_bytes;
    int oper_host_masking;
    char oper_host_format[CFG_STR];
    char klines_file[CFG_PATH];
    char default_user_modes[16];
    char oper_auto_join[CFG_STR];
    char die_password[CFG_STR];
    char die_password_hash[CFG_STR];
    char restart_password[CFG_STR];
    char restart_password_hash[CFG_STR];
    int max_connections;
    int max_connections_per_ip;
    int connect_flood_max;
    double connect_flood_window;
    char connect_flood_kline_duration[16];
    char reserved_nicks[CFG_MAX_RESERVED_NICKS][CFG_STR];
    int n_reserved_nicks;
    int ident_enabled;
    double ident_timeout;
    int rdns_enabled;
    double rdns_timeout;
} cfg_security_t;

typedef struct {
    int enabled;
    char store_file[CFG_PATH];
} cfg_accounts_t;

typedef struct {
    int enabled;
    int port;
    char cert_file[CFG_PATH];
    char key_file[CFG_PATH];
    int request_client_cert; /* ask (never require) a TLS client cert -- see SASL EXTERNAL */
} cfg_tls_t;

typedef struct {
    char motd[CFG_PATH];
    int max_message_length;
} cfg_messages_t;

typedef struct {
    char name[CFG_STR];
    char password[CFG_STR];
    char password_hash[CFG_STR];
    char hosts[CFG_MAX_HOSTS_PER_OPER][CFG_MASK];
    int n_hosts;
} cfg_operator_t;

typedef struct {
    char location1[CFG_STR];
    char location2[CFG_STR];
    char email[CFG_STR];
} cfg_admin_t;

typedef struct {
    char host[CFG_STR];
    char allowed_hosts[CFG_MAX_HOSTS_PER_VHOST][CFG_MASK];
    int n_allowed_hosts;
} cfg_vhost_t;

typedef struct {
    char name[CFG_STR];
    char password[CFG_STR];
    char password_hash[CFG_STR];
    char host[CFG_STR];  /* "" = hub-role (accepts); set = leaf-role (dials out) */
    int port;
} cfg_link_peer_t;

typedef struct {
    int enabled;
    char mode[8]; /* "hub" | "leaf" */
    char bind[CFG_STR];
    int port;
    int tls;
    int tls_insecure_skip_verify;
    double ping_interval;
    double ping_timeout;
    int max_line_length;
    double reconnect_delay;
    double reconnect_delay_max;
    cfg_link_peer_t peers[CFG_MAX_LINK_PEERS];
    int n_peers;
} cfg_links_t;

typedef struct {
    int restrict_creation;
    char allowed_channels[CFG_MAX_ALLOWED_CHANNELS][CFG_STR];
    int n_allowed_channels;
    char default_modes[16];
    char auto_join[CFG_MAX_AUTO_JOIN][CFG_STR];
    int n_auto_join;
} cfg_channels_t;

typedef struct {
    int enabled;
    char zones[CFG_MAX_DNSBL_ZONES][CFG_STR];
    int n_zones;
    double timeout;
    char action[16]; /* "kline" | "reject" */
    char kline_duration[16];
    char lookup_url[CFG_PATH];
} cfg_dnsbl_t;

typedef struct {
    int enabled;
    char name[CFG_STR];
    char min_level[16];
    int stats_interval;              /* seconds between periodic stats snotes; 0 = off */
    char chanserv_pidfile[CFG_PATH]; /* "" = don't report chanserv CPU/mem */
} cfg_debug_channel_t;

typedef struct {
    int enabled;
    char directory[CFG_PATH];
    int debug;
    char level[16];
    char file[CFG_STR];
    long max_bytes;
    int backup_count;
} cfg_logging_t;

typedef struct {
    cfg_server_t server;
    cfg_security_t security;
    cfg_messages_t messages;
    cfg_logging_t logging;
    cfg_operator_t operators[CFG_MAX_OPERATORS];
    int n_operators;
    cfg_admin_t admin;
    cfg_vhost_t vhosts[CFG_MAX_VHOSTS];
    int n_vhosts;
    cfg_channels_t channels;
    cfg_dnsbl_t dnsbl;
    cfg_tls_t tls;
    cfg_links_t links;
    cfg_accounts_t accounts;
    cfg_debug_channel_t debug_channel;
    char path[CFG_PATH]; /* "" = built-in defaults, no file loaded */
} config_t;

/* Fill `out` with built-in defaults (equivalent to Python's Config()). */
void config_defaults(config_t *out);

/* Load from `path`. If `path` is NULL, falls back to "config/sekurircd.toml"
 * in the CWD if it exists, else built-in defaults (config_defaults). Returns
 * 0 on success, -1 on error with a message in `errbuf`. */
int config_load(const char *path, config_t *out, char *errbuf, size_t errbufsz);

/* Path helpers -- apply the resolution rules documented above. */
void config_motd_path(const config_t *cfg, char *out, size_t outsz);
/* Returns 1 and fills `out`, or 0 (out untouched) if klines_file is empty. */
int config_klines_path(const config_t *cfg, char *out, size_t outsz);
/* Returns 1 and fills `out`, or 0 (out untouched) if accounts are disabled. */
int config_accounts_path(const config_t *cfg, char *out, size_t outsz);
void config_tls_cert_path(const config_t *cfg, char *out, size_t outsz);
void config_tls_key_path(const config_t *cfg, char *out, size_t outsz);

/* {token}/{network} template substitution for security.host_masking_format
 * (validated at load time in config_load, reused at runtime for the actual
 * per-connection cloak). Supports only {token}, {network}, {{, }} -- an
 * unknown placeholder or unbalanced brace returns -1.
 * ponytail: two placeholders is all this format ever needed; not a general
 * str.format clone. */
int config_format_cloak(const char *fmt, const char *token, const char *network,
                         char *out, size_t outsz);

#endif /* SEKURIRCD_CONFIG_H */
