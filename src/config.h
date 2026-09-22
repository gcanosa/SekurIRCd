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
#define CFG_MAX_LINK_ALLOWED_IPS 16
#define CFG_MAX_SCAN_PROTOCOLS   32
#define CFG_MAX_BLACKLISTS       16 /* == WORKER_MAX_ZONES (worker.h) */
#define CFG_MAX_BL_REPLIES       16
#define CFG_MAX_EXEMPTS          64
#define CFG_MAX_TARGET_STRINGS    8

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
    char protection_file[CFG_PATH]; /* Protection bundle (config/protection.toml); "" = don't load one */
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
    int max_accounts;   /* 0 = unlimited; caps self-service /REGISTER growth */
} cfg_accounts_t;

typedef struct {
    int enabled;
    int port;
    char cert_file[CFG_PATH];
    char key_file[CFG_PATH];
    int request_client_cert; /* ask (never require) a TLS client cert -- see SASL EXTERNAL */
    int sts_duration; /* seconds; 0 = don't advertise IRCv3 "sts" (STS policy expiry) */
} cfg_tls_t;

typedef struct {
    char motd[CFG_PATH];
    char oper_motd[CFG_PATH];
    char rules[CFG_PATH];
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
    char allowed_ips[CFG_MAX_LINK_ALLOWED_IPS][CFG_MASK]; /* hub-role only: IP globs this peer may
                                                             * connect from; empty = any IP (back-compat) */
    int n_allowed_ips;
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
    int enabled;                /* master switch for everything in [spam] */
    int exempt_opers;
    int exempt_identified;      /* accounts (+r) skip every check */
    long trust_age;             /* seconds connected before the limits stop applying; 0 = never */
    long new_user_period;       /* seconds a fresh connection can't PM users; 0 = off */
    int max_targets;            /* distinct recipients per window; 0 = off */
    long target_window;         /* seconds */
    int max_repeat;             /* distinct recipients of one identical text per window; 0 = off */
    char limit_action[8];       /* block | warn | kill | zline */
    long zline_duration;        /* seconds; 0 = permanent */
    int filters_enabled;        /* use the regex filters file */
    char filters_file[CFG_PATH];
} cfg_spam_t;

typedef struct {
    int enabled;
    char name[CFG_STR];
    char min_level[16];
    int stats_interval;              /* seconds between periodic stats snotes; 0 = off */
    char chanserv_pidfile[CFG_PATH]; /* "" = don't report chanserv CPU/mem */
} cfg_debug_channel_t;

/* Protection bundle (config/protection.toml). Everything that guards the
 * server against abusive connections lives in that one file: the DNSBL
 * blacklists, the active open-proxy scanner, connection caps, the connect
 * flood throttle, the per-client flood guard and [spam]. The last four are
 * not stored here -- when the file is present it simply overlays the
 * matching cfg.security.* / cfg.spam.* fields, so the rest of the daemon is
 * unchanged. The blacklists and scanner are new state, held below. */
#define SCAN_HTTP     1
#define SCAN_HTTPPOST 2
#define SCAN_SOCKS4   3
#define SCAN_SOCKS5   4

typedef struct { int type; int port; } cfg_scan_proto_t;
typedef struct { int code; char text[CFG_STR]; } cfg_bl_reply_t;
typedef struct {
    char zone[CFG_STR];
    int bitmask;                /* 1: reply codes are bit values; 0: exact last-octet match */
    int ban_unknown;            /* listed with a code not in replies[]: ban anyway? */
    char reason[CFG_STR];       /* %i ip, %t zone, %r matched reply text */
    cfg_bl_reply_t replies[CFG_MAX_BL_REPLIES];
    int n_replies;              /* 0 = any listing bans */
} cfg_blacklist_t;

typedef struct {
    int loaded;                 /* a protection file was found and parsed */
    char exempt[CFG_MAX_EXEMPTS][CFG_MASK]; /* IP globs never scanned or DNSBL-checked */
    int n_exempt;

    int bl_enabled;
    int bl_configured;          /* the bundle file has a [blacklist] section: it overrides legacy [dnsbl] */
    int bl_legacy;              /* zones came from the deprecated [dnsbl] section */
    double bl_timeout;
    char bl_action[16];         /* "zline" | "kline" | "reject" */
    char bl_ban_duration[16];
    cfg_blacklist_t blacklists[CFG_MAX_BLACKLISTS];
    int n_blacklists;

    int scan_enabled;
    char scan_action[16];       /* "zline" | "kline" | "reject" */
    char scan_ban_duration[16];
    char scan_reason[CFG_STR];  /* %i ip, %t protocol, %p port */
    double scan_timeout;
    int scan_max_read;
    int scan_max_concurrent;
    char scan_bind[64];
    long scan_negcache;         /* seconds a clean IP isn't rescanned; 0 = off */
    int scan_log_all;
    char target_ip[64];
    int target_port;
    char target_strings[CFG_MAX_TARGET_STRINGS][CFG_STR];
    int n_target_strings;
    cfg_scan_proto_t protocols[CFG_MAX_SCAN_PROTOCOLS];
    int n_protocols;
} cfg_protection_t;

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
    cfg_spam_t spam;
    cfg_tls_t tls;
    cfg_links_t links;
    cfg_accounts_t accounts;
    cfg_debug_channel_t debug_channel;
    cfg_protection_t protection;
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
void config_oper_motd_path(const config_t *cfg, char *out, size_t outsz);
void config_rules_path(const config_t *cfg, char *out, size_t outsz);
/* Returns 1 and fills `out`, or 0 (out untouched) if klines_file is empty. */
int config_klines_path(const config_t *cfg, char *out, size_t outsz);
/* [spam] filters_file resolved against the config dir; 0 if unset. */
int config_spamfilters_path(const config_t *cfg, char *out, size_t outsz);
/* [security] protection_file resolved against the config dir; 0 if unset. */
int config_protection_path(const config_t *cfg, char *out, size_t outsz);
/* Scanner protocol name <-> SCAN_* (case-insensitive). 0 / "?" if unknown. */
int config_scan_proto_parse(const char *name);
const char *config_scan_proto_name(int type);
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
