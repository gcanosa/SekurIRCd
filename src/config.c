#include "config.h"

#include <arpa/inet.h>
#include "client.h" /* SPAM_TRACK */
#include "proto.h"
#include "version.h"
#include "vendor/toml.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *DEFAULT_RESERVED_NICKS[] = {
    "nickserv", "chanserv", "operserv", "memoserv", "hostserv", "botserv",
};
#define N_DEFAULT_RESERVED_NICKS 6

static const char *VALID_LEVELS[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
static int is_valid_level(const char *s) {
    for (size_t i = 0; i < sizeof VALID_LEVELS / sizeof VALID_LEVELS[0]; i++)
        if (strcmp(s, VALID_LEVELS[i]) == 0) return 1;
    return 0;
}

/* self-togglable user modes (client.USER_MODE_SELF) */
#define USER_MODE_SELF "iwdsB"
/* argument-free channel modes a deployment may set as a default
 * (channel.CHAN_MODES - MODE_ARG - {"r"}) */
#define CHAN_FLAG_MODES "niptsmz"

/* --- tomlc99 helpers -------------------------------------------------------- */

static toml_table_t *cfg_get_section(toml_table_t *raw, const char *name,
                                      char *errbuf, size_t errbufsz, int *err) {
    *err = 0;
    toml_table_t *sec = toml_table_in(raw, name);
    if (!sec && toml_key_exists(raw, name)) {
        snprintf(errbuf, errbufsz, "[%s] must be a table", name);
        *err = -1;
    }
    return sec;
}

static int cfg_get_bool(toml_table_t *tab, const char *key, int def, int *out,
                         char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { *out = def; return 0; }
    toml_datum_t d = toml_bool_in(tab, key);
    if (!d.ok) {
        snprintf(errbuf, errbufsz, "%s must be a boolean (true/false)", fieldname);
        return -1;
    }
    *out = d.u.b;
    return 0;
}

static int cfg_get_int(toml_table_t *tab, const char *key, int def, int *out,
                        char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { *out = def; return 0; }
    toml_datum_t d = toml_int_in(tab, key);
    if (!d.ok) {
        snprintf(errbuf, errbufsz, "%s is not a valid int", fieldname);
        return -1;
    }
    *out = (int)d.u.i;
    return 0;
}

static int cfg_get_long(toml_table_t *tab, const char *key, long def, long *out,
                         char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { *out = def; return 0; }
    toml_datum_t d = toml_int_in(tab, key);
    if (!d.ok) {
        snprintf(errbuf, errbufsz, "%s is not a valid int", fieldname);
        return -1;
    }
    *out = (long)d.u.i;
    return 0;
}

static int cfg_get_double(toml_table_t *tab, const char *key, double def, double *out,
                           char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { *out = def; return 0; }
    toml_datum_t d = toml_double_in(tab, key);
    if (d.ok) { *out = d.u.d; return 0; }
    toml_datum_t di = toml_int_in(tab, key); /* a bare int literal is a valid float too */
    if (di.ok) { *out = (double)di.u.i; return 0; }
    snprintf(errbuf, errbufsz, "%s is not a valid float", fieldname);
    return -1;
}

static int cfg_get_str(toml_table_t *tab, const char *key, const char *def,
                        char *out, size_t outsz,
                        char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { snprintf(out, outsz, "%s", def); return 0; }
    toml_datum_t d = toml_string_in(tab, key);
    if (!d.ok) {
        snprintf(errbuf, errbufsz, "%s is not a valid string", fieldname);
        return -1;
    }
    snprintf(out, outsz, "%s", d.u.s);
    free(d.u.s);
    return 0;
}

/* A duration string ("30s", "10m", "1h", "1d", bare seconds) or "" / "0" for
 * zero, stored as seconds. */
static int cfg_get_duration(toml_table_t *tab, const char *key, long def, long *out,
                             char *errbuf, size_t errbufsz, const char *fieldname) {
    if (!tab || !toml_key_exists(tab, key)) { *out = def; return 0; }
    char buf[32];
    if (cfg_get_str(tab, key, "", buf, sizeof buf, errbuf, errbufsz, fieldname)) return -1;
    if (buf[0] == '\0') { *out = 0; return 0; }
    long v = irc_parse_duration(buf);
    if (v < 0) {
        snprintf(errbuf, errbufsz, "%s \"%s\" is not a valid duration (e.g. \"30s\", \"10m\", \"1h\", \"1d\")", fieldname, buf);
        return -1;
    }
    *out = v;
    return 0;
}

static int cfg_get_str_array(toml_table_t *tab, const char *key,
                              char out[][CFG_STR], int max, int *n,
                              char *errbuf, size_t errbufsz, const char *fieldname) {
    *n = 0;
    if (!tab || !toml_key_exists(tab, key)) return 0;
    toml_array_t *arr = toml_array_in(tab, key);
    if (!arr) {
        snprintf(errbuf, errbufsz, "%s must be an array of strings", fieldname);
        return -1;
    }
    int cnt = toml_array_nelem(arr);
    for (int i = 0; i < cnt; i++) {
        toml_datum_t d = toml_string_at(arr, i);
        if (!d.ok) {
            snprintf(errbuf, errbufsz, "%s must be an array of strings", fieldname);
            return -1;
        }
        if (i < max) {
            snprintf(out[i], CFG_STR, "%s", d.u.s);
            (*n)++;
        }
        free(d.u.s);
    }
    return 0;
}

/* --- path helpers ------------------------------------------------------------ */

static int is_absolute_path(const char *p) { return p[0] == '/'; }

static void config_dir(const config_t *cfg, char *out, size_t outsz) {
    if (cfg->path[0] == '\0') {
        if (!getcwd(out, outsz)) snprintf(out, outsz, ".");
        return;
    }
    const char *slash = strrchr(cfg->path, '/');
    if (!slash) { snprintf(out, outsz, "."); return; }
    size_t len = (size_t)(slash - cfg->path);
    if (len == 0) len = 1; /* "/" */
    if (len >= outsz) len = outsz - 1;
    memcpy(out, cfg->path, len);
    out[len] = '\0';
}

static void resolve_against_config_dir(const config_t *cfg, const char *rel, char *out, size_t outsz) {
    if (rel[0] == '\0' || is_absolute_path(rel)) { snprintf(out, outsz, "%s", rel); return; }
    char dir[CFG_PATH];
    config_dir(cfg, dir, sizeof dir);
    snprintf(out, outsz, "%s/%s", dir, rel);
}

void config_motd_path(const config_t *cfg, char *out, size_t outsz) {
    resolve_against_config_dir(cfg, cfg->messages.motd, out, outsz);
}

void config_oper_motd_path(const config_t *cfg, char *out, size_t outsz) {
    resolve_against_config_dir(cfg, cfg->messages.oper_motd, out, outsz);
}

void config_rules_path(const config_t *cfg, char *out, size_t outsz) {
    resolve_against_config_dir(cfg, cfg->messages.rules, out, outsz);
}

int config_klines_path(const config_t *cfg, char *out, size_t outsz) {
    if (cfg->security.klines_file[0] == '\0') return 0;
    resolve_against_config_dir(cfg, cfg->security.klines_file, out, outsz);
    return 1;
}

int config_spamfilters_path(const config_t *cfg, char *out, size_t outsz) {
    if (cfg->spam.filters_file[0] == '\0') return 0;
    resolve_against_config_dir(cfg, cfg->spam.filters_file, out, outsz);
    return 1;
}

int config_protection_path(const config_t *cfg, char *out, size_t outsz) {
    if (cfg->security.protection_file[0] == '\0' || cfg->path[0] == '\0') return 0;
    resolve_against_config_dir(cfg, cfg->security.protection_file, out, outsz);
    return 1;
}

static const struct { const char *name; int type; } SCAN_PROTOS[] = {
    {"http", SCAN_HTTP}, {"httppost", SCAN_HTTPPOST}, {"socks4", SCAN_SOCKS4}, {"socks5", SCAN_SOCKS5},
};

int config_scan_proto_parse(const char *name) {
    for (size_t i = 0; i < sizeof SCAN_PROTOS / sizeof SCAN_PROTOS[0]; i++)
        if (strcasecmp(name, SCAN_PROTOS[i].name) == 0) return SCAN_PROTOS[i].type;
    return 0;
}

const char *config_scan_proto_name(int type) {
    for (size_t i = 0; i < sizeof SCAN_PROTOS / sizeof SCAN_PROTOS[0]; i++)
        if (SCAN_PROTOS[i].type == type) return SCAN_PROTOS[i].name;
    return "?";
}

int config_accounts_path(const config_t *cfg, char *out, size_t outsz) {
    if (!cfg->accounts.enabled) return 0;
    resolve_against_config_dir(cfg, cfg->accounts.store_file, out, outsz);
    return 1;
}

void config_tls_cert_path(const config_t *cfg, char *out, size_t outsz) {
    resolve_against_config_dir(cfg, cfg->tls.cert_file, out, outsz);
}

void config_tls_key_path(const config_t *cfg, char *out, size_t outsz) {
    resolve_against_config_dir(cfg, cfg->tls.key_file, out, outsz);
}

int config_format_cloak(const char *fmt, const char *token, const char *network,
                         char *out, size_t outsz) {
    size_t o = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p == '{') {
            if (strncmp(p, "{token}", 7) == 0) {
                size_t l = strlen(token);
                if (o + l >= outsz) return -1;
                memcpy(out + o, token, l); o += l; p += 6;
            } else if (strncmp(p, "{network}", 9) == 0) {
                size_t l = strlen(network);
                if (o + l >= outsz) return -1;
                memcpy(out + o, network, l); o += l; p += 8;
            } else if (p[1] == '{') {
                if (o + 1 >= outsz) return -1;
                out[o++] = '{'; p += 1;
            } else {
                return -1; /* unknown placeholder */
            }
        } else if (*p == '}') {
            if (p[1] == '}') {
                if (o + 1 >= outsz) return -1;
                out[o++] = '}'; p += 1;
            } else {
                return -1; /* unbalanced brace */
            }
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = *p;
        }
    }
    out[o] = '\0';
    return 0;
}

/* --- defaults ----------------------------------------------------------------- */

void config_defaults(config_t *out) {
    memset(out, 0, sizeof *out);

    snprintf(out->server.name, CFG_STR, "sekuri");
    snprintf(out->server.network, CFG_STR, "SekuriIRC Network");
    snprintf(out->server.version, CFG_STR, "%s", SEKURIRCD_VERSION);
    snprintf(out->server.bind, CFG_STR, "0.0.0.0");
    out->server.port = 6667;

    out->security.max_line_length = 512;
    out->security.max_params = 15;
    out->security.max_nick_length = 30;
    out->security.flood_max_msgs = 20;
    out->security.flood_window = 1.0;
    out->security.ping_interval = 120.0;
    out->security.ping_timeout = 300.0;
    out->security.host_masking = 0;
    snprintf(out->security.host_masking_format, CFG_STR, "{token}.users.{network}");
    out->security.host_masking_token_bytes = 4;
    out->security.oper_host_masking = 0;
    snprintf(out->security.oper_host_format, CFG_STR, "netadmin.{network}");
    for (int i = 0; i < N_DEFAULT_RESERVED_NICKS; i++)
        snprintf(out->security.reserved_nicks[i], CFG_STR, "%s", DEFAULT_RESERVED_NICKS[i]);
    out->security.n_reserved_nicks = N_DEFAULT_RESERVED_NICKS;
    out->security.ident_enabled = 0;
    out->security.ident_timeout = 3.0;
    out->security.rdns_enabled = 1;
    out->security.rdns_timeout = 3.0;
    out->security.connect_flood_max = 5;
    out->security.connect_flood_window = 10.0;
    snprintf(out->security.connect_flood_kline_duration, sizeof out->security.connect_flood_kline_duration, "10m");

    snprintf(out->security.protection_file, CFG_PATH, "protection.toml");

    snprintf(out->protection.bl_action, sizeof out->protection.bl_action, "zline");
    snprintf(out->protection.bl_ban_duration, sizeof out->protection.bl_ban_duration, "1d");
    out->protection.bl_timeout = 5.0;
    snprintf(out->protection.scan_action, sizeof out->protection.scan_action, "zline");
    snprintf(out->protection.scan_ban_duration, sizeof out->protection.scan_ban_duration, "1d");
    snprintf(out->protection.scan_reason, CFG_STR, "Open %%t proxy found on your host (port %%p) -- secure it and reconnect");
    out->protection.scan_timeout = 10.0;
    out->protection.scan_max_read = 4096;
    out->protection.scan_max_concurrent = 256;
    out->protection.target_port = 6667;

    snprintf(out->messages.motd, CFG_PATH, "ircd.motd");
    snprintf(out->messages.oper_motd, CFG_PATH, "oper.motd");
    snprintf(out->messages.rules, CFG_PATH, "ircd.rules");
    out->messages.max_message_length = 400;

    out->logging.enabled = 1;
    snprintf(out->logging.directory, CFG_PATH, "logs");
    out->logging.debug = 0;
    snprintf(out->logging.level, sizeof out->logging.level, "INFO");
    snprintf(out->logging.file, CFG_STR, "sekurircd.log");
    out->logging.max_bytes = 5 * 1024 * 1024;
    out->logging.backup_count = 5;

    snprintf(out->tls.cert_file, CFG_PATH, "%s", "");
    out->tls.port = 6697;

    snprintf(out->accounts.store_file, CFG_PATH, "accounts.json");
    out->accounts.max_accounts = 10000;

    snprintf(out->links.mode, sizeof out->links.mode, "hub");
    snprintf(out->links.bind, CFG_STR, "0.0.0.0");
    out->links.port = 7000;
    out->links.ping_interval = 60.0;
    out->links.ping_timeout = 180.0;
    out->links.max_line_length = 8192;
    out->links.reconnect_delay = 5.0;
    out->links.reconnect_delay_max = 300.0;

    snprintf(out->dnsbl.action, sizeof out->dnsbl.action, "kline");
    snprintf(out->dnsbl.kline_duration, sizeof out->dnsbl.kline_duration, "1d");
    out->dnsbl.timeout = 5.0;

    out->spam.exempt_opers = 1;
    out->spam.exempt_identified = 1;
    out->spam.new_user_period = 30;
    out->spam.max_targets = 5;
    out->spam.target_window = 30;
    out->spam.max_repeat = 4;
    snprintf(out->spam.limit_action, sizeof out->spam.limit_action, "block");
    out->spam.zline_duration = 3600;
    out->spam.filters_enabled = 1;
    snprintf(out->spam.filters_file, CFG_PATH, "spamfilters.conf");

    snprintf(out->debug_channel.name, CFG_STR, "#server-debug");
    snprintf(out->debug_channel.min_level, sizeof out->debug_channel.min_level, "WARNING");
    out->debug_channel.stats_interval = 0;
    snprintf(out->debug_channel.chanserv_pidfile, CFG_PATH, "%s", "");
}

/* [spam]. Defaults are the values already in `out`, so this can run twice --
 * once over sekurircd.toml, once over the Protection bundle file -- with the
 * second pass only overriding the keys that file actually sets. */
static int parse_spam(toml_table_t *sp, config_t *out, char *errbuf, size_t errbufsz) {
    cfg_spam_t *o = &out->spam;
    /* cfg_get_str snprintf's the default into `out`; passing `out` itself as
     * the default would be an overlapping copy, so hand it a snapshot. */
    char dflt[sizeof o->limit_action], dflt2[sizeof o->filters_file];
    snprintf(dflt, sizeof dflt, "%s", o->limit_action);
    snprintf(dflt2, sizeof dflt2, "%s", o->filters_file);
    if (cfg_get_bool(sp, "enabled", o->enabled, &o->enabled, errbuf, errbufsz, "spam.enabled")) return -1;
    if (cfg_get_bool(sp, "exempt_opers", o->exempt_opers, &o->exempt_opers, errbuf, errbufsz, "spam.exempt_opers")) return -1;
    if (cfg_get_bool(sp, "exempt_identified", o->exempt_identified, &o->exempt_identified, errbuf, errbufsz, "spam.exempt_identified")) return -1;
    if (cfg_get_duration(sp, "trust_age", o->trust_age, &o->trust_age, errbuf, errbufsz, "spam.trust_age")) return -1;
    if (cfg_get_duration(sp, "new_user_period", o->new_user_period, &o->new_user_period, errbuf, errbufsz, "spam.new_user_period")) return -1;
    if (cfg_get_int(sp, "max_targets", o->max_targets, &o->max_targets, errbuf, errbufsz, "spam.max_targets")) return -1;
    if (cfg_get_duration(sp, "target_window", o->target_window, &o->target_window, errbuf, errbufsz, "spam.target_window")) return -1;
    if (cfg_get_int(sp, "max_repeat", o->max_repeat, &o->max_repeat, errbuf, errbufsz, "spam.max_repeat")) return -1;
    if (cfg_get_str(sp, "limit_action", dflt, o->limit_action, sizeof o->limit_action, errbuf, errbufsz, "spam.limit_action")) return -1;
    if (cfg_get_duration(sp, "zline_duration", o->zline_duration, &o->zline_duration, errbuf, errbufsz, "spam.zline_duration")) return -1;
    if (cfg_get_bool(sp, "filters_enabled", o->filters_enabled, &o->filters_enabled, errbuf, errbufsz, "spam.filters_enabled")) return -1;
    if (cfg_get_str(sp, "filters_file", dflt2, o->filters_file, CFG_PATH, errbuf, errbufsz, "spam.filters_file")) return -1;
    if (o->max_targets < 0 || o->max_targets >= SPAM_TRACK) {
        snprintf(errbuf, errbufsz, "spam.max_targets must be 0 (off) to %d", SPAM_TRACK - 1);
        return -1;
    }
    if (o->max_repeat < 0 || o->max_repeat > SPAM_TRACK) {
        snprintf(errbuf, errbufsz, "spam.max_repeat must be 0 (off) to %d", SPAM_TRACK);
        return -1;
    }
    if (o->target_window < 1 && (o->max_targets || o->max_repeat)) {
        snprintf(errbuf, errbufsz, "spam.target_window must be at least 1s while max_targets/max_repeat are on");
        return -1;
    }
    if (strcmp(o->limit_action, "block") && strcmp(o->limit_action, "warn") &&
        strcmp(o->limit_action, "kill") && strcmp(o->limit_action, "zline")) {
        snprintf(errbuf, errbufsz, "spam.limit_action must be \"block\", \"warn\", \"kill\" or \"zline\"");
        return -1;
    }

    return 0;
}

/* --- build from parsed TOML ---------------------------------------------------- */

static int build_config(toml_table_t *raw, const char *path, config_t *out,
                         char *errbuf, size_t errbufsz) {
    config_defaults(out);
    snprintf(out->path, CFG_PATH, "%s", path ? path : "");

    int err;
    toml_table_t *srv = cfg_get_section(raw, "server", errbuf, errbufsz, &err);
    if (err) return -1;
    toml_table_t *sec = cfg_get_section(raw, "security", errbuf, errbufsz, &err);
    if (err) return -1;
    toml_table_t *msg = cfg_get_section(raw, "messages", errbuf, errbufsz, &err);
    if (err) return -1;
    toml_table_t *log = cfg_get_section(raw, "logging", errbuf, errbufsz, &err);
    if (err) return -1;

    if (cfg_get_str(srv, "name", "sekuri", out->server.name, CFG_STR, errbuf, errbufsz, "server.name")) return -1;
    if (cfg_get_str(srv, "network", "SekuriIRC Network", out->server.network, CFG_STR, errbuf, errbufsz, "server.network")) return -1;
    if (cfg_get_str(srv, "version", SEKURIRCD_VERSION, out->server.version, CFG_STR, errbuf, errbufsz, "server.version")) return -1;
    if (cfg_get_str(srv, "bind", "0.0.0.0", out->server.bind, CFG_STR, errbuf, errbufsz, "server.bind")) return -1;
    if (cfg_get_int(srv, "port", 6667, &out->server.port, errbuf, errbufsz, "server.port")) return -1;
    if (out->server.port < 1 || out->server.port > 65535) {
        snprintf(errbuf, errbufsz, "server.port must be in 1-65535");
        return -1;
    }

    /* security.reserved_nicks: default differs from "absent -> []" (every
     * other array here), so it needs its own presence check like Python's
     * sec.get(..., DEFAULT_RESERVED_NICKS). */
    if (sec && toml_key_exists(sec, "reserved_nicks")) {
        if (cfg_get_str_array(sec, "reserved_nicks", out->security.reserved_nicks,
                               CFG_MAX_RESERVED_NICKS, &out->security.n_reserved_nicks,
                               errbuf, errbufsz, "security.reserved_nicks")) return -1;
        for (int i = 0; i < out->security.n_reserved_nicks; i++)
            if (out->security.reserved_nicks[i][0] == '\0') {
                snprintf(errbuf, errbufsz, "security.reserved_nicks must be an array of non-empty nickname strings");
                return -1;
            }
    } /* else: config_defaults already seeded the standard services names */

    if (cfg_get_int(sec, "max_line_length", 512, &out->security.max_line_length, errbuf, errbufsz, "security.max_line_length")) return -1;
    if (cfg_get_int(sec, "max_params", 15, &out->security.max_params, errbuf, errbufsz, "security.max_params")) return -1;
    if (cfg_get_int(sec, "max_nick_length", 30, &out->security.max_nick_length, errbuf, errbufsz, "security.max_nick_length")) return -1;
    if (cfg_get_int(sec, "flood_max_msgs", 20, &out->security.flood_max_msgs, errbuf, errbufsz, "security.flood_max_msgs")) return -1;
    if (cfg_get_double(sec, "flood_window", 1.0, &out->security.flood_window, errbuf, errbufsz, "security.flood_window")) return -1;
    if (cfg_get_double(sec, "ping_interval", 120.0, &out->security.ping_interval, errbuf, errbufsz, "security.ping_interval")) return -1;
    if (cfg_get_double(sec, "ping_timeout", 300.0, &out->security.ping_timeout, errbuf, errbufsz, "security.ping_timeout")) return -1;
    if (cfg_get_bool(sec, "host_masking", 0, &out->security.host_masking, errbuf, errbufsz, "security.host_masking")) return -1;
    if (cfg_get_str(sec, "host_masking_format", "{token}.users.{network}", out->security.host_masking_format, CFG_STR, errbuf, errbufsz, "security.host_masking_format")) return -1;
    if (cfg_get_int(sec, "host_masking_token_bytes", 4, &out->security.host_masking_token_bytes, errbuf, errbufsz, "security.host_masking_token_bytes")) return -1;
    if (cfg_get_bool(sec, "oper_host_masking", 0, &out->security.oper_host_masking, errbuf, errbufsz, "security.oper_host_masking")) return -1;
    if (cfg_get_str(sec, "oper_host_format", "netadmin.{network}", out->security.oper_host_format, CFG_STR, errbuf, errbufsz, "security.oper_host_format")) return -1;
    if (cfg_get_str(sec, "klines_file", "", out->security.klines_file, CFG_PATH, errbuf, errbufsz, "security.klines_file")) return -1;
    if (cfg_get_str(sec, "protection_file", "protection.toml", out->security.protection_file, CFG_PATH, errbuf, errbufsz, "security.protection_file")) return -1;
    if (cfg_get_str(sec, "default_user_modes", "", out->security.default_user_modes, sizeof out->security.default_user_modes, errbuf, errbufsz, "security.default_user_modes")) return -1;
    if (cfg_get_str(sec, "oper_auto_join", "", out->security.oper_auto_join, CFG_STR, errbuf, errbufsz, "security.oper_auto_join")) return -1;
    if (cfg_get_str(sec, "die_password", "", out->security.die_password, CFG_STR, errbuf, errbufsz, "security.die_password")) return -1;
    if (cfg_get_str(sec, "die_password_hash", "", out->security.die_password_hash, CFG_STR, errbuf, errbufsz, "security.die_password_hash")) return -1;
    if (cfg_get_str(sec, "restart_password", "", out->security.restart_password, CFG_STR, errbuf, errbufsz, "security.restart_password")) return -1;
    if (cfg_get_str(sec, "restart_password_hash", "", out->security.restart_password_hash, CFG_STR, errbuf, errbufsz, "security.restart_password_hash")) return -1;
    if (cfg_get_int(sec, "max_connections", 0, &out->security.max_connections, errbuf, errbufsz, "security.max_connections")) return -1;
    if (cfg_get_int(sec, "max_connections_per_ip", 0, &out->security.max_connections_per_ip, errbuf, errbufsz, "security.max_connections_per_ip")) return -1;
    if (cfg_get_bool(sec, "ident_enabled", 0, &out->security.ident_enabled, errbuf, errbufsz, "security.ident_enabled")) return -1;
    if (cfg_get_double(sec, "ident_timeout", 3.0, &out->security.ident_timeout, errbuf, errbufsz, "security.ident_timeout")) return -1;
    if (cfg_get_bool(sec, "rdns_enabled", 1, &out->security.rdns_enabled, errbuf, errbufsz, "security.rdns_enabled")) return -1;
    if (cfg_get_double(sec, "rdns_timeout", 3.0, &out->security.rdns_timeout, errbuf, errbufsz, "security.rdns_timeout")) return -1;
    if (cfg_get_int(sec, "connect_flood_max", 5, &out->security.connect_flood_max, errbuf, errbufsz, "security.connect_flood_max")) return -1;
    if (cfg_get_double(sec, "connect_flood_window", 10.0, &out->security.connect_flood_window, errbuf, errbufsz, "security.connect_flood_window")) return -1;
    if (cfg_get_str(sec, "connect_flood_kline_duration", "10m", out->security.connect_flood_kline_duration, sizeof out->security.connect_flood_kline_duration, errbuf, errbufsz, "security.connect_flood_kline_duration")) return -1;

    /* Range-check BEFORE the probe below: that memsets token0[] using this
     * value, so validating afterwards meant a large (or negative, which
     * becomes a huge size_t) setting smashed the stack during config load --
     * reachable from /REHASH and SIGHUP, not just startup. The upper bound
     * matches crypto_random_hex's own 64-byte cap. */
    if (out->security.host_masking_token_bytes < 1 || out->security.host_masking_token_bytes > 32) {
        snprintf(errbuf, errbufsz, "security.host_masking_token_bytes must be in 1-32");
        return -1;
    }
    {
        char probe[CFG_STR];
        char token0[64]; memset(token0, '0', (size_t)out->security.host_masking_token_bytes * 2);
        token0[(size_t)out->security.host_masking_token_bytes * 2] = '\0';
        if (config_format_cloak(out->security.host_masking_format, token0, "example", probe, sizeof probe)) {
            snprintf(errbuf, errbufsz, "security.host_masking_format: invalid template");
            return -1;
        }
    }
    {
        char probe[CFG_STR];
        if (config_format_cloak(out->security.oper_host_format, "x", "example", probe, sizeof probe)) {
            snprintf(errbuf, errbufsz, "security.oper_host_format: invalid template");
            return -1;
        }
    }
    for (const char *c = out->security.default_user_modes; *c; c++) {
        if (!strchr(USER_MODE_SELF, *c)) {
            snprintf(errbuf, errbufsz, "security.default_user_modes: '%c' is not a valid default user mode (allowed: disw)", *c);
            return -1;
        }
    }
    if (out->security.oper_auto_join[0] && !irc_valid_channel(out->security.oper_auto_join, 50)) {
        snprintf(errbuf, errbufsz, "security.oper_auto_join: '%s' is not a valid channel name", out->security.oper_auto_join);
        return -1;
    }
    if (out->security.max_line_length < 1) { snprintf(errbuf, errbufsz, "security.max_line_length must be >= 1"); return -1; }
    /* max_params bounds IRC_MAX_PARAMS (proto.h). 0 or negative used to slip
     * through and leave msg->params[0] unwritten for the handlers registered
     * with min_params 0 that still index it -- an uninitialized stack read. */
    if (out->security.max_params < 1 || out->security.max_params > IRC_MAX_PARAMS) {
        snprintf(errbuf, errbufsz, "security.max_params must be in 1-%d", IRC_MAX_PARAMS);
        return -1;
    }
    /* Upper bound is NICKLEN - 1 (client.h): anything longer is silently
     * truncated into client_t.nick, and the advertised NICKLEN ISUPPORT
     * token would be a promise the server can't keep. */
    if (out->security.max_nick_length < 1 || out->security.max_nick_length > 63) {
        snprintf(errbuf, errbufsz, "security.max_nick_length must be in 1-63");
        return -1;
    }
    if (out->security.flood_max_msgs < 1) { snprintf(errbuf, errbufsz, "security.flood_max_msgs must be >= 1"); return -1; }
    if (out->security.flood_window <= 0) { snprintf(errbuf, errbufsz, "security.flood_window must be > 0"); return -1; }
    if (out->security.ping_interval <= 0) { snprintf(errbuf, errbufsz, "security.ping_interval must be > 0"); return -1; }
    if (out->security.ping_timeout <= out->security.ping_interval) {
        snprintf(errbuf, errbufsz, "security.ping_timeout must be greater than security.ping_interval");
        return -1;
    }
    if (out->security.max_connections < 0) { snprintf(errbuf, errbufsz, "security.max_connections must be >= 0 (0 = unlimited)"); return -1; }
    if (out->security.max_connections_per_ip < 0) { snprintf(errbuf, errbufsz, "security.max_connections_per_ip must be >= 0 (0 = unlimited)"); return -1; }
    if (out->security.ident_timeout <= 0) { snprintf(errbuf, errbufsz, "security.ident_timeout must be > 0"); return -1; }
    if (out->security.rdns_timeout <= 0) { snprintf(errbuf, errbufsz, "security.rdns_timeout must be > 0"); return -1; }
    if (out->security.die_password[0] && out->security.die_password_hash[0]) {
        snprintf(errbuf, errbufsz, "security.die_password and security.die_password_hash are mutually exclusive");
        return -1;
    }
    if (out->security.restart_password[0] && out->security.restart_password_hash[0]) {
        snprintf(errbuf, errbufsz, "security.restart_password and security.restart_password_hash are mutually exclusive");
        return -1;
    }

    if (cfg_get_str(msg, "motd", "ircd.motd", out->messages.motd, CFG_PATH, errbuf, errbufsz, "messages.motd")) return -1;
    if (cfg_get_str(msg, "oper_motd", "oper.motd", out->messages.oper_motd, CFG_PATH, errbuf, errbufsz, "messages.oper_motd")) return -1;
    if (cfg_get_str(msg, "rules", "ircd.rules", out->messages.rules, CFG_PATH, errbuf, errbufsz, "messages.rules")) return -1;
    if (cfg_get_int(msg, "max_message_length", 400, &out->messages.max_message_length, errbuf, errbufsz, "messages.max_message_length")) return -1;
    /* Upper bound is the send_msg/cmd_squery text buffer (420) less its NUL.
     * A negative value made the "%.*s" truncation a no-op. */
    if (out->messages.max_message_length < 1 || out->messages.max_message_length > 419) {
        snprintf(errbuf, errbufsz, "messages.max_message_length must be in 1-419");
        return -1;
    }

    {
        char level[16];
        if (cfg_get_str(log, "level", "INFO", level, sizeof level, errbuf, errbufsz, "logging.level")) return -1;
        for (char *c = level; *c; c++) *c = (char)toupper((unsigned char)*c);
        if (!is_valid_level(level)) {
            snprintf(errbuf, errbufsz, "logging.level must be one of CRITICAL, DEBUG, ERROR, INFO, WARNING");
            return -1;
        }
        snprintf(out->logging.level, sizeof out->logging.level, "%s", level);
    }
    if (cfg_get_bool(log, "enabled", 1, &out->logging.enabled, errbuf, errbufsz, "logging.enabled")) return -1;
    if (cfg_get_str(log, "directory", "logs", out->logging.directory, CFG_PATH, errbuf, errbufsz, "logging.directory")) return -1;
    if (cfg_get_bool(log, "debug", 0, &out->logging.debug, errbuf, errbufsz, "logging.debug")) return -1;
    if (cfg_get_str(log, "file", "sekurircd.log", out->logging.file, CFG_STR, errbuf, errbufsz, "logging.file")) return -1;
    if (cfg_get_long(log, "max_bytes", 5 * 1024 * 1024, &out->logging.max_bytes, errbuf, errbufsz, "logging.max_bytes")) return -1;
    if (cfg_get_int(log, "backup_count", 5, &out->logging.backup_count, errbuf, errbufsz, "logging.backup_count")) return -1;
    if (out->logging.max_bytes < 1) { snprintf(errbuf, errbufsz, "logging.max_bytes must be >= 1"); return -1; }
    if (out->logging.backup_count < 0) { snprintf(errbuf, errbufsz, "logging.backup_count must be >= 0"); return -1; }

    /* [[operators]] */
    if (toml_key_exists(raw, "operators")) {
        toml_array_t *arr = toml_array_in(raw, "operators");
        if (!arr) { snprintf(errbuf, errbufsz, "[[operators]] must be an array of tables"); return -1; }
        int cnt = toml_array_nelem(arr);
        for (int i = 0; i < cnt; i++) {
            toml_table_t *o = toml_table_at(arr, i);
            if (!o) { snprintf(errbuf, errbufsz, "operators[%d] must be a table", i); return -1; }
            if (i >= CFG_MAX_OPERATORS) { snprintf(errbuf, errbufsz, "too many [[operators]] entries (max %d)", CFG_MAX_OPERATORS); return -1; }
            cfg_operator_t *op = &out->operators[i];
            char fn[64];
            snprintf(fn, sizeof fn, "operators[%d].name", i);
            if (cfg_get_str(o, "name", "", op->name, CFG_STR, errbuf, errbufsz, fn)) return -1;
            snprintf(fn, sizeof fn, "operators[%d].password", i);
            if (cfg_get_str(o, "password", "", op->password, CFG_STR, errbuf, errbufsz, fn)) return -1;
            snprintf(fn, sizeof fn, "operators[%d].password_hash", i);
            if (cfg_get_str(o, "password_hash", "", op->password_hash, CFG_STR, errbuf, errbufsz, fn)) return -1;
            if (!op->name[0]) { snprintf(errbuf, errbufsz, "operators[%d] requires name", i); return -1; }
            if ((op->password[0] != '\0') == (op->password_hash[0] != '\0')) {
                snprintf(errbuf, errbufsz, "operators[%d] requires exactly one of password or password_hash", i);
                return -1;
            }
            snprintf(fn, sizeof fn, "operators[%d].hosts", i);
            if (cfg_get_str_array(o, "hosts", op->hosts, CFG_MAX_HOSTS_PER_OPER, &op->n_hosts, errbuf, errbufsz, fn)) return -1;
            if (op->n_hosts == 0) {
                snprintf(errbuf, errbufsz, "operators[%d] requires at least one hosts mask (use \"*@*\" to allow from anywhere)", i);
                return -1;
            }
            for (int j = 0; j < op->n_hosts; j++) {
                if (!op->hosts[j][0] || strpbrk(op->hosts[j], " \t\r\n")) {
                    snprintf(errbuf, errbufsz, "operators[%d].hosts[%d] must be a non-empty mask with no whitespace", i, j);
                    return -1;
                }
            }
            out->n_operators++;
        }
    }

    {
        int e;
        toml_table_t *adm = cfg_get_section(raw, "admin", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_str(adm, "location1", "", out->admin.location1, CFG_STR, errbuf, errbufsz, "admin.location1")) return -1;
        if (cfg_get_str(adm, "location2", "", out->admin.location2, CFG_STR, errbuf, errbufsz, "admin.location2")) return -1;
        if (cfg_get_str(adm, "email", "", out->admin.email, CFG_STR, errbuf, errbufsz, "admin.email")) return -1;
    }

    /* [[vhosts]] */
    if (toml_key_exists(raw, "vhosts")) {
        toml_array_t *arr = toml_array_in(raw, "vhosts");
        if (!arr) { snprintf(errbuf, errbufsz, "[[vhosts]] must be an array of tables"); return -1; }
        int cnt = toml_array_nelem(arr);
        for (int i = 0; i < cnt; i++) {
            toml_table_t *v = toml_table_at(arr, i);
            if (!v) { snprintf(errbuf, errbufsz, "vhosts[%d] must be a table", i); return -1; }
            if (i >= CFG_MAX_VHOSTS) { snprintf(errbuf, errbufsz, "too many [[vhosts]] entries (max %d)", CFG_MAX_VHOSTS); return -1; }
            cfg_vhost_t *vh = &out->vhosts[i];
            char fn[64];
            snprintf(fn, sizeof fn, "vhosts[%d].host", i);
            if (cfg_get_str(v, "host", "", vh->host, CFG_STR, errbuf, errbufsz, fn)) return -1;
            if (!vh->host[0] || strpbrk(vh->host, " \t\r\n")) {
                snprintf(errbuf, errbufsz, "vhosts[%d].host must be a non-empty hostname with no whitespace", i);
                return -1;
            }
            snprintf(fn, sizeof fn, "vhosts[%d].allowed_hosts", i);
            if (cfg_get_str_array(v, "allowed_hosts", vh->allowed_hosts, CFG_MAX_HOSTS_PER_VHOST, &vh->n_allowed_hosts, errbuf, errbufsz, fn)) return -1;
            for (int j = 0; j < vh->n_allowed_hosts; j++) {
                if (!vh->allowed_hosts[j][0] || strpbrk(vh->allowed_hosts[j], " \t\r\n")) {
                    snprintf(errbuf, errbufsz, "vhosts[%d].allowed_hosts[%d] must be a non-empty mask with no whitespace", i, j);
                    return -1;
                }
            }
            out->n_vhosts++;
        }
    }

    /* [channels] */
    {
        int e;
        toml_table_t *chan = cfg_get_section(raw, "channels", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_bool(chan, "restrict_creation", 0, &out->channels.restrict_creation, errbuf, errbufsz, "channels.restrict_creation")) return -1;
        if (cfg_get_str_array(chan, "allowed_channels", out->channels.allowed_channels, CFG_MAX_ALLOWED_CHANNELS, &out->channels.n_allowed_channels, errbuf, errbufsz, "channels.allowed_channels")) return -1;
        if (cfg_get_str(chan, "default_modes", "", out->channels.default_modes, sizeof out->channels.default_modes, errbuf, errbufsz, "channels.default_modes")) return -1;
        for (const char *c = out->channels.default_modes; *c; c++) {
            if (!strchr(CHAN_FLAG_MODES, *c)) {
                snprintf(errbuf, errbufsz, "channels.default_modes: '%c' is not a valid argument-free channel mode (allowed: imnpstz)", *c);
                return -1;
            }
        }
        if (cfg_get_str_array(chan, "auto_join", out->channels.auto_join, CFG_MAX_AUTO_JOIN, &out->channels.n_auto_join, errbuf, errbufsz, "channels.auto_join")) return -1;
        for (int i = 0; i < out->channels.n_auto_join; i++) {
            if (!irc_valid_channel(out->channels.auto_join[i], 50)) {
                snprintf(errbuf, errbufsz, "channels.auto_join: '%s' is not a valid channel name", out->channels.auto_join[i]);
                return -1;
            }
        }
    }

    /* [dnsbl] */
    {
        int e;
        toml_table_t *dns = cfg_get_section(raw, "dnsbl", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_str_array(dns, "zones", out->dnsbl.zones, CFG_MAX_DNSBL_ZONES, &out->dnsbl.n_zones, errbuf, errbufsz, "dnsbl.zones")) return -1;
        for (int i = 0; i < out->dnsbl.n_zones; i++)
            if (!out->dnsbl.zones[i][0]) { snprintf(errbuf, errbufsz, "dnsbl.zones must be an array of non-empty zone-hostname strings"); return -1; }
        if (cfg_get_bool(dns, "enabled", 0, &out->dnsbl.enabled, errbuf, errbufsz, "dnsbl.enabled")) return -1;
        if (cfg_get_double(dns, "timeout", 5.0, &out->dnsbl.timeout, errbuf, errbufsz, "dnsbl.timeout")) return -1;
        if (cfg_get_str(dns, "action", "kline", out->dnsbl.action, sizeof out->dnsbl.action, errbuf, errbufsz, "dnsbl.action")) return -1;
        if (cfg_get_str(dns, "kline_duration", "1d", out->dnsbl.kline_duration, sizeof out->dnsbl.kline_duration, errbuf, errbufsz, "dnsbl.kline_duration")) return -1;
        if (cfg_get_str(dns, "lookup_url", "", out->dnsbl.lookup_url, CFG_PATH, errbuf, errbufsz, "dnsbl.lookup_url")) return -1;
        if (out->dnsbl.enabled && out->dnsbl.n_zones == 0) {
            snprintf(errbuf, errbufsz, "dnsbl.enabled is true but dnsbl.zones is empty -- add at least one zone");
            return -1;
        }
        if (out->dnsbl.timeout <= 0) { snprintf(errbuf, errbufsz, "dnsbl.timeout must be > 0"); return -1; }
        if (strcmp(out->dnsbl.action, "kline") != 0 && strcmp(out->dnsbl.action, "reject") != 0) {
            snprintf(errbuf, errbufsz, "dnsbl.action must be \"kline\" or \"reject\"");
            return -1;
        }
        if (out->dnsbl.kline_duration[0] && irc_parse_duration(out->dnsbl.kline_duration) < 0) {
            snprintf(errbuf, errbufsz, "dnsbl.kline_duration \"%s\" is not a valid duration (e.g. \"1d\", \"12h\", \"30m\", or a number of seconds)", out->dnsbl.kline_duration);
            return -1;
        }
    }

    /* [spam] */
    {
        int e;
        toml_table_t *sp = cfg_get_section(raw, "spam", errbuf, errbufsz, &e);
        if (e) return -1;
        if (parse_spam(sp, out, errbuf, errbufsz)) return -1;
    }

    /* [tls] */
    {
        int e;
        toml_table_t *t = cfg_get_section(raw, "tls", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_bool(t, "enabled", 0, &out->tls.enabled, errbuf, errbufsz, "tls.enabled")) return -1;
        if (cfg_get_int(t, "port", 6697, &out->tls.port, errbuf, errbufsz, "tls.port")) return -1;
        if (cfg_get_str(t, "cert_file", "", out->tls.cert_file, CFG_PATH, errbuf, errbufsz, "tls.cert_file")) return -1;
        if (cfg_get_str(t, "key_file", "", out->tls.key_file, CFG_PATH, errbuf, errbufsz, "tls.key_file")) return -1;
        if (cfg_get_bool(t, "request_client_cert", 0, &out->tls.request_client_cert, errbuf, errbufsz, "tls.request_client_cert")) return -1;
        /* IRCv3 STS (Strict Transport Security): tells a plaintext client to
         * switch to the TLS port and remember to for this many seconds. 0 (the
         * default) means don't advertise it -- most deployments either only
         * offer plaintext, or want an explicit opt-in before telling clients
         * to pin a redirect. */
        if (cfg_get_int(t, "sts_duration", 0, &out->tls.sts_duration, errbuf, errbufsz, "tls.sts_duration")) return -1;
        if (out->tls.sts_duration < 0) { snprintf(errbuf, errbufsz, "tls.sts_duration must be >= 0"); return -1; }
        if (out->tls.port < 1 || out->tls.port > 65535) { snprintf(errbuf, errbufsz, "tls.port must be in 1-65535"); return -1; }
        if (out->tls.enabled && !(out->tls.cert_file[0] && out->tls.key_file[0])) {
            snprintf(errbuf, errbufsz, "tls.enabled is true but tls.cert_file/tls.key_file are not both set");
            return -1;
        }
    }

    /* [links] */
    {
        int e;
        toml_table_t *lk = cfg_get_section(raw, "links", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_bool(lk, "enabled", 0, &out->links.enabled, errbuf, errbufsz, "links.enabled")) return -1;
        if (cfg_get_str(lk, "mode", "hub", out->links.mode, sizeof out->links.mode, errbuf, errbufsz, "links.mode")) return -1;
        if (cfg_get_str(lk, "bind", "0.0.0.0", out->links.bind, CFG_STR, errbuf, errbufsz, "links.bind")) return -1;
        if (cfg_get_int(lk, "port", 7000, &out->links.port, errbuf, errbufsz, "links.port")) return -1;
        if (cfg_get_bool(lk, "tls", 0, &out->links.tls, errbuf, errbufsz, "links.tls")) return -1;
        if (cfg_get_bool(lk, "tls_insecure_skip_verify", 0, &out->links.tls_insecure_skip_verify, errbuf, errbufsz, "links.tls_insecure_skip_verify")) return -1;
        if (cfg_get_double(lk, "ping_interval", 60.0, &out->links.ping_interval, errbuf, errbufsz, "links.ping_interval")) return -1;
        if (cfg_get_double(lk, "ping_timeout", 180.0, &out->links.ping_timeout, errbuf, errbufsz, "links.ping_timeout")) return -1;
        if (cfg_get_int(lk, "max_line_length", 8192, &out->links.max_line_length, errbuf, errbufsz, "links.max_line_length")) return -1;
        if (cfg_get_double(lk, "reconnect_delay", 5.0, &out->links.reconnect_delay, errbuf, errbufsz, "links.reconnect_delay")) return -1;
        if (cfg_get_double(lk, "reconnect_delay_max", 300.0, &out->links.reconnect_delay_max, errbuf, errbufsz, "links.reconnect_delay_max")) return -1;

        if (lk && toml_key_exists(lk, "peers")) {
            toml_array_t *arr = toml_array_in(lk, "peers");
            if (!arr) { snprintf(errbuf, errbufsz, "[[links.peers]] must be an array of tables"); return -1; }
            int cnt = toml_array_nelem(arr);
            for (int i = 0; i < cnt; i++) {
                toml_table_t *pe = toml_table_at(arr, i);
                if (!pe) { snprintf(errbuf, errbufsz, "links.peers[%d] must be a table", i); return -1; }
                if (i >= CFG_MAX_LINK_PEERS) { snprintf(errbuf, errbufsz, "too many [[links.peers]] entries (max %d)", CFG_MAX_LINK_PEERS); return -1; }
                cfg_link_peer_t *p = &out->links.peers[i];
                char fn[64];
                snprintf(fn, sizeof fn, "links.peers[%d].name", i);
                if (cfg_get_str(pe, "name", "", p->name, CFG_STR, errbuf, errbufsz, fn)) return -1;
                snprintf(fn, sizeof fn, "links.peers[%d].password", i);
                if (cfg_get_str(pe, "password", "", p->password, CFG_STR, errbuf, errbufsz, fn)) return -1;
                snprintf(fn, sizeof fn, "links.peers[%d].password_hash", i);
                if (cfg_get_str(pe, "password_hash", "", p->password_hash, CFG_STR, errbuf, errbufsz, fn)) return -1;
                snprintf(fn, sizeof fn, "links.peers[%d].host", i);
                if (cfg_get_str(pe, "host", "", p->host, CFG_STR, errbuf, errbufsz, fn)) return -1;
                snprintf(fn, sizeof fn, "links.peers[%d].port", i);
                if (cfg_get_int(pe, "port", 0, &p->port, errbuf, errbufsz, fn)) return -1;

                if (!p->name[0] || strpbrk(p->name, " \t\r\n")) {
                    snprintf(errbuf, errbufsz, "links.peers[%d].name must be non-empty with no whitespace", i);
                    return -1;
                }
                if (p->password[0] && strpbrk(p->password, " \t\r\n")) {
                    snprintf(errbuf, errbufsz, "links.peers[%d].password must not contain whitespace", i);
                    return -1;
                }
                if (p->host[0]) {
                    if (!p->password[0] || p->password_hash[0]) {
                        snprintf(errbuf, errbufsz, "links.peers[%d] has host set (leaf-role) and must use a plain password, not password_hash", i);
                        return -1;
                    }
                } else if ((p->password[0] != '\0') == (p->password_hash[0] != '\0')) {
                    snprintf(errbuf, errbufsz, "links.peers[%d] requires exactly one of password or password_hash", i);
                    return -1;
                }
                out->links.n_peers++;
            }
        }

        if (out->links.enabled) {
            if (strcmp(out->links.mode, "hub") != 0 && strcmp(out->links.mode, "leaf") != 0) {
                snprintf(errbuf, errbufsz, "links.mode must be \"hub\" or \"leaf\""); return -1;
            }
            if (out->links.port < 1 || out->links.port > 65535) { snprintf(errbuf, errbufsz, "links.port must be in 1-65535"); return -1; }
            if (out->links.ping_interval <= 0) { snprintf(errbuf, errbufsz, "links.ping_interval must be > 0"); return -1; }
            if (out->links.ping_timeout <= out->links.ping_interval) { snprintf(errbuf, errbufsz, "links.ping_timeout must be greater than links.ping_interval"); return -1; }
            if (out->links.max_line_length < 1) { snprintf(errbuf, errbufsz, "links.max_line_length must be >= 1"); return -1; }
            /* link.c's rbuf/sbuf are fixed LINK_BUF-byte arrays (link.h), not
             * malloc'd to fit this value -- a larger configured limit would
             * silently never take effect (every line still cut off at 8192),
             * so reject it loudly instead. */
            if (out->links.max_line_length > 8192) {
                snprintf(errbuf, errbufsz, "links.max_line_length must be <= 8192 (link.h's LINK_BUF)");
                return -1;
            }
            if (out->links.tls && strcmp(out->links.mode, "hub") == 0 && !out->tls.enabled) {
                snprintf(errbuf, errbufsz, "links.tls requires [tls] enabled (a hub-mode link reuses the client-facing TLS certificate)");
                return -1;
            }
            if (strcmp(out->links.mode, "hub") == 0) {
                int have_hub_peer = 0;
                for (int i = 0; i < out->links.n_peers; i++) {
                    if (out->links.peers[i].host[0]) {
                        snprintf(errbuf, errbufsz, "links.mode is \"hub\" but peer '%s' sets host -- a hub never dials out", out->links.peers[i].name);
                        return -1;
                    }
                    have_hub_peer = 1;
                }
                if (!have_hub_peer) {
                    snprintf(errbuf, errbufsz, "links.mode is \"hub\" but no [[links.peers]] entry accepts an incoming leaf");
                    return -1;
                }
            } else {
                if (out->links.n_peers != 1) {
                    snprintf(errbuf, errbufsz, "links.mode is \"leaf\" but requires exactly one [[links.peers]] entry (its uplink)");
                    return -1;
                }
                cfg_link_peer_t *up = &out->links.peers[0];
                if (!up->host[0]) { snprintf(errbuf, errbufsz, "links.peers[0].host is required in leaf mode"); return -1; }
                if (up->port < 1 || up->port > 65535) { snprintf(errbuf, errbufsz, "links.peers[0].port must be in 1-65535"); return -1; }
            }
        }
    }

    /* [accounts] */
    {
        int e;
        toml_table_t *acc = cfg_get_section(raw, "accounts", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_bool(acc, "enabled", 0, &out->accounts.enabled, errbuf, errbufsz, "accounts.enabled")) return -1;
        if (cfg_get_str(acc, "store_file", "accounts.json", out->accounts.store_file, CFG_PATH, errbuf, errbufsz, "accounts.store_file")) return -1;
        if (cfg_get_int(acc, "max_accounts", 10000, &out->accounts.max_accounts, errbuf, errbufsz, "accounts.max_accounts")) return -1;
        if (out->accounts.max_accounts < 0) {
            snprintf(errbuf, errbufsz, "accounts.max_accounts must be >= 0 (0 = unlimited)");
            return -1;
        }
    }

    /* [debug_channel] */
    {
        int e;
        toml_table_t *dbg = cfg_get_section(raw, "debug_channel", errbuf, errbufsz, &e);
        if (e) return -1;
        if (cfg_get_bool(dbg, "enabled", 0, &out->debug_channel.enabled, errbuf, errbufsz, "debug_channel.enabled")) return -1;
        if (cfg_get_str(dbg, "name", "#server-debug", out->debug_channel.name, CFG_STR, errbuf, errbufsz, "debug_channel.name")) return -1;
        char lvl[16];
        if (cfg_get_str(dbg, "min_level", "WARNING", lvl, sizeof lvl, errbuf, errbufsz, "debug_channel.min_level")) return -1;
        for (char *c = lvl; *c; c++) *c = (char)toupper((unsigned char)*c);
        if (!is_valid_level(lvl)) {
            snprintf(errbuf, errbufsz, "debug_channel.min_level must be one of CRITICAL, DEBUG, ERROR, INFO, WARNING");
            return -1;
        }
        snprintf(out->debug_channel.min_level, sizeof out->debug_channel.min_level, "%s", lvl);
        if (out->debug_channel.enabled && !irc_valid_channel(out->debug_channel.name, 50)) {
            snprintf(errbuf, errbufsz, "debug_channel.name: '%s' is not a valid channel name", out->debug_channel.name);
            return -1;
        }
        if (cfg_get_int(dbg, "stats_interval", 0, &out->debug_channel.stats_interval, errbuf, errbufsz, "debug_channel.stats_interval")) return -1;
        if (cfg_get_str(dbg, "chanserv_pidfile", "", out->debug_channel.chanserv_pidfile, CFG_PATH, errbuf, errbufsz, "debug_channel.chanserv_pidfile")) return -1;
    }

    return 0;
}

/* --- Protection bundle ----------------------------------------------------------
 *
 * config/protection.toml groups every abuse-protection knob in one file. Its
 * [connection] / [flood] / [spam] sections overlay the matching
 * [security] / [spam] keys of sekurircd.toml (only the keys it sets), and
 * [blacklist] / [scanner] / [exempt] are read into cfg.protection. Absent file
 * = nothing overlaid, and a legacy [dnsbl] section keeps working. */

static int check_ban_action(const char *field, const char *v, char *errbuf, size_t errbufsz) {
    if (strcmp(v, "zline") && strcmp(v, "kline") && strcmp(v, "reject")) {
        snprintf(errbuf, errbufsz, "%s must be \"zline\", \"kline\" or \"reject\"", field);
        return -1;
    }
    return 0;
}

static int check_duration(const char *field, const char *v, char *errbuf, size_t errbufsz) {
    if (v[0] && irc_parse_duration(v) < 0) {
        snprintf(errbuf, errbufsz, "%s \"%s\" is not a valid duration (e.g. \"1d\", \"12h\", \"30m\", or a number of seconds)", field, v);
        return -1;
    }
    return 0;
}

static int parse_bl_zones(toml_table_t *bl, cfg_protection_t *p, char *errbuf, size_t errbufsz) {
    if (!bl || !toml_key_exists(bl, "zone")) return 0;
    toml_array_t *arr = toml_array_in(bl, "zone");
    if (!arr) { snprintf(errbuf, errbufsz, "[[blacklist.zone]] must be an array of tables"); return -1; }
    int cnt = toml_array_nelem(arr);
    if (cnt > CFG_MAX_BLACKLISTS) { snprintf(errbuf, errbufsz, "at most %d [[blacklist.zone]] entries are supported", CFG_MAX_BLACKLISTS); return -1; }
    for (int i = 0; i < cnt; i++) {
        toml_table_t *t = toml_table_at(arr, i);
        cfg_blacklist_t *z = &p->blacklists[p->n_blacklists];
        char type[16], replies[CFG_MAX_BL_REPLIES][CFG_STR];
        int nrep = 0;
        if (cfg_get_str(t, "name", "", z->zone, CFG_STR, errbuf, errbufsz, "blacklist.zone.name")) return -1;
        if (!z->zone[0]) { snprintf(errbuf, errbufsz, "every [[blacklist.zone]] needs a non-empty name"); return -1; }
        if (cfg_get_str(t, "type", "reply", type, sizeof type, errbuf, errbufsz, "blacklist.zone.type")) return -1;
        if (strcmp(type, "reply") && strcmp(type, "bitmask")) {
            snprintf(errbuf, errbufsz, "blacklist.zone.type must be \"reply\" or \"bitmask\" (zone %s)", z->zone);
            return -1;
        }
        z->bitmask = strcmp(type, "bitmask") == 0;
        if (cfg_get_bool(t, "ban_unknown", 1, &z->ban_unknown, errbuf, errbufsz, "blacklist.zone.ban_unknown")) return -1;
        if (cfg_get_str(t, "reason", "Proxy/Drone detected (%t)", z->reason, CFG_STR, errbuf, errbufsz, "blacklist.zone.reason")) return -1;
        if (cfg_get_str_array(t, "replies", replies, CFG_MAX_BL_REPLIES, &nrep, errbuf, errbufsz, "blacklist.zone.replies")) return -1;
        for (int r = 0; r < nrep; r++) {
            char *colon = strchr(replies[r], ':');
            int code = colon ? atoi(replies[r]) : 0;
            if (!colon || code < 0 || code > 255) {
                snprintf(errbuf, errbufsz, "blacklist.zone.replies entries look like \"<0-255>:<text>\" (zone %s: \"%s\")", z->zone, replies[r]);
                return -1;
            }
            z->replies[z->n_replies].code = code;
            snprintf(z->replies[z->n_replies].text, CFG_STR, "%s", colon + 1);
            z->n_replies++;
        }
        p->n_blacklists++;
    }
    return 0;
}

static int parse_scanner(toml_table_t *sc, cfg_protection_t *p, char *errbuf, size_t errbufsz) {
    char dflt_a[sizeof p->scan_action], dflt_d[sizeof p->scan_ban_duration], dflt_r[CFG_STR];
    snprintf(dflt_a, sizeof dflt_a, "%s", p->scan_action);
    snprintf(dflt_d, sizeof dflt_d, "%s", p->scan_ban_duration);
    snprintf(dflt_r, sizeof dflt_r, "%s", p->scan_reason);
    if (cfg_get_bool(sc, "enabled", 0, &p->scan_enabled, errbuf, errbufsz, "scanner.enabled")) return -1;
    if (cfg_get_str(sc, "action", dflt_a, p->scan_action, sizeof p->scan_action, errbuf, errbufsz, "scanner.action")) return -1;
    if (cfg_get_str(sc, "ban_duration", dflt_d, p->scan_ban_duration, sizeof p->scan_ban_duration, errbuf, errbufsz, "scanner.ban_duration")) return -1;
    if (cfg_get_str(sc, "reason", dflt_r, p->scan_reason, CFG_STR, errbuf, errbufsz, "scanner.reason")) return -1;
    if (cfg_get_double(sc, "timeout", p->scan_timeout, &p->scan_timeout, errbuf, errbufsz, "scanner.timeout")) return -1;
    if (cfg_get_int(sc, "max_read", p->scan_max_read, &p->scan_max_read, errbuf, errbufsz, "scanner.max_read")) return -1;
    if (cfg_get_int(sc, "max_concurrent", p->scan_max_concurrent, &p->scan_max_concurrent, errbuf, errbufsz, "scanner.max_concurrent")) return -1;
    if (cfg_get_str(sc, "bind", "", p->scan_bind, sizeof p->scan_bind, errbuf, errbufsz, "scanner.bind")) return -1;
    if (cfg_get_duration(sc, "negcache", 0, &p->scan_negcache, errbuf, errbufsz, "scanner.negcache")) return -1;
    if (cfg_get_bool(sc, "log_all_scans", 0, &p->scan_log_all, errbuf, errbufsz, "scanner.log_all_scans")) return -1;

    char protos[CFG_MAX_SCAN_PROTOCOLS][CFG_STR];
    int np = 0;
    if (cfg_get_str_array(sc, "protocols", protos, CFG_MAX_SCAN_PROTOCOLS, &np, errbuf, errbufsz, "scanner.protocols")) return -1;
    for (int i = 0; i < np; i++) {
        char *colon = strchr(protos[i], ':');
        int port = colon ? atoi(colon + 1) : 0;
        if (colon) *colon = '\0';
        int type = config_scan_proto_parse(protos[i]);
        if (!colon || !type || port < 1 || port > 65535) {
            snprintf(errbuf, errbufsz, "scanner.protocols entries look like \"socks5:1080\" -- type is http, httppost, socks4 or socks5, port 1-65535");
            return -1;
        }
        p->protocols[p->n_protocols].type = type;
        p->protocols[p->n_protocols].port = port;
        p->n_protocols++;
    }

    toml_table_t *tg = sc ? toml_table_in(sc, "target") : NULL;
    if (cfg_get_str(tg, "ip", "", p->target_ip, sizeof p->target_ip, errbuf, errbufsz, "scanner.target.ip")) return -1;
    if (cfg_get_int(tg, "port", p->target_port, &p->target_port, errbuf, errbufsz, "scanner.target.port")) return -1;
    if (cfg_get_str_array(tg, "strings", p->target_strings, CFG_MAX_TARGET_STRINGS, &p->n_target_strings, errbuf, errbufsz, "scanner.target.strings")) return -1;
    if (p->n_target_strings == 0) {
        /* What this ircd itself sends first (net.c's connect banner), plus the
         * two refusals a relayed scan connection can hit instead. */
        static const char *DEF[] = {"*** Looking up your hostname", "ERROR :Closing Link", "ERROR :Too many connections"};
        for (int i = 0; i < 3; i++) snprintf(p->target_strings[i], CFG_STR, "%s", DEF[i]);
        p->n_target_strings = 3;
    }
    for (int i = 0; i < p->n_target_strings; i++)
        if (!p->target_strings[i][0] || strlen(p->target_strings[i]) > 200) {
            snprintf(errbuf, errbufsz, "scanner.target.strings entries must be 1-200 characters");
            return -1;
        }

    if (p->scan_timeout <= 0) { snprintf(errbuf, errbufsz, "scanner.timeout must be > 0"); return -1; }
    if (p->scan_max_read < 64 || p->scan_max_read > 65536) { snprintf(errbuf, errbufsz, "scanner.max_read must be 64-65536"); return -1; }
    if (p->scan_max_concurrent < 1) { snprintf(errbuf, errbufsz, "scanner.max_concurrent must be >= 1"); return -1; }
    if (p->target_port < 1 || p->target_port > 65535) { snprintf(errbuf, errbufsz, "scanner.target.port must be in 1-65535"); return -1; }
    if (check_ban_action("scanner.action", p->scan_action, errbuf, errbufsz)) return -1;
    if (check_duration("scanner.ban_duration", p->scan_ban_duration, errbuf, errbufsz)) return -1;
    struct in_addr ia;
    if (p->scan_bind[0] && inet_pton(AF_INET, p->scan_bind, &ia) != 1) { snprintf(errbuf, errbufsz, "scanner.bind must be an IPv4 address"); return -1; }
    if (p->scan_enabled) {
        if (p->n_protocols == 0) { snprintf(errbuf, errbufsz, "scanner.enabled is true but scanner.protocols is empty"); return -1; }
        if (inet_pton(AF_INET, p->target_ip, &ia) != 1) {
            snprintf(errbuf, errbufsz, "scanner.enabled is true but scanner.target.ip is not set to an IPv4 address -- it must be this server's PUBLIC address, reachable from the internet");
            return -1;
        }
    }
    return 0;
}

/* Overlays a parsed protection file onto `out`. */
static int apply_protection(toml_table_t *raw, config_t *out, char *errbuf, size_t errbufsz) {
    cfg_security_t *sec = &out->security;
    cfg_protection_t *p = &out->protection;
    int e;

    toml_table_t *ex = cfg_get_section(raw, "exempt", errbuf, errbufsz, &e);
    if (e) return -1;
    if (cfg_get_str_array(ex, "ips", p->exempt, CFG_MAX_EXEMPTS, &p->n_exempt, errbuf, errbufsz, "exempt.ips")) return -1;

    toml_table_t *cn = cfg_get_section(raw, "connection", errbuf, errbufsz, &e);
    if (e) return -1;
    char dur[sizeof sec->connect_flood_kline_duration];
    snprintf(dur, sizeof dur, "%s", sec->connect_flood_kline_duration);
    if (cfg_get_int(cn, "max_connections", sec->max_connections, &sec->max_connections, errbuf, errbufsz, "connection.max_connections")) return -1;
    if (cfg_get_int(cn, "max_connections_per_ip", sec->max_connections_per_ip, &sec->max_connections_per_ip, errbuf, errbufsz, "connection.max_connections_per_ip")) return -1;
    if (cfg_get_int(cn, "connect_flood_max", sec->connect_flood_max, &sec->connect_flood_max, errbuf, errbufsz, "connection.connect_flood_max")) return -1;
    if (cfg_get_double(cn, "connect_flood_window", sec->connect_flood_window, &sec->connect_flood_window, errbuf, errbufsz, "connection.connect_flood_window")) return -1;
    if (cfg_get_str(cn, "connect_flood_ban_duration", dur, sec->connect_flood_kline_duration, sizeof sec->connect_flood_kline_duration, errbuf, errbufsz, "connection.connect_flood_ban_duration")) return -1;
    if (sec->max_connections < 0) { snprintf(errbuf, errbufsz, "connection.max_connections must be >= 0 (0 = unlimited)"); return -1; }
    if (sec->max_connections_per_ip < 0) { snprintf(errbuf, errbufsz, "connection.max_connections_per_ip must be >= 0 (0 = unlimited)"); return -1; }
    if (check_duration("connection.connect_flood_ban_duration", sec->connect_flood_kline_duration, errbuf, errbufsz)) return -1;

    toml_table_t *fl = cfg_get_section(raw, "flood", errbuf, errbufsz, &e);
    if (e) return -1;
    if (cfg_get_int(fl, "max_msgs", sec->flood_max_msgs, &sec->flood_max_msgs, errbuf, errbufsz, "flood.max_msgs")) return -1;
    if (cfg_get_double(fl, "window", sec->flood_window, &sec->flood_window, errbuf, errbufsz, "flood.window")) return -1;
    if (sec->flood_max_msgs < 1) { snprintf(errbuf, errbufsz, "flood.max_msgs must be >= 1"); return -1; }
    if (sec->flood_window <= 0) { snprintf(errbuf, errbufsz, "flood.window must be > 0"); return -1; }

    toml_table_t *sp = cfg_get_section(raw, "spam", errbuf, errbufsz, &e);
    if (e) return -1;
    if (sp && parse_spam(sp, out, errbuf, errbufsz)) return -1;

    toml_table_t *bl = cfg_get_section(raw, "blacklist", errbuf, errbufsz, &e);
    if (e) return -1;
    if (bl) {
        p->bl_configured = 1;
        char dflt_a[sizeof p->bl_action], dflt_d[sizeof p->bl_ban_duration];
        snprintf(dflt_a, sizeof dflt_a, "%s", p->bl_action);
        snprintf(dflt_d, sizeof dflt_d, "%s", p->bl_ban_duration);
        if (cfg_get_bool(bl, "enabled", 1, &p->bl_enabled, errbuf, errbufsz, "blacklist.enabled")) return -1;
        if (cfg_get_double(bl, "timeout", p->bl_timeout, &p->bl_timeout, errbuf, errbufsz, "blacklist.timeout")) return -1;
        if (cfg_get_str(bl, "action", dflt_a, p->bl_action, sizeof p->bl_action, errbuf, errbufsz, "blacklist.action")) return -1;
        if (cfg_get_str(bl, "ban_duration", dflt_d, p->bl_ban_duration, sizeof p->bl_ban_duration, errbuf, errbufsz, "blacklist.ban_duration")) return -1;
        if (parse_bl_zones(bl, p, errbuf, errbufsz)) return -1;
        if (p->bl_timeout <= 0) { snprintf(errbuf, errbufsz, "blacklist.timeout must be > 0"); return -1; }
        if (check_ban_action("blacklist.action", p->bl_action, errbuf, errbufsz)) return -1;
        if (check_duration("blacklist.ban_duration", p->bl_ban_duration, errbuf, errbufsz)) return -1;
        if (p->bl_enabled && p->n_blacklists == 0) {
            snprintf(errbuf, errbufsz, "blacklist.enabled is true but there is no [[blacklist.zone]] -- add at least one");
            return -1;
        }
    }
    toml_table_t *sc = cfg_get_section(raw, "scanner", errbuf, errbufsz, &e);
    if (e) return -1;
    if (sc && parse_scanner(sc, p, errbuf, errbufsz)) return -1;
    return 0;
}

/* Legacy [dnsbl] -> one blacklist entry per zone, when the bundle configures none. */
static void protection_legacy_dnsbl(config_t *out) {
    cfg_protection_t *p = &out->protection;
    if (p->bl_configured || p->n_blacklists > 0 || !out->dnsbl.enabled) return;
    p->bl_enabled = 1;
    p->bl_legacy = 1;
    p->bl_timeout = out->dnsbl.timeout;
    /* [dnsbl] "kline" has always meant a Z-line (IP-only pre-registration ban). */
    snprintf(p->bl_action, sizeof p->bl_action, "%s", strcmp(out->dnsbl.action, "kline") == 0 ? "zline" : "reject");
    snprintf(p->bl_ban_duration, sizeof p->bl_ban_duration, "%s", out->dnsbl.kline_duration);
    for (int i = 0; i < out->dnsbl.n_zones && i < CFG_MAX_BLACKLISTS; i++) {
        cfg_blacklist_t *z = &p->blacklists[p->n_blacklists++];
        snprintf(z->zone, CFG_STR, "%s", out->dnsbl.zones[i]);
        z->ban_unknown = 1;
        if (out->dnsbl.lookup_url[0]) {
            /* {ip} -> %i, and any literal '%' doubled would need escaping; a URL rarely has one. */
            char url[CFG_PATH]; size_t o = 0;
            for (const char *c = out->dnsbl.lookup_url; *c && o + 3 < sizeof url; c++) {
                if (strncmp(c, "{ip}", 4) == 0) { url[o++] = '%'; url[o++] = 'i'; c += 3; }
                else url[o++] = *c;
            }
            url[o] = '\0';
            snprintf(z->reason, CFG_STR, "Proxy/Drone detected (%%t). Check %s for details.", url);
        } else {
            snprintf(z->reason, CFG_STR, "Proxy/Drone detected (%%t)");
        }
    }
}

static int load_protection_file(config_t *out, char *errbuf, size_t errbufsz) {
    char path[CFG_PATH];
    if (config_protection_path(out, path, sizeof path)) {
        FILE *fp = fopen(path, "rb");
        if (fp) { /* a missing file is fine: enabling the bundle is "copy the template" */
            char toml_err[256];
            toml_table_t *raw = toml_parse_file(fp, toml_err, sizeof toml_err);
            fclose(fp);
            if (!raw) {
                snprintf(errbuf, errbufsz, "invalid TOML in %s: %s", path, toml_err);
                return -1;
            }
            out->protection.loaded = 1;
            int rc = apply_protection(raw, out, errbuf, errbufsz);
            if (rc) {
                char msg[512];
                snprintf(msg, sizeof msg, "%s: %s", path, errbuf);
                snprintf(errbuf, errbufsz, "%s", msg);
            }
            toml_free(raw);
            if (rc) return -1;
        }
    }
    protection_legacy_dnsbl(out);
    return 0;
}

int config_load(const char *path, config_t *out, char *errbuf, size_t errbufsz) {
    char resolved[CFG_PATH];

    if (!path) {
        struct stat st;
        if (stat("config/sekurircd.toml", &st) == 0 && S_ISREG(st.st_mode)) {
            path = "config/sekurircd.toml";
        } else {
            config_defaults(out);
            return 0;
        }
    }

    /* Resolve to an absolute path (best-effort) so config_dir() is stable
     * regardless of the caller's cwd, mirroring Path(path).resolve(). */
    if (path[0] == '/') {
        snprintf(resolved, sizeof resolved, "%s", path);
    } else {
        char cwd[CFG_PATH];
        if (!getcwd(cwd, sizeof cwd)) snprintf(cwd, sizeof cwd, ".");
        snprintf(resolved, sizeof resolved, "%s/%s", cwd, path);
    }

    FILE *fp = fopen(resolved, "rb");
    if (!fp) {
        snprintf(errbuf, errbufsz, "config file not found: %s", resolved);
        return -1;
    }
    char toml_err[256];
    toml_table_t *raw = toml_parse_file(fp, toml_err, sizeof toml_err);
    fclose(fp);
    if (!raw) {
        snprintf(errbuf, errbufsz, "invalid TOML in %s: %s", resolved, toml_err);
        return -1;
    }

    int rc = build_config(raw, resolved, out, errbuf, errbufsz);
    toml_free(raw);
    if (rc == 0) rc = load_protection_file(out, errbuf, errbufsz);
    return rc;
}
