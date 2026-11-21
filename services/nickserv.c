/* NickServ -- the account service, hosted by the services daemon next to ChanServ (see chanserv.c for the link, config
 * and main loop). It owns the account database (src/accounts.c's JSON store, the same file the ircd's built-in NickServ
 * used to keep, so an upgrade reads it in place) and is the network's only authority for it: logins happen here (SASL
 * relayed by every server, IDENTIFY, PASS) and reach the user's server as SVSLOGIN.
 *
 * What the hub tells us (src/link.c):
 *   SVCINFO <hub> :<network>  (first, after our SVCWATCH)
 *   SVCUSER <uid> <nick> <user> <realhost> <ip> <account|*> <certfp|*> <server>   (connect / update)
 *   SVCNICK <uid> <newnick>    SVCQUIT <uid>    SVCACCOUNT <uid> <account|*>
 *   SVCSASL <cid> S <mech> <certfp|*> <ip>  |  SVCSASL <cid> C <data>  |  SVCSASL <cid> D A
 *   SVCREGISTER <cid> <ip> <account> <email|*> :<password>
 * What we send: SVSLOGIN <id> <account|*> [regts [always-on secs]], SVSOPER <uid> <privileges|-> <account> ([[opers]]: IRC operator
 * status for a logged-in account, or "-" to take it back), SVSJOIN <id> <#chan,...> (SET AJOIN, after a login), SVSNICK <id> <nick>,
 * KILL <id> :reason, SVCSASL <cid> C|D ...,
 * SVCREGRESULT <cid> SUCCESS|FAIL <code> <account> :text. <id> is a UID or a SASL client id (see link.h). */
#include "svc.h"

#include "../src/accounts.h"
#include "../src/crypto.h"
#include "../src/log.h"
#include "../src/scram.h"
#include "../src/vendor/uthash.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define NS_MAX_ADMINS 32
#define NS_MAX_OPERS 32

/* [[opers]]: an account whose logged-in users get IRC operator status (SVSOPER) on whichever server they are on. */
typedef struct {
    char account[64];
    char privs[96];     /* OPER_PRIV names, comma-separated, as the ircd's oper_priv_from_csv reads them */
    char certfp[72];    /* SHA-256 hex of the TLS client certificate that must come with the login ("" with password_only) */
    int password_only;  /* no certificate needed: the account's password is enough */
} ns_oper_t;

typedef struct {
    int enabled;
    char nick[64], user[64], host[256], realname[256];
    char store_file[512];
    int backup_count;
    int max_accounts;
    char email_command[512];
    char network[128];
    int network_set; /* [nickserv] network given (else the hub's SVCINFO names it) */
    int enforce_nicks, enforce_grace;
    int always_on;         /* SET ALWAYS-ON allowed on this network */
    long always_on_expire; /* seconds a detached always-on nick is kept (0 = never expires) */
    int expire_days;       /* drop an account nobody logged in to for this long (0 = never) */
    int expire_warn_days;  /* email its verified address this long before (0 = no warning; needs email_command) */
    int require_email;     /* REGISTER needs an email, and the account works once it is verified */
    long verify_window;    /* seconds an unverified registration waits for VERIFY before it is dropped */
    char admins[NS_MAX_ADMINS][64];
    int n_admins;
    ns_oper_t opers[NS_MAX_OPERS];
    int n_opers;
} ns_cfg_t;
static ns_cfg_t C;

static account_store_t g_acc;
static void opers_resync(void); /* [[opers]] below */

/* --- config ---------------------------------------------------------------------------------------------------- */

static void t_str(toml_node_t *t, const char *k, char *out, size_t outsz) {
    if (!t) return;
    toml_node_t *d = tx_string(t, k);
    if (d) snprintf(out, outsz, "%s", d->u.s);
}
static int t_int(toml_node_t *t, const char *k, int def) {
    if (!t) return def;
    toml_node_t *d = tx_int(t, k);
    return d && d->u.int64 >= INT_MIN && d->u.int64 <= INT_MAX ? (int)d->u.int64 : def;
}
static int t_bool(toml_node_t *t, const char *k, int def) {
    if (!t) return def;
    toml_node_t *d = tx_bool(t, k);
    return d ? d->u.boolean : def;
}

/* `rel` resolved against the directory `base` (a file path) lives in. */
static void beside(const char *base, const char *rel, char *out, size_t outsz) {
    if (rel[0] == '/') { snprintf(out, outsz, "%s", rel); return; }
    const char *slash = strrchr(base, '/');
    if (!slash) snprintf(out, outsz, "%s", rel);
    else snprintf(out, outsz, "%.*s/%s", (int)(slash - base), base, rel);
}

static int file_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

/* A rehash: ns_save() before load_app_config re-runs ns_config, then ns_rehashed() keeps what can't change live and
 * names it in `kept`, or ns_restore() if the new file was refused. */
void *ns_save(void) {
    ns_cfg_t *o = malloc(sizeof *o);
    if (o) *o = C;
    return o;
}
void ns_restore(void *old) { if (old) C = *(ns_cfg_t *)old; free(old); }
void ns_rehashed(void *old, char *kept, size_t keptsz) {
    ns_cfg_t *o = old;
    if (!o) return;
    /* On or off, its nick and host, and its database: the bot is introduced and the accounts are loaded at start. */
#define KEEP(cond, what, restore) do { if (cond) { restore; size_t l_ = strlen(kept); snprintf(kept + l_, keptsz - l_, "%s" what, l_ ? ", " : ""); } } while (0)
    KEEP(o->enabled != C.enabled, "[nickserv] enabled", C.enabled = o->enabled);
    KEEP(strcmp(o->nick, C.nick) || strcmp(o->user, C.user) || strcmp(o->host, C.host) || strcmp(o->realname, C.realname),
         "[nickserv] nick/user/host/realname",
         (memcpy(C.nick, o->nick, sizeof C.nick), memcpy(C.user, o->user, sizeof C.user), memcpy(C.host, o->host, sizeof C.host),
          memcpy(C.realname, o->realname, sizeof C.realname)));
    KEEP(strcmp(o->store_file, C.store_file), "[nickserv] store_file", memcpy(C.store_file, o->store_file, sizeof C.store_file));
#undef KEEP
    if (!C.network_set) memcpy(C.network, o->network, sizeof C.network); /* the one the hub's SVCINFO named */
    free(o);
    opers_resync(); /* [[opers]] entries added or removed: logged-in users get (or lose) oper status now */
}

int ns_config(toml_node_t *raw, const char *config_path, char *err, size_t errsz) {
    memset(&C, 0, sizeof C);
    toml_node_t *t = tx_table(raw, "nickserv");
    C.enabled = t_bool(t, "enabled", 1);
    snprintf(C.nick, sizeof C.nick, "NickServ");
    snprintf(C.user, sizeof C.user, "NickServ");
    snprintf(C.host, sizeof C.host, "services.sekurircd.local");
    toml_node_t *cs = tx_table(raw, "chanserv"); /* same services host as ChanServ unless set */
    t_str(cs, "host", C.host, sizeof C.host);
    snprintf(C.realname, sizeof C.realname, "Nickname and Account Service");
    t_str(t, "nick", C.nick, sizeof C.nick);
    t_str(t, "user", C.user, sizeof C.user);
    t_str(t, "host", C.host, sizeof C.host);
    t_str(t, "realname", C.realname, sizeof C.realname);
    C.backup_count = t_int(t, "backup_count", 5);
    if (C.backup_count < 0) C.backup_count = 0;
    if (C.backup_count > 50) C.backup_count = 50;
    C.max_accounts = t_int(t, "max_accounts", 0);
    t_str(t, "email_command", C.email_command, sizeof C.email_command);
    t_str(t, "network", C.network, sizeof C.network);
    C.network_set = C.network[0] != '\0';
    C.enforce_nicks = t_bool(t, "enforce_nicks", 0);
    C.enforce_grace = t_int(t, "enforce_grace", 60);
    if (C.enforce_grace < 5) C.enforce_grace = 5;
    if (C.enforce_grace > 600) C.enforce_grace = 600;
    C.always_on = t_bool(t, "always_on", 1);
    int days = t_int(t, "always_on_expire_days", 30);
    C.always_on_expire = days > 0 ? (long)days * 86400 : 0;
    C.expire_days = t_int(t, "expire_days", 0);
    if (C.expire_days < 0) C.expire_days = 0;
    if (C.expire_days > 3650) C.expire_days = 3650;
    C.require_email = t_bool(t, "require_email", 0);
    int vh = t_int(t, "verify_window_hours", 24);
    C.verify_window = (long)(vh < 1 ? 1 : vh > 168 ? 168 : vh) * 3600;
    C.expire_warn_days = t_int(t, "expire_warn_days", 0);
    if (C.expire_warn_days < 0 || C.expire_warn_days >= C.expire_days) C.expire_warn_days = 0;
    toml_node_t *ad = t ? tx_array(t, "admins") : NULL;
    for (int i = 0; ad && i < tx_len(ad) && C.n_admins < NS_MAX_ADMINS; i++) {
        toml_node_t *d = tx_at(ad, i, TOML_STRING);
        if (d) snprintf(C.admins[C.n_admins++], sizeof C.admins[0], "%s", d->u.s);
    }
    /* [[opers]]: keep the names in step with config.c's OPER_PRIV_NAMES */
    static const char *const PRIVS[] = {"kill", "kline", "sa", "host", "wallops", "rehash", "die", "link", "override", "auspex", "immune", "all"};
    toml_node_t *ol = tx_array(raw, "opers");
    for (int i = 0; ol && i < tx_len(ol); i++) {
        toml_node_t *o = tx_at(ol, i, TOML_TABLE);
        if (!o) continue;
        if (C.n_opers >= NS_MAX_OPERS) { snprintf(err, errsz, "too many [[opers]] entries (max %d)", NS_MAX_OPERS); return -1; }
        ns_oper_t *e = &C.opers[C.n_opers];
        t_str(o, "account", e->account, sizeof e->account);
        if (!e->account[0]) { snprintf(err, errsz, "[[opers]] entry %d needs an account", i + 1); return -1; }
        toml_node_t *pr = tx_array(o, "privileges");
        if (!pr) snprintf(e->privs, sizeof e->privs, "all");
        for (int k = 0; pr && k < tx_len(pr); k++) {
            toml_node_t *d = tx_at(pr, k, TOML_STRING);
            int known = 0;
            for (size_t q = 0; d && q < sizeof PRIVS / sizeof *PRIVS; q++) known |= strcasecmp(d->u.s, PRIVS[q]) == 0;
            if (!known) { snprintf(err, errsz, "[[opers]] %s: unknown privilege '%s' (kill, kline, sa, host, wallops, rehash, die, link, override, auspex, immune, all)", e->account, d ? d->u.s : "?"); return -1; }
            size_t l = strlen(e->privs);
            snprintf(e->privs + l, sizeof e->privs - l, "%s%s", l ? "," : "", d->u.s);
        }
        if (!e->privs[0]) { snprintf(err, errsz, "[[opers]] %s: privileges is empty", e->account); return -1; }
        e->password_only = t_bool(o, "password_only", 0);
        char fp[160] = "";
        t_str(o, "certfp", fp, sizeof fp);
        size_t n = 0;
        for (const char *c = fp; *c; c++) if (*c != ':' && *c != ' ' && n + 1 < sizeof e->certfp) e->certfp[n++] = (char)tolower((unsigned char)*c);
        e->certfp[n] = '\0';
        if (e->certfp[0] && (n != 64 || strspn(e->certfp, "0123456789abcdef") != 64)) {
            snprintf(err, errsz, "[[opers]] %s: certfp must be the 64 hex digits of the certificate's SHA-256 fingerprint", e->account);
            return -1;
        }
        if (!e->certfp[0] && !e->password_only) {
            snprintf(err, errsz, "[[opers]] %s: needs certfp (the SHA-256 fingerprint of their TLS client certificate) or password_only = true", e->account);
            return -1;
        }
        C.n_opers++;
    }
    if (!irc_valid_nick(C.nick, 30)) { snprintf(err, errsz, "[nickserv] nick is not a valid nickname"); return -1; }
    if (C.email_command[0] && C.email_command[0] != '/') { snprintf(err, errsz, "[nickserv] email_command must be an absolute path"); return -1; }
    if (C.require_email && !C.email_command[0]) {
        snprintf(err, errsz, "[nickserv] require_email = true needs email_command (the codes that activate new accounts are mailed)");
        return -1;
    }

    /* Where the accounts live. Unset = find the database the ircd's built-in NickServ kept (an upgrade then uses it in
     * place, nothing copied or converted): the git-clone layout first, then a make-install one, else a new file. */
    char set[512] = "";
    t_str(t, "store_file", set, sizeof set);
    if (set[0]) beside(config_path, set, C.store_file, sizeof C.store_file);
    else {
        static const char *cands[] = {"../config/accounts.json", "accounts.json"};
        for (size_t i = 0; i < sizeof cands / sizeof cands[0] && !C.store_file[0]; i++) {
            char p[512];
            beside(config_path, cands[i], p, sizeof p);
            if (file_exists(p)) snprintf(C.store_file, sizeof C.store_file, "%s", p);
        }
        if (!C.store_file[0]) beside(config_path, "nickserv.json", C.store_file, sizeof C.store_file);
    }
    return 0;
}

int ns_enabled(void) { return C.enabled; }
int ns_account_count(void) { return C.enabled ? accounts_count(&g_acc) : -1; }

int ns_start(char *err, size_t errsz) {
    if (!C.enabled) return 0;
    char note[700];
    if (accounts_load(&g_acc, C.store_file, C.backup_count, note, sizeof note) != 0) {
        snprintf(err, errsz, "%s", note);
        return -1;
    }
    if (note[0]) log_warn("nickserv", "%s", note);
    log_info("nickserv", "account database %s (%d accounts)", C.store_file, accounts_count(&g_acc));
    return 0;
}

void ns_shutdown(void) {
    if (C.enabled) accounts_free(&g_acc);
}

/* --- the network's users (from the hub's SVCUSER feed) ----------------------------------------------------------- */

typedef struct nsuser {
    char uid[16], nick[64], cf[64], user[32], host[128], ip[64], account[64], certfp[72], server[128];
    char oper_sent[96];    /* the SVSOPER privileges last sent for this user ("" = none): resent only when they change */
    time_t enforce_at;     /* rename deadline for an unidentified user on a registered nick (0 = none) */
    char enforce_owner[64];
    UT_hash_handle hh;     /* by uid */
    UT_hash_handle hn;     /* by casefolded nick */
} nsuser_t;

static nsuser_t *g_by_uid, *g_by_nick;

static nsuser_t *user_by_uid(const char *uid) { nsuser_t *u; HASH_FIND(hh, g_by_uid, uid, strlen(uid), u); return u; }
static nsuser_t *user_by_nick(const char *nick) {
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    nsuser_t *u;
    HASH_FIND(hn, g_by_nick, cf, strlen(cf), u);
    return u;
}

const char *ns_account_of(const char *nick) {
    nsuser_t *u = user_by_nick(nick);
    return u && u->account[0] ? u->account : NULL;
}

static void user_set_nick(nsuser_t *u, const char *nick) {
    nsuser_t *f = NULL;
    if (u->cf[0]) { HASH_FIND(hn, g_by_nick, u->cf, strlen(u->cf), f); if (f == u) HASH_DELETE(hn, g_by_nick, u); }
    snprintf(u->nick, sizeof u->nick, "%s", nick);
    irc_casefold(u->cf, sizeof u->cf, nick);
    HASH_ADD(hn, g_by_nick, cf, strlen(u->cf), u);
}

static void user_free(nsuser_t *u) {
    HASH_DELETE(hh, g_by_uid, u);
    nsuser_t *f = NULL;
    HASH_FIND(hn, g_by_nick, u->cf, strlen(u->cf), f);
    if (f == u) HASH_DELETE(hn, g_by_nick, u);
    free(u);
}

static void users_clear(void) {
    nsuser_t *u, *tmp;
    HASH_ITER(hh, g_by_uid, u, tmp) user_free(u);
}

/* --- wire helpers -------------------------------------------------------------------------------------------------- */

static void say(const char *to, const char *text) {
    char prefix[400], line[700];
    irc_prefix_for(prefix, sizeof prefix, C.nick, C.user, C.host);
    irc_build(line, sizeof line, NULL, 0, prefix, "NOTICE", (const char *[]){to}, 1, text);
    svc_queue_line(line);
}

static void sayf(const char *to, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sayf(const char *to, const char *fmt, ...) {
    char m[500];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m, sizeof m, fmt, ap);
    va_end(ap);
    say(to, m);
}

static void wire(const char *cmd, const char **p, int n, const char *trailing) {
    char line[700];
    irc_build(line, sizeof line, NULL, 0, NULL, cmd, p, n, trailing);
    svc_queue_line(line);
}

/* SET AJOIN: the channels an account joins at every login -- one comma-separated list, so it fits one SVSJOIN line. */
#define AJOIN_MAX 10
#define AJOIN_LEN 200

/* The account's AJOIN list to the hub, which joins `uid` through its normal JOIN checks (SVSJOIN, cmd_svsjoin). Sent from
 * SVCACCOUNT (IDENTIFY, REGISTER, SASL re-auth), and from SVCUSER for a SASL login made before registration -- the hub
 * sends no SVCACCOUNT for those. Never from login() too, or a refused channel is announced twice. */
static void ajoin_send(const char *uid, const char *account) {
    const char *list = accounts_ajoin(&g_acc, account);
    if (list && list[0]) wire("SVSJOIN", (const char *[]){uid, list}, 2, NULL);
}

/* What an [[opers]] entry makes of this user: the entry for the account they are logged in to, if its certificate condition holds. */
static const ns_oper_t *oper_entry(const nsuser_t *u) {
    if (!C.enabled || !u->account[0]) return NULL;
    for (int i = 0; i < C.n_opers; i++) {
        const ns_oper_t *e = &C.opers[i];
        if (strcasecmp(e->account, u->account) != 0) continue;
        if (e->password_only || (u->certfp[0] && strcasecmp(u->certfp, e->certfp) == 0)) return e;
        return NULL; /* the right account without the right certificate: no oper */
    }
    return NULL;
}

/* Tell the user's server what oper status they should have (SVSOPER), when it differs from what we last said. "-" takes it back. */
static void oper_sync(nsuser_t *u) {
    const ns_oper_t *e = oper_entry(u);
    const char *want = e ? e->privs : "";
    if (strcmp(want, u->oper_sent) == 0) return;
    wire("SVSOPER", (const char *[]){u->uid, want[0] ? want : "-", u->account[0] ? u->account : "-"}, 3, NULL);
    snprintf(u->oper_sent, sizeof u->oper_sent, "%s", want);
    if (want[0]) log_info("nickserv", "%s (account %s) is a network oper (%s)", u->nick, u->account, want);
    else log_info("nickserv", "%s is no longer a network oper", u->nick);
}

/* After a reload: say it all again to everyone who should be an oper (a server that now takes grants, or that restarted, hears it;
 * an unchanged one ignores it), and take it back from those whose entry is gone. */
static void opers_resync(void) {
    nsuser_t *u, *tmp;
    HASH_ITER(hh, g_by_uid, u, tmp) {
        if (oper_entry(u)) u->oper_sent[0] = '\0';
        oper_sync(u);
    }
}

/* Log `id` in as `account` (NULL = log out). The hub sets it on the user's own server, which announces it network-wide.
 * The 4th parameter is always-on: how many seconds the user's server keeps the nick after the connection drops (-1 =
 * until it restarts), "0" = off. Older servers ignore it. Sent again by SET ALWAYS-ON to update a live login. */
static void login(const char *id, const char *account) {
    char ts[24], ao[24] = "0";
    snprintf(ts, sizeof ts, "%ld", account ? accounts_created_at(&g_acc, account) : 0L);
    if (account && C.always_on && accounts_always_on(&g_acc, account)) snprintf(ao, sizeof ao, "%ld", C.always_on_expire ? C.always_on_expire : -1L);
    if (account) wire("SVSLOGIN", (const char *[]){id, account, ts, ao}, 4, NULL);
    else wire("SVSLOGIN", (const char *[]){id, "*"}, 2, NULL);
    nsuser_t *u = user_by_uid(id);
    if (u) {
        if (account && strcasecmp(u->account, account) != 0) u->oper_sent[0] = '\0'; /* the old account's grant went with the SVSLOGIN */
        snprintf(u->account, sizeof u->account, "%s", account ? account : "");
        if (account) u->enforce_at = 0;
        oper_sync(u);
    }
}

/* "Last login from: ..." to `u`, then record this login as the new last one. */
static void last_login_note(nsuser_t *u) {
    long at;
    const char *prev = accounts_last_login(&g_acc, u->account, &at);
    if (prev && at) {
        time_t t = (time_t)at;
        char when[48];
        strftime(when, sizeof when, "%b %d %H:%M:%S %Y +0000", gmtime(&t));
        sayf(u->nick, "Last login from: %s on %s.", prev, when);
    }
    char mask[200];
    snprintf(mask, sizeof mask, "%s@%s", u->user, u->host);
    accounts_set_last_login(&g_acc, u->account, mask);
}

/* SASL logins land before the user is on the network (or arrive as SVCACCOUNT): remember (account, ip) for a minute
 * so the matching SVCUSER/SVCACCOUNT gets the note -- and the resend-everyone burst after a services restart doesn't. */
#define SASL_SEEN 64
static struct { char account[64], ip[64]; time_t at; } g_sasl_seen[SASL_SEEN];
static int g_sasl_seen_next;

static void sasl_seen_add(const char *account, const char *ip) {
    int i = g_sasl_seen_next++ % SASL_SEEN; /* ponytail: ring of 64, a burst of >64 SASL logins/min loses some notes */
    snprintf(g_sasl_seen[i].account, sizeof g_sasl_seen[i].account, "%s", account);
    snprintf(g_sasl_seen[i].ip, sizeof g_sasl_seen[i].ip, "%s", ip);
    g_sasl_seen[i].at = time(NULL);
}

/* 1 if `u` matches a SASL login from the last minute (consumed): a real login, not a services-restart resend. */
static int sasl_seen_check(nsuser_t *u) {
    if (!u->account[0]) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < SASL_SEEN; i++)
        if (g_sasl_seen[i].at && now - g_sasl_seen[i].at <= 60 && strcmp(g_sasl_seen[i].ip, u->ip) == 0 &&
            strcasecmp(g_sasl_seen[i].account, u->account) == 0) {
            g_sasl_seen[i].at = 0;
            last_login_note(u);
            return 1;
        }
    return 0;
}

static void logout_all(const char *account) {
    nsuser_t *u, *tmp;
    HASH_ITER(hh, g_by_uid, u, tmp)
        if (u->account[0] && strcasecmp(u->account, account) == 0) { login(u->uid, NULL); say(u->nick, "You have been logged out"); }
}

/* --- failed-password throttle, per IP (IDENTIFY and every password-checked command) ----------------------------- */

#define FAIL_SLOTS 256
#define FAIL_MAX 5
#define FAIL_WINDOW 60
static struct { char ip[64]; time_t start; int n; } g_fail[FAIL_SLOTS];

static int fail_throttled(const char *ip) {
    for (int i = 0; i < FAIL_SLOTS; i++)
        if (strcmp(g_fail[i].ip, ip) == 0) return time(NULL) - g_fail[i].start <= FAIL_WINDOW && g_fail[i].n >= FAIL_MAX;
    return 0;
}

static void fail_record(const char *ip) {
    time_t now = time(NULL);
    int slot = -1, oldest = 0;
    for (int i = 0; i < FAIL_SLOTS; i++) {
        if (strcmp(g_fail[i].ip, ip) == 0) { slot = i; break; }
        if (!g_fail[i].ip[0] || g_fail[i].start < g_fail[oldest].start) oldest = i;
    }
    if (slot < 0) slot = oldest;
    if (strcmp(g_fail[slot].ip, ip) != 0 || now - g_fail[slot].start > FAIL_WINDOW) {
        snprintf(g_fail[slot].ip, sizeof g_fail[slot].ip, "%s", ip);
        g_fail[slot].start = now;
        g_fail[slot].n = 0;
    }
    g_fail[slot].n++;
}

/* An unknown account still costs one full scrypt verify, so its reply time doesn't tell it apart from a wrong password. */
static const char *decoy_hash(void) {
    static char buf[160];
    if (!buf[0]) crypto_hash_password("sekurircd-timing-decoy, not a real password", buf, sizeof buf);
    return buf;
}

/* Checks `password` for `account` (a name or one of its grouped nicks). Returns the stored account name, or NULL. */
static const char *check_password(const char *account, const char *password) {
    const char *owner = accounts_owner_of_nick(&g_acc, account);
    if (owner) account = owner;
    const char *hash = accounts_hash(&g_acc, account);
    /* ponytail: scrypt (~30 ms) runs on the services loop -- a burst of a few hundred logins queues a few seconds;
     * a worker thread is the fix if that is ever felt. */
    int ok = crypto_verify_password(password, hash ? hash : decoy_hash());
    if (!ok || !hash) return NULL;
    const char *name = accounts_display_name(&g_acc, account);
    if (!accounts_scram(&g_acc, name)) { /* an account from before SCRAM: derive its verifier now the password is known */
        scram_verifier_t sv;
        char vs[160];
        if (scram_make_verifier(password, &sv) == 0) { scram_verifier_to_string(&sv, vs, sizeof vs); accounts_set_scram(&g_acc, name, vs); }
    }
    return name;
}

static void set_password(const char *account, const char *password, char *hash, size_t hashsz) {
    crypto_hash_password(password, hash, hashsz);
    accounts_set_hash(&g_acc, account, hash);
    scram_verifier_t sv;
    char vs[160];
    if (scram_make_verifier(password, &sv) == 0) { scram_verifier_to_string(&sv, vs, sizeof vs); accounts_set_scram(&g_acc, account, vs); }
}

static int is_admin(const nsuser_t *u) {
    if (!u || !u->account[0]) return 0;
    for (int i = 0; i < C.n_admins; i++) if (strcasecmp(C.admins[i], u->account) == 0) return 1;
    return 0;
}

/* --- email ---------------------------------------------------------------------------------------------------------- */

static int valid_email(const char *e) {
    size_t n = strlen(e);
    if (n < 3 || n > 120 || e[0] == '-' || e[0] == '@') return 0;
    int at = 0;
    for (const char *p = e; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '@') { if (++at > 1) return 0; continue; }
        if (!(isalnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-')) return 0; /* never a shell metacharacter */
    }
    return at == 1 && e[n - 1] != '@';
}

/* `cmd addr code account network purpose`, fully detached (double fork), no shell. */
static void spawn_email(const char *addr, const char *code, const char *account, const char *purpose) {
    pid_t p1 = fork();
    if (p1 < 0) return;
    if (p1 == 0) {
        if (fork() == 0) {
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }
            execl(C.email_command, C.email_command, addr, code, account, C.network, purpose, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
    waitpid(p1, NULL, 0);
}

/* A code for `email`, valid `ttl` seconds, mailed for VERIFY. */
static void mail_code(const char *account, const char *email, long ttl) {
    char code[12];
    crypto_random_hex(code, sizeof code, 4);
    accounts_set_pending_email(&g_acc, account, email, code, (long)time(NULL) + ttl);
    spawn_email(email, code, account, "verify");
}

static void begin_email(const char *to, const char *account, const char *email) {
    if (!valid_email(email)) { say(to, "That does not look like a valid email address"); return; }
    if (!C.email_command[0]) {
        accounts_set_email(&g_acc, account, email, 0);
        say(to, "Email saved (this network does not verify addresses)");
        return;
    }
    char code[12];
    crypto_random_hex(code, sizeof code, 4);
    accounts_set_pending_email(&g_acc, account, email, code, (long)time(NULL) + 3600);
    spawn_email(email, code, account, "verify");
    say(to, "A verification code was sent -- finish with /msg NickServ VERIFY <code> within an hour");
}

/* --- registration (NickServ REGISTER and the ircd's REGISTER command) ------------------------------------------- */

/* NULL = registered (and *ts set), else the failure as "CODE text". */
static const char *do_register(const char *account, const char *password, const char *ip) {
    static char why[200];
    if (!irc_valid_user(account, 30)) { snprintf(why, sizeof why, "BAD_ACCOUNT_NAME %s is not a valid account name", account); return why; }
    if (accounts_exists(&g_acc, account) || accounts_owner_of_nick(&g_acc, account)) {
        snprintf(why, sizeof why, "ACCOUNT_EXISTS Account %s already exists", account);
        return why;
    }
    if (strlen(password) < 5 || strlen(password) > 200) return "BAD_PASSWORD The password must be 5-200 characters";
    if (C.max_accounts > 0 && accounts_count(&g_acc) >= C.max_accounts)
        return "REG_UNAVAILABLE This network has reached its account limit -- ask an operator";
    if (fail_throttled(ip)) return "TEMPORARILY_UNAVAILABLE Too many attempts -- wait a minute";
    fail_record(ip); /* registrations count against the same per-IP budget, so one host can't create accounts in a loop */
    char hash[200];
    crypto_hash_password(password, hash, sizeof hash);
    accounts_register_hashed(&g_acc, account, hash);
    scram_verifier_t sv;
    char vs[160];
    if (scram_make_verifier(password, &sv) == 0) { scram_verifier_to_string(&sv, vs, sizeof vs); accounts_set_scram(&g_acc, account, vs); }
    log_info("nickserv", "account %s registered (from %s)", account, ip);
    return NULL;
}

/* VERIFY of a registration waiting for its email (require_email): the account becomes usable and its email verified.
 * NULL = activated (*name set), else why not. Wrong codes count against the IP like wrong passwords. */
static const char *activate(const char *account, const char *code, const char *ip, const char **name) {
    if (fail_throttled(ip)) return "Too many attempts -- wait a minute";
    const char *owner = accounts_owner_of_nick(&g_acc, account);
    if (!owner || !accounts_unverified(&g_acc, owner)) return "No registration of that name is waiting for verification";
    if (!accounts_check_verify(&g_acc, owner, code)) { fail_record(ip); return "That code is wrong or has expired"; }
    accounts_set_unverified(&g_acc, owner, 0);
    *name = accounts_display_name(&g_acc, owner);
    log_info("nickserv", "account %s verified its email and is active (from %s)", *name, ip);
    return NULL;
}

/* SVCVERIFY <cid> <ip> <account> :<code> -- the ircd's VERIFY (draft/account-registration). Answered as SVCREGRESULT VERIFIED
 * or VERIFYFAIL (an older ircd shows those as a failed REGISTER). */
static void ev_verify(irc_message_t *m) {
    if (m->nparams < 4) return;
    const char *cid = m->params[0], *name = NULL;
    const char *why = activate(m->params[2], m->params[3], m->params[1], &name);
    if (why) { wire("SVCREGRESULT", (const char *[]){cid, "VERIFYFAIL", "INVALID_CODE", m->params[2]}, 4, why); return; }
    char keep[64], msg[200];
    snprintf(keep, sizeof keep, "%s", name);
    login(cid, keep);
    snprintf(msg, sizeof msg, "Email verified -- account %s is active and you are logged in", keep);
    wire("SVCREGRESULT", (const char *[]){cid, "VERIFIED", "*", keep}, 4, msg);
}

/* SVCREGISTER <cid> <ip> <account> <email|*> :<password> */
static void ev_register(irc_message_t *m) {
    if (m->nparams < 5) return;
    const char *cid = m->params[0], *ip = m->params[1], *account = m->params[2], *email = m->params[3], *pw = m->params[4];
    if (C.require_email && (strcmp(email, "*") == 0 || !valid_email(email))) {
        wire("SVCREGRESULT", (const char *[]){cid, "FAIL", "INVALID_EMAIL", account}, 4, "This network needs a valid email address to register");
        return;
    }
    const char *why = do_register(account, pw, ip);
    if (why) {
        char code[40];
        const char *sp = strchr(why, ' ');
        snprintf(code, sizeof code, "%.*s", (int)(sp - why), why);
        wire("SVCREGRESULT", (const char *[]){cid, "FAIL", code, account}, 4, sp + 1);
        return;
    }
    const char *name = accounts_display_name(&g_acc, account);
    if (C.require_email) {
        char keep[64], msg[300];
        snprintf(keep, sizeof keep, "%s", name);
        accounts_set_unverified(&g_acc, keep, 1);
        mail_code(keep, email, C.verify_window);
        snprintf(msg, sizeof msg, "A code was sent to %s -- the account works once you VERIFY %s <code> (within %ld hours)", email, keep,
                 C.verify_window / 3600);
        wire("SVCREGRESULT", (const char *[]){cid, "VERIFICATION_REQUIRED", "*", keep}, 4, msg);
        return;
    }
    login(cid, name);
    char msg[200];
    snprintf(msg, sizeof msg, "Account %s registered -- you are now logged in as it", name);
    wire("SVCREGRESULT", (const char *[]){cid, "SUCCESS", "*", name}, 4, msg);
    if (strcmp(email, "*") != 0 && valid_email(email)) { /* no nick to send the notice to yet: store it unverified */
        accounts_set_email(&g_acc, name, email, 0);
    }
}

/* --- SASL (relayed by the client's server) ------------------------------------------------------------------------ */

#define SASL_SLOTS 128
typedef struct {
    char cid[40], mech[16], certfp[72], ip[64];
    time_t started;
    int step;                      /* SCRAM: 0 = expecting client-first, 1 = client-final, 2 = the final "+" */
    char account[64], first_bare[300], server_first[300];
    scram_verifier_t v;
} sasl_t;
static sasl_t g_sasl[SASL_SLOTS];

static sasl_t *sasl_find(const char *cid, int create) {
    sasl_t *free_slot = NULL, *oldest = &g_sasl[0];
    for (int i = 0; i < SASL_SLOTS; i++) {
        if (g_sasl[i].cid[0] && strcmp(g_sasl[i].cid, cid) == 0) return &g_sasl[i];
        if (!g_sasl[i].cid[0] && !free_slot) free_slot = &g_sasl[i];
        if (g_sasl[i].started < oldest->started) oldest = &g_sasl[i];
    }
    if (!create) return NULL;
    sasl_t *s = free_slot ? free_slot : oldest;
    OPENSSL_cleanse(s, sizeof *s);
    snprintf(s->cid, sizeof s->cid, "%s", cid);
    s->started = time(NULL);
    return s;
}

static void sasl_send(const char *cid, const char *kind, const char *data) { wire("SVCSASL", (const char *[]){cid, kind, data}, 3, NULL); }

static void sasl_done(sasl_t *s, const char *account) {
    if (account) {
        login(s->cid, account);
        sasl_seen_add(account, s->ip);
        sasl_send(s->cid, "D", "S");
        log_info("nickserv", "SASL %s login as %s (%s)", s->mech, account, s->ip);
    } else {
        fail_record(s->ip);
        sasl_send(s->cid, "D", "F");
    }
    OPENSSL_cleanse(s, sizeof *s);
}

static int scram_attr(const char *msg, char key, char *out, size_t outsz) {
    for (const char *p = msg; *p;) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len >= 2 && p[0] == key && p[1] == '=') {
            if (len - 2 >= outsz) return 0;
            memcpy(out, p + 2, len - 2);
            out[len - 2] = '\0';
            return 1;
        }
        p = end ? end + 1 : p + len;
    }
    return 0;
}

static void sasl_scram(sasl_t *s, const char *data) {
    unsigned char raw[320];
    char msg[320];
    if (strcmp(data, "+") == 0) msg[0] = '\0';
    else {
        int n = strlen(data) > 400 ? -1 : scram_b64_decode(data, raw, sizeof raw - 1);
        if (n < 0) { sasl_done(s, NULL); return; }
        memcpy(msg, raw, (size_t)n);
        msg[n] = '\0';
    }
    if (s->step == 0) { /* client-first: "n,,n=<user>,r=<cnonce>" (no channel binding) */
        if (strncmp(msg, "n,,", 3) != 0 && strncmp(msg, "y,,", 3) != 0) { sasl_done(s, NULL); return; }
        const char *bare = msg + 3;
        char user[64], cnonce[96];
        if (!scram_attr(bare, 'n', user, sizeof user) || !scram_attr(bare, 'r', cnonce, sizeof cnonce) || strchr(user, '=')) { sasl_done(s, NULL); return; }
        const char *owner = accounts_owner_of_nick(&g_acc, user);
        const char *name = owner ? owner : user;
        const char *stored = accounts_scram(&g_acc, name);
        if (accounts_suspended(&g_acc, name, NULL, NULL) || accounts_unverified(&g_acc, name) || !stored || scram_verifier_from_string(stored, &s->v) != 0) { sasl_done(s, NULL); return; }
        snprintf(s->account, sizeof s->account, "%s", accounts_display_name(&g_acc, name));
        snprintf(s->first_bare, sizeof s->first_bare, "%s", bare);
        char snonce[24], saltb[64], out[500];
        crypto_random_hex(snonce, sizeof snonce, 11);
        scram_b64_encode(s->v.salt, (size_t)s->v.saltlen, saltb, sizeof saltb);
        snprintf(s->server_first, sizeof s->server_first, "r=%s%s,s=%s,i=%d", cnonce, snonce, saltb, s->v.iter);
        if (scram_b64_encode((const unsigned char *)s->server_first, strlen(s->server_first), out, sizeof out) < 0) { sasl_done(s, NULL); return; }
        s->step = 1;
        sasl_send(s->cid, "C", out);
        return;
    }
    if (s->step == 1) { /* client-final: "c=biws,r=<nonce>,p=<proof>" */
        char chan[16], nonce[200], proofb[64], expect[200];
        if (!scram_attr(msg, 'c', chan, sizeof chan) || (strcmp(chan, "biws") != 0 && strcmp(chan, "eSws") != 0) ||
            !scram_attr(msg, 'r', nonce, sizeof nonce) || !scram_attr(msg, 'p', proofb, sizeof proofb) ||
            !scram_attr(s->server_first, 'r', expect, sizeof expect) || strcmp(nonce, expect) != 0) { sasl_done(s, NULL); return; }
        const char *pp = strstr(msg, ",p=");
        unsigned char proof[64], sig[SCRAM_KEYLEN];
        if (!pp || scram_b64_decode(proofb, proof, sizeof proof) != SCRAM_KEYLEN) { sasl_done(s, NULL); return; }
        char authmsg[900];
        snprintf(authmsg, sizeof authmsg, "%s,%s,%.*s", s->first_bare, s->server_first, (int)(pp - msg), msg);
        if (!scram_check_proof(&s->v, authmsg, proof, sig)) { sasl_done(s, NULL); return; }
        char sigb[64], final[100], out[200];
        scram_b64_encode(sig, SCRAM_KEYLEN, sigb, sizeof sigb);
        snprintf(final, sizeof final, "v=%s", sigb);
        scram_b64_encode((const unsigned char *)final, strlen(final), out, sizeof out);
        s->step = 2;
        sasl_send(s->cid, "C", out);
        return;
    }
    char account[64];
    snprintf(account, sizeof account, "%s", s->account);
    sasl_done(s, account); /* the client's "+" after the server signature */
}

static void sasl_plain(sasl_t *s, const char *data) {
    unsigned char blob[600];
    size_t inlen = strlen(data);
    if (inlen == 0 || inlen > 400 || inlen % 4) { sasl_done(s, NULL); return; }
    int n = EVP_DecodeBlock(blob, (const unsigned char *)data, (int)inlen);
    if (n < 0) { sasl_done(s, NULL); return; }
    if (data[inlen - 1] == '=') n--;
    if (inlen >= 2 && data[inlen - 2] == '=') n--;
    unsigned char *end = blob + n, *nul1 = memchr(blob, '\0', (size_t)n);
    unsigned char *ac = nul1 ? nul1 + 1 : NULL, *nul2 = ac ? memchr(ac, '\0', (size_t)(end - ac)) : NULL;
    if (!nul2 || nul2 == ac || end - (nul2 + 1) <= 0 || end - (nul2 + 1) >= 256 || nul2 - ac >= 64) { sasl_done(s, NULL); return; }
    char account[64], password[256];
    snprintf(account, sizeof account, "%.*s", (int)(nul2 - ac), ac);
    snprintf(password, sizeof password, "%.*s", (int)(end - (nul2 + 1)), nul2 + 1);
    OPENSSL_cleanse(blob, sizeof blob);
    const char *name = fail_throttled(s->ip) ? NULL : check_password(account, password);
    OPENSSL_cleanse(password, sizeof password);
    if (name && (accounts_suspended(&g_acc, name, NULL, NULL) || accounts_unverified(&g_acc, name))) name = NULL;
    char keep[64] = "";
    if (name) snprintf(keep, sizeof keep, "%s", name);
    sasl_done(s, name ? keep : NULL);
}

/* SVCSASL <cid> S <mech> <certfp|*> <ip>  |  <cid> C <data>  |  <cid> D A */
static void ev_sasl(irc_message_t *m) {
    if (m->nparams < 3) return;
    const char *cid = m->params[0], *kind = m->params[1];
    if (strcmp(kind, "S") == 0) {
        sasl_t *s = sasl_find(cid, 1);
        snprintf(s->mech, sizeof s->mech, "%s", m->params[2]);
        if (m->nparams > 3 && strcmp(m->params[3], "*") != 0) snprintf(s->certfp, sizeof s->certfp, "%s", m->params[3]);
        if (m->nparams > 4) snprintf(s->ip, sizeof s->ip, "%s", m->params[4]);
        return;
    }
    sasl_t *s = sasl_find(cid, 0);
    if (!s) { if (strcmp(kind, "C") == 0) sasl_send(cid, "D", "F"); return; }
    if (strcmp(kind, "D") == 0) { OPENSSL_cleanse(s, sizeof *s); return; } /* the client aborted */
    if (strcmp(kind, "C") != 0) return;
    const char *data = m->params[2];
    if (strcasecmp(s->mech, "PLAIN") == 0) sasl_plain(s, data);
    else if (strcasecmp(s->mech, "SCRAM-SHA-256") == 0) sasl_scram(s, data);
    else if (strcasecmp(s->mech, "EXTERNAL") == 0) {
        const char *acct = s->certfp[0] ? accounts_find_by_fingerprint(&g_acc, s->certfp) : NULL;
        if (acct && (accounts_suspended(&g_acc, acct, NULL, NULL) || accounts_unverified(&g_acc, acct))) acct = NULL;
        char keep[64] = "";
        if (acct) snprintf(keep, sizeof keep, "%s", acct);
        sasl_done(s, acct ? keep : NULL);
    } else sasl_done(s, NULL);
}

/* --- enforcement ([nickserv] enforce_nicks) -------------------------------------------------------------------------- */

static void guest_nick(char *out, size_t outsz) {
    for (int tries = 0; tries < 20; tries++) {
        char rh[9];
        crypto_random_hex(rh, sizeof rh, 4);
        snprintf(out, outsz, "Guest%u", 10000 + (unsigned)(strtoul(rh, NULL, 16) % 90000));
        if (!user_by_nick(out)) return;
    }
}

static void enforce_check(nsuser_t *u) {
    u->enforce_at = 0;
    if (!C.enabled || !C.enforce_nicks) return;
    const char *owner = accounts_owner_of_nick(&g_acc, u->nick);
    if (!owner || (u->account[0] && strcasecmp(u->account, owner) == 0) || accounts_unverified(&g_acc, owner)) return; /* not active yet: protects nothing */
    snprintf(u->enforce_owner, sizeof u->enforce_owner, "%s", owner);
    u->enforce_at = time(NULL) + C.enforce_grace;
    sayf(u->nick, "This nickname is registered. Log in (SASL, or /msg %s IDENTIFY <password>) within %d seconds or you "
                  "will be renamed.", C.nick, C.enforce_grace);
}

static void rename_user(nsuser_t *u, const char *newnick) { wire("SVSNICK", (const char *[]){u->uid, newnick}, 2, NULL); }

/* --- user feed ------------------------------------------------------------------------------------------------------ */

/* SVCUSER <uid> <nick> <user> <realhost> <ip> <account|*> <certfp|*> <server> */
static void ev_user(irc_message_t *m) {
    if (m->nparams < 8) return;
    nsuser_t *u = user_by_uid(m->params[0]);
    int fresh = !u;
    if (!u) {
        if (!(u = calloc(1, sizeof *u))) return;
        snprintf(u->uid, sizeof u->uid, "%s", m->params[0]);
        HASH_ADD(hh, g_by_uid, uid, strlen(u->uid), u);
    }
    int renamed = fresh || strcasecmp(u->nick, m->params[1]) != 0;
    if (renamed && !fresh) cs_user_nick(u->nick, m->params[1]);
    if (renamed) user_set_nick(u, m->params[1]);
    snprintf(u->user, sizeof u->user, "%s", m->params[2]);
    snprintf(u->host, sizeof u->host, "%s", m->params[3]);
    snprintf(u->ip, sizeof u->ip, "%s", m->params[4]);
    snprintf(u->account, sizeof u->account, "%s", strcmp(m->params[5], "*") ? m->params[5] : "");
    snprintf(u->certfp, sizeof u->certfp, "%s", strcmp(m->params[6], "*") ? m->params[6] : "");
    snprintf(u->server, sizeof u->server, "%s", m->params[7]);
    if (renamed) enforce_check(u);
    if (fresh && sasl_seen_check(u)) ajoin_send(u->uid, u->account); /* SASL: no SVCACCOUNT follows */
    oper_sync(u); /* a SASL login made before registration, or a user the hub resent after a services restart */
}

int ns_event(irc_message_t *m) {
    const char *c = m->command;
    if (!strcmp(c, "SVCUSER")) { ev_user(m); return 1; }
    if (!strcmp(c, "SVCNICK")) {
        nsuser_t *u = m->nparams >= 2 ? user_by_uid(m->params[0]) : NULL;
        if (u) { cs_user_nick(u->nick, m->params[1]); user_set_nick(u, m->params[1]); enforce_check(u); }
        return 1;
    }
    if (!strcmp(c, "SVCQUIT")) {
        nsuser_t *u = m->nparams >= 1 ? user_by_uid(m->params[0]) : NULL;
        if (u) { cs_user_quit(u->nick); user_free(u); }
        return 1;
    }
    if (!strcmp(c, "SVCACCOUNT")) {
        nsuser_t *u = m->nparams >= 2 ? user_by_uid(m->params[0]) : NULL;
        if (u) {
            if (strcasecmp(u->account, strcmp(m->params[1], "*") ? m->params[1] : "") != 0) u->oper_sent[0] = '\0';
            snprintf(u->account, sizeof u->account, "%s", strcmp(m->params[1], "*") ? m->params[1] : "");
            if (u->account[0] && strcasecmp(u->account, u->enforce_owner) == 0) u->enforce_at = 0;
            if (u->account[0]) { cs_user_login(u->nick); sasl_seen_check(u); ajoin_send(u->uid, u->account); }
            oper_sync(u);
        }
        return 1;
    }
    if (!strcmp(c, "SVCINFO")) { /* SVCINFO <hub> :<network> -- names the network in mails unless [nickserv] network does */
        if (m->nparams >= 2 && !C.network_set) snprintf(C.network, sizeof C.network, "%s", m->params[1]);
        return 1;
    }
    if (!C.enabled) return 0;
    if (!strcmp(c, "SVCSASL")) { ev_sasl(m); return 1; }
    if (!strcmp(c, "SVCREGISTER")) { ev_register(m); return 1; }
    if (!strcmp(c, "SVCVERIFY")) { ev_verify(m); return 1; }
    return 0;
}

void ns_session_start(void) {
    users_clear(); /* the hub resends everyone after SVCWATCH */
    if (!C.enabled) { svc_queue_line("SVCWATCH USERS"); return; } /* ChanServ still wants the QUIT/NICK feed */
    memset(g_sasl, 0, sizeof g_sasl);
    memset(g_sasl_seen, 0, sizeof g_sasl_seen);
    char line[600];
    irc_build(line, sizeof line, NULL, 0, NULL, "NICK", (const char *[]){C.nick, C.user, C.host}, 3, C.realname);
    svc_queue_line(line);
    svc_queue_line("SVCWATCH USERS");
}

/* --- expiry ([nickserv] expire_days) --------------------------------------------------------------------------------- */

static int expire_exempt(const char *account) {
    for (int i = 0; i < C.n_admins; i++) if (strcasecmp(C.admins[i], account) == 0) return 1;
    for (int i = 0; i < C.n_opers; i++) if (strcasecmp(C.opers[i].account, account) == 0) return 1;
    return accounts_noexpire(&g_acc, account) || accounts_suspended(&g_acc, account, NULL, NULL); /* a suspension can't be waited out */
}

/* Hourly: accounts in use are stamped, an account nobody logged in to for expire_days is dropped (with its ChanServ founder
 * and access entries), and with expire_warn_days its verified address is mailed first. An account with no time on record
 * (an older store) starts its clock now, so upgrading can't expire anything at once. At most 32 drops an hour. */
static void expire_sweep(void) {
    static time_t last;
    time_t now = time(NULL);
    if (C.expire_days <= 0 || now - last < 3600) return;
    last = now;
    nsuser_t *u, *tmp;
    HASH_ITER(hh, g_by_uid, u, tmp) if (u->account[0]) accounts_touch(&g_acc, u->account, (long)now);
    long limit = (long)C.expire_days * 86400, warn = (long)C.expire_warn_days * 86400;
    char dead[32][64], warned[32][64];
    int nd = 0, nw = 0;
    cJSON *rec;
    cJSON_ArrayForEach(rec, g_acc.data) {
        const cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
        const char *name = cJSON_IsString(nm) ? nm->valuestring : rec->string;
        if (!name || expire_exempt(name)) continue;
        long seen = accounts_seen_at(&g_acc, name);
        if (!seen) { accounts_touch(&g_acc, name, (long)now); continue; }
        if (now - seen > limit) { if (nd < 32) snprintf(dead[nd++], sizeof dead[0], "%s", name); }
        else if (warn && C.email_command[0] && now - seen > limit - warn && accounts_expire_warned(&g_acc, name) < seen &&
                 accounts_email_verified(&g_acc, name) && nw < 32)
            snprintf(warned[nw++], sizeof warned[0], "%s", name);
    }
    for (int i = 0; i < nw; i++) {
        long left = (accounts_seen_at(&g_acc, warned[i]) + limit - (long)now + 86399) / 86400;
        char days[16];
        snprintf(days, sizeof days, "%ld", left);
        spawn_email(accounts_email(&g_acc, warned[i]), days, warned[i], "expire");
        accounts_set_expire_warned(&g_acc, warned[i], (long)now);
        log_info("nickserv", "account %s expires in %ld day(s): warning mailed", warned[i], left);
    }
    for (int i = 0; i < nd; i++) {
        accounts_drop(&g_acc, dead[i]);
        int ch = cs_account_dropped(dead[i]);
        log_info("nickserv", "account %s expired after %d days without a login%s", dead[i], C.expire_days,
                 ch ? " (removed from its channels' founder/access lists)" : "");
    }
}

/* Registrations that never verified their email within verify_window: dropped, so the name is free again. Every 5 minutes,
 * whether or not require_email is still on (it may have been turned off with some waiting). */
static void unverified_sweep(void) {
    static time_t last;
    time_t now = time(NULL);
    if (now - last < 300) return;
    last = now;
    char dead[64][64];
    int nd = 0;
    cJSON *rec;
    cJSON_ArrayForEach(rec, g_acc.data) {
        if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rec, "unverified")) || nd >= 64) continue;
        const cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
        const char *name = cJSON_IsString(nm) ? nm->valuestring : rec->string;
        if (name && accounts_created_at(&g_acc, name) + C.verify_window < (long)now) snprintf(dead[nd++], sizeof dead[0], "%s", name);
    }
    for (int i = 0; i < nd; i++) {
        accounts_drop(&g_acc, dead[i]);
        cs_account_dropped(dead[i]);
        log_info("nickserv", "registration %s dropped: its email was never verified", dead[i]);
    }
}

void ns_tick(void) {
    if (!C.enabled) return;
    expire_sweep();
    unverified_sweep();
    time_t now = time(NULL);
    nsuser_t *u, *tmp;
    HASH_ITER(hh, g_by_uid, u, tmp) {
        if (!u->enforce_at || now < u->enforce_at) continue;
        u->enforce_at = 0;
        char guest[32];
        guest_nick(guest, sizeof guest);
        say(u->nick, "You did not identify in time -- changing your nickname.");
        rename_user(u, guest);
    }
    for (int i = 0; i < SASL_SLOTS; i++)
        if (g_sasl[i].cid[0] && now - g_sasl[i].started > 60) OPENSSL_cleanse(&g_sasl[i], sizeof g_sasl[i]); /* abandoned */
    accounts_flush(&g_acc);
}

/* --- commands ------------------------------------------------------------------------------------------------------ */

static const char *skip_words(const char *s, int n) {
    while (n-- > 0) { while (*s == ' ') s++; while (*s && *s != ' ') s++; }
    while (*s == ' ') s++;
    return s;
}

static int owns_nick(const nsuser_t *u, const char *nick) {
    const char *owner = accounts_owner_of_nick(&g_acc, nick);
    return u->account[0] && owner && strcasecmp(u->account, owner) == 0;
}

#define RESET_TTL 3600
#define RESET_SPACING 300

static void cmd_identify(nsuser_t *u, const char *a, const char *b) {
    const char *account = b ? a : u->nick, *password = b ? b : a;
    if (!password) { say(u->nick, "Syntax: IDENTIFY [account] <password>"); return; }
    if (u->account[0]) { say(u->nick, "You are already identified"); return; }
    if (fail_throttled(u->ip)) { say(u->nick, "Too many failed attempts -- wait a minute"); return; }
    const char *owner = accounts_owner_of_nick(&g_acc, account);
    if (accounts_suspended(&g_acc, owner ? owner : account, NULL, NULL)) { say(u->nick, "That account is suspended -- contact a network operator"); return; }
    const char *name = check_password(account, password);
    if (!name) { fail_record(u->ip); say(u->nick, "Invalid account or password"); return; }
    if (accounts_unverified(&g_acc, name)) {
        sayf(u->nick, "Account %s is not active yet: confirm the email it was registered with -- /msg %s VERIFY %s <code from the mail>",
             name, C.nick, name);
        return;
    }
    char keep[64];
    snprintf(keep, sizeof keep, "%s", name);
    login(u->uid, keep);
    sayf(u->nick, "You are now identified for %s", keep);
    last_login_note(u);
    log_info("nickserv", "%s identified as %s", u->nick, keep);
}

static void cmd_regain(nsuser_t *u, const char *nick) {
    if (!u->account[0]) { say(u->nick, "You must IDENTIFY first"); return; }
    if (!owns_nick(u, nick)) { say(u->nick, "You do not own that nickname"); return; }
    nsuser_t *t = user_by_nick(nick);
    if (t == u) { say(u->nick, "You are already using that nickname"); return; }
    if (t && strcmp(t->server, u->server) != 0) { /* its server must let go of it first: disconnect that session */
        wire("KILL", (const char *[]){t->uid}, 1, "REGAIN command used");
        sayf(u->nick, "The session using %s was on another server and has been disconnected -- /NICK %s in a moment", nick, nick);
        return;
    }
    sayf(u->nick, "You have regained %s", nick); /* before the rename: the notice is addressed by the current nick */
    log_info("nickserv", "%s regained %s", u->nick, nick);
    if (t) {
        char guest[32];
        guest_nick(guest, sizeof guest);
        say(t->nick, "This nickname was reclaimed by its owner -- changing your nickname.");
        rename_user(t, guest);
    }
    rename_user(u, nick);
}

static void cmd_resetpass(nsuser_t *u, const char *a, const char *b, const char *c3) {
    if (a && !b) {
        if (!C.email_command[0]) { say(u->nick, "Password reset is not available here (no mail is configured) -- ask a network operator"); return; }
        const char *owner = accounts_owner_of_nick(&g_acc, a);
        const char *email = owner && accounts_email_verified(&g_acc, owner) ? accounts_email(&g_acc, owner) : NULL;
        long pending = owner ? accounts_reset_expires(&g_acc, owner) : 0;
        if (email && !(pending && pending - RESET_TTL + RESET_SPACING > time(NULL))) {
            char code[16];
            crypto_random_hex(code, sizeof code, 5);
            accounts_set_reset(&g_acc, owner, code, (long)time(NULL) + RESET_TTL);
            spawn_email(email, code, owner, "reset");
            log_info("nickserv", "%s requested a password reset for %s", u->nick, owner);
        }
        /* the same reply whether or not the account exists or has a verified address */
        say(u->nick, "If that account has a verified email address, a reset code has been sent -- then "
                     "/msg NickServ RESETPASS <account> <code> <new password> within an hour");
        return;
    }
    if (!a || !b || !c3) { say(u->nick, "Syntax: RESETPASS <account> (mails a code), then RESETPASS <account> <code> <new password>"); return; }
    const char *owner = accounts_owner_of_nick(&g_acc, a);
    if (fail_throttled(u->ip) || !owner || !accounts_check_reset(&g_acc, owner, b)) {
        fail_record(u->ip);
        say(u->nick, "That code is wrong or has expired");
        return;
    }
    if (strlen(c3) < 6 || strlen(c3) >= 200) { say(u->nick, "The new password must be 6-199 characters"); return; }
    char account[64], hash[200];
    snprintf(account, sizeof account, "%s", owner);
    set_password(account, c3, hash, sizeof hash);
    logout_all(account); /* whoever knew the old password is out */
    if (!u->account[0] && !accounts_suspended(&g_acc, account, NULL, NULL)) login(u->uid, account);
    sayf(u->nick, "Password of %s reset%s", account, strcasecmp(u->account, account) == 0 ? " -- you are now identified" : "");
    log_info("nickserv", "%s reset the password of %s by email code", u->nick, account);
}

static void cmd_info(nsuser_t *u, const char *a) {
    const char *who = a ? accounts_owner_of_nick(&g_acc, a) : (u->account[0] ? u->account : NULL);
    if (!who) { say(u->nick, a ? "No such account" : "You are not identified -- INFO <account>"); return; }
    time_t reg = (time_t)accounts_created_at(&g_acc, who);
    char when[64];
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S UTC", gmtime(&reg));
    sayf(u->nick, "Account %s, registered %s", who, when);
    if (accounts_unverified(&g_acc, who)) {
        long left = accounts_created_at(&g_acc, who) + C.verify_window - (long)time(NULL);
        sayf(u->nick, "Not active yet: waiting for its email to be verified (dropped in %ld hour(s) otherwise)", left > 0 ? (left + 3599) / 3600 : 0);
    }
    const char *sby, *sreason;
    if (accounts_suspended(&g_acc, who, &sby, &sreason)) {
        if (is_admin(u)) sayf(u->nick, "Suspended by %s%s%s", sby, sreason[0] ? ": " : "", sreason);
        else say(u->nick, "This account is suspended");
    }
    int self = u->account[0] && strcasecmp(u->account, who) == 0;
    if (!self && !is_admin(u)) return; /* the owner (and services admins) also see the email and grouped nicks */
    const char *ajoin = accounts_ajoin(&g_acc, who);
    if (ajoin && ajoin[0]) sayf(u->nick, "Auto-join: %s", ajoin);
    const char *em = accounts_email(&g_acc, who);
    sayf(u->nick, "Email: %s%s", em ? em : "(none)", em ? (accounts_email_verified(&g_acc, who) ? " (verified)" : " (unverified)") : "");
    int gn = accounts_group_count(&g_acc, who);
    if (gn) {
        char list[300] = "";
        for (int i = 0; i < gn; i++) {
            strncat(list, i ? ", " : "", sizeof list - strlen(list) - 1);
            strncat(list, accounts_group_nick(&g_acc, who, i), sizeof list - strlen(list) - 1);
        }
        sayf(u->nick, "Grouped nicks: %s", list);
    }
    const char *fp = accounts_fingerprint(&g_acc, who);
    if (fp) sayf(u->nick, "Certificate fingerprint: %s", fp);
    long at;
    const char *last = accounts_last_login(&g_acc, who, &at);
    if (last && at) {
        time_t t = (time_t)at;
        char lw[48];
        strftime(lw, sizeof lw, "%b %d %H:%M:%S %Y +0000", gmtime(&t));
        sayf(u->nick, "Last login from: %s on %s", last, lw);
    }
    if (C.expire_days > 0) {
        if (expire_exempt(who)) say(u->nick, "Expires: never");
        else {
            long seen = accounts_seen_at(&g_acc, who), left = seen ? seen + (long)C.expire_days * 86400 - (long)time(NULL) : (long)C.expire_days * 86400;
            sayf(u->nick, "Expires: in %ld day(s) without a login (after %d days unused)", left > 0 ? (left + 86399) / 86400 : 0, C.expire_days);
        }
    }
}

static void cmd_cert(nsuser_t *u, const char *sub) {
    if (!u->account[0]) { say(u->nick, "You must IDENTIFY first"); return; }
    if (sub && strcasecmp(sub, "ADD") == 0) {
        if (!u->certfp[0]) { say(u->nick, "Your connection isn't presenting a TLS client certificate"); return; }
        accounts_set_fingerprint(&g_acc, u->account, u->certfp);
        sayf(u->nick, "Certificate fingerprint %s bound to %s -- SASL EXTERNAL will now log this certificate in", u->certfp, u->account);
    } else if (sub && strcasecmp(sub, "DEL") == 0) {
        accounts_set_fingerprint(&g_acc, u->account, NULL);
        say(u->nick, "Certificate fingerprint removed -- SASL EXTERNAL is now disabled for this account");
    } else if (sub && strcasecmp(sub, "INFO") == 0) {
        const char *fp = accounts_fingerprint(&g_acc, u->account);
        if (fp) sayf(u->nick, "Certificate fingerprint on file: %s", fp);
        else say(u->nick, "No certificate fingerprint is on file for this account");
    } else say(u->nick, "Syntax: CERT ADD|DEL|INFO");
}

/* SUSPEND/UNSUSPEND/NOEXPIRE/ACTIVATE/FDROP/SASET PASSWORD -- services admins ([nickserv] admins, by account) only. */
static void cmd_admin(nsuser_t *u, const char *cmd, const char *a, const char *b, const char *c3, const char *text) {
    if (!is_admin(u)) { say(u->nick, "Permission denied -- that needs a services admin account ([nickserv] admins)"); return; }
    int saset = strcasecmp(cmd, "SASET") == 0;
    const char *name = saset ? b : a;
    if (saset && (!a || strcasecmp(a, "PASSWORD") != 0 || !b || !c3)) { say(u->nick, "Syntax: SASET PASSWORD <account> <new password>"); return; }
    if (!name) { sayf(u->nick, "Syntax: %s <account>%s", cmd, strcasecmp(cmd, "SUSPEND") == 0 ? " [reason]" : strcasecmp(cmd, "NOEXPIRE") == 0 ? " ON|OFF" : ""); return; }
    const char *owner = accounts_owner_of_nick(&g_acc, name);
    if (!owner) { say(u->nick, "No such account"); return; }
    char account[64], m[400];
    snprintf(account, sizeof account, "%s", owner);
    if (strcasecmp(cmd, "SUSPEND") == 0) {
        const char *reason = skip_words(text, 2);
        accounts_set_suspended(&g_acc, account, u->nick, reason);
        logout_all(account);
        snprintf(m, sizeof m, "%s suspended account %s%s%s", u->nick, account, reason[0] ? ": " : "", reason);
    } else if (strcasecmp(cmd, "UNSUSPEND") == 0) {
        if (!accounts_suspended(&g_acc, account, NULL, NULL)) { say(u->nick, "That account is not suspended"); return; }
        accounts_set_suspended(&g_acc, account, NULL, NULL);
        snprintf(m, sizeof m, "%s unsuspended account %s", u->nick, account);
    } else if (strcasecmp(cmd, "ACTIVATE") == 0) {
        if (!accounts_unverified(&g_acc, account)) { say(u->nick, "That account is already active"); return; }
        accounts_set_unverified(&g_acc, account, 0);
        snprintf(m, sizeof m, "%s activated account %s without email verification", u->nick, account);
    } else if (strcasecmp(cmd, "NOEXPIRE") == 0) {
        if (!b || (strcasecmp(b, "ON") != 0 && strcasecmp(b, "OFF") != 0)) { say(u->nick, "Syntax: NOEXPIRE <account> ON|OFF"); return; }
        accounts_set_noexpire(&g_acc, account, strcasecmp(b, "ON") == 0);
        snprintf(m, sizeof m, "%s set NOEXPIRE %s on account %s", u->nick, strcasecmp(b, "ON") == 0 ? "on" : "off", account);
    } else if (strcasecmp(cmd, "FDROP") == 0) {
        logout_all(account);
        accounts_drop(&g_acc, account);
        cs_account_dropped(account);
        snprintf(m, sizeof m, "%s force-dropped account %s", u->nick, account);
    } else {
        if (strlen(c3) < 6 || strlen(c3) >= 200) { say(u->nick, "The new password must be 6-199 characters"); return; }
        char hash[200];
        set_password(account, c3, hash, sizeof hash);
        snprintf(m, sizeof m, "%s used SASET PASSWORD on account %s", u->nick, account);
    }
    say(u->nick, m);
    log_info("nickserv", "%s", m);
}

/* SET AJOIN <#chan[,#chan...]> | OFF -- the channels this account joins at every login. Names are checked here; the hub
 * still applies the usual JOIN checks (bans, +i, +k, +l, +R ...) when it joins them, so nothing is bypassed. */
static void cmd_set_ajoin(nsuser_t *u, const char *list) {
    if (strcasecmp(list, "OFF") == 0) {
        accounts_set_ajoin(&g_acc, u->account, NULL);
        say(u->nick, "Auto-join cleared");
        log_info("nickserv", "%s cleared the AJOIN list of %s", u->nick, u->account);
        return;
    }
    char buf[420], out[AJOIN_LEN] = "";
    snprintf(buf, sizeof buf, "%s", list);
    int n = 0;
    char *save = NULL;
    for (char *ch = strtok_r(buf, ",", &save); ch; ch = strtok_r(NULL, ",", &save)) {
        if (!irc_valid_channel(ch, 50)) { sayf(u->nick, "Not a valid channel name: %s", ch); return; }
        if (++n > AJOIN_MAX) { sayf(u->nick, "At most %d auto-join channels", AJOIN_MAX); return; }
        if (strlen(out) + strlen(ch) + 2 > sizeof out) { say(u->nick, "That channel list is too long"); return; }
        if (out[0]) strcat(out, ",");
        strcat(out, ch);
    }
    accounts_set_ajoin(&g_acc, u->account, out);
    sayf(u->nick, "Auto-join set to %s -- you will join these at every login", out);
    log_info("nickserv", "%s set the AJOIN list of %s to %s", u->nick, u->account, out);
}

/* SET ALWAYS-ON ON|OFF: re-sent to every connection logged in to the account, so it takes effect at once. */
static void cmd_set_always_on(nsuser_t *u, const char *v) {
    int on = !strcasecmp(v, "ON") || !strcasecmp(v, "TRUE") || !strcmp(v, "1");
    if (!on && strcasecmp(v, "OFF") && strcasecmp(v, "FALSE") && strcmp(v, "0")) { say(u->nick, "Syntax: SET ALWAYS-ON ON|OFF"); return; }
    if (on && !C.always_on) { say(u->nick, "Always-on is disabled on this network"); return; }
    char account[64]; /* login() rewrites u->account: never hand it its own buffer */
    snprintf(account, sizeof account, "%s", u->account);
    accounts_set_always_on(&g_acc, account, on);
    nsuser_t *x, *tmp;
    HASH_ITER(hh, g_by_uid, x, tmp) if (strcasecmp(x->account, account) == 0) login(x->uid, account);
    if (on) sayf(u->nick, "Always-on enabled: your nick stays online when you disconnect%s. Reconnect with SASL to resume it.",
                 C.always_on_expire ? "" : " (no expiry)");
    else say(u->nick, "Always-on disabled");
    log_info("nickserv", "%s turned always-on %s for %s", u->nick, on ? "on" : "off", account);
}

/* STATUS / ACC <nick>: is that nick logged in to the account that owns it? For bots. 0 = offline or not registered,
 * 1 = online but not logged in to its owner, 3 = logged in to its owner (2, "recognised by ACCESS", is never given:
 * there is no ACCESS list, CERT logs in outright). STATUS answers Anope's way, ACC Atheme's. */
static void cmd_status(nsuser_t *u, const char *cmd, const char *nick) {
    if (!nick) nick = u->nick;
    nsuser_t *t = user_by_nick(nick);
    const char *owner = accounts_owner_of_nick(&g_acc, nick);
    int level = !t || !owner ? 0 : t->account[0] && strcasecmp(t->account, owner) == 0 ? 3 : 1;
    if (strcasecmp(cmd, "ACC") == 0) sayf(u->nick, "%s ACC %d", t ? t->nick : nick, level);
    else sayf(u->nick, "STATUS %s %d %s", t ? t->nick : nick, level, level == 3 ? owner : "*");
}

static void cmd_listlogins(nsuser_t *u) {
    if (!u->account[0]) { say(u->nick, "You must IDENTIFY first"); return; }
    int n = 0;
    nsuser_t *x, *tmp;
    HASH_ITER(hh, g_by_uid, x, tmp)
        if (strcasecmp(x->account, u->account) == 0) {
            n++;
            sayf(u->nick, "  %s (%s@%s) on %s%s", x->nick, x->user, x->host, x->server, x == u ? " -- this connection" : "");
        }
    sayf(u->nick, "%d connection%s logged in as %s", n, n == 1 ? "" : "s", u->account);
}

struct listchans_ctx { const char *to; int n; };
static void listchans_one(const char *chan, const char *level, void *ctx) {
    struct listchans_ctx *c = ctx;
    c->n++;
    sayf(c->to, "  %-24s %s", chan, level);
}

static void cmd_listchans(nsuser_t *u) {
    if (!u->account[0]) { say(u->nick, "You must IDENTIFY first"); return; }
    struct listchans_ctx c = {u->nick, 0};
    cs_account_chans(u->account, listchans_one, &c);
    if (c.n) sayf(u->nick, "%d channel%s where %s is founder or on the access list (=%s)", c.n, c.n == 1 ? "" : "s", u->account, u->account);
    else sayf(u->nick, "%s is not founder of, or on the access list (=%s) of, any registered channel", u->account, u->account);
}

static const svc_help_t NS_HELP[] = {
    {"REGISTER", "register your nick as an account",
     "Syntax: REGISTER <password> [email]\n"
     "Registers the nick you are using as an account and logs you in to it. Password: 6-199 characters.\n"
     "With an email address, a code is mailed to you -- confirm it with VERIFY. A verified email is what\n"
     "lets you RESETPASS a forgotten password. Some networks need the email: then the account starts\n"
     "working (and logs you in) once you VERIFY the code.\n"
     "Examples: /msg NickServ REGISTER s3cretpass\n"
     "          /msg NickServ REGISTER s3cretpass me@example.org", 0},
    {"IDENTIFY|ID", "log in (ID works too)",
     "Syntax: IDENTIFY [account] <password>\n"
     "Logs you in. Without an account, your current nick is used. Repeated wrong passwords lock you out for\n"
     "a minute. Tip: SASL logs you in while you connect, before you join anything.\n"
     "Examples: /msg NickServ IDENTIFY s3cretpass\n"
     "          /msg NickServ ID alice s3cretpass", 0},
    {"LOGOUT", "log out (you keep your nick)",
     "Syntax: LOGOUT\n"
     "Logs you out of your account. You keep the nick you are using.\n"
     "Example: /msg NickServ LOGOUT", 0},
    {"INFO", "about an account",
     "Syntax: INFO [account]\n"
     "When an account was registered. For your own account also its email, grouped nicks, AJOIN,\n"
     "certificate and last login.\n"
     "Examples: /msg NickServ INFO\n"
     "          /msg NickServ INFO alice", 0},
    {"VERIFY", "confirm your email address",
     "Syntax: VERIFY [account] <code>\n"
     "Confirms your email address with the code REGISTER or SET EMAIL mailed you. On a network that needs an\n"
     "email to register, this is also what makes a new account work: then it needs no login, and the account\n"
     "name can be left out when you use that nick.\n"
     "Example: /msg NickServ VERIFY 4f9a1c2e", 0},
    {"RESETPASS", "forgot your password? reset it by email",
     "Syntax: RESETPASS <account>\n"
     "        RESETPASS <account> <code> <new password>\n"
     "The first form mails a code to the account's verified email address; the second sets a new password\n"
     "with that code (valid for an hour). Every session logged in with the old password is logged out.\n"
     "Examples: /msg NickServ RESETPASS alice\n"
     "          /msg NickServ RESETPASS alice 4f9a1c2e7b30 newpass456", 0},
    {"DROP", "delete your account for good",
     "Syntax: DROP <password>\n"
     "Permanently deletes your account and logs out every session on it. Cannot be undone.\n"
     "Example: /msg NickServ DROP s3cretpass", 0},
    {"SET PASSWORD|PASSWORD", "change your password",
     "Syntax: SET PASSWORD <current> <new>\n"
     "Changes your password (6-199 characters). Needs you logged in.\n"
     "Example: /msg NickServ SET PASSWORD s3cretpass newpass456", 0},
    {"SET EMAIL|EMAIL", "change your email address",
     "Syntax: SET EMAIL <address>\n"
     "Changes your email address; a new code is mailed to it for VERIFY. Needs you logged in.\n"
     "Example: /msg NickServ SET EMAIL me@example.org", 0},
    {"SET AJOIN|AJOIN", "channels to join at every login",
     "Syntax: SET AJOIN <#channel[,#channel...]>\n"
     "        SET AJOIN OFF\n"
     "You join these channels automatically every time you log in. Bans, +i, +k and +l still apply as usual.\n"
     "OFF clears the list. Needs you logged in.\n"
     "Examples: /msg NickServ SET AJOIN #sekurnet,#help\n"
     "          /msg NickServ SET AJOIN OFF", 0},
    {"SET ALWAYS-ON|ALWAYS-ON", "stay online while disconnected",
     "Syntax: SET ALWAYS-ON [ON|OFF]\n"
     "ON keeps your nick online and in your channels when you disconnect; reconnect with SASL to pick it up\n"
     "again. Without ON or OFF it shows whether it is on. Needs you logged in.\n"
     "Example: /msg NickServ SET ALWAYS-ON ON", 0},
    {"CERT|CERT ADD|CERT DEL|CERT INFO", "log in with a TLS client certificate",
     "Syntax: CERT ADD|DEL|INFO\n"
     "  ADD   binds the TLS client certificate you are connected with, so SASL EXTERNAL logs you in\n"
     "        without a password\n"
     "  DEL   removes it (SASL EXTERNAL stops working for the account)\n"
     "  INFO  shows the fingerprint on file\n"
     "Needs you logged in.\n"
     "Example: /msg NickServ CERT ADD", 0},
    {"GROUP", "add your current nick to your account",
     "Syntax: GROUP\n"
     "Adds the nick you are using now to your account (up to 10 nicks), so it is protected and logs in to\n"
     "the same account. Log in first, then change to the nick and GROUP.\n"
     "Example: /nick alice_away  then  /msg NickServ GROUP", 0},
    {"UNGROUP", "remove a nick from your account",
     "Syntax: UNGROUP <nick>\n"
     "Removes a grouped nick from your account. Needs you logged in.\n"
     "Example: /msg NickServ UNGROUP alice_away", 0},
    {"GHOST", "disconnect a session using your nick",
     "Syntax: GHOST <nick>\n"
     "Disconnects whoever is using one of your nicks, e.g. your own stale connection after a dropped link.\n"
     "Needs you logged in.\n"
     "Example: /msg NickServ GHOST alice", 0},
    {"REGAIN", "take your nick back",
     "Syntax: REGAIN <nick>\n"
     "Takes one of your nicks back: whoever has it is renamed to a guest nick and you switch to it.\n"
     "Needs you logged in.\n"
     "Example: /msg NickServ REGAIN alice", 0},
    {"STATUS", "is a nick logged in to its account?",
     "Syntax: STATUS [nick]\n"
     "Reply: STATUS <nick> <0|1|3> <account>. 0 = offline or not registered, 1 = online but not logged in,\n"
     "3 = logged in. Without a nick it is you.\n"
     "Example: /msg NickServ STATUS alice", 0},
    {"ACC", "STATUS in Atheme's format",
     "Syntax: ACC [nick]\n"
     "Same as STATUS, replied as <nick> ACC <0|1|3>, for bots and scripts written for Atheme.\n"
     "Example: /msg NickServ ACC alice", 0},
    {"LISTLOGINS", "connections logged in to your account",
     "Syntax: LISTLOGINS\n"
     "Every connection logged in to your account right now. Needs you logged in.\n"
     "Example: /msg NickServ LISTLOGINS", 0},
    {"LISTCHANS", "channels you found or have access to",
     "Syntax: LISTCHANS\n"
     "Channels where you are founder or on the access list (=account). Needs you logged in.\n"
     "Example: /msg NickServ LISTCHANS", 0},
    {"HELP", "this list, or HELP <command>",
     "Syntax: HELP [command [subcommand]]\n"
     "Examples: /msg NickServ HELP REGISTER\n"
     "          /msg NickServ HELP SET AJOIN\n"
     "          /msg NickServ HELP SET", 0},
    {"SUSPEND", "(admin) lock an account",
     "Syntax: SUSPEND <account> [reason]\n"
     "Locks an account: it is logged out everywhere and cannot log in until UNSUSPEND.\n"
     "Example: /msg NickServ SUSPEND spammer flooding #help", 1},
    {"UNSUSPEND", "(admin) lift a suspension",
     "Syntax: UNSUSPEND <account>\n"
     "Example: /msg NickServ UNSUSPEND spammer", 1},
    {"ACTIVATE", "(admin) activate a registration without its email",
     "Syntax: ACTIVATE <account>\n"
     "With [nickserv] require_email, a new account works once its email is verified. ACTIVATE makes it work\n"
     "now, for someone whose mail never arrives.\n"
     "Example: /msg NickServ ACTIVATE newuser", 1},
    {"NOEXPIRE", "(admin) keep an account from expiring",
     "Syntax: NOEXPIRE <account> ON|OFF\n"
     "With [nickserv] expire_days set, an account nobody logs in to for that long is dropped. ON keeps this one\n"
     "forever. Services admins, [[opers]] accounts and suspended accounts never expire anyway.\n"
     "Example: /msg NickServ NOEXPIRE oldfounder ON", 1},
    {"FDROP", "(admin) delete an account",
     "Syntax: FDROP <account>\n"
     "Deletes an account without its password. Cannot be undone.\n"
     "Example: /msg NickServ FDROP spammer", 1},
    {"SASET PASSWORD|SASET", "(admin) set an account's password",
     "Syntax: SASET PASSWORD <account> <new password>\n"
     "Example: /msg NickServ SASET PASSWORD alice temppass123", 1},
};

static void cmd_help(nsuser_t *u, const char *args) {
    svc_help("NickServ", "  Your account is named after the nick you REGISTER with. Logging in (IDENTIFY, or SASL when you\n"
             "  connect) is what ChanServ, AJOIN and always-on go by.",
             NS_HELP, sizeof NS_HELP / sizeof *NS_HELP, args, is_admin(u), say, u->nick);
}

int ns_privmsg(const char *target, const char *from_nick, const char *text) {
    if (!C.enabled || strcasecmp(target, C.nick) != 0) return 0;
    nsuser_t *u = user_by_nick(from_nick);
    if (!u) return 1; /* not in the feed yet (it arrives before any message can) */
    if (text[0] == '\001') {
        if (strncasecmp(text + 1, "VERSION", 7) == 0)
            sayf(u->nick, "\001VERSION NickServ v%s -- SekurIRCd services, https://github.com/gcanosa/SekurIRCd\001", SERVICES_VERSION);
        return 1;
    }
    char buf[420];
    snprintf(buf, sizeof buf, "%s", text);
    char *save = NULL, *cmd = strtok_r(buf, " ", &save);
    char *a = cmd ? strtok_r(NULL, " ", &save) : NULL, *b = cmd ? strtok_r(NULL, " ", &save) : NULL;
    char *c3 = cmd ? strtok_r(NULL, " ", &save) : NULL;
    if (!cmd || strcasecmp(cmd, "HELP") == 0) cmd_help(u, cmd ? text + strcspn(text, " ") : "");
    else if (strcasecmp(cmd, "REGISTER") == 0) {
        if (!a) say(u->nick, C.require_email ? "Syntax: REGISTER <password> <email>" : "Syntax: REGISTER <password> [email]");
        else if (u->account[0]) say(u->nick, "You are already logged in to an account");
        else if (C.require_email && (!b || !valid_email(b))) say(u->nick, "This network needs an email address to register: REGISTER <password> <email>");
        else {
            const char *why = do_register(u->nick, a, u->ip);
            if (why) say(u->nick, strchr(why, ' ') + 1);
            else if (C.require_email) {
                char keep[64];
                snprintf(keep, sizeof keep, "%s", accounts_display_name(&g_acc, u->nick));
                accounts_set_unverified(&g_acc, keep, 1);
                mail_code(keep, b, C.verify_window);
                sayf(u->nick, "A code was sent to %s. Your account starts working once you /msg %s VERIFY <code> (within %ld hours).",
                     b, C.nick, C.verify_window / 3600);
            } else {
                const char *name = accounts_display_name(&g_acc, u->nick);
                char keep[64];
                snprintf(keep, sizeof keep, "%s", name);
                login(u->uid, keep);
                sayf(u->nick, "Account %s registered -- you are now logged in as it", keep);
                last_login_note(u);
                if (b) begin_email(u->nick, keep, b);
            }
        }
    } else if (strcasecmp(cmd, "IDENTIFY") == 0 || strcasecmp(cmd, "ID") == 0) cmd_identify(u, a, b);
    else if (strcasecmp(cmd, "LOGOUT") == 0) {
        if (!u->account[0]) say(u->nick, "You are not identified");
        else { login(u->uid, NULL); say(u->nick, "You are now logged out"); }
    } else if (strcasecmp(cmd, "GHOST") == 0) {
        nsuser_t *t = a ? user_by_nick(a) : NULL;
        if (!a) say(u->nick, "Syntax: GHOST <nick>");
        else if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!t || t == u) say(u->nick, "No such nick (or that is you)");
        else if (!owns_nick(u, a) && strcasecmp(u->account, t->account) != 0) say(u->nick, "You do not own that nickname");
        else {
            char reason[120];
            snprintf(reason, sizeof reason, "GHOST command used by %s", u->nick);
            wire("KILL", (const char *[]){t->uid}, 1, reason);
            say(u->nick, "Ghost session disconnected");
            log_info("nickserv", "%s ghosted %s", u->nick, a);
        }
    } else if (strcasecmp(cmd, "REGAIN") == 0) {
        if (!a) say(u->nick, "Syntax: REGAIN <nick>");
        else cmd_regain(u, a);
    } else if (strcasecmp(cmd, "RESETPASS") == 0) cmd_resetpass(u, a, b, c3);
    else if (strcasecmp(cmd, "SUSPEND") == 0 || strcasecmp(cmd, "UNSUSPEND") == 0 || strcasecmp(cmd, "FDROP") == 0 || strcasecmp(cmd, "NOEXPIRE") == 0 || strcasecmp(cmd, "ACTIVATE") == 0 ||
             strcasecmp(cmd, "SASET") == 0) cmd_admin(u, cmd, a, b, c3, text);
    else if (strcasecmp(cmd, "INFO") == 0) cmd_info(u, a);
    else if (strcasecmp(cmd, "STATUS") == 0 || strcasecmp(cmd, "ACC") == 0) cmd_status(u, cmd, a);
    else if (strcasecmp(cmd, "LISTLOGINS") == 0) cmd_listlogins(u);
    else if (strcasecmp(cmd, "LISTCHANS") == 0) cmd_listchans(u);
    else if (strcasecmp(cmd, "CERT") == 0) cmd_cert(u, a);
    else if (strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "PASSWORD") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!b || !c3) say(u->nick, "Syntax: SET PASSWORD <current> <new>");
        else if (strlen(c3) < 6 || strlen(c3) >= 200) say(u->nick, "The new password must be 6-199 characters");
        else if (fail_throttled(u->ip)) say(u->nick, "Too many failed attempts -- wait a minute");
        else if (!check_password(u->account, b)) { fail_record(u->ip); say(u->nick, "Current password incorrect"); }
        else {
            char hash[200];
            set_password(u->account, c3, hash, sizeof hash);
            say(u->nick, "Password changed");
            log_info("nickserv", "%s changed the password of %s", u->nick, u->account);
        }
    } else if (strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "EMAIL") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!b) say(u->nick, "Syntax: SET EMAIL <address>");
        else begin_email(u->nick, u->account, b);
    } else if (strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "AJOIN") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!b) say(u->nick, "Syntax: SET AJOIN <#channel[,#channel...]> | SET AJOIN OFF");
        else cmd_set_ajoin(u, b);
    } else if (strcasecmp(cmd, "SET") == 0 && a && strcasecmp(a, "ALWAYS-ON") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!b) sayf(u->nick, "Always-on is %s. Syntax: SET ALWAYS-ON ON|OFF", accounts_always_on(&g_acc, u->account) && C.always_on ? "on" : "off");
        else cmd_set_always_on(u, b);
    } else if (strcasecmp(cmd, "VERIFY") == 0) {
        if (!a) say(u->nick, "Syntax: VERIFY [account] <code>");
        else if (!u->account[0]) { /* a registration waiting for its email: VERIFY <code> (as that nick) or VERIFY <account> <code> */
            const char *name = NULL, *why = activate(b ? a : u->nick, b ? b : a, u->ip, &name);
            if (why) say(u->nick, why);
            else if (strcasecmp(name, u->nick) == 0) {
                char keep[64];
                snprintf(keep, sizeof keep, "%s", name);
                login(u->uid, keep);
                sayf(u->nick, "Email verified -- account %s is active and you are logged in", keep);
                last_login_note(u);
            } else sayf(u->nick, "Email verified -- account %s is active. Log in with /msg %s IDENTIFY %s <password>", name, C.nick, name);
        } else if (fail_throttled(u->ip)) say(u->nick, "Too many attempts -- wait a minute");
        else if (accounts_check_verify(&g_acc, u->account, b ? b : a)) say(u->nick, "Email verified");
        else { fail_record(u->ip); say(u->nick, "That code is wrong or has expired"); }
    } else if (strcasecmp(cmd, "DROP") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!a) say(u->nick, "Syntax: DROP <password> -- permanently deletes your account");
        else if (fail_throttled(u->ip)) say(u->nick, "Too many failed attempts -- wait a minute");
        else if (!check_password(u->account, a)) { fail_record(u->ip); say(u->nick, "Password incorrect -- account NOT dropped"); }
        else {
            char account[64];
            snprintf(account, sizeof account, "%s", u->account);
            logout_all(account);
            accounts_drop(&g_acc, account);
            cs_account_dropped(account);
            say(u->nick, "Your account has been dropped");
            log_info("nickserv", "account %s dropped by %s", account, u->nick);
        }
    } else if (strcasecmp(cmd, "GROUP") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (accounts_group_add(&g_acc, u->account, u->nick) != 0) say(u->nick, "That nick is already registered/grouped, or your group is full (10 nicks)");
        else sayf(u->nick, "%s is now part of account %s", u->nick, u->account);
    } else if (strcasecmp(cmd, "UNGROUP") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!a || accounts_group_del(&g_acc, u->account, a) != 0) say(u->nick, "Syntax: UNGROUP <nick> (a nick in your group)");
        else say(u->nick, "Nick removed from your account");
    } else say(u->nick, "Unknown command -- /msg NickServ HELP");
    OPENSSL_cleanse(buf, sizeof buf);
    return 1;
}
