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
 * What we send: SVSLOGIN <id> <account|*> [regts], SVSNICK <id> <nick>, KILL <id> :reason, SVCSASL <cid> C|D ...,
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

static struct {
    int enabled;
    char nick[64], user[64], host[256], realname[256];
    char store_file[512];
    int backup_count;
    int max_accounts;
    char email_command[512];
    char network[128];
    int network_set; /* [nickserv] network given (else the hub's SVCINFO names it) */
    int enforce_nicks, enforce_grace;
    char admins[NS_MAX_ADMINS][64];
    int n_admins;
} C;

static account_store_t g_acc;

/* --- config ---------------------------------------------------------------------------------------------------- */

static void t_str(toml_table_t *t, const char *k, char *out, size_t outsz) {
    if (!t) return;
    toml_datum_t d = toml_string_in(t, k);
    if (d.ok) { snprintf(out, outsz, "%s", d.u.s); free(d.u.s); }
}
static int t_int(toml_table_t *t, const char *k, int def) {
    if (!t) return def;
    toml_datum_t d = toml_int_in(t, k);
    return d.ok && d.u.i >= INT_MIN && d.u.i <= INT_MAX ? (int)d.u.i : def;
}
static int t_bool(toml_table_t *t, const char *k, int def) {
    if (!t) return def;
    toml_datum_t d = toml_bool_in(t, k);
    return d.ok ? d.u.b : def;
}

/* `rel` resolved against the directory `base` (a file path) lives in. */
static void beside(const char *base, const char *rel, char *out, size_t outsz) {
    if (rel[0] == '/') { snprintf(out, outsz, "%s", rel); return; }
    const char *slash = strrchr(base, '/');
    if (!slash) snprintf(out, outsz, "%s", rel);
    else snprintf(out, outsz, "%.*s/%s", (int)(slash - base), base, rel);
}

static int file_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

int ns_config(toml_table_t *raw, const char *config_path, char *err, size_t errsz) {
    memset(&C, 0, sizeof C);
    toml_table_t *t = toml_table_in(raw, "nickserv");
    C.enabled = t_bool(t, "enabled", 1);
    snprintf(C.nick, sizeof C.nick, "NickServ");
    snprintf(C.user, sizeof C.user, "NickServ");
    snprintf(C.host, sizeof C.host, "services.sekurircd.local");
    toml_table_t *cs = toml_table_in(raw, "chanserv"); /* same services host as ChanServ unless set */
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
    toml_array_t *ad = t ? toml_array_in(t, "admins") : NULL;
    for (int i = 0; ad && i < toml_array_nelem(ad) && C.n_admins < NS_MAX_ADMINS; i++) {
        toml_datum_t d = toml_string_at(ad, i);
        if (d.ok) { snprintf(C.admins[C.n_admins++], sizeof C.admins[0], "%s", d.u.s); free(d.u.s); }
    }
    if (!irc_valid_nick(C.nick, 30)) { snprintf(err, errsz, "[nickserv] nick is not a valid nickname"); return -1; }
    if (C.email_command[0] && C.email_command[0] != '/') { snprintf(err, errsz, "[nickserv] email_command must be an absolute path"); return -1; }

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

/* Log `id` in as `account` (NULL = log out). The hub sets it on the user's own server, which announces it network-wide. */
static void login(const char *id, const char *account) {
    char ts[24];
    snprintf(ts, sizeof ts, "%ld", account ? accounts_created_at(&g_acc, account) : 0L);
    if (account) wire("SVSLOGIN", (const char *[]){id, account, ts}, 3, NULL);
    else wire("SVSLOGIN", (const char *[]){id, "*"}, 2, NULL);
    nsuser_t *u = user_by_uid(id);
    if (u) { snprintf(u->account, sizeof u->account, "%s", account ? account : ""); if (account) u->enforce_at = 0; }
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

/* SVCREGISTER <cid> <ip> <account> <email|*> :<password> */
static void ev_register(irc_message_t *m) {
    if (m->nparams < 5) return;
    const char *cid = m->params[0], *ip = m->params[1], *account = m->params[2], *email = m->params[3], *pw = m->params[4];
    const char *why = do_register(account, pw, ip);
    if (why) {
        char code[40];
        const char *sp = strchr(why, ' ');
        snprintf(code, sizeof code, "%.*s", (int)(sp - why), why);
        wire("SVCREGRESULT", (const char *[]){cid, "FAIL", code, account}, 4, sp + 1);
        return;
    }
    const char *name = accounts_display_name(&g_acc, account);
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
        if (accounts_suspended(&g_acc, name, NULL, NULL) || !stored || scram_verifier_from_string(stored, &s->v) != 0) { sasl_done(s, NULL); return; }
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
    if (name && accounts_suspended(&g_acc, name, NULL, NULL)) name = NULL;
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
        if (acct && accounts_suspended(&g_acc, acct, NULL, NULL)) acct = NULL;
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
    if (!C.enforce_nicks) return;
    const char *owner = accounts_owner_of_nick(&g_acc, u->nick);
    if (!owner || (u->account[0] && strcasecmp(u->account, owner) == 0)) return;
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
    if (renamed) user_set_nick(u, m->params[1]);
    snprintf(u->user, sizeof u->user, "%s", m->params[2]);
    snprintf(u->host, sizeof u->host, "%s", m->params[3]);
    snprintf(u->ip, sizeof u->ip, "%s", m->params[4]);
    snprintf(u->account, sizeof u->account, "%s", strcmp(m->params[5], "*") ? m->params[5] : "");
    snprintf(u->certfp, sizeof u->certfp, "%s", strcmp(m->params[6], "*") ? m->params[6] : "");
    snprintf(u->server, sizeof u->server, "%s", m->params[7]);
    if (renamed) enforce_check(u);
}

int ns_event(irc_message_t *m) {
    if (!C.enabled) return 0;
    const char *c = m->command;
    if (!strcmp(c, "SVCUSER")) { ev_user(m); return 1; }
    if (!strcmp(c, "SVCNICK")) {
        nsuser_t *u = m->nparams >= 2 ? user_by_uid(m->params[0]) : NULL;
        if (u) { user_set_nick(u, m->params[1]); enforce_check(u); }
        return 1;
    }
    if (!strcmp(c, "SVCQUIT")) {
        nsuser_t *u = m->nparams >= 1 ? user_by_uid(m->params[0]) : NULL;
        if (u) user_free(u);
        return 1;
    }
    if (!strcmp(c, "SVCACCOUNT")) {
        nsuser_t *u = m->nparams >= 2 ? user_by_uid(m->params[0]) : NULL;
        if (u) {
            snprintf(u->account, sizeof u->account, "%s", strcmp(m->params[1], "*") ? m->params[1] : "");
            if (u->account[0] && strcasecmp(u->account, u->enforce_owner) == 0) u->enforce_at = 0;
        }
        return 1;
    }
    if (!strcmp(c, "SVCINFO")) { /* SVCINFO <hub> :<network> -- names the network in mails unless [nickserv] network does */
        if (m->nparams >= 2 && !C.network_set) snprintf(C.network, sizeof C.network, "%s", m->params[1]);
        return 1;
    }
    if (!strcmp(c, "SVCSASL")) { ev_sasl(m); return 1; }
    if (!strcmp(c, "SVCREGISTER")) { ev_register(m); return 1; }
    return 0;
}

void ns_session_start(void) {
    if (!C.enabled) return;
    users_clear(); /* the hub resends everyone after SVCWATCH */
    memset(g_sasl, 0, sizeof g_sasl);
    char line[600];
    irc_build(line, sizeof line, NULL, 0, NULL, "NICK", (const char *[]){C.nick, C.user, C.host}, 3, C.realname);
    svc_queue_line(line);
    svc_queue_line("SVCWATCH USERS");
}

void ns_tick(void) {
    if (!C.enabled) return;
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
    char keep[64];
    snprintf(keep, sizeof keep, "%s", name);
    login(u->uid, keep);
    sayf(u->nick, "You are now identified for %s", keep);
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
    const char *sby, *sreason;
    if (accounts_suspended(&g_acc, who, &sby, &sreason)) {
        if (is_admin(u)) sayf(u->nick, "Suspended by %s%s%s", sby, sreason[0] ? ": " : "", sreason);
        else say(u->nick, "This account is suspended");
    }
    int self = u->account[0] && strcasecmp(u->account, who) == 0;
    if (!self && !is_admin(u)) return; /* the owner (and services admins) also see the email and grouped nicks */
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

/* SUSPEND/UNSUSPEND/FDROP/SASET PASSWORD -- services admins ([nickserv] admins, by account) only. */
static void cmd_admin(nsuser_t *u, const char *cmd, const char *a, const char *b, const char *c3, const char *text) {
    if (!is_admin(u)) { say(u->nick, "Permission denied -- that needs a services admin account ([nickserv] admins)"); return; }
    int saset = strcasecmp(cmd, "SASET") == 0;
    const char *name = saset ? b : a;
    if (saset && (!a || strcasecmp(a, "PASSWORD") != 0 || !b || !c3)) { say(u->nick, "Syntax: SASET PASSWORD <account> <new password>"); return; }
    if (!name) { sayf(u->nick, "Syntax: %s <account>%s", cmd, strcasecmp(cmd, "SUSPEND") == 0 ? " [reason]" : ""); return; }
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
    } else if (strcasecmp(cmd, "FDROP") == 0) {
        logout_all(account);
        accounts_drop(&g_acc, account);
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

static void cmd_help(nsuser_t *u) {
    say(u->nick, "Commands: REGISTER <password> [email], IDENTIFY [account] <password>, LOGOUT, INFO [account], "
                 "SET PASSWORD <old> <new>, SET EMAIL <address>, VERIFY <code>, GROUP, UNGROUP <nick>, GHOST <nick>, "
                 "REGAIN <nick>, RESETPASS <account> [<code> <new password>], CERT ADD|DEL|INFO, DROP <password>");
    if (is_admin(u)) say(u->nick, "Admin commands: SUSPEND <account> [reason], UNSUSPEND <account>, FDROP <account>, SASET PASSWORD <account> <new>");
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
    if (!cmd || strcasecmp(cmd, "HELP") == 0) cmd_help(u);
    else if (strcasecmp(cmd, "REGISTER") == 0) {
        if (!a) say(u->nick, "Syntax: REGISTER <password> [email]");
        else if (u->account[0]) say(u->nick, "You are already logged in to an account");
        else {
            const char *why = do_register(u->nick, a, u->ip);
            if (why) say(u->nick, strchr(why, ' ') + 1);
            else {
                const char *name = accounts_display_name(&g_acc, u->nick);
                char keep[64];
                snprintf(keep, sizeof keep, "%s", name);
                login(u->uid, keep);
                sayf(u->nick, "Account %s registered -- you are now logged in as it", keep);
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
    else if (strcasecmp(cmd, "SUSPEND") == 0 || strcasecmp(cmd, "UNSUSPEND") == 0 || strcasecmp(cmd, "FDROP") == 0 ||
             strcasecmp(cmd, "SASET") == 0) cmd_admin(u, cmd, a, b, c3, text);
    else if (strcasecmp(cmd, "INFO") == 0) cmd_info(u, a);
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
    } else if (strcasecmp(cmd, "VERIFY") == 0) {
        if (!u->account[0]) say(u->nick, "You must IDENTIFY first");
        else if (!a) say(u->nick, "Syntax: VERIFY <code>");
        else if (accounts_check_verify(&g_acc, u->account, a)) say(u->nick, "Email verified");
        else say(u->nick, "That code is wrong or has expired");
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
