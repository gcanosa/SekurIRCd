/* ChanServ -- standalone channel-registration service for SekurIRCd (C port).
 *
 * A completely separate process from sekurircd itself (ported from
 * services/chanserv.py): it dials the ircd's [links] hub listener as a
 * leaf, authenticates, introduces one bot nick, and answers PRIVMSGs
 * addressed to it. Nothing in the ircd core is aware this is "services"
 * rather than another node -- see src/link.h's protocol doc. Only
 * sekurircd's `proto`/`crypto` primitives are reused (no server/network
 * internals), same design rule as the Python original.
 *
 * Command set: REGISTER, IDENTIFY, DROP, JOIN/PART (GUARD), SETPASS,
 * TOPICLOCK, INFO, ACCESS, SUCCESSOR, AKICK, SET (MLOCK/DESC/URL/ENTRYMSG),
 * HELP. REGISTER's "must hold ops" check and IDENTIFY/ACCESS's op-grants
 * ride two small link-protocol extensions (WHOISCHAN query, trusted
 * JOIN/PART/MODE/KICK) -- see src/link.h and src/link.c's `lc->service`
 * branch for the hub side.
 */
#include "../src/crypto.h"
#include "../src/log.h"
#include "../src/proto.h"
#include "../src/vendor/cJSON.h"
#include "../src/vendor/toml.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHANSERV_VERSION "1.0.3"
#define RBUF_SZ 8192
#define SBUF_SZ (8192 * 2)
#define MLOCK_LETTERS "niptsm"

typedef struct {
    char link_host[256];
    int link_port;
    char link_name[128];
    char link_password[256];
    char nick[64];
    char user[64];
    char host[256];
    char realname[256];
    char storage_path[512];
    int backup_count;
} app_cfg_t;

static volatile sig_atomic_t g_term = 0;
static void on_term(int sig) { (void)sig; g_term = 1; }

/* --- tiny services.toml loader (schema is small; not worth reusing config.c,
 * which is ircd-specific and lives in a different translation unit tree) --- */

/* Resolve `rel` against the directory `base_path` (a file path) lives in --
 * same convention as sekurircd's own config.c (resolve_against_config_dir),
 * so [storage] path in services.toml can be a plain relative filename that
 * always means "next to this config file", regardless of the daemon's cwd. */
static void resolve_against_dir(const char *base_path, const char *rel, char *out, size_t outsz) {
    if (rel[0] == '\0' || rel[0] == '/') { snprintf(out, outsz, "%s", rel); return; }
    const char *slash = strrchr(base_path, '/');
    char resolved[512];
    if (!slash) snprintf(resolved, sizeof resolved, "%s", rel);
    else {
        size_t dirlen = (size_t)(slash - base_path);
        if (dirlen >= sizeof resolved) dirlen = sizeof resolved - 1;
        char dir[512];
        memcpy(dir, base_path, dirlen);
        dir[dirlen] = '\0';
        snprintf(resolved, sizeof resolved, "%s/%s", dir, rel);
    }
    snprintf(out, outsz, "%s", resolved);
}

static void toml_str(toml_table_t *tab, const char *key, const char *def, char *out, size_t outsz) {
    if (tab && toml_key_exists(tab, key)) {
        toml_datum_t d = toml_string_in(tab, key);
        if (d.ok) { snprintf(out, outsz, "%s", d.u.s); free(d.u.s); return; }
    }
    /* Callers pass the same buffer as both `def` and `out` (the field's
     * current value doubles as its default), and snprintf with overlapping
     * source and destination is undefined behaviour. */
    if (out != def) snprintf(out, outsz, "%s", def);
}
static int toml_int(toml_table_t *tab, const char *key, int def) {
    if (tab && toml_key_exists(tab, key)) {
        toml_datum_t d = toml_int_in(tab, key);
        if (d.ok) return (int)d.u.i;
    }
    return def;
}

static int load_app_config(const char *path, app_cfg_t *cfg, char *errbuf, size_t errbufsz) {
    memset(cfg, 0, sizeof *cfg);
    snprintf(cfg->link_host, sizeof cfg->link_host, "127.0.0.1");
    cfg->link_port = 7000;
    snprintf(cfg->nick, sizeof cfg->nick, "ChanServ");
    snprintf(cfg->user, sizeof cfg->user, "ChanServ");
    snprintf(cfg->host, sizeof cfg->host, "services.sekurircd.local");
    snprintf(cfg->realname, sizeof cfg->realname, "Channel Registration Service");
    snprintf(cfg->storage_path, sizeof cfg->storage_path, "chanserv.json");
    cfg->backup_count = 5;

    FILE *fp = fopen(path, "rb");
    if (!fp) { snprintf(errbuf, errbufsz, "config file not found: %s", path); return -1; }
    char toml_err[256];
    toml_table_t *raw = toml_parse_file(fp, toml_err, sizeof toml_err);
    fclose(fp);
    if (!raw) { snprintf(errbuf, errbufsz, "invalid TOML in %s: %s", path, toml_err); return -1; }

    toml_table_t *link = toml_table_in(raw, "link");
    toml_str(link, "host", cfg->link_host, cfg->link_host, sizeof cfg->link_host);
    cfg->link_port = toml_int(link, "port", cfg->link_port);
    toml_str(link, "name", "", cfg->link_name, sizeof cfg->link_name);
    toml_str(link, "password", "", cfg->link_password, sizeof cfg->link_password);

    toml_table_t *cs = toml_table_in(raw, "chanserv");
    toml_str(cs, "nick", cfg->nick, cfg->nick, sizeof cfg->nick);
    toml_str(cs, "user", cfg->user, cfg->user, sizeof cfg->user);
    toml_str(cs, "host", cfg->host, cfg->host, sizeof cfg->host);
    toml_str(cs, "realname", cfg->realname, cfg->realname, sizeof cfg->realname);

    toml_table_t *st = toml_table_in(raw, "storage");
    toml_str(st, "path", cfg->storage_path, cfg->storage_path, sizeof cfg->storage_path);
    cfg->backup_count = toml_int(st, "backup_count", cfg->backup_count);
    resolve_against_dir(path, cfg->storage_path, cfg->storage_path, sizeof cfg->storage_path);

    toml_free(raw);
    if (!cfg->link_name[0] || !cfg->link_password[0]) {
        snprintf(errbuf, errbufsz, "[link] name and password are required");
        return -1;
    }
    return 0;
}

/* --- channel registration store (cJSON, rotating backups, corruption-safe load) ---
 *
 * Per-channel record: name, pw_hash, registered_at, guard(bool),
 * topiclock(bool), topic(str, TOPICLOCK's last-known-good baseline),
 * access(object: normalized mask -> "v"|"h"|"o"), successor(str, a mask),
 * akick(array of normalized masks), desc/url/entrymsg(str), mlock(str,
 * argument-free channel-mode letters). */

static cJSON *g_store = NULL;
static app_cfg_t g_cfg;

static void store_load(void) {
    for (int gen = 0; gen <= g_cfg.backup_count; gen++) {
        char path[600];
        if (gen == 0) snprintf(path, sizeof path, "%s", g_cfg.storage_path);
        else snprintf(path, sizeof path, "%s.bak%d", g_cfg.storage_path, gen);

        FILE *fp = fopen(path, "rb");
        if (!fp) continue;
        fseek(fp, 0, SEEK_END);
        long len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (len <= 0) { fclose(fp); continue; }
        char *buf = malloc((size_t)len + 1);
        if (!buf) { fclose(fp); continue; }
        size_t rd = fread(buf, 1, (size_t)len, fp);
        fclose(fp);
        buf[rd] = '\0';
        cJSON *parsed = cJSON_Parse(buf);
        free(buf);
        /* Must be a JSON object -- cJSON_Parse happily accepts `[]`, `"x"`,
         * `null`, etc, and later cJSON_AddItemToObject calls on anything
         * else silently lose every key on the next save, quietly deleting
         * every registration. */
        if (parsed && cJSON_IsObject(parsed)) {
            g_store = parsed;
            if (gen > 0) log_warn("chanserv", "live store was missing/corrupt -- loaded backup %s", path);
            return;
        }
        cJSON_Delete(parsed);
        log_warn("chanserv", "%s was corrupt (not a JSON object), trying an older backup", path);
    }
    log_info("chanserv", "no existing store found -- starting with zero registered channels");
    g_store = cJSON_CreateObject();
}

/* Backups rotate at most this often -- store_save() can be marked dirty
 * (and store_flush() called) once a second by something as routine as a
 * single TOPICLOCK channel's /TOPIC, so rotating on every flush only ever
 * covered a few seconds of history, and any flush that landed right after a
 * write failure (see below) copied the SAME truncated file into every
 * backup slot in a matter of seconds. */
#define BACKUP_ROTATE_MIN_INTERVAL 300
static time_t g_last_backup_rotate = 0;

/* Returns 1 on a successful write, 0 if it was abandoned (see the comment
 * above the atomic-rename write below) -- store_flush() uses this so a
 * failed write leaves g_store_dirty set and gets retried on the next tick,
 * instead of the failure being silently accepted as "saved". */
static int store_write_now(void) {
    time_t now = time(NULL);
    if (g_cfg.backup_count > 0 && now - g_last_backup_rotate >= BACKUP_ROTATE_MIN_INTERVAL) {
        g_last_backup_rotate = now;
        char oldest[600];
        snprintf(oldest, sizeof oldest, "%s.bak%d", g_cfg.storage_path, g_cfg.backup_count);
        unlink(oldest);
        for (int i = g_cfg.backup_count - 1; i >= 1; i--) {
            char from[600], to[600];
            snprintf(from, sizeof from, "%s.bak%d", g_cfg.storage_path, i);
            snprintf(to, sizeof to, "%s.bak%d", g_cfg.storage_path, i + 1);
            rename(from, to);
        }
        char to1[600];
        snprintf(to1, sizeof to1, "%s.bak1", g_cfg.storage_path);
        FILE *src = fopen(g_cfg.storage_path, "rb");
        if (src) {
            int fd1 = open(to1, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            FILE *dst = fd1 >= 0 ? fdopen(fd1, "wb") : NULL;
            if (dst) {
                char buf[4096];
                size_t n;
                while ((n = fread(buf, 1, sizeof buf, src)) > 0) fwrite(buf, 1, n, dst);
                fclose(dst);
            } else if (fd1 >= 0) close(fd1);
            fclose(src);
        }
    }
    char *text = cJSON_Print(g_store);
    if (!text) return 0;
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_cfg.storage_path);
    /* 0600 (this store holds per-channel scrypt password hashes), fsync
     * before the atomic rename, and the write is abandoned -- keeping the
     * previous good file on disk -- on any error instead of possibly
     * renaming a truncated file over it (e.g. a full disk). */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { free(text); return 0; }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) { close(fd); free(text); return 0; }
    size_t len = strlen(text);
    int ok = fwrite(text, 1, len, fp) == len && fflush(fp) == 0 && fsync(fd) == 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok) rename(tmp, g_cfg.storage_path);
    else { unlink(tmp); log_error("chanserv", "failed to write %s -- keeping the previous version on disk", g_cfg.storage_path); }
    free(text);
    return ok;
}

/* Debounced. Every state-changing command used to trigger the whole of
 * store_write_now above -- a backup rotation, a full file copy and a complete
 * cJSON_Print of the store -- including on every /TOPIC in a TOPICLOCK
 * channel. Mark dirty instead; run_session's one-second poll flushes it, and
 * both the reconnect loop and shutdown flush unconditionally, so the worst
 * case is losing under a second of changes to a hard kill (and the rotating
 * backups still cover that). */
static int g_store_dirty = 0;
static void store_save(void) { g_store_dirty = 1; }
static void store_flush(void) {
    if (!g_store_dirty) return;
    /* Only clear dirty on a successful write -- a failed one (full disk,
     * permissions) used to be accepted as "saved" and never retried, so
     * whatever changes it lost stayed lost until the next unrelated write
     * happened to succeed and cover them too. */
    if (store_write_now()) g_store_dirty = 0;
}

static cJSON *store_get(const char *chan) {
    char cf[128];
    irc_casefold(cf, sizeof cf, chan);
    return cJSON_GetObjectItemCaseSensitive(g_store, cf);
}

static int rec_bool(cJSON *rec, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(rec, key);
    return v && cJSON_IsBool(v) && cJSON_IsTrue(v);
}
static const char *rec_str(cJSON *rec, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(rec, key);
    return (v && cJSON_IsString(v)) ? v->valuestring : "";
}
static void rec_set_bool(cJSON *rec, const char *key, int val) {
    cJSON_DeleteItemFromObjectCaseSensitive(rec, key);
    cJSON_AddBoolToObject(rec, key, val);
}
static void rec_set_str(cJSON *rec, const char *key, const char *val) {
    cJSON_DeleteItemFromObjectCaseSensitive(rec, key);
    cJSON_AddStringToObject(rec, key, val);
}

/* Expand an ACCESS/AKICK mask into a full nick!user@host glob, same three
 * shorthands as upstream's _normalize_access_mask: a bare host, user@host,
 * or an already-full mask. The host component is never optional -- see
 * that function's docstring for why (spoofable-by-nick-grab otherwise).
 *
 * A leading '=' instead means "services account", passed through verbatim
 * (case folded) -- stable across reconnects/host changes, unlike a hostmask,
 * which under host_masking only ever sees a random per-connection cloak
 * (see link.c's SVCJOIN comment). */
/* Returns 0 and fills `out`, or -1 (out untouched) if the host component is
 * missing or a bare "*" -- e.g. "Bob!*@*", which HELP already promises never
 * grants access but which nothing actually enforced: whoever takes the nick
 * "Bob" matched it (and SUCCESSOR/INFO happily advertise which nick to grab). */
static int normalize_mask(const char *mask, char *out, size_t outsz) {
    if (mask[0] == '=') { snprintf(out, outsz, "=%s", mask + 1); return 0; }
    const char *at = strchr(mask, '@');
    const char *host = at ? at + 1 : mask; /* bare-host form: the whole mask IS the host */
    if (!host[0] || strcmp(host, "*") == 0) return -1;
    if (strchr(mask, '!')) { snprintf(out, outsz, "%s", mask); return 0; }
    if (at) { snprintf(out, outsz, "*!%s", mask); return 0; }
    snprintf(out, outsz, "*!*@%s", mask);
    return 0;
}

static int access_level_rank(const char *level) {
    if (strcmp(level, "v") == 0) return 0;
    if (strcmp(level, "h") == 0) return 1;
    if (strcmp(level, "o") == 0) return 2;
    return -1;
}

/* True if an ACCESS/AKICK entry (hostmask, or "=account") matches this join. */
static int entry_matches(const char *entry, const char *nick, const char *user,
                          const char *host, const char *account, int ident_confirmed) {
    if (entry[0] == '=') return account[0] && account[0] != '*' && strcasecmp(entry + 1, account) == 0;
    return irc_mask_match(nick, user, host, entry, ident_confirmed);
}

/* Strongest access level whose mask/account matches, or "" if none. */
static const char *access_level_for(cJSON *rec, const char *nick, const char *user,
                                     const char *host, const char *account, int ident_confirmed) {
    cJSON *access = cJSON_GetObjectItemCaseSensitive(rec, "access");
    if (!access) return "";
    static char best[2];
    int best_rank = -1;
    cJSON *entry;
    cJSON_ArrayForEach(entry, access) {
        if (!cJSON_IsString(entry)) continue;
        if (!entry_matches(entry->string, nick, user, host, account, ident_confirmed)) continue;
        int r = access_level_rank(entry->valuestring);
        if (r > best_rank) { best_rank = r; snprintf(best, sizeof best, "%s", entry->valuestring); }
    }
    return best_rank >= 0 ? best : "";
}

/* Returns the matching AKICK entry (valid until the store's next mutation),
 * or NULL. `out_ban` (if non-NULL, at least 300 bytes) gets that entry
 * translated into a +b-able mask: "=account" -> "a:account" (the ircd's own
 * extban syntax, see channel.c's channel_mask_hit), anything else passed
 * through as-is (already a full nick!user@host glob). */
static const char *akick_matches(cJSON *rec, const char *nick, const char *user,
                                  const char *host, const char *account, int ident_confirmed,
                                  char *out_ban, size_t out_ban_sz) {
    cJSON *akick = cJSON_GetObjectItemCaseSensitive(rec, "akick");
    if (!akick) return NULL;
    cJSON *m;
    cJSON_ArrayForEach(m, akick) {
        if (!cJSON_IsString(m) || !entry_matches(m->valuestring, nick, user, host, account, ident_confirmed)) continue;
        if (out_ban) {
            if (m->valuestring[0] == '=') snprintf(out_ban, out_ban_sz, "a:%s", m->valuestring + 1);
            else snprintf(out_ban, out_ban_sz, "%s", m->valuestring);
        }
        return m->valuestring;
    }
    return NULL;
}

/* --- link connection to the ircd hub -------------------------------------- */

static int g_fd = -1;
static char g_rbuf[RBUF_SZ];
static size_t g_rbuf_len = 0;
static char g_sbuf[SBUF_SZ];
static size_t g_sbuf_len = 0;
static time_t g_last_activity = 0;

static void queue_line(const char *line) {
    size_t len = strlen(line);
    if (g_sbuf_len + len + 2 >= sizeof g_sbuf) return; /* sendq overflow: drop */
    memcpy(g_sbuf + g_sbuf_len, line, len);
    g_sbuf_len += len;
    g_sbuf[g_sbuf_len++] = '\r';
    g_sbuf[g_sbuf_len++] = '\n';
}

static void flush_sbuf(void) {
    /* Bounded by wall-clock time, not iteration count: if the hub stops
     * reading, this used to loop on EAGAIN + poll(1000) forever, ignoring
     * g_term and the 240s keepalive timeout entirely -- SIGTERM (a normal
     * `--stop` or service restart) never actually stopped the daemon while
     * a write was stuck. */
    time_t deadline = time(NULL) + 5;
    while (g_sbuf_len > 0 && !g_term && time(NULL) < deadline) {
        ssize_t n = write(g_fd, g_sbuf, g_sbuf_len);
        if (n > 0) {
            memmove(g_sbuf, g_sbuf + n, g_sbuf_len - (size_t)n);
            g_sbuf_len -= (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = {.fd = g_fd, .events = POLLOUT};
            poll(&pfd, 1, 200);
        } else {
            break; /* connection is gone; the read side will notice and reconnect */
        }
    }
}

static void reply(const char *to_nick, const char *text) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[700];
    const char *p[] = {to_nick};
    irc_build(line, sizeof line, NULL, 0, prefix, "NOTICE", p, 1, text);
    queue_line(line);
}

static void wire_join(const char *chan) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[300];
    const char *p[] = {chan};
    irc_build(line, sizeof line, NULL, 0, prefix, "JOIN", p, 1, NULL);
    queue_line(line);
}
static void wire_part(const char *chan) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[300];
    const char *p[] = {chan};
    irc_build(line, sizeof line, NULL, 0, prefix, "PART", p, 1, NULL);
    queue_line(line);
}
static void wire_mode(const char *chan, const char *modestring, const char *arg) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[400];
    const char *p[3] = {chan, modestring, arg};
    irc_build(line, sizeof line, NULL, 0, prefix, "MODE", p, arg ? 3 : 2, NULL);
    queue_line(line);
}
static void wire_topic(const char *chan, const char *topic) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[600];
    const char *p[] = {chan};
    irc_build(line, sizeof line, NULL, 0, prefix, "TOPIC", p, 1, topic);
    queue_line(line);
}
static void wire_kick(const char *chan, const char *target, const char *reason) {
    char prefix[320];
    irc_prefix_for(prefix, sizeof prefix, g_cfg.nick, g_cfg.user, g_cfg.host);
    char line[500];
    const char *p[] = {chan, target};
    irc_build(line, sizeof line, NULL, 0, prefix, "KICK", p, 2, reason);
    queue_line(line);
}
static void wire_whoischan(const char *chan, const char *nick) {
    char line[300];
    const char *p[] = {chan, nick};
    irc_build(line, sizeof line, NULL, 0, NULL, "WHOISCHAN", p, 2, NULL);
    queue_line(line);
}
static void wire_whoisuser(const char *nick) {
    char line[300];
    const char *p[] = {nick};
    irc_build(line, sizeof line, NULL, 0, NULL, "WHOISUSER", p, 1, NULL);
    queue_line(line);
}
static void wire_invite(const char *chan, const char *nick) {
    char line[300];
    const char *p[] = {chan, nick};
    irc_build(line, sizeof line, NULL, 0, NULL, "INVITE", p, 2, NULL);
    queue_line(line);
}
static void wire_unban(const char *chan, const char *nick) {
    char line[300];
    const char *p[] = {chan, nick};
    irc_build(line, sizeof line, NULL, 0, NULL, "UNBAN", p, 2, NULL);
    queue_line(line);
}

/* --- commands --------------------------------------------------------------- */

/* Checks the channel is registered and `password` matches; on failure,
 * replies the reason and returns NULL. Shared by every password-gated
 * command below (same role as chanserv.py's ChanServ.check_password). */
/* Failed-password cooldown per nick: each scrypt verify is ~30ms of this
 * single-threaded daemon, so unthrottled guessing is both a brute-force and
 * a CPU-pinning DoS.
 * ponytail: keyed by nick (a nick change evades it); key by account/IP if
 * that's ever seen in practice. */
#define FAIL_SLOTS 64
#define FAIL_COOLDOWN 3
static struct { char nick[64]; time_t until; } g_fails[FAIL_SLOTS];

static int fail_slot(const char *nick, int create) {
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    time_t now = time(NULL);
    int free_slot = -1;
    for (int i = 0; i < FAIL_SLOTS; i++) {
        if (g_fails[i].until > now && strcmp(g_fails[i].nick, cf) == 0) return i;
        if (g_fails[i].until <= now && free_slot < 0) free_slot = i;
    }
    if (!create) return -1;
    if (free_slot < 0) free_slot = (int)(now % FAIL_SLOTS); /* table full: evict something */
    snprintf(g_fails[free_slot].nick, sizeof g_fails[0].nick, "%s", cf);
    return free_slot;
}

static cJSON *check_password(const char *from_nick, const char *chan, const char *password) {
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return NULL; }
    if (fail_slot(from_nick, 0) >= 0) {
        reply(from_nick, "Too many failed password attempts -- wait a few seconds and try again.");
        return NULL;
    }
    const char *hash = rec_str(rec, "pw_hash");
    if (!hash[0] || !crypto_verify_password(password, hash)) {
        g_fails[fail_slot(from_nick, 1)].until = time(NULL) + FAIL_COOLDOWN;
        reply(from_nick, "Password incorrect.");
        log_warn("chanserv", "failed password for %s from %s", chan, from_nick);
        return NULL;
    }
    return rec;
}

/* MLOCK: (re)assert the locked flag modes on the ircd. */
static void apply_mlock(cJSON *rec, const char *chan) {
    const char *mlock = rec_str(rec, "mlock");
    if (!mlock[0]) return;
    char modes[16];
    snprintf(modes, sizeof modes, "+%s", mlock);
    wire_mode(chan, modes, NULL);
}

/* Sessions that IDENTIFY'd (or REGISTERed, or SUCCESSOR CLAIMed) successfully
 * -- ported from Python's ChanServ.identified: (casefolded chan, casefolded
 * nick) pairs, cleared on QUIT, migrated on NICK. Not persisted to the JSON
 * store -- matches real ChanServ semantics ("repeat IDENTIFY every
 * reconnect").
 *
 * QUIT/NICK for a member only ever reaches this daemon for a channel it is
 * GUARD-joined to (see link.c's `lc->service` doc comment) -- but REGISTER,
 * IDENTIFY and CLAIM itself all mark_identified() unconditionally,
 * regardless of GUARD. So for a never-GUARDed channel this set is NOT
 * reliably empty (an earlier version of this comment claimed it was): a
 * founder who REGISTERs, never GUARDs, and quits leaves a TRUE entry here
 * forever, since no QUIT ever arrives to clear it -- permanently blocking a
 * legitimate SUCCESSOR CLAIM. IDENTIFIED_TTL bounds that: an entry older
 * than the TTL is treated as gone (and opportunistically pruned), same
 * practical effect as the "have to reidentify eventually" model every real
 * ChanServ already presents to users, just on a timer instead of only on a
 * QUIT this daemon happens to observe.
 * ponytail: capped at MAX_IDENTIFIED, oldest untouched entries are evicted
 * past that -- bump it if a real deployment ever needs more. */
#define MAX_IDENTIFIED 256
#define IDENTIFIED_TTL (6 * 3600) /* 6h */
static struct { char chan[128]; char nick[64]; time_t at; } g_identified[MAX_IDENTIFIED];
static int g_n_identified;

/* Drops every entry older than IDENTIFIED_TTL. O(n), called from the few
 * paths that read the table -- n is capped at MAX_IDENTIFIED (256), so this
 * is cheap even on every PRIVMSG to ChanServ. */
static void prune_identified(void) {
    time_t now = time(NULL);
    int w = 0;
    for (int i = 0; i < g_n_identified; i++)
        if (now - g_identified[i].at < IDENTIFIED_TTL) g_identified[w++] = g_identified[i];
    g_n_identified = w;
}

static int is_identified(const char *chan, const char *nick) {
    prune_identified();
    char cf_c[128], cf_n[64];
    irc_casefold(cf_c, sizeof cf_c, chan);
    irc_casefold(cf_n, sizeof cf_n, nick);
    for (int i = 0; i < g_n_identified; i++)
        if (strcmp(g_identified[i].chan, cf_c) == 0 && strcmp(g_identified[i].nick, cf_n) == 0) return 1;
    return 0;
}

static void mark_identified(const char *chan, const char *nick) {
    if (is_identified(chan, nick)) return; /* already prunes */
    if (g_n_identified >= MAX_IDENTIFIED) {
        /* Table full: evict the oldest entry instead of silently dropping
         * this one. Without this, once 256 (chan, nick) pairs were live --
         * easily reached over a long uptime, or by anyone registering ~256
         * throwaway channels (they're op in each of their own, no per-user
         * cap) -- no further IDENTIFY was ever remembered, so any_identified()
         * kept reporting "nobody identified" even while a real founder was
         * actively in the channel, letting a designated successor CLAIM out
         * from under them. */
        memmove(&g_identified[0], &g_identified[1], (size_t)(MAX_IDENTIFIED - 1) * sizeof g_identified[0]);
        g_n_identified = MAX_IDENTIFIED - 1;
    }
    irc_casefold(g_identified[g_n_identified].chan, sizeof g_identified[0].chan, chan);
    irc_casefold(g_identified[g_n_identified].nick, sizeof g_identified[0].nick, nick);
    g_identified[g_n_identified].at = time(NULL);
    g_n_identified++;
}

/* DROP: nothing should still read as "identified" for a channel that no
 * longer exists -- a stale entry from before this daemon reset (or simply
 * never got a QUIT for, see is_identified's doc) would otherwise linger
 * forever and could confuse a future re-registration of the same name. */
static void clear_identified_chan(const char *chan) {
    char cf_c[128];
    irc_casefold(cf_c, sizeof cf_c, chan);
    int w = 0;
    for (int i = 0; i < g_n_identified; i++)
        if (strcmp(g_identified[i].chan, cf_c) != 0) g_identified[w++] = g_identified[i];
    g_n_identified = w;
}

static int any_identified(const char *chan) {
    prune_identified();
    char cf_c[128];
    irc_casefold(cf_c, sizeof cf_c, chan);
    for (int i = 0; i < g_n_identified; i++)
        if (strcmp(g_identified[i].chan, cf_c) == 0) return 1;
    return 0;
}

/* QUIT: drop every (chan, nick) entry for the nick that just disconnected. */
static void clear_identified_nick(const char *nick) {
    char cf_n[64];
    irc_casefold(cf_n, sizeof cf_n, nick);
    int w = 0;
    for (int i = 0; i < g_n_identified; i++)
        if (strcmp(g_identified[i].nick, cf_n) != 0) g_identified[w++] = g_identified[i];
    g_n_identified = w;
}

/* NICK: identified status follows the session across a nick change, same as
 * Python's _on_nick_change. */
static void rename_identified_nick(const char *old_nick, const char *new_nick) {
    char cf_old[64];
    irc_casefold(cf_old, sizeof cf_old, old_nick);
    for (int i = 0; i < g_n_identified; i++)
        if (strcmp(g_identified[i].nick, cf_old) == 0)
            irc_casefold(g_identified[i].nick, sizeof g_identified[0].nick, new_nick);
}

/* A REGISTER awaiting the hub's WHOISCHANREPLY (is the requester actually
 * an op there?) -- one slot at a time, ponytail: this is a low-traffic
 * service; a second REGISTER while one is pending just gets "try again". */
static struct {
    int active;
    char nick[64];
    char chan[128];
    char password[128];
    time_t sent_at;
} g_pending_register;

/* A SUCCESSOR CLAIM awaiting the hub's WHOISUSERREPLY (the claimant's real
 * identity) -- same one-slot-at-a-time shape as g_pending_register above. */
static struct {
    int active;
    char nick[64];
    char chan[128];
    char new_password[128];
    time_t sent_at;
} g_pending_claim;

static void cmd_register(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !password) { reply(from_nick, "Syntax: REGISTER <#channel> <password>"); return; }
    if (!irc_valid_channel(chan, 50)) { reply(from_nick, "That doesn't look like a valid channel name."); return; }
    if (store_get(chan)) { reply(from_nick, "That channel is already registered."); return; }
    if (g_pending_register.active) { reply(from_nick, "Busy processing another REGISTER -- try again shortly."); return; }

    g_pending_register.active = 1;
    snprintf(g_pending_register.nick, sizeof g_pending_register.nick, "%s", from_nick);
    snprintf(g_pending_register.chan, sizeof g_pending_register.chan, "%s", chan);
    snprintf(g_pending_register.password, sizeof g_pending_register.password, "%s", password);
    g_pending_register.sent_at = time(NULL);
    wire_whoischan(chan, from_nick);
}

static void finish_register(void) {
    const char *from_nick = g_pending_register.nick;
    const char *chan = g_pending_register.chan;
    char hash[256];
    if (crypto_hash_password(g_pending_register.password, hash, sizeof hash) != 0) {
        reply(from_nick, "Internal error hashing password -- try again.");
        return;
    }
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", chan);
    cJSON_AddStringToObject(rec, "pw_hash", hash);
    cJSON_AddNumberToObject(rec, "registered_at", (double)time(NULL));
    char cf[128];
    irc_casefold(cf, sizeof cf, chan);
    cJSON_AddItemToObject(g_store, cf, rec);
    store_save();
    mark_identified(chan, from_nick);

    /* Trusted MODE (see link.c's `lc->service` branch, same as IDENTIFY's
     * +o) -- marks the channel +r (registered with services) on the ircd
     * side. Applies even if ChanServ isn't sitting in the channel, but only
     * if the channel currently exists there (i.e. someone has JOINed it). */
    wire_mode(chan, "+r", NULL);

    char msg[300];
    snprintf(msg, sizeof msg, "%s is now registered. Use IDENTIFY to reclaim access after a reconnect.", chan);
    reply(from_nick, msg);
    log_info("chanserv", "%s registered %s", from_nick, chan);
}

static void cmd_identify(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !password) { reply(from_nick, "Syntax: IDENTIFY <#channel> <password>"); return; }
    if (!check_password(from_nick, chan, password)) return;
    mark_identified(chan, from_nick);
    /* Trusted MODE (see link.c's `lc->service` branch) -- applies even if
     * ChanServ itself isn't sitting in the channel (no GUARD needed). */
    wire_mode(chan, "+o", from_nick);
    reply(from_nick, "Password correct -- you have been re-opped.");
}

static void cmd_drop(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !password) { reply(from_nick, "Syntax: DROP <#channel> <password>"); return; }
    cJSON *rec = check_password(from_nick, chan, password);
    if (!rec) return;
    wire_mode(chan, "-r", NULL);
    if (rec_bool(rec, "guard")) wire_part(chan);
    char cf[128];
    irc_casefold(cf, sizeof cf, chan);
    cJSON_DeleteItemFromObjectCaseSensitive(g_store, cf);
    clear_identified_chan(chan);
    store_save();
    reply(from_nick, "Channel registration dropped.");
    log_info("chanserv", "%s dropped %s", from_nick, chan);
}

static void cmd_guard_join(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !password) { reply(from_nick, "Syntax: JOIN <#channel> <password>"); return; }
    cJSON *rec = check_password(from_nick, chan, password);
    if (!rec) return;
    rec_set_bool(rec, "guard", 1);
    store_save();
    wire_join(chan);
    reply(from_nick, "ChanServ will now stay joined (rejoining after a restart) -- PART to undo.");
}

static void cmd_guard_part(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !password) { reply(from_nick, "Syntax: PART <#channel> <password>"); return; }
    cJSON *rec = check_password(from_nick, chan, password);
    if (!rec) return;
    rec_set_bool(rec, "guard", 0);
    store_save();
    wire_part(chan);
    reply(from_nick, "ChanServ has left the channel.");
}

static void cmd_setpass(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *old_password = strtok_r(NULL, " ", &save);
    char *new_password = strtok_r(NULL, " ", &save);
    if (!chan || !old_password || !new_password || !new_password[0]) {
        reply(from_nick, "Syntax: SETPASS <#channel> <old-password> <new-password>");
        return;
    }
    cJSON *rec = check_password(from_nick, chan, old_password);
    if (!rec) return;
    char hash[256];
    if (crypto_hash_password(new_password, hash, sizeof hash) != 0) { reply(from_nick, "Internal error -- try again."); return; }
    rec_set_str(rec, "pw_hash", hash);
    store_save();
    reply(from_nick, "Password changed.");
}

static void cmd_topiclock(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *setting = strtok_r(NULL, " ", &save);
    char *password = strtok_r(NULL, " ", &save);
    if (!chan || !setting || !password || (strcasecmp(setting, "on") != 0 && strcasecmp(setting, "off") != 0)) {
        reply(from_nick, "Syntax: TOPICLOCK <#channel> ON|OFF <password>");
        return;
    }
    cJSON *rec = check_password(from_nick, chan, password);
    if (!rec) return;
    int on = strcasecmp(setting, "on") == 0;
    rec_set_bool(rec, "topiclock", on);
    store_save();
    char msg[200];
    snprintf(msg, sizeof msg, "TOPICLOCK for %s is now %s", chan, on ? "ON" : "OFF");
    reply(from_nick, msg);
}

static void cmd_info(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    if (!chan) { reply(from_nick, "Syntax: INFO <#channel>"); return; }
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; }
    cJSON *when = cJSON_GetObjectItemCaseSensitive(rec, "registered_at");
    time_t t = when && cJSON_IsNumber(when) ? (time_t)when->valuedouble : 0;
    char tbuf[64] = "unknown";
    if (t) { struct tm tmv; gmtime_r(&t, &tmv); strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S UTC", &tmv); }
    char msg[300];
    snprintf(msg, sizeof msg, "%s: registered %s, GUARD %s, TOPICLOCK %s", chan, tbuf,
             rec_bool(rec, "guard") ? "on" : "off", rec_bool(rec, "topiclock") ? "on" : "off");
    reply(from_nick, msg);
    if (rec_str(rec, "desc")[0]) { snprintf(msg, sizeof msg, "  Description: %s", rec_str(rec, "desc")); reply(from_nick, msg); }
    if (rec_str(rec, "url")[0]) { snprintf(msg, sizeof msg, "  URL: %s", rec_str(rec, "url")); reply(from_nick, msg); }
    if (rec_str(rec, "mlock")[0]) { snprintf(msg, sizeof msg, "  MLOCK: +%s", rec_str(rec, "mlock")); reply(from_nick, msg); }
    if (rec_str(rec, "successor")[0]) { snprintf(msg, sizeof msg, "  Successor: %s", rec_str(rec, "successor")); reply(from_nick, msg); }
}

static void cmd_access(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *sub = strtok_r(NULL, " ", &save);
    if (!chan || !sub) { reply(from_nick, "Syntax: ACCESS <#channel> ADD|DEL|LIST ..."); return; }
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; }

    if (strcasecmp(sub, "LIST") == 0) {
        cJSON *access = cJSON_GetObjectItemCaseSensitive(rec, "access");
        if (!access || !cJSON_GetArraySize(access)) { reply(from_nick, "No access entries for that channel."); return; }
        char header[200]; snprintf(header, sizeof header, "Access list for %s:", chan);
        reply(from_nick, header);
        cJSON *entry;
        cJSON_ArrayForEach(entry, access) {
            if (!cJSON_IsString(entry)) continue; /* a hand-edited/corrupt store: valuestring is NULL for a non-string node */
            char line[300];
            snprintf(line, sizeof line, "  %s -- %s", entry->string, entry->valuestring);
            reply(from_nick, line);
        }
    } else if (strcasecmp(sub, "ADD") == 0) {
        char *mask = strtok_r(NULL, " ", &save);
        char *level = strtok_r(NULL, " ", &save);
        char *password = strtok_r(NULL, " ", &save);
        if (!mask || !level || !password) { reply(from_nick, "Syntax: ACCESS <#channel> ADD <mask> <v|h|o> <password>"); return; }
        char levelbuf[2]; levelbuf[0] = (char)tolower((unsigned char)level[0]); levelbuf[1] = '\0';
        if (access_level_rank(levelbuf) < 0) { reply(from_nick, "Level must be one of: v h o"); return; }
        if (!check_password(from_nick, chan, password)) return;
        char norm[300];
        if (normalize_mask(mask, norm, sizeof norm) != 0) { reply(from_nick, "That mask needs a host (a nick alone never grants access) -- see HELP ACCESS"); return; }
        cJSON *access = cJSON_GetObjectItemCaseSensitive(rec, "access");
        if (!access) { access = cJSON_CreateObject(); cJSON_AddItemToObject(rec, "access", access); }
        cJSON_DeleteItemFromObjectCaseSensitive(access, norm);
        cJSON_AddStringToObject(access, norm, levelbuf);
        store_save();
        char msg[300]; snprintf(msg, sizeof msg, "%s now has %s access on %s", norm, levelbuf, chan);
        reply(from_nick, msg);
    } else if (strcasecmp(sub, "DEL") == 0) {
        char *mask = strtok_r(NULL, " ", &save);
        char *password = strtok_r(NULL, " ", &save);
        if (!mask || !password) { reply(from_nick, "Syntax: ACCESS <#channel> DEL <mask> <password>"); return; }
        if (!check_password(from_nick, chan, password)) return;
        char norm[300];
        if (normalize_mask(mask, norm, sizeof norm) != 0) { reply(from_nick, "That mask needs a host -- see HELP ACCESS"); return; }
        cJSON *access = cJSON_GetObjectItemCaseSensitive(rec, "access");
        int existed = access && cJSON_HasObjectItem(access, norm);
        /* Case-insensitive delete to match cJSON_HasObjectItem's own
         * case-insensitive lookup above -- the CaseSensitive delete used to
         * report "removed" for an entry whose stored casing didn't exactly
         * match `norm`, while actually leaving it in place. */
        if (existed) cJSON_DeleteItemFromObject(access, norm);
        store_save();
        char msg[300];
        snprintf(msg, sizeof msg, existed ? "%s removed from %s's access list" : "%s is not on %s's access list", norm, chan);
        reply(from_nick, msg);
    } else {
        reply(from_nick, "Syntax: ACCESS <#channel> ADD|DEL|LIST ...");
    }
}

static void cmd_akick(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *sub = strtok_r(NULL, " ", &save);
    if (!chan || !sub) { reply(from_nick, "Syntax: AKICK <#channel> ADD|DEL|LIST ..."); return; }
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; }

    if (strcasecmp(sub, "LIST") == 0) {
        cJSON *akick = cJSON_GetObjectItemCaseSensitive(rec, "akick");
        if (!akick || !cJSON_GetArraySize(akick)) { reply(from_nick, "No AKICK entries for that channel."); return; }
        char header[200]; snprintf(header, sizeof header, "AKICK list for %s:", chan);
        reply(from_nick, header);
        cJSON *m;
        cJSON_ArrayForEach(m, akick) {
            if (!cJSON_IsString(m)) continue; /* see the ACCESS LIST note above */
            char line[300]; snprintf(line, sizeof line, "  %s", m->valuestring);
            reply(from_nick, line);
        }
    } else if (strcasecmp(sub, "ADD") == 0) {
        char *mask = strtok_r(NULL, " ", &save);
        char *password = strtok_r(NULL, " ", &save);
        if (!mask || !password) { reply(from_nick, "Syntax: AKICK <#channel> ADD <mask> <password>"); return; }
        if (!check_password(from_nick, chan, password)) return;
        char norm[300];
        if (normalize_mask(mask, norm, sizeof norm) != 0) { reply(from_nick, "That mask needs a host -- see HELP AKICK"); return; }
        cJSON *akick = cJSON_GetObjectItemCaseSensitive(rec, "akick");
        if (!akick) { akick = cJSON_CreateArray(); cJSON_AddItemToObject(rec, "akick", akick); }
        cJSON_AddItemToArray(akick, cJSON_CreateString(norm));
        store_save();
        char msg[300]; snprintf(msg, sizeof msg, "%s added to %s's AKICK list", norm, chan);
        reply(from_nick, msg);
    } else if (strcasecmp(sub, "DEL") == 0) {
        char *mask = strtok_r(NULL, " ", &save);
        char *password = strtok_r(NULL, " ", &save);
        if (!mask || !password) { reply(from_nick, "Syntax: AKICK <#channel> DEL <mask> <password>"); return; }
        if (!check_password(from_nick, chan, password)) return;
        char norm[300];
        if (normalize_mask(mask, norm, sizeof norm) != 0) { reply(from_nick, "That mask needs a host -- see HELP AKICK"); return; }
        cJSON *akick = cJSON_GetObjectItemCaseSensitive(rec, "akick");
        int removed = 0;
        if (akick) {
            int idx = 0;
            cJSON *m;
            cJSON_ArrayForEach(m, akick) {
                if (cJSON_IsString(m) && strcasecmp(m->valuestring, norm) == 0) { cJSON_DeleteItemFromArray(akick, idx); removed = 1; break; }
                idx++;
            }
        }
        store_save();
        char msg[300];
        snprintf(msg, sizeof msg, removed ? "%s removed from %s's AKICK list" : "%s is not on %s's AKICK list", norm, chan);
        reply(from_nick, msg);
    } else {
        reply(from_nick, "Syntax: AKICK <#channel> ADD|DEL|LIST ...");
    }
}

static void cmd_successor(const char *from_nick, const char *prefix, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *sub = strtok_r(NULL, " ", &save);
    if (!chan || !sub) { reply(from_nick, "Syntax: SUCCESSOR <#channel> SET <mask> <password> | CLAIM <new-password>"); return; }
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; }

    if (strcasecmp(sub, "SET") == 0) {
        char *mask = strtok_r(NULL, " ", &save);
        char *password = strtok_r(NULL, " ", &save);
        if (!mask || !password) { reply(from_nick, "Syntax: SUCCESSOR <#channel> SET <mask> <password>"); return; }
        if (!check_password(from_nick, chan, password)) return;
        char norm[300];
        if (normalize_mask(mask, norm, sizeof norm) != 0) { reply(from_nick, "That mask needs a host -- see HELP SUCCESSOR"); return; }
        rec_set_str(rec, "successor", norm);
        store_save();
        char msg[300]; snprintf(msg, sizeof msg, "%s may now CLAIM %s if nobody is IDENTIFY'd for it", norm, chan);
        reply(from_nick, msg);
    } else if (strcasecmp(sub, "CLAIM") == 0) {
        char *new_password = strtok_r(NULL, " ", &save);
        if (!new_password || !new_password[0]) { reply(from_nick, "Syntax: SUCCESSOR <#channel> CLAIM <new-password>"); return; }
        const char *successor = rec_str(rec, "successor");
        if (!successor[0]) { reply(from_nick, "That channel has no designated successor."); return; }
        if (any_identified(chan)) {
            reply(from_nick, "That channel still has an identified founder -- CLAIM refused.");
            return;
        }
        if (g_pending_claim.active) { reply(from_nick, "Busy processing another CLAIM -- try again shortly."); return; }
        /* The requester's REAL identity (realhost/account/ident_confirmed),
         * not `prefix` (the PRIVMSG sender prefix, which is the CLOAKED
         * display host under host_masking -- a hostmask successor could
         * then never match at all) -- fetched the same way REGISTER checks
         * op status: an async WHOISUSER query to the hub, finished in
         * finish_claim() once WHOISUSERREPLY comes back. See link.c. */
        g_pending_claim.active = 1;
        snprintf(g_pending_claim.nick, sizeof g_pending_claim.nick, "%s", from_nick);
        snprintf(g_pending_claim.chan, sizeof g_pending_claim.chan, "%s", chan);
        snprintf(g_pending_claim.new_password, sizeof g_pending_claim.new_password, "%s", new_password);
        g_pending_claim.sent_at = time(NULL);
        wire_whoisuser(from_nick);
    } else {
        reply(from_nick, "Syntax: SUCCESSOR <#channel> SET <mask> <password> | CLAIM <new-password>");
    }
}

static void finish_claim(const char *user, const char *host, const char *account, int ident_confirmed) {
    const char *from_nick = g_pending_claim.nick;
    const char *chan = g_pending_claim.chan;
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; } /* DROPped while the query was in flight */
    const char *successor = rec_str(rec, "successor");
    if (!successor[0]) { reply(from_nick, "That channel has no designated successor."); return; }
    if (any_identified(chan)) { reply(from_nick, "That channel still has an identified founder -- CLAIM refused."); return; }
    /* entry_matches (not irc_mask_match directly): handles both a
     * nick!user@host glob AND the "=account" form the same way ACCESS/AKICK
     * do -- a "=account" successor went through irc_mask_match before,
     * which doesn't know that syntax, so it could never match anything. */
    if (!entry_matches(successor, from_nick, user, host, account, ident_confirmed)) {
        reply(from_nick, "Your current connection doesn't match the designated successor mask.");
        return;
    }
    char hash[256];
    if (crypto_hash_password(g_pending_claim.new_password, hash, sizeof hash) != 0) {
        reply(from_nick, "Internal error hashing password -- try again.");
        return;
    }
    rec_set_str(rec, "pw_hash", hash);
    rec_set_str(rec, "successor", "");
    store_save();
    mark_identified(chan, from_nick);
    wire_mode(chan, "+o", from_nick);
    char msg[300]; snprintf(msg, sizeof msg, "You are now founder of %s -- SETPASS/ACCESS as needed", chan);
    reply(from_nick, msg);
    log_info("chanserv", "%s claimed founder of %s via SUCCESSOR", from_nick, chan);
}

static void cmd_set(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *option = strtok_r(NULL, " ", &save);
    if (!chan || !option) { reply(from_nick, "Syntax: SET <#channel> MLOCK|DESC|URL|ENTRYMSG <text> <password>"); return; }
    cJSON *rec = store_get(chan);
    if (!rec) { reply(from_nick, "That channel isn't registered."); return; }
    char optlower[16] = ""; /* strtok_r can't hand us an empty token today, but the
                              * loop below leaves this uninitialized if it ever does */
    for (int i = 0; option[i] && i < 15; i++) optlower[i] = (char)tolower((unsigned char)option[i]), optlower[i + 1] = '\0';
    if (strcmp(optlower, "mlock") != 0 && strcmp(optlower, "desc") != 0 &&
        strcmp(optlower, "url") != 0 && strcmp(optlower, "entrymsg") != 0) {
        reply(from_nick, "Syntax: SET <#channel> MLOCK|DESC|URL|ENTRYMSG <text> <password>");
        return;
    }
    /* Remainder is "[value ]password" -- split on the LAST space so a
     * value may itself contain spaces (same as upstream's rpartition). */
    char *rest = save;
    if (!rest || !*rest) { reply(from_nick, "Syntax: SET <#channel> MLOCK|DESC|URL|ENTRYMSG <text> <password>"); return; }
    char *last_space = strrchr(rest, ' ');
    char value[300] = "", password[128];
    if (last_space) {
        size_t vl = (size_t)(last_space - rest);
        if (vl >= sizeof value) vl = sizeof value - 1;
        memcpy(value, rest, vl); value[vl] = '\0';
        snprintf(password, sizeof password, "%s", last_space + 1);
    } else {
        snprintf(password, sizeof password, "%s", rest);
    }
    if (strcmp(optlower, "mlock") == 0) {
        for (const char *p = value; *p; p++) {
            if (!strchr(MLOCK_LETTERS, *p)) {
                char msg[100]; snprintf(msg, sizeof msg, "MLOCK letters must be from: %s", MLOCK_LETTERS);
                reply(from_nick, msg);
                return;
            }
        }
    }
    if (!check_password(from_nick, chan, password)) return;
    rec_set_str(rec, optlower, value);
    store_save();
    if (strcmp(optlower, "mlock") == 0) apply_mlock(rec, rec_str(rec, "name"));
    char msg[350];
    if (value[0]) snprintf(msg, sizeof msg, "%s for %s is now: '%s'", option, chan, value);
    else snprintf(msg, sizeof msg, "%s for %s cleared", option, chan);
    reply(from_nick, msg);
}

/* OP/DEOP/VOICE/DEVOICE/HALFOP/DEHALFOP <#channel> [nick] <password> --
 * nick defaults to the caller. Password-gated like every other command
 * here (same as SETPASS/ACCESS/etc); there's no ACCESS-level shortcut,
 * matching this daemon's existing "always the channel password" design. */
static void cmd_chanmode_one(const char *from_nick, char *args, const char *name, char sign, char letter) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *a = strtok_r(NULL, " ", &save);
    char *b = strtok_r(NULL, " ", &save);
    if (!chan || !a) {
        char m[100]; snprintf(m, sizeof m, "Syntax: %s <#channel> [nick] <password>", name);
        reply(from_nick, m);
        return;
    }
    const char *target = b ? a : from_nick;
    const char *password = b ? b : a;
    if (!check_password(from_nick, chan, password)) return;
    char modestring[3] = {sign, letter, '\0'};
    wire_mode(chan, modestring, target);
    char msg[200];
    snprintf(msg, sizeof msg, "%s: %c%c %s", chan, sign, letter, target);
    reply(from_nick, msg);
}

static void cmd_svc_invite(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *a = strtok_r(NULL, " ", &save);
    char *b = strtok_r(NULL, " ", &save);
    if (!chan || !a) { reply(from_nick, "Syntax: INVITE <#channel> [nick] <password>"); return; }
    const char *target = b ? a : from_nick;
    const char *password = b ? b : a;
    if (!check_password(from_nick, chan, password)) return;
    wire_invite(chan, target);
    char msg[200]; snprintf(msg, sizeof msg, "Invited %s to %s", target, chan);
    reply(from_nick, msg);
}

static void cmd_svc_unban(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *a = strtok_r(NULL, " ", &save);
    char *b = strtok_r(NULL, " ", &save);
    if (!chan || !a) { reply(from_nick, "Syntax: UNBAN <#channel> [nick] <password>"); return; }
    const char *target = b ? a : from_nick;
    const char *password = b ? b : a;
    if (!check_password(from_nick, chan, password)) return;
    wire_unban(chan, target);
    char msg[200]; snprintf(msg, sizeof msg, "Removed any ban matching %s on %s", target, chan);
    reply(from_nick, msg);
}

static void cmd_svc_kick(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    char *target = strtok_r(NULL, " ", &save);
    if (!chan || !target || !save || !*save) { reply(from_nick, "Syntax: KICK <#channel> <nick> [reason] <password>"); return; }
    /* Remainder is "[reason ]password" -- split on the LAST space, same as
     * cmd_set's value/password split, so a reason may itself contain spaces. */
    char *rest = save;
    char *last_space = strrchr(rest, ' ');
    char reason[300] = "", password[128];
    if (last_space) {
        size_t rl = (size_t)(last_space - rest);
        if (rl >= sizeof reason) rl = sizeof reason - 1;
        memcpy(reason, rest, rl); reason[rl] = '\0';
        snprintf(password, sizeof password, "%s", last_space + 1);
    } else {
        snprintf(password, sizeof password, "%s", rest);
    }
    if (!check_password(from_nick, chan, password)) return;
    wire_kick(chan, target, reason[0] ? reason : "Kicked");
    char msg[300]; snprintf(msg, sizeof msg, "Kicked %s from %s", target, chan);
    reply(from_nick, msg);
}

static void cmd_svc_topic(const char *from_nick, char *args) {
    char *save = NULL;
    char *chan = strtok_r(args, " ", &save);
    if (!chan || !save || !*save) { reply(from_nick, "Syntax: TOPIC <#channel> <text> <password>"); return; }
    char *rest = save;
    char *last_space = strrchr(rest, ' ');
    char topic[300] = "", password[128];
    if (last_space) {
        size_t tl = (size_t)(last_space - rest);
        if (tl >= sizeof topic) tl = sizeof topic - 1;
        memcpy(topic, rest, tl); topic[tl] = '\0';
        snprintf(password, sizeof password, "%s", last_space + 1);
    } else {
        snprintf(password, sizeof password, "%s", rest);
    }
    if (!check_password(from_nick, chan, password)) return;
    wire_topic(chan, topic);
    char msg[300]; snprintf(msg, sizeof msg, "Topic set on %s", chan);
    reply(from_nick, msg);
}

static void cmd_help(const char *from_nick, char *args) {
    (void)args;
    reply(from_nick, "ChanServ commands:");
    reply(from_nick, "  REGISTER #channel <password>  -- register a channel you currently op");
    reply(from_nick, "  IDENTIFY #channel <password>  -- reclaim founder status this session");
    reply(from_nick, "  DROP #channel <password>      -- unregister a channel");
    reply(from_nick, "  JOIN #channel <password>      -- ChanServ joins and stays, protecting the");
    reply(from_nick, "                                    channel from ever emptying/being destroyed");
    reply(from_nick, "  PART #channel <password>      -- ChanServ leaves (undoes JOIN above)");
    reply(from_nick, "  SETPASS #channel <old> <new>  -- change a channel's password");
    reply(from_nick, "  TOPICLOCK #channel ON|OFF <password>");
    reply(from_nick, "                                -- remember the topic and restore it when");
    reply(from_nick, "                                   ChanServ (re)joins (server restart, channel");
    reply(from_nick, "                                   emptied out, etc.)");
    reply(from_nick, "  INFO #channel                 -- show registration/GUARD/TOPICLOCK status");
    reply(from_nick, "  ACCESS #channel ADD <mask> <v|h|o> <password>");
    reply(from_nick, "                                -- auto-grant +v/+h/+o on every JOIN matching");
    reply(from_nick, "                                   <mask>, without sharing the password. Accepts");
    reply(from_nick, "                                   a bare host (*.example.com), user@host, or a");
    reply(from_nick, "                                   full nick!user@host mask -- host is always");
    reply(from_nick, "                                   required, so a nick alone never grants it.");
    reply(from_nick, "                                   =accountname matches by services account");
    reply(from_nick, "                                   instead (must be SASL/REGISTER identified) --");
    reply(from_nick, "                                   use this if host_masking is on, since the");
    reply(from_nick, "                                   cloak shown in JOIN/WHOIS is random per");
    reply(from_nick, "                                   connection and can never match a hostmask");
    reply(from_nick, "  ACCESS #channel DEL <mask> <password>");
    reply(from_nick, "                                -- remove a mask from the access list");
    reply(from_nick, "  ACCESS #channel LIST          -- show the access list");
    reply(from_nick, "  SUCCESSOR #channel SET <mask> <password>");
    reply(from_nick, "                                -- designate who may CLAIM founder status if");
    reply(from_nick, "                                   nobody is currently IDENTIFY'd for this channel");
    reply(from_nick, "  SUCCESSOR #channel CLAIM <new-password>");
    reply(from_nick, "                                -- become founder (only works from the designated");
    reply(from_nick, "                                   mask, and only while nobody is IDENTIFY'd)");
    reply(from_nick, "  AKICK #channel ADD <mask> <password>");
    reply(from_nick, "                                -- auto-kick anyone matching <mask> on JOIN;");
    reply(from_nick, "                                   same mask forms as ACCESS, incl. =accountname");
    reply(from_nick, "  AKICK #channel DEL <mask> <password>");
    reply(from_nick, "                                -- remove a mask from the auto-kick list");
    reply(from_nick, "  AKICK #channel LIST           -- show the auto-kick list");
    reply(from_nick, "  SET #channel MLOCK <modes> <password>");
    reply(from_nick, "                                -- lock flag modes on; ChanServ re-applies any");
    reply(from_nick, "                                   of them that gets removed (empty <modes> clears)");
    reply(from_nick, "  SET #channel DESC|URL|ENTRYMSG <text> <password>");
    reply(from_nick, "                                -- free-text metadata (DESC/URL shown by INFO,");
    reply(from_nick, "                                   ENTRYMSG sent to whoever JOINs); empty clears");
    reply(from_nick, "  OP|DEOP|VOICE|DEVOICE|HALFOP|DEHALFOP #channel [nick] <password>");
    reply(from_nick, "                                -- set/remove that rank; nick defaults to yourself");
    reply(from_nick, "  INVITE #channel [nick] <password>  -- invite yourself or someone else in");
    reply(from_nick, "  UNBAN #channel [nick] <password>   -- remove any ban matching yourself/someone");
    reply(from_nick, "  KICK #channel <nick> [reason] <password>  -- kick someone out");
    reply(from_nick, "  TOPIC #channel <text> <password>          -- set the topic");
}

#define CTCP_DELIM '\x01'

/* CTCP VERSION only -- matches Python's _handle_ctcp (unrecognized CTCPs are
 * silently dropped, never a noisy error reply, since some clients/bots probe
 * this speculatively). */
static void handle_ctcp(const char *from_nick, const char *text) {
    size_t len = strlen(text);
    if (len < 2 || text[0] != CTCP_DELIM) return;
    char inner[256];
    size_t n = len - 1;
    if (text[len - 1] == CTCP_DELIM) n--;
    if (n >= sizeof inner) n = sizeof inner - 1;
    memcpy(inner, text + 1, n);
    inner[n] = '\0';
    char *save = NULL;
    char *verb = strtok_r(inner, " ", &save);
    if (verb && strcasecmp(verb, "VERSION") == 0) {
        char line[300];
        snprintf(line, sizeof line, "%cVERSION ChanServ v%s -- SekurIRCd channel services (services/chanserv.c), "
                 "https://github.com/gcanosa/SekurIRCd%c", CTCP_DELIM, CHANSERV_VERSION, CTCP_DELIM);
        reply(from_nick, line);
    }
}

static void dispatch_privmsg(const char *from_nick, const char *from_prefix, const char *text) {
    if (text[0] == CTCP_DELIM) { handle_ctcp(from_nick, text); return; }
    char buf[512];
    snprintf(buf, sizeof buf, "%s", text);
    char *save = NULL;
    char *verb = strtok_r(buf, " ", &save);
    if (!verb) return;
    char *rest = save;
    char empty[1] = "";
    if (!rest) rest = empty;

    if (strcasecmp(verb, "REGISTER") == 0) cmd_register(from_nick, rest);
    else if (strcasecmp(verb, "IDENTIFY") == 0) cmd_identify(from_nick, rest);
    else if (strcasecmp(verb, "DROP") == 0) cmd_drop(from_nick, rest);
    else if (strcasecmp(verb, "JOIN") == 0) cmd_guard_join(from_nick, rest);
    else if (strcasecmp(verb, "PART") == 0) cmd_guard_part(from_nick, rest);
    else if (strcasecmp(verb, "SETPASS") == 0) cmd_setpass(from_nick, rest);
    else if (strcasecmp(verb, "TOPICLOCK") == 0) cmd_topiclock(from_nick, rest);
    else if (strcasecmp(verb, "INFO") == 0) cmd_info(from_nick, rest);
    else if (strcasecmp(verb, "ACCESS") == 0) cmd_access(from_nick, rest);
    else if (strcasecmp(verb, "AKICK") == 0) cmd_akick(from_nick, rest);
    else if (strcasecmp(verb, "SUCCESSOR") == 0) cmd_successor(from_nick, from_prefix, rest);
    else if (strcasecmp(verb, "SET") == 0) cmd_set(from_nick, rest);
    else if (strcasecmp(verb, "OP") == 0) cmd_chanmode_one(from_nick, rest, "OP", '+', 'o');
    else if (strcasecmp(verb, "DEOP") == 0) cmd_chanmode_one(from_nick, rest, "DEOP", '-', 'o');
    else if (strcasecmp(verb, "VOICE") == 0) cmd_chanmode_one(from_nick, rest, "VOICE", '+', 'v');
    else if (strcasecmp(verb, "DEVOICE") == 0) cmd_chanmode_one(from_nick, rest, "DEVOICE", '-', 'v');
    else if (strcasecmp(verb, "HALFOP") == 0) cmd_chanmode_one(from_nick, rest, "HALFOP", '+', 'h');
    else if (strcasecmp(verb, "DEHALFOP") == 0) cmd_chanmode_one(from_nick, rest, "DEHALFOP", '-', 'h');
    else if (strcasecmp(verb, "INVITE") == 0) cmd_svc_invite(from_nick, rest);
    else if (strcasecmp(verb, "UNBAN") == 0) cmd_svc_unban(from_nick, rest);
    else if (strcasecmp(verb, "KICK") == 0) cmd_svc_kick(from_nick, rest);
    else if (strcasecmp(verb, "TOPIC") == 0) cmd_svc_topic(from_nick, rest);
    else if (strcasecmp(verb, "HELP") == 0) cmd_help(from_nick, rest);
    else reply(from_nick, "Unknown command. Try HELP.");
}

/* --- SVCJOIN: someone joined a channel ChanServ is sitting in (GUARD) --
 * apply AKICK, an ENTRYMSG notice, or an ACCESS auto-op/halfop/voice. --- */
static void handle_svcjoin(irc_message_t *msg) {
    if (msg->nparams < 4) return;
    const char *chan = msg->params[0], *nick = msg->params[1];
    const char *user = msg->params[2], *host = msg->params[3];
    const char *account = msg->nparams >= 5 ? msg->params[4] : "*";
    /* 6th field (added alongside irc_mask_match's ident_confirmed parameter);
     * an older ircd that doesn't send it degrades to the pre-fix behaviour. */
    int ident_confirmed = msg->nparams >= 6 && msg->params[5][0] == '1';
    cJSON *rec = store_get(chan);
    if (!rec) return;

    char ban[300];
    if (akick_matches(rec, nick, user, host, account, ident_confirmed, ban, sizeof ban)) {
        /* Set the ban before the KICK, not just the kick alone -- AKICK
         * with no ban meant a client could JOIN/get-kicked/JOIN again as
         * fast as the server's flood limits allowed, forever. */
        wire_mode(chan, "+b", ban);
        wire_kick(chan, nick, "Banned from this channel (AKICK)");
        return;
    }
    const char *entrymsg = rec_str(rec, "entrymsg");
    if (entrymsg[0]) reply(nick, entrymsg);

    const char *level = access_level_for(rec, nick, user, host, account, ident_confirmed);
    if (level[0]) {
        char modestring[4];
        snprintf(modestring, sizeof modestring, "+%s", level);
        wire_mode(chan, modestring, nick);
    }
}

/* --- link handshake + main loop --------------------------------------------- */

static int connect_hub(void) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portbuf[16];
    snprintf(portbuf, sizeof portbuf, "%d", g_cfg.link_port);
    if (getaddrinfo(g_cfg.link_host, portbuf, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int read_line_blocking(int fd, char *out, size_t outsz, int timeout_ms) {
    size_t len = 0;
    time_t deadline = time(NULL) + (timeout_ms / 1000) + 1;
    while (time(NULL) < deadline && len + 1 < outsz) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) return -1;
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') { out[len] = '\0'; return 0; }
        if (c != '\r') out[len++] = c;
    }
    return -1;
}

static int do_handshake(void) {
    char line[512];
    snprintf(line, sizeof line, "PASS %s", g_cfg.link_password);
    if (write(g_fd, line, strlen(line)) < 0 || write(g_fd, "\r\n", 2) < 0) return -1;

    const char *p[] = {g_cfg.link_name, "1"};
    irc_build(line, sizeof line, NULL, 0, NULL, "SERVER", p, 2, "ChanServ services (C port)");
    if (write(g_fd, line, strlen(line)) < 0 || write(g_fd, "\r\n", 2) < 0) return -1;

    char resp[512];
    if (read_line_blocking(g_fd, resp, sizeof resp, 5000) != 0) return -1;
    irc_message_t msg;
    if (irc_parse_line(resp, &msg) != 0 || strcasecmp(msg.command, "SERVER") != 0) return -1;
    log_info("chanserv", "linked to hub '%s'", msg.nparams > 0 ? msg.params[0] : "?");

    const char *np[] = {g_cfg.nick, g_cfg.user, g_cfg.host};
    irc_build(line, sizeof line, NULL, 0, NULL, "NICK", np, 3, g_cfg.realname);
    if (write(g_fd, line, strlen(line)) < 0 || write(g_fd, "\r\n", 2) < 0) return -1;
    return 0;
}

/* Rejoins every GUARDed channel, and reasserts +r/MLOCK for EVERY registered
 * channel regardless of GUARD -- covers both a fresh start and a reconnect
 * after a dropped link (guard_join in upstream's terms). Channel state
 * (including +r and any locked mode) lives only in the ircd's memory, not in
 * this store, so an ircd restart/rehash wipes it; a MODE for a channel that
 * doesn't currently exist there (nobody in it right now) is simply ignored
 * by the hub (see link.c's MODE handler), so this is safe to send broadly --
 * a non-GUARDed registered channel used to only get +r/MLOCK back if someone
 * happened to run /SAMODE by hand, since ChanServ was never in it to see
 * anything reset. */
static void guard_join_all(void) {
    cJSON *entry;
    cJSON_ArrayForEach(entry, g_store) {
        const char *chan = rec_str(entry, "name");
        if (rec_bool(entry, "guard")) {
            wire_join(chan);
            /* TOPICLOCK: same reasoning as +r/MLOCK below -- the ircd's live
             * topic is memory-only too, so a restart/recreate loses it. Only
             * meaningful once ChanServ has actually (re)joined. Ported from
             * Python's guard_join baseline restore. */
            if (rec_bool(entry, "topiclock")) {
                const char *stored_topic = rec_str(entry, "topic");
                if (stored_topic[0]) wire_topic(chan, stored_topic);
            }
        }
        wire_mode(chan, "+r", NULL);
        apply_mlock(entry, chan);
    }
}

/* "nick!user@host" -> "nick" (or the whole thing if there's no '!'). */
static void nick_from_prefix(const char *prefix, char *out, size_t outsz) {
    const char *bang = strchr(prefix, '!');
    size_t nl = bang ? (size_t)(bang - prefix) : strlen(prefix);
    if (nl >= outsz) nl = outsz - 1;
    memcpy(out, prefix, nl);
    out[nl] = '\0';
}

static void process_line(char *line) {
    irc_message_t msg;
    if (irc_parse_line(line, &msg) != 0) return;
    if (strcasecmp(msg.command, "PING") == 0) { queue_line("PONG"); return; }
    if (strcasecmp(msg.command, "PONG") == 0) return;

    /* QUIT/NICK for a shared-channel member reach us like any other channel
     * event (see link.c's client_send/server_send_common_channels fan-out --
     * no purpose-built relay needed here, unlike SVCJOIN). Only ever
     * observed for a GUARDed channel's members (see MAX_IDENTIFIED's doc
     * comment above); QUIT clears identified status, NICK carries it over. */
    if (strcasecmp(msg.command, "QUIT") == 0) {
        if (!msg.prefix) return;
        char from_nick[64];
        nick_from_prefix(msg.prefix, from_nick, sizeof from_nick);
        clear_identified_nick(from_nick);
        return;
    }
    if (strcasecmp(msg.command, "NICK") == 0) {
        if (!msg.prefix || msg.nparams < 1) return;
        char old_nick[64];
        nick_from_prefix(msg.prefix, old_nick, sizeof old_nick);
        rename_identified_nick(old_nick, msg.params[0]);
        return;
    }

    /* TOPICLOCK: whenever the live topic changes (by anyone), remember it
     * as the baseline to restore on a later guard_join -- ported from
     * Python's _on_topic. Was never handled here at all, so the JSON
     * store's "topic" field went stale the moment anyone ran /TOPIC. */
    if (strcasecmp(msg.command, "TOPIC") == 0) {
        if (msg.nparams < 1) return;
        const char *topic = msg.nparams > 1 ? msg.params[msg.nparams - 1] : "";
        cJSON *rec = store_get(msg.params[0]);
        if (rec && rec_bool(rec, "topiclock")) {
            rec_set_str(rec, "topic", topic);
            store_save();
        }
        return;
    }

    /* MLOCK enforcement: the hub relays channel MODE changes for channels
     * ChanServ sits in (GUARD) -- put back any locked letter someone removed. */
    if (strcasecmp(msg.command, "MODE") == 0) {
        if (msg.nparams < 2 || msg.params[0][0] != '#') return;
        cJSON *rec = store_get(msg.params[0]);
        const char *mlock = rec ? rec_str(rec, "mlock") : "";
        if (!mlock[0]) return;
        char restore[16] = "+";
        size_t rp = 1;
        char sign = '+';
        for (const char *c = msg.params[1]; *c; c++) {
            if (*c == '+' || *c == '-') { sign = *c; continue; }
            if (sign == '-' && strchr(mlock, *c) && !strchr(restore, *c) && rp + 1 < sizeof restore) {
                restore[rp++] = *c;
                restore[rp] = '\0';
            }
        }
        if (rp > 1) wire_mode(msg.params[0], restore, NULL);
        return;
    }

    if (strcasecmp(msg.command, "PRIVMSG") == 0) {
        if (msg.nparams < 2 || !msg.prefix) return;
        if (strcasecmp(msg.params[0], g_cfg.nick) != 0) return; /* not addressed to us (e.g. channel chatter while GUARD-joined) */
        char from_nick[64];
        nick_from_prefix(msg.prefix, from_nick, sizeof from_nick);
        dispatch_privmsg(from_nick, msg.prefix, msg.params[msg.nparams - 1]);
        return;
    }
    if (strcasecmp(msg.command, "SVCJOIN") == 0) { handle_svcjoin(&msg); return; }
    if (strcasecmp(msg.command, "WHOISCHANREPLY") == 0) {
        if (msg.nparams < 3 || !g_pending_register.active) return;
        char cf1[128], cf2[128];
        irc_casefold(cf1, sizeof cf1, msg.params[0]);
        irc_casefold(cf2, sizeof cf2, g_pending_register.chan);
        if (strcmp(cf1, cf2) != 0 || strcasecmp(msg.params[1], g_pending_register.nick) != 0) return;
        g_pending_register.active = 0;
        if (strcmp(msg.params[2], "o") == 0) finish_register();
        else reply(g_pending_register.nick, "You must be a channel operator there to register it.");
        return;
    }
    if (strcasecmp(msg.command, "WHOISUSERREPLY") == 0) {
        if (msg.nparams < 5 || !g_pending_claim.active) return;
        if (strcasecmp(msg.params[0], g_pending_claim.nick) != 0) return;
        g_pending_claim.active = 0;
        if (strcmp(msg.params[1], "*") == 0) { reply(g_pending_claim.nick, "You're not online anymore."); return; }
        finish_claim(msg.params[1], msg.params[2], msg.params[3], msg.params[4][0] == '1');
        return;
    }
}

static int run_session(void) {
    g_fd = connect_hub();
    if (g_fd < 0) return -1;
    if (do_handshake() != 0) { close(g_fd); g_fd = -1; return -1; }
    int flags = fcntl(g_fd, F_GETFL, 0);
    fcntl(g_fd, F_SETFL, flags | O_NONBLOCK);
    g_rbuf_len = 0;
    /* A previous session's queued-but-unsent output (e.g. a MODE left in
     * g_sbuf when the link dropped mid-write) must not bleed into this new
     * one -- it would be sent before NICK even reintroduces the service
     * pseudo-client, applying to whatever a nick/channel means on THIS
     * connection, not the one it was meant for. */
    g_sbuf_len = 0;
    /* Likewise, "who's identified" can't survive a lost link: any QUIT/NICK
     * that happened while disconnected was never seen, so a stale entry
     * could wrongly block (or, worse, a stale nick given to someone else
     * could wrongly satisfy) a SUCCESSOR CLAIM after reconnecting. */
    g_n_identified = 0;
    g_last_activity = time(NULL);
    log_info("chanserv", "session established as '%s'", g_cfg.nick);
    guard_join_all();

    while (!g_term) {
        struct pollfd pfd;
        pfd.fd = g_fd;
        pfd.events = POLLIN | (g_sbuf_len > 0 ? POLLOUT : 0);
        int rc = poll(&pfd, 1, 1000);
        if (rc < 0) { if (errno == EINTR) continue; break; }
        if (rc > 0) {
            if (pfd.revents & (POLLHUP | POLLERR)) break;
            if (pfd.revents & POLLIN) {
                char tmp[4096];
                ssize_t n = read(g_fd, tmp, sizeof tmp);
                if (n <= 0) { if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { /* spurious */ } else break; }
                else {
                    g_last_activity = time(NULL);
                    if (g_rbuf_len + (size_t)n + 1 > sizeof g_rbuf) break; /* line too long */
                    memcpy(g_rbuf + g_rbuf_len, tmp, (size_t)n);
                    g_rbuf_len += (size_t)n;
                    size_t start = 0;
                    for (size_t i = 0; i < g_rbuf_len; i++) {
                        if (g_rbuf[i] != '\n') continue;
                        size_t end = i;
                        if (end > start && g_rbuf[end - 1] == '\r') end--;
                        g_rbuf[end] = '\0';
                        process_line(g_rbuf + start);
                        start = i + 1;
                    }
                    memmove(g_rbuf, g_rbuf + start, g_rbuf_len - start);
                    g_rbuf_len -= start;
                }
            }
            if (pfd.revents & POLLOUT) flush_sbuf();
        }
        if (g_sbuf_len > 0) flush_sbuf();
        store_flush();
        if (g_pending_register.active && difftime(time(NULL), g_pending_register.sent_at) > 5) {
            g_pending_register.active = 0;
            reply(g_pending_register.nick, "Timed out waiting for the server -- try REGISTER again.");
        }
        if (g_pending_claim.active && difftime(time(NULL), g_pending_claim.sent_at) > 5) {
            g_pending_claim.active = 0;
            reply(g_pending_claim.nick, "Timed out waiting for the server -- try CLAIM again.");
        }
        if (difftime(time(NULL), g_last_activity) > 240) break; /* link keepalive timeout */
    }
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    return 0;
}

/* --- CLI: -d/--daemon, --pidfile, --stop (mirrors sekurircd's own main.c) --- */

static void daemonize(void) {
    if (fork() > 0) _exit(0);
    setsid();
    if (fork() > 0) _exit(0);
    umask(0022);
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 1); dup2(devnull, 2); if (devnull > 2) close(devnull); }
}

static long read_pidfile(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    long pid;
    int ok = fscanf(fp, "%ld", &pid) == 1;
    fclose(fp);
    return ok ? pid : -1;
}

static int pidfile_is_live(const char *path) {
    long pid = read_pidfile(path);
    if (pid <= 0) return 0;
    return kill((pid_t)pid, 0) == 0;
}

static int stop_daemon(const char *pidfile) {
    long pid = read_pidfile(pidfile);
    if (pid <= 0) { fprintf(stderr, "chanserv: no running daemon (can't read a pid from %s)\n", pidfile); return 1; }
    if (kill((pid_t)pid, SIGTERM) != 0) {
        fprintf(stderr, "chanserv: could not signal process %ld: %s\n", pid, strerror(errno));
        return 1;
    }
    time_t deadline = time(NULL) + 10;
    while (time(NULL) < deadline) {
        if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) { printf("chanserv: stopped (pid %ld)\n", pid); return 0; }
        struct timespec ts = {0, 200000000L};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "chanserv: process %ld did not stop in time\n", pid);
    return 1;
}

int main(int argc, char **argv) {
    const char *config_path = "services/services.toml";
    const char *pidfile = getenv("CHANSERV_PIDFILE");
    if (!pidfile) pidfile = "chanserv.pid";
    int do_daemon = 0, do_stop = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((strcmp(a, "-c") == 0 || strcmp(a, "--config") == 0) && i + 1 < argc) config_path = argv[++i];
        else if (strcmp(a, "-d") == 0 || strcmp(a, "--daemon") == 0) do_daemon = 1;
        else if (strcmp(a, "--pidfile") == 0 && i + 1 < argc) pidfile = argv[++i];
        else if (strcmp(a, "--stop") == 0) do_stop = 1;
        else if (strcmp(a, "--version") == 0) { printf("chanserv %s\n", CHANSERV_VERSION); return 0; }
        else { fprintf(stderr, "unrecognized argument: %s\n", a); return 2; }
    }

    if (do_stop) return stop_daemon(pidfile);

    char errbuf[256];
    if (load_app_config(config_path, &g_cfg, errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "chanserv: %s\n", errbuf);
        return 2;
    }

    /* Unlike sekurircd's own main.c (see its pidfile_is_live), this was
     * missing entirely -- starting chanserv twice against the same pidfile
     * silently ran two live daemons, the second one clobbering the pidfile
     * while the first kept its link to the hub, showing up as the same
     * peer name twice in /MAP. */
    if (pidfile[0] && pidfile_is_live(pidfile)) {
        long existing = read_pidfile(pidfile);
        fprintf(stderr, "chanserv: a daemon is already running (pid %ld, pidfile %s) "
                         "-- refusing to start a second one and clobber its pidfile\n",
                existing, pidfile);
        return 2;
    }

    if (do_daemon) daemonize();
    if (pidfile[0]) {
        FILE *fp = fopen(pidfile, "w");
        if (fp) { fprintf(fp, "%d\n", (int)getpid()); fclose(fp); }
    }

    log_config_t lcfg = {0};
    lcfg.enabled = 0; /* console only -- chanserv has no [logging] section of its own */
    lcfg.level = LOG_INFO;
    log_init(&lcfg, 0);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    store_load();
    log_info("chanserv", "starting (v%s), storage=%s", CHANSERV_VERSION, g_cfg.storage_path);

    int backoff = 2;
    while (!g_term) {
        int rc = run_session();
        store_flush(); /* the link is down; don't sit on unwritten changes */
        if (rc != 0) {
            log_warn("chanserv", "could not reach hub %s:%d -- retrying in %ds",
                      g_cfg.link_host, g_cfg.link_port, backoff);
        } else {
            /* The session actually established before it ended, so the hub is
             * reachable -- drop any penalty accumulated by earlier failures.
             * Without this a long-lived daemon drifts to the 60s ceiling and
             * stays there reconnecting to a perfectly healthy hub. */
            backoff = 2;
            log_warn("chanserv", "link session ended -- reconnecting in %ds", backoff);
        }
        if (g_term) break;
        struct timespec ts = {backoff, 0};
        nanosleep(&ts, NULL);
        if (rc != 0) backoff = backoff < 60 ? backoff * 2 : 60;
    }

    log_info("chanserv", "shutting down");
    store_flush();
    if (pidfile[0]) unlink(pidfile);
    cJSON_Delete(g_store);
    return 0;
}
