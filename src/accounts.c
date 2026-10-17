#include "accounts.h"
#include "proto.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* --- hash indexes over st->data (see accounts.h) ----------------------------------------------------------------------- */

struct aidx { char key[72]; cJSON *rec; UT_hash_handle hh; };

static void idx_put(struct aidx **head, const char *key, cJSON *rec) {
    if (strlen(key) >= sizeof ((struct aidx *)0)->key) return; /* longer than any account name / fingerprint: simply unindexed */
    struct aidx *e;
    HASH_FIND_STR(*head, key, e);
    if (e) return; /* first record wins, same as the linear scan this replaces */
    e = malloc(sizeof *e);
    if (!e) return;
    snprintf(e->key, sizeof e->key, "%s", key);
    e->rec = rec;
    HASH_ADD_STR(*head, key, e);
}

static void idx_del(struct aidx **head, const char *key) {
    struct aidx *e;
    HASH_FIND_STR(*head, key, e);
    if (e) { HASH_DEL(*head, e); free(e); }
}

static void idx_clear(struct aidx **head) {
    struct aidx *e, *tmp;
    HASH_ITER(hh, *head, e, tmp) { HASH_DEL(*head, e); free(e); }
}

static cJSON *idx_get(struct aidx *head, const char *key) {
    struct aidx *e;
    HASH_FIND_STR(head, key, e);
    return e ? e->rec : NULL;
}

/* Rebuilds the nick-group and fingerprint indexes if a record changed since they were last built. */
static void derive(account_store_t *st) {
    if (!st->derived_stale) return;
    idx_clear(&st->by_nick);
    idx_clear(&st->by_fp);
    cJSON *rec, *it;
    cJSON_ArrayForEach(rec, st->data) {
        cJSON *nicks = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
        if (cJSON_IsArray(nicks))
            cJSON_ArrayForEach(it, nicks) if (cJSON_IsString(it)) idx_put(&st->by_nick, it->valuestring, rec);
        cJSON *fp = cJSON_GetObjectItemCaseSensitive(rec, "cert_fp");
        if (cJSON_IsString(fp)) {
            char lower[72];
            size_t i = 0;
            for (; fp->valuestring[i] && i < sizeof lower - 1; i++) lower[i] = (char)tolower((unsigned char)fp->valuestring[i]);
            lower[i] = '\0';
            idx_put(&st->by_fp, lower, rec);
        }
    }
    st->derived_stale = 0;
}

void accounts_init(account_store_t *st, const char *path) {
    memset(st, 0, sizeof *st);
    if (path && path[0]) snprintf(st->path, sizeof st->path, "%s", path);

    if (st->path[0]) {
        FILE *fp = fopen(st->path, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long len = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (len > 0) {
                char *buf = malloc((size_t)len + 1);
                if (buf) {
                    size_t rd = fread(buf, 1, (size_t)len, fp);
                    buf[rd] = '\0';
                    st->data = cJSON_Parse(buf);
                    free(buf);
                }
            }
            fclose(fp);
        }
    }
    if (!st->data) st->data = cJSON_CreateObject();
    cJSON *rec;
    cJSON_ArrayForEach(rec, st->data) {
        cJSON *n = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
        if (cJSON_IsArray(n)) st->n_grouped += cJSON_GetArraySize(n);
        if (rec->string) idx_put(&st->by_name, rec->string, rec);
    }
    st->derived_stale = 1;
}

void accounts_free(account_store_t *st) {
    accounts_flush(st);
    idx_clear(&st->by_name);
    idx_clear(&st->by_nick);
    idx_clear(&st->by_fp);
    if (st->data) cJSON_Delete(st->data);
    st->data = NULL;
}

/* A change worth persisting: written by accounts_flush (net.c's 1-second tick, and at shutdown), so a burst of
 * registrations or logins costs one write+fsync instead of one each -- the same batching the K-line store uses. */
static void save(account_store_t *st) {
    if (st->path[0]) st->dirty = 1; /* accounts disabled -- never touch disk */
}

void accounts_flush(account_store_t *st) {
    if (!st->dirty || !st->path[0]) return;
    char tmp[sizeof st->path + 5];
    snprintf(tmp, sizeof tmp, "%s.tmp", st->path);
    /* O_CREAT with an explicit 0600 (not fopen()+chmod after the fact,
     * racy) -- this file holds every account's scrypt hash and any bound
     * SASL EXTERNAL certificate fingerprint; main.c's umask(0022) would
     * otherwise leave it world-readable. fsync before rename so a write
     * that loses the race with a crash/power loss can't replace the good
     * file on disk with a truncated one. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return; /* still dirty: tried again next tick */
    FILE *fp = fdopen(fd, "wb");
    if (!fp) { close(fd); return; }
    /* One account per line, printed and written one at a time: a printed copy of the whole store (what cJSON_Print
     * of the root made) is as large as the file itself. */
    int ok = 1;
    fputc('{', fp);
    int first = 1;
    cJSON *rec;
    cJSON_ArrayForEach(rec, st->data) {
        char *text = cJSON_PrintUnformatted(rec);
        if (!text) { ok = 0; break; }
        fputs(first ? "\n" : ",\n", fp);
        first = 0;
        json_put_string(fp, rec->string ? rec->string : "");
        fputc(':', fp);
        fputs(text, fp);
        free(text);
    }
    fputs("\n}\n", fp);
    ok = ok && ferror(fp) == 0 && fflush(fp) == 0 && fsync(fd) == 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok && rename(tmp, st->path) == 0) st->dirty = 0; /* atomic on POSIX */
    else unlink(tmp);
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A mutation worth replicating: stamp the record (strictly newer than before), persist, and tell the network. */
static void commit(account_store_t *st, cJSON *rec) {
    cJSON *u = cJSON_GetObjectItemCaseSensitive(rec, "updated_at");
    long long prev = cJSON_IsNumber(u) ? (long long)u->valuedouble : 0;
    long long ts = now_ms();
    if (ts <= prev) ts = prev + 1;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "updated_at");
    cJSON_AddNumberToObject(rec, "updated_at", (double)ts);
    save(st);
    cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
    if (st->on_change && !st->applying && cJSON_IsString(nm)) st->on_change(st->ud, nm->valuestring, ts, 0);
}

static cJSON *find(account_store_t *st, const char *name) {
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    return idx_get(st->by_name, cf);
}

int accounts_exists(account_store_t *st, const char *name) {
    return find(st, name) != NULL;
}

int accounts_count(account_store_t *st) {
    return st->data ? cJSON_GetArraySize(st->data) : 0;
}

void accounts_register_hashed(account_store_t *st, const char *name, const char *hash) {
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "pw_hash", hash);
    cJSON_AddNumberToObject(rec, "created_at", (double)time(NULL));
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    cJSON_AddItemToObject(st->data, cf, rec);
    idx_put(&st->by_name, cf, rec);
    commit(st, rec);
}

const char *accounts_hash(account_store_t *st, const char *name) {
    cJSON *hash = cJSON_GetObjectItemCaseSensitive(find(st, name), "pw_hash");
    return cJSON_IsString(hash) ? hash->valuestring : NULL;
}

const char *accounts_display_name(account_store_t *st, const char *name) {
    cJSON *n = cJSON_GetObjectItemCaseSensitive(find(st, name), "name");
    return cJSON_IsString(n) ? n->valuestring : name;
}

const char *accounts_scram(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "scram");
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

void accounts_set_scram(account_store_t *st, const char *name, const char *verifier) {
    cJSON *rec = find(st, name);
    if (!rec || !verifier || !verifier[0]) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "scram");
    cJSON_AddStringToObject(rec, "scram", verifier);
    commit(st, rec);
}

long accounts_created_at(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "created_at");
    return cJSON_IsNumber(v) ? (long)v->valuedouble : 0;
}

void accounts_set_fingerprint(account_store_t *st, const char *name, const char *fp) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "cert_fp");
    if (fp && fp[0]) cJSON_AddStringToObject(rec, "cert_fp", fp);
    st->derived_stale = 1;
    commit(st, rec);
}

const char *accounts_fingerprint(account_store_t *st, const char *name) {
    cJSON *fp = cJSON_GetObjectItemCaseSensitive(find(st, name), "cert_fp");
    return cJSON_IsString(fp) ? fp->valuestring : NULL;
}

const char *accounts_find_by_fingerprint(account_store_t *st, const char *fp) {
    if (!fp || !fp[0]) return NULL;
    char lower[72];
    size_t i = 0;
    for (; fp[i] && i < sizeof lower - 1; i++) lower[i] = (char)tolower((unsigned char)fp[i]);
    lower[i] = '\0';
    derive(st);
    cJSON *rec = idx_get(st->by_fp, lower);
    cJSON *name = rec ? cJSON_GetObjectItemCaseSensitive(rec, "name") : NULL;
    return cJSON_IsString(name) ? name->valuestring : NULL;
}

void accounts_set_hash(account_store_t *st, const char *name, const char *hash) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "pw_hash");
    cJSON_AddStringToObject(rec, "pw_hash", hash);
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "scram"); /* derived from the old password */
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "reset_code"); /* a pending reset is moot now */
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "reset_expires");
    commit(st, rec);
}

void accounts_set_reset(account_store_t *st, const char *name, const char *code, long expires_at) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "reset_code");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "reset_expires");
    if (code && code[0]) {
        cJSON_AddStringToObject(rec, "reset_code", code);
        cJSON_AddNumberToObject(rec, "reset_expires", (double)expires_at);
    }
    commit(st, rec);
}

long accounts_reset_expires(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "reset_expires");
    return cJSON_IsNumber(v) ? (long)v->valuedouble : 0;
}

int accounts_check_reset(account_store_t *st, const char *name, const char *code) {
    cJSON *rec = find(st, name);
    cJSON *c = rec ? cJSON_GetObjectItemCaseSensitive(rec, "reset_code") : NULL;
    if (!cJSON_IsString(c) || accounts_reset_expires(st, name) < (long)time(NULL)) return 0;
    if (strlen(c->valuestring) != strlen(code) || strcasecmp(c->valuestring, code) != 0) return 0;
    accounts_set_reset(st, name, NULL, 0); /* one use */
    return 1;
}

void accounts_set_suspended(account_store_t *st, const char *name, const char *by, const char *reason) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "suspended");
    if (by) {
        cJSON *s = cJSON_CreateObject();
        cJSON_AddStringToObject(s, "by", by);
        cJSON_AddStringToObject(s, "reason", reason ? reason : "");
        cJSON_AddNumberToObject(s, "at", (double)time(NULL));
        cJSON_AddItemToObject(rec, "suspended", s);
    }
    commit(st, rec);
}

int accounts_suspended(account_store_t *st, const char *name, const char **by, const char **reason) {
    cJSON *s = cJSON_GetObjectItemCaseSensitive(find(st, name), "suspended");
    if (!cJSON_IsObject(s)) return 0;
    cJSON *b = cJSON_GetObjectItemCaseSensitive(s, "by"), *r = cJSON_GetObjectItemCaseSensitive(s, "reason");
    if (by) *by = cJSON_IsString(b) ? b->valuestring : "";
    if (reason) *reason = cJSON_IsString(r) ? r->valuestring : "";
    return 1;
}

int accounts_drop(account_store_t *st, const char *name) {
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    cJSON *rec = idx_get(st->by_name, cf);
    if (!rec) return 0;
    cJSON *n = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
    if (cJSON_IsArray(n)) st->n_grouped -= cJSON_GetArraySize(n);
    long long ts = 0;
    cJSON *u = cJSON_GetObjectItemCaseSensitive(rec, "updated_at");
    ts = now_ms();
    if (cJSON_IsNumber(u) && ts <= (long long)u->valuedouble) ts = (long long)u->valuedouble + 1;
    char shown[64] = "";
    cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
    snprintf(shown, sizeof shown, "%s", cJSON_IsString(nm) ? nm->valuestring : name);
    idx_del(&st->by_name, cf);
    st->derived_stale = 1;
    cJSON_DeleteItemFromObjectCaseSensitive(st->data, cf);
    save(st);
    if (st->on_change && !st->applying) st->on_change(st->ud, shown, ts, 1);
    return 1;
}

const char *accounts_email(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "email");
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

int accounts_email_verified(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "email_verified");
    return cJSON_IsTrue(v);
}

void accounts_set_email(account_store_t *st, const char *name, const char *email, int verified) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "email");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "email_verified");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "pending_email");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "verify_code");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "verify_expires");
    if (email && email[0]) {
        cJSON_AddStringToObject(rec, "email", email);
        cJSON_AddBoolToObject(rec, "email_verified", verified);
    }
    commit(st, rec);
}

void accounts_set_pending_email(account_store_t *st, const char *name, const char *email, const char *code, long expires_at) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "pending_email");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "verify_code");
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "verify_expires");
    cJSON_AddStringToObject(rec, "pending_email", email);
    cJSON_AddStringToObject(rec, "verify_code", code);
    cJSON_AddNumberToObject(rec, "verify_expires", (double)expires_at);
    save(st);
}

const char *accounts_pending_email(account_store_t *st, const char *name) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(find(st, name), "pending_email");
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

int accounts_check_verify(account_store_t *st, const char *name, const char *code) {
    cJSON *rec = find(st, name);
    if (!rec) return 0;
    cJSON *c = cJSON_GetObjectItemCaseSensitive(rec, "verify_code");
    cJSON *e = cJSON_GetObjectItemCaseSensitive(rec, "verify_expires");
    cJSON *pe = cJSON_GetObjectItemCaseSensitive(rec, "pending_email");
    if (!cJSON_IsString(c) || !cJSON_IsString(pe) || !cJSON_IsNumber(e)) return 0;
    if ((long)e->valuedouble < (long)time(NULL) || strcasecmp(c->valuestring, code) != 0) return 0;
    char email[200];
    snprintf(email, sizeof email, "%s", pe->valuestring);
    accounts_set_email(st, name, email, 1);
    return 1;
}

int accounts_group_add(account_store_t *st, const char *name, const char *nick) {
    cJSON *rec = find(st, name);
    if (!rec || accounts_owner_of_nick(st, nick)) return -1; /* already an account name or somebody's grouped nick */
    cJSON *n = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
    if (!n) { n = cJSON_CreateArray(); cJSON_AddItemToObject(rec, "nicks", n); }
    if (cJSON_GetArraySize(n) >= ACCOUNT_MAX_GROUP) return -1;
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    cJSON_AddItemToArray(n, cJSON_CreateString(cf));
    st->n_grouped++;
    st->derived_stale = 1;
    commit(st, rec);
    return 0;
}

int accounts_group_del(account_store_t *st, const char *name, const char *nick) {
    cJSON *rec = find(st, name);
    cJSON *n = rec ? cJSON_GetObjectItemCaseSensitive(rec, "nicks") : NULL;
    if (!n) return -1;
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    int idx = 0;
    cJSON *it;
    cJSON_ArrayForEach(it, n) {
        if (cJSON_IsString(it) && strcmp(it->valuestring, cf) == 0) {
            cJSON_DeleteItemFromArray(n, idx);
            st->n_grouped--;
            st->derived_stale = 1;
            commit(st, rec);
            return 0;
        }
        idx++;
    }
    return -1;
}

int accounts_group_count(account_store_t *st, const char *name) {
    cJSON *n = cJSON_GetObjectItemCaseSensitive(find(st, name), "nicks");
    return cJSON_IsArray(n) ? cJSON_GetArraySize(n) : 0;
}

const char *accounts_group_nick(account_store_t *st, const char *name, int i) {
    cJSON *n = cJSON_GetObjectItemCaseSensitive(find(st, name), "nicks");
    cJSON *it = cJSON_IsArray(n) ? cJSON_GetArrayItem(n, i) : NULL;
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

const char *accounts_owner_of_nick(account_store_t *st, const char *nick) {
    cJSON *own = find(st, nick);
    if (own) { cJSON *nm = cJSON_GetObjectItemCaseSensitive(own, "name"); return cJSON_IsString(nm) ? nm->valuestring : NULL; }
    if (st->n_grouped <= 0) return NULL;
    char cf[64];
    irc_casefold(cf, sizeof cf, nick);
    derive(st);
    cJSON *rec = idx_get(st->by_nick, cf);
    cJSON *nm = rec ? cJSON_GetObjectItemCaseSensitive(rec, "name") : NULL;
    return cJSON_IsString(nm) ? nm->valuestring : NULL;
}

long long accounts_updated_at(account_store_t *st, const char *name) {
    cJSON *u = cJSON_GetObjectItemCaseSensitive(find(st, name), "updated_at");
    return cJSON_IsNumber(u) ? (long long)u->valuedouble : 0;
}

char *accounts_record_json(account_store_t *st, const char *name) {
    cJSON *rec = find(st, name);
    return rec ? cJSON_PrintUnformatted(rec) : NULL;
}

int accounts_apply_remote(account_store_t *st, const char *name, long long ts, const char *json) {
    cJSON *rec = cJSON_Parse(json);
    cJSON *nm = rec ? cJSON_GetObjectItemCaseSensitive(rec, "name") : NULL;
    if (!cJSON_IsObject(rec) || !cJSON_IsString(nm) || strcasecmp(nm->valuestring, name) != 0) { cJSON_Delete(rec); return 0; }
    if (accounts_updated_at(st, name) >= ts && find(st, name)) { cJSON_Delete(rec); return 0; } /* ours is as new or newer */
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "updated_at");
    cJSON_AddNumberToObject(rec, "updated_at", (double)ts);
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    cJSON *old = idx_get(st->by_name, cf);
    if (old) {
        cJSON *on = cJSON_GetObjectItemCaseSensitive(old, "nicks");
        if (cJSON_IsArray(on)) st->n_grouped -= cJSON_GetArraySize(on);
        idx_del(&st->by_name, cf);
        cJSON_DeleteItemFromObjectCaseSensitive(st->data, cf);
    }
    cJSON *nn = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
    if (cJSON_IsArray(nn)) st->n_grouped += cJSON_GetArraySize(nn);
    cJSON_AddItemToObject(st->data, cf, rec);
    idx_put(&st->by_name, cf, rec);
    st->derived_stale = 1;
    save(st);
    return 1;
}

int accounts_apply_remote_delete(account_store_t *st, const char *name, long long ts) {
    cJSON *rec = find(st, name);
    if (!rec) return 0;
    if (accounts_updated_at(st, name) >= ts) return 0; /* modified after the delete: keep it */
    char saved = st->applying;
    st->applying = 1;
    accounts_drop(st, name);
    st->applying = saved;
    return 1;
}

const char **accounts_all_names(account_store_t *st, int *n) {
    int cnt = cJSON_GetArraySize(st->data);
    const char **out = malloc(sizeof *out * (size_t)(cnt ? cnt : 1));
    *n = 0;
    cJSON *rec;
    if (!out) return NULL;
    cJSON_ArrayForEach(rec, st->data) {
        cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
        if (cJSON_IsString(nm)) out[(*n)++] = nm->valuestring;
    }
    return out;
}
