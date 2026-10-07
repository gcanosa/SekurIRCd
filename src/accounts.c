#include "accounts.h"
#include "proto.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

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
    cJSON_ArrayForEach(rec, st->data) { cJSON *n = cJSON_GetObjectItemCaseSensitive(rec, "nicks"); if (cJSON_IsArray(n)) st->n_grouped += cJSON_GetArraySize(n); }
}

void accounts_free(account_store_t *st) {
    if (st->data) cJSON_Delete(st->data);
    st->data = NULL;
}

static void save(account_store_t *st) {
    if (!st->path[0]) return; /* accounts disabled -- never touch disk */
    char *text = cJSON_Print(st->data);
    if (!text) return;
    char tmp[sizeof st->path + 5];
    snprintf(tmp, sizeof tmp, "%s.tmp", st->path);
    /* O_CREAT with an explicit 0600 (not fopen()+chmod after the fact,
     * racy) -- this file holds every account's scrypt hash and any bound
     * SASL EXTERNAL certificate fingerprint; main.c's umask(0022) would
     * otherwise leave it world-readable. fsync before rename so a write
     * that loses the race with a crash/power loss can't replace the good
     * file on disk with a truncated one. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { free(text); return; }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) { close(fd); free(text); return; }
    size_t len = strlen(text);
    int ok = fwrite(text, 1, len, fp) == len && fflush(fp) == 0 && fsync(fd) == 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok) rename(tmp, st->path); /* atomic on POSIX */
    else unlink(tmp);
    free(text);
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
    return cJSON_GetObjectItemCaseSensitive(st->data, cf);
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
    commit(st, rec);
}

const char *accounts_fingerprint(account_store_t *st, const char *name) {
    cJSON *fp = cJSON_GetObjectItemCaseSensitive(find(st, name), "cert_fp");
    return cJSON_IsString(fp) ? fp->valuestring : NULL;
}

const char *accounts_find_by_fingerprint(account_store_t *st, const char *fp) {
    if (!fp || !fp[0]) return NULL;
    cJSON *rec;
    cJSON_ArrayForEach(rec, st->data) {
        cJSON *cf = cJSON_GetObjectItemCaseSensitive(rec, "cert_fp");
        if (!cJSON_IsString(cf) || strcasecmp(cf->valuestring, fp) != 0) continue;
        cJSON *name = cJSON_GetObjectItemCaseSensitive(rec, "name");
        return cJSON_IsString(name) ? name->valuestring : NULL;
    }
    return NULL;
}

void accounts_set_hash(account_store_t *st, const char *name, const char *hash) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "pw_hash");
    cJSON_AddStringToObject(rec, "pw_hash", hash);
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "scram"); /* derived from the old password */
    commit(st, rec);
}

int accounts_drop(account_store_t *st, const char *name) {
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    cJSON *rec = cJSON_GetObjectItemCaseSensitive(st->data, cf);
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
    cJSON *rec;
    cJSON_ArrayForEach(rec, st->data) {
        cJSON *n = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
        cJSON *it;
        if (!cJSON_IsArray(n)) continue;
        cJSON_ArrayForEach(it, n) {
            if (cJSON_IsString(it) && strcmp(it->valuestring, cf) == 0) {
                cJSON *nm = cJSON_GetObjectItemCaseSensitive(rec, "name");
                return cJSON_IsString(nm) ? nm->valuestring : NULL;
            }
        }
    }
    return NULL;
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
    cJSON *old = cJSON_GetObjectItemCaseSensitive(st->data, cf);
    if (old) {
        cJSON *on = cJSON_GetObjectItemCaseSensitive(old, "nicks");
        if (cJSON_IsArray(on)) st->n_grouped -= cJSON_GetArraySize(on);
        cJSON_DeleteItemFromObjectCaseSensitive(st->data, cf);
    }
    cJSON *nn = cJSON_GetObjectItemCaseSensitive(rec, "nicks");
    if (cJSON_IsArray(nn)) st->n_grouped += cJSON_GetArraySize(nn);
    cJSON_AddItemToObject(st->data, cf, rec);
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
