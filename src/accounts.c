#include "accounts.h"
#include "proto.h"

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
                size_t rd = fread(buf, 1, (size_t)len, fp);
                buf[rd] = '\0';
                st->data = cJSON_Parse(buf);
                free(buf);
            }
            fclose(fp);
        }
    }
    if (!st->data) st->data = cJSON_CreateObject();
}

void accounts_free(account_store_t *st) {
    if (st->data) cJSON_Delete(st->data);
    st->data = NULL;
}

static void save(account_store_t *st) {
    if (!st->path[0]) return; /* accounts disabled -- never touch disk */
    char *text = cJSON_Print(st->data);
    char tmp[560];
    snprintf(tmp, sizeof tmp, "%s.tmp", st->path);
    FILE *fp = fopen(tmp, "wb");
    if (fp) {
        fputs(text, fp);
        fclose(fp);
        rename(tmp, st->path); /* atomic on POSIX */
    }
    free(text);
}

static cJSON *find(account_store_t *st, const char *name) {
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    return cJSON_GetObjectItemCaseSensitive(st->data, cf);
}

int accounts_exists(account_store_t *st, const char *name) {
    return find(st, name) != NULL;
}

void accounts_register_hashed(account_store_t *st, const char *name, const char *hash) {
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "pw_hash", hash);
    cJSON_AddNumberToObject(rec, "created_at", (double)time(NULL));
    char cf[64];
    irc_casefold(cf, sizeof cf, name);
    cJSON_AddItemToObject(st->data, cf, rec);
    save(st);
}

const char *accounts_hash(account_store_t *st, const char *name) {
    cJSON *hash = cJSON_GetObjectItemCaseSensitive(find(st, name), "pw_hash");
    return cJSON_IsString(hash) ? hash->valuestring : NULL;
}

void accounts_set_fingerprint(account_store_t *st, const char *name, const char *fp) {
    cJSON *rec = find(st, name);
    if (!rec) return;
    cJSON_DeleteItemFromObjectCaseSensitive(rec, "cert_fp");
    if (fp && fp[0]) cJSON_AddStringToObject(rec, "cert_fp", fp);
    save(st);
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
