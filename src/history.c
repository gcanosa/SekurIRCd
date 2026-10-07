#include "history.h"

#include "config.h"
#include "log.h"
#include "proto.h"
#include "server.h"
#include "vendor/cJSON.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void history_key_channel(char *out, size_t outsz, const char *chan) {
    irc_casefold(out, outsz, chan);
}

void history_key_dm(char *out, size_t outsz, const char *account_a, const char *account_b) {
    char a[72], b[72];
    irc_casefold(a, sizeof a, account_a);
    irc_casefold(b, sizeof b, account_b);
    if (strcmp(a, b) > 0) { char t[72]; memcpy(t, a, sizeof t); memcpy(a, b, sizeof a); memcpy(b, t, sizeof b); }
    snprintf(out, outsz, "\x01%s\x01%s", a, b);
}

int history_key_is_dm(const char *key) { return key[0] == '\x01'; }

void hist_buf_add(hist_buf_t *b, int cap, const hist_entry_t *entry) {
    if (cap <= 0) return;
    if (!b->e || b->cap != cap) { /* first message, or history_size changed on a rehash: start over at the new size */
        free(b->e);
        b->e = calloc((size_t)cap, sizeof *b->e);
        b->cap = b->e ? cap : 0;
        b->head = b->n = 0;
        if (!b->e) return;
    }
    int idx = (b->head + b->n) % b->cap;
    if (b->n == b->cap) b->head = (b->head + 1) % b->cap; else b->n++;
    b->e[idx] = *entry;
    b->last_ms = entry->ms;
}

const hist_entry_t *hist_buf_at(const hist_buf_t *b, int i) {
    if (!b->e || i < 0 || i >= b->n) return NULL;
    return &b->e[(b->head + i) % b->cap];
}

hist_buf_t *history_get(server_t *srv, const char *key) {
    hist_buf_t *b;
    HASH_FIND_STR(srv->history, key, b);
    return b;
}

void history_add(server_t *srv, const char *key, int cap, const hist_entry_t *entry) {
    hist_buf_t *b = history_get(srv, key);
    if (!b) {
        if (HASH_COUNT(srv->history) >= HIST_MAX_BUFFERS) { /* drop the conversation that has been quiet the longest */
            hist_buf_t *cur, *tmp, *oldest = NULL;
            HASH_ITER(hh, srv->history, cur, tmp) if (!oldest || cur->last_ms < oldest->last_ms) oldest = cur;
            if (oldest) { HASH_DEL(srv->history, oldest); free(oldest->e); free(oldest); }
        }
        b = calloc(1, sizeof *b);
        if (!b) return;
        snprintf(b->key, sizeof b->key, "%s", key);
        HASH_ADD_STR(srv->history, key, b);
    }
    hist_buf_add(b, cap, entry);
    srv->history_dirty = 1;
}

void history_free(server_t *srv) {
    hist_buf_t *b, *tmp;
    HASH_ITER(hh, srv->history, b, tmp) { HASH_DEL(srv->history, b); free(b->e); free(b); }
}

/* --- persistence ----------------------------------------------------------- */

static int history_path(const server_t *srv, char *out, size_t outsz) {
    if (!srv->cfg.messages.history_file[0] || srv->cfg.messages.history_size <= 0) return 0;
    config_history_path(&srv->cfg, out, outsz);
    return 1;
}

static const char *jstr(const cJSON *arr, int i) {
    const cJSON *v = cJSON_GetArrayItem(arr, i);
    return cJSON_IsString(v) ? v->valuestring : "";
}

void history_load(server_t *srv) {
    char path[CFG_PATH];
    if (!history_path(srv, path, sizeof path)) return;
    FILE *fp = fopen(path, "rb");
    if (!fp) return; /* first run */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0 || len > (64L << 20)) { fclose(fp); return; }
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(fp); return; }
    size_t rd = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[rd] = '\0';
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!cJSON_IsObject(root)) { cJSON_Delete(root); log_warn("history", "%s is not valid -- starting with no history", path); return; }
    int cap = srv->cfg.messages.history_size, loaded = 0;
    cJSON *bufs = cJSON_GetObjectItemCaseSensitive(root, "buffers");
    cJSON *b;
    cJSON_ArrayForEach(b, bufs) {
        if (!b->string || !cJSON_IsArray(b)) continue;
        cJSON *e;
        cJSON_ArrayForEach(e, b) {
            if (!cJSON_IsArray(e) || cJSON_GetArraySize(e) < 7) continue;
            hist_entry_t h;
            memset(&h, 0, sizeof h);
            snprintf(h.msgid, sizeof h.msgid, "%s", jstr(e, 0));
            const cJSON *ms = cJSON_GetArrayItem(e, 1);
            if (!cJSON_IsNumber(ms)) continue;
            h.ms = (long long)ms->valuedouble;
            snprintf(h.sender, sizeof h.sender, "%s", jstr(e, 2));
            snprintf(h.account, sizeof h.account, "%s", jstr(e, 3));
            snprintf(h.verb, sizeof h.verb, "%s", jstr(e, 4));
            snprintf(h.target, sizeof h.target, "%s", jstr(e, 5));
            snprintf(h.text, sizeof h.text, "%s", jstr(e, 6));
            history_add(srv, b->string, cap, &h);
            loaded++;
        }
    }
    cJSON *marks = cJSON_GetObjectItemCaseSensitive(root, "markers");
    cJSON *m;
    cJSON_ArrayForEach(m, marks) {
        if (!m->string || !cJSON_IsNumber(m)) continue;
        const char *sep = strchr(m->string, '\x01');
        if (!sep) continue;
        char acct[72];
        snprintf(acct, sizeof acct, "%.*s", (int)(sep - m->string), m->string);
        server_marker_set(srv, acct, sep + 1, (long long)m->valuedouble);
    }
    cJSON_Delete(root);
    srv->history_dirty = 0;
    if (loaded) log_info("history", "restored %d message(s) from %s", loaded, path);
}

void history_maybe_save(server_t *srv, int force) {
    char path[CFG_PATH];
    if (!history_path(srv, path, sizeof path)) return;
    time_t now = time(NULL);
    if (!srv->history_dirty) return;
    if (!force && now - srv->history_last_save < 30) return; /* debounce: a busy network would rewrite this every second */
    srv->history_last_save = now;

    cJSON *root = cJSON_CreateObject();
    cJSON *bufs = cJSON_AddObjectToObject(root, "buffers");
    hist_buf_t *b, *tmp;
    HASH_ITER(hh, srv->history, b, tmp) {
        cJSON *arr = cJSON_AddArrayToObject(bufs, b->key);
        for (int i = 0; i < b->n; i++) {
            const hist_entry_t *e = hist_buf_at(b, i);
            cJSON *row = cJSON_CreateArray();
            cJSON_AddItemToArray(row, cJSON_CreateString(e->msgid));
            cJSON_AddItemToArray(row, cJSON_CreateNumber((double)e->ms));
            cJSON_AddItemToArray(row, cJSON_CreateString(e->sender));
            cJSON_AddItemToArray(row, cJSON_CreateString(e->account));
            cJSON_AddItemToArray(row, cJSON_CreateString(e->verb));
            cJSON_AddItemToArray(row, cJSON_CreateString(e->target));
            cJSON_AddItemToArray(row, cJSON_CreateString(e->text));
            cJSON_AddItemToArray(arr, row);
        }
    }
    cJSON *marks = cJSON_AddObjectToObject(root, "markers");
    for (const struct marker *m = srv->markers; m; m = m->hh.next) cJSON_AddNumberToObject(marks, m->key, (double)m->ms);
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) return;

    char tmpath[CFG_PATH + 8];
    snprintf(tmpath, sizeof tmpath, "%s.tmp", path);
    int fd = open(tmpath, O_WRONLY | O_CREAT | O_TRUNC, 0600); /* private conversations live here */
    int ok = 0;
    if (fd >= 0) {
        FILE *fp = fdopen(fd, "wb");
        if (fp) {
            size_t len = strlen(text);
            ok = fwrite(text, 1, len, fp) == len && fflush(fp) == 0 && fsync(fd) == 0;
            if (fclose(fp) != 0) ok = 0;
        } else close(fd);
    }
    free(text);
    if (ok && rename(tmpath, path) == 0) srv->history_dirty = 0;
    else { unlink(tmpath); log_error("history", "could not write %s -- will retry", path); }
}
