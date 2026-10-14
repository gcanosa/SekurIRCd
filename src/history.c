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

/* Longest each string may be (the old fixed field sizes, less the NUL). */
static const size_t HIST_FIELD_MAX[6] = {47, 159, 31, 7, 71, 419};

/* Copies `src`'s six strings into one malloc'd block and points `dst` at it. */
static int entry_dup(hist_entry_t *dst, const hist_entry_t *src) {
    const char *in[6] = {src->msgid, src->sender, src->account, src->verb, src->target, src->text};
    size_t len[6], total = 0;
    for (int i = 0; i < 6; i++) {
        if (!in[i]) in[i] = "";
        len[i] = strnlen(in[i], HIST_FIELD_MAX[i]);
        total += len[i] + 1;
    }
    char *blob = malloc(total), *p = blob;
    if (!blob) return -1;
    const char *out[6];
    for (int i = 0; i < 6; i++) {
        memcpy(p, in[i], len[i]);
        p[len[i]] = '\0';
        out[i] = p;
        p += len[i] + 1;
    }
    dst->ms = src->ms;
    dst->msgid = out[0]; dst->sender = out[1]; dst->account = out[2];
    dst->verb = out[3]; dst->target = out[4]; dst->text = out[5];
    return 0;
}

static void entry_release(hist_entry_t *e) {
    free((void *)e->msgid); /* msgid is the start of the block */
    memset(e, 0, sizeof *e);
}

void hist_buf_clear(hist_buf_t *b) {
    for (int i = 0; i < b->n; i++) entry_release(&b->e[(b->head + i) % b->cap]);
    free(b->e);
    b->e = NULL;
    b->alloc = b->head = b->n = 0;
}

void hist_buf_add(hist_buf_t *b, int cap, const hist_entry_t *entry) {
    if (cap <= 0) return;
    if (b->e && b->cap != cap) hist_buf_clear(b); /* history_size changed on a rehash: start over at the new size */
    b->cap = cap;
    hist_entry_t copy;
    if (entry_dup(&copy, entry) != 0) return;
    if (b->n == b->alloc && b->alloc < cap) { /* full but not at the cap yet: double (head is still 0 here) */
        int na = b->alloc ? b->alloc * 2 : 4;
        if (na > cap) na = cap;
        hist_entry_t *ne = realloc(b->e, (size_t)na * sizeof *ne);
        if (!ne) { entry_release(&copy); return; }
        b->e = ne;
        b->alloc = na;
    }
    int idx;
    if (b->n == b->cap) { /* ring full: overwrite the oldest */
        idx = b->head;
        entry_release(&b->e[idx]);
        b->head = (b->head + 1) % b->cap;
    } else {
        idx = b->n++;
    }
    b->e[idx] = copy;
    b->last_ms = copy.ms;
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
            if (oldest) { HASH_DEL(srv->history, oldest); hist_buf_clear(oldest); free(oldest); }
        }
        b = calloc(1, sizeof *b);
        if (!b) return;
        snprintf(b->key, sizeof b->key, "%s", key);
        HASH_ADD_STR(srv->history, key, b);
    }
    hist_buf_add(b, cap, entry);
    srv->history_dirty = 1;
}

void history_rename_channel(server_t *srv, const char *oldname, const char *newname) {
    char ok[160], nk[160];
    history_key_channel(ok, sizeof ok, oldname);
    history_key_channel(nk, sizeof nk, newname);
    hist_buf_t *b = history_get(srv, ok), *stale = history_get(srv, nk);
    if (!b || b == stale) return;
    if (stale) { HASH_DEL(srv->history, stale); hist_buf_clear(stale); free(stale); }
    HASH_DEL(srv->history, b);
    snprintf(b->key, sizeof b->key, "%s", nk);
    HASH_ADD_STR(srv->history, key, b);
    srv->history_dirty = 1;
}

void history_free(server_t *srv) {
    hist_buf_t *b, *tmp;
    HASH_ITER(hh, srv->history, b, tmp) { HASH_DEL(srv->history, b); hist_buf_clear(b); free(b); }
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
            const cJSON *ms = cJSON_GetArrayItem(e, 1);
            if (!cJSON_IsNumber(ms)) continue;
            hist_entry_t h = {.ms = (long long)ms->valuedouble, .msgid = jstr(e, 0), .sender = jstr(e, 2), .account = jstr(e, 3),
                              .verb = jstr(e, 4), .target = jstr(e, 5), .text = jstr(e, 6)};
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

    /* Streamed straight to the file: a cJSON tree of every kept message (and its printed copy) used to be built here,
     * a spike of tens of MB each time a busy network's history changed. */
    char tmpath[CFG_PATH + 8];
    snprintf(tmpath, sizeof tmpath, "%s.tmp", path);
    int fd = open(tmpath, O_WRONLY | O_CREAT | O_TRUNC, 0600); /* private conversations live here */
    FILE *fp = fd >= 0 ? fdopen(fd, "wb") : NULL;
    int ok = 0;
    if (fp) {
        fputs("{\"buffers\":{", fp);
        hist_buf_t *b, *tmp;
        int first_buf = 1;
        HASH_ITER(hh, srv->history, b, tmp) {
            if (!first_buf) fputc(',', fp);
            first_buf = 0;
            json_put_string(fp, b->key);
            fputs(":[", fp);
            for (int i = 0; i < b->n; i++) {
                const hist_entry_t *e = hist_buf_at(b, i);
                fputs(i ? ",[" : "[", fp);
                json_put_string(fp, e->msgid);
                fprintf(fp, ",%lld,", e->ms);
                json_put_string(fp, e->sender);
                fputc(',', fp);
                json_put_string(fp, e->account);
                fputc(',', fp);
                json_put_string(fp, e->verb);
                fputc(',', fp);
                json_put_string(fp, e->target);
                fputc(',', fp);
                json_put_string(fp, e->text);
                fputc(']', fp);
            }
            fputc(']', fp);
        }
        fputs("},\"markers\":{", fp);
        for (const struct marker *m = srv->markers; m; m = m->hh.next) {
            json_put_string(fp, m->key);
            fprintf(fp, ":%lld%s", m->ms, m->hh.next ? "," : "");
        }
        fputs("}}", fp);
        ok = ferror(fp) == 0 && fflush(fp) == 0 && fsync(fd) == 0;
        if (fclose(fp) != 0) ok = 0;
    } else if (fd >= 0) {
        close(fd);
    }
    if (ok && rename(tmpath, path) == 0) srv->history_dirty = 0;
    else { unlink(tmpath); log_error("history", "could not write %s -- will retry", path); }
}
