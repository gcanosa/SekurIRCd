/* Q-lines, RESVs and X-lines -- see xline.h. */
#include "xline.h"
#include "log.h"
#include "vendor/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static const char *type_name(char t) { return t == 'Q' ? "Q-line" : t == 'R' ? "RESV" : "X-line"; }

/* --- storage ------------------------------------------------------------------------------------------------------ */

static void prune(server_t *srv) {
    time_t now = time(NULL);
    xline_t **pp = &srv->xlines;
    while (*pp) {
        if ((*pp)->expires_at && (*pp)->expires_at <= now) {
            xline_t *dead = *pp;
            char snote[350];
            snprintf(snote, sizeof snote, "Expiring %s '%s' (%s)", type_name(dead->type), dead->mask, dead->reason);
            server_notify_opers(srv, snote);
            *pp = dead->next;
            free(dead);
            srv->xlines_dirty = 1;
        } else pp = &(*pp)->next;
    }
}

static int save_path(const server_t *srv, char *out, size_t outsz) {
    char k[CFG_PATH];
    if (!config_klines_path(&srv->cfg, k, sizeof k)) return 0; /* K-lines are memory only: so are these */
    char *slash = strrchr(k, '/');
    if (slash) *slash = '\0';
    snprintf(out, outsz, "%s/xlines.json", slash ? k : ".");
    return 1;
}

static void save(server_t *srv) {
    char path[CFG_PATH + 16];
    if (!save_path(srv, path, sizeof path)) return;
    cJSON *arr = cJSON_CreateArray();
    for (xline_t *x = srv->xlines; x; x = x->next) {
        cJSON *o = cJSON_CreateObject();
        char t[2] = {x->type, 0};
        cJSON_AddStringToObject(o, "type", t);
        cJSON_AddStringToObject(o, "mask", x->mask);
        cJSON_AddStringToObject(o, "reason", x->reason);
        cJSON_AddStringToObject(o, "set_by", x->set_by);
        cJSON_AddNumberToObject(o, "expires_at", (double)x->expires_at);
        cJSON_AddItemToArray(arr, o);
    }
    char *text = cJSON_Print(arr);
    char tmp[CFG_PATH + 24];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (text) { /* fsync before rename: a crash must not leave a truncated file where a good one was */
        FILE *fp = fopen(tmp, "wb");
        if (fp) {
            size_t len = strlen(text);
            int ok = fwrite(text, 1, len, fp) == len && fflush(fp) == 0 && fsync(fileno(fp)) == 0;
            if (fclose(fp) != 0) ok = 0;
            if (ok) rename(tmp, path); else unlink(tmp);
        }
        free(text);
    }
    cJSON_Delete(arr);
}

void xline_flush(server_t *srv) {
    if (!srv->xlines_dirty) return;
    srv->xlines_dirty = 0;
    save(srv);
}

void xline_free(server_t *srv) {
    while (srv->xlines) { xline_t *n = srv->xlines->next; free(srv->xlines); srv->xlines = n; }
}

void xline_load(server_t *srv) {
    char path[CFG_PATH + 16];
    if (!save_path(srv, path, sizeof path)) return;
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0) { fclose(fp); return; }
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(fp); return; }
    size_t rd = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[rd] = '\0';
    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (!arr) return;
    cJSON *o;
    cJSON_ArrayForEach(o, arr) {
        cJSON *t = cJSON_GetObjectItem(o, "type"), *m = cJSON_GetObjectItem(o, "mask"), *r = cJSON_GetObjectItem(o, "reason");
        cJSON *b = cJSON_GetObjectItem(o, "set_by"), *e = cJSON_GetObjectItem(o, "expires_at");
        if (!cJSON_IsString(t) || !cJSON_IsString(m) || !t->valuestring[0] || !strchr("QRX", t->valuestring[0]) || t->valuestring[1]) continue;
        xline_add(srv, t->valuestring[0], m->valuestring, cJSON_IsString(r) ? r->valuestring : "", cJSON_IsString(b) ? b->valuestring : "",
                  cJSON_IsNumber(e) ? (time_t)e->valuedouble : 0);
    }
    cJSON_Delete(arr);
    srv->xlines_dirty = 0; /* what we just read is what the file holds */
    prune(srv);
}

int xline_add(server_t *srv, char type, const char *mask, const char *reason, const char *set_by, time_t expires_at) {
    for (xline_t *x = srv->xlines; x; x = x->next) {
        if (x->type != type || strcasecmp(x->mask, mask) != 0) continue;
        if (expires_at == 0 || x->expires_at == 0) x->expires_at = 0;
        else if (expires_at > x->expires_at) x->expires_at = expires_at;
        srv->xlines_dirty = 1;
        return 0;
    }
    xline_t *x = calloc(1, sizeof *x);
    if (!x) return 0;
    x->type = type;
    snprintf(x->mask, sizeof x->mask, "%s", mask);
    snprintf(x->reason, sizeof x->reason, "%s", reason);
    snprintf(x->set_by, sizeof x->set_by, "%s", set_by);
    x->expires_at = expires_at;
    x->next = srv->xlines;
    srv->xlines = x;
    srv->xlines_dirty = 1;
    return 1;
}

int xline_remove(server_t *srv, char type, const char *mask) {
    for (xline_t **pp = &srv->xlines; *pp; pp = &(*pp)->next) {
        if ((*pp)->type != type || strcasecmp((*pp)->mask, mask) != 0) continue;
        xline_t *dead = *pp;
        *pp = dead->next;
        free(dead);
        srv->xlines_dirty = 1;
        return 1;
    }
    return 0;
}

const char *xline_match(server_t *srv, char type, const char *subject) {
    if (!srv->xlines) return NULL;
    prune(srv);
    char sub[300], pat[300];
    irc_casefold(sub, sizeof sub, subject);
    for (xline_t *x = srv->xlines; x; x = x->next) {
        if (x->type != type) continue;
        irc_casefold(pat, sizeof pat, x->mask);
        if (type == 'X') for (char *c = pat; *c; c++) if (*c == '_') *c = ' ';
        if (irc_glob_match(pat, sub)) return x->reason;
    }
    return NULL;
}

/* --- commands ----------------------------------------------------------------------------------------------------- */

static void expiry_text(time_t t, char *out, size_t outsz) {
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, outsz, "%Y-%m-%d %H:%M:%S UTC", &tmv);
}

static void list_lines(server_t *srv, client_t *cl, char type) {
    prune(srv);
    int any = 0;
    for (xline_t *x = srv->xlines; x; x = x->next) {
        if (x->type != type) continue;
        any = 1;
        char m[700], exp[32];
        if (x->expires_at) { expiry_text(x->expires_at, exp, sizeof exp); snprintf(m, sizeof m, "%s %s (by %s, expires %s): %s", type_name(type), x->mask, x->set_by, exp, x->reason); }
        else snprintf(m, sizeof m, "%s %s (by %s, permanent): %s", type_name(type), x->mask, x->set_by, x->reason);
        notice_self(srv, cl, m);
    }
    if (!any) { char m[64]; snprintf(m, sizeof m, "No %ss", type_name(type)); notice_self(srv, cl, m); }
}

static void add_common(server_t *srv, client_t *cl, irc_message_t *msg, char type) {
    if (msg->nparams < 1) { list_lines(srv, cl, type); return; }
    char mask[256];
    snprintf(mask, sizeof mask, "%s", msg->params[0]);
    if (!mask[0] || mask[strspn(mask, "*?")] == '\0') { /* nothing but wildcards: it would ban every name */
        notice_self(srv, cl, "Refusing a mask that matches everything");
        return;
    }
    if (type == 'R' && mask[0] != '#' && mask[0] != '*' && mask[0] != '?') { notice_self(srv, cl, "A RESV takes a channel name or glob (#warez*)"); return; }
    long duration = 0;
    int argi = 1;
    if (argi < msg->nparams) {
        long d = irc_parse_duration(msg->params[argi]);
        if (d >= 0) { duration = d; argi++; }
    }
    const char *reason = argi < msg->nparams ? msg->params[argi] : "No reason given";
    time_t expires = duration > 0 ? time(NULL) + duration : 0;
    xline_add(srv, type, mask, reason, cl->nick, expires);
    int global = !srv->oper_local || cl->remote; /* a leaf the hub limits to itself keeps its lines to itself */
    if (global) netsync_xline(srv, type, mask, cl->nick, (long)expires, reason);
    char m[500], exp[32];
    if (expires) { expiry_text(expires, exp, sizeof exp); snprintf(m, sizeof m, "%s added: %s (%s) [expires %s]%s", type_name(type), mask, reason, exp, global ? "" : " [this server only: the hub limits your opers to it]"); }
    else snprintf(m, sizeof m, "%s added: %s (%s) [permanent]%s", type_name(type), mask, reason, global ? "" : " [this server only: the hub limits your opers to it]");
    notice_self(srv, cl, m);
}

static void del_common(server_t *srv, client_t *cl, irc_message_t *msg, char type) {
    char m[300];
    int had = xline_remove(srv, type, msg->params[0]);
    if (!srv->oper_local || cl->remote) netsync_unxline(srv, type, msg->params[0]);
    snprintf(m, sizeof m, had ? "Removed %s: %s" : "No such %s: %s", type_name(type), msg->params[0]);
    notice_self(srv, cl, m);
}

void cmd_qline(server_t *srv, client_t *cl, irc_message_t *msg) { add_common(srv, cl, msg, 'Q'); }
void cmd_unqline(server_t *srv, client_t *cl, irc_message_t *msg) { del_common(srv, cl, msg, 'Q'); }
void cmd_resv(server_t *srv, client_t *cl, irc_message_t *msg) { add_common(srv, cl, msg, 'R'); }
void cmd_unresv(server_t *srv, client_t *cl, irc_message_t *msg) { del_common(srv, cl, msg, 'R'); }
void cmd_xline(server_t *srv, client_t *cl, irc_message_t *msg) { add_common(srv, cl, msg, 'X'); }
void cmd_unxline(server_t *srv, client_t *cl, irc_message_t *msg) { del_common(srv, cl, msg, 'X'); }
