/* The stats collector. Off unless stats.toml (next to services.toml, else ../stats/stats.toml from it) says
 * [collector] enabled = true. When on, it asks the hub for its stats feed (link.c's SVCSTATS: a network snapshot every
 * sample_seconds, plus link/split/ban/stats-line events as they happen) and appends each as one JSON object per line
 * to stats/events.log, which stats/netstats.py loads into its database and empties.
 *
 * Records ("t" = unix time, "k" = kind):
 *   net      users channels regchans opers away tls logged peak hub_start      (SVCSTATNET)
 *   srv      name sid uplink hop users linked_at synced desc                   (SVCSTATSRV, one per server)
 *   end      accounts regchans_cs svc_start svc_version                        (SVCSTATEND + our own numbers)
 *   link     name uplink desc         split  name uplink reason                (SVCSTATEV LINK / SPLIT)
 *   ban      type by dur mask reason                                           (SVCSTATEV BAN)
 *   statline name text                                                         (SVCSTATLINE: a server's stats line)
 *   session  ev=up|down               svc  ev=start|stop version               (this daemon and its hub link)
 *   announced id                                                               (an announce.queue entry went out)
 * The writer and netstats.py take a POSIX lock (fcntl here, fcntl.lockf there) on the file, so netstats can rename it
 * away between our appends. */
#include "svc.h"
#include "../src/log.h"
#include "../src/vendor/cJSON.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static struct {
    int enabled, sample;
    char conf[512], log[512];
    time_t conf_mtime, last_check, last_req, started;
    int session;
    char *batch;       /* the snapshot being received (SVCSTATNET .. SVCSTATEND), written in one go */
    size_t batch_len;
} S;

static void dir_of(const char *path, char *out, size_t outsz) {
    const char *slash = strrchr(path, '/');
    if (!slash) snprintf(out, outsz, ".");
    else snprintf(out, outsz, "%.*s", (int)(slash - path), path);
}

static void load(void) {
    struct stat sb;
    int was = S.enabled;
    S.enabled = 0;
    S.conf_mtime = stat(S.conf, &sb) == 0 ? sb.st_mtime : 0;
    if (!S.conf_mtime) { if (was) log_info("stats", "%s is gone -- collector off", S.conf); return; }
    FILE *fp = fopen(S.conf, "rb");
    if (!fp) return;
    toml_result_t res = toml_parse_file(fp);
    fclose(fp);
    if (!res.ok) { log_warn("stats", "invalid TOML in %s: %s -- collector off", S.conf, res.errmsg); toml_free(res); return; }
    toml_node_t *c = tx_table(&res.toptab, "collector");
    toml_node_t *en = tx_bool(c, "enabled"), *sm = tx_int(c, "sample_seconds"), *lg = tx_string(c, "log");
    S.enabled = en && en->u.boolean;
    S.sample = sm ? (int)sm->u.int64 : 60;
    if (S.sample < 10) S.sample = 10;
    if (S.sample > 3600) S.sample = 3600;
    char dir[512];
    dir_of(S.conf, dir, sizeof dir);
    const char *rel = lg && lg->u.s[0] ? lg->u.s : "events.log";
    if (rel[0] == '/') snprintf(S.log, sizeof S.log, "%s", rel);
    else snprintf(S.log, sizeof S.log, "%s/%s", dir, rel);
    toml_free(res);
    if (S.enabled != was) log_info("stats", "collector %s (%s, every %ds)", S.enabled ? "on" : "off", S.log, S.sample);
}

void st_config(const char *services_config_path) {
    char dir[512];
    dir_of(services_config_path, dir, sizeof dir);
    /* make install keeps every config in one directory; a git checkout has stats/ next to services/ */
    snprintf(S.conf, sizeof S.conf, "%s/stats.toml", dir);
    struct stat sb;
    if (stat(S.conf, &sb) != 0) snprintf(S.conf, sizeof S.conf, "%s/../stats/stats.toml", dir);
    S.started = time(NULL);
    load();
}

static void write_text(const char *text, size_t len) {
    int fd = open(S.log, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd < 0) { log_warn("stats", "can't write %s: %s", S.log, strerror(errno)); return; }
    struct flock lk = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    (void)fcntl(fd, F_SETLKW, &lk);
    while (len > 0) {
        ssize_t n = write(fd, text, len);
        if (n <= 0) break;
        text += n; len -= (size_t)n;
    }
    close(fd); /* releases the lock */
}

/* One record: obj gets "t" and "k", is printed as a line and freed. Inside a snapshot it waits for SVCSTATEND. */
static void emit(const char *kind, cJSON *obj) {
    cJSON_AddNumberToObject(obj, "t", (double)time(NULL));
    cJSON_AddStringToObject(obj, "k", kind);
    char *s = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!s) return;
    size_t n = strlen(s);
    if (S.batch) {
        char *nb = realloc(S.batch, S.batch_len + n + 2);
        if (nb) { S.batch = nb; memcpy(S.batch + S.batch_len, s, n); S.batch_len += n; S.batch[S.batch_len++] = '\n'; }
    } else {
        s[n] = '\n'; /* cJSON's buffer: overwrite the NUL, write n + 1 */
        write_text(s, n + 1);
    }
    free(s);
}

static void note(const char *kind, const char *ev) {
    if (!S.enabled) return;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ev", ev);
    if (!strcmp(kind, "svc")) cJSON_AddStringToObject(o, "version", SERVICES_VERSION);
    emit(kind, o);
}

void st_started(void) { note("svc", "start"); }
void st_stopping(void) { note("svc", "stop"); }

void st_session_start(void) {
    S.session = 1;
    S.last_req = 0;
    free(S.batch); S.batch = NULL; S.batch_len = 0;
    note("session", "up");
}

void st_session_end(void) {
    if (!S.session) return;
    S.session = 0;
    free(S.batch); S.batch = NULL; S.batch_len = 0;
    note("session", "down");
}

/* announce.queue, next to events.log: one JSON object per line, {"id": n, "text": "..."}, appended by netstats.py (the planned
 * maintenance notices). Sent to the hub as SVCGLOBAL and reported back as an "announced" record. Left in place while the hub
 * link is down, so nothing is lost. */
static void send_announcements(void) {
    char path[600], dir[512];
    dir_of(S.log, dir, sizeof dir);
    snprintf(path, sizeof path, "%s/announce.queue", dir);
    int fd = open(path, O_RDWR);
    if (fd < 0) return;
    struct flock lk = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    (void)fcntl(fd, F_SETLKW, &lk);
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0 && ftruncate(fd, 0) != 0) n = 0; /* can't empty it: send nothing rather than twice */
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    for (char *save = NULL, *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        cJSON *j = cJSON_Parse(line);
        const cJSON *t = cJSON_GetObjectItem(j, "text"), *id = cJSON_GetObjectItem(j, "id");
        if (cJSON_IsString(t) && t->valuestring[0]) {
            char text[420], out[440];
            size_t k = 0;
            for (const char *p = t->valuestring; *p && k + 1 < sizeof text; p++) text[k++] = (unsigned char)*p < 32 ? ' ' : *p;
            text[k] = '\0';
            snprintf(out, sizeof out, "SVCGLOBAL :%s", text);
            svc_queue_line(out);
            cJSON *o = cJSON_CreateObject();
            cJSON_AddNumberToObject(o, "id", cJSON_IsNumber(id) ? id->valuedouble : 0);
            emit("announced", o);
        }
        cJSON_Delete(j);
    }
}

void st_tick(void) {
    time_t now = time(NULL);
    static time_t last_ann;
    if (S.enabled && S.session && now - last_ann >= 5) { last_ann = now; send_announcements(); }
    if (now - S.last_check >= 30) { /* turned on/off in stats.toml: picked up within 30s, no restart */
        S.last_check = now;
        struct stat sb;
        time_t m = stat(S.conf, &sb) == 0 ? sb.st_mtime : 0;
        if (m != S.conf_mtime) load();
    }
    if (!S.enabled || !S.session || now - S.last_req < S.sample) return;
    S.last_req = now;
    svc_queue_line("SVCSTATS");
}

static long num(const irc_message_t *m, int i) { return i < m->nparams ? atol(m->params[i]) : 0; }
static const char *str(const irc_message_t *m, int i) { return i < m->nparams ? m->params[i] : ""; }

int st_event(irc_message_t *msg) {
    const char *c = msg->command;
    if (strncasecmp(c, "SVCSTAT", 7) != 0) return 0;
    if (!S.enabled) return 1;
    cJSON *o = cJSON_CreateObject();
    if (!strcasecmp(c, "SVCSTATNET")) {
        free(S.batch); S.batch = malloc(1); S.batch_len = 0; /* the snapshot starts */
        static const char *k[] = {"now", "users", "channels", "regchans", "opers", "away", "tls", "logged", "peak", "hub_start"};
        for (int i = 1; i < 10; i++) cJSON_AddNumberToObject(o, k[i], (double)num(msg, i));
        emit("net", o);
    } else if (!strcasecmp(c, "SVCSTATSRV")) {
        cJSON_AddStringToObject(o, "name", str(msg, 0));
        cJSON_AddStringToObject(o, "sid", str(msg, 1));
        cJSON_AddStringToObject(o, "uplink", str(msg, 2));
        cJSON_AddNumberToObject(o, "hop", (double)num(msg, 3));
        cJSON_AddNumberToObject(o, "users", (double)num(msg, 4));
        cJSON_AddNumberToObject(o, "linked_at", (double)num(msg, 5));
        cJSON_AddNumberToObject(o, "synced", (double)num(msg, 6));
        cJSON_AddStringToObject(o, "desc", str(msg, 7));
        emit("srv", o);
    } else if (!strcasecmp(c, "SVCSTATEND")) {
        cJSON_AddNumberToObject(o, "accounts", (double)ns_account_count());
        cJSON_AddNumberToObject(o, "regchans_cs", (double)cs_registered_count());
        cJSON_AddNumberToObject(o, "svc_start", (double)S.started);
        cJSON_AddStringToObject(o, "svc_version", SERVICES_VERSION);
        emit("end", o);
        if (S.batch) { write_text(S.batch, S.batch_len); free(S.batch); S.batch = NULL; S.batch_len = 0; }
    } else if (!strcasecmp(c, "SVCSTATEV") && msg->nparams >= 2) {
        const char *ev = str(msg, 0), *trail = str(msg, msg->nparams - 1);
        if (!strcasecmp(ev, "LINK") || !strcasecmp(ev, "SPLIT")) {
            cJSON_AddStringToObject(o, "name", str(msg, 1));
            cJSON_AddStringToObject(o, "uplink", str(msg, 2));
            cJSON_AddStringToObject(o, ev[0] == 'L' || ev[0] == 'l' ? "desc" : "reason", trail);
            emit(ev[0] == 'L' || ev[0] == 'l' ? "link" : "split", o);
        } else if (!strcasecmp(ev, "BAN") && msg->nparams >= 6) {
            cJSON_AddStringToObject(o, "type", str(msg, 1));
            cJSON_AddStringToObject(o, "by", str(msg, 2));
            cJSON_AddNumberToObject(o, "dur", (double)num(msg, 3));
            cJSON_AddStringToObject(o, "mask", str(msg, 4));
            cJSON_AddStringToObject(o, "reason", trail);
            emit("ban", o);
        } else cJSON_Delete(o);
    } else if (!strcasecmp(c, "SVCSTATLINE") && msg->nparams >= 2) {
        cJSON_AddStringToObject(o, "name", str(msg, 0));
        cJSON_AddStringToObject(o, "text", str(msg, msg->nparams - 1));
        emit("statline", o);
    } else cJSON_Delete(o);
    return 1;
}
