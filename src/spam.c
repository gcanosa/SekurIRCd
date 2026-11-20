/* Spam protection -- see spam.h. Three independent layers, all behind
 * [spam] enabled:
 *   1. new-connection restriction: a fresh connection can't PM users for
 *      new_user_period seconds (services and opers are always reachable);
 *   2. regex content filters loaded from [spam] filters_file;
 *   3. per-client limits: too many distinct recipients, or the same text to
 *      too many recipients, inside a sliding window.
 * Filter file format, one rule per line (# comments and blank lines ok):
 *   [global] <targets> <action> <duration|-> "<reason>" <regex to end of line>
 * e.g.  pcn block - "advertising" (buy|cheap) +viagra
 * A "global" rule is also published to every linked server (netsync SPAMFILTER): they keep it in srv->spam_net, behind
 * their own rules (first match wins, so a local rule or an `allow` overrides it) and replace the whole set whenever
 * the origin sends it again. They live in memory there and come back with the link's burst.
 * Regexes are POSIX ERE, case-insensitive, matched against the text with
 * mIRC colour/formatting codes stripped. */
#include "spam.h"
#include "cmd.h"
#include "link.h"
#include "log.h"
#include "netsync.h"

#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define SPAM_MAX_FILTERS 256
#define SPAM_MIN_REPEAT_LEN 8 /* shorter texts ("hi", "lol") never count as a repeat */

typedef enum { SPAM_BLOCK, SPAM_WARN, SPAM_KILL, SPAM_ZLINE, SPAM_HIDE, SPAM_SHUN, SPAM_ALLOW } spam_action_t;

typedef struct spam_filter {
    unsigned targets;
    spam_action_t action;
    long duration;
    char reason[128];
    char pattern[256];
    unsigned char global; /* published to every linked server */
    char origin[8];       /* SID of the server that published it; "" for a rule of ours */
    regex_t re;
    struct spam_filter *next;
} spam_filter_t;

/* --- rule parsing ------------------------------------------------------------ */

unsigned spam_parse_targets(const char *s) {
    unsigned m = 0;
    if (!s || !*s) return 0;
    for (; *s; s++) {
        switch (*s) {
            case 'p': m |= SPAM_T_PRIVMSG_USER; break;
            case 'c': m |= SPAM_T_PRIVMSG_CHAN; break;
            case 'n': m |= SPAM_T_NOTICE_USER; break;
            case 'N': m |= SPAM_T_NOTICE_CHAN; break;
            case 'a': m |= SPAM_T_AWAY; break;
            case 'q': m |= SPAM_T_QUIT; break;
            case 'P': m |= SPAM_T_PART; break;
            case 't': m |= SPAM_T_TOPIC; break;
            default: return 0;
        }
    }
    return m;
}

static int parse_action(const char *s, spam_action_t *out) {
    if (!strcasecmp(s, "block")) *out = SPAM_BLOCK;
    else if (!strcasecmp(s, "warn")) *out = SPAM_WARN;
    else if (!strcasecmp(s, "kill")) *out = SPAM_KILL;
    else if (!strcasecmp(s, "zline")) *out = SPAM_ZLINE;
    else if (!strcasecmp(s, "hide")) *out = SPAM_HIDE;
    else if (!strcasecmp(s, "shun")) *out = SPAM_SHUN;
    else if (!strcasecmp(s, "allow")) *out = SPAM_ALLOW;
    else return -1;
    return 0;
}

static const char *action_name(spam_action_t a) {
    static const char *names[] = {"block", "warn", "kill", "zline", "hide", "shun", "allow"};
    return names[a];
}

/* Splits one file line into its fields (no regex compile). Returns 0 ok, -1
 * on a syntax error with `err` filled in, 1 for a blank/comment line. */
static int parse_line(const char *line, spam_filter_t *f, char *err, size_t errsz) {
    while (isspace((unsigned char)*line)) line++;
    if (*line == '\0' || *line == '#') return 1;
    int global = 0;
    if (!strncasecmp(line, "global", 6) && isspace((unsigned char)line[6])) {
        global = 1;
        for (line += 6; isspace((unsigned char)*line); line++) ;
    }
    char tgt[16], act[16], dur[16];
    int n = 0;
    if (sscanf(line, "%15s %15s %15s %n", tgt, act, dur, &n) < 3 || n == 0) {
        snprintf(err, errsz, "expected: <targets> <action> <duration|-> \"<reason>\" <regex>");
        return -1;
    }
    memset(f, 0, sizeof *f);
    f->global = (unsigned char)global;
    f->targets = spam_parse_targets(tgt);
    if (!f->targets) { snprintf(err, errsz, "bad targets '%s' (letters from p c n N a q P t)", tgt); return -1; }
    if (parse_action(act, &f->action) != 0) { snprintf(err, errsz, "bad action '%s' (block|warn|kill|zline|hide|shun|allow)", act); return -1; }
    if (strcmp(dur, "-") == 0) f->duration = 0;
    else {
        f->duration = irc_parse_duration(dur);
        if (f->duration < 0) { snprintf(err, errsz, "bad duration '%s'", dur); return -1; }
    }
    const char *p = line + n;
    if (*p != '"') { snprintf(err, errsz, "reason must be in double quotes"); return -1; }
    const char *q = strchr(p + 1, '"');
    if (!q) { snprintf(err, errsz, "unterminated reason quote"); return -1; }
    snprintf(f->reason, sizeof f->reason, "%.*s", (int)(q - p - 1), p + 1);
    q++;
    while (isspace((unsigned char)*q)) q++;
    size_t len = strlen(q);
    while (len && isspace((unsigned char)q[len - 1])) len--;
    if (!len) { snprintf(err, errsz, "missing regex"); return -1; }
    if (len >= sizeof f->pattern) { snprintf(err, errsz, "regex too long (max %zu)", sizeof f->pattern - 1); return -1; }
    memcpy(f->pattern, q, len);
    f->pattern[len] = '\0';
    return 0;
}

/* Compile f->pattern. Rejects backreferences (glibc's matcher goes
 * exponential on them) and any pattern that matches the empty string --
 * that would hit every single message. */
static int compile_rule(spam_filter_t *f, char *err, size_t errsz) {
    for (const char *c = f->pattern; *c; c++) {
        if (*c == '\\' && c[1] >= '1' && c[1] <= '9') {
            snprintf(err, errsz, "backreferences are not allowed");
            return -1;
        }
        if (*c == '\\' && c[1]) c++;
    }
    int rc = regcomp(&f->re, f->pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    if (rc != 0) {
        char eb[100];
        regerror(rc, &f->re, eb, sizeof eb);
        snprintf(err, errsz, "invalid regex: %s", eb);
        return -1;
    }
    if (regexec(&f->re, "", 0, NULL, 0) == 0) {
        regfree(&f->re);
        snprintf(err, errsz, "regex matches the empty string (would match every message)");
        return -1;
    }
    return 0;
}

static void format_rule(const spam_filter_t *f, char *out, size_t outsz) {
    char tg[10], dur[24];
    int n = 0;
    static const struct { unsigned bit; char c; } T[] = {
        {SPAM_T_PRIVMSG_USER, 'p'}, {SPAM_T_PRIVMSG_CHAN, 'c'}, {SPAM_T_NOTICE_USER, 'n'},
        {SPAM_T_NOTICE_CHAN, 'N'}, {SPAM_T_AWAY, 'a'}, {SPAM_T_QUIT, 'q'}, {SPAM_T_PART, 'P'}, {SPAM_T_TOPIC, 't'},
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) if (f->targets & T[i].bit) tg[n++] = T[i].c;
    tg[n] = '\0';
    if (f->duration) snprintf(dur, sizeof dur, "%lds", f->duration); else snprintf(dur, sizeof dur, "-");
    snprintf(out, outsz, "%s %s %s \"%s\" %s", tg, action_name(f->action), dur, f->reason, f->pattern);
}

/* "[global] " for a rule we publish, "[global from hub.example.org] " for one we were sent. */
static void rule_tag(server_t *srv, const spam_filter_t *f, char *out, size_t outsz) {
    out[0] = '\0';
    if (f->origin[0]) {
        netserver_t *o = netsync_find_sid(srv, f->origin);
        snprintf(out, outsz, "[global from %s] ", o ? o->name : f->origin);
    } else if (f->global) snprintf(out, outsz, "[global] ");
}

/* Our rules, then the ones other servers sent: the order they are checked in, and the numbers SPAMFILTER DEL takes. */
static void rule_line(server_t *srv, const spam_filter_t *f, int n, char *out, size_t outsz) {
    char rule[600], tag[80];
    format_rule(f, rule, sizeof rule);
    rule_tag(srv, f, tag, sizeof tag);
    snprintf(out, outsz, "#%d %s%s", n, tag, rule);
}

void spam_stats(server_t *srv, client_t *cl) {
    int n = 0;
    for (const spam_filter_t *f = srv->spam_filters; f; f = f->next) {
        char line[760];
        rule_line(srv, f, ++n, line, sizeof line);
        client_reply(cl, N_STATSDEBUG, (const char *[]){"f"}, 1, line);
    }
    for (const spam_filter_t *f = srv->spam_net; f; f = f->next) {
        char line[760];
        rule_line(srv, f, ++n, line, sizeof line);
        client_reply(cl, N_STATSDEBUG, (const char *[]){"f"}, 1, line);
    }
    char sum[160];
    snprintf(sum, sizeof sum, "%d filter%s loaded (%s), %ld message%s acted on since start", n, n == 1 ? "" : "s",
             srv->cfg.spam.enabled && srv->cfg.spam.filters_enabled ? "active" : "not active", srv->spam_hits, srv->spam_hits == 1 ? "" : "s");
    client_reply(cl, N_STATSDEBUG, (const char *[]){"f"}, 1, sum);
}

/* --- rule list --------------------------------------------------------------- */

static void list_free(spam_filter_t **head) {
    spam_filter_t *f = *head;
    while (f) {
        spam_filter_t *next = f->next;
        regfree(&f->re);
        free(f);
        f = next;
    }
    *head = NULL;
}

void spam_free(server_t *srv) {
    list_free(&srv->spam_filters);
    list_free(&srv->spam_net);
}

static int list_count(const server_t *srv) {
    int n = 0;
    for (const spam_filter_t *f = srv->spam_filters; f; f = f->next) n++;
    return n;
}

static void list_append(spam_filter_t **head, spam_filter_t *f) {
    spam_filter_t **pp = head;
    while (*pp) pp = &(*pp)->next;
    f->next = NULL;
    *pp = f;
}

static void rewrite_without(const char *path, const spam_filter_t *victim);

/* --- global rules: what we publish, and what other servers sent us -------------------------------------------- */

/* The rule `f` as the wire carries it: format_rule's text (the file's "global" word is implied). */
static void send_rules(server_t *srv, link_conn_t *to, const spam_filter_t *f, const char *origin) {
    char rule[600];
    format_rule(f, rule, sizeof rule);
    netsync_spamfilter(srv, to, origin, rule);
}

/* Our own global rules, as a complete set: every server drops what it had from us first, so a deleted rule goes too.
 * `to` NULL = every link (a change), a link = its burst. */
static void send_own(server_t *srv, link_conn_t *to) {
    netsync_spamfilter(srv, to, NULL, NULL);
    for (const spam_filter_t *f = srv->spam_filters; f; f = f->next)
        if (f->global) send_rules(srv, to, f, NULL);
}

static void publish_global(server_t *srv) { send_own(srv, NULL); }

/* A new link: our set, then every set we hold from other servers (the link drops those that already lie behind it). */
void spam_burst(server_t *srv, link_conn_t *lc) {
    send_own(srv, lc);
    for (const spam_filter_t *f = srv->spam_net; f; f = f->next) {
        const spam_filter_t *e = srv->spam_net;
        while (e != f && strcmp(e->origin, f->origin) != 0) e = e->next;
        if (e != f) continue; /* this origin's set already went out with its first rule */
        netsync_spamfilter(srv, lc, f->origin, NULL);
        for (const spam_filter_t *g = f; g; g = g->next)
            if (strcmp(g->origin, f->origin) == 0) send_rules(srv, lc, g, f->origin);
    }
}

/* From a server's SPAMFILTER line: CLEAR drops everything `origin` sent, ADD takes one rule (same syntax as the file). */
void spam_net_receive(server_t *srv, const char *origin, const char *verb, const char *rule) {
    spam_filter_t **pp = &srv->spam_net;
    if (!strcasecmp(verb, "CLEAR")) {
        while (*pp) {
            spam_filter_t *f = *pp;
            if (strcmp(f->origin, origin) != 0) { pp = &f->next; continue; }
            *pp = f->next;
            regfree(&f->re);
            free(f);
        }
        return;
    }
    if (strcasecmp(verb, "ADD") != 0 || !rule) return;
    int n = 0;
    for (const spam_filter_t *f = srv->spam_net; f; f = f->next) n++;
    spam_filter_t *f = malloc(sizeof *f);
    if (!f) return;
    char err[160] = "";
    if (n >= SPAM_MAX_FILTERS) snprintf(err, sizeof err, "too many global rules (max %d)", SPAM_MAX_FILTERS);
    else if (parse_line(rule, f, err, sizeof err) != 0) { if (!err[0]) snprintf(err, sizeof err, "empty rule"); }
    else compile_rule(f, err, sizeof err); /* leaves err empty when it compiles */
    if (err[0]) {
        log_warn("spam", "global rule from %s refused: %s", origin, err);
        free(f);
        return;
    }
    f->global = 1;
    snprintf(f->origin, sizeof f->origin, "%s", origin);
    list_append(&srv->spam_net, f);
}

/* A DEL routed here (netsync): drops our own global rule that reads `rule` -- from the file too -- and sends the set again. */
void spam_global_del(server_t *srv, const char *rule, const char *by) {
    spam_filter_t q;
    char err[160];
    if (parse_line(rule, &q, err, sizeof err) != 0) return;
    for (spam_filter_t **pp = &srv->spam_filters; *pp; pp = &(*pp)->next) {
        spam_filter_t *f = *pp;
        if (!f->global || f->targets != q.targets || f->action != q.action || strcmp(f->pattern, q.pattern) != 0) continue;
        *pp = f->next;
        char path[CFG_PATH], note[500];
        if (config_spamfilters_path(&srv->cfg, path, sizeof path)) rewrite_without(path, f);
        snprintf(note, sizeof note, "%s removed global spam filter (%s's): %s", by, srv->cfg.server.name, f->pattern);
        server_notify_network(srv, note);
        regfree(&f->re);
        free(f);
        publish_global(srv);
        return;
    }
}

int spam_reload(server_t *srv) {
    char path[CFG_PATH];
    if (!srv->cfg.spam.filters_enabled) { list_free(&srv->spam_filters); publish_global(srv); return -1; }
    if (!config_spamfilters_path(&srv->cfg, path, sizeof path)) return -1; /* memory-only rules stay */
    list_free(&srv->spam_filters); /* ours only: what other servers sent stays until they send it again */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (srv->cfg.spam.enabled) log_warn("spam", "cannot open filters_file %s -- no content filters loaded", path);
        publish_global(srv);
        return -1;
    }
    char line[700], err[160];
    int lineno = 0, loaded = 0;
    while (fgets(line, sizeof line, fp)) {
        lineno++;
        spam_filter_t *f = malloc(sizeof *f);
        if (!f) break;
        int rc = parse_line(line, f, err, sizeof err);
        if (rc == 0 && loaded >= SPAM_MAX_FILTERS) { snprintf(err, sizeof err, "too many rules (max %d)", SPAM_MAX_FILTERS); rc = -1; }
        if (rc == 0 && compile_rule(f, err, sizeof err) != 0) rc = -1;
        if (rc != 0) {
            if (rc < 0) log_warn("spam", "%s:%d skipped: %s", path, lineno, err);
            free(f);
            continue;
        }
        list_append(&srv->spam_filters, f);
        loaded++;
    }
    fclose(fp);
    log_info("spam", "loaded %d spam filter(s) from %s", loaded, path);
    publish_global(srv);
    return loaded;
}

/* --- per-client tracking ----------------------------------------------------- */

static uint32_t fnv(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) { h ^= (unsigned char)tolower((unsigned char)*s); h *= 16777619u; }
    return h;
}

void spam_track(client_t *cl, const char *target, const char *text, time_t now,
                long window, int *distinct_targets, int *same_text_targets) {
    uint32_t tg = fnv(target), tx = fnv(text);
    int hit = -1;
    for (int i = 0; i < SPAM_TRACK; i++)
        if (cl->spam_ring[i].at && cl->spam_ring[i].tgt == tg && cl->spam_ring[i].txt == tx) { hit = i; break; }
    if (hit < 0) { /* ponytail: 32-slot ring, a bot can flush it with 32 varied texts -- the flood limiter caps that rate */
        hit = cl->spam_head;
        cl->spam_head = (cl->spam_head + 1) % SPAM_TRACK;
    }
    cl->spam_ring[hit].tgt = tg;
    cl->spam_ring[hit].txt = tx;
    cl->spam_ring[hit].at = now;

    int distinct = 0, same = 0;
    for (int i = 0; i < SPAM_TRACK; i++) {
        if (!cl->spam_ring[i].at || now - cl->spam_ring[i].at > window) continue;
        if (cl->spam_ring[i].txt == tx) same++;
        int seen = 0;
        for (int j = 0; j < i && !seen; j++)
            seen = cl->spam_ring[j].at && now - cl->spam_ring[j].at <= window && cl->spam_ring[j].tgt == cl->spam_ring[i].tgt;
        if (!seen) distinct++;
    }
    *distinct_targets = distinct;
    *same_text_targets = same;
}

/* --- enforcement ------------------------------------------------------------- */

static int is_exempt(const cfg_spam_t *sp, const client_t *cl) {
    if (cl->fd < 0 || cl->is_service) return 1;
    if (sp->exempt_opers && OPER_CAN(cl, OPER_PRIV_IMMUNE)) return 1;
    if (sp->exempt_identified && cl->account[0]) return 1;
    return 0;
}

static void snippet(const char *text, char *out, size_t outsz) {
    size_t o = 0;
    for (; *text && o + 1 < outsz && o < 60; text++) out[o++] = (unsigned char)*text < 0x20 ? '?' : *text;
    out[o] = '\0';
}

/* Carries out `act` for a hit. Returns 1 if the message should be dropped,
 * 2 if it should be dropped while looking sent to the sender (hide/shun). */
static int apply_action(server_t *srv, client_t *cl, spam_action_t act, long duration,
                        const char *reason, const char *what, const char *text, int quiet) {
    srv->spam_hits++;
    char prefix[320], snip[80], note[700];
    client_prefix(cl, prefix, sizeof prefix);
    snippet(text, snip, sizeof snip);
    snprintf(note, sizeof note, "Spam: %s [%s] %s (%s): \"%s\" -> %s", prefix, cl->ip, action_name(act), reason, snip, what);
    server_notify_opers(srv, note);
    log_info("spam", "%s", note);

    switch (act) {
        case SPAM_ALLOW: /* run_filters stops at an allow before getting here */
        case SPAM_WARN:
            return 0;
        case SPAM_BLOCK: {
            if (!quiet) {
                char m[300];
                snprintf(m, sizeof m, "Message to %s blocked: %s", what, reason);
                notice_self(srv, cl, m);
            }
            return 1;
        }
        case SPAM_SHUN:
            if (cl->ip[0]) { /* network-wide S-line on *@ip: every later message vanishes too */
                long dur = duration > 0 ? duration : srv->cfg.spam.zline_duration;
                char mask[80], sr[200];
                snprintf(mask, sizeof mask, "*@%s", cl->ip);
                snprintf(sr, sizeof sr, "Spam: %s", reason);
                server_kline_add(srv, mask, sr, "spam", "S", dur);
                netsync_shun(srv, mask, "spam", dur > 0 ? (long)time(NULL) + dur : 0, sr);
            }
            /* fall through */
        case SPAM_HIDE:
            return 2;
        case SPAM_KILL:
        case SPAM_ZLINE: {
            snprintf(cl->quit_reason, sizeof cl->quit_reason, "Spam: %s", reason);
            client_mark_quit(cl);
            if (act == SPAM_ZLINE && cl->ip[0]) {
                long dur = duration > 0 ? duration : srv->cfg.spam.zline_duration;
                char zr[200];
                snprintf(zr, sizeof zr, "Spam: %s", reason);
                server_kline_add(srv, cl->ip, zr, "spam", "Z", dur);
                for (client_t *c = srv->all_clients; c; c = c->all_next) {
                    if (c == cl || c->fd < 0 || c->quitting || OPER_CAN(c, OPER_PRIV_IMMUNE)) continue;
                    if (strcmp(c->ip, cl->ip) != 0) continue;
                    snprintf(c->quit_reason, sizeof c->quit_reason, "%s", cl->quit_reason);
                    client_mark_quit(c);
                }
            }
            return 1;
        }
    }
    return 1;
}

/* Strip mIRC colour + formatting bytes so "\x03""4buy\x02 now" still matches. */
static void strip_codes(char *dst, size_t dstsz, const char *src) {
    size_t di = 0;
    for (const char *p = src; *p && di + 1 < dstsz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == 0x02 || c == 0x0F || c == 0x11 || c == 0x16 || c == 0x1D || c == 0x1E || c == 0x1F) continue;
        if (c == 0x03) {
            for (int n = 0; n < 2 && isdigit((unsigned char)p[1]); n++) p++;
            if (p[1] == ',') { p++; for (int n = 0; n < 2 && isdigit((unsigned char)p[1]); n++) p++; }
            continue;
        }
        dst[di++] = (char)c;
    }
    dst[di] = '\0';
}

/* Runs the regex rules for `kind`; first match wins. Returns apply_action's verdict. */
int spam_filter_count(server_t *srv) {
    int n = 0;
    for (spam_filter_t *f = srv->spam_filters; f; f = f->next) n++;
    for (spam_filter_t *f = srv->spam_net; f; f = f->next) n++;
    return n;
}

/* Our rules (only while [spam] enabled and filters_enabled), then the global ones other servers sent: those apply here
 * whatever this server's own switches say -- a leaf can't switch the hub's rules off, only override them with a rule of
 * its own above them (`allow` lets the text through untouched). */
static int run_filters(server_t *srv, client_t *cl, unsigned kind, const char *what,
                       const char *text, int quiet) {
    int own = srv->cfg.spam.enabled && srv->cfg.spam.filters_enabled;
    if (!(own && srv->spam_filters) && !srv->spam_net) return 0;
    char clean[512];
    strip_codes(clean, sizeof clean, text);
    spam_filter_t *lists[2] = {own ? srv->spam_filters : NULL, srv->spam_net};
    for (int i = 0; i < 2; i++)
        for (spam_filter_t *f = lists[i]; f; f = f->next) {
            if (!(f->targets & kind)) continue;
            if (regexec(&f->re, clean, 0, NULL, 0) != 0) continue;
            if (f->action == SPAM_ALLOW) return 0;
            return apply_action(srv, cl, f->action, f->duration, f->reason, what, text, quiet);
        }
    return 0;
}

int spam_check_text(server_t *srv, client_t *cl, unsigned kind, const char *text) {
    if ((!srv->cfg.spam.enabled && !srv->spam_net) || is_exempt(&srv->cfg.spam, cl)) return 0;
    const char *what = kind == SPAM_T_AWAY ? "AWAY" : kind == SPAM_T_QUIT ? "QUIT" : kind == SPAM_T_PART ? "PART" : "TOPIC";
    /* quit/part reasons are swapped for a blank one by the caller, silently */
    return run_filters(srv, cl, kind, what, text, kind == SPAM_T_QUIT || kind == SPAM_T_PART);
}

int spam_check_message(server_t *srv, client_t *cl, const char *target, const char *text, int is_notice) {
    const cfg_spam_t *sp = &srv->cfg.spam;
    if (!sp->enabled && !srv->spam_net) return 0; /* off: only global rules from other servers still run */
    if (cl->fd < 0 || cl->is_service || (sp->exempt_opers && OPER_CAN(cl, OPER_PRIV_IMMUNE))) return 0;

    const char *t = target;
    if (t[0] && strchr("~&@%+", t[0]) && t[1] == '#') t++; /* STATUSMSG (the same prefixes send_msg accepts) */
    int chan = t[0] == '#';
    if (!chan) {
        client_t *dst = server_find_user(srv, t);
        /* Anyone must always be able to reach services and opers (help!). */
        if (dst && (dst->is_service || (dst->umodes & UMODE_O))) return 0;
    }
    time_t now = time(NULL);

    /* exempt_identified is meant for an account this server has trusted for
     * a while, not "anyone who just ran /REGISTER" -- that's instant,
     * unverified self-service (NickServ REGISTER), so without an age floor it's
     * a one-line bypass of every check below. Age-gate it against the same
     * new_user_period a fresh *connection* already has to wait out; with
     * new_user_period == 0 (the feature off) this is always true, same as
     * the old unconditional exemption. */
    int trusted_account = 0;
    if (sp->exempt_identified && cl->account[0]) {
        /* the account's registration time came with the login (services' SVSLOGIN, see cmd_reg.c's svc_command) */
        long created = strcmp(cl->acct_created_for, cl->account) == 0 ? cl->acct_created : 0;
        trusted_account = created > 0 && now - created >= sp->new_user_period;
    }
    if (trusted_account) return 0;

    /* 1. fresh connections can't PM users */
    if (sp->enabled && !chan && sp->new_user_period > 0 && now - cl->signon_time < sp->new_user_period) {
        char m[200];
        snprintf(m, sizeof m, "You must be connected %lds before messaging users (%lds to go)",
                 sp->new_user_period, sp->new_user_period - (long)(now - cl->signon_time));
        if (!is_notice) notice_self(srv, cl, m);
        srv->spam_hits++;
        return 1;
    }

    /* 2. content filters */
    unsigned kind = is_notice ? (chan ? SPAM_T_NOTICE_CHAN : SPAM_T_NOTICE_USER)
                              : (chan ? SPAM_T_PRIVMSG_CHAN : SPAM_T_PRIVMSG_USER);
    int verdict = run_filters(srv, cl, kind, t, text, is_notice);
    if (verdict) return verdict;

    /* 3. recipient / repeat limits */
    if (!sp->enabled) return 0;
    if (sp->max_targets == 0 && sp->max_repeat == 0) return 0;
    if (sp->trust_age > 0 && now - cl->signon_time >= sp->trust_age) return 0;
    char clean[512];
    strip_codes(clean, sizeof clean, text);
    int distinct, same;
    spam_track(cl, t, clean, now, sp->target_window, &distinct, &same);
    int too_many = sp->max_targets > 0 && distinct > sp->max_targets;
    int repeated = sp->max_repeat > 0 && strlen(clean) >= SPAM_MIN_REPEAT_LEN && same >= sp->max_repeat;
    if (!too_many && !repeated) return 0;

    spam_action_t act = SPAM_BLOCK;
    parse_action(sp->limit_action, &act);
    return apply_action(srv, cl, act, 0,
                        too_many ? "too many recipients" : "same message to too many recipients",
                        t, text, is_notice);
}

/* --- SPAMFILTER command ------------------------------------------------------ */

/* Drops the first file line that parses to the same rule as `victim`, leaving
 * comments and every other line untouched. */
static void rewrite_without(const char *path, const spam_filter_t *victim) {
    FILE *in = fopen(path, "r");
    if (!in) return;
    char tmp[CFG_PATH + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *out = fopen(tmp, "w");
    if (!out) { fclose(in); return; }
    char line[700], err[160];
    int dropped = 0;
    while (fgets(line, sizeof line, in)) {
        spam_filter_t f;
        if (!dropped && parse_line(line, &f, err, sizeof err) == 0 && f.targets == victim->targets && f.global == victim->global &&
            f.action == victim->action && strcmp(f.pattern, victim->pattern) == 0) { dropped = 1; continue; }
        fputs(line, out);
    }
    fclose(in);
    if (fclose(out) == 0) rename(tmp, path); else remove(tmp);
}

static void append_rule(const char *path, const spam_filter_t *f) {
    FILE *fp = fopen(path, "a+");
    if (!fp) return;
    if (fseek(fp, -1, SEEK_END) == 0) { /* file didn't end in a newline: don't glue onto its last line */
        int c = fgetc(fp);
        if (c != EOF && c != '\n') fputc('\n', fp);
    }
    fseek(fp, 0, SEEK_END);
    char line[700];
    format_rule(f, line, sizeof line);
    fprintf(fp, "%s%s\n", f->global ? "global " : "", line);
    fclose(fp);
}

static void spamfilter_list(server_t *srv, client_t *cl) {
    if (!srv->cfg.spam.enabled) notice_self(srv, cl, "Note: [spam] enabled = false -- only the global rules from other servers are being enforced");
    else if (!srv->cfg.spam.filters_enabled) notice_self(srv, cl, "Note: [spam] filters_enabled = false -- only the global rules from other servers are being enforced");
    int i = 0;
    for (int pass = 0; pass < 2; pass++)
        for (spam_filter_t *f = pass ? srv->spam_net : srv->spam_filters; f; f = f->next) {
            char m[760];
            rule_line(srv, f, ++i, m, sizeof m);
            notice_self(srv, cl, m);
        }
    if (!i) notice_self(srv, cl, "No spam filters");
    char m[120];
    snprintf(m, sizeof m, "Spam protection has acted on %ld message(s) since start", srv->spam_hits);
    notice_self(srv, cl, m);
}

void cmd_spamfilter(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *sub = msg->nparams > 0 ? msg->params[0] : "LIST";
    if (!strcasecmp(sub, "LIST")) { spamfilter_list(srv, cl); return; }

    if (!strcasecmp(sub, "DEL")) {
        int n = msg->nparams > 1 ? atoi(msg->params[1]) : 0;
        spam_filter_t **pp = &srv->spam_filters;
        int i = 1, remote = 0;
        for (; *pp && i < n; i++) pp = &(*pp)->next;
        if (n >= 1 && !*pp) { /* past our own rules: the global ones other servers sent, numbered on from ours */
            remote = 1;
            for (pp = &srv->spam_net; *pp && i < n; i++) pp = &(*pp)->next;
        }
        if (n < 1 || !*pp) { notice_self(srv, cl, "No such filter number (see SPAMFILTER LIST)"); return; }
        if (remote) { /* another server's global rule: gone here now, and the owner is asked to drop it (its next set confirms) */
            if (netsync_scope_refuse(srv, cl, "SPAMFILTER DEL of another server's global rule")) return;
            spam_filter_t *gone = *pp;
            char rule[600], origin[8], pat[256], note[500], m[300];
            format_rule(gone, rule, sizeof rule);
            snprintf(origin, sizeof origin, "%s", gone->origin);
            snprintf(pat, sizeof pat, "%s", gone->pattern);
            netserver_t *o = netsync_find_sid(srv, origin);
            *pp = gone->next;
            regfree(&gone->re);
            free(gone);
            netsync_spamfilter_del(srv, origin, rule);
            snprintf(note, sizeof note, "%s removed global spam filter from %s: %s", cl->nick, o ? o->name : origin, pat);
            server_notify_opers(srv, note);
            snprintf(m, sizeof m, o ? "Spam filter removed; %s was asked to remove it at the source" : "Spam filter removed here only (%s is not linked)",
                     o ? o->name : origin);
            notice_self(srv, cl, m);
            return;
        }
        spam_filter_t *dead = *pp;
        *pp = dead->next;
        char path[CFG_PATH];
        if (config_spamfilters_path(&srv->cfg, path, sizeof path)) rewrite_without(path, dead);
        char note[400];
        snprintf(note, sizeof note, "%s removed %sspam filter: %s", cl->nick, dead->global ? "global " : "", dead->pattern);
        if (dead->global) { publish_global(srv); server_notify_network(srv, note); } else server_notify_opers(srv, note);
        regfree(&dead->re);
        free(dead);
        notice_self(srv, cl, "Spam filter removed");
        return;
    }

    if (!strcasecmp(sub, "ADD")) {
        if (!srv->cfg.spam.filters_enabled) { notice_self(srv, cl, "Filters are disabled ([spam] filters_enabled = false)"); return; }
        int gl = msg->nparams > 1 && !strcasecmp(msg->params[1], "GLOBAL"); /* ADD GLOBAL <targets> ...: every linked server enforces it */
        const char **a = (const char **)msg->params + (gl ? 1 : 0);        /* a[1..] = targets action duration reason regex */
        if (msg->nparams < (gl ? 7 : 6)) {
            notice_self(srv, cl, "Usage: SPAMFILTER ADD [GLOBAL] <targets> <block|warn|kill|zline|hide|shun|allow> <duration|-> <reason_with_underscores> <regex>");
            return;
        }
        if (gl && netsync_scope_refuse(srv, cl, "SPAMFILTER ADD GLOBAL (a network-wide rule; leave out GLOBAL for this server)")) return;
        if (list_count(srv) >= SPAM_MAX_FILTERS) { notice_self(srv, cl, "Too many spam filters"); return; }
        char reason[128], pattern[256], rule[600], err[160];
        snprintf(reason, sizeof reason, "%s", a[4]);
        for (char *c = reason; *c; c++) { if (*c == '_') *c = ' '; else if (*c == '"') *c = '\''; }
        pattern[0] = '\0';
        for (int i = 5; i < msg->nparams - (gl ? 1 : 0); i++) { /* tolerate a forgotten ':' on a regex containing spaces */
            size_t l = strlen(pattern);
            snprintf(pattern + l, sizeof pattern - l, "%s%s", i > 5 ? " " : "", a[i]);
        }
        snprintf(rule, sizeof rule, "%s%s %s %s \"%s\" %s", gl ? "global " : "", a[1], a[2], a[3], reason, pattern);
        spam_filter_t *f = malloc(sizeof *f);
        if (!f) return;
        if (parse_line(rule, f, err, sizeof err) != 0 || compile_rule(f, err, sizeof err) != 0) {
            char m[220];
            snprintf(m, sizeof m, "Rejected: %s", err);
            notice_self(srv, cl, m);
            free(f);
            return;
        }
        list_append(&srv->spam_filters, f);
        char path[CFG_PATH];
        if (config_spamfilters_path(&srv->cfg, path, sizeof path)) append_rule(path, f);
        char note[500];
        snprintf(note, sizeof note, "%s added %sspam filter #%d: %s", cl->nick, gl ? "global " : "", list_count(srv), pattern);
        if (gl) { publish_global(srv); server_notify_network(srv, note); } else server_notify_opers(srv, note);
        notice_self(srv, cl, gl ? "Global spam filter added (every linked server enforces it)"
                                : srv->cfg.spam.enabled ? "Spam filter added"
                                                        : "Spam filter added (note: [spam] enabled = false, not enforced yet)");
        return;
    }
    notice_self(srv, cl, "Usage: SPAMFILTER [LIST] | ADD [GLOBAL] <targets> <action> <duration|-> <reason> <regex> | DEL <n>");
}
