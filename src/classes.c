/* Connection classes: config + CLASS ADD + other servers' global ones, in one table. See classes.h. */
#include "classes.h"
#include "log.h"
#include "net.h"
#include "vendor/cJSON.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* --- one definition <-> text ---------------------------------------------------------------------------------------- */

static int valid_name(const char *n) {
    size_t l = strlen(n);
    if (l < 1 || l > 63) return 0;
    for (; *n; n++) if (!isalnum((unsigned char)*n) && !strchr("_.-", *n)) return 0;
    return 1;
}

/* "name max_clients max_per_ip sendq_max flood_max_msgs flood_window host,host,..." -- the form that travels on a link. */
static void format_class(const cfg_class_t *c, char *out, size_t outsz) {
    int n = snprintf(out, outsz, "%s %d %d %d %d %g ", c->name, c->max_clients, c->max_per_ip, c->sendq_max, c->flood_max_msgs, c->flood_window);
    for (int i = 0; i < c->n_hosts && n > 0 && (size_t)n < outsz; i++)
        n += snprintf(out + n, outsz - (size_t)n, "%s%s", i ? "," : "", c->hosts[i]);
}

static int limits_ok(const cfg_class_t *c) {
    return c->max_clients >= 0 && c->max_per_ip >= 0 && c->flood_max_msgs >= 0 && c->flood_window >= 0 && c->sendq_max >= 0 &&
           (c->sendq_max == 0 || (c->sendq_max >= 4096 && c->sendq_max <= (16 << 20)));
}

static int parse_class(const char *text, cfg_class_t *c, char *err, size_t errsz) {
    char name[64], hosts[1100];
    memset(c, 0, sizeof *c);
    if (sscanf(text, "%63s %d %d %d %d %lf %1099s", name, &c->max_clients, &c->max_per_ip, &c->sendq_max, &c->flood_max_msgs, &c->flood_window, hosts) != 7 ||
        !valid_name(name) || !limits_ok(c)) { snprintf(err, errsz, "malformed class"); return -1; }
    snprintf(c->name, sizeof c->name, "%s", name);
    for (char *h = strtok(hosts, ","); h; h = strtok(NULL, ",")) {
        if (c->n_hosts >= CFG_MAX_HOSTS_PER_WEBIRC || strlen(h) >= CFG_MASK) { snprintf(err, errsz, "too many or too long hosts"); return -1; }
        snprintf(c->hosts[c->n_hosts], CFG_MASK, "%s", h);
        config_ip_mask_normalize(c->hosts[c->n_hosts], "CLASS hosts");
        c->n_hosts++;
    }
    if (c->n_hosts < 1) { snprintf(err, errsz, "no hosts"); return -1; }
    return 0;
}

/* --- the table ------------------------------------------------------------------------------------------------------- */

static int in_table(const server_t *srv, int n, const char *name) {
    for (int i = 0; i < n; i++) if (strcasecmp(srv->class_tab[i]->name, name) == 0) return 1;
    return 0;
}

void classes_rebuild(server_t *srv) {
    int n = 0;
    for (int i = 0; i < srv->cfg.n_classes && n < SRV_MAX_CLASSES; i++) srv->class_tab[n++] = &srv->cfg.classes[i];
    for (const sclass_t *s = srv->rt_classes; s && n < SRV_MAX_CLASSES; s = s->next)
        if (!in_table(srv, n, s->c.name)) srv->class_tab[n++] = &s->c;
    if (srv->cfg.links.accept_global_classes)
        for (const sclass_t *s = srv->net_classes; s && n < SRV_MAX_CLASSES; s = s->next)
            if (!in_table(srv, n, s->c.name)) srv->class_tab[n++] = &s->c;
    srv->n_class_tab = n;
}

static void list_free(sclass_t **head) {
    while (*head) { sclass_t *n = (*head)->next; free(*head); *head = n; }
}

void classes_free(server_t *srv) {
    list_free(&srv->rt_classes);
    list_free(&srv->net_classes);
}

static void list_append(sclass_t **head, sclass_t *s) {
    sclass_t **pp = head;
    while (*pp) pp = &(*pp)->next;
    s->next = NULL;
    *pp = s;
}

static int total(const server_t *srv) {
    int n = srv->cfg.n_classes;
    for (const sclass_t *s = srv->rt_classes; s; s = s->next) n++;
    for (const sclass_t *s = srv->net_classes; s; s = s->next) n++;
    return n;
}

static const cfg_class_t *find_any(const server_t *srv, const char *name) {
    for (int i = 0; i < srv->cfg.n_classes; i++) if (strcasecmp(srv->cfg.classes[i].name, name) == 0) return &srv->cfg.classes[i];
    for (const sclass_t *s = srv->rt_classes; s; s = s->next) if (strcasecmp(s->c.name, name) == 0) return &s->c;
    for (const sclass_t *s = srv->net_classes; s; s = s->next) if (strcasecmp(s->c.name, name) == 0) return &s->c;
    return NULL;
}

/* --- classes.json: the classes CLASS ADD made ------------------------------------------------------------------------- */

static void save(server_t *srv) {
    char path[CFG_PATH];
    if (!config_classes_path(&srv->cfg, path, sizeof path)) return; /* no config file: memory only */
    cJSON *arr = cJSON_CreateArray();
    for (const sclass_t *s = srv->rt_classes; s; s = s->next) {
        cJSON *o = cJSON_CreateObject(), *h = cJSON_CreateArray();
        cJSON_AddStringToObject(o, "name", s->c.name);
        for (int i = 0; i < s->c.n_hosts; i++) cJSON_AddItemToArray(h, cJSON_CreateString(s->c.hosts[i]));
        cJSON_AddItemToObject(o, "hosts", h);
        cJSON_AddNumberToObject(o, "max_clients", s->c.max_clients);
        cJSON_AddNumberToObject(o, "max_per_ip", s->c.max_per_ip);
        cJSON_AddNumberToObject(o, "sendq_max", s->c.sendq_max);
        cJSON_AddNumberToObject(o, "flood_max_msgs", s->c.flood_max_msgs);
        cJSON_AddNumberToObject(o, "flood_window", s->c.flood_window);
        cJSON_AddBoolToObject(o, "global", s->c.global);
        cJSON_AddItemToArray(arr, o);
    }
    char *text = cJSON_Print(arr);
    char tmp[CFG_PATH + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (text) {
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

void classes_load(server_t *srv) {
    char path[CFG_PATH];
    if (!config_classes_path(&srv->cfg, path, sizeof path)) return;
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
    if (!arr) { log_warn("classes", "%s is not valid JSON: ignored", path); return; }
    cJSON *o;
    cJSON_ArrayForEach(o, arr) {
        cJSON *nm = cJSON_GetObjectItem(o, "name"), *hs = cJSON_GetObjectItem(o, "hosts");
        if (!cJSON_IsString(nm) || !valid_name(nm->valuestring) || !cJSON_IsArray(hs) || total(srv) >= SRV_MAX_CLASSES) continue;
        sclass_t *s = calloc(1, sizeof *s);
        if (!s) break;
        snprintf(s->c.name, sizeof s->c.name, "%s", nm->valuestring);
        cJSON *h;
        cJSON_ArrayForEach(h, hs)
            if (cJSON_IsString(h) && s->c.n_hosts < CFG_MAX_HOSTS_PER_WEBIRC && strlen(h->valuestring) < CFG_MASK)
                snprintf(s->c.hosts[s->c.n_hosts++], CFG_MASK, "%s", h->valuestring);
        static const char *const KEY[] = {"max_clients", "max_per_ip", "sendq_max", "flood_max_msgs"};
        int *dst[] = {&s->c.max_clients, &s->c.max_per_ip, &s->c.sendq_max, &s->c.flood_max_msgs};
        for (int k = 0; k < 4; k++) { cJSON *v = cJSON_GetObjectItem(o, KEY[k]); if (cJSON_IsNumber(v)) *dst[k] = (int)v->valuedouble; }
        cJSON *fw = cJSON_GetObjectItem(o, "flood_window");
        if (cJSON_IsNumber(fw)) s->c.flood_window = fw->valuedouble;
        s->c.global = cJSON_IsTrue(cJSON_GetObjectItem(o, "global"));
        if (s->c.n_hosts < 1 || !limits_ok(&s->c) || find_any(srv, s->c.name)) { free(s); continue; }
        list_append(&srv->rt_classes, s);
    }
    cJSON_Delete(arr);
}

/* --- publishing and receiving global classes -------------------------------------------------------------------------- */

static int is_own_global(const cfg_class_t *c) { return c->global; }

/* Our own global classes, as a complete set (the file's, then CLASS ADD GLOBAL's): every server drops what it had from us first. */
static void send_own(server_t *srv, link_conn_t *to) {
    netsync_class(srv, to, NULL, NULL);
    char rule[1300];
    for (int i = 0; i < srv->cfg.n_classes; i++)
        if (is_own_global(&srv->cfg.classes[i])) { format_class(&srv->cfg.classes[i], rule, sizeof rule); netsync_class(srv, to, NULL, rule); }
    for (const sclass_t *s = srv->rt_classes; s; s = s->next)
        if (is_own_global(&s->c)) { format_class(&s->c, rule, sizeof rule); netsync_class(srv, to, NULL, rule); }
}

void classes_publish(server_t *srv) { send_own(srv, NULL); }

void classes_burst(server_t *srv, link_conn_t *lc) {
    send_own(srv, lc);
    char rule[1300];
    for (const sclass_t *s = srv->net_classes; s; s = s->next) {
        const sclass_t *e = srv->net_classes;
        while (e != s && strcmp(e->origin, s->origin) != 0) e = e->next;
        if (e != s) continue; /* this origin's set went out with its first class */
        netsync_class(srv, lc, s->origin, NULL);
        for (const sclass_t *g = s; g; g = g->next)
            if (strcmp(g->origin, s->origin) == 0) { format_class(&g->c, rule, sizeof rule); netsync_class(srv, lc, s->origin, rule); }
    }
}

void classes_net_receive(server_t *srv, const char *origin, const char *verb, const char *rule) {
    if (!strcasecmp(verb, "CLEAR")) {
        sclass_t **pp = &srv->net_classes;
        while (*pp) {
            sclass_t *s = *pp;
            if (strcmp(s->origin, origin) != 0) { pp = &s->next; continue; }
            *pp = s->next;
            free(s);
        }
        classes_rebuild(srv);
        net_reclass_all(srv);
        return;
    }
    if (strcasecmp(verb, "ADD") != 0 || !rule) return;
    sclass_t *s = calloc(1, sizeof *s);
    if (!s) return;
    char err[80];
    if (total(srv) >= SRV_MAX_CLASSES) snprintf(err, sizeof err, "too many classes (max %d)", SRV_MAX_CLASSES);
    else if (parse_class(rule, &s->c, err, sizeof err) != 0) { /* err set */ }
    else err[0] = '\0';
    if (err[0]) { log_warn("classes", "class from %s refused: %s", origin, err); free(s); return; }
    s->c.global = 1;
    snprintf(s->origin, sizeof s->origin, "%s", origin);
    list_append(&srv->net_classes, s);
    classes_rebuild(srv);
    net_reclass_all(srv);
}

void classes_global_del(server_t *srv, const char *name, const char *by) {
    for (sclass_t **pp = &srv->rt_classes; *pp; pp = &(*pp)->next) {
        sclass_t *s = *pp;
        if (!s->c.global || strcasecmp(s->c.name, name) != 0) continue;
        *pp = s->next;
        char note[300];
        snprintf(note, sizeof note, "%s removed global class %s (%s's)", by, s->c.name, srv->cfg.server.name);
        server_notify_network(srv, note);
        free(s);
        save(srv);
        classes_rebuild(srv);
        net_reclass_all(srv);
        classes_publish(srv);
        return;
    }
}

/* --- CLASS -------------------------------------------------------------------------------------------------------------- */

static void say_class(server_t *srv, client_t *cl, const cfg_class_t *c, const char *source, int cur) {
    char m[900], lim[200] = "", hosts[400] = "";
    int n = 0;
    if (c->max_clients) n += snprintf(lim + n, sizeof lim - (size_t)n, " max_clients=%d", c->max_clients);
    if (c->max_per_ip) n += snprintf(lim + n, sizeof lim - (size_t)n, " max_per_ip=%d", c->max_per_ip);
    if (c->sendq_max) n += snprintf(lim + n, sizeof lim - (size_t)n, " sendq_max=%d", c->sendq_max);
    if (c->flood_max_msgs) n += snprintf(lim + n, sizeof lim - (size_t)n, " flood_max_msgs=%d", c->flood_max_msgs);
    if (c->flood_window > 0) snprintf(lim + n, sizeof lim - (size_t)n, " flood_window=%g", c->flood_window);
    for (int i = 0; i < c->n_hosts; i++) { size_t l = strlen(hosts); snprintf(hosts + l, sizeof hosts - l, "%s%s", i ? "," : "", c->hosts[i]); }
    snprintf(m, sizeof m, "%s [%s%s] %s%s (%d here now)", c->name, source, c->global ? ", global" : "", hosts, lim[0] ? lim : " (no limits)", cur);
    notice_self(srv, cl, m);
}

static void list_classes(server_t *srv, client_t *cl) {
    if (srv->n_class_tab == 0) { notice_self(srv, cl, "No classes (the default limits apply to everyone)"); return; }
    for (int i = 0; i < srv->n_class_tab; i++) {
        const cfg_class_t *c = srv->class_tab[i];
        char src[64] = "config file";
        int found = 0;
        for (const sclass_t *s = srv->rt_classes; s && !found; s = s->next) if (&s->c == c) { snprintf(src, sizeof src, "CLASS"); found = 1; }
        for (const sclass_t *s = srv->net_classes; s && !found; s = s->next)
            if (&s->c == c) { netserver_t *o = netsync_find_sid(srv, s->origin); snprintf(src, sizeof src, "from %s", o ? o->name : s->origin); found = 1; }
        say_class(srv, cl, c, src, srv->class_count[i]);
    }
}

static int apply_key(cfg_class_t *c, const char *kv, char *err, size_t errsz) {
    char *eq = strchr(kv, '=');
    if (!eq) { snprintf(err, errsz, "expected key=value, got %s", kv); return -1; }
    char key[40];
    snprintf(key, sizeof key, "%.*s", (int)(eq - kv) < 39 ? (int)(eq - kv) : 39, kv);
    char *end;
    double v = strtod(eq + 1, &end);
    if (*end || end == eq + 1 || v < 0) { snprintf(err, errsz, "%s needs a number >= 0", key); return -1; }
    if (!strcasecmp(key, "max_clients")) c->max_clients = (int)v;
    else if (!strcasecmp(key, "max_per_ip")) c->max_per_ip = (int)v;
    else if (!strcasecmp(key, "sendq_max")) c->sendq_max = (int)v;
    else if (!strcasecmp(key, "flood_max_msgs")) c->flood_max_msgs = (int)v;
    else if (!strcasecmp(key, "flood_window")) c->flood_window = v;
    else { snprintf(err, errsz, "unknown setting %s (max_clients max_per_ip sendq_max flood_max_msgs flood_window)", key); return -1; }
    return 0;
}

static const sclass_t *find_rt(const server_t *srv, const char *name) {
    for (const sclass_t *s = srv->rt_classes; s; s = s->next) if (strcasecmp(s->c.name, name) == 0) return s;
    return NULL;
}

void cmd_class(server_t *srv, client_t *cl, irc_message_t *msg) {
    const char *sub = msg->nparams > 0 ? msg->params[0] : "LIST";
    char err[200], m[400];
    if (!strcasecmp(sub, "LIST")) { list_classes(srv, cl); return; }

    if (!strcasecmp(sub, "ADD")) {
        int argi = 1, global = 0;
        if (argi < msg->nparams && !strcasecmp(msg->params[argi], "GLOBAL")) { global = 1; argi++; }
        if (msg->nparams < argi + 2) { notice_self(srv, cl, "Usage: CLASS ADD [GLOBAL] <name> <host,host,...> [max_clients=N] [max_per_ip=N] [sendq_max=N] [flood_max_msgs=N] [flood_window=S]"); return; }
        if (global && netsync_scope_refuse(srv, cl, "CLASS ADD GLOBAL (a network-wide class; leave out GLOBAL for this server)")) return;
        cfg_class_t c;
        memset(&c, 0, sizeof c);
        if (!valid_name(msg->params[argi])) { notice_self(srv, cl, "A class name is letters, digits and _ . - (63 at most)"); return; }
        snprintf(c.name, sizeof c.name, "%s", msg->params[argi]);
        char hosts[1100];
        snprintf(hosts, sizeof hosts, "%s", msg->params[argi + 1]);
        for (char *h = strtok(hosts, ","); h; h = strtok(NULL, ",")) {
            if (c.n_hosts >= CFG_MAX_HOSTS_PER_WEBIRC || strlen(h) >= CFG_MASK) { notice_self(srv, cl, "Too many or too long hosts (16 at most)"); return; }
            snprintf(c.hosts[c.n_hosts], CFG_MASK, "%s", h);
            config_ip_mask_normalize(c.hosts[c.n_hosts], "CLASS hosts");
            c.n_hosts++;
        }
        for (int i = argi + 2; i < msg->nparams; i++)
            if (apply_key(&c, msg->params[i], err, sizeof err)) { notice_self(srv, cl, err); return; }
        if (c.n_hosts < 1 || !limits_ok(&c)) { notice_self(srv, cl, "A class needs hosts, and limits of 0 or more (sendq_max 4096-16777216)"); return; }
        if (find_any(srv, c.name)) { notice_self(srv, cl, "A class of that name exists already (CLASS DEL it first)"); return; }
        if (total(srv) >= SRV_MAX_CLASSES) { notice_self(srv, cl, "No room for another class"); return; }
        c.global = global;
        sclass_t *s = calloc(1, sizeof *s);
        if (!s) return;
        s->c = c;
        list_append(&srv->rt_classes, s);
        save(srv);
        classes_rebuild(srv);
        net_reclass_all(srv);
        if (global) classes_publish(srv);
        snprintf(m, sizeof m, "Class %s added%s", c.name, global ? " on every linked server" : " (this server only)");
        notice_self(srv, cl, m);
        char note[300];
        snprintf(note, sizeof note, "%s added class %s%s", cl->nick, c.name, global ? " (global)" : "");
        server_notify_opers(srv, note);
        return;
    }

    if (!strcasecmp(sub, "DEL")) {
        if (msg->nparams < 2) { notice_self(srv, cl, "Usage: CLASS DEL <name>"); return; }
        const char *name = msg->params[1];
        for (int i = 0; i < srv->cfg.n_classes; i++)
            if (!strcasecmp(srv->cfg.classes[i].name, name)) {
                notice_self(srv, cl, "That class is defined in the config file: remove it there and REHASH");
                return;
            }
        const sclass_t *rt = find_rt(srv, name);
        if (rt) {
            int was_global = rt->c.global;
            if (was_global && netsync_scope_refuse(srv, cl, "CLASS DEL of a global class")) return;
            for (sclass_t **pp = &srv->rt_classes; *pp; pp = &(*pp)->next)
                if (*pp == rt) { sclass_t *dead = *pp; *pp = dead->next; free(dead); break; }
            save(srv);
            classes_rebuild(srv);
            net_reclass_all(srv);
            if (was_global) classes_publish(srv);
            snprintf(m, sizeof m, "Class %s removed", name);
            notice_self(srv, cl, m);
            return;
        }
        for (sclass_t **pp = &srv->net_classes; *pp; pp = &(*pp)->next) { /* another server's global class: gone here, and its owner is asked to drop it */
            if (strcasecmp((*pp)->c.name, name) != 0) continue;
            if (netsync_scope_refuse(srv, cl, "CLASS DEL of another server's global class")) return;
            sclass_t *dead = *pp;
            char origin[8], cname[64];
            snprintf(origin, sizeof origin, "%s", dead->origin);
            snprintf(cname, sizeof cname, "%s", dead->c.name);
            netserver_t *o = netsync_find_sid(srv, origin);
            *pp = dead->next;
            free(dead);
            classes_rebuild(srv);
            net_reclass_all(srv);
            netsync_class_del(srv, origin, cname);
            snprintf(m, sizeof m, o ? "Class %s removed; %s was asked to remove it at the source" : "Class %s removed here only (%s is not linked)", cname, o ? o->name : origin);
            notice_self(srv, cl, m);
            return;
        }
        snprintf(m, sizeof m, "No such class: %s", name);
        notice_self(srv, cl, m);
        return;
    }
    notice_self(srv, cl, "Usage: CLASS [LIST] | ADD [GLOBAL] <name> <host,host,...> [key=value ...] | DEL <name>");
}
