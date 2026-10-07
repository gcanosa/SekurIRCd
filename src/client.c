#include "client.h"
#include "link.h"
#include "proto.h"
#include "server.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

client_t *client_new(int fd, struct server *srv) {
    client_t *cl = calloc(1, sizeof *cl);
    if (!cl) return NULL;
    cl->fd = fd;
    cl->srv = srv;
    cl->class_idx = -1; /* calloc's 0 would mean "class 0" */
    cl->signon_time = cl->last_activity = time(NULL);
    cl->sbuf_cap = 4096;
    cl->sbuf = malloc(cl->sbuf_cap);
    cl->rbuf_cap = 4096;
    cl->rbuf = malloc(cl->rbuf_cap);
    if (!cl->sbuf || !cl->rbuf) { free(cl->sbuf); free(cl->rbuf); free(cl); return NULL; }
    return cl;
}

void client_free(client_t *cl) {
    if (!cl) return;
    chan_node_t *n = cl->channels;
    while (n) { chan_node_t *next = n->next; free(n); n = next; }
    if (cl->ssl) SSL_free(cl->ssl); /* abrupt close, no SSL_shutdown close_notify -- fine for a teardown path */
    free(cl->sbuf);
    free(cl->rbuf);
    free(cl->ml);
    free(cl->label_buf);
    free(cl->scram);
    free(cl->ws_in);
    free(cl->ws_out);
    free(cl);
}

void client_mode_string(const client_t *cl, char *out, size_t outsz) {
    char modestr[24] = "+";
    size_t p = 1;
    if (cl->umodes & UMODE_I) modestr[p++] = 'i';
    if (cl->umodes & UMODE_W) modestr[p++] = 'w';
    if (cl->umodes & UMODE_D) modestr[p++] = 'd';
    if (cl->umodes & UMODE_S) modestr[p++] = 's';
    if (cl->umodes & UMODE_O) modestr[p++] = 'o';
    if (cl->umodes & UMODE_Z) modestr[p++] = 'Z';
    if (cl->umodes & UMODE_R) modestr[p++] = 'r';
    if (cl->umodes & UMODE_P) modestr[p++] = 'p';
    if (cl->umodes & UMODE_HIDEIDLE) modestr[p++] = 'I';
    if (cl->umodes & UMODE_H) modestr[p++] = 'H';
    if (cl->umodes & UMODE_Q) modestr[p++] = 'q';
    if (cl->umodes & UMODE_REGONLY) modestr[p++] = 'R';
    if (cl->umodes & UMODE_NOPM) modestr[p++] = 'D';
    if (cl->umodes & UMODE_B) modestr[p++] = 'B';
    if (cl->umodes & UMODE_G) modestr[p++] = 'g';
    modestr[p] = '\0';
    snprintf(out, outsz, "%s", modestr);
}

void client_prefix(const client_t *cl, char *out, size_t outsz) {
    const char *nick = cl->nick[0] ? cl->nick : "*";
    const char *host = cl->host[0] ? cl->host : "*";
    if (cl->ident_confirmed) {
        /* A real identd answered -- cl->user is authoritative, no "~"
         * self-provided-ident marker (matches every other ircd's ident
         * convention: the tilde means "unconfirmed", not "confirmed"). */
        snprintf(out, outsz, "%s!%s@%s", nick, cl->user, host);
    } else {
        irc_prefix_for(out, outsz, nick, cl->user, host);
    }
}

void client_send(client_t *cl, const char *line) {
    if (cl->quitting) return;
    if (cl->fd < 0) {
        /* service pseudo-client (see link.h): no real socket, forward the
         * already-built line (its sender prefix is already in it) to the
         * link peer verbatim -- no separate wire encoding needed. */
        if (cl->link_conn) link_forward_line(cl->link_conn, line);
        return;
    }
    if (cl->label_capture) { /* held until client_label_end decides how to label it */
        size_t l = strlen(line);
        if (cl->label_len + l + 1 > 65536) { /* absurd reply volume: stop labeling, release what we hold unlabeled */
            cl->label_capture = 0;
            if (cl->label_buf) {
                char *p = cl->label_buf, *end = cl->label_buf + cl->label_len;
                while (p < end) { char *nl = memchr(p, '\n', (size_t)(end - p)); if (!nl) break; *nl = '\0'; client_send(cl, p); p = nl + 1; }
            }
            cl->label_len = 0; cl->label_lines = 0;
        } else {
            if (cl->label_len + l + 1 > cl->label_cap) {
                size_t cap = cl->label_cap ? cl->label_cap : 1024;
                while (cap < cl->label_len + l + 1) cap *= 2;
                char *nb = realloc(cl->label_buf, cap);
                if (!nb) { cl->quitting = 1; return; }
                cl->label_buf = nb; cl->label_cap = cap;
            }
            memcpy(cl->label_buf + cl->label_len, line, l);
            cl->label_len += l;
            cl->label_buf[cl->label_len++] = '\n';
            cl->label_lines++;
            return;
        }
    }
    /* IRCv3 server-time: every outgoing line gets a time= tag once negotiated
     * -- same single choke point as Client.send in the Python daemon. */
    char tagged[1536];
    if (cl->caps & CAP_SERVER_TIME) {
        snprintf(tagged, sizeof tagged, "%s", line);
        irc_add_time_tag(tagged, sizeof tagged);
        line = tagged;
    }

    size_t len = strlen(line);
    size_t need = cl->sbuf_len + len + 2;
    if (need > (cl->sendq_max ? cl->sendq_max : (size_t)SENDQ_MAX)) {
        cl->quitting = 1;
        snprintf(cl->quit_reason, sizeof cl->quit_reason, "SendQ exceeded");
        return;
    }
    if (need > cl->sbuf_cap) {
        size_t newcap = cl->sbuf_cap * 2;
        while (newcap < need) newcap *= 2;
        char *nb = realloc(cl->sbuf, newcap);
        if (!nb) { cl->quitting = 1; return; }
        cl->sbuf = nb;
        cl->sbuf_cap = newcap;
    }
    memcpy(cl->sbuf + cl->sbuf_len, line, len);
    cl->sbuf_len += len;
    cl->sbuf[cl->sbuf_len++] = '\r';
    cl->sbuf[cl->sbuf_len++] = '\n';
}

void client_reply(client_t *cl, const char *code, const char **params, int nparams, const char *trailing) {
    const char *target = cl->nick[0] ? cl->nick : "*";
    const char *allparams[IRC_MAX_PARAMS];
    allparams[0] = target;
    int n = 1;
    for (int i = 0; i < nparams && n < IRC_MAX_PARAMS; i++) allparams[n++] = params[i];

    char out[1024];
    const char *srvname = (cl->srv && cl->srv->cfg.server.name[0]) ? cl->srv->cfg.server.name : "server";
    irc_build(out, sizeof out, NULL, 0, srvname, code, allparams, n, trailing);
    client_send(cl, out);
}

int client_flood_ok(client_t *cl, int max_msgs, double window_seconds) {
    time_t now = time(NULL);
    if (cl->flood_window_start == 0 || difftime(now, cl->flood_window_start) >= window_seconds) {
        cl->flood_window_start = now;
        cl->flood_count = 0;
    }
    cl->flood_count++;
    return cl->flood_count <= max_msgs;
}

const char *client_invite_key(client_t *cl) {
    if (!cl->invite_key[0]) snprintf(cl->invite_key, sizeof cl->invite_key, "c%llu", (unsigned long long)cl->conn_id);
    return cl->invite_key;
}

void client_label_begin(client_t *cl, const char *label) {
    snprintf(cl->label, sizeof cl->label, "%s", label);
    cl->label_capture = 1;
    cl->label_len = 0;
    cl->label_lines = 0;
}

/* Prefixes `line` with one extra message tag ("k=v"), merging into any existing tag section. */
static void line_add_tag(const char *tag, const char *line, char *out, size_t outsz) {
    if (line[0] == '@') snprintf(out, outsz, "@%s;%s", tag, line + 1);
    else snprintf(out, outsz, "@%s %s", tag, line);
}

void client_label_end(client_t *cl) {
    if (!cl->label_capture) return; /* overflowed and already released */
    cl->label_capture = 0;
    const char *srvname = (cl->srv && cl->srv->cfg.server.name[0]) ? cl->srv->cfg.server.name : "server";
    /* Render "label=<escaped>" once, using irc_build's tag escaping. */
    irc_tag_t lt = {"label", cl->label};
    char tmp[200];
    irc_build(tmp, sizeof tmp, &lt, 1, NULL, "X", NULL, 0, NULL);
    char *sp = strchr(tmp, ' ');
    if (sp) *sp = '\0';
    const char *labeltag = tmp + 1; /* skip '@' */
    char out[1700];
    if (cl->label_lines == 0) {
        const char *p[1] = {NULL};
        char bare[200];
        irc_build(bare, sizeof bare, NULL, 0, srvname, "ACK", p, 0, NULL);
        line_add_tag(labeltag, bare, out, sizeof out);
        client_send(cl, out);
    } else if (cl->label_lines == 1) {
        char *nl = memchr(cl->label_buf, '\n', cl->label_len);
        if (nl) *nl = '\0';
        line_add_tag(labeltag, cl->label_buf, out, sizeof out);
        client_send(cl, out);
    } else {
        static unsigned long seq = 0;
        char bid[24], tagb[40], start[300];
        snprintf(bid, sizeof bid, "lr%lu", ++seq);
        const char *bp[] = {"+", "labeled-response"};
        char plus[40];
        snprintf(plus, sizeof plus, "+%s", bid);
        bp[0] = plus;
        irc_build(start, sizeof start, NULL, 0, srvname, "BATCH", bp, 2, NULL);
        line_add_tag(labeltag, start, out, sizeof out);
        client_send(cl, out);
        snprintf(tagb, sizeof tagb, "batch=%s", bid);
        char *p = cl->label_buf, *end = cl->label_buf + cl->label_len;
        while (p < end) {
            char *nl = memchr(p, '\n', (size_t)(end - p));
            if (!nl) break;
            *nl = '\0';
            line_add_tag(tagb, p, out, sizeof out);
            client_send(cl, out);
            p = nl + 1;
        }
        char minus[40], endl[300];
        snprintf(minus, sizeof minus, "-%s", bid);
        const char *ep[] = {minus};
        irc_build(endl, sizeof endl, NULL, 0, srvname, "BATCH", ep, 1, NULL);
        client_send(cl, endl);
    }
    cl->label_len = 0;
    cl->label_lines = 0;
}
