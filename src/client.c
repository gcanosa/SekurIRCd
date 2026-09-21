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
    if (need > SENDQ_MAX) {
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
