#include "proto.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* --- parsing -------------------------------------------------------------- */

static char *unescape_tag_value_inplace(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\\' && *(r + 1)) {
            char c = *(r + 1);
            switch (c) {
                case '\\': *w++ = '\\'; break;
                case ':':  *w++ = ';';  break;
                case 's':  *w++ = ' ';  break;
                case 'r':  *w++ = '\r'; break;
                case 'n':  *w++ = '\n'; break;
                default:   *w++ = c;    break;
            }
            r += 2;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return s;
}

/* Bound on raw whitespace-split tokens (including empties from runs of
 * spaces) before the trailing marker -- generous relative to any sane
 * max_line_length; server.c enforces the real max_params limit afterward. */
#define MAX_RAW_TOKENS 300

int irc_parse_line(char *line, irc_message_t *msg) {
    msg->ntags = 0;
    msg->prefix = NULL;
    msg->command = NULL;
    msg->nparams = 0;
    if (!line || !*line) return -1;

    if (line[0] == '@') {
        char *space = strchr(line, ' ');
        if (!space) return -1;
        *space = '\0';
        char *tag_str = line + 1;
        line = space + 1;

        char *save = NULL;
        char *part = strtok_r(tag_str, ";", &save);
        while (part && msg->ntags < IRC_MAX_TAGS) {
            if (*part) {
                char *eq = strchr(part, '=');
                if (eq) {
                    *eq = '\0';
                    msg->tags[msg->ntags].key = part;
                    msg->tags[msg->ntags].val = unescape_tag_value_inplace(eq + 1);
                } else {
                    msg->tags[msg->ntags].key = part;
                    msg->tags[msg->ntags].val = "";
                }
                msg->ntags++;
            }
            part = strtok_r(NULL, ";", &save);
        }
        if (!*line) return -1;
    }

    if (line[0] == ':') {
        char *space = strchr(line, ' ');
        if (!space) return -1;
        *space = '\0';
        msg->prefix = line + 1;
        line = space + 1;
    }
    if (!*line) return -1;

    /* Trailing param starts at " :" -- a bare ':' with no preceding space is
     * a literal character in a middle param (IPv6 literal, mode key, ...). */
    char *trailing = NULL;
    char *marker = strstr(line, " :");
    if (marker) {
        *marker = '\0';
        trailing = marker + 2;
    }

    char *raw[MAX_RAW_TOKENS];
    int nraw = 0;
    {
        char *p = line;
        raw[nraw++] = p;
        while (nraw < MAX_RAW_TOKENS && (p = strchr(p, ' ')) != NULL) {
            *p = '\0';
            p++;
            raw[nraw++] = p;
        }
    }
    if (nraw == 0 || raw[0][0] == '\0') return -1;
    for (char *c = raw[0]; *c; c++) *c = (char)toupper((unsigned char)*c);
    msg->command = raw[0];

    for (int i = 1; i < nraw && msg->nparams < IRC_MAX_PARAMS; i++) {
        if (raw[i][0] != '\0') msg->params[msg->nparams++] = raw[i];
    }
    if (trailing && msg->nparams < IRC_MAX_PARAMS) {
        msg->params[msg->nparams++] = trailing;
    }
    return 0;
}

/* --- building --------------------------------------------------------------- */

size_t irc_escape(char *out, size_t outsz, const char *in) {
    size_t o = 0;
    if (outsz == 0) return 0;
    for (const char *p = in; *p && o + 1 < outsz; p++) {
        if (*p == '\r' || *p == '\n') continue;
        out[o++] = *p;
    }
    out[o] = '\0';
    return o;
}

static void escape_tag_value(char *out, size_t outsz, const char *in) {
    size_t o = 0;
    if (outsz == 0) return;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 2 < outsz; p++) {
        switch (*p) {
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case ';':  out[o++] = '\\'; out[o++] = ':';  break;
            case ' ':  out[o++] = '\\'; out[o++] = 's';  break;
            case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
            case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
            default:   out[o++] = (char)*p; break;
        }
    }
    out[o] = '\0';
}

static int append_str(char *out, size_t outsz, size_t *pos, const char *s) {
    size_t l = strlen(s);
    if (*pos + l >= outsz) return -1;
    memcpy(out + *pos, s, l);
    *pos += l;
    out[*pos] = '\0';
    return 0;
}

static int append_escaped(char *out, size_t outsz, size_t *pos, const char *s) {
    char buf[1024];
    irc_escape(buf, sizeof buf, s);
    return append_str(out, outsz, pos, buf);
}

int irc_build(char *out, size_t outsz,
              const irc_tag_t *tags, int ntags,
              const char *prefix, const char *command,
              const char **params, int nparams,
              const char *trailing) {
    if (outsz == 0) return -1;
    out[0] = '\0';
    size_t pos = 0;

    if (tags && ntags > 0) {
        if (append_str(out, outsz, &pos, "@") != 0) return -1;
        for (int i = 0; i < ntags; i++) {
            if (i > 0 && append_str(out, outsz, &pos, ";") != 0) return -1;
            if (append_str(out, outsz, &pos, tags[i].key) != 0) return -1;
            if (tags[i].val && tags[i].val[0]) {
                char ebuf[1024];
                escape_tag_value(ebuf, sizeof ebuf, tags[i].val);
                if (append_str(out, outsz, &pos, "=") != 0) return -1;
                if (append_str(out, outsz, &pos, ebuf) != 0) return -1;
            }
        }
        if (append_str(out, outsz, &pos, " ") != 0) return -1;
    }

    if (prefix) {
        if (append_str(out, outsz, &pos, ":") != 0) return -1;
        if (append_escaped(out, outsz, &pos, prefix) != 0) return -1;
        if (append_str(out, outsz, &pos, " ") != 0) return -1;
    }

    if (append_escaped(out, outsz, &pos, command) != 0) return -1;

    for (int i = 0; i < nparams; i++) {
        if (append_str(out, outsz, &pos, " ") != 0) return -1;
        if (append_escaped(out, outsz, &pos, params[i]) != 0) return -1;
    }
    if (trailing) {
        if (append_str(out, outsz, &pos, " :") != 0) return -1;
        if (append_escaped(out, outsz, &pos, trailing) != 0) return -1;
    }
    return (int)pos;
}

/* --- validators ------------------------------------------------------------- */

static int is_nick_special(unsigned char c) {
    return c == '\\' || c == '^' || c == '[' || c == ']' ||
           c == '`' || c == '{' || c == '|' || c == '_';
}

int irc_valid_nick(const char *nick, int max_len) {
    if (!nick || !*nick) return 0;
    size_t len = strlen(nick);
    if ((int)len > max_len) return 0;
    unsigned char c0 = (unsigned char)nick[0];
    if (!(isalpha(c0) || is_nick_special(c0))) return 0;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)nick[i];
        if (!(isalnum(c) || is_nick_special(c) || c == '-')) return 0;
    }
    return 1;
}

int irc_valid_user(const char *user, int max_len) {
    if (!user || !*user) return 0;
    size_t len = strlen(user);
    if ((int)len > max_len) return 0;
    unsigned char c0 = (unsigned char)user[0];
    if (!(isalnum(c0) || c0 == '_')) return 0;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)user[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return 0;
    }
    return 1;
}

int irc_valid_channel(const char *chan, int max_len) {
    if (!chan || !*chan) return 0;
    size_t len = strlen(chan);
    if ((int)len > max_len) return 0;
    if (chan[0] != '#') return 0;
    if (len < 2 || len - 1 > 49) return 0;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)chan[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '[' || c == ']' ||
              c == '{' || c == '}' || c == '^' || c == '|')) return 0;
    }
    return 1;
}

int irc_valid_host(const char *host) {
    if (!host) return 0;
    size_t len = strlen(host);
    if (len < 1 || len > 253) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == ':')) return 0;
    }
    return 1;
}

void irc_casefold(char *out, size_t outsz, const char *in) {
    size_t i = 0;
    if (outsz == 0) return;
    for (; in[i] && i + 1 < outsz; i++) out[i] = (char)tolower((unsigned char)in[i]);
    out[i] = '\0';
}

/* --- masks ------------------------------------------------------------------ */

int irc_glob_match(const char *pattern, const char *text) {
    const char *p = pattern, *t = text;
    const char *star_p = NULL, *star_t = NULL;
    while (*t) {
        if (*p && (tolower((unsigned char)*p) == tolower((unsigned char)*t) || *p == '?')) {
            p++; t++;
        } else if (*p == '*') {
            star_p = p++;
            star_t = t;
        } else if (star_p) {
            p = star_p + 1;
            t = ++star_t;
        } else {
            return 0;
        }
    }
    while (*p == '*') p++;
    return *p == '\0';
}

int irc_mask_match(const char *nick, const char *user, const char *host, const char *mask) {
    if (!strchr(mask, '!') && !strchr(mask, '@')) {
        return irc_glob_match(mask, nick ? nick : "");
    }
    char ident[128];
    if (user && user[0]) {
        if (user[0] == '~') snprintf(ident, sizeof ident, "%s", user);
        else snprintf(ident, sizeof ident, "~%s", user);
    } else {
        ident[0] = '\0';
    }
    char full[384];
    snprintf(full, sizeof full, "%s!%s@%s", nick ? nick : "", ident, host ? host : "");
    return irc_glob_match(mask, full);
}

int irc_host_mask_match(const char *user, const char *host, const char *mask) {
    char full[384];
    snprintf(full, sizeof full, "%s@%s", user ? user : "", host ? host : "");
    if (strchr(mask, '@')) {
        return irc_glob_match(mask, full);
    }
    char m2[320];
    snprintf(m2, sizeof m2, "*@%s", mask);
    return irc_glob_match(m2, full);
}

/* --- misc --------------------------------------------------------------------- */

long irc_parse_duration(const char *token) {
    if (!token || !*token) return -1;
    const char *p = token;
    if (!isdigit((unsigned char)*p)) return -1;
    long n = 0;
    while (isdigit((unsigned char)*p)) {
        if (n > LONG_MAX / 10) n = LONG_MAX / 10; /* clamp: defensive, not a real limit */
        n = n * 10 + (*p - '0');
        p++;
    }
    long mult = 1;
    if (*p) {
        switch (tolower((unsigned char)*p)) {
            case 's': mult = 1; break;
            case 'm': mult = 60; break;
            case 'h': mult = 3600; break;
            case 'd': mult = 86400; break;
            case 'w': mult = 604800; break;
            default: return -1;
        }
        p++;
        if (*p) return -1; /* trailing garbage after the unit char */
    }
    if (n > LONG_MAX / mult) return LONG_MAX;
    return n * mult;
}

void irc_prefix_for(char *out, size_t outsz, const char *nick, const char *user, const char *host) {
    if (user && user[0]) {
        if (user[0] == '~') snprintf(out, outsz, "%s!%s@%s", nick, user, host);
        else snprintf(out, outsz, "%s!~%s@%s", nick, user, host);
    } else {
        snprintf(out, outsz, "%s@%s", nick, host);
    }
}

void irc_iso8601_now(char *out, size_t outsz) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    gmtime_r(&ts.tv_sec, &tmv);
    long ms = ts.tv_nsec / 1000000;
    snprintf(out, outsz, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ms);
}

void irc_add_time_tag(char *line, size_t linesz) {
    char ts[40];
    irc_iso8601_now(ts, sizeof ts);
    size_t len = strlen(line);

    if (line[0] == '@') {
        char *space = strchr(line, ' ');
        if (!space) return;
        size_t tag_len = (size_t)(space - line - 1);
        char tagbuf[1536], tagbuf_copy[1536];
        if (tag_len >= sizeof tagbuf) return;
        memcpy(tagbuf, line + 1, tag_len);
        tagbuf[tag_len] = '\0';
        memcpy(tagbuf_copy, tagbuf, tag_len + 1);

        char *save = NULL;
        char *tok = strtok_r(tagbuf_copy, ";", &save);
        while (tok) {
            if (strcmp(tok, "time") == 0 || strncmp(tok, "time=", 5) == 0) return;
            tok = strtok_r(NULL, ";", &save);
        }

        char rest[1536];
        size_t rest_len = len - (size_t)(space - line);
        if (rest_len >= sizeof rest) return;
        memcpy(rest, space, rest_len);
        rest[rest_len] = '\0';
        snprintf(line, linesz, "@%s;time=%s%s", tagbuf, ts, rest);
    } else {
        char restbuf[1536];
        if (len >= sizeof restbuf) return;
        memcpy(restbuf, line, len + 1);
        snprintf(line, linesz, "@time=%s %s", ts, restbuf);
    }
}
