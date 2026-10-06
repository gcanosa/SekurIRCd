#include "ws.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

int ws_accept_key(const char *client_key, char *out, size_t outsz) {
    char buf[128];
    int n = snprintf(buf, sizeof buf, "%s%s", client_key, WS_GUID);
    if (n <= 0 || (size_t)n >= sizeof buf) return -1;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    if (EVP_Digest(buf, (size_t)n, digest, &dlen, EVP_sha1(), NULL) != 1) return -1;
    unsigned char b64[64];
    if (outsz < 29) return -1;
    int b = EVP_EncodeBlock(b64, digest, (int)dlen); /* 20 bytes -> 28 chars */
    if (b <= 0 || (size_t)b >= outsz) return -1;
    memcpy(out, b64, (size_t)b);
    out[b] = '\0';
    return 0;
}

/* Copies the value of header `name` (case-insensitive, at a line start) into out. */
static int header_value(const char *req, const char *name, char *out, size_t outsz) {
    size_t nl = strlen(name);
    for (const char *p = req; p && *p; ) {
        const char *eol = strstr(p, "\r\n");
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        if (linelen > nl && strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (v < p + linelen && (*v == ' ' || *v == '\t')) v++;
            size_t vl = (size_t)(p + linelen - v);
            while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
            if (vl >= outsz) vl = outsz - 1;
            memcpy(out, v, vl);
            out[vl] = '\0';
            return 1;
        }
        p = eol ? eol + 2 : NULL;
    }
    return 0;
}

int ws_parse_request(const char *req, ws_request_t *out) {
    memset(out, 0, sizeof *out);
    if (strncmp(req, "GET ", 4) != 0) return -1;
    char upgrade[32] = "";
    if (!header_value(req, "Upgrade", upgrade, sizeof upgrade) || strcasecmp(upgrade, "websocket") != 0) return -1;
    if (!header_value(req, "Sec-WebSocket-Key", out->key, sizeof out->key) || !out->key[0]) return -1;
    header_value(req, "Origin", out->origin, sizeof out->origin);
    char fwd[128] = "";
    if (header_value(req, "X-Forwarded-For", fwd, sizeof fwd) || header_value(req, "X-Real-IP", fwd, sizeof fwd)) {
        size_t n = strcspn(fwd, ", ");
        if (n >= sizeof out->forwarded) n = sizeof out->forwarded - 1;
        memcpy(out->forwarded, fwd, n);
        out->forwarded[n] = '\0';
    }
    return 0;
}

int ws_build_response(const char *client_key, char *out, size_t outsz) {
    char acc[64];
    if (ws_accept_key(client_key, acc, sizeof acc) != 0) return -1;
    int n = snprintf(out, outsz,
                     "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
    return (n > 0 && (size_t)n < outsz) ? n : -1;
}

size_t ws_encode_frame(unsigned char *out, int opcode, const unsigned char *payload, size_t len) {
    size_t h = 0;
    out[h++] = (unsigned char)(0x80 | (opcode & 0x0f)); /* FIN + opcode */
    if (len < 126) out[h++] = (unsigned char)len;
    else if (len <= 0xffff) { out[h++] = 126; out[h++] = (unsigned char)(len >> 8); out[h++] = (unsigned char)len; }
    else {
        out[h++] = 127;
        for (int i = 7; i >= 0; i--) out[h++] = (unsigned char)((unsigned long long)len >> (8 * i));
    }
    if (len) memcpy(out + h, payload, len);
    return h + len;
}

int ws_decode_frame(unsigned char *in, size_t inlen, int *opcode, int *fin,
                    unsigned char **payload, size_t *plen, size_t *consumed) {
    if (inlen < 2) return 0;
    if (in[0] & 0x70) return -1; /* RSV bits: no extensions negotiated */
    *fin = (in[0] & 0x80) != 0;
    *opcode = in[0] & 0x0f;
    if (!(in[1] & 0x80)) return -1; /* client frames must be masked */
    size_t len = in[1] & 0x7f, h = 2;
    if (len == 126) {
        if (inlen < 4) return 0;
        len = ((size_t)in[2] << 8) | in[3];
        h = 4;
    } else if (len == 127) {
        if (inlen < 10) return 0;
        unsigned long long l = 0;
        for (int i = 0; i < 8; i++) l = (l << 8) | in[2 + i];
        if (l > WS_MAX_PAYLOAD) return -1;
        len = (size_t)l;
        h = 10;
    }
    if (len > WS_MAX_PAYLOAD) return -1;
    if (*opcode >= 8 && (len > 125 || !*fin)) return -1; /* control frames: short and unfragmented */
    if (inlen < h + 4 + len) return 0;
    unsigned char *mask = in + h;
    unsigned char *p = in + h + 4;
    for (size_t i = 0; i < len; i++) p[i] ^= mask[i & 3];
    *payload = p;
    *plen = len;
    *consumed = h + 4 + len;
    return 1;
}
