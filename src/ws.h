/* Minimal RFC 6455 WebSocket server-side helpers: the HTTP upgrade handshake
 * and frame encode/decode. Pure functions on byte buffers (no sockets) so
 * tests/unit.c can exercise them; net.c wires them into a client's I/O. */
#ifndef SEKURIRCD_WS_H
#define SEKURIRCD_WS_H

#include <stddef.h>

#include "config.h"

#define WS_MAX_PAYLOAD 4000 /* must stay below net.c's 4096-byte read buffer (a frame is handed over whole); plenty for an IRC line */

/* Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key. 0 on success. */
int ws_accept_key(const char *client_key, char *out, size_t outsz);

typedef struct {
    char key[64];       /* Sec-WebSocket-Key */
    char origin[256];   /* "" if absent */
    int text_proto;     /* client offered the text.ircv3.net subprotocol */
    char forwarded[256]; /* raw X-Forwarded-For (else X-Real-IP) value, "" if absent -- see ws_forwarded_client */
} ws_request_t;

/* Parses a complete HTTP request head (up to, not including, the blank line)
 * as a WebSocket upgrade. 0 if it is one (key present, Upgrade: websocket), else -1. */
int ws_parse_request(const char *req, ws_request_t *out);

/* The real client address in a forwarded list: the rightmost entry not matching one of the trusted proxy globs.
 * 0 and `out` filled, or -1 if the list is empty. */
int ws_forwarded_client(const char *list, const char globs[][CFG_MASK], int nglobs, char *out, size_t outsz);

/* Builds the "101 Switching Protocols" response; echoes Sec-WebSocket-Protocol: text.ircv3.net when text_proto (Kiwi IRC requires it). Returns its length, or -1. */
int ws_build_response(const char *client_key, int text_proto, char *out, size_t outsz);

/* Encodes one unmasked server->client frame. `out` needs len + 10 bytes. Returns the frame length. */
size_t ws_encode_frame(unsigned char *out, int opcode, const unsigned char *payload, size_t len);

/* Decodes one client frame from in[0..inlen). Client frames must be masked.
 * Returns 1 and fills the outputs if a whole frame was present (payload is
 * unmasked IN PLACE inside `in`), 0 if more bytes are needed, -1 on a
 * protocol violation (unmasked, oversized, reserved bits). */
int ws_decode_frame(unsigned char *in, size_t inlen, int *opcode, int *fin,
                    unsigned char **payload, size_t *plen, size_t *consumed);

#endif
