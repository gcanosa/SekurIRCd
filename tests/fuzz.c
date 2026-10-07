/* Mutation fuzzer for the byte-level parsers (no libFuzzer needed): `make fuzz` builds it with ASan+UBSan and runs
 * FUZZ_ITERS (default 300000) mutated inputs per target. Any sanitizer report or crash is a bug. FUZZ_SEED reproduces a run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto.h"
#include "ws.h"
#include "scram.h"

static unsigned long long rng_state;
static unsigned rnd(void) { rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL; return (unsigned)(rng_state >> 33); }

static const char *seeds[] = {
    "@time=2024-01-01T00:00:00.000Z;msgid=abc :nick!user@host PRIVMSG #chan :hello world",
    "MODE #chan +beI-o+lk a!b@c d!e@f g!h@i 25 key",
    "PROXY TCP4 1.2.3.4 5.6.7.8 1234 6667",
    "CAP REQ :multi-prefix sasl message-tags",
    "WEBIRC pass gw host 203.0.113.9",
    "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    "4096$c2FsdHNhbHRzYWx0c2FsdA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "*!*@*.example.com", "nick!~user@192.0.2.*", "#chan,&other,+x", "30d12h5m", "",
};
#define NSEEDS ((int)(sizeof seeds / sizeof *seeds))

static size_t mutate(unsigned char *buf, size_t cap) {
    const char *s = seeds[rnd() % NSEEDS];
    size_t len = strlen(s);
    if (len > cap) len = cap;
    memcpy(buf, s, len);
    int n = 1 + (int)(rnd() % 6);
    while (n--) {
        switch (rnd() % 5) {
        case 0: if (len) buf[rnd() % len] = (unsigned char)rnd(); break;                                  /* flip a byte */
        case 1: if (len) buf[rnd() % len] ^= (unsigned char)(1u << (rnd() % 8)); break;                   /* flip a bit */
        case 2: if (len < cap) { size_t at = len ? rnd() % len : 0; memmove(buf + at + 1, buf + at, len - at); buf[at] = (unsigned char)rnd(); len++; } break;
        case 3: if (len > 1) { size_t at = rnd() % len; memmove(buf + at, buf + at + 1, len - at - 1); len--; } break;
        case 4: { size_t extra = rnd() % 700; while (extra-- && len < cap) buf[len++] = " :,!@*#+-"[rnd() % 9]; } break;
        }
    }
    return len;
}

int main(void) {
    const char *e = getenv("FUZZ_ITERS"), *sd = getenv("FUZZ_SEED");
    long iters = e ? atol(e) : 300000;
    rng_state = sd ? strtoull(sd, NULL, 10) : 12345;
    unsigned char buf[2048], copy[2048];
    for (long i = 0; i < iters; i++) {
        size_t len = mutate(buf, sizeof buf - 1);
        buf[len] = 0;

        memcpy(copy, buf, len + 1);                      /* IRC line (mutated in place by the parser) */
        irc_message_t m;
        irc_parse_line((char *)copy, &m);

        char ip[64]; int port; size_t used;              /* PROXY v1/v2 header */
        irc_proxy_v2_parse(buf, len, ip, sizeof ip, &port, &used);

        memcpy(copy, buf, len + 1);                      /* WebSocket frame, unmasked in place */
        int op, fin; unsigned char *pl; size_t pl_len, consumed;
        ws_decode_frame(copy, len, &op, &fin, &pl, &pl_len, &consumed);

        ws_request_t rq;                                 /* HTTP upgrade request head */
        ws_parse_request((const char *)buf, &rq);

        scram_verifier_t v;                              /* stored verifier string */
        scram_verifier_from_string((const char *)buf, &v);
        unsigned char dec[256];
        scram_b64_decode((const char *)buf, dec, sizeof dec);

        irc_glob_match((const char *)buf, (const char *)buf + len / 2);
        irc_mask_match("nick", "user", "host.example.com", (const char *)buf, (int)(rnd() & 1));
        irc_valid_nick((const char *)buf, 30); irc_valid_channel((const char *)buf, 50); irc_valid_host((const char *)buf);
        char cf[64]; irc_casefold(cf, sizeof cf, (const char *)buf);
        long dur; (void)dur;
    }
    printf("fuzz: %ld iterations per target, no crashes\n", iters);
    return 0;
}
