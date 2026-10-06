/* SCRAM-SHA-256 (RFC 5802 / 7677) server-side primitives for SASL.
 * Pure functions on buffers so tests/unit.c can run the RFC 7677 vector. The
 * account store keeps a *verifier* (salt, iteration count, StoredKey,
 * ServerKey) rather than the password, derived when the password is seen. */
#ifndef SEKURIRCD_SCRAM_H
#define SEKURIRCD_SCRAM_H

#include <stddef.h>

#define SCRAM_ITER 4096
#define SCRAM_KEYLEN 32

typedef struct {
    int iter;
    unsigned char salt[32];
    int saltlen;
    unsigned char stored_key[SCRAM_KEYLEN];
    unsigned char server_key[SCRAM_KEYLEN];
} scram_verifier_t;

/* Derives a verifier for `password` with the given salt (SCRAM_ITER iterations). 0 on success. */
int scram_derive(const char *password, const unsigned char *salt, int saltlen, int iter, scram_verifier_t *out);

/* Same, with a fresh random salt. */
int scram_make_verifier(const char *password, scram_verifier_t *out);

/* "iter$salt_b64$stored_b64$server_b64" -- the form kept in accounts.json. */
void scram_verifier_to_string(const scram_verifier_t *v, char *out, size_t outsz);
int scram_verifier_from_string(const char *s, scram_verifier_t *out);

/* Checks a client proof against the exchange transcript (client-first-bare,
 * server-first, client-final-without-proof joined by commas). On success
 * writes the ServerSignature that goes into the server-final "v=" and returns 1. */
int scram_check_proof(const scram_verifier_t *v, const char *auth_message, const unsigned char proof[SCRAM_KEYLEN],
                      unsigned char server_sig[SCRAM_KEYLEN]);

/* Base64 helpers (standard alphabet, padded). Return the output length, or -1. */
int scram_b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outsz);
int scram_b64_decode(const char *in, unsigned char *out, size_t outsz);

#endif
