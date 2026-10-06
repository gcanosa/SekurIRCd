#include "scram.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hmac256(const unsigned char *key, size_t keylen, const unsigned char *msg, size_t msglen, unsigned char out[SCRAM_KEYLEN]) {
    unsigned int n = 0;
    return HMAC(EVP_sha256(), key, (int)keylen, msg, msglen, out, &n) && n == SCRAM_KEYLEN ? 0 : -1;
}

int scram_b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outsz) {
    if (outsz < 4 * ((inlen + 2) / 3) + 1) return -1;
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)inlen);
    return n < 0 ? -1 : n;
}

int scram_b64_decode(const char *in, unsigned char *out, size_t outsz) {
    size_t inlen = strlen(in);
    if (inlen == 0 || inlen % 4 != 0 || inlen / 4 * 3 > outsz) return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)inlen);
    if (n < 0) return -1;
    if (in[inlen - 1] == '=') n--;
    if (inlen >= 2 && in[inlen - 2] == '=') n--;
    return n;
}

int scram_derive(const char *password, const unsigned char *salt, int saltlen, int iter, scram_verifier_t *out) {
    if (saltlen < 1 || saltlen > (int)sizeof out->salt || iter < 1) return -1;
    unsigned char salted[SCRAM_KEYLEN], client_key[SCRAM_KEYLEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, saltlen, iter, EVP_sha256(), SCRAM_KEYLEN, salted) != 1) return -1;
    if (hmac256(salted, sizeof salted, (const unsigned char *)"Client Key", 10, client_key) != 0) return -1;
    if (hmac256(salted, sizeof salted, (const unsigned char *)"Server Key", 10, out->server_key) != 0) return -1;
    SHA256(client_key, sizeof client_key, out->stored_key);
    out->iter = iter;
    memcpy(out->salt, salt, (size_t)saltlen);
    out->saltlen = saltlen;
    OPENSSL_cleanse(salted, sizeof salted);
    OPENSSL_cleanse(client_key, sizeof client_key);
    return 0;
}

int scram_make_verifier(const char *password, scram_verifier_t *out) {
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof salt) != 1) return -1;
    return scram_derive(password, salt, sizeof salt, SCRAM_ITER, out);
}

void scram_verifier_to_string(const scram_verifier_t *v, char *out, size_t outsz) {
    char s[64], st[64], sk[64];
    s[0] = st[0] = sk[0] = '\0';
    scram_b64_encode(v->salt, (size_t)v->saltlen, s, sizeof s);
    scram_b64_encode(v->stored_key, SCRAM_KEYLEN, st, sizeof st);
    scram_b64_encode(v->server_key, SCRAM_KEYLEN, sk, sizeof sk);
    snprintf(out, outsz, "%d$%s$%s$%s", v->iter, s, st, sk);
}

int scram_verifier_from_string(const char *str, scram_verifier_t *out) {
    char buf[300];
    if (strlen(str) >= sizeof buf) return -1;
    snprintf(buf, sizeof buf, "%s", str);
    char *save = NULL;
    char *it = strtok_r(buf, "$", &save), *s = strtok_r(NULL, "$", &save);
    char *st = strtok_r(NULL, "$", &save), *sk = strtok_r(NULL, "$", &save);
    if (!it || !s || !st || !sk) return -1;
    int iter = atoi(it);
    if (iter < 1 || iter > 1000000) return -1;
    unsigned char tmp[64];
    int sl = scram_b64_decode(s, out->salt, sizeof out->salt);
    int a = scram_b64_decode(st, tmp, sizeof tmp);
    if (sl < 1 || a != SCRAM_KEYLEN) return -1;
    memcpy(out->stored_key, tmp, SCRAM_KEYLEN);
    int b = scram_b64_decode(sk, tmp, sizeof tmp);
    if (b != SCRAM_KEYLEN) return -1;
    memcpy(out->server_key, tmp, SCRAM_KEYLEN);
    out->iter = iter;
    out->saltlen = sl;
    return 0;
}

int scram_check_proof(const scram_verifier_t *v, const char *auth_message, const unsigned char proof[SCRAM_KEYLEN],
                      unsigned char server_sig[SCRAM_KEYLEN]) {
    unsigned char client_sig[SCRAM_KEYLEN], client_key[SCRAM_KEYLEN], check[SCRAM_KEYLEN];
    if (hmac256(v->stored_key, SCRAM_KEYLEN, (const unsigned char *)auth_message, strlen(auth_message), client_sig) != 0) return 0;
    for (int i = 0; i < SCRAM_KEYLEN; i++) client_key[i] = proof[i] ^ client_sig[i];
    SHA256(client_key, sizeof client_key, check);
    int ok = CRYPTO_memcmp(check, v->stored_key, SCRAM_KEYLEN) == 0;
    OPENSSL_cleanse(client_key, sizeof client_key);
    if (!ok) return 0;
    return hmac256(v->server_key, SCRAM_KEYLEN, (const unsigned char *)auth_message, strlen(auth_message), server_sig) == 0;
}
