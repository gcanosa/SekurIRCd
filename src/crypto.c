#include "crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OWASP-minimum scrypt cost, same as passwords.py: ~16 MiB, well under 100ms
 * on any modern machine. maxmem must cover it (scrypt needs ~128*N*r bytes);
 * 32 MiB gives headroom without letting a malicious N explode memory use. */
#define SCRYPT_N 16384
#define SCRYPT_R 8
#define SCRYPT_P 1
#define SCRYPT_DKLEN 64
#define SCRYPT_MAXMEM (32 * 1024 * 1024)

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_decode(const char *hex, unsigned char *out, size_t outsz) {
    size_t len = strlen(hex);
    if (len == 0 || len % 2 != 0) return 0;
    size_t n = len / 2;
    if (n > outsz) return 0;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}

static void hex_encode(const unsigned char *in, size_t inlen, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; i++) {
        out[2 * i] = hexd[in[i] >> 4];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * inlen] = '\0';
}

int crypto_hash_password(const char *password, char *out, size_t outsz) {
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof salt) != 1) return -1;

    unsigned char digest[SCRYPT_DKLEN];
    if (EVP_PBE_scrypt(password, strlen(password), salt, sizeof salt,
                        SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_MAXMEM,
                        digest, sizeof digest) != 1) {
        return -1;
    }

    char salt_hex[2 * sizeof salt + 1];
    char digest_hex[2 * sizeof digest + 1];
    hex_encode(salt, sizeof salt, salt_hex);
    hex_encode(digest, sizeof digest, digest_hex);

    int n = snprintf(out, outsz, "scrypt$%d$%d$%d$%s$%s",
                      SCRYPT_N, SCRYPT_R, SCRYPT_P, salt_hex, digest_hex);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return 0;
}

int crypto_verify_password(const char *password, const char *stored) {
    if (!password || !stored) return 0;
    size_t len = strlen(stored);
    char buf[512];
    if (len >= sizeof buf) return 0;
    memcpy(buf, stored, len + 1);

    char *save = NULL;
    char *algo = strtok_r(buf, "$", &save);
    char *n_s = strtok_r(NULL, "$", &save);
    char *r_s = strtok_r(NULL, "$", &save);
    char *p_s = strtok_r(NULL, "$", &save);
    char *salt_hex = strtok_r(NULL, "$", &save);
    char *digest_hex = strtok_r(NULL, "$", &save);
    char *extra = strtok_r(NULL, "$", &save);
    if (!algo || !n_s || !r_s || !p_s || !salt_hex || !digest_hex || extra) return 0;
    if (strcmp(algo, "scrypt") != 0) return 0;

    char *endp;
    unsigned long n = strtoul(n_s, &endp, 10);
    if (*endp) return 0;
    unsigned long r = strtoul(r_s, &endp, 10);
    if (*endp) return 0;
    unsigned long p = strtoul(p_s, &endp, 10);
    if (*endp) return 0;

    unsigned char salt[64];
    size_t saltlen = hex_decode(salt_hex, salt, sizeof salt);
    unsigned char expected[128];
    size_t digestlen = hex_decode(digest_hex, expected, sizeof expected);
    if (saltlen == 0 || digestlen == 0) return 0;

    unsigned char candidate[128];
    if (EVP_PBE_scrypt(password, strlen(password), salt, saltlen,
                        n, r, p, SCRYPT_MAXMEM, candidate, digestlen) != 1) {
        return 0;
    }
    return CRYPTO_memcmp(candidate, expected, digestlen) == 0;
}

void crypto_random_hex(char *out, size_t outsz, int count) {
    unsigned char buf[64];
    if (count < 0) count = 0;
    if (count > (int)sizeof buf) count = (int)sizeof buf;      /* defensive cap */
    if (outsz < 3) { if (outsz) out[0] = '\0'; return; } /* (outsz - 1) / 2 would wrap at outsz == 0 */
    if ((size_t)(2 * count + 1) > outsz) count = (int)((outsz - 1) / 2);
    if (count > 0 && RAND_bytes(buf, count) != 1) abort();     /* no sane fallback for a broken CSPRNG */
    hex_encode(buf, (size_t)count, out);
}

void crypto_hmac_hex(const char *key, const char *msg, char *out, size_t outsz, int bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    HMAC(EVP_sha256(), key, (int)strlen(key), (const unsigned char *)msg, strlen(msg), digest, &dlen);
    if (bytes < 0) bytes = 0;
    if ((size_t)bytes > dlen) bytes = (int)dlen;
    if (outsz < 3) { if (outsz) out[0] = '\0'; return; }
    if ((size_t)(2 * bytes + 1) > outsz) bytes = (int)((outsz - 1) / 2);
    hex_encode(digest, (size_t)bytes, out);
}

int crypto_secure_streq(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    unsigned char pa[256], pb[256];
    if (la >= sizeof pa || lb >= sizeof pb) return 0;
    /* Compare a fixed-width zero-padded window so neither the running time
     * nor the number of iterations depends on where the first difference is. */
    memset(pa, 0, sizeof pa);
    memset(pb, 0, sizeof pb);
    memcpy(pa, a, la);
    memcpy(pb, b, lb);
    return CRYPTO_memcmp(pa, pb, sizeof pa) == 0;
}
