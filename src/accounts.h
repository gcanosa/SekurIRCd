/* Self-service account store. Backs SASL PLAIN and `/REGISTER`. Ported from
 * sekurircd/src/sekurircd/accounts.py: JSON-backed (cJSON), load-once +
 * rewrite-on-mutation, no locking (single-threaded poll loop, same
 * reasoning as every other in-memory registry in this daemon).
 *
 * `path == NULL` (accounts disabled, see config_accounts_path) means a
 * purely in-memory, never-persisted store -- no file is ever created or
 * read while the feature is off.
 */
#ifndef SEKURIRCD_ACCOUNTS_H
#define SEKURIRCD_ACCOUNTS_H

#include "vendor/cJSON.h"

#include <stddef.h>

typedef struct {
    cJSON *data;      /* object: casefolded account name -> {name, pw_hash, created_at} */
    char path[512];   /* "" = in-memory only */
} account_store_t;

void accounts_init(account_store_t *st, const char *path /* may be NULL */);
void accounts_free(account_store_t *st);

/* True if `name` (case-insensitive) is already registered. */
int accounts_exists(account_store_t *st, const char *name);
/* Register `name` with an already-computed crypto_hash_password string,
 * persist if a path is configured. Caller must have already checked
 * !accounts_exists. */
void accounts_register_hashed(account_store_t *st, const char *name, const char *hash);
/* Stored scrypt hash for `name`, or NULL if no such account. Valid until the
 * next mutation of the store. */
const char *accounts_hash(account_store_t *st, const char *name);

/* Bind (fp non-empty) or clear (fp NULL or "") the SASL EXTERNAL certificate
 * fingerprint -- hex-encoded SHA-256 of the DER certificate, see cmd_reg.c's
 * peer_cert_fingerprint() -- on `name`. No-op if `name` isn't registered. */
void accounts_set_fingerprint(account_store_t *st, const char *name, const char *fp);
/* Hex fingerprint on file for `name`, or NULL if none/no such account. Valid
 * until the next mutation of the store. */
const char *accounts_fingerprint(account_store_t *st, const char *name);
/* Registered account name (as stored, not casefolded) whose fingerprint
 * matches `fp` case-insensitively, or NULL if none -- backs SASL EXTERNAL.
 * Valid until the next mutation of the store. */
const char *accounts_find_by_fingerprint(account_store_t *st, const char *fp);

#endif /* SEKURIRCD_ACCOUNTS_H */
