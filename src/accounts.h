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
/* Register `name` with `password` (hashed via crypto_hash_password), persist
 * if a path is configured. Caller must have already checked !accounts_exists. */
void accounts_register(account_store_t *st, const char *name, const char *password);
/* True if `password` matches the stored hash for `name`. */
int accounts_verify(account_store_t *st, const char *name, const char *password);

#endif /* SEKURIRCD_ACCOUNTS_H */
