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
    int n_grouped;    /* total grouped nicks across all accounts (0 = skip the owner scan) */
} account_store_t;

void accounts_init(account_store_t *st, const char *path /* may be NULL */);
void accounts_free(account_store_t *st);

/* True if `name` (case-insensitive) is already registered. */
int accounts_exists(account_store_t *st, const char *name);
/* Number of registered accounts (for [accounts] max_accounts). */
int accounts_count(account_store_t *st);
/* Register `name` with an already-computed crypto_hash_password string,
 * persist if a path is configured. Caller must have already checked
 * !accounts_exists. */
void accounts_register_hashed(account_store_t *st, const char *name, const char *hash);
/* Stored scrypt hash for `name`, or NULL if no such account. Valid until the
 * next mutation of the store. */
const char *accounts_hash(account_store_t *st, const char *name);
/* SCRAM-SHA-256 verifier string (see scram.h) or NULL; set when the account's password is seen (REGISTER, or a later PLAIN login). */
const char *accounts_scram(account_store_t *st, const char *name);
void accounts_set_scram(account_store_t *st, const char *name, const char *verifier);
/* The account's canonical (as registered) name, or `name` itself if unknown. */
const char *accounts_display_name(account_store_t *st, const char *name);
/* Unix time `name` was registered, or 0 if no such account -- see spam.c's
 * use of it to age-gate [spam] exempt_identified against an instant
 * self-service /REGISTER. */
long accounts_created_at(account_store_t *st, const char *name);

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

/* --- account maintenance (NickServ SET PASSWORD / DROP / SET EMAIL / VERIFY / GROUP) ----------------------------- */

/* Replace the stored scrypt hash (and drop the old SCRAM verifier -- the caller sets a fresh one). */
void accounts_set_hash(account_store_t *st, const char *name, const char *hash);
/* Delete the account. 1 if it existed. */
int accounts_drop(account_store_t *st, const char *name);

/* Contact email. set_email stores it unverified; with a pending code (set_pending_email) it only becomes the email once
 * check_verify sees the matching, unexpired code. */
const char *accounts_email(account_store_t *st, const char *name);
int accounts_email_verified(account_store_t *st, const char *name);
void accounts_set_email(account_store_t *st, const char *name, const char *email, int verified);
void accounts_set_pending_email(account_store_t *st, const char *name, const char *email, const char *code, long expires_at);
const char *accounts_pending_email(account_store_t *st, const char *name);
/* 1 and the email is promoted to verified if `code` matches and hasn't expired. */
int accounts_check_verify(account_store_t *st, const char *name, const char *code);

/* Nick groups: extra nicks that belong to an account (max ACCOUNT_MAX_GROUP). */
#define ACCOUNT_MAX_GROUP 10
int accounts_group_add(account_store_t *st, const char *name, const char *nick); /* 0 ok, -1 limit/taken */
int accounts_group_del(account_store_t *st, const char *name, const char *nick); /* 0 removed, -1 not in group */
int accounts_group_count(account_store_t *st, const char *name);
const char *accounts_group_nick(account_store_t *st, const char *name, int i);
/* The account (display name) that owns `nick` -- either an account of that name or a grouped nick -- or NULL. */
const char *accounts_owner_of_nick(account_store_t *st, const char *nick);

#endif /* SEKURIRCD_ACCOUNTS_H */
