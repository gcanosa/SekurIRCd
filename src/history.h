/* Message history for CHATHISTORY: one bounded ring per conversation (a channel, or a pair of logged-in accounts for
 * private messages), kept at server level so it outlives an emptied channel, and optionally saved to disk so it
 * survives a restart. Read markers (draft/read-marker) ride along in the same file. */
#ifndef SEKURIRCD_HISTORY_H
#define SEKURIRCD_HISTORY_H

#include "vendor/uthash.h"

#include <stddef.h>

struct server;

/* One stored message. The six strings live packed in a single heap block owned by the stored entry (most lines are
 * ~100 bytes, so this costs a fraction of fixed char[] fields sized for the worst case). A hist_entry_t passed to
 * history_add/hist_buf_add only borrows its strings (NULL = ""): they are copied, and clipped to the old field sizes. */
typedef struct {
    long long ms;       /* epoch milliseconds */
    const char *msgid;
    const char *sender; /* nick!user@host at send time */
    const char *account;/* sender's account, "" if none */
    const char *verb;   /* "PRIVMSG" / "NOTICE" */
    const char *target; /* where it was sent: the channel, or the recipient's nick for a DM */
    const char *text;
} hist_entry_t;

/* The ring grows on demand (`alloc` slots, doubling) up to `cap` = [messages] history_size, so a quiet channel
 * doesn't hold a full-size ring. head stays 0 until the ring is full. */
typedef struct hist_buf {
    char key[160];
    int cap, alloc, head, n;
    hist_entry_t *e;
    long long last_ms;
    UT_hash_handle hh;
} hist_buf_t;

#define HIST_MAX_BUFFERS 1000 /* conversations kept; the one idle longest is dropped beyond this */

/* Conversation keys (stable, casefolded). A DM key is the two accounts in sorted order. */
void history_key_channel(char *out, size_t outsz, const char *chan);
void history_key_dm(char *out, size_t outsz, const char *account_a, const char *account_b);
int history_key_is_dm(const char *key);

/* Ring operations on one buffer (no server needed -- tests/unit.c uses these directly). */
void hist_buf_add(hist_buf_t *b, int cap, const hist_entry_t *entry);
const hist_entry_t *hist_buf_at(const hist_buf_t *b, int i);
void hist_buf_clear(hist_buf_t *b); /* drop every entry and the ring (not the hist_buf_t itself) */

/* Store (hangs off server_t). `cap` is [messages] history_size. */
hist_buf_t *history_get(struct server *srv, const char *key);
void history_add(struct server *srv, const char *key, int cap, const hist_entry_t *entry);
/* A channel RENAME: its conversation moves to the new name (replacing any stale history kept under that name). */
void history_rename_channel(struct server *srv, const char *oldname, const char *newname);
void history_free(struct server *srv);

/* Persistence ([messages] history_file). load: at startup; maybe_save: from the 1-second tick (debounced) or force=1. */
void history_load(struct server *srv);
void history_maybe_save(struct server *srv, int force);

#endif
