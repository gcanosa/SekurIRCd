/* Pointer-style lookups over tomlc17's tree (src/vendor/tomlc17.h).
 * tomlc17's toml_get() returns a copy and signals "missing" with TOML_UNKNOWN;
 * these return a pointer into the parsed tree, or NULL when the key is absent
 * or has the wrong type, so callers can keep `if (!tab)` checks. The tree lives
 * until toml_free() on its toml_result_t. */
#ifndef SEKURIRCD_TOMLX_H
#define SEKURIRCD_TOMLX_H

#include "vendor/tomlc17.h"
#include <string.h>

typedef const toml_datum_t toml_node_t;

/* Any value under `key`, or NULL. */
static inline toml_node_t *tx_get(toml_node_t *tab, const char *key) {
    if (!tab || tab->type != TOML_TABLE) return NULL;
    size_t kl = strlen(key);
    for (int i = 0; i < tab->u.tab.size; i++)
        if ((size_t)tab->u.tab.len[i] == kl && memcmp(tab->u.tab.key[i], key, kl) == 0)
            return &tab->u.tab.value[i];
    return NULL;
}

static inline toml_node_t *tx_typed(toml_node_t *d, toml_type_t t) {
    return d && d->type == t ? d : NULL;
}

static inline toml_node_t *tx_table(toml_node_t *tab, const char *key) { return tx_typed(tx_get(tab, key), TOML_TABLE); }
static inline toml_node_t *tx_array(toml_node_t *tab, const char *key) { return tx_typed(tx_get(tab, key), TOML_ARRAY); }
static inline toml_node_t *tx_string(toml_node_t *tab, const char *key) { return tx_typed(tx_get(tab, key), TOML_STRING); }
static inline toml_node_t *tx_int(toml_node_t *tab, const char *key) { return tx_typed(tx_get(tab, key), TOML_INT64); }
static inline toml_node_t *tx_bool(toml_node_t *tab, const char *key) { return tx_typed(tx_get(tab, key), TOML_BOOLEAN); }

static inline int tx_len(toml_node_t *arr) { return arr && arr->type == TOML_ARRAY ? arr->u.arr.size : 0; }

/* Element i of an array, or NULL when out of range or not of type t. */
static inline toml_node_t *tx_at(toml_node_t *arr, int i, toml_type_t t) {
    if (!arr || arr->type != TOML_ARRAY || i < 0 || i >= arr->u.arr.size) return NULL;
    return tx_typed(&arr->u.arr.elem[i], t);
}

#endif
