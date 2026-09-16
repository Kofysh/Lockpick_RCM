#pragma once
#include <utils/types.h>
#include "crypto.h"
#include "tsec_crypto.h"

// Mounts BIS, scans for NCA 0100000000000816, and — if its master_key_revision
// exceeds CURRENT_KEY_GENERATION — extracts package1 and derives new keys for
// both prod (out) and dev (out_dev) key hierarchies.
// Returns master_key_revision (positive) on success, 0 if up to date, -1 on error.
// out_mkr is set to the new master_key_revision on success, 0 otherwise.
// out_gap_start/out_gap_end describe the inclusive range of revisions between
// CURRENT_KEY_GENERATION and out_mkr that could NOT be recovered (package1 only
// ever yields the master_kek_source for its own live revision). Range is empty
// (out_gap_start > out_gap_end) when out_mkr == CURRENT_KEY_GENERATION + 1.
int extract_new_gen_keys(key_storage_t *keys, new_gen_keys_t *out, new_gen_keys_t *out_dev,
                          int *out_mkr, int *out_gap_start, int *out_gap_end);