#pragma once
#include <utils/types.h>

typedef struct {
    u8  magic[4];
    u8  distribution_type;
    u8  content_type;
    u8  crypto_type;
    u8  key_index;
    u64 content_size;
    u8  title_id[8];        // big-endian display order (reversed from file's little-endian)
    u32 content_index;
    u8  sdk_version[4];
    u8  key_generation;
    u8  crypto_type2;
    u8  rights_id[16];      // all-zero = standard crypto; non-zero = titlekey crypto
    u8  encrypted_key_area[4][16];
} NcaHeader;

// header_key: 32 bytes from key_storage_t.header_key
int ReadNcaHeader(const char *path, const u8 *header_key, NcaHeader *out);
