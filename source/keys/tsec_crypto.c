/*
 * Copyright (c) 2019-2022 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tsec_crypto.h"
#include "fs_crypto.h"

#include <sec/se.h>
#include <sec/se_t210.h>
#include <string.h>

#include "key_sources.inl"

// "HOVI_KEK_KEY_PRD" — tsec_root_kek_source
static const u8 tsec_root_kek_source[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44 };
// "HOVI_ENC_KEY_PRD" — package1_kek_source
static const u8 package1_kek_source_hovi[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44 };
// HOVI_SIG_KEY_PRD - package1_mac_kek_source
static const u8 package1_mac_kek_source_hovi[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44 };

// "HOVI_KEK_KEY_DEV" — tsec_root_kek_source
static const u8 tsec_root_kek_source_dev[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56 };
// "HOVI_ENC_KEY_DEV" — package1_kek_source
static const u8 package1_kek_source_hovi_dev[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56 };
// HOVI_SIG_KEY_DEV - package1_mac_kek_source
static const u8 package1_mac_kek_source_hovi_dev[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56 };

// TSEC auth signatures for TSEC key revision 00, 01, 02
static const u8 tsec_auth_signature_00[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0xA7, 0x7B, 0x86, 0x58, 0x6A, 0xE1, 0xB0, 0x3D, 0x4F, 0xFB, 0xA3, 0xAD, 0xA8, 0xF8, 0xDE, 0x32 };
static const u8 tsec_auth_signature_01[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0xA3, 0xFF, 0xB0, 0xF6, 0xBC, 0x49, 0xA0, 0x6D, 0xF2, 0xFC, 0x79, 0x16, 0x97, 0xD8, 0x1D, 0x32 };
static const u8 tsec_auth_signature_02[SE_KEY_128_SIZE] __attribute__((aligned(4))) = {
    0x0B, 0x55, 0xCC, 0x08, 0x20, 0xE6, 0x30, 0x7F, 0xD0, 0x87, 0x47, 0x9E, 0xAA, 0x2E, 0x7F, 0x98 };

void tsec_derive_package1_key_08(u8 *out) {
    u8 pkg1_kek[SE_KEY_128_SIZE];
    load_aes_key(KS_AES_ECB, pkg1_kek, hovi_kek, package1_kek_source_hovi);
    se_aes_key_set(KS_AES_ECB, pkg1_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out, tsec_auth_signature_02);
}

// tsec_root_kek_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_root_kek_sw(u8 *out_00, u8 *out_01, u8 *out_02) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, tsec_root_kek_source); // this is both kek 00 and 01
    memcpy(out_00, kek, SE_KEY_128_SIZE);
    memcpy(out_01, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, tsec_root_kek_source); // this is kek 02
    memcpy(out_02, kek, SE_KEY_128_SIZE);
}

// tsec_root_kek_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_root_kek_dev_sw(u8 *out_00, u8 *out_01, u8 *out_02) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, tsec_root_kek_source_dev); // this is both kek 00 and 01
    memcpy(out_00, kek, SE_KEY_128_SIZE);
    memcpy(out_01, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, tsec_root_kek_source_dev); // this is kek 02
    memcpy(out_02, kek, SE_KEY_128_SIZE);
}

// package1_key_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_package1_kek_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, package1_kek_source_hovi); // this is both kek 00 and 01
    memcpy(out_06, kek, SE_KEY_128_SIZE);
    memcpy(out_07, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, package1_kek_source_hovi); // this is kek 02
    memcpy(out_08, kek, SE_KEY_128_SIZE);
}

// package1_key_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_package1_kek_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, package1_kek_source_hovi_dev); // this is both kek 00 and 01
    memcpy(out_06, kek, SE_KEY_128_SIZE);
    memcpy(out_07, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, package1_kek_source_hovi_dev); // this is kek 02
    memcpy(out_08, kek, SE_KEY_128_SIZE);
}

// package1_mac_key_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_package1_mac_kek_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, package1_mac_kek_source_hovi); // this is both kek 00 and 01
    memcpy(out_06, kek, SE_KEY_128_SIZE);
    memcpy(out_07, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, package1_mac_kek_source_hovi); // this is kek 02
    memcpy(out_08, kek, SE_KEY_128_SIZE);
}

// package1_mac_key_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_package1_mac_kek_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek[SE_KEY_128_SIZE];
    se_aes_key_set(KS_AES_ECB, hovi_kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, kek, package1_mac_kek_source_hovi_dev); // this is both kek 00 and 01
    memcpy(out_06, kek, SE_KEY_128_SIZE);
    memcpy(out_07, kek, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, kek, package1_mac_kek_source_hovi_dev); // this is kek 02
    memcpy(out_08, kek, SE_KEY_128_SIZE);
}

// tsec_root_key_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_root_keys_sw(u8 *out_00, u8 *out_01, u8 *out_02) {
    u8 kek_00[SE_KEY_128_SIZE], kek_01[SE_KEY_128_SIZE], kek_02[SE_KEY_128_SIZE];
    tsec_derive_root_kek_sw(kek_00, kek_01, kek_02);

    se_aes_key_set(KS_AES_ECB, kek_00, SE_KEY_128_SIZE); // kek_00 == kek_01
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_00, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_01, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_02, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_02, tsec_auth_signature_02);
}

// tsec_root_key_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_root_keys_dev_sw(u8 *out_00, u8 *out_01, u8 *out_02) {
    u8 kek_00[SE_KEY_128_SIZE], kek_01[SE_KEY_128_SIZE], kek_02[SE_KEY_128_SIZE];
    tsec_derive_root_kek_dev_sw(kek_00, kek_01, kek_02);

    se_aes_key_set(KS_AES_ECB, kek_00, SE_KEY_128_SIZE); // kek_00 == kek_01
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_00, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_01, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_02, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_02, tsec_auth_signature_02);
}

// package1_key_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_package1_keys_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek_06[SE_KEY_128_SIZE], kek_07[SE_KEY_128_SIZE], kek_08[SE_KEY_128_SIZE];
    tsec_derive_package1_kek_sw(kek_06, kek_07, kek_08);

    se_aes_key_set(KS_AES_ECB, kek_06, SE_KEY_128_SIZE); // kek_06 == kek_07
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_06, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_07, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_08, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_08, tsec_auth_signature_02);
}

// package1_key_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_package1_keys_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek_06[SE_KEY_128_SIZE], kek_07[SE_KEY_128_SIZE], kek_08[SE_KEY_128_SIZE];
    tsec_derive_package1_kek_dev_sw(kek_06, kek_07, kek_08);

    se_aes_key_set(KS_AES_ECB, kek_06, SE_KEY_128_SIZE); // kek_06 == kek_07
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_06, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_07, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_08, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_08, tsec_auth_signature_02);
}

// package1_mac_key_00/01 derived from hovi_kek for prod.keys output.
void tsec_derive_package1_mac_keys_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek_06[SE_KEY_128_SIZE], kek_07[SE_KEY_128_SIZE], kek_08[SE_KEY_128_SIZE];
    tsec_derive_package1_mac_kek_sw(kek_06, kek_07, kek_08);

    se_aes_key_set(KS_AES_ECB, kek_06, SE_KEY_128_SIZE); // kek_06 == kek_07
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_06, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_07, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_08, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_08, tsec_auth_signature_02);
}

// package1_mac_key_00/01 derived from hovi_kek for dev.keys output.
void tsec_derive_package1_mac_keys_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08) {
    u8 kek_06[SE_KEY_128_SIZE], kek_07[SE_KEY_128_SIZE], kek_08[SE_KEY_128_SIZE];
    tsec_derive_package1_mac_kek_dev_sw(kek_06, kek_07, kek_08);

    se_aes_key_set(KS_AES_ECB, kek_06, SE_KEY_128_SIZE); // kek_06 == kek_07
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_06, tsec_auth_signature_00);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_07, tsec_auth_signature_01);
    se_aes_key_set(KS_AES_ECB, kek_08, SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(KS_AES_ECB, ENCRYPT, out_08, tsec_auth_signature_02);
}

// Derive all new-generation keys from master_kek_source + tsec_root_key (= tsec_root_key_02).
void tsec_derive_new_gen_keys(const u8 *new_mkek_src, const u8 *tsec_root_key, new_gen_keys_t *out) {
    // master_kek = DECRYPT(new_mkek_src, tsec_root_key)
    load_aes_key(KS_AES_ECB, out->master_kek, tsec_root_key, new_mkek_src);
    // master_key = DECRYPT(master_key_source, master_kek)
    load_aes_key(KS_AES_ECB, out->master_key, out->master_kek, master_key_source);
    // package2_key, titlekek
    load_aes_key(KS_AES_ECB, out->package2_key, out->master_key, package2_key_source);
    load_aes_key(KS_AES_ECB, out->titlekek,     out->master_key, titlekek_source);

    // key_area_key_* via generateKek chain:
    //   kek     = DECRYPT(aes_kek_generation_source, master_key)
    //   src_kek = DECRYPT(key_area_key_sources[t], kek)
    //   result  = DECRYPT(aes_key_generation_source, src_kek)
    u8 kek[SE_KEY_128_SIZE], src_kek[SE_KEY_128_SIZE];
    u8 *targets[3] = {
        out->key_area_key_application,
        out->key_area_key_ocean,
        out->key_area_key_system
    };
    for (int t = 0; t < 3; t++) {
        load_aes_key(KS_AES_ECB, kek,       out->master_key, aes_kek_generation_source);
        load_aes_key(KS_AES_ECB, src_kek,   kek,             key_area_key_sources[t]);
        load_aes_key(KS_AES_ECB, targets[t], src_kek,        aes_key_generation_source);
    }
}
