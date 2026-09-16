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

#pragma once
#include <utils/types.h>
#include "crypto.h"

// The master_key_revision expected from the latest known firmware (= KB_FIRMWARE_VERSION_MAX).
// Matches nca.py: master_key_revision = key_generation - 1
// Update alongside KB_FIRMWARE_VERSION_MAX in hos.h when new master keys are added.
#define CURRENT_KEY_GENERATION KB_FIRMWARE_VERSION_MAX

typedef struct {
    u8 master_kek[SE_KEY_128_SIZE];
    u8 master_key[SE_KEY_128_SIZE];
    u8 package2_key[SE_KEY_128_SIZE];
    u8 titlekek[SE_KEY_128_SIZE];
    u8 key_area_key_application[SE_KEY_128_SIZE];
    u8 key_area_key_ocean[SE_KEY_128_SIZE];
    u8 key_area_key_system[SE_KEY_128_SIZE];
    u8 tsec_root_key_00[SE_KEY_128_SIZE];
    u8 tsec_root_key_01[SE_KEY_128_SIZE];
    u8 tsec_root_key_02[SE_KEY_128_SIZE];
} new_gen_keys_t;

// package1_key_08 = AES_ECB_ENCRYPT(tsec_auth_signature_02, AES_ECB_DECRYPT("HOVI_ENC_KEY_PRD", hovi_kek))
void tsec_derive_package1_key_08(u8 *out);

// tsec_root_key_00/01/02 derived from hovi_kek for prod.keys output.
void tsec_derive_root_keys_sw(u8 *out_00, u8 *out_01, u8 *out_02);

// tsec_root_key_00/01/02 derived from hovi_kek for dev.keys output.
void tsec_derive_root_keys_dev_sw(u8 *out_00, u8 *out_01, u8 *out_02);

// tsec_root_kek_00/01/02 derived from hovi_kek for prod/dev.keys output.
void tsec_derive_root_kek_sw(u8 *out_00, u8 *out_01, u8 *out_02);
void tsec_derive_root_kek_dev_sw(u8 *out_00, u8 *out_01, u8 *out_02);

// package1_kek_06/07/08 derived from hovi_kek for prod/dev.keys output.
void tsec_derive_package1_kek_sw(u8 *out_06, u8 *out_07, u8 *out_08);
void tsec_derive_package1_kek_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08);

// package1_mac_kek_06/07/08 derived from hovi_kek for prod/dev.keys output.
void tsec_derive_package1_mac_kek_sw(u8 *out_06, u8 *out_07, u8 *out_08);
void tsec_derive_package1_mac_kek_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08);

// package1_key_06/07/08 derived from hovi_kek for prod/dev.keys output.
void tsec_derive_package1_keys_sw(u8 *out_06, u8 *out_07, u8 *out_08);
void tsec_derive_package1_keys_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08);

// package1_mac_key_06/07/08 derived from hovi_kek for prod/dev.keys output.
void tsec_derive_package1_mac_keys_sw(u8 *out_06, u8 *out_07, u8 *out_08);
void tsec_derive_package1_mac_keys_dev_sw(u8 *out_06, u8 *out_07, u8 *out_08);

// Derive all new-generation keys from master_kek_source + tsec_root_key (= tsec_root_key_02).
void tsec_derive_new_gen_keys(const u8 *new_mkek_src, const u8 *tsec_root_key, new_gen_keys_t *out);
