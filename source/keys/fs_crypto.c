/*
 * Copyright (c) 2022 shchmue
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

#include "fs_crypto.h"

#include "../config.h"
#include <sec/se_t210.h>

#include <string.h>

extern hekate_config h_cfg;

void fs_derive_bis_keys(key_storage_t *keys, u8 out_bis_keys[4][32], u32 generation) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    generate_specific_aes_key(KS_AES_ECB, keys, out_bis_keys[0], bis_key_sources[0], generation);
    u32 access_key[SE_KEY_128_SIZE / 4] = {0};
    const u32 option = IS_DEVICE_UNIQUE;
    generate_aes_kek(KS_AES_ECB, keys, access_key, bis_kek_source, generation, option);
    generate_aes_key(KS_AES_ECB, keys, out_bis_keys[1], sizeof(bis_key_sources[1]), access_key, bis_key_sources[1]);
    generate_aes_key(KS_AES_ECB, keys, out_bis_keys[2], sizeof(bis_key_sources[2]), access_key, bis_key_sources[2]);
    memcpy(out_bis_keys[3], out_bis_keys[2], sizeof(bis_key_sources[2]));
}

void fs_derive_header_key(key_storage_t *keys, void *out_key) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    u32 access_key[SE_KEY_128_SIZE / 4] = {0};
    const u32 generation = 0;
    const u32 option = NOT_DEVICE_UNIQUE;
    generate_aes_kek(KS_AES_ECB, keys, access_key, header_kek_source, generation, option);
    generate_aes_key(KS_AES_ECB, keys, out_key, sizeof(header_key_source), access_key, header_key_source);
}

void fs_derive_key_area_key(key_storage_t *keys, void *out_key, u32 source_type, u32 generation) {
    u32 access_key[SE_KEY_128_SIZE / 4] = {0};
    const u32 option = NOT_DEVICE_UNIQUE;
    generate_aes_kek(KS_AES_ECB, keys, access_key, key_area_key_sources[source_type], generation + 1, option);
    load_aes_key(KS_AES_ECB, out_key, access_key, aes_key_generation_source);
}

void fs_derive_save_mac_key(key_storage_t *keys, void *out_key) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    u32 access_key[SE_KEY_128_SIZE / 4] = {0};
    const u32 generation = 0;
    const u32 option = IS_DEVICE_UNIQUE;
    generate_aes_kek(KS_AES_ECB, keys, access_key, save_mac_kek_source, generation, option);
    load_aes_key(KS_AES_ECB, out_key, access_key, save_mac_key_source);
}
