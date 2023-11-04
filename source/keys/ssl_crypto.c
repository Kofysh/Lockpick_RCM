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

#include "ssl_crypto.h"

#include "cal0_read.h"
#include "gmac.h"

#include "../config.h"
#include <gfx_utils.h>
#include <sec/se.h>
#include <sec/se_t210.h>

#include <string.h>

extern hekate_config h_cfg;

void ssl_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_SSL_KEY) | IS_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_client_cert_kek_source, ssl_client_cert_key_source, generation, option);
}

void ssl_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_rsa_kekek_source, ssl_rsa_kek_source_legacy, generation, option);
}

void ssl_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const void *ssl_kek_source = is_dev ? ssl_rsa_kek_source_dev : ssl_rsa_kek_source;
    const u32 generation = 0;
    u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_DECRYPT_DEVICE_UNIQUE_DATA) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, ssl_rsa_kekek_source, ssl_kek_source, generation, option);
}

bool decrypt_ssl_rsa_key(key_storage_t *keys, void *buffer) {
    if (!cal0_read(KS_BIS_00_TWEAK, KS_BIS_00_CRYPT, buffer)) {
        return false;
    }

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)buffer;
    u32 generation = 0;
    const void *encrypted_key = NULL;
    const void *iv = NULL;
    u32 key_size = 0;
    void *ctr_key = NULL;
    bool enforce_unique = true;

    if (!cal0_get_ssl_rsa_key(cal0, &encrypted_key, &key_size, &iv, &generation)) {
        return false;
    }

    if (key_size == SSL_RSA_KEY_SIZE) {
        bool all_zero = true;
        const u8 *key8 = (const u8 *)encrypted_key;
        for (u32 i = SE_RSA2048_DIGEST_SIZE; i < SSL_RSA_KEY_SIZE; i++) {
            if (key8[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            // Keys of this form are not encrypted
            memcpy(keys->ssl_rsa_key, encrypted_key, SE_RSA2048_DIGEST_SIZE);
            return true;
        }

        ssl_derive_rsa_kek_legacy(keys, keys->ssl_rsa_kek_legacy);
        ctr_key = keys->ssl_rsa_kek_legacy;
        enforce_unique = false;
    } else if (generation) {
        ssl_derive_rsa_kek_device_unique(keys, keys->ssl_rsa_kek_personalized, generation);
        ctr_key = keys->ssl_rsa_kek_personalized;
    } else {
        ctr_key = keys->ssl_rsa_kek;
    }

    u32 ctr_size = enforce_unique ? key_size - 0x20 : key_size - 0x10;
    se_aes_key_set(KS_AES_CTR, ctr_key, SE_KEY_128_SIZE);
    se_aes_crypt_ctr(KS_AES_CTR, keys->ssl_rsa_key, ctr_size, encrypted_key, ctr_size, iv);

    if (enforce_unique) {
        u32 calc_mac[SE_KEY_128_SIZE / 4] = {0};
        calc_gmac(KS_AES_ECB, calc_mac, keys->ssl_rsa_key, ctr_size, ctr_key, iv);

        const u8 *key8 = (const u8 *)encrypted_key;
        if (memcmp(calc_mac, &key8[ctr_size], 0x10) != 0) {
            EPRINTF("SSL keypair has invalid GMac.");
            memset(keys->ssl_rsa_key, 0, sizeof(keys->ssl_rsa_key));
            return false;
        }
    }

    return true;
}
