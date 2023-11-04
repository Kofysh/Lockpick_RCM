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

#include "es_crypto.h"

#include "cal0_read.h"

#include "../config.h"
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include <mem/minerva.h>
#include <sec/se.h>
#include <sec/se_t210.h>

#include <string.h>

extern hekate_config h_cfg;

bool test_eticket_rsa_keypair(const eticket_rsa_keypair_t *keypair) {
    if (byte_swap_32(keypair->public_exponent) != RSA_PUBLIC_EXPONENT)
        return false;
    return test_rsa_keypair(&keypair->public_exponent, keypair->private_exponent, keypair->modulus);
}

void es_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation, bool is_dev) {
    if ((!h_cfg.t210b01 && !key_exists(keys->device_key)) || (h_cfg.t210b01 && (!key_exists(keys->master_key[0]) || !key_exists(keys->device_key_4x)))) {
        return;
    }

    const void *kek_source = is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | IS_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, kek_source, generation, option);
}

void es_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, eticket_rsa_kek_source_legacy, generation, option);
}

void es_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev) {
    if (!key_exists(keys->master_key[0])) {
        return;
    }

    const void *kek_source = is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source;
    const u32 generation = 0;
    const u32 option = SET_SEAL_KEY_INDEX(SEAL_KEY_IMPORT_ES_DEVICE_KEY) | NOT_DEVICE_UNIQUE;
    derive_rsa_kek(KS_AES_ECB, keys, out_rsa_kek, eticket_rsa_kekek_source, kek_source, generation, option);
}

bool decrypt_eticket_rsa_key(key_storage_t *keys, void *buffer, bool is_dev) {
    if (!cal0_read(KS_BIS_00_TWEAK, KS_BIS_00_CRYPT, buffer)) {
        return false;
    }

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)buffer;
    u32 generation = 0;
    const void *encrypted_key = NULL;
    const void *iv = NULL;
    u32 key_size = 0;
    void *ctr_key = NULL;

    if (!cal0_get_eticket_rsa_key(cal0, &encrypted_key, &key_size, &iv, &generation)) {
        return false;
    }

    // Handle legacy case
    if (key_size == ETICKET_RSA_KEYPAIR_SIZE) {
        u32 temp_key[SE_KEY_128_SIZE / 4] = {0};
        es_derive_rsa_kek_legacy(keys, temp_key);
        ctr_key = temp_key;

        se_aes_key_set(KS_AES_CTR, ctr_key, SE_KEY_128_SIZE);
        se_aes_crypt_ctr(KS_AES_CTR, &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), encrypted_key, sizeof(keys->eticket_rsa_keypair), iv);

        if (test_eticket_rsa_keypair(&keys->eticket_rsa_keypair)) {
            memcpy(keys->eticket_rsa_kek, ctr_key, sizeof(keys->eticket_rsa_kek));
            return true;
        }
        // Fall through and try usual method if not applicable
    }

    if (generation) {
        es_derive_rsa_kek_device_unique(keys, keys->eticket_rsa_kek_personalized, generation, is_dev);
        ctr_key = keys->eticket_rsa_kek_personalized;
    } else {
        ctr_key = keys->eticket_rsa_kek;
    }

    se_aes_key_set(KS_AES_CTR, ctr_key, SE_KEY_128_SIZE);
    se_aes_crypt_ctr(KS_AES_CTR, &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), encrypted_key, sizeof(keys->eticket_rsa_keypair), iv);

    if (!test_eticket_rsa_keypair(&keys->eticket_rsa_keypair)) {
        EPRINTF("Invalid eticket keypair.");
        memset(&keys->eticket_rsa_keypair, 0, sizeof(keys->eticket_rsa_keypair));
        return false;
    }

    return true;
}

void es_decode_tickets(u32 buf_size, titlekey_buffer_t *titlekey_buffer, u32 remaining, u32 total, u32 *titlekey_count, u32 x, u32 y, u32 *pct, u32 *last_pct, bool is_personalized) {
    ticket_t *curr_ticket = (ticket_t *)titlekey_buffer->read_buffer;
    for (u32 i = 0; i < MIN(buf_size / sizeof(ticket_t), remaining) * sizeof(ticket_t) && curr_ticket->signature_type != 0; i += sizeof(ticket_t), curr_ticket++) {
        minerva_periodic_training();
        *pct = (total - remaining) * 100 / total;
        if (*pct > *last_pct && *pct <= 100) {
            *last_pct = *pct;
            tui_pbar(x, y, *pct, COLOR_GREEN, 0xFF155500);
        }

        // This is in case an encrypted volatile ticket is left behind
        if (curr_ticket->signature_type != TICKET_SIG_TYPE_RSA2048_SHA256)
            continue;

        u8 *curr_titlekey = curr_ticket->titlekey_block;
        const u32 block_size = SE_RSA2048_DIGEST_SIZE;
        const u32 titlekey_size = sizeof(titlekey_buffer->titlekeys[0]);
        if (is_personalized) {
            se_rsa_exp_mod(0, curr_titlekey, block_size, curr_titlekey, block_size);
            if (rsa_oaep_decode(curr_titlekey, titlekey_size, null_hash, sizeof(null_hash), curr_titlekey, block_size) != titlekey_size)
                continue;
        }
        memcpy(titlekey_buffer->rights_ids[*titlekey_count], curr_ticket->rights_id, sizeof(titlekey_buffer->rights_ids[0]));
        memcpy(titlekey_buffer->titlekeys[*titlekey_count], curr_titlekey, titlekey_size);
        (*titlekey_count)++;
    }
}
