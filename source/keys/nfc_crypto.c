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

#include "nfc_crypto.h"

#include <mem/minerva.h>
#include <sec/se.h>

#include <string.h>

void nfc_decrypt_amiibo_keys(key_storage_t *keys, nfc_save_key_t out_nfc_save_keys[2], bool is_dev) {
    const u8 *encrypted_keys = is_dev ? encrypted_nfc_keys_dev : encrypted_nfc_keys;
    u32 kek[SE_KEY_128_SIZE / 4] = {0};
    decrypt_aes_key(KS_AES_ECB, keys, kek, nfc_key_source, 0, 0);

    nfc_keyblob_t __attribute__((aligned(4))) nfc_keyblob;
    static const u8 nfc_iv[SE_AES_IV_SIZE] = {
        0xB9, 0x1D, 0xC1, 0xCF, 0x33, 0x5F, 0xA6, 0x13, 0x2A, 0xEF, 0x90, 0x99, 0xAA, 0xCA, 0x93, 0xC8};
    se_aes_key_set(KS_AES_CTR, kek, SE_KEY_128_SIZE);
    se_aes_crypt_ctr(KS_AES_CTR, &nfc_keyblob, sizeof(nfc_keyblob), encrypted_keys, sizeof(nfc_keyblob), &nfc_iv);

    minerva_periodic_training();

    u32 xor_pad[0x20 / 4] = {0};
    se_aes_key_set(KS_AES_CTR, nfc_keyblob.ctr_key, SE_KEY_128_SIZE);
    se_aes_crypt_ctr(KS_AES_CTR, xor_pad, sizeof(xor_pad), xor_pad, sizeof(xor_pad), nfc_keyblob.ctr_iv);

    minerva_periodic_training();

    memcpy(out_nfc_save_keys[0].hmac_key, nfc_keyblob.hmac_key, sizeof(nfc_keyblob.hmac_key));
    memcpy(out_nfc_save_keys[0].phrase, nfc_keyblob.phrase, sizeof(nfc_keyblob.phrase));
    out_nfc_save_keys[0].seed_size = sizeof(nfc_keyblob.seed);
    memcpy(out_nfc_save_keys[0].seed, nfc_keyblob.seed, sizeof(nfc_keyblob.seed));
    memcpy(out_nfc_save_keys[0].xor_pad, xor_pad, sizeof(xor_pad));

    memcpy(out_nfc_save_keys[1].hmac_key, nfc_keyblob.hmac_key_for_verif, sizeof(nfc_keyblob.hmac_key_for_verif));
    memcpy(out_nfc_save_keys[1].phrase, nfc_keyblob.phrase_for_verif, sizeof(nfc_keyblob.phrase_for_verif));
    out_nfc_save_keys[1].seed_size = sizeof(nfc_keyblob.seed_for_verif);
    memcpy(out_nfc_save_keys[1].seed, nfc_keyblob.seed_for_verif, sizeof(nfc_keyblob.seed_for_verif));
    memcpy(out_nfc_save_keys[1].xor_pad, xor_pad, sizeof(xor_pad));
}
