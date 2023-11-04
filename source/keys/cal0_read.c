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

#include "cal0_read.h"

#include <gfx_utils.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include <utils/util.h>

bool cal0_read(u32 tweak_ks, u32 crypt_ks, void *read_buffer) {
    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)read_buffer;

    // Check if CAL0 was already read into this buffer
    if (cal0->magic == MAGIC_CAL0) {
        return true;
    }

    if (!emummc_storage_read(NX_EMMC_CALIBRATION_OFFSET / NX_EMMC_BLOCKSIZE, NX_EMMC_CALIBRATION_SIZE / NX_EMMC_BLOCKSIZE, read_buffer)) {
        EPRINTF("Unable to read PRODINFO.");
        return false;
    }

    se_aes_xts_crypt(tweak_ks, crypt_ks, DECRYPT, 0, read_buffer, read_buffer, XTS_CLUSTER_SIZE, NX_EMMC_CALIBRATION_SIZE / XTS_CLUSTER_SIZE);

    if (cal0->magic != MAGIC_CAL0) {
        EPRINTF("Invalid CAL0 magic. Check BIS key 0.");
        return false;
    }

    return true;
}

bool cal0_get_ssl_rsa_key(const nx_emmc_cal0_t *cal0, const void **out_key, u32 *out_key_size, const void **out_iv, u32 *out_generation) {
    const u32 ext_key_size = sizeof(cal0->ext_ssl_key_iv) + sizeof(cal0->ext_ssl_key);
    const u32 ext_key_crc_size = ext_key_size + sizeof(cal0->ext_ssl_key_ver) + sizeof(cal0->crc16_pad39);
    const u32 key_size = sizeof(cal0->ssl_key_iv) + sizeof(cal0->ssl_key);
    const u32 key_crc_size = key_size + sizeof(cal0->crc16_pad18);

    if (cal0->ext_ssl_key_crc == crc16_calc(cal0->ext_ssl_key_iv, ext_key_crc_size)) {
        *out_key = cal0->ext_ssl_key;
        *out_key_size = ext_key_size;
        *out_iv = cal0->ext_ssl_key_iv;
        // Settings sysmodule manually zeroes this out below cal version 9
        *out_generation = cal0->version <= 8 ? 0 : cal0->ext_ssl_key_ver;
    } else if (cal0->ssl_key_crc == crc16_calc(cal0->ssl_key_iv, key_crc_size)) {
        *out_key = cal0->ssl_key;
        *out_key_size = key_size;
        *out_iv = cal0->ssl_key_iv;
        *out_generation = 0;
    } else {
        EPRINTF("Crc16 error reading device key.");
        return false;
    }
    return true;
}


bool cal0_get_eticket_rsa_key(const nx_emmc_cal0_t *cal0, const void **out_key, u32 *out_key_size, const void **out_iv, u32 *out_generation) {
    const u32 ext_key_size = sizeof(cal0->ext_ecc_rsa2048_eticket_key_iv) + sizeof(cal0->ext_ecc_rsa2048_eticket_key);
    const u32 ext_key_crc_size = ext_key_size + sizeof(cal0->ext_ecc_rsa2048_eticket_key_ver) + sizeof(cal0->crc16_pad38);
    const u32 key_size = sizeof(cal0->rsa2048_eticket_key_iv) + sizeof(cal0->rsa2048_eticket_key);
    const u32 key_crc_size = key_size + sizeof(cal0->crc16_pad21);

    if (cal0->ext_ecc_rsa2048_eticket_key_crc == crc16_calc(cal0->ext_ecc_rsa2048_eticket_key_iv, ext_key_crc_size)) {
        *out_key = cal0->ext_ecc_rsa2048_eticket_key;
        *out_key_size = ext_key_size;
        *out_iv = cal0->ext_ecc_rsa2048_eticket_key_iv;
        // Settings sysmodule manually zeroes this out below cal version 9
        *out_generation = cal0->version <= 8 ? 0 : cal0->ext_ecc_rsa2048_eticket_key_ver;
    } else if (cal0->rsa2048_eticket_key_crc == crc16_calc(cal0->rsa2048_eticket_key_iv, key_crc_size)) {
        *out_key = cal0->rsa2048_eticket_key;
        *out_key_size = key_size;
        *out_iv = cal0->rsa2048_eticket_key_iv;
        *out_generation = 0;
    } else {
        EPRINTF("Crc16 error reading device key.");
        return false;
    }
    return true;
}
