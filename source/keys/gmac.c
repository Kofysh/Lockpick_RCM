/*
 * Copyright (c) 2018-2020 Atmosphère-NX
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

#include "gmac.h"

#include <sec/se.h>
#include <sec/se_t210.h>

#include <stdint.h>
#include <string.h>

/* Shifts right a little endian 128-bit value. */
static void _shr_128(uint64_t *val) {
    val[0] >>= 1;
    val[0] |= (val[1] & 1) << 63;
    val[1] >>= 1;
}

/* Shifts left a little endian 128-bit value. */
static void _shl_128(uint64_t *val) {
    val[1] <<= 1;
    val[1] |= (val[0] & (1ull << 63)) >> 63;
    val[0] <<= 1;
}

/* Multiplies two 128-bit numbers X,Y in the GF(128) Galois Field. */
static void _gf128_mul(uint8_t *dst, const uint8_t *x, const uint8_t *y) {
    uint8_t x_work[0x10];
    uint8_t y_work[0x10];
    uint8_t dst_work[0x10];

    uint64_t *p_x = (uint64_t *)(&x_work[0]);
    uint64_t *p_y = (uint64_t *)(&y_work[0]);
    uint64_t *p_dst = (uint64_t *)(&dst_work[0]);

    /* Initialize buffers. */
    for (unsigned int i = 0; i < 0x10; i++) {
        x_work[i] = x[0xF-i];
        y_work[i] = y[0xF-i];
        dst_work[i] = 0;
    }

    /* Perform operation for each bit in y. */
    for (unsigned int round = 0; round < 0x80; round++) {
        p_dst[0] ^= p_x[0] * ((y_work[0xF] & 0x80) >> 7);
        p_dst[1] ^= p_x[1] * ((y_work[0xF] & 0x80) >> 7);
        _shl_128(p_y);
        uint8_t xval = 0xE1 * (x_work[0] & 1);
        _shr_128(p_x);
        x_work[0xF] ^= xval;
    }

    for (unsigned int i = 0; i < 0x10; i++) {
        dst[i] = dst_work[0xF-i];
    }
}

static void _ghash(u32 ks, void *dst, const void *src, u32 src_size, const void *j_block, bool encrypt) {
    uint8_t x[0x10] = {0};
    uint8_t h[0x10];

    uint64_t *p_x = (uint64_t *)(&x[0]);
    uint64_t *p_data = (uint64_t *)src;

    /* H = aes_ecb_encrypt(zeroes) */
    se_aes_crypt_block_ecb(ks, ENCRYPT, h, x);

    u64 total_size = src_size;

    while (src_size >= 0x10) {
        /* X = (X ^ current_block) * H */
        p_x[0] ^= p_data[0];
        p_x[1] ^= p_data[1];
        _gf128_mul(x, x, h);

        /* Increment p_data by 0x10 bytes. */
        p_data += 2;
        src_size -= 0x10;
    }

    /* Nintendo's code *discards all data in the last block* if unaligned. */
    /* And treats that block as though it were all-zero. */
    /* This is a bug, they just forget to XOR with the copy of the last block they save. */
    if (src_size & 0xF) {
        _gf128_mul(x, x, h);
    }

    uint64_t xor_size = total_size << 3;
    xor_size = __builtin_bswap64(xor_size);

    /* Due to a Nintendo bug, the wrong QWORD gets XOR'd in the "final output block" case. */
    if (encrypt) {
        p_x[0] ^= xor_size;
    } else {
        p_x[1] ^= xor_size;
    }

    _gf128_mul(x, x, h);

    /* If final output block, XOR with encrypted J block. */
    if (encrypt) {
        se_aes_crypt_block_ecb(ks, ENCRYPT, h, j_block);
        for (unsigned int i = 0; i < 0x10; i++) {
            x[i] ^= h[i];
        }
    }
    /* Copy output. */
    memcpy(dst, x, 0x10);
}

void calc_gmac(u32 ks, void *out_gmac, const void *data, u32 size, const void *key, const void *iv) {
    u32 j_block[4] = {0};
    se_aes_key_set(ks, key, 0x10);
    _ghash(ks, j_block, iv, 0x10, NULL, false);
    _ghash(ks, out_gmac, data, size, j_block, true);
}
