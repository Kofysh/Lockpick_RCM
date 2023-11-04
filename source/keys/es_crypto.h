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

#ifndef _ES_CRYPTO_H_
#define _ES_CRYPTO_H_

#include "crypto.h"
#include "es_types.h"

#include <sec/se_t210.h>
#include <utils/types.h>

#define ETICKET_RSA_KEYPAIR_SIZE (SE_AES_IV_SIZE + SE_RSA2048_DIGEST_SIZE * 2 + SE_KEY_128_SIZE)

#define TICKET_SIG_TYPE_RSA2048_SHA256 0x10004

static const u8 eticket_rsa_kek_source[0x10] __attribute__((aligned(4))) = {
    0xDB, 0xA4, 0x51, 0x12, 0x4C, 0xA0, 0xA9, 0x83, 0x68, 0x14, 0xF5, 0xED, 0x95, 0xE3, 0x12, 0x5B};
static const u8 eticket_rsa_kek_source_dev[0x10] __attribute__((aligned(4))) = {
    0xBE, 0xC0, 0xBC, 0x8E, 0x75, 0xA0, 0xF6, 0x0C, 0x4A, 0x56, 0x64, 0x02, 0x3E, 0xD4, 0x9C, 0xD5};
static const u8 eticket_rsa_kek_source_legacy[0x10] __attribute__((aligned(4))) = {
    0x88, 0x87, 0x50, 0x90, 0xA6, 0x2F, 0x75, 0x70, 0xA2, 0xD7, 0x71, 0x51, 0xAE, 0x6D, 0x39, 0x87};
static const u8 eticket_rsa_kekek_source[0x10] __attribute__((aligned(4))) = {
    0x46, 0x6E, 0x57, 0xB7, 0x4A, 0x44, 0x7F, 0x02, 0xF3, 0x21, 0xCD, 0xE5, 0x8F, 0x2F, 0x55, 0x35};

bool test_eticket_rsa_keypair(const eticket_rsa_keypair_t *keypair);

void es_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation, bool is_dev);
void es_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek);
void es_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev);

bool decrypt_eticket_rsa_key(key_storage_t *keys, void *buffer, bool is_dev);

void es_decode_tickets(u32 buf_size, titlekey_buffer_t *titlekey_buffer, u32 remaining, u32 total, u32 *titlekey_count, u32 x, u32 y, u32 *pct, u32 *last_pct, bool is_personalized);

#endif
