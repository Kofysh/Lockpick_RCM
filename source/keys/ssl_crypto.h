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

#ifndef _SSL_CRYPTO_H_
#define _SSL_CRYPTO_H_

#include "crypto.h"

#include <utils/types.h>

#define SSL_RSA_KEY_SIZE (SE_AES_IV_SIZE + SE_RSA2048_DIGEST_SIZE)

static const u8 ssl_rsa_kekek_source[0x10] __attribute__((aligned(4))) = {
    0x7F, 0x5B, 0xB0, 0x84, 0x7B, 0x25, 0xAA, 0x67, 0xFA, 0xC8, 0x4B, 0xE2, 0x3D, 0x7B, 0x69, 0x03};
static const u8 ssl_rsa_kek_source[0x10] __attribute__((aligned(4))) = {
    0x9A, 0x38, 0x3B, 0xF4, 0x31, 0xD0, 0xBD, 0x81, 0x32, 0x53, 0x4B, 0xA9, 0x64, 0x39, 0x7D, 0xE3};
static const u8 ssl_rsa_kek_source_dev[0x10] __attribute__((aligned(4))) = {
    0xD5, 0xD2, 0xFC, 0x00, 0xFD, 0x49, 0xDD, 0xF8, 0xEE, 0x7B, 0xC4, 0x4B, 0xE1, 0x4C, 0xAA, 0x99};
static const u8 ssl_rsa_kek_source_legacy[0x10] __attribute__((aligned(4))) = {
    0xED, 0x36, 0xB1, 0x32, 0x27, 0x17, 0xD2, 0xB0, 0xBA, 0x1F, 0xC1, 0xBD, 0x4D, 0x38, 0x0F, 0x5E};
static const u8 ssl_client_cert_kek_source[0x10] __attribute__((aligned(4))) = {
    0x64, 0xB8, 0x30, 0xDD, 0x0F, 0x3C, 0xB7, 0xFB, 0x4C, 0x16, 0x01, 0x97, 0xEA, 0x9D, 0x12, 0x10};
static const u8 ssl_client_cert_key_source[0x10] __attribute__((aligned(4))) = {
    0x4D, 0x92, 0x5A, 0x69, 0x42, 0x23, 0xBB, 0x92, 0x59, 0x16, 0x3E, 0x51, 0x8C, 0x78, 0x14, 0x0F};

void ssl_derive_rsa_kek_device_unique(key_storage_t *keys, void *out_rsa_kek, u32 generation);
void ssl_derive_rsa_kek_legacy(key_storage_t *keys, void *out_rsa_kek);
void ssl_derive_rsa_kek_original(key_storage_t *keys, void *out_rsa_kek, bool is_dev);

bool decrypt_ssl_rsa_key(key_storage_t *keys, void *buffer);

#endif
