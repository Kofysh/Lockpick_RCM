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

#ifndef _CAL0_READ_H_
#define _CAL0_READ_H_

#include "../storage/nx_emmc_bis.h"
#include <utils/types.h>

bool cal0_read(u32 tweak_ks, u32 crypt_ks, void *read_buffer);
bool cal0_get_ssl_rsa_key(const nx_emmc_cal0_t *cal0, const void **out_key, u32 *out_key_size, const void **out_iv, u32 *out_generation);
bool cal0_get_eticket_rsa_key(const nx_emmc_cal0_t *cal0, const void **out_key, u32 *out_key_size, const void **out_iv, u32 *out_generation);

#endif
