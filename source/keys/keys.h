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

#ifndef _KEYS_H_
#define _KEYS_H_

#include "crypto.h"

#include "../hos/hos.h"
#include <sec/se_t210.h>
#include <utils/types.h>

#define TPRINTF(text) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

#define TPRINTFARGS(text, args...) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", args, end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

// save key wrapper
#define SAVE_KEY(name) _save_key(#name, name, sizeof(name), text_buffer)
// save key with different name than variable
#define SAVE_KEY_VAR(name, varname) _save_key(#name, varname, sizeof(varname), text_buffer)
// save key family wrapper
#define SAVE_KEY_FAMILY(name, start) _save_key_family(#name, name, start, ARRAY_SIZE(name), sizeof(*(name)), text_buffer)
// save key family with different name than variable
#define SAVE_KEY_FAMILY_VAR(name, varname, start) _save_key_family(#name, varname, start, ARRAY_SIZE(varname), sizeof(*(varname)), text_buffer)

void dump_keys();
int save_mariko_partial_keys(u32 start, u32 count, bool append);
void derive_amiibo_keys();

#endif
