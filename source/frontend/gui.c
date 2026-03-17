/*
 * Copyright (c) 2018-2021 CTCaer
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

#include "../gfx/gfx.h"
#include <mem/heap.h>
#include <rtc/max77620-rtc.h>
#include <storage/nx_sd.h>
#include <utils/util.h>

#include <string.h>

int save_fb_to_bmp()
{
	// Disallow screenshots if less than 2s passed.
	static u32 timer = 0;
	if (get_tmr_ms() < timer)
		return 1;

	const u32 file_size = 0x384000 + 0x36;
	u8 *bitmap = malloc(file_size);
	u32 *fb = malloc(0x384000);
	u32 *fb_ptr = gfx_ctxt.fb;

	// Reconstruct FB for bottom-top, portrait bmp.
	for (int y = 1279; y > -1; y--)
	{
		for (u32 x = 0; x < 720; x++)
			fb[y * 720 + x] = *fb_ptr++;
	}

	memcpy(bitmap + 0x36, fb, 0x384000);

	typedef struct _bmp_t
	{
		u16 magic;
		u32 size;
		u32 rsvd;
		u32 data_off;
		u32 hdr_size;
		u32 width;
		u32 height;
		u16 planes;
		u16 pxl_bits;
		u32 comp;
		u32 img_size;
		u32 res_h;
		u32 res_v;
		u64 rsvd2;
	} __attribute__((packed)) bmp_t;

	bmp_t *bmp = (bmp_t *)bitmap;

	bmp->magic    = 0x4D42;
	bmp->size     = file_size;
	bmp->rsvd     = 0;
	bmp->data_off = 0x36;
	bmp->hdr_size = 40;
	bmp->width    = 720;
	bmp->height   = 1280;
	bmp->planes   = 1;
	bmp->pxl_bits = 32;
	bmp->comp     = 0;
	bmp->img_size = 0x384000;
	bmp->res_h    = 2834;
	bmp->res_v    = 2834;
	bmp->rsvd2    = 0;

	sd_mount();

	f_mkdir("sd:/switch");
	
	char path[0x80] = "sd:/switch/lockpick_rcm.bmp";

	// Save screenshot and log.
	int res = sd_save_to_file(bitmap, file_size, path);

	// sd_unmount();

	free(bitmap);
	free(fb);

	// Set timer to 2s.
	timer = get_tmr_ms() + 2000;

    return res;
}
