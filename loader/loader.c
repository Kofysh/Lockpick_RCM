/*
 * Copyright (c) 2019 CTCaer
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

#include <string.h>
#include <stdlib.h>
#include "payload_00.h"
#include "payload_01.h"
#include <memory_map.h>
#include <libs/compr/lz.h>
#include <soc/clock.h>
#include <soc/t210.h>

#define IPL_RELOC_TOP  0x40038000
#define IPL_PATCHED_RELOC_SZ 0x94
#define ALIGN_4_BYTES(x) (((x) + 3) & ~3)

// Boot configuration and IPL version metadata sections.
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic = LP_MAGIC,
	.version = (LP_VER_MJ + '0') | ((LP_VER_MN + '0') << 8) | ((LP_VER_BF + '0') << 16),
	.rsvd0 = 0,
	.rsvd1 = 0
};

void initialize_clocks() {
	// Preliminary BPMP clocks initialization.
	CLOCK(CLK_RST_CONTROLLER_CLK_SYSTEM_RATE) = 0x10;          // Set HCLK div to 2 and PCLK div to 1.
	CLOCK(CLK_RST_CONTROLLER_CLK_SOURCE_SYS) = 0;              // Set SCLK div to 1.
	CLOCK(CLK_RST_CONTROLLER_SCLK_BURST_POLICY) = 0x20004444;  // Set clock source to Run and PLLP_OUT2 (204MHz).
	CLOCK(CLK_RST_CONTROLLER_SUPER_SCLK_DIVIDER) = 0x80000000; // Enable SUPER_SDIV to 1.
	CLOCK(CLK_RST_CONTROLLER_CLK_SYSTEM_RATE) = 2;             // Set HCLK div to 1 and PCLK div to 3.
	CLOCK(CLK_RST_CONTROLLER_SCLK_BURST_POLICY) = 0x20003333;  // Set SCLK to PLLP_OUT (408MHz).
}

void relocate_payload(u32 *payload_addr, u32 payload_size) {
	u32 bytes = ALIGN_4_BYTES(payload_size) >> 2;
	u32 *addr = payload_addr + bytes - 1;
	u32 *dst = (u32 *)(IPL_RELOC_TOP - 4);

	while (bytes) {
		*dst = *addr;
		dst--;
		addr--;
		bytes--;
	}
}

void uncompress_payload(u8 *src_addr, u32 payload_size_part, u8 *dest_addr, u32 *dst_pos) {
	*dst_pos = LZ_Uncompress(src_addr, dest_addr, payload_size_part);
}

void loader_main() {
	initialize_clocks();

	// Calculate the total payload size with alignment.
	u32 payload_size = sizeof(payload_00) + sizeof(payload_01) + 
	                  ((u32)payload_01 - (u32)payload_00 - sizeof(payload_00));
	u32 *payload_addr = (u32 *)payload_00;

	// Relocate payload to a safer place.
	relocate_payload(payload_addr, payload_size);

	// Uncompress the first part of the payload.
	u8 *src_addr = (u8 *)(IPL_RELOC_TOP - ALIGN_4_BYTES(payload_size));
	u32 dst_pos = 0;
	uncompress_payload(src_addr, sizeof(payload_00), (u8*)IPL_LOAD_ADDR, &dst_pos);

	// Uncompress the second part of the payload.
	src_addr += (u32)payload_01 - (u32)payload_00;
	uncompress_payload(src_addr, sizeof(payload_01), (u8*)IPL_LOAD_ADDR + dst_pos, &dst_pos);

	// Copy over boot configuration storage.
	memcpy((u8 *)(IPL_LOAD_ADDR + IPL_PATCHED_RELOC_SZ), &b_cfg, sizeof(boot_cfg_t));

	// Chainload into the uncompressed payload.
	void (*ipl_ptr)() = (void *)IPL_LOAD_ADDR;
	ipl_ptr();

	// Halt if we managed to get out of execution.
	while (true)
		;
}
