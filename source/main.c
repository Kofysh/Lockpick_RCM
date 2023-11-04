/*
 * Copyright (c) 2018 naehrwert
 *
 * Copyright (c) 2018-2021 CTCaer
 * Copyright (c) 2019-2021 shchmue
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

#include "config.h"
#include <display/di.h>
#include <gfx_utils.h>
#include "gfx/tui.h"
#include <libs/fatfs/ff.h>
#include <mem/heap.h>
#include <mem/minerva.h>
#include <power/bq24193.h>
#include <power/max17050.h>
#include <power/max77620.h>
#include <rtc/max77620-rtc.h>
#include <soc/bpmp.h>
#include <soc/hw_init.h>
#include "storage/emummc.h"
#include "storage/nx_emmc.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/dirlist.h>
#include <utils/ini.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "keys/keys.h"

hekate_config h_cfg;
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic = LP_MAGIC,
	.version = (LP_VER_MJ + '0') | ((LP_VER_MN + '0') << 8) | ((LP_VER_BF + '0') << 16),
	.rsvd0 = 0,
	.rsvd1 = 0
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define COREBOOT_END_ADDR   0xD0000000
#define COREBOOT_VER_OFF    0x41
#define CBFS_DRAM_EN_ADDR   0x4003e000
#define  CBFS_DRAM_MAGIC    0x4452414D // "DRAM"

static void *coreboot_addr;

void reloc_patcher(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	volatile reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(payload_src + ALIGN(PATCHED_RELOC_SZ, 0x10)), coreboot_addr, 0x7000); //Bootblock
		*(vu32 *)CBFS_DRAM_EN_ADDR = CBFS_DRAM_MAGIC;
	}
}

int launch_payload(char *path, bool clear_screen)
{
	if (clear_screen)
		gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);
	if (!path)
		return 1;

	if (sd_mount())
	{
		FIL fp;
		if (f_open(&fp, path, FA_READ))
		{
			gfx_con.mute = false;
			EPRINTFARGS("Payload file is missing!\n(%s)", path);

			goto out;
		}

		// Read and copy the payload to our chosen address
		void *buf;
		u32 size = f_size(&fp);

		if (size < 0x30000)
			buf = (void *)RCM_PAYLOAD_ADDR;
		else
		{
			coreboot_addr = (void *)(COREBOOT_END_ADDR - size);
			buf = coreboot_addr;
			if (h_cfg.t210b01)
			{
				f_close(&fp);

				gfx_con.mute = false;
				EPRINTF("Coreboot not allowed on Mariko!");

				goto out;
			}
		}

		if (f_read(&fp, buf, size, NULL))
		{
			f_close(&fp);

			goto out;
		}

		f_close(&fp);

		sd_end();

		if (size < 0x30000)
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

			hw_reinit_workaround(false, byte_swap_32(*(u32 *)(buf + size - sizeof(u32))));
		}
		else
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, 0x7000);

			// Get coreboot seamless display magic.
			u32 magic = 0;
			char *magic_ptr = buf + COREBOOT_VER_OFF;
			memcpy(&magic, magic_ptr + strlen(magic_ptr) - 4, 4);
			hw_reinit_workaround(true, magic);
		}

		// Some cards (Sandisk U1), do not like a fast power cycle. Wait min 100ms.
		sdmmc_storage_init_wait_sd();

		void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

		// Launch our payload.
		(*ext_payload_ptr)();
	}

out:
	sd_end();
	return 1;
}

void launch_tools()
{
	u8 max_entries = 61;
	char *filelist = NULL;
	char *file_sec = NULL;
	char *dir = NULL;

	ment_t *ments = (ment_t *)malloc(sizeof(ment_t) * (max_entries + 3));

	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	if (sd_mount())
	{
		dir = (char *)malloc(256);

		memcpy(dir, "sd:/bootloader/payloads", 24);

		filelist = dirlist(dir, NULL, false, false);

		u32 i = 0;
		u32 i_off = 2;

		if (filelist)
		{
			// Build configuration menu.
			u32 color_idx = 0;

			ments[0].type = MENT_BACK;
			ments[0].caption = "Back";
			ments[0].color = colors[(color_idx++) % 6];
			ments[1].type = MENT_CHGLINE;
			ments[1].color = colors[(color_idx++) % 6];
			if (!f_stat("sd:/atmosphere/reboot_payload.bin", NULL))
			{
				ments[i_off].type = INI_CHOICE;
				ments[i_off].caption = "reboot_payload.bin";
				ments[i_off].color = colors[(color_idx++) % 6];
				ments[i_off].data = "sd:/atmosphere/reboot_payload.bin";
				i_off++;
			}
			if (!f_stat("sd:/ReiNX.bin", NULL))
			{
				ments[i_off].type = INI_CHOICE;
				ments[i_off].caption = "ReiNX.bin";
				ments[i_off].color = colors[(color_idx++) % 6];
				ments[i_off].data = "sd:/ReiNX.bin";
				i_off++;
			}

			while (true)
			{
				if (i > max_entries || !filelist[i * 256])
					break;
				ments[i + i_off].type = INI_CHOICE;
				ments[i + i_off].caption = &filelist[i * 256];
				ments[i + i_off].color = colors[(color_idx++) % 6];
				ments[i + i_off].data = &filelist[i * 256];

				i++;
			}
		}

		if (i > 0)
		{
			memset(&ments[i + i_off], 0, sizeof(ment_t));
			menu_t menu = { ments, "Choose a file to launch", 0, 0 };

			file_sec = (char *)tui_do_menu(&menu);

			if (!file_sec)
			{
				free(ments);
				free(dir);
				free(filelist);
				sd_end();

				return;
			}
		}
		else
			EPRINTF("No payloads or modules found.");

		free(ments);
		free(filelist);
	}
	else
	{
		free(ments);
		goto out;
	}

	if (file_sec)
	{
		if (memcmp("sd:/", file_sec, 4) != 0)
		{
			memcpy(dir + strlen(dir), "/", 2);
			memcpy(dir + strlen(dir), file_sec, strlen(file_sec) + 1);
		}
		else
			memcpy(dir, file_sec, strlen(file_sec) + 1);

		launch_payload(dir, true);
		EPRINTF("Failed to launch payload.");
	}

out:
	sd_end();
	free(dir);

	btn_wait();
}

void launch_hekate()
{
	sd_mount();
	if (!f_stat("bootloader/update.bin", NULL))
		launch_payload("bootloader/update.bin", false);
}

void dump_sysnand()
{
	h_cfg.emummc_force_disable = true;
	emu_cfg.enabled = false;
	dump_keys();
}

void dump_emunand()
{
	if (h_cfg.emummc_force_disable)
		return;
	emu_cfg.enabled = true;
	dump_keys();
}

void dump_amiibo_keys()
{
	derive_amiibo_keys();
}

void dump_mariko_partial_keys();

ment_t ment_partials[] = {
	MDEF_BACK(colors[0]),
	MDEF_CHGLINE(),
	MDEF_CAPTION("This dumps the results of writing zeros", colors[1]),
	MDEF_CAPTION("over consecutive 32-bit portions of each", colors[1]),
	MDEF_CAPTION("keyslot, the results of which can then", colors[1]),
	MDEF_CAPTION("be bruteforced quickly on a computer", colors[1]),
	MDEF_CAPTION("to recover keys from unreadable keyslots.", colors[1]),
	MDEF_CHGLINE(),
	MDEF_CAPTION("This includes the Mariko KEK and BEK", colors[2]),
	MDEF_CAPTION("as well as the unique SBK.", colors[2]),
	MDEF_CHGLINE(),
	MDEF_CAPTION("These are not useful for most users", colors[3]),
	MDEF_CAPTION("but are included for archival purposes.", colors[3]),
	MDEF_CHGLINE(),
	MDEF_CAPTION("Warning: this wipes keyslots!", colors[4]),
	MDEF_CAPTION("The console must be completely restarted!", colors[4]),
	MDEF_CAPTION("Modchip must run again to fix the keys!", colors[4]),
	MDEF_CAPTION("---------------", colors[5]),
	MDEF_HANDLER("Dump Mariko Partials", dump_mariko_partial_keys, colors[0]),
	MDEF_END()
};

menu_t menu_partials = { ment_partials, NULL, 0, 0 };

power_state_t STATE_POWER_OFF           = POWER_OFF_RESET;
power_state_t STATE_REBOOT_FULL         = POWER_OFF_REBOOT;
power_state_t STATE_REBOOT_RCM          = REBOOT_RCM;
power_state_t STATE_REBOOT_BYPASS_FUSES = REBOOT_BYPASS_FUSES;

ment_t ment_top[] = {
	MDEF_HANDLER("Dump from SysNAND", dump_sysnand, colors[0]),
	MDEF_HANDLER("Dump from EmuNAND", dump_emunand, colors[1]),
	MDEF_CAPTION("---------------", colors[2]),
	MDEF_HANDLER("Dump Amiibo Keys", dump_amiibo_keys, colors[3]),
	MDEF_MENU("Dump Mariko Partials (requires reboot)", &menu_partials, colors[4]),
	MDEF_CAPTION("---------------", colors[5]),
	MDEF_HANDLER("Payloads...", launch_tools, colors[0]),
	MDEF_HANDLER("Reboot to hekate", launch_hekate, colors[1]),
	MDEF_CAPTION("---------------", colors[2]),
	MDEF_HANDLER_EX("Reboot (OFW)", &STATE_REBOOT_BYPASS_FUSES, power_set_state_ex, colors[3]),
	MDEF_HANDLER_EX("Reboot (RCM)", &STATE_REBOOT_RCM, power_set_state_ex, colors[4]),
	MDEF_HANDLER_EX("Power off", &STATE_POWER_OFF, power_set_state_ex, colors[5]),
	MDEF_END()
};

menu_t menu_top = { ment_top, NULL, 0, 0 };

void grey_out_menu_item(ment_t *menu)
{
	menu->type = MENT_CAPTION;
	menu->color = 0xFF555555;
	menu->handler = NULL;
}

void dump_mariko_partial_keys()
{
	if (h_cfg.t210b01) {
		int res = save_mariko_partial_keys(0, 16, false);
		if (res == 0 || res == 3)
		{
			// Grey out dumping menu items as the keyslots have been invalidated.
			grey_out_menu_item(&ment_top[0]);
			grey_out_menu_item(&ment_top[1]);
			grey_out_menu_item(&ment_top[4]);
			grey_out_menu_item(&ment_partials[18]);
		}

		gfx_printf("\n%kPress a button to return to the menu.", COLOR_ORANGE);
		btn_wait();
	}
}

extern void pivot_stack(u32 stack_top);

void ipl_main()
{
	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack so we have enough space.
	pivot_stack(IPL_STACK_TOP);

	// Tegra/Horizon configuration goes to 0x80000000+, package2 goes to 0xA9800000, we place our heap in between.
	heap_init(IPL_HEAP_START);

#ifdef DEBUG_UART_PORT
	uart_send(DEBUG_UART_PORT, (u8 *)"hekate: Hello!\r\n", 16);
	uart_wait_idle(DEBUG_UART_PORT, UART_TX_IDLE);
#endif

	// Set bootloader's default configuration.
	set_default_configuration();

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Train DRAM and switch to max frequency.
	if (minerva_init()) //!TODO: Add Tegra210B01 support to minerva.
		h_cfg.errors |= ERR_LIBSYS_MTC;

	display_init();

	u32 *fb = display_init_framebuffer_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);

	gfx_con_init();

	display_backlight_pwm_init();

	// Overclock BPMP.
	bpmp_clk_rate_set(h_cfg.t210b01 ? BPMP_CLK_DEFAULT_BOOST : BPMP_CLK_LOWER_BOOST);

	// Load emuMMC configuration from SD.
	emummc_load_cfg();
	// Ignore whether emummc is enabled.
	h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
	emu_cfg.enabled = !h_cfg.emummc_force_disable;

	// Grey out emummc option if not present.
	if (h_cfg.emummc_force_disable)
	{
		grey_out_menu_item(&ment_top[1]);
	}

	// Grey out reboot to RCM option if on Mariko or patched console.
	if (h_cfg.t210b01 || h_cfg.rcm_patched)
	{
		grey_out_menu_item(&ment_top[10]);
	}

	// Grey out Mariko partial dump option on Erista.
	if (!h_cfg.t210b01) {
		grey_out_menu_item(&ment_top[4]);
	}

	// Grey out reboot to hekate option if no update.bin found.
	if (f_stat("bootloader/update.bin", NULL))
	{
		grey_out_menu_item(&ment_top[7]);
	}

	minerva_change_freq(FREQ_800);

	while (true)
		tui_do_menu(&menu_top);

	// Halt BPMP if we managed to get out of execution.
	while (true)
		bpmp_halt();
}
