/*
 * Copyright (c) 2018 naehrwert
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
boot_cfg_t __attribute__((section("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section("._ipl_version"))) ipl_ver = {
    .magic = LP_MAGIC,
    .version = (LP_VER_MJ + '0') | ((LP_VER_MN + '0') << 8) | ((LP_VER_BF + '0') << 16),
    .rsvd0 = 0,
    .rsvd1 = 0
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;

// Define constants
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + RELOC_META_OFF)

void main(void) {
    // Initialize hardware
    hw_init();

    // Pivot the stack to ensure enough space
    pivot_stack(IPL_STACK_TOP);

    // Initialize heap between Tegra/Horizon and package2
    heap_init(IPL_HEAP_START);

#ifdef DEBUG_UART_PORT
    uart_send(DEBUG_UART_PORT, (u8 *)"hekate: Hello !\r\n", 16);
    uart_wait_idle(DEBUG_UART_PORT, UART_TX_IDLE);
#endif

    // Set default bootloader configuration
    set_default_configuration();

    // Mount SD Card and set error flag if failed
    h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

    // Train DRAM and switch to max frequency, set error flag if failed
    if (minerva_init()) //!TODO: Add Tegra210B01 support to minerva.
        h_cfg.errors |= ERR_LIBSYS_MTC;

    // Initialize display
    display_init();
    u32 *fb = display_init_framebuffer_pitch();
    gfx_init_ctxt(fb, 720, 1280, 720);
    gfx_con_init();
    display_backlight_pwm_init();

    // Overclock BPMP
    bpmp_clk_rate_set(h_cfg.t210b01 ? BPMP_CLK_DEFAULT_BOOST : BPMP_CLK_LOWER_BOOST);

    // Load emuMMC configuration from SD
    emummc_load_cfg();
    // Ignore whether emummc is enabled
    h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
    emu_cfg.enabled = !h_cfg.emummc_force_disable;

    // Grey out emummc option if not present
    if (h_cfg.emummc_force_disable) {
        grey_out_menu_item(&ment_top[1]);
    }

    // Grey out reboot to RCM option if on Mariko or patched console
    if (h_cfg.t210b01 || h_cfg.rcm_patched) {
        grey_out_menu_item(&ment_top[10]);
    }

    // Grey out Mariko partial dump option on Erista
    if (!h_cfg.t210b01) {
        grey_out_menu_item(&ment_top[4]);
    }

    // Grey out reboot to hekate option if no update.bin found
    if (f_stat("bootloader/update.bin", NULL)) {
        grey_out_menu_item(&ment_top[7]);
    }

    // Change frequency using minerva
    minerva_change_freq(FREQ_800);

    // Display menu in a loop
    while (true) {
        tui_do_menu(&menu_top);
    }

    // Halt BPMP if execution exits the loop
    while (true) {
        bpmp_halt();
    }
}
