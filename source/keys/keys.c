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

#include "keys.h"

#include "es_crypto.h"
#include "fs_crypto.h"
#include "nfc_crypto.h"
#include "ssl_crypto.h"

#include "../config.h"
#include <display/di.h>
#include "../frontend/gui.h"
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include "../hos/hos.h"
#include <libs/fatfs/ff.h>
#include <libs/nx_savedata/header.h>
#include <libs/nx_savedata/save.h>
#include <mem/heap.h>
#include <mem/minerva.h>
#include <mem/sdram.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include <soc/fuse.h>
#include <soc/t210.h>
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_emmc_bis.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "key_sources.inl"

#include <string.h>

extern hekate_config h_cfg;

static u32 _key_count = 0, _titlekey_count = 0;
static u32 start_time, end_time;
u32 color_idx = 0;

static void _save_key(const char *name, const void *data, u32 len, char *outbuf) {
    if (!key_exists(data))
        return;
    u32 pos = strlen(outbuf);
    pos += s_printf(&outbuf[pos], "%s = ", name);
    for (u32 i = 0; i < len; i++)
        pos += s_printf(&outbuf[pos], "%02x", *(u8*)(data + i));
    s_printf(&outbuf[pos], "\n");
    _key_count++;
}

static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf) {
    char *temp_name = calloc(1, 0x40);
    for (u32 i = 0; i < num_keys; i++) {
        s_printf(temp_name, "%s_%02x", name, i + start_key);
        _save_key(temp_name, data + i * len, len, outbuf);
    }
    free(temp_name);
}

static void _derive_master_keys_mariko(key_storage_t *keys, bool is_dev) {
    minerva_periodic_training();
    // Relies on the SBK being properly set in slot 14
    se_aes_crypt_block_ecb(KS_SECURE_BOOT, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
    // Derive all master keys based on Mariko KEK
    for (u32 i = KB_FIRMWARE_VERSION_600; i < ARRAY_SIZE(mariko_master_kek_sources) + KB_FIRMWARE_VERSION_600; i++) {
        // Relies on the Mariko KEK being properly set in slot 12
        u32 kek_source_index = i - KB_FIRMWARE_VERSION_600;
        const void *kek_source = is_dev ? &mariko_master_kek_sources_dev[kek_source_index] : &mariko_master_kek_sources[kek_source_index];
        se_aes_crypt_block_ecb(KS_MARIKO_KEK, DECRYPT, keys->master_kek[i], kek_source);
        load_aes_key(KS_AES_ECB, keys->master_key[i], keys->master_kek[i], master_key_source);
    }
}

static void _derive_master_keys_from_latest_key(key_storage_t *keys, bool is_dev) {
    minerva_periodic_training();
    if (!h_cfg.t210b01) {
        u32 tsec_root_key_slot = is_dev ? KS_TSEC_ROOT_DEV : KS_TSEC_ROOT;
        // Derive all master keys based on current root key
        for (u32 i = KB_FIRMWARE_VERSION_810 - KB_FIRMWARE_VERSION_620; i < ARRAY_SIZE(master_kek_sources); i++) {
            u32 key_index = i + KB_FIRMWARE_VERSION_620;
            se_aes_crypt_block_ecb(tsec_root_key_slot, DECRYPT, keys->master_kek[key_index], master_kek_sources[i]);
            load_aes_key(KS_AES_ECB, keys->master_key[key_index], keys->master_kek[key_index], master_key_source);
        }
    }

    minerva_periodic_training();

    // Derive all lower master keys
    for (u32 i = KB_FIRMWARE_VERSION_MAX; i > 0; i--) {
        load_aes_key(KS_AES_ECB, keys->master_key[i - 1], keys->master_key[i], is_dev ? master_key_vectors_dev[i] : master_key_vectors[i]);
    }
    load_aes_key(KS_AES_ECB, keys->temp_key, keys->master_key[0], is_dev ? master_key_vectors_dev[0] : master_key_vectors[0]);

    if (key_exists(keys->temp_key)) {
        EPRINTFARGS("Unable to derive master keys for %s.", is_dev ? "dev" : "prod");
        memset(keys->master_key, 0, sizeof(keys->master_key));
    }
}

static void _derive_keyblob_keys(key_storage_t *keys) {
    minerva_periodic_training();

    encrypted_keyblob_t *keyblob_buffer = (encrypted_keyblob_t *)calloc(KB_FIRMWARE_VERSION_600 + 1, sizeof(encrypted_keyblob_t));
    u32 keyblob_mac[SE_AES_CMAC_DIGEST_SIZE / 4] = {0};
    bool have_keyblobs = true;

    if (FUSE(FUSE_PRIVATE_KEY0) != 0xFFFFFFFF) {
        keys->secure_boot_key[0] = FUSE(FUSE_PRIVATE_KEY0);
        keys->secure_boot_key[1] = FUSE(FUSE_PRIVATE_KEY1);
        keys->secure_boot_key[2] = FUSE(FUSE_PRIVATE_KEY2);
        keys->secure_boot_key[3] = FUSE(FUSE_PRIVATE_KEY3);
    }

    if (!emmc_storage.initialized) {
        have_keyblobs = false;
    } else if (!emummc_storage_read(KEYBLOB_OFFSET / NX_EMMC_BLOCKSIZE, KB_FIRMWARE_VERSION_600 + 1, keyblob_buffer)) {
        EPRINTF("Unable to read keyblobs.");
        have_keyblobs = false;
    } else {
        have_keyblobs = true;
    }

    encrypted_keyblob_t *current_keyblob = keyblob_buffer;
    for (u32 i = 0; i < ARRAY_SIZE(keyblob_key_sources); i++, current_keyblob++) {
        minerva_periodic_training();
        se_aes_crypt_block_ecb(KS_TSEC, DECRYPT, keys->keyblob_key[i], keyblob_key_sources[i]);
        se_aes_crypt_block_ecb(KS_SECURE_BOOT, DECRYPT, keys->keyblob_key[i], keys->keyblob_key[i]);
        load_aes_key(KS_AES_ECB, keys->keyblob_mac_key[i], keys->keyblob_key[i], keyblob_mac_key_source);
        if (i == 0) {
            se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, keys->device_key, per_console_key_source);
            se_aes_crypt_block_ecb(KS_AES_ECB, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
        }

        if (!have_keyblobs) {
            continue;
        }

        // Verify keyblob is not corrupt
        se_aes_key_set(KS_AES_CMAC, keys->keyblob_mac_key[i], sizeof(keys->keyblob_mac_key[i]));
        se_aes_cmac(KS_AES_CMAC, keyblob_mac, sizeof(keyblob_mac), current_keyblob->iv, sizeof(current_keyblob->iv) + sizeof(keyblob_t));
        if (memcmp(current_keyblob->cmac, keyblob_mac, sizeof(keyblob_mac)) != 0) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            continue;
        }

        // Decrypt keyblobs
        se_aes_key_set(KS_AES_CTR, keys->keyblob_key[i], sizeof(keys->keyblob_key[i]));
        se_aes_crypt_ctr(KS_AES_CTR, &keys->keyblob[i], sizeof(keyblob_t), &current_keyblob->key_data, sizeof(keyblob_t), current_keyblob->iv);

        memcpy(keys->package1_key[i], keys->keyblob[i].package1_key, sizeof(keys->package1_key[i]));
        memcpy(keys->master_kek[i], keys->keyblob[i].master_kek, sizeof(keys->master_kek[i]));
        if (!key_exists(keys->master_key[i])) {
            load_aes_key(KS_AES_ECB, keys->master_key[i], keys->master_kek[i], master_key_source);
        }
    }
    free(keyblob_buffer);
}

static void _derive_master_keys(key_storage_t *prod_keys, key_storage_t *dev_keys, bool is_dev) {
    key_storage_t *keys = is_dev ? dev_keys : prod_keys;

    if (h_cfg.t210b01) {
        _derive_master_keys_mariko(keys, is_dev);
        _derive_master_keys_from_latest_key(keys, is_dev);
    } else {
        if (run_ams_keygen()) {
            EPRINTF("Failed to run keygen.");
            return;
        }

        u8 *aes_keys = (u8 *)calloc(1, SZ_4K);
        se_get_aes_keys(aes_keys + SZ_2K, aes_keys, SE_KEY_128_SIZE);
        memcpy(&dev_keys->tsec_root_key,  aes_keys + KS_TSEC_ROOT_DEV * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
        memcpy(&dev_keys->tsec_key,       aes_keys + KS_TSEC          * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
        memcpy(&prod_keys->tsec_key,      aes_keys + KS_TSEC          * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
        memcpy(&prod_keys->tsec_root_key, aes_keys + KS_TSEC_ROOT     * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
        if (FUSE(FUSE_PRIVATE_KEY0) != 0xFFFFFFFF) {
            memcpy(&dev_keys->secure_boot_key,  aes_keys + KS_SECURE_BOOT * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
            memcpy(&prod_keys->secure_boot_key, aes_keys + KS_SECURE_BOOT * SE_KEY_128_SIZE, SE_KEY_128_SIZE);
        }
        free(aes_keys);

        _derive_master_keys_from_latest_key(prod_keys, false);
        _derive_master_keys_from_latest_key(dev_keys, true);
        _derive_keyblob_keys(keys);
    }
}

static void _derive_bis_keys(key_storage_t *keys) {
    minerva_periodic_training();
    u32 generation = fuse_read_odm_keygen_rev();
    fs_derive_bis_keys(keys, keys->bis_key, generation);
}

static void _derive_misc_keys(key_storage_t *keys) {
    minerva_periodic_training();
    fs_derive_save_mac_key(keys, keys->save_mac_key);
}

static void _derive_non_unique_keys(key_storage_t *keys, bool is_dev) {
    minerva_periodic_training();
    fs_derive_header_key(keys, keys->header_key);
    es_derive_rsa_kek_original(keys, keys->eticket_rsa_kek, is_dev);
    ssl_derive_rsa_kek_original(keys, keys->ssl_rsa_kek, is_dev);

    for (u32 generation = 0; generation < ARRAY_SIZE(keys->master_key); generation++) {
        minerva_periodic_training();
        if (!key_exists(keys->master_key[generation]))
            continue;
        for (u32 source_type = 0; source_type < ARRAY_SIZE(key_area_key_sources); source_type++) {
            fs_derive_key_area_key(keys, keys->key_area_key[source_type][generation], source_type, generation);
        }
        load_aes_key(KS_AES_ECB, keys->package2_key[generation], keys->master_key[generation], package2_key_source);
        load_aes_key(KS_AES_ECB, keys->titlekek[generation], keys->master_key[generation], titlekek_source);
    }
}

// Returns true when terminator is found
static bool _count_ticket_records(u32 buf_size, titlekey_buffer_t *titlekey_buffer, u32 *tkey_count) {
    ticket_record_t *curr_ticket_record = (ticket_record_t *)titlekey_buffer->read_buffer;
    for (u32 i = 0; i < buf_size; i += sizeof(ticket_record_t), curr_ticket_record++) {
        if (curr_ticket_record->rights_id[0] == 0xFF)
            return true;
        (*tkey_count)++;
    }
    return false;
}

static bool _get_titlekeys_from_save(u32 buf_size, const u8 *save_mac_key, titlekey_buffer_t *titlekey_buffer, eticket_rsa_keypair_t *rsa_keypair) {
    FIL fp;
    u64 br = buf_size;
    u64 offset = 0;
    u32 file_tkey_count = 0;
    u32 save_x = gfx_con.x, save_y = gfx_con.y;
    bool is_personalized = rsa_keypair != NULL;
    const char ticket_bin_path[32] = "/ticket.bin";
    const char ticket_list_bin_path[32] = "/ticket_list.bin";
    char titlekey_save_path[32] = "bis:/save/80000000000000E1";
    save_data_file_ctx_t ticket_file;

    if (is_personalized) {
        titlekey_save_path[25] = '2';
        gfx_printf("\n%kPersonalized... ", colors[color_idx % 6]);
    } else {
        gfx_printf("\n%kCommon...       ", colors[color_idx % 6]);
    }

    if (f_open(&fp, titlekey_save_path, FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open e1 save. Skipping.");
        return false;
    }

    save_ctx_t *save_ctx = calloc(1, sizeof(save_ctx_t));
    save_init(save_ctx, &fp, save_mac_key, 0);

    bool save_process_success = save_process(save_ctx);
    TPRINTF("\n  Save process...");

    if (!save_process_success) {
        EPRINTF("Failed to process es save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    if (!save_open_file(save_ctx, &ticket_file, ticket_list_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket_list.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    // Read ticket list to get ticket count
    while (offset < ticket_file.size) {
        minerva_periodic_training();
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) ||
            titlekey_buffer->read_buffer[0] == 0 ||
            br != buf_size ||
            _count_ticket_records(buf_size, titlekey_buffer, &file_tkey_count)
        ) {
            break;
        }
        offset += br;
    }
    TPRINTF("  Count titlekeys...");

    if (!save_open_file(save_ctx, &ticket_file, ticket_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    if (is_personalized)
        se_rsa_key_set(0, rsa_keypair->modulus, sizeof(rsa_keypair->modulus), rsa_keypair->private_exponent, sizeof(rsa_keypair->private_exponent));

    offset = 0;
    u32 pct = 0, last_pct = 0, remaining = file_tkey_count;
    while (offset < ticket_file.size && remaining) {
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) || titlekey_buffer->read_buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        es_decode_tickets(buf_size, titlekey_buffer, remaining, file_tkey_count, &_titlekey_count, save_x, save_y, &pct, &last_pct, is_personalized);
        remaining -= MIN(buf_size / sizeof(ticket_t), remaining);
    }
    tui_pbar(save_x, save_y, 100, COLOR_GREEN, 0xFF155500);
    f_close(&fp);
    save_free_contexts(save_ctx);
    free(save_ctx);

    gfx_con_setpos(0, save_y);

    if (is_personalized) {
        TPRINTFARGS("\n%kPersonalized... ", colors[(color_idx++) % 6]);
    } else {
        TPRINTFARGS("\n%kCommon...       ", colors[(color_idx++) % 6]);
    }

    gfx_printf("\n\n\n");

    return true;
}

static bool _derive_sd_seed(key_storage_t *keys) {
    FIL fp;
    u32 read_bytes = 0;
    char *private_path = malloc(200);
    strcpy(private_path, "sd:/");

    if (emu_cfg.nintendo_path && (emu_cfg.enabled || !h_cfg.emummc_force_disable)) {
        strcat(private_path, emu_cfg.nintendo_path);
    } else {
        strcat(private_path, "Nintendo");
    }
    strcat(private_path, "/Contents/private");
    FRESULT fr = f_open(&fp, private_path, FA_READ | FA_OPEN_EXISTING);
    free(private_path);
    if (fr) {
        EPRINTF("Unable to open SD seed vector. Skipping.");
        return false;
    }
    // Get sd seed verification vector
    if (f_read(&fp, keys->temp_key, SE_KEY_128_SIZE, &read_bytes) || read_bytes != SE_KEY_128_SIZE) {
        EPRINTF("Unable to read SD seed vector. Skipping.");
        f_close(&fp);
        return false;
    }
    f_close(&fp);

    // This file is small enough that parsing the savedata properly is slower
    if (f_open(&fp, "bis:/save/8000000000000043", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open ns_appman save.\nSkipping SD seed.");
        return false;
    }

    u8 read_buf[0x20] __attribute__((aligned(4))) = {0};
    // Skip the two header blocks and only check the first bytes of each block
    // File contents are always block-aligned
    for (u32 i = SAVE_BLOCK_SIZE_DEFAULT * 2; i < f_size(&fp); i += SAVE_BLOCK_SIZE_DEFAULT) {
        if (f_lseek(&fp, i) || f_read(&fp, read_buf, 0x20, &read_bytes) || read_bytes != 0x20)
            break;
        if (memcmp(keys->temp_key, read_buf, sizeof(keys->temp_key)) == 0) {
            memcpy(keys->sd_seed, read_buf + 0x10, sizeof(keys->sd_seed));
            break;
        }
    }
    f_close(&fp);

    TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

    return true;
}

static bool _derive_titlekeys(key_storage_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    if (!key_exists(&keys->eticket_rsa_keypair)) {
        return false;
    }

    gfx_printf("%kTitlekeys...     \n", colors[(color_idx++) % 6]);

    const u32 buf_size = SAVE_BLOCK_SIZE_DEFAULT;
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, NULL);
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, &keys->eticket_rsa_keypair);

    gfx_printf("\n%k  Found %d titlekeys.\n\n", colors[(color_idx++) % 6], _titlekey_count);

    return true;
}

static void _derive_emmc_keys(key_storage_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    // Set BIS keys.
    // PRODINFO/PRODINFOF
    se_aes_key_set(KS_BIS_00_CRYPT, keys->bis_key[0] + 0x00, SE_KEY_128_SIZE);
    se_aes_key_set(KS_BIS_00_TWEAK, keys->bis_key[0] + 0x10, SE_KEY_128_SIZE);
    // SAFE
    se_aes_key_set(KS_BIS_01_CRYPT, keys->bis_key[1] + 0x00, SE_KEY_128_SIZE);
    se_aes_key_set(KS_BIS_01_TWEAK, keys->bis_key[1] + 0x10, SE_KEY_128_SIZE);
    // SYSTEM/USER
    se_aes_key_set(KS_BIS_02_CRYPT, keys->bis_key[2] + 0x00, SE_KEY_128_SIZE);
    se_aes_key_set(KS_BIS_02_TWEAK, keys->bis_key[2] + 0x10, SE_KEY_128_SIZE);

    if (!emummc_storage_set_mmc_partition(EMMC_GPP)) {
        EPRINTF("Unable to set partition.");
        return;
    }

    if (!decrypt_ssl_rsa_key(keys, titlekey_buffer)) {
        EPRINTF("Unable to derive SSL key.");
    }

    if (!decrypt_eticket_rsa_key(keys, titlekey_buffer, is_dev)) {
        EPRINTF("Unable to derive ETicket key.");
    }

    // Parse eMMC GPT
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &emmc_storage);

    emmc_part_t *system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Unable to locate System partition.");
        nx_emmc_gpt_free(&gpt);
        return;
    }

    nx_emmc_bis_init(system_part);

    if (f_mount(&emmc_fs, "bis:", 1)) {
        EPRINTF("Unable to mount system partition.");
        nx_emmc_gpt_free(&gpt);
        return;
    }

    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
    } else if (!_derive_sd_seed(keys)) {
        EPRINTF("Unable to get SD seed.");
    }

    if (!_derive_titlekeys(keys, titlekey_buffer, is_dev)) {
        EPRINTF("Unable to derive titlekeys.");
    }

    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);
}

// The security engine supports partial key override for locked keyslots
// This allows for a manageable brute force on a PC
// Then the Mariko AES class keys, KEK, BEK, unique SBK and SSK can be recovered
int save_mariko_partial_keys(u32 start, u32 count, bool append) {
    const char *keyfile_path = "sd:/switch/partialaes.keys";
    if (!f_stat(keyfile_path, NULL)) {
        f_unlink(keyfile_path);
    }

    if (start + count > SE_AES_KEYSLOT_COUNT) {
        return 1;
    }

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 32, 1224);
    gfx_con_setpos(0, 32);

    color_idx = 0;

    u32 pos = 0;
    u32 zeros[SE_KEY_128_SIZE / 4] = {0};
    u8 *data = malloc(4 * SE_KEY_128_SIZE);
    char *text_buffer = calloc(count, 0x100);

    for (u32 ks = start; ks < start + count; ks++) {
        // Check if key is as expected
        if (ks < ARRAY_SIZE(mariko_key_vectors)) {
            se_aes_crypt_block_ecb(ks, DECRYPT, &data[0], mariko_key_vectors[ks]);
            if (key_exists(data)) {
                EPRINTFARGS("Failed to validate keyslot %d.", ks);
                continue;
            }
        }

        // Encrypt zeros with complete key
        se_aes_crypt_block_ecb(ks, ENCRYPT, &data[3 * SE_KEY_128_SIZE], zeros);

        // We only need to overwrite 3 of the dwords of the key
        for (u32 i = 0; i < 3; i++) {
            // Overwrite ith dword of key with zeros
            se_aes_key_partial_set(ks, i, 0);
            // Encrypt zeros with more of the key zeroed out
            se_aes_crypt_block_ecb(ks, ENCRYPT, &data[(2 - i) * SE_KEY_128_SIZE], zeros);
        }

        // Skip saving key if two results are the same indicating unsuccessful overwrite or empty slot
        if (memcmp(&data[0], &data[SE_KEY_128_SIZE], SE_KEY_128_SIZE) == 0) {
            EPRINTFARGS("Failed to overwrite keyslot %d.", ks);
            continue;
        }

        pos += s_printf(&text_buffer[pos], "%d\n", ks);
        for (u32 i = 0; i < 4; i++) {
            for (u32 j = 0; j < SE_KEY_128_SIZE; j++)
                pos += s_printf(&text_buffer[pos], "%02x", data[i * SE_KEY_128_SIZE + j]);
            pos += s_printf(&text_buffer[pos], " ");
        }
        pos += s_printf(&text_buffer[pos], "\n");
    }
    free(data);

    if (strlen(text_buffer) == 0) {
        EPRINTFARGS("Failed to dump partial keys %d-%d.", start, start + count - 1);
        free(text_buffer);
        return 2;
    }

    FIL fp;
    BYTE mode = FA_WRITE;

    if (append) {
        mode |= FA_OPEN_APPEND;
    } else {
        mode |= FA_CREATE_ALWAYS;
    }

    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        free(text_buffer);
        return 3;
    }

    if (f_open(&fp, keyfile_path, mode)) {
        EPRINTF("Unable to write partial keys to SD.");
        free(text_buffer);
        return 3;
    }

    f_write(&fp, text_buffer, strlen(text_buffer), NULL);
    f_close(&fp);

    gfx_printf("%kWrote partials to %s\n", colors[(color_idx++) % 6], keyfile_path);

    free(text_buffer);

    return 0;
}

static void _save_keys_to_sd(key_storage_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        return;
    }

    u32 text_buffer_size = MAX(_titlekey_count * sizeof(titlekey_text_buffer_t) + 1, SZ_32K);
    char *text_buffer = (char *)calloc(1, text_buffer_size);

    SAVE_KEY(aes_kek_generation_source);
    SAVE_KEY(aes_key_generation_source);
    SAVE_KEY(bis_kek_source);
    SAVE_KEY_FAMILY_VAR(bis_key, keys->bis_key, 0);
    SAVE_KEY_FAMILY_VAR(bis_key_source, bis_key_sources, 0);
    SAVE_KEY_VAR(device_key, keys->device_key);
    SAVE_KEY_VAR(device_key_4x, keys->device_key_4x);
    SAVE_KEY_VAR(eticket_rsa_kek, keys->eticket_rsa_kek);
    SAVE_KEY_VAR(eticket_rsa_kek_personalized, keys->eticket_rsa_kek_personalized);
    if (is_dev) {
        SAVE_KEY_VAR(eticket_rsa_kek_source, eticket_rsa_kek_source_dev);
    } else {
        SAVE_KEY(eticket_rsa_kek_source);
    }
    SAVE_KEY(eticket_rsa_kekek_source);
    _save_key("eticket_rsa_keypair", &keys->eticket_rsa_keypair, sizeof(keys->eticket_rsa_keypair), text_buffer);
    SAVE_KEY(header_kek_source);
    SAVE_KEY_VAR(header_key, keys->header_key);
    SAVE_KEY(header_key_source);
    SAVE_KEY_FAMILY_VAR(key_area_key_application, keys->key_area_key[0], 0);
    SAVE_KEY_VAR(key_area_key_application_source, key_area_key_sources[0]);
    SAVE_KEY_FAMILY_VAR(key_area_key_ocean, keys->key_area_key[1], 0);
    SAVE_KEY_VAR(key_area_key_ocean_source, key_area_key_sources[1]);
    SAVE_KEY_FAMILY_VAR(key_area_key_system, keys->key_area_key[2], 0);
    SAVE_KEY_VAR(key_area_key_system_source, key_area_key_sources[2]);
    SAVE_KEY_FAMILY_VAR(keyblob, keys->keyblob, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key, keys->keyblob_key, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key_source, keyblob_key_sources, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_mac_key, keys->keyblob_mac_key, 0);
    SAVE_KEY(keyblob_mac_key_source);
    if (is_dev) {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources_dev, KB_FIRMWARE_VERSION_600);
    } else {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources, KB_FIRMWARE_VERSION_600);
    }
    SAVE_KEY_FAMILY_VAR(master_kek, keys->master_kek, 0);
    SAVE_KEY_FAMILY_VAR(master_kek_source, master_kek_sources, KB_FIRMWARE_VERSION_620);
    SAVE_KEY_FAMILY_VAR(master_key, keys->master_key, 0);
    SAVE_KEY(master_key_source);
    SAVE_KEY_FAMILY_VAR(package1_key, keys->package1_key, 0);
    SAVE_KEY_FAMILY_VAR(package2_key, keys->package2_key, 0);
    SAVE_KEY(package2_key_source);
    SAVE_KEY(per_console_key_source);
    SAVE_KEY(retail_specific_aes_key_source);
    SAVE_KEY(save_mac_kek_source);
    SAVE_KEY_VAR(save_mac_key, keys->save_mac_key);
    SAVE_KEY(save_mac_key_source);
    SAVE_KEY(save_mac_sd_card_kek_source);
    SAVE_KEY(save_mac_sd_card_key_source);
    SAVE_KEY(sd_card_custom_storage_key_source);
    SAVE_KEY(sd_card_kek_source);
    SAVE_KEY(sd_card_nca_key_source);
    SAVE_KEY(sd_card_save_key_source);
    SAVE_KEY_VAR(sd_seed, keys->sd_seed);
    SAVE_KEY_VAR(secure_boot_key, keys->secure_boot_key);
    SAVE_KEY_VAR(ssl_rsa_kek, keys->ssl_rsa_kek);
    SAVE_KEY_VAR(ssl_rsa_kek_personalized, keys->ssl_rsa_kek_personalized);
    if (is_dev) {
        SAVE_KEY_VAR(ssl_rsa_kek_source, ssl_rsa_kek_source_dev);
    } else {
        SAVE_KEY(ssl_rsa_kek_source);
    }
    SAVE_KEY(ssl_rsa_kekek_source);
    _save_key("ssl_rsa_key", keys->ssl_rsa_key, SE_RSA2048_DIGEST_SIZE, text_buffer);
    SAVE_KEY_FAMILY_VAR(titlekek, keys->titlekek, 0);
    SAVE_KEY(titlekek_source);
    SAVE_KEY_VAR(tsec_key, keys->tsec_key);

    char root_key_name[21] = "tsec_root_key_00";
    s_printf(root_key_name + 14, "%02x", TSEC_ROOT_KEY_VERSION);
    _save_key(root_key_name, keys->tsec_root_key, SE_KEY_128_SIZE, text_buffer);

    gfx_printf("\n%k  Found %d %s keys.\n\n", colors[(color_idx++) % 6], _key_count, is_dev ? "dev" : "prod");
    gfx_printf("%kFound through master_key_%02x.\n\n", colors[(color_idx++) % 6], KB_FIRMWARE_VERSION_MAX);

    f_mkdir("sd:/switch");

    const char *keyfile_path = is_dev ? "sd:/switch/dev.keys" : "sd:/switch/prod.keys";

    FILINFO fno;
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else {
        EPRINTF("Unable to save keys to SD.");
    }

    if (_titlekey_count == 0 || !titlekey_buffer) {
        free(text_buffer);
        return;
    }
    memset(text_buffer, 0, text_buffer_size);

    titlekey_text_buffer_t *titlekey_text = (titlekey_text_buffer_t *)text_buffer;

    for (u32 i = 0; i < _titlekey_count; i++) {
        for (u32 j = 0; j < SE_KEY_128_SIZE; j++)
            s_printf(&titlekey_text[i].rights_id[j * 2], "%02x", titlekey_buffer->rights_ids[i][j]);
        s_printf(titlekey_text[i].equals, " = ");
        for (u32 j = 0; j < SE_KEY_128_SIZE; j++)
            s_printf(&titlekey_text[i].titlekey[j * 2], "%02x", titlekey_buffer->titlekeys[i][j]);
        s_printf(titlekey_text[i].newline, "\n");
    }

    keyfile_path = "sd:/switch/title.keys";
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else {
        EPRINTF("Unable to save titlekeys to SD.");
    }

    free(text_buffer);
}

static void _derive_keys() {
    minerva_periodic_training();

    if (!check_keyslot_access()) {
        EPRINTF("Unable to set crypto keyslots!\nTry launching payload differently\n or flash Spacecraft-NX if using a modchip.");
        return;
    }

    u32 start_whole_operation_time = get_tmr_us();

    if (emummc_storage_init_mmc()) {
        EPRINTF("Unable to init MMC.");
    } else {
        TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);
    }

    minerva_periodic_training();

    if (emmc_storage.initialized && !emummc_storage_set_mmc_partition(EMMC_BOOT0)) {
        EPRINTF("Unable to set partition.");
        emummc_storage_end();
    }

    bool is_dev = fuse_read_hw_state() == FUSE_NX_HW_STATE_DEV;

    key_storage_t __attribute__((aligned(4))) prod_keys = {0}, dev_keys = {0};
    key_storage_t *keys = is_dev ? &dev_keys : &prod_keys;

    _derive_master_keys(&prod_keys, &dev_keys, is_dev);

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    _derive_bis_keys(keys);

    TPRINTFARGS("%kBIS keys...     ", colors[(color_idx++) % 6]);

    _derive_misc_keys(keys);
    _derive_non_unique_keys(&prod_keys, is_dev);
    _derive_non_unique_keys(&dev_keys, is_dev);

    titlekey_buffer_t *titlekey_buffer = (titlekey_buffer_t *)TITLEKEY_BUF_ADR;

    // Requires BIS key for SYSTEM partition
    if (!emmc_storage.initialized) {
        EPRINTF("eMMC not initialized.\nSkipping SD seed and titlekeys.");
    } else if (key_exists(keys->bis_key[2])) {
        _derive_emmc_keys(keys, titlekey_buffer, is_dev);
    } else {
        EPRINTF("Missing needed BIS keys.\nSkipping SD seed and titlekeys.");
    }

    end_time = get_tmr_us();
    gfx_printf("%kLockpick totally done in %d us\n", colors[(color_idx++) % 6], end_time - start_whole_operation_time);

    if (h_cfg.t210b01) {
        // On Mariko, save only relevant key set
        _save_keys_to_sd(keys, titlekey_buffer, is_dev);
    } else {
        // On Erista, save both prod and dev key sets
        _save_keys_to_sd(&prod_keys, titlekey_buffer, false);
        _key_count = 0;
        _save_keys_to_sd(&dev_keys, NULL, true);
    }
}

void derive_amiibo_keys() {
    minerva_change_freq(FREQ_1600);

    bool is_dev = fuse_read_hw_state() == FUSE_NX_HW_STATE_DEV;

    key_storage_t __attribute__((aligned(4))) prod_keys = {0}, dev_keys = {0};
    key_storage_t *keys = is_dev ? &dev_keys : &prod_keys;

    _derive_master_keys(&prod_keys, &dev_keys, is_dev);

    minerva_periodic_training();

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 32, 1224);
    gfx_con_setpos(0, 32);

    color_idx = 0;

    minerva_periodic_training();

    if (!key_exists(keys->master_key[0])) {
        EPRINTF("Unable to derive master keys for NFC.");
        minerva_change_freq(FREQ_800);
        btn_wait();
        return;
    }

    nfc_save_key_t __attribute__((aligned(4))) nfc_save_keys[2] = {0};

    nfc_decrypt_amiibo_keys(keys, nfc_save_keys, is_dev);

    minerva_periodic_training();

    u32 hash[SE_SHA_256_SIZE / 4] = {0};
    se_calc_sha256_oneshot(hash, &nfc_save_keys[0], sizeof(nfc_save_keys));

    if (memcmp(hash, is_dev ? nfc_blob_hash_dev : nfc_blob_hash, sizeof(hash)) != 0) {
        EPRINTF("Amiibo hash mismatch. Skipping save.");
    } else {
        const char *keyfile_path = is_dev ? "sd:/switch/key_dev.bin" : "sd:/switch/key_retail.bin";

        if (!sd_save_to_file(&nfc_save_keys[0], sizeof(nfc_save_keys), keyfile_path)) {
            gfx_printf("%kWrote Amiibo keys to\n %s\n", colors[(color_idx++) % 6], keyfile_path);
        } else {
            EPRINTF("Unable to save Amiibo keys to SD.");
        }
    }

    gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
    minerva_change_freq(FREQ_800);
    btn_wait();
    gfx_clear_grey(0x1B);
}

void dump_keys() {
    minerva_change_freq(FREQ_1600);

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    _key_count = 0;
    _titlekey_count = 0;
    color_idx = 0;

    start_time = get_tmr_us();

    _derive_keys();

    emummc_load_cfg();
    // Ignore whether emummc is enabled.
    h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
    emu_cfg.enabled = !h_cfg.emummc_force_disable;
    if (emmc_storage.initialized) {
        sdmmc_storage_end(&emmc_storage);
    }

    minerva_change_freq(FREQ_800);
    gfx_printf("\n%kPress VOL+ to save a screenshot\n or another button to return to the menu.\n\n", colors[(color_idx++) % 6]);
    u8 btn = btn_wait();
    if (btn == BTN_VOL_UP) {
        int res = save_fb_to_bmp();
        if (!res) {
            gfx_printf("%kScreenshot sd:/switch/lockpick_rcm.bmp saved.", colors[(color_idx++) % 6]);
        } else {
            EPRINTF("Screenshot failed.");
        }
        gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
        btn_wait();
    }
    gfx_clear_grey(0x1B);
}
