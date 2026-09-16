#include "nca.h"
#include "crypto.h"
#include <libs/fatfs/ff.h>
#include <sec/se.h>
#include <mem/heap.h>
#include <string.h>

int ReadNcaHeader(const char *path, const u8 *header_key, NcaHeader *out) {
    FIL fp;
    u32 read_bytes = 0;

    if (f_open(&fp, path, FA_READ | FA_OPEN_EXISTING))
        return -1;

    // 0x400: first 0x200 = raw sector 1, second 0x200 = XTS output
    u8 *buf = (u8 *)malloc(0x400);
    if (!buf) { f_close(&fp); return -1; }

    if (f_lseek(&fp, 0x200) || f_read(&fp, buf, 0x200, &read_bytes) || read_bytes != 0x200) {
        f_close(&fp); free(buf); return -1;
    }
    f_close(&fp);

    // Load header key halves into temporary keyslots, decrypt sector 1, then clear
    se_aes_key_set(KS_NCA_HDR_CRYPT, header_key,        SE_KEY_128_SIZE);
    se_aes_key_set(KS_NCA_HDR_TWEAK, header_key + 0x10, SE_KEY_128_SIZE);

    se_aes_xts_crypt(KS_NCA_HDR_TWEAK, KS_NCA_HDR_CRYPT, 0, 1, buf + 0x200, buf, 0x200, 1);

    se_aes_key_clear(KS_NCA_HDR_CRYPT);
    se_aes_key_clear(KS_NCA_HDR_TWEAK);

    u8 *d = buf + 0x200;

    memcpy(out->magic,             d + 0x00, 4);
    out->distribution_type       = d[0x04];
    out->content_type            = d[0x05];
    out->crypto_type             = d[0x06];
    out->key_index               = d[0x07];
    out->content_size            = *(u64 *)(d + 0x08);

    for (int i = 0; i < 8; i++)
        out->title_id[i] = d[0x10 + (7 - i)];

    out->content_index           = *(u32 *)(d + 0x18);
    memcpy(out->sdk_version,       d + 0x1C, 4);
    out->key_generation          = d[0x20];
    out->crypto_type2            = d[0x21];
    memcpy(out->rights_id,         d + 0x30, 16);

    for (int i = 0; i < 4; i++)
        memcpy(out->encrypted_key_area[i], d + 0x100 + i * 16, 16);

    free(buf);
    return 0;
}
