// zip_writer.c — 见 zip_writer.h
#include "zip_writer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// ============================================================
// CRC32 (IEEE, 多项式 0xEDB88320) —— zlib 风格, 可链式调用
// ============================================================
static uint32_t kCrcTable[256];
static int kCrcReady = 0;

static void crc_build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        kCrcTable[i] = c;
    }
    kCrcReady = 1;
}

// 初始 crc 传 0; 内部 pre/post 取反, 故连续调用等价于对拼接数据求 crc。
static uint32_t crc_update(uint32_t crc, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    crc = ~crc;
    while (len--) crc = kCrcTable[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

// ============================================================
// 内部结构
// ============================================================
typedef struct {
    char    *name;
    uint32_t crc;
    uint32_t size;     // store: compressed == uncompressed
    uint32_t offset;   // local header 在文件中的偏移
    uint16_t mode;     // unix 权限 (低 12 位)
} zw_entry;

struct dh_zip_writer {
    FILE    *fp;
    char    *path;
    uint32_t offset;   // 当前写入偏移
    zw_entry *entries;
    size_t   count;
    size_t   cap;
    int      failed;
    uint16_t dosTime;
    uint16_t dosDate;
};

// ---- 小端顺序写 ----
static int w_bytes(dh_zip_writer *zw, const void *p, size_t n) {
    if (zw->failed) return -1;
    if (n && fwrite(p, 1, n, zw->fp) != n) { zw->failed = 1; return -1; }
    zw->offset += (uint32_t)n;
    return 0;
}
static int w_u16(dh_zip_writer *zw, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)(v >> 8) };
    return w_bytes(zw, b, 2);
}
static int w_u32(dh_zip_writer *zw, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                     (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
    return w_bytes(zw, b, 4);
}

static void dos_now(uint16_t *t, uint16_t *d) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    if (tmv.tm_year < 80) { *t = 0; *d = (uint16_t)((0 << 9) | (1 << 5) | 1); return; } // < 1980 兜底
    *t = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec / 2));
    *d = (uint16_t)(((tmv.tm_year - 80) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
}

dh_zip_writer *zw_open(const char *zip_path) {
    if (!kCrcReady) crc_build_table();
    FILE *fp = fopen(zip_path, "wb");
    if (!fp) return NULL;
    dh_zip_writer *zw = (dh_zip_writer *)calloc(1, sizeof(*zw));
    if (!zw) { fclose(fp); return NULL; }
    zw->fp = fp;
    zw->path = strdup(zip_path);
    zw->cap = 16;
    zw->entries = (zw_entry *)calloc(zw->cap, sizeof(zw_entry));
    if (!zw->path || !zw->entries) {
        fclose(fp); free(zw->path); free(zw->entries); free(zw);
        return NULL;
    }
    dos_now(&zw->dosTime, &zw->dosDate);
    return zw;
}

// general purpose flag: bit 3 (data descriptor) | bit 11 (UTF-8 文件名)
#define ZW_FLAGS 0x0808

static int write_local_header(dh_zip_writer *zw, const char *name, uint32_t *headerOffset) {
    size_t namelen = strlen(name);
    if (namelen > 0xFFFF) { zw->failed = 1; return -1; }
    *headerOffset = zw->offset;
    w_u32(zw, 0x04034b50);          // local file header signature
    w_u16(zw, 20);                  // version needed to extract
    w_u16(zw, ZW_FLAGS);
    w_u16(zw, 0);                   // method = store
    w_u16(zw, zw->dosTime);
    w_u16(zw, zw->dosDate);
    w_u32(zw, 0);                   // crc-32       (在 data descriptor)
    w_u32(zw, 0);                   // compressed   (在 data descriptor)
    w_u32(zw, 0);                   // uncompressed (在 data descriptor)
    w_u16(zw, (uint16_t)namelen);
    w_u16(zw, 0);                   // extra length
    w_bytes(zw, name, namelen);
    return zw->failed ? -1 : 0;
}

static int write_data_descriptor(dh_zip_writer *zw, uint32_t crc, uint32_t size) {
    w_u32(zw, 0x08074b50);          // optional data descriptor signature
    w_u32(zw, crc);
    w_u32(zw, size);                // compressed size
    w_u32(zw, size);                // uncompressed size
    return zw->failed ? -1 : 0;
}

static int record_entry(dh_zip_writer *zw, const char *name,
                        uint32_t crc, uint32_t size, uint32_t headerOffset, unsigned mode) {
    if (zw->count == zw->cap) {
        size_t ncap = zw->cap * 2;
        zw_entry *ne = (zw_entry *)realloc(zw->entries, ncap * sizeof(zw_entry));
        if (!ne) { zw->failed = 1; return -1; }
        zw->entries = ne; zw->cap = ncap;
    }
    zw_entry *e = &zw->entries[zw->count];
    e->name = strdup(name);
    if (!e->name) { zw->failed = 1; return -1; }
    e->crc = crc; e->size = size; e->offset = headerOffset; e->mode = (uint16_t)(mode & 07777);
    zw->count++;
    return 0;
}

int zw_add_data(dh_zip_writer *zw, const char *entry_name, const void *data, size_t len, unsigned unix_mode) {
    if (!zw || zw->failed) return -1;
    if (len > 0xFFFFFFFFu) { zw->failed = 1; return -1; }
    uint32_t headerOffset;
    if (write_local_header(zw, entry_name, &headerOffset) != 0) return -1;
    uint32_t crc = crc_update(0, data, len);
    if (len && w_bytes(zw, data, len) != 0) return -1;
    if (write_data_descriptor(zw, crc, (uint32_t)len) != 0) return -1;
    return record_entry(zw, entry_name, crc, (uint32_t)len, headerOffset, unix_mode);
}

int zw_add_file(dh_zip_writer *zw, const char *entry_name, const char *src_path, unsigned unix_mode) {
    if (!zw || zw->failed) return -1;
    FILE *in = fopen(src_path, "rb");
    // 源文件打不开(如 FairPlay SC_Info DRM 文件主进程无权读): 此刻 local header 尚未写出,
    // zip 流仍完好。返回 1(可跳过), 区别于真正写流失败的 -1, 让调用方跳过该文件而非中止整包。
    if (!in) return 1;
    uint32_t headerOffset;
    if (write_local_header(zw, entry_name, &headerOffset) != 0) { fclose(in); return -1; }

    uint32_t crc = 0;
    uint64_t total = 0;
    uint8_t buf[64 * 1024];
    size_t n;
    int err = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        total += n;
        if (total > 0xFFFFFFFFu) { err = 1; break; }   // 单文件 >4GB 需 zip64, 不支持
        crc = crc_update(crc, buf, n);
        if (w_bytes(zw, buf, n) != 0) { err = 1; break; }
    }
    if (ferror(in)) err = 1;
    fclose(in);
    if (err) { zw->failed = 1; return -1; }
    if (write_data_descriptor(zw, crc, (uint32_t)total) != 0) return -1;
    return record_entry(zw, entry_name, crc, (uint32_t)total, headerOffset, unix_mode);
}

static void zw_free(dh_zip_writer *zw) {
    for (size_t i = 0; i < zw->count; i++) free(zw->entries[i].name);
    free(zw->entries);
    free(zw->path);
    free(zw);
}

int zw_close(dh_zip_writer *zw) {
    if (!zw) return -1;
    int rc = -1;

    if (!zw->failed && zw->count < 0xFFFF) {
        uint32_t cdStart = zw->offset;
        for (size_t i = 0; i < zw->count; i++) {
            zw_entry *e = &zw->entries[i];
            size_t namelen = strlen(e->name);
            // external attr 高 16 位 = unix st_mode (S_IFREG | perm), 需 version-made-by 高字节=3(Unix)
            uint32_t external = ((uint32_t)(0100000u | (e->mode & 07777u))) << 16;
            w_u32(zw, 0x02014b50);          // central file header signature
            w_u16(zw, (3 << 8) | 20);       // version made by: Unix(3), spec 2.0
            w_u16(zw, 20);                  // version needed
            w_u16(zw, ZW_FLAGS);
            w_u16(zw, 0);                   // method store
            w_u16(zw, zw->dosTime);
            w_u16(zw, zw->dosDate);
            w_u32(zw, e->crc);
            w_u32(zw, e->size);             // compressed
            w_u32(zw, e->size);             // uncompressed
            w_u16(zw, (uint16_t)namelen);
            w_u16(zw, 0);                   // extra len
            w_u16(zw, 0);                   // comment len
            w_u16(zw, 0);                   // disk number start
            w_u16(zw, 0);                   // internal attrs
            w_u32(zw, external);            // external attrs
            w_u32(zw, e->offset);           // local header offset
            w_bytes(zw, e->name, namelen);
        }
        uint32_t cdSize = zw->offset - cdStart;
        // EOCD
        w_u32(zw, 0x06054b50);
        w_u16(zw, 0);
        w_u16(zw, 0);
        w_u16(zw, (uint16_t)zw->count);
        w_u16(zw, (uint16_t)zw->count);
        w_u32(zw, cdSize);
        w_u32(zw, cdStart);
        w_u16(zw, 0);                       // comment len
        if (!zw->failed && fflush(zw->fp) == 0) rc = 0;
    }

    fclose(zw->fp);
    zw->fp = NULL;
    if (rc != 0 && zw->path) remove(zw->path);
    zw_free(zw);
    return rc;
}

void zw_abort(dh_zip_writer *zw) {
    if (!zw) return;
    if (zw->fp) fclose(zw->fp);
    if (zw->path) remove(zw->path);
    zw->fp = NULL;
    zw_free(zw);
}
