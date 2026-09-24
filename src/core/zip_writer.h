// zip_writer.h — 纯 C, 零依赖的 store-only (不压缩) zip 写入器
//
// 设计:
//   - 顺序写, 不回填: 用 data descriptor (general purpose flag bit 3) 把
//     crc/size 放到文件数据之后, 因此写 local header 时无需预知大小, 可流式低内存。
//   - 仅 store (compression method 0), 不引入 libz, 维持项目零第三方依赖。
//   - 用于两处: 把多个砸壳后的裸二进制打成一个 zip; 把 .app 目录树打成 .ipa。
//
// 限制: 32 位字段, 单文件与整包均需 < 4GB, 条目数 < 65535 (IPA 场景足够; 否则报错)。

#ifndef DH_ZIP_WRITER_H
#define DH_ZIP_WRITER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dh_zip_writer dh_zip_writer;

// 创建(覆盖)一个 zip 文件用于顺序写入。失败返回 NULL。
dh_zip_writer *zw_open(const char *zip_path);

// 把磁盘文件 src_path 以 zip 内路径 entry_name 加入 (store, 流式)。
// unix_mode 例如 0644 / 0755, 写入 external attributes 以保留可执行权限。
// 返回: 0 成功; 1 源文件打不开(local header 未写, zip 流仍完好, 调用方可安全跳过该文件);
//      -1 写流失败(zip 已不可用, 调用方应 zw_abort)。
int zw_add_file(dh_zip_writer *zw, const char *entry_name, const char *src_path, unsigned unix_mode);

// 把内存数据以 zip 内路径 entry_name 加入。成功 0, 失败 -1。
int zw_add_data(dh_zip_writer *zw, const char *entry_name, const void *data, size_t len, unsigned unix_mode);

// 写中央目录 + EOCD, 关闭并释放。成功 0; 失败 -1 并删除半成品文件。
int zw_close(dh_zip_writer *zw);

// 放弃: 关闭、删除半成品、释放。用于中途出错。
void zw_abort(dh_zip_writer *zw);

#ifdef __cplusplus
}
#endif

#endif // DH_ZIP_WRITER_H
