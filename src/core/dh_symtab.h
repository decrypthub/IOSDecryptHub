// dh_symtab.h — 读取已加载 image 的「导入符号表」(纯 C, 零依赖)
//
// 用途: 给 Web 面板「符号」页提供观测数据 —— 列出每个 image 调用其它 dylib 的导入
// (undefined)符号。fishhook 只能改导入符号表(__la_symbol_ptr / __got 指向的 undefined
// 符号), 所以「出现在导入表里的符号」≈「fishhook 可拦截的候选」; 而被静态链接进主二进制
// 的符号不在导入表里, fishhook 无法 hook —— 这页正是用来当场判断目标属于哪种情况。
//
// 符号名一律去掉前导下划线后返回(如 "_SSL_write" -> "SSL_write"), 与 fishhook rebinding
// 里使用的名字一致, 便于直接照抄去 hook。

#ifndef DH_SYMTAB_H
#define DH_SYMTAB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 每命中一个符号(或 image 名)回调一次。
typedef void (*dh_sym_cb)(const char *name, void *ctx);

// 已加载 image 数量(= _dyld_image_count)。
int  dh_symtab_image_count(void);

// 取第 idx 个 image 的短名(basename)写入 buf; isMain 非空时回填是否为主可执行(MH_EXECUTE)。
void dh_symtab_image_name(int idx, char *buf, size_t buflen, int *isMain);

// 枚举第 idx 个 image 的导入(undefined)符号。
//   q     非空时仅统计/回调「包含子串 q」的符号(大小写敏感); NULL/空 = 全部。
//   limit 仅限制回调次数(>0 截断, <=0 不回调只计数); 返回值始终是匹配总数(不受 limit 影响)。
//   cb    为 NULL 时只计数(用于取导入总数)。
// 返回匹配到的导入符号总数。
int  dh_symtab_imports(int idx, const char *q, int limit, dh_sym_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif // DH_SYMTAB_H
