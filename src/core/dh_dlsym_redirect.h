// dh_dlsym_redirect.h — dlsym 返回 hook wrapper 的符号表
//
// fishhook 只能改导入符号表; 若目标通过 dlsym(handle, "CCCrypt") 拿函数指针再调用,
// 不会走 import slot。hook dlsym 本身(它通常也是导入符号)可在解析时把已知符号
// 替换成我们的 wrapper, 使 dlsym 路径也能被捕获。
//
// 边界: 注入前已 dlsym 并缓存的指针无法追溯; 仅对注入后的 dlsym 调用生效。

#ifndef DH_DLSYM_REDIRECT_H
#define DH_DLSYM_REDIRECT_H

#include "fishhook.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 将 rebind 表里的 {name, replacement} 登记为 dlsym 重定向候选(安装 hook 时调用)。
void dh_dlsym_register_rebindings(const struct rebinding *r, size_t n);

// dlsym hook 内: 若 symbol 已登记则返回 wrapper, 否则 NULL(调用方继续用 orig 结果)。
void *dh_dlsym_redirect_lookup(const char *symbol);

#ifdef __cplusplus
}
#endif

#endif // DH_DLSYM_REDIRECT_H
