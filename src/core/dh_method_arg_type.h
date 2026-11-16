#ifndef DH_METHOD_ARG_TYPE_H
#define DH_METHOD_ARG_TYPE_H

#include <string.h>

// 2=对象/类，1=单个通用寄存器标量/指针，0=本采集器不解释其 ABI。
// 浮点、聚合、向量等不能按「参数序号+2」猜 x 寄存器。
static inline int dh_method_arg_type(const char *type) {
    if (!type) return 0;
    while (*type && strchr("rnNoORV", *type)) type++;
    if (!*type) return 0;
    if (*type == '@' || *type == '#') return 2;
    return strchr(":*^cCsSiIlLqQB", *type) ? 1 : 0;
}

static inline unsigned int dh_method_arg_size(const char *type) {
    if (!type) return 0;
    while (*type && strchr("rnNoORV", *type)) type++;
    if (!*type) return 0;
    if (strchr("cCB", *type)) return 1;
    if (strchr("sS", *type)) return 2;
    if (strchr("iI", *type)) return 4;
    return dh_method_arg_type(type) ? 8 : 0;
}

// Apple ARM64 的小整数栈参数紧密放置，按自身尺寸对齐，并非每参占 8 字节。
// https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
static inline unsigned int dh_method_stack_offset(unsigned int current, unsigned int size) {
    return size ? (current + size - 1) & ~(size - 1) : current;
}

#endif
