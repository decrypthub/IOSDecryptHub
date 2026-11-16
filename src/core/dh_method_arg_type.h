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

#endif
