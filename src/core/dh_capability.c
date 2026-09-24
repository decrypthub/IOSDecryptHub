// dh_capability.c — 见 dh_capability.h

#include "dh_capability.h"
#include <string.h>

// 变体在编译期决定; Makefile 未注入时按开发者 dylib 处理。
#ifndef DH_VARIANT
#define DH_VARIANT 0
#endif

dh_variant dh_variant_current(void) {
    int v = DH_VARIANT;
    if (v < 0 || v >= DH_VARIANT_COUNT) return DH_VARIANT_DEV;
    return (dh_variant)v;
}

const char *dh_variant_id(dh_variant v) {
    switch (v) {
        case DH_VARIANT_DEV:        return "dev";
        case DH_VARIANT_TROLLSTORE: return "trollstore";
        case DH_VARIANT_ROOTLESS:   return "rootless";
        default:                    return "dev";
    }
}

const char *dh_variant_label(dh_variant v) {
    switch (v) {
        case DH_VARIANT_DEV:        return "开发者 dylib (insert_dylib / DYLD_INSERT_LIBRARIES)";
        case DH_VARIANT_TROLLSTORE: return "巨魔 (TrollStore) 持久化";
        case DH_VARIANT_ROOTLESS:   return "越狱 rootless (ElleKit 加载器注入)";
        default:                    return "未知变体";
    }
}

const char *dh_cpu_arch(void) {
#if defined(__arm64e__)
    return "arm64e";
#elif defined(__arm64__) || defined(__aarch64__)
    return "arm64";
#elif defined(__arm__)
    return "arm";
#elif defined(__x86_64__)
    return "x86_64";
#else
    return "unknown";
#endif
}

uint32_t dh_capability_bits(void) {
    // 全平台都具备: 改导入符号表 + ObjC swizzle + 脱壳
    uint32_t bits = DH_CAPBIT_HOOK_IMPORT | DH_CAPBIT_HOOK_METHOD | DH_CAPBIT_UNPACK;
    return bits;
}
