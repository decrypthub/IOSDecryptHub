// dh_capability.h — 能力边界中心 (纯 C, 零依赖)
//
// 打包变体(编译期) = 当前插件真正拥有的能力位。
// 这是 MCP `get_capabilities` 握手与「按变体门控注册工具」的单一真相源:
//   - dylib(开发者/巨魔) 只能改数据页(fishhook GOT)+ ObjC 运行时元数据(swizzle);
//   - 不支持 inline patch __TEXT (需要 AMFI/CS 绕过, 非越狱环境不可用)。
// 上层 AI 先调 get_capabilities, 据此决定用哪一档 hook, 避免对着做不到的能力空转。

#ifndef DH_CAPABILITY_H
#define DH_CAPABILITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 打包变体 —— 编译期 -DDH_VARIANT=<n> 注入, 缺省 0 (开发者 dylib)。
// 已有取值不得重排: 0/1/2 是已发布产物的既有语义, 新增只能往后追加。
typedef enum {
    DH_VARIANT_DEV = 0,      // insert_dylib / DYLD_INSERT_LIBRARIES (开发者手动注入)
    DH_VARIANT_TROLLSTORE,   // 巨魔 (TrollStore) 持久化安装
    DH_VARIANT_ROOTLESS,     // 越狱 rootless (ElleKit 加载器注入, arm64)
    DH_VARIANT_ROOTHIDE,     // 越狱 roothide (ElleKit 加载器注入, 胖切片 arm64+arm64e)
    DH_VARIANT_COUNT
} dh_variant;

// 能力位 —— compile ∧ runtime 求交。用于变体门控与 get_capabilities 握手。
enum {
    DH_CAPBIT_HOOK_IMPORT   = 1u << 0,  // fishhook 改导入符号表 (GOT/la_symbol_ptr) —— 全平台
    DH_CAPBIT_HOOK_METHOD   = 1u << 1,  // ObjC method swizzle —— 全平台
    DH_CAPBIT_UNPACK        = 1u << 4,  // Mach-O 脱壳
};

dh_variant   dh_variant_current(void);          // 当前变体 (越界兜底为 DEV)
const char  *dh_variant_id(dh_variant v);       // 机读短名: "dev"/"trollstore"
const char  *dh_variant_label(dh_variant v);    // 人读中文标签
const char  *dh_cpu_arch(void);                 // 编译期 CPU: "arm64"/"arm"/...
uint32_t     dh_capability_bits(void);          // compile ∧ runtime 能力位

#ifdef __cplusplus
}
#endif

#endif // DH_CAPABILITY_H
