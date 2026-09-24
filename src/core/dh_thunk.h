// dh_thunk.h — 通用 record-only hook 引擎 (thunk-bank)
//
// 目标: 让上层 AI 在运行时对「任意导入 C 符号」或「任意 ObjC 方法」装一个只读 hook ——
// 记录调用(参数寄存器快照 + 调用栈 + 命中次数)后原样转发, 不改变行为。
//
// 机制: 预编译一排固定大小的汇编 thunk(活在本 dylib 自己签名的 __TEXT 里, 无需 JIT 内存,
// 巨魔/非越狱也能用)。装 hook = 把目标的跳转入口(GOT 项 / ObjC IMP)改指向 thunk[i];
// thunk 保存 x0-x8 / v0-v7 / lr, 调用 C 处理器记录, 再恢复寄存器尾调用原函数。因是「入口快照 +
// 尾调用」, 对被 hook 函数完全透明(不介入返回值 —— 一期只观测)。
//
// unhook: 原子开关。thunk 永远留着(slot 不回收), 只把 enabled 翻成 0; 处理器见 0 即静默转发。
// 无需改回 GOT/IMP, 天然免竞争。

#ifndef DH_THUNK_H
#define DH_THUNK_H

#include <stdint.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DH_THUNK_COUNT 128   // thunk 槽位总数 (单调分配, 不回收)

// 槽位类型 —— 决定处理器如何解读寄存器快照。
typedef enum {
    DH_HOOK_IMPORT = 0,   // 导入 C 符号 (fishhook): x0.. = 原始参数
    DH_HOOK_METHOD = 1,   // ObjC 方法 (swizzle): x0=self, x1=_cmd(SEL), x2.. = 参数
} dh_hook_kind;

// 一个已装 hook 的运行时快照 (给 list_hooks 用)。
typedef struct {
    int          slot;
    int          enabled;
    dh_hook_kind kind;
    uint64_t     hits;
    const char  *name;    // 符号名 / "-[Class sel]"
    int          capture_ptr_arg;   // >=0: 从该寄存器位置的指针参数抓内存; -1: 未开启
    int          capture_len_arg;   // >=0: 从该寄存器位置取长度; -1: 用 capture_max_bytes 固定长度
    int          capture_max_bytes; // 单次最多抓多少字节
} dh_hook_info;

// 装导入符号 hook。symbol 去前导下划线的名字(与 list_imports 一致); label 可为 NULL。
// 返回 slot(>=0) 成功; -1 槽位耗尽; -2 符号在任何 image 的导入表里都没找到(静态链接/未导入, hook 无效)。
int  dh_thunk_install_import(const char *symbol, const char *label);

// 装 ObjC 方法 hook。classMethod!=0 走类方法。返回 slot(>=0); -1 槽位耗尽; -3 类/方法不存在。
int  dh_thunk_install_method(const char *className, const char *selector, int classMethod);

// 打开某个 hook 的「参数反引用」(默认关闭, 返回 0 成功 / -1 槽位无效):
//   - DH_HOOK_METHOD: 前几个参数当 ObjC 对象读 (NSData → hex 前缀, NSString → 文本, 其它 → description)
//   - DH_HOOK_IMPORT: 前几个参数当「可打印 C 字符串」尝试 (如 getaddrinfo 的域名、dlopen 的路径)
int  dh_thunk_set_describe(int slot, int on);

// 打开某个 hook 的「参数内存快照」(默认关闭, 返回 0 成功 / -1 参数或槽位无效):
// 命中瞬间按寄存器索引取「指针参数」和「长度参数」, 用 vm_read_overwrite 拷贝一份内存写进事件
// 的 input 字段。ptr_arg: x 寄存器索引(import: x0..x8; method: x0=self, x1=_cmd, x2..=参数);
// len_arg >=0 时从该寄存器读长度, -1 时固定抓 max_bytes。max_bytes 上限 DH_THUNK_CAPTURE_MAX。
// 传 ptr_arg<0 关闭捕获。拷贝在 hook 命中时完成, 不依赖事后回读(缓冲区可能已释放/复用)。
#define DH_THUNK_CAPTURE_MAX 8192
int  dh_thunk_set_capture(int slot, int ptr_arg, int len_arg, int max_bytes);

// 原子关闭一个 hook(停止记录, 仍透明转发)。越界/未用返回 -1, 成功返回 0。
int  dh_thunk_disable(int slot);

// 枚举所有生效槽位, 回填到 out(最多 max 个), 返回实际写入条数。
int  dh_thunk_list(dh_hook_info *out, int max);

#ifdef __cplusplus
}
#endif

#endif // DH_THUNK_H
