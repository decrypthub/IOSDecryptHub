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
#include <stddef.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DH_THUNK_COUNT 256   // thunk 槽位总数 (单调分配; 软停不回收, 硬停后退休)

// 槽位类型 —— 决定处理器如何解读寄存器快照。
typedef enum {
    DH_HOOK_IMPORT = 0,   // 导入 C 符号 (fishhook): x0.. = 原始参数
    DH_HOOK_METHOD = 1,   // ObjC 方法 (swizzle): x0=self, x1=_cmd(SEL), x2.. = 参数
    DH_HOOK_INLINE = 2,   // 内联 hook (Dobby): 直接改写函数序言, x0.. = 原始参数
} dh_hook_kind;

// 一个已装 hook 的运行时快照 (给 list_hooks 用)。
typedef struct {
    int          slot;
    int          enabled;
    int          retired;   // 已硬卸载并恢复原代码; 槽位不再复用
    int          capture_return;   // 1 = post 路径, 记录返回值
    int          capture_after;    // 1 = capture_ptr_arg 指向调用后才写好的输出缓冲
    dh_hook_kind kind;
    uint64_t     hits;
    const char  *name;    // 符号名 / "-[Class sel]"
    int          capture_ptr_arg;   // >=0: 从该寄存器位置的指针参数抓内存; -1: 未开启
    int          capture_len_arg;   // >=0: 从该寄存器位置取长度; -1: 用 capture_max_bytes 固定长度
    int          capture_max_bytes; // 单次最多抓多少字节
    char         capture_multi[96]; // 多窗口抓取规格: "x0:64,x3:32,x5:128" (空=关闭)
} dh_hook_info;

// 装导入符号 hook。symbol 去前导下划线的名字(与 list_imports 一致); label 可为 NULL。
// 返回 slot(>=0) 成功; -1 槽位耗尽; -2 符号在任何 image 的导入表里都没找到(静态链接/未导入, hook 无效)。
// 返回值: >=0 新槽位; -1 槽位耗尽; -2 符号不存在; -(slot+10) 该符号已装过, 用这个槽位
int  dh_thunk_install_import(const char *symbol, const char *label);

// 装 ObjC 方法 hook。classMethod!=0 走类方法。返回 slot(>=0); -1 槽位耗尽; -3 类/方法不存在。
int  dh_thunk_install_method(const char *className, const char *selector, int classMethod);

// 装内联 hook (Dobby)。module 可为 NULL/"" (退化为 RTLD_DEFAULT)，symbol 或 addr 二选一：
//   - module+symbol: dlopen(module) + dlsym(symbol)，module 也尝试 /var/jb/usr/lib、/usr/lib 下同名库
//   - addr: 绝对地址，安装前用 vm_region 校验落在可执行映射里
// 返回 slot(>=0); -1 槽位耗尽; -2 目标无法解析/非可执行地址; -4 后端不可用或安装失败。
// err 写入可读原因（可为 NULL）。
int  dh_thunk_install_inline(const char *module, const char *symbol, uint64_t addr,
                             const char *label, char *err, size_t errsz);

// 内联 hook 后端名称/可用性（不安装任何东西；用于 get_capabilities / 错误解释）。
const char *dh_thunk_inline_backend(void);

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

// 打开某个 hook 的「返回值记录」(默认关闭, 返回 0 成功 / -1 槽位无效):
// on=1 时该槽位改走 post 路径: 先调原函数, 记录 x0(返回值, 对象会反引用成描述) 后再返回。
// 代价是这一层栈帧要留到原函数返回, 只在需要看返回值时开。import hook 同样支持。
int  dh_thunk_set_return(int slot, int on);
// 输出缓冲抓取: 目标把结果写进调用方提供的缓冲 (CCHmac digest / CCCrypt 密文)。
// 这种槽位必须走 post 路径, 入口抓到的是未初始化内存。
int  dh_thunk_set_capture_after(int slot, int on);
// 纯语法校验, 不改状态。安装 hook 之前先调它, 避免「装完再撤销」。
// 返回 0=合法, -1=语法错, -2=超长(>=96 字节)
int  dh_thunk_validate_capture_multi(const char *spec);
int  dh_thunk_set_capture_multi(int slot, const char *spec);

// 原子关闭一个 hook(停止记录, 仍透明转发)。越界/未用返回 -1, 成功返回 0。
int  dh_thunk_disable(int slot);

// 卸载一个 hook。hard=0: 只停记录(软停, patch 保留);
// hard=1: inline 恢复原函数入口字节(DobbyCodePatch, 不释放 Dobby 蹦床, 避免在途线程 UAF),
//         method 恢复原 IMP; import 不支持硬卸载(-5)。硬卸载后槽位标记 retired、不再复用。
// 返回 0 成功; -1 槽位无效; -4 恢复失败; -5 该类型不支持硬卸载。
int  dh_thunk_uninstall(int slot, int hard, char *err, size_t errsz);

// 枚举所有生效槽位, 回填到 out(最多 max 个), 返回实际写入条数。
int  dh_thunk_list(dh_hook_info *out, int max);

#ifdef __cplusplus
}
#endif

#endif // DH_THUNK_H
