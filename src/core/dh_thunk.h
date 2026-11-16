// dh_thunk.h — 通用 record-only hook 引擎 (thunk-bank)
//
// 目标: 让上层 AI 在运行时对「任意导入 C 符号」或「任意 ObjC 方法」装一个只读 hook ——
// 记录调用(参数寄存器快照 + 调用栈 + 命中次数)后原样转发, 不改变行为。
//
// 机制: 预编译一排固定大小的汇编 thunk(活在本 dylib 自己签名的 __TEXT 里, 无需 JIT 内存,
// 巨魔/非越狱也能用)。装 hook = 把目标的跳转入口(GOT 项 / ObjC IMP)改指向 thunk[i];
// 默认入口路径恢复寄存器后尾调用；post 仅允许已确认固定 GPR 签名，按 Darwin ABI
// 转发有界栈参数并保留调用帧。不支持变参/浮点聚合 post 或异常展开。
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

// 当前切片实际链接了 Inline 后端；不能仅凭工具名或 CPU 型号推断可用性。
int dh_thunk_inline_available(void);

#define DH_THUNK_COUNT 256   // thunk 槽位总数 (单调分配; 软停不回收, 硬停后退休)

// 槽位类型 —— 决定处理器如何解读寄存器快照。
typedef enum {
    DH_HOOK_IMPORT = 0,   // 导入 C 符号 (fishhook): x0.. = 原始参数
    DH_HOOK_METHOD = 1,   // ObjC 方法 (swizzle): x0=self, x1=_cmd(SEL), x2.. = 参数
    DH_HOOK_INLINE = 2,   // 内联 hook (Dobby): 直接改写函数序言, x0.. = 原始参数
} dh_hook_kind;

// 完整配置在发布 patch 之前应用；发布后的槽位配置不可变。
typedef struct {
    int describe_args, capture_return, capture_after;
    int fixed_abi; // ObjC 元数据不能识别 ...；post 需要调用者确认固定非变参原型。
    int ptr_arg, len_arg, max_bytes;
    char capture_multi[96], capture_ret_multi[96];
    int abi_declared; // C 固定 GPR 签名由调用者显式声明，不代表二进制已自动验证。
    unsigned int argument_count;
    char argument_types[32]; // ObjC 标量编码；^=指针，不接受浮点/聚合/变参 post。
    char return_type;
} dh_hook_options;
void dh_thunk_options_default(dh_hook_options *options);
int dh_thunk_validate_options(const dh_hook_options *options, char *err, size_t errsz);
// method: owner=class/name=selector；inline: owner=module/name=symbol；import: name=symbol。
int dh_thunk_install_configured(dh_hook_kind kind, const char *owner, const char *name,
    uint64_t address, int classMethod, const char *label, const dh_hook_options *options,
    char *err, size_t errsz);
#ifdef __OBJC__
@class NSDictionary;
NSDictionary *dh_thunk_metadata(int slot);
#endif

// 一个已装 hook 的运行时快照 (给 list_hooks 用)。
typedef struct {
    int          slot;
    int          enabled;
    int          retired;   // 已硬卸载并恢复原代码; 槽位不再复用
    int          capture_return;   // 1 = post 路径, 记录返回值
    int          capture_after;    // 1 = capture_ptr_arg 指向调用后才写好的输出缓冲
    unsigned int method_arg_count; // ObjC 声明参数数，不含 self/_cmd
    int          method_simple_gpr; // 0=只保留原始寄存器，不推断参数位置
    unsigned int method_stack_bytes; // 入口栈快照上限（最多 256B）
    dh_hook_kind kind;
    uint64_t     hits;
    const char  *name;    // 符号名 / "-[Class sel]"
    int          capture_ptr_arg;   // >=0: 从该寄存器位置的指针参数抓内存; -1: 未开启
    int          capture_len_arg;   // >=0: 从该寄存器位置取长度; -1: 用 capture_max_bytes 固定长度
    int          capture_max_bytes; // 单次最多抓多少字节
    char         capture_multi[96]; // 多窗口抓取规格: "x0:64,x3:32,x5:128" (空=关闭)
    char         capture_ret_multi[96]; // 返回值寄存器的多窗口(仅 post 路径)
} dh_hook_info;

// 装导入符号 hook。symbol 去前导下划线的名字(与 list_imports 一致); label 可为 NULL。
// 返回值: >=0 新槽位(含未来镜像注册); -1 槽位耗尽; -2 符号不可解析/非代码;
// -6 不安全符号; -(slot+10) 已注册，配置不变。原函数固定为 dlsym 结果，不保留逐镜像 interposer 链。
int  dh_thunk_install_import(const char *symbol, const char *label);

// 装 ObjC 方法 hook。classMethod!=0 走类方法。返回 slot(>=0); -1 槽位耗尽; -3 类/方法不存在。
int  dh_thunk_install_method(const char *className, const char *selector, int classMethod);
// 已知固定 GPR/对象参数签名支持有界栈转发；复杂 ABI 明确拒绝。
int dh_thunk_method_post_supported(const char *className, const char *selector, int classMethod);

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
// 只对声明为对象的参数抓有界 NSString/NSData；其他对象只记类名与地址。
// 以下配置 setter 在发布后均返回 -3；新调用方使用 install_configured，不在安装后改配置。
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
int  dh_thunk_validate_capture_ret_multi(const char *spec);
int  dh_thunk_set_capture_multi(int slot, const char *spec);
// 返回值寄存器的多窗口(post 路径): 抓 x1 指向的缓冲这类「返回后即释放」的输出
int  dh_thunk_set_capture_ret_multi(int slot, const char *spec);

// 原子关闭一个 hook(停止记录, 仍透明转发)。越界/未用返回 -1, 成功返回 0。
int  dh_thunk_disable(int slot);

// 卸载一个 hook。hard=0: 只停记录(软停, patch 保留);
// hard=1: method 仅在 IMP 仍由本 Hook 持有时恢复；inline 缺线程静止机制、import 不可安全解绑，
//         均返回 -5 且状态不变。方法退休后槽位/配置不再复用，保留在途调用所需的原函数。
// 返回 0 成功; -1 槽位无效; -4 恢复失败; -5 该类型不支持硬卸载。
int  dh_thunk_uninstall(int slot, int hard, char *err, size_t errsz);

// 枚举所有生效槽位, 回填到 out(最多 max 个), 返回实际写入条数。
int  dh_thunk_list(dh_hook_info *out, int max);

#ifdef __cplusplus
}
#endif

#endif // DH_THUNK_H
