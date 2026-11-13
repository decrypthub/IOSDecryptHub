// dh_thunk.m — 见 dh_thunk.h
//
// 仅 arm64 / arm64e。其它架构下 thunk 表与安装 API 退化为空实现(编译期屏蔽)。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <pthread.h>
#import <stdatomic.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <dlfcn.h>
#include <string.h>
#include <ptrauth.h>
#import "dh_thunk.h"
#import "log_store.h"
#import "fishhook.h"

// 内联 hook 后端：Dobby（静态链接）。arm64e 切片在 Makefile 里把 DH_HAVE_INLINE 置 0，
// 因为 vendor 里的 Dobby/QBDI 静态库只有 arm64 切片；代码仍编译，只拒绝安装并说明原因。
#ifndef DH_HAVE_INLINE
#define DH_HAVE_INLINE 1
#endif

#if DH_HAVE_INLINE
#include "dobby.h"
#endif

// asm 尾调用要用的「原函数指针表」—— thunk 用 slot 索引它跳转。必须是全局符号(asm 引用)。
void *g_dh_thunk_orig[DH_THUNK_COUNT];

// 需要记录返回值的槽位标记 (1 = 走 post 路径: 先调原函数, 抓到返回值再返回)。
// 必须是全局符号, 汇编里按 slot 索引读。
uint8_t g_dh_thunk_post[DH_THUNK_COUNT];

// 槽位注册表 (单调分配; 软停不回收, 硬停后退休)。
typedef struct {
    char             name[160];
    _Atomic uint64_t hits;
    _Atomic int      enabled;
    _Atomic int      retired;         // 已硬卸载: 原代码已恢复, 槽位不再复用
    _Atomic int      describe_args;   // method hook: 记录时反引用前几个参数内容
    _Atomic int      capture_ptr_arg;   // >=0: 抓该寄存器位置的指针参数
    _Atomic int      capture_len_arg;   // >=0: 从该寄存器取长度; -1: 固定长度
    _Atomic int      capture_max_bytes;
    _Atomic int      capture_return;   // 1 = post 路径, 记录返回值
    _Atomic int      capture_after;    // 1 = capture_ptr_arg 指向「调用后才写好的输出缓冲」
    char             capture_multi[96];        // 多窗口: "x0:64,x3:32,x5:128" (空=关闭)
    char             capture_multi_shadow[96]; // 写入用的影子缓冲, 避免读到写了一半的串
    _Atomic int      capture_multi_ready;      // 1 = capture_multi 内容完整可读
    dh_hook_kind     kind;
    int              used;
    void            *target;          // inline: DobbyHook 的目标地址
    void            *method;          // method: Method 指针 (硬卸载恢复 IMP)
    uint8_t          saved[32];       // inline: 安装前的原始入口字节 (硬卸载恢复)
    int              saved_len;
    uint8_t          patched[32];     // inline: Dobby 安装后的入口字节 (硬卸载后重装同目标时复用)
    int              patched_len;
} dh_slot_t;

static dh_slot_t g_slots[DH_THUNK_COUNT];
static _Atomic int g_next_slot = 0;
static pthread_mutex_t g_install_lock = PTHREAD_MUTEX_INITIALIZER;

#if defined(__arm64__) || defined(__aarch64__)

// ---- thunk 表 + 蹦床 (arm64) ----
// 每个 thunk = [ movz x17,#slot ; b _dh_thunk_trampoline ] 固定 8 字节。
// x17(IP1) 是 ABI 允许在调用边界随意破坏的临时寄存器, 不会承载参数, 拿来传 slot 最合适。
__asm__(
".section __TEXT,__text\n"
".p2align 2\n"
".globl _dh_thunk_table\n"
"_dh_thunk_table:\n"
".set _dht_idx, 0\n"
".rept 256\n"                       // 必须与 DH_THUNK_COUNT 一致
"  movz x17, #_dht_idx\n"
"  b    _dh_thunk_trampoline\n"
"  .set _dht_idx, _dht_idx + 1\n"
".endr\n"
"\n"
".globl _dh_thunk_trampoline\n"
"_dh_thunk_trampoline:\n""  sub  sp, sp, #0x130\n"           // 304B 帧: x0-8 + slot + q0-7 + lr + 入口快照
"  stp  x0, x1, [sp, #0x00]\n"
"  stp  x2, x3, [sp, #0x10]\n"
"  stp  x4, x5, [sp, #0x20]\n"
"  stp  x6, x7, [sp, #0x30]\n"
"  stp  x8, x17, [sp, #0x40]\n"    // x8(间接返回) + slot; x0..x8 至此在 [sp..sp+0x48] 连续
"  stp  q0, q1, [sp, #0x50]\n"     // 保住 FP/向量参数, 否则 double/struct 传参会被处理器破坏
"  stp  q2, q3, [sp, #0x70]\n"
"  stp  q4, q5, [sp, #0x90]\n"
"  stp  q6, q7, [sp, #0xB0]\n"
"  str  x30, [sp, #0xD0]\n"        // 原始 lr
"  mov  x0, x17\n"                 // handler(slot,
"  add  x1, sp, #0\n"             //         gpr* -> x0..x8,
"  add  x2, sp, #0xE0\n"          //         caller_sp,
"  mov  x3, x30\n"                //         lr)
"  bl   _dh_thunk_handler\n"
"  ldp  x0, x1, [sp, #0x00]\n"
"  ldp  x2, x3, [sp, #0x10]\n"
"  ldp  x4, x5, [sp, #0x20]\n"
"  ldp  x6, x7, [sp, #0x30]\n"
"  ldp  x8, x17, [sp, #0x40]\n"
"  ldp  q0, q1, [sp, #0x50]\n"
"  ldp  q2, q3, [sp, #0x70]\n"
"  ldp  q4, q5, [sp, #0x90]\n"
"  ldp  q6, q7, [sp, #0xB0]\n"
"  ldr  x30, [sp, #0xD0]\n"
"  adrp x16, _g_dh_thunk_orig@PAGE\n"
"  add  x16, x16, _g_dh_thunk_orig@PAGEOFF\n"
"  ldr  x16, [x16, x17, lsl #3]\n"  // 原函数 = g_dh_thunk_orig[slot]
"  adrp x15, _g_dh_thunk_post@PAGE\n"
"  add  x15, x15, _g_dh_thunk_post@PAGEOFF\n"
"  ldrb w15, [x15, x17]\n"           // post 标记
"  cbnz w15, 1f\n"
"  add  sp, sp, #0x130\n"
"  br   x16\n"                       // 尾调用: lr 已复原, 原函数直接返回真正的调用者
"\n"
"// post 路径: 需要返回值的槽位。先调原函数, 保存 x0/x1/q0/q1, 让 C 记录一次, 再原样返回。\n"
"// 代价是这层栈帧要一直留到原函数返回 (而不是尾调用), 因此只对付费槽位启用。\n"
"1:\n"
"  stp  x16, x30, [sp, #0xD0]\n"      // [0xD0]=原函数, [0xD8]=返回地址
// 调用前把入口寄存器另存一份: capture_after 要用「进入时」的 ptr_arg/len_arg,
// 而 blr 之后 [sp,#0x00] 会被返回值覆盖 —— ptr_arg=0 时会读到返回值, 抓出完全无关的内存。
"  add  x9, sp, #0xE0\n"
"  add  x10, sp, #0x00\n"
"  ldp  x11, x12, [x10]\n"
"  stp  x11, x12, [x9]\n"
"  ldp  x11, x12, [x10, #0x10]\n"
"  stp  x11, x12, [x9, #0x10]\n"
"  ldp  x11, x12, [x10, #0x20]\n"
"  stp  x11, x12, [x9, #0x20]\n"
"  ldp  x11, x12, [x10, #0x30]\n"
"  stp  x11, x12, [x9, #0x30]\n"
"  ldr  x11, [x10, #0x40]\n"
"  str  x11, [x9, #0x40]\n"
"  blr  x16\n"
"  str  x0, [sp, #0x00]\n"            // 返回值 x0
"  str  x1, [sp, #0x08]\n"            // 返回值 x1 (结构体/双整返回)
"  stp  q0, q1, [sp, #0x50]\n"        // 浮点/向量返回值
"  stp  q2, q3, [sp, #0x70]\n"        // HFA 结构体返回可能用到 q2/q3
"  ldp  x8, x17, [sp, #0x40]\n"       // x8 = 间接返回缓冲, x17 = slot
"  mov  x0, x17\n"                    // dh_thunk_post_handler(slot,
"  add  x1, sp, #0\n"                 //                    retval regs,
"  ldp  x2, x3, [sp, #0xD0]\n"        //                    orig, real_lr)
"  add  x4, sp, #0xE0\n"           //                    entry_regs)
"  bl   _dh_thunk_post_handler\n"
"  ldr  x0, [sp, #0x00]\n"
"  ldr  x1, [sp, #0x08]\n"
"  ldp  q0, q1, [sp, #0x50]\n"
"  ldp  q2, q3, [sp, #0x70]\n"
"  ldr  x30, [sp, #0xD8]\n"
"  add  sp, sp, #0x130\n"
"  ret\n"
);

extern void dh_thunk_table(void);   // asm label; 取地址即表基址
static inline void *dh_slot_addr(int i) { return (uint8_t *)dh_thunk_table + (size_t)i * 8; }

#define DH_THUNK_ARM64 1
#else
static inline void *dh_slot_addr(int i) { (void)i; return NULL; }
#define DH_THUNK_ARM64 0
#endif

// 线程内重入保护: 处理器会调 Foundation(可能再触发被 hook 的底层函数), 用 TLS 标志防无限递归。
static __thread int g_in_thunk = 0;

// ---- 参数反引用（可选; method hook 走对象反引用, import hook 走可打印 C 字符串判定）----
// 目的: 直接看到参数「内容」(明文/密钥/密文/字典), 而不是只有一个指针值。
// 安全策略(逐层收敛, 任何一层不满足就放弃):
//   1) 指针必须对齐且 > 4GB;
//   2) 用 vm_read_overwrite 读 isa —— 不可读地址直接失败, 绝不解引用野指针;
//   3) isa 必须命中运行时类表(objc_copyClassList 排序后 bsearch);
//   4) 才当作对象访问, 且全程 @try; 文本/字节数都有上限, 不产生大对象。
static Class *gDHKnownClasses = NULL;
static unsigned gDHKnownClassCount = 0;

static int dh_class_cmp(const void *pa, const void *pb) {
    Class a = *(const Class *)pa, b = *(const Class *)pb;
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

// 参数内存快照: 命中时把 [ptr, ptr+len) 拷贝到事件 input。
// 为什么必须在 handler 里拷贝: 调用返回后原缓冲区可能立刻被释放/复用(实测 CryptoSwift
// 的 key 缓冲区经 mlock 锁定又立即 munlock, 事后回读只剩零), 只有命中瞬间的内容可信。
// 安全边界: 只读用户态地址, 显式长度上限, vm_read_overwrite 失败/部分成功都安全降级,
// 不新增任何可执行内存或 inline hook。
// 同 dh_capture_arg_memory，但指针/长度直接给定。post 路径要用「已返回的原函数返回的缓冲」，
// 那些值只在寄存器快照里，没有槽位字段可读。
static NSData *dh_capture_at(uint64_t addr, size_t want) {
    if (addr < 0x100000000ULL || want == 0) return nil;
    if (want > DH_THUNK_CAPTURE_MAX) want = DH_THUNK_CAPTURE_MAX;
    NSMutableData *data = [NSMutableData dataWithLength:want];
    if (!data) return nil;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         (vm_size_t)want,
                                         (mach_vm_address_t)data.mutableBytes, &got);
    if (kr != KERN_SUCCESS || got == 0) return nil;
    if (got < want) data.length = got;
    return data;
}

static NSData *dh_capture_arg_memory(dh_slot_t *s, uint64_t *gpr) {
    int ptrArg = atomic_load_explicit(&s->capture_ptr_arg, memory_order_acquire);
    if (ptrArg < 0 || ptrArg > 8) return nil;
    int lenArg = atomic_load_explicit(&s->capture_len_arg, memory_order_relaxed);
    int maxBytes = atomic_load_explicit(&s->capture_max_bytes, memory_order_relaxed);
    if (maxBytes <= 0 || maxBytes > DH_THUNK_CAPTURE_MAX) return nil;
    uint64_t addr = gpr[ptrArg];
    if (addr < 0x100000000ULL) return nil;
    size_t want = (size_t)maxBytes;
    if (lenArg >= 0 && lenArg <= 8) {
        uint64_t rawLen = gpr[lenArg];
        if (rawLen == 0) return nil;
        if (rawLen < want) want = (size_t)rawLen;
    }
    if (want == 0) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:want];
    if (!data) return nil;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         (vm_size_t)want,
                                         (mach_vm_address_t)data.mutableBytes, &got);
    if (kr != KERN_SUCCESS || got == 0) return nil;
    if (got < want) data.length = got;
    return data;
}

// 多窗口抓取: 一次 hook 同时看多个寄存器指向的内存。
// 为什么需要: 一个 inline 目标只能装一个 hook(重复装会被拒绝), 而分析一个函数往往要同时
// 看「输入 / 密钥 / 输出」三个寄存器。没有这个能力就只能卸了重装, 而 inline 槽位一旦
// 分配不会回收 —— 每次换寄存器都得重启目标进程, 实测把一轮分析拖成十几分钟。
// 语法: "x0:64,x3:32,x5:128" 或 "0:64,3:32"; len 用 :N 显式给, 不给就用 max_bytes 上限。
// 返回 @[{reg, addr, bytes(NSData)}], 由调用方渲染。
static NSArray *dh_capture_multi(dh_slot_t *s, uint64_t *gpr) {
    NSString *spec = @(s->capture_multi);
    if (!spec || spec.length == 0) return nil;
    NSMutableArray *out = [NSMutableArray array];
    int defaultMax = atomic_load_explicit(&s->capture_max_bytes, memory_order_relaxed);
    if (defaultMax <= 0 || defaultMax > DH_THUNK_CAPTURE_MAX) defaultMax = 256;
    for (NSString *piece in [spec componentsSeparatedByString:@","]) {
        NSString *tok = [piece stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceCharacterSet]];
        if (tok.length == 0) continue;
        NSString *regPart = tok;
        size_t want = (size_t)defaultMax;
        NSRange colon = [tok rangeOfString:@":"];
        if (colon.location != NSNotFound) {
            regPart = [tok substringToIndex:colon.location];
            want = (size_t)[[tok substringFromIndex:colon.location + 1] integerValue];
        }
        if ([regPart hasPrefix:@"x"] || [regPart hasPrefix:@"X"]) regPart = [regPart substringFromIndex:1];
        int reg = [regPart intValue];
        if (reg < 0 || reg > 8) continue;
        if (want == 0 || want > DH_THUNK_CAPTURE_MAX) want = DH_THUNK_CAPTURE_MAX;
        uint64_t addr = gpr[reg];
        if (addr < 0x100000000ULL) continue;
        NSMutableData *data = [NSMutableData dataWithLength:want];
        if (!data) continue;
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                             (vm_size_t)want,
                                             (mach_vm_address_t)data.mutableBytes, &got);
        if (kr != KERN_SUCCESS || got == 0) continue;
        if (got < want) data.length = got;
        [out addObject:@{@"reg": @(reg), @"addr": @(addr), @"bytes": data}];
    }
    return out.count ? out : nil;
}

static BOOL dh_is_runtime_class(Class c) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned n = 0;
        Class *all = objc_copyClassList(&n);
        if (all) {
            qsort(all, n, sizeof(Class), dh_class_cmp);
            gDHKnownClasses = all;
            gDHKnownClassCount = n;
        }
    });
    if (!gDHKnownClasses || !c) return NO;
    return bsearch(&c, gDHKnownClasses, gDHKnownClassCount, sizeof(Class), dh_class_cmp) != NULL;
}

static NSString *dh_describe_arg(uint64_t v) {
    if (v < 0x100000000ULL || (v & 0x7)) return nil;    // 判定分两层, 顺序很重要:
    //   1) vm_read_overwrite 确认地址可读(挡野指针);
    //   2) 读出对象头 isa → 剥离 PAC(arm64e/Apple Silicon 上 isa 是签名指针) → 必须命中运行时类表。
    // 只有第 2 步通过后才当对象访问。绝不能直接 object_getClass(): 参数里常见的 NSError**
    // 等「可读但非对象」的指针会让它段错误, @try 也拦不住(SIGSEGV)。
    uint64_t isaRaw = 0;
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)v, sizeof(isaRaw),
                          (vm_address_t)&isaRaw, &got) != KERN_SUCCESS || got != sizeof(isaRaw)) return nil;
    // isa 的编码随平台而变(实测 arm64e/Apple Silicon: PAC 签名在高位 + 低位若干标志位,
    // 例如真实类 0x1f4c106e8 会以 0x1000001f4c106e9 出现)。逐个候选剥离后比对运行时类表,
    // 命中任意一个才认为「这是个对象」; 全部不中直接放弃(裸缓冲/出参指针都是这种)。
    uint64_t masked = isaRaw & 0x0000FFFFFFFFFFFFULL;
    uint64_t lower  = isaRaw & 0x0000000FFFFFFFFFULL;
    uint64_t cands[5] = {
        (uint64_t)(uintptr_t)ptrauth_strip((void *)(uintptr_t)isaRaw, ptrauth_key_asia),
        masked, masked & ~0x7ULL, lower, lower & ~0x7ULL,
    };
    BOOL isObj = NO;
    for (int ci = 0; ci < 5; ci++) {
        if (dh_is_runtime_class((__bridge Class)(void *)(uintptr_t)cands[ci])) { isObj = YES; break; }
    }
    if (!isObj) return nil;
    id obj = (__bridge id)(void *)v;
    @try {
        if ([obj isKindOfClass:[NSData class]]) {
            NSData *data = (NSData *)obj;
            NSUInteger n = MIN(data.length, (NSUInteger)64);
            NSData *head = n ? [data subdataWithRange:NSMakeRange(0, n)] : [NSData data];
            return [NSString stringWithFormat:@"NSData(%lu) %@%@", (unsigned long)data.length,
                    DHHexFromData(head), data.length > n ? @"…" : @""];
        }
        if ([obj isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)obj;
            // 返回值常常就是整条签名/header (几百到几千字符), 截到 200 会把要看的字段切掉。
            // 这里放宽到 4000 字符, 与事件 detail 的展示上限一致; 再长的才截断。
            NSString *t = s.length > 4000 ? [[s substringToIndex:4000] stringByAppendingString:@"…"] : s;
            return [NSString stringWithFormat:@"NSString(%lu) %@", (unsigned long)s.length, t];
        }
        NSString *desc = [obj description];
        if (desc.length > 4000) desc = [[desc substringToIndex:4000] stringByAppendingString:@"…"];
        return desc;
    } @catch (__unused NSException *ex) {
        return @"<describe-exception>";
    }
}

// C 符号参数: 把指针当「可打印 C 字符串」尝试(只读 256B, 必须 NUL 结尾且全是可见字符)。
// 用于 getaddrinfo 的域名、dlopen/dlopen 的路径、stat 的 path 等 —— 这类参数没有任何类型信息,
// 只能靠内容形态判断, 因此判定条件从严: 失败就静默跳过, 绝不误报二进制缓冲。
static NSString *dh_describe_cstr(uint64_t p) {
    if (p < 0x100000000ULL) return nil;
    uint8_t buf[256];
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)p, sizeof(buf),
                          (vm_address_t)buf, &got) != KERN_SUCCESS || got < 3) return nil;
    size_t n = 0;
    while (n < got && buf[n] != 0) {
        uint8_t c = buf[n];
        if (c < 0x20 || c > 0x7e) return nil;   // 非可见字符 → 不是纯文本参数
        n++;
    }
    if (n < 2 || n >= got) return nil;          // 没在缓冲区内找到 NUL → 放弃
    NSString *s = [[NSString alloc] initWithBytes:buf length:n encoding:NSUTF8StringEncoding];
    if (!s) return nil;
    return s.length > 200 ? [[s substringToIndex:200] stringByAppendingString:@"…"] : s;
}

// 汇编蹦床唯一的 C 落点。slot=槽位; gpr[0..8]=x0..x8; caller_sp/lr 供参考。
void dh_thunk_handler(uint64_t slot, uint64_t *gpr, uint64_t caller_sp, uint64_t lr) {
    if (slot >= DH_THUNK_COUNT) return;
    dh_slot_t *s = &g_slots[slot];
    if (!atomic_load_explicit(&s->enabled, memory_order_relaxed)) return;  // 已 unhook: 静默转发
    uint64_t n = atomic_fetch_add_explicit(&s->hits, 1, memory_order_relaxed) + 1;
    if (g_in_thunk) return;             // 重入: 只计数不记录
    g_in_thunk = 1;
    @autoreleasepool {
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryOther;
        e.algorithm = (s->kind == DH_HOOK_METHOD) ? @"objc-hook"
                    : (s->kind == DH_HOOK_INLINE) ? @"inline-hook" : @"import-hook";
        e.operation = [NSString stringWithUTF8String:s->name];
        NSMutableString *d = [NSMutableString stringWithFormat:@"slot=%llu hits=%llu\n",
                              (unsigned long long)slot, (unsigned long long)n];
        if (s->kind == DH_HOOK_METHOD) {
            [d appendFormat:@"self=0x%llx _cmd=%s\n", gpr[0],
                sel_getName((SEL)gpr[1]) ?: "?"];
            for (int i = 2; i < 9; i++) [d appendFormat:@"arg%d(x%d)=0x%llx ", i - 2, i, gpr[i]];
            if (atomic_load_explicit(&s->describe_args, memory_order_relaxed)) {
                for (int i = 2; i <= 6; i++) {
                    NSString *desc = dh_describe_arg(gpr[i]);
                    if (desc.length) [d appendFormat:@"\n  arg%d = %@", i - 2, desc];
                }
            }
        } else {
            for (int i = 0; i < 9; i++) [d appendFormat:@"x%d=0x%llx ", i, gpr[i]];
            if (atomic_load_explicit(&s->describe_args, memory_order_relaxed)) {
                for (int i = 0; i <= 3; i++) {
                    NSString *desc = dh_describe_cstr(gpr[i]);
                    if (desc.length) [d appendFormat:@"\n  arg%d(cstr) = %@", i, desc];
                }
            }
        }
        int capPtr = atomic_load_explicit(&s->capture_ptr_arg, memory_order_acquire);
        if (capPtr >= 0 && capPtr <= 8) {
            int capLen = atomic_load_explicit(&s->capture_len_arg, memory_order_relaxed);
            int capMax = atomic_load_explicit(&s->capture_max_bytes, memory_order_relaxed);
            NSData *captured = dh_capture_arg_memory(s, gpr);
            if (captured.length) {
                e.input = captured;
                [d appendFormat:@"\ncaptured arg%d(x%d) @0x%llx = %lu bytes (ptr_arg=%d len_arg=%d max=%d)",
                 capPtr, capPtr, gpr[capPtr], (unsigned long)captured.length, capPtr, capLen, capMax];
            } else {
                [d appendFormat:@"\ncaptured arg%d(x%d) @0x%llx failed (ptr_arg=%d len_arg=%d max=%d)",
                 capPtr, capPtr, gpr[capPtr], capPtr, capLen, capMax];
            }
        }
        // 多窗口: 一次 hook 同时记录多个寄存器指向的内存。
        // 一个 inline 目标只能装一个 hook 且槽位不回收, 换寄存器就得重启进程, 所以这是分析多参数函数的关键能力。
        if (atomic_load_explicit(&s->capture_multi_ready, memory_order_acquire) && s->capture_multi[0]) {
            NSArray *wins = dh_capture_multi(s, gpr);
            for (NSDictionary *w in wins) {
                int reg = [w[@"reg"] intValue];
                NSData *b = w[@"bytes"];
                uint64_t waddr = [w[@"addr"] unsignedLongLongValue];
                // 必须自己转完整 hex: NSData.description 会在 16 字节后折叠成 "...", 分析时等于白抓。
                // 用查表 + stringWithCharacters 一次性成串: 逐字节 appendFormat 在热函数上是几万次
                // 格式化调用, 会把命中耗时拉长到毫秒级, 改变目标 App 的时序。
                NSUInteger take = b.length;   // 已在 dh_capture_multi 里钳到 CAPTURE_MAX
                static const char hexd[] = "0123456789abcdef";
                unichar *hbuf = (unichar *)malloc(take * 2 * sizeof(unichar));
                if (hbuf) {
                    const uint8_t *p = (const uint8_t *)b.bytes;
                    for (NSUInteger k = 0; k < take; k++) {
                        hbuf[k * 2]     = (unichar)hexd[p[k] >> 4];
                        hbuf[k * 2 + 1] = (unichar)hexd[p[k] & 0xF];
                    }
                    NSString *hex = [NSString stringWithCharacters:hbuf length:take * 2];
                    free(hbuf);
                    [d appendFormat:@"\nwin x%d @0x%llx = %lu bytes: %@", reg, waddr, (unsigned long)b.length, hex];
                } else {
                    [d appendFormat:@"\nwin x%d @0x%llx = %lu bytes (hex alloc failed)", reg, waddr, (unsigned long)b.length];
                }
            }
            if (!wins.count) [d appendFormat:@"\nwin [%s] unreadable (所有窗口都读不到: 地址<4GB 或 vm_read_overwrite 失败)", s->capture_multi];
        }
        [d appendFormat:@"\nsp=0x%llx lr=0x%llx", caller_sp, lr];
        e.detail    = d;
        e.callStack = DHCallStackFiltered();
        e.timestamp = DHTimestampNow();
        [[DHLogStore shared] append:e];
    }
    g_in_thunk = 0;
}

// ---- post 路径: 原函数返回后记录返回值 ----
// 只在 g_dh_thunk_post[slot] 置位时被汇编调用; regs[0]=x0(返回值), regs[1]=x1。
void dh_thunk_post_handler(uint64_t slot, uint64_t *regs, uint64_t orig, uint64_t real_lr,
                           uint64_t *entry_regs) {
    (void)orig; (void)real_lr;
    if (slot >= DH_THUNK_COUNT) return;
    dh_slot_t *s = &g_slots[slot];
    if (!atomic_load_explicit(&s->enabled, memory_order_relaxed)) return;
    if (g_in_thunk) return;
    g_in_thunk = 1;
    @autoreleasepool {
        uint64_t ret = regs[0];
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryOther;
        e.algorithm = (s->kind == DH_HOOK_METHOD) ? @"objc-hook" : @"inline-hook";
        e.operation = [NSString stringWithUTF8String:s->name];
        NSMutableString *d = [NSMutableString stringWithFormat:
            @"slot=%llu return\nx0(ret)=0x%llx x1=0x%llx",
            (unsigned long long)slot, (unsigned long long)ret, (unsigned long long)regs[1]];
        NSString *desc = dh_describe_arg(ret);   // 对象/NSData/NSString 才反引用
        if (desc.length) {
            [d appendFormat:@"\n  ret = %@", desc];
            e.input = [desc dataUsingEncoding:NSUTF8StringEncoding];
        }
        // capture_after: 输出缓冲在原函数返回后才有效 (CCHmac 的 digest 出参、CCCrypt 的密文出参)。
        // 入口抓只能拿到未初始化内存, 所以这类槽位必须在 post 路径读。
        if (atomic_load_explicit(&s->capture_after, memory_order_relaxed)) {
            int ap = atomic_load_explicit(&s->capture_ptr_arg, memory_order_acquire);
            int al = atomic_load_explicit(&s->capture_len_arg, memory_order_relaxed);
            int am = atomic_load_explicit(&s->capture_max_bytes, memory_order_relaxed);
            if (ap >= 0 && ap <= 8) {
                // 必须用「进入时」的寄存器: regs[] 是返回后的快照, x0 已被返回值覆盖。
                // 用 regs 会在 ptr_arg=0 时把返回值当成出参缓冲, 抓到完全无关的内存并当成证据上报。
                const uint64_t *src = entry_regs ? entry_regs : regs;
                uint64_t bufPtr = src[ap];
                size_t want = (am > 0 && am <= DH_THUNK_CAPTURE_MAX) ? (size_t)am : 64;
                if (al >= 0 && al <= 8) {
                    uint64_t n = src[al];
                    if (n > 0 && n < (uint64_t)want) want = (size_t)n;
                }
                NSData *outBuf = dh_capture_at(bufPtr, want);
                if (outBuf.length) {
                    e.output = outBuf;
                    [d appendFormat:@"\n  out arg%d(x%d) @0x%llx = %lu bytes: %@",
                     ap, ap, bufPtr, (unsigned long)outBuf.length, DHHexFromData(outBuf)];
                } else {
                    [d appendFormat:@"\n  out arg%d(x%d) @0x%llx unreadable", ap, ap, bufPtr];
                }
            }
        }
        e.detail    = d;
        e.callStack = DHCallStackFiltered();
        e.timestamp = DHTimestampNow();
        [[DHLogStore shared] append:e];
    }
    g_in_thunk = 0;
}

// ---- 安装 / 关闭 / 枚举 ----

static int dh_alloc_slot(void) {
    int i = atomic_fetch_add_explicit(&g_next_slot, 1, memory_order_relaxed);
    if (i >= DH_THUNK_COUNT) { atomic_fetch_sub_explicit(&g_next_slot, 1, memory_order_relaxed); return -1; }
    return i;
}

int dh_thunk_install_import(const char *symbol, const char *label) {
    if (!DH_THUNK_ARM64 || !symbol || !symbol[0]) return -1;
    pthread_mutex_lock(&g_install_lock);
    // fishhook 按符号改 GOT: 同一符号装第二次会把 GOT 指向新槽位, 旧槽位从此 0 命中
    // (它还留在 list_hooks 里, 看起来像「装好了却不生效」)。重复安装直接拒绝, 让调用方复用。
    {
        int n = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
        if (n > DH_THUNK_COUNT) n = DH_THUNK_COUNT;
        for (int i = 0; i < n; i++) {
            dh_slot_t *o = &g_slots[i];
            if (!o->used || o->kind != DH_HOOK_IMPORT) continue;
            if (strncmp(o->name, symbol, strlen(symbol)) != 0) continue;
            char after = o->name[strlen(symbol)];
            if (after != '\0' && after != ' ') continue;
            pthread_mutex_unlock(&g_install_lock);
            // 返回 -(slot+10): 让调用方拿到准确槽位, 不必再按名字模糊匹配
            // (MCP 层曾用 strncmp 前缀匹配, CCHmac 会误命中 CCHmacInit)。
            return -(i + 10);
        }
    }
    int slot = dh_alloc_slot();
    if (slot < 0) { pthread_mutex_unlock(&g_install_lock); return -1; }
    dh_slot_t *s = &g_slots[slot];
    snprintf(s->name, sizeof(s->name), "%s%s%s", symbol,
             (label && label[0]) ? " " : "", (label && label[0]) ? label : "");
    s->kind = DH_HOOK_IMPORT;
    s->used = 1;
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    atomic_store_explicit(&s->capture_return, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_after, 0, memory_order_relaxed);
    s->capture_multi[0] = '\0';
    atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
    g_dh_thunk_post[slot] = 0;
    // 必须先清 orig: 同进程里本 dylib 可能被 reload 过, g_dh_thunk_orig 里可能残留上一代的值,
    // 那样 rebind 失败也会被当成成功, 槽位从此 0 命中(实测踩过)。
    g_dh_thunk_orig[slot] = NULL;
    struct rebinding rb = { symbol, dh_slot_addr(slot), &g_dh_thunk_orig[slot] };
    rebind_symbols(&rb, 1);
    if (g_dh_thunk_orig[slot] == NULL) {
        // 任何 image 的 la_symbol_ptr/__got 里都没这个符号 —— fishhook 从未把任何跳转指向 thunk[slot],
        // 所以回收该槽 100% 安全(没有遗留跳转)。若它正好是最后分配的一个, 直接回退计数复用。
        s->used = 0;
        s->name[0] = '\0';
        s->capture_multi[0] = '\0';
        atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
        int last = slot + 1;
        atomic_compare_exchange_strong_explicit(&g_next_slot, &last, slot,
                                                memory_order_relaxed, memory_order_relaxed);
        pthread_mutex_unlock(&g_install_lock);
        return -2;
    }
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    pthread_mutex_unlock(&g_install_lock);
    return slot;
}

int dh_thunk_install_method(const char *className, const char *selector, int classMethod) {
    if (!DH_THUNK_ARM64 || !className || !selector) return -1;
    Class cls = objc_getClass(className);
    if (!cls) return -3;
    SEL sel = sel_registerName(selector);
    Method m = nil;
    if (classMethod) {
        // Swift 类的 +method 只在元类上以实例方法形式存在, class_getClassMethod 会漏。
        Class meta = object_getClass((id)cls);
        if (meta) m = class_getInstanceMethod(meta, sel);
        if (!m) m = class_getClassMethod(cls, sel);
    } else {
        m = class_getInstanceMethod(cls, sel);
    }
    if (!m) return -3;
    pthread_mutex_lock(&g_install_lock);
    int total = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
    if (total > DH_THUNK_COUNT) total = DH_THUNK_COUNT;
    for (int i = 0; i < total; i++) {
        dh_slot_t *old = &g_slots[i];
        if (!old->used || old->kind != DH_HOOK_METHOD || old->method != (void *)m) continue;
        if (!atomic_load_explicit(&old->retired, memory_order_relaxed)) {
            pthread_mutex_unlock(&g_install_lock);
            return -5;   // 同一 Method 已有 active hook
        }
        // hard-unhook 后原 IMP 已恢复且未被别的插件改写: 复用原槽位/原蹦床。
        if (g_dh_thunk_orig[i] &&
            method_getImplementation(m) == (IMP)g_dh_thunk_orig[i]) {
            method_setImplementation(m, (IMP)dh_slot_addr(i));
            atomic_store_explicit(&old->retired, 0, memory_order_release);
            atomic_store_explicit(&old->enabled, 1, memory_order_release);
            pthread_mutex_unlock(&g_install_lock);
            return i;
        }
    }
    int slot = dh_alloc_slot();
    if (slot < 0) { pthread_mutex_unlock(&g_install_lock); return -1; }
    dh_slot_t *s = &g_slots[slot];
    snprintf(s->name, sizeof(s->name), "%c[%s %s]", classMethod ? '+' : '-', className, selector);
    s->kind = DH_HOOK_METHOD;
    s->used = 1;
    s->method = (void *)m;
    s->target = NULL;
    s->saved_len = 0;
    atomic_store_explicit(&s->retired, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    g_dh_thunk_orig[slot] = (void *)method_getImplementation(m);
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    method_setImplementation(m, (IMP)dh_slot_addr(slot));
    pthread_mutex_unlock(&g_install_lock);
    return slot;
}

// ---- 内联 hook (Dobby) ----
// 复用同一张 thunk 表：DobbyHook 把目标函数序言改跳到 thunk[slot]，thunk 记录后尾调用
// DobbyHook 返回的原函数蹦床。参数寄存器/栈保持原样，所以对目标透明（入口观测）。

static BOOL dh_addr_is_executable(uint64_t addr) {
    vm_address_t region = (vm_address_t)addr;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    return kr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE) &&
           addr >= (uint64_t)region && addr < (uint64_t)region + size;
}

static void *dh_resolve_inline_target(const char *module, const char *symbol,
                                      uint64_t addr, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (addr) {
        if (!dh_addr_is_executable(addr)) {
            if (err) snprintf(err, errsz, "addr 0x%llx is not in an executable mapping",
                              (unsigned long long)addr);
            return NULL;
        }
        return (void *)(uintptr_t)addr;
    }
    if (!symbol || !symbol[0]) {
        if (err) snprintf(err, errsz, "symbol or addr required");
        return NULL;
    }
    void *handle = NULL;
    if (module && module[0]) {
        const char *prefixes[3] = { "", "/var/jb/usr/lib/", "/usr/lib/" };
        char path[512];
        for (int i = 0; i < 3 && !handle; i++) {
            snprintf(path, sizeof(path), "%s%s", prefixes[i], module);
            handle = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
            if (!handle) handle = dlopen(path, RTLD_LAZY);
        }
        if (!handle && err) snprintf(err, errsz, "dlopen(%s) failed: %s", module,
                                     dlerror() ?: "unknown");
    } else {
        handle = dlopen(NULL, RTLD_LAZY);
    }
    void *target = handle ? dlsym(handle, symbol) : NULL;
    if (!target) target = dlsym(RTLD_DEFAULT, symbol);
    if (!target && symbol[0] != '_') {
        char underscored[256];
        snprintf(underscored, sizeof(underscored), "_%s", symbol);
        target = dlsym(RTLD_DEFAULT, underscored);
    }
    if (!target && err) {
        snprintf(err, errsz, "symbol %s not found%s%s", symbol,
                 (module && module[0]) ? " in " : "", (module && module[0]) ? module : "");
    }
    return target;
}

static int dh_save_code_bytes(void *target, uint8_t *out, size_t cap) {
    size_t want = cap < 32 ? cap : 32;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)target,
                                         (vm_size_t)want, (vm_address_t)out, &copied);
    if (kr == KERN_SUCCESS && copied == want) return (int)want;
    if (want > 16) {
        copied = 0;
        kr = vm_read_overwrite(mach_task_self(), (vm_address_t)target, 16,
                               (vm_address_t)out, &copied);
        if (kr == KERN_SUCCESS && copied == 16) return 16;
    }
    return 0;
}

int dh_thunk_install_inline(const char *module, const char *symbol, uint64_t addr,
                            const char *label, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!DH_THUNK_ARM64) {
        if (err) snprintf(err, errsz, "inline hook is only supported on arm64/arm64e");
        return -4;
    }
    // 处理器在命中瞬间会分配 Foundation 对象（事件、字符串、栈符号化）。
    // hook 分配器本身会递归进同一分配器，在 malloc 序言/原函数蹦床尚未完成时重入，
    // 实测会直接把宿主打死（engine_shell 在 hook malloc 后立刻退出）。这里显式拒绝。
    if (symbol && symbol[0]) {
        static const char *unsafe_syms[] = {
            "malloc", "calloc", "realloc", "free", "valloc", "posix_memalign",
            "aligned_alloc", "malloc_zone_malloc", "malloc_zone_calloc",
            "malloc_zone_realloc", "malloc_zone_free",
            "objc_msgSend", "_objc_msgSend", "objc_retain", "objc_release",
            NULL
        };
        for (int i = 0; unsafe_syms[i]; i++) {
            if (strcmp(symbol, unsafe_syms[i]) == 0) {
                if (err) snprintf(err, errsz,
                    "refusing to inline-hook allocator/runtime symbol '%s': the hit handler allocates, "
                    "so hooking allocation itself recurses before the original prologue completes and kills the process. "
                    "Hook the caller/algorithm function instead.", symbol);
                return -4;
            }
        }
    }
#if !DH_HAVE_INLINE
    if (err) snprintf(err, errsz,
                      "inline hook backend is not linked in this slice (vendor Dobby is arm64-only)");
    return -4;
#else
    void *target = dh_resolve_inline_target(module, symbol, addr, err, errsz);
    if (!target) return -2;

    pthread_mutex_lock(&g_install_lock);
    // 同一目标不允许重复 inline hook: 旧补丁会把入口改成 thunk, 再 DobbyHook 会去 hook thunk 本身。
    int total = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
    if (total > DH_THUNK_COUNT) total = DH_THUNK_COUNT;
    for (int i = 0; i < total; i++) {
        dh_slot_t *old = &g_slots[i];
        if (old->used && !atomic_load_explicit(&old->retired, memory_order_relaxed) &&
            old->kind == DH_HOOK_INLINE && old->target == target) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz,
                "target 0x%llx is already inline-hooked at slot %d; unhook it first (hard:true restores the original code)",
                (unsigned long long)(uintptr_t)target, i);
            return -5;
        }
    }
    // 同一目标 hard-unhook 后再次安装: 复用原槽位和原 Dobby 蹦床, 重新写回 patched 字节。
    // 不调用 DobbyHook(它会因内部 closure 表已有该地址而拒绝), 也不回收槽位给别的目标。
    for (int i = total - 1; i >= 0; i--) {
        dh_slot_t *old = &g_slots[i];
        if (!old->used || old->kind != DH_HOOK_INLINE || old->target != target) continue;
        if (!atomic_load_explicit(&old->retired, memory_order_relaxed)) continue;
        if (old->saved_len <= 0 || old->patched_len != old->saved_len) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz,
                "slot %d was hard-unhooked but has no reusable patch image; restart the process to hook 0x%llx again",
                i, (unsigned long long)(uintptr_t)target);
            return -5;
        }
        uint8_t cur[32];
        int curlen = dh_save_code_bytes(target, cur, sizeof(cur));
        if (curlen < old->saved_len ||
            memcmp(cur, old->saved, (size_t)old->saved_len) != 0) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz,
                "target 0x%llx was hard-unhooked but its entry bytes changed since then; refusing to re-hook (a stale hook or another patch owns it)",
                (unsigned long long)(uintptr_t)target);
            return -5;
        }
        int prc = DobbyCodePatch(target, old->patched, (uint32_t)old->patched_len);
        if (prc != 0) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz, "DobbyCodePatch re-apply failed: rc=%d", prc);
            return -4;
        }
        if (label && label[0]) snprintf(old->name, sizeof(old->name), "%s", label);
        atomic_store_explicit(&old->retired, 0, memory_order_release);
        atomic_store_explicit(&old->enabled, 1, memory_order_release);
        pthread_mutex_unlock(&g_install_lock);
        return i;
    }
    int slot = dh_alloc_slot();
    if (slot < 0) {
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "hook slots exhausted (capacity %d)", DH_THUNK_COUNT);
        return -1;
    }
    dh_slot_t *s = &g_slots[slot];
    memset(s, 0, sizeof(*s));
    if (label && label[0]) {
        snprintf(s->name, sizeof(s->name), "%s", label);
    } else if (symbol && symbol[0] && module && module[0]) {
        snprintf(s->name, sizeof(s->name), "%s!%s", module, symbol);
    } else if (symbol && symbol[0]) {
        snprintf(s->name, sizeof(s->name), "%s", symbol);
    } else {
        snprintf(s->name, sizeof(s->name), "0x%llx", (unsigned long long)(uintptr_t)target);
    }
    s->kind = DH_HOOK_INLINE;
    s->used = 1;
    s->target = target;
    s->saved_len = dh_save_code_bytes(target, s->saved, sizeof(s->saved));
    atomic_store_explicit(&s->retired, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    atomic_store_explicit(&s->capture_return, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_after, 0, memory_order_relaxed);
    s->capture_multi[0] = '\0';
    atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
    g_dh_thunk_post[slot] = 0;
    g_dh_thunk_orig[slot] = NULL;
    atomic_store_explicit(&s->enabled, 0, memory_order_release);

    int rc = DobbyHook(target, (void *)dh_slot_addr(slot),
                       (void **)&g_dh_thunk_orig[slot]);
    if (rc != 0 || g_dh_thunk_orig[slot] == NULL) {
        s->used = 0;
        s->name[0] = '\0';
        s->capture_multi[0] = '\0';
        atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
        s->target = NULL;
        s->saved_len = 0;
        s->patched_len = 0;
        int last = slot + 1;
        atomic_compare_exchange_strong_explicit(&g_next_slot, &last, slot,
                                                memory_order_relaxed, memory_order_relaxed);
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "DobbyHook(0x%llx) failed: rc=%d orig=%p",
                          (unsigned long long)(uintptr_t)target, rc, g_dh_thunk_orig[slot]);
        return -4;
    }
    s->patched_len = dh_save_code_bytes(target, s->patched, sizeof(s->patched));
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    pthread_mutex_unlock(&g_install_lock);
    return slot;
#endif
}

const char *dh_thunk_inline_backend(void) {
#if DH_HAVE_INLINE
    return "dobby";
#else
    return "unavailable(arm64e-slice)";
#endif
}

int dh_thunk_set_describe(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;   // import hook 走「可打印 C 字符串」判定, method hook 走对象反引用
    atomic_store_explicit(&s->describe_args, on ? 1 : 0, memory_order_relaxed);
    return 0;
}

int dh_thunk_set_capture(int slot, int ptr_arg, int len_arg, int max_bytes) {    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (ptr_arg < 0) {   // 关闭捕获
        atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_release);
        return 0;
    }
    if (ptr_arg > 8 || len_arg < -1 || len_arg > 8) return -1;
    if (max_bytes < 1 || max_bytes > DH_THUNK_CAPTURE_MAX) return -1;
    // 先发布长度/上限, 最后用 release 发布 ptr_arg —— handler 用 acquire 读 ptr_arg,
    // 保证它看到 ptr_arg>=0 时另外两个字段一定已是本次配置。
    atomic_store_explicit(&s->capture_len_arg, len_arg, memory_order_relaxed);
    atomic_store_explicit(&s->capture_max_bytes, max_bytes, memory_order_relaxed);
    atomic_store_explicit(&s->capture_ptr_arg, ptr_arg, memory_order_release);
    return 0;
}

int dh_thunk_set_return(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) return -1;
    // 先写槽位字段再发布汇编可见的标记位 (release), 保证 handler 看到 1 时字段已就绪。
    atomic_store_explicit(&s->capture_return, on ? 1 : 0, memory_order_relaxed);
    g_dh_thunk_post[slot] = on ? 1 : 0;
    return 0;
}

// capture_after=1: capture_ptr_arg 指向的是「调用之后才写好的输出缓冲」(CCHmac 的 digest 出参、
// CCCrypt 的密文出参)。这种槽位必须走 post 路径, 否则入口抓到的是未初始化内存。
int dh_thunk_set_capture_after(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) return -1;
    // 只开 after 而不配 capture_memory 是悬空语义(没有 ptr_arg 可读), 直接拒绝而不是让它静默什么都不做。
    if (on && atomic_load_explicit(&s->capture_ptr_arg, memory_order_acquire) < 0) return -2;
    atomic_store_explicit(&s->capture_after, on ? 1 : 0, memory_order_relaxed);
    if (on) {   // 输出缓冲只有返回后才有内容, 必须同时打开 post 路径
        atomic_store_explicit(&s->capture_return, 1, memory_order_relaxed);
        g_dh_thunk_post[slot] = 1;
    }
    return 0;
}
// 多窗口抓取: 一次 hook 同时观察多个寄存器指向的内存。
// 一个 inline 目标只能装一个 hook，没有这个能力就只能卸了重装换寄存器；
// 而 inline 槽位分配后不回收，换一次寄存器就要重启目标进程一次。
int dh_thunk_set_capture_multi(int slot, const char *spec) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (!spec || !spec[0]) {
        atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
        s->capture_multi[0] = '\\0';
        return 0;
    }
    if (strlen(spec) >= sizeof(s->capture_multi)) return -1;
    // 语法预检: 只接受 "x<0-8>[:N]" 的逗号序列，其它一律拒绝（不让坏规格静默变成空抓取）。
    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        if (*p != 'x' && *p != 'X' && !(*p >= '0' && *p <= '9')) return -1;
        if (*p == 'x' || *p == 'X') p++;
        if (!(*p >= '0' && *p <= '8')) return -1;
        p++;
        if (*p == ':') {
            p++;
            if (!(*p >= '0' && *p <= '9')) return -1;
            while (*p >= '0' && *p <= '9') p++;
        }
        if (*p && *p != ',' && *p != ' ') return -1;
    }
    // 写入端与 hook 命中线程的读取端没有锁。若直接 strlcpy 覆盖, 读到的是「写了一半」的混合串
    // (例如旧 "x0:64,x3:32" 被新 "x5:128" 覆盖时读到 "x5:64,x3:32"), 会抓错寄存器产出错误证据。
    // 做法: 先把新规格写进 shadow, 再原子翻转 ready 标志; 读取端只在 ready 为 1 时整串读。
    strlcpy(s->capture_multi_shadow, spec, sizeof(s->capture_multi_shadow));
    atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
    strlcpy(s->capture_multi, s->capture_multi_shadow, sizeof(s->capture_multi));
    atomic_store_explicit(&s->capture_multi_ready, 1, memory_order_release);
    return 0;
}

// 撤销一次刚完成的安装（参数校验失败时用）。
// 为什么需要: 装 hook 时槽位先分配、参数后校验；校验失败如果只 disable 不回收，
// 槽位会以「已用但半配置」的状态留在表里，list_hooks 会显示一个名字是旧 label、
// 配置是新参数的混合体 —— 排查时完全误导。
int dh_thunk_abort_install(int slot) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    pthread_mutex_lock(&g_install_lock);
    dh_slot_t *s = &g_slots[slot];
    if (s->used) {
        s->used = 0;
        s->name[0] = '\0';
        s->capture_multi[0] = '\0';
        atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
        atomic_store_explicit(&s->enabled, 0, memory_order_release);
        atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
        atomic_store_explicit(&s->capture_return, 0, memory_order_relaxed);
        atomic_store_explicit(&s->capture_after, 0, memory_order_relaxed);
        g_dh_thunk_post[slot] = 0;
        int last = slot + 1;
        atomic_compare_exchange_strong_explicit(&g_next_slot, &last, slot,
                                                memory_order_relaxed, memory_order_relaxed);
    }
    pthread_mutex_unlock(&g_install_lock);
    return 0;
}

int dh_thunk_disable(int slot) {
    if (slot < 0 || slot >= DH_THUNK_COUNT || !g_slots[slot].used) return -1;
    atomic_store_explicit(&g_slots[slot].enabled, 0, memory_order_release);
    return 0;
}

int dh_thunk_uninstall(int slot, int hard, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (slot < 0 || slot >= DH_THUNK_COUNT || !g_slots[slot].used) {
        if (err) snprintf(err, errsz, "slot %d is not an active hook", slot);
        return -1;
    }
    pthread_mutex_lock(&g_install_lock);
    dh_slot_t *s = &g_slots[slot];
    atomic_store_explicit(&s->enabled, 0, memory_order_release);
    if (!hard) {   // 软停: 停止记录, patch 保留
        pthread_mutex_unlock(&g_install_lock);
        return 0;
    }
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) {
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "slot %d is already hard-unhooked (retired)", slot);
        return 0;
    }
    if (s->kind == DH_HOOK_INLINE) {
#if DH_HAVE_INLINE
        if (!s->target || s->saved_len <= 0) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz,
                "slot %d has no saved original bytes; hard unhook unavailable, use soft unhook", slot);
            return -5;
        }
        // 只恢复目标入口的原始字节, 不调用 DobbyDestroy: 后者会释放 Dobby 的原函数蹦床,
        // 而在途线程可能已经进入 thunk 并即将 br 到该蹦床; 保留蹦床可避免 use-after-free。
        int rc = DobbyCodePatch(s->target, s->saved, (uint32_t)s->saved_len);
        if (rc != 0) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz, "DobbyCodePatch restore failed: rc=%d", rc);
            return -4;
        }
        atomic_store_explicit(&s->retired, 1, memory_order_release);
        pthread_mutex_unlock(&g_install_lock);
        return 0;
#else
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "Dobby backend is not linked in this slice (arm64e)");
        return -5;
#endif
    }
    if (s->kind == DH_HOOK_METHOD) {
        Method m = (Method)s->method;
        IMP orig = (IMP)g_dh_thunk_orig[slot];
        if (!m || !orig) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz, "slot %d has no original IMP", slot);
            return -5;
        }
        method_setImplementation(m, orig);
        atomic_store_explicit(&s->retired, 1, memory_order_release);
        pthread_mutex_unlock(&g_install_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_install_lock);
    if (err) snprintf(err, errsz,
        "hard unhook is not supported for fishhook import hooks; use soft unhook");
    return -5;
}

int dh_thunk_list(dh_hook_info *out, int max) {
    int total = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
    if (total > DH_THUNK_COUNT) total = DH_THUNK_COUNT;
    int n = 0;
    for (int i = 0; i < total && n < max; i++) {
        if (!g_slots[i].used) continue;
        out[n].slot    = i;
        out[n].enabled = atomic_load_explicit(&g_slots[i].enabled, memory_order_relaxed);
        out[n].retired = atomic_load_explicit(&g_slots[i].retired, memory_order_relaxed);
        out[n].kind    = g_slots[i].kind;
        out[n].hits    = atomic_load_explicit(&g_slots[i].hits, memory_order_relaxed);
        out[n].name    = g_slots[i].name;
        // capture_multi 必须回填: 否则 list_hooks 看不到多窗口配置, 用户没法自查是否真的生效。
        strlcpy(out[n].capture_multi, g_slots[i].capture_multi, sizeof(out[n].capture_multi));
        out[n].capture_ptr_arg   = atomic_load_explicit(&g_slots[i].capture_ptr_arg, memory_order_acquire);
        out[n].capture_len_arg   = atomic_load_explicit(&g_slots[i].capture_len_arg, memory_order_relaxed);
        out[n].capture_max_bytes = atomic_load_explicit(&g_slots[i].capture_max_bytes, memory_order_relaxed);
        out[n].capture_return   = atomic_load_explicit(&g_slots[i].capture_return, memory_order_relaxed);
        out[n].capture_after    = atomic_load_explicit(&g_slots[i].capture_after, memory_order_relaxed);
        n++;
    }
    return n;   // 实际写入条数 (跳过被作废的槽)
}
