// dh_thunk.m — 见 dh_thunk.h
//
// 仅 arm64 / arm64e。其它架构下 thunk 表与安装 API 退化为空实现(编译期屏蔽)。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <pthread.h>
#import <stdatomic.h>
#include <mach/mach.h>
#include <ptrauth.h>
#import "dh_thunk.h"
#import "log_store.h"
#import "fishhook.h"

// asm 尾调用要用的「原函数指针表」—— thunk 用 slot 索引它跳转。必须是全局符号(asm 引用)。
void *g_dh_thunk_orig[DH_THUNK_COUNT];

// 槽位注册表 (单调分配, 不回收)。
typedef struct {
    char             name[160];
    _Atomic uint64_t hits;
    _Atomic int      enabled;
    _Atomic int      describe_args;   // method hook: 记录时反引用前几个参数内容
    _Atomic int      capture_ptr_arg;   // >=0: 抓该寄存器位置的指针参数
    _Atomic int      capture_len_arg;   // >=0: 从该寄存器取长度; -1: 固定长度
    _Atomic int      capture_max_bytes;
    dh_hook_kind     kind;
    int              used;
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
".rept 128\n"                       // 必须与 DH_THUNK_COUNT 一致
"  movz x17, #_dht_idx\n"
"  b    _dh_thunk_trampoline\n"
"  .set _dht_idx, _dht_idx + 1\n"
".endr\n"
"\n"
".globl _dh_thunk_trampoline\n"
"_dh_thunk_trampoline:\n"
"  sub  sp, sp, #0xE0\n"           // 224B 帧: x0-8 + slot + q0-7 + lr
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
"  add  sp, sp, #0xE0\n"
"  adrp x16, _g_dh_thunk_orig@PAGE\n"
"  add  x16, x16, _g_dh_thunk_orig@PAGEOFF\n"
"  ldr  x16, [x16, x17, lsl #3]\n" // 原函数 = g_dh_thunk_orig[slot]
"  br   x16\n"                     // 尾调用: lr 已复原, 原函数直接返回真正的调用者
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
    if (v < 0x100000000ULL || (v & 0x7)) return nil;
    // 判定分两层, 顺序很重要:
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
            NSString *t = s.length > 200 ? [[s substringToIndex:200] stringByAppendingString:@"…"] : s;
            return [NSString stringWithFormat:@"NSString(%lu) %@", (unsigned long)s.length, t];
        }
        NSString *desc = [obj description];
        if (desc.length > 300) desc = [[desc substringToIndex:300] stringByAppendingString:@"…"];
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
        e.algorithm = (s->kind == DH_HOOK_METHOD) ? @"objc-hook" : @"import-hook";
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
        [d appendFormat:@"\nsp=0x%llx lr=0x%llx", caller_sp, lr];
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
    int slot = dh_alloc_slot();
    if (slot < 0) { pthread_mutex_unlock(&g_install_lock); return -1; }
    dh_slot_t *s = &g_slots[slot];
    snprintf(s->name, sizeof(s->name), "%s%s%s", symbol,
             (label && label[0]) ? " " : "", (label && label[0]) ? label : "");
    s->kind = DH_HOOK_IMPORT;
    s->used = 1;
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    g_dh_thunk_orig[slot] = NULL;
    struct rebinding rb = { symbol, dh_slot_addr(slot), &g_dh_thunk_orig[slot] };
    rebind_symbols(&rb, 1);
    if (g_dh_thunk_orig[slot] == NULL) {
        // 任何 image 的 la_symbol_ptr/__got 里都没这个符号 —— fishhook 从未把任何跳转指向 thunk[slot],
        // 所以回收该槽 100% 安全(没有遗留跳转)。若它正好是最后分配的一个, 直接回退计数复用。
        s->used = 0;
        s->name[0] = '\0';
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
    Method m = classMethod ? class_getClassMethod(cls, sel)
                           : class_getInstanceMethod(cls, sel);
    if (!m) return -3;
    pthread_mutex_lock(&g_install_lock);
    int slot = dh_alloc_slot();
    if (slot < 0) { pthread_mutex_unlock(&g_install_lock); return -1; }
    dh_slot_t *s = &g_slots[slot];
    snprintf(s->name, sizeof(s->name), "%c[%s %s]", classMethod ? '+' : '-', className, selector);
    s->kind = DH_HOOK_METHOD;
    s->used = 1;
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    g_dh_thunk_orig[slot] = (void *)method_getImplementation(m);
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    method_setImplementation(m, (IMP)dh_slot_addr(slot));
    pthread_mutex_unlock(&g_install_lock);
    return slot;
}

int dh_thunk_set_describe(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;   // import hook 走「可打印 C 字符串」判定, method hook 走对象反引用
    atomic_store_explicit(&s->describe_args, on ? 1 : 0, memory_order_relaxed);
    return 0;
}

int dh_thunk_set_capture(int slot, int ptr_arg, int len_arg, int max_bytes) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
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

int dh_thunk_disable(int slot) {
    if (slot < 0 || slot >= DH_THUNK_COUNT || !g_slots[slot].used) return -1;
    atomic_store_explicit(&g_slots[slot].enabled, 0, memory_order_release);
    return 0;
}

int dh_thunk_list(dh_hook_info *out, int max) {
    int total = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
    if (total > DH_THUNK_COUNT) total = DH_THUNK_COUNT;
    int n = 0;
    for (int i = 0; i < total && n < max; i++) {
        if (!g_slots[i].used) continue;
        out[n].slot    = i;
        out[n].enabled = atomic_load_explicit(&g_slots[i].enabled, memory_order_relaxed);
        out[n].kind    = g_slots[i].kind;
        out[n].hits    = atomic_load_explicit(&g_slots[i].hits, memory_order_relaxed);
        out[n].name    = g_slots[i].name;
        out[n].capture_ptr_arg   = atomic_load_explicit(&g_slots[i].capture_ptr_arg, memory_order_acquire);
        out[n].capture_len_arg   = atomic_load_explicit(&g_slots[i].capture_len_arg, memory_order_relaxed);
        out[n].capture_max_bytes = atomic_load_explicit(&g_slots[i].capture_max_bytes, memory_order_relaxed);
        n++;
    }
    return n;   // 实际写入条数 (跳过被作废的槽)
}
