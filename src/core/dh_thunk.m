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
#import "dh_health.h"
#import "fishhook.h"
#include "dh_method_arg_type.h"
#include "dh_vm_map.h"
#import "dh_event.h"
#include "dh_call_context.h"
#import "dh_unwind.h"
#import "dh_flow.h"
#import "../trace/qbdi_live.h"
#include <errno.h>

// 内联后端按实际链接切片决定；arm64e Dobby 输出已签名函数指针，而 thunk 使用原始 br/blr。
#ifndef DH_HAVE_INLINE
#define DH_HAVE_INLINE 1
#endif

#if DH_HAVE_INLINE
#include "dobby.h"
extern int DobbyHookWithContext(void *,void *,void **);
#endif

int dh_thunk_inline_available(void) {
#if DH_HAVE_INLINE && (defined(__arm64__) || defined(__aarch64__))
    return 1;
#else
    return 0;
#endif
}

// asm 尾调用要用的「原函数指针表」—— thunk 用 slot 索引它跳转。必须是全局符号(asm 引用)。
void *g_dh_thunk_orig[DH_THUNK_COUNT];

// 需要记录返回值的槽位标记 (1 = 走 post 路径: 先调原函数, 抓到返回值再返回)。
// 必须是全局符号, 汇编里按 slot 索引读。
uint8_t g_dh_thunk_post[DH_THUNK_COUNT];
uint16_t g_dh_thunk_stack_bytes[DH_THUNK_COUNT];

// 槽位注册表 (单调分配; 软停不回收, 硬停后退休)。
typedef struct {
    char             name[160];
    _Atomic uint64_t hits;
    _Atomic int      enabled;
    _Atomic int      retired;         // 已硬卸载: 原代码已恢复, 槽位不再复用
    _Atomic int      describe_args;   // method hook: 记录时反引用前几个参数内容
    unsigned int     method_arg_count; // 不含 self/_cmd 的真实声明参数数
    int              method_simple_gpr; // 只对单 GPR 标量/指针签名解释参数位置
    uint8_t          method_object_gprs; // 允许作为 ObjC 对象反引用的 x2..x7 位
    unsigned int     method_stack_bytes;
    struct { uint16_t offset; uint8_t size, object; } method_stack_args[26]; // arg6..arg31
    char             argument_types[32][64];
    char             return_type[64];
    _Atomic int      capture_ptr_arg;   // >=0: 抓该寄存器位置的指针参数
    _Atomic int      capture_len_arg;   // >=0: 从该寄存器取长度; -1: 固定长度
    _Atomic int      capture_max_bytes;
    _Atomic int      capture_return;   // 1 = post 路径, 记录返回值
    _Atomic int      capture_after;    // 1 = capture_ptr_arg 指向「调用后才写好的输出缓冲」
    char             capture_multi[96];        // 多窗口: "x0:64,x3:32,x5:128" (空=关闭)
    _Atomic int      capture_multi_ready;      // 1 = capture_multi 内容完整可读
    char             capture_ret_multi[96];  // 同上, 但作用于「返回值寄存器」(post 路径)
    _Atomic int      capture_ret_multi_ready;
    dh_hook_kind     kind;
    char             import_symbol[256]; // fishhook keeps this pointer for future images
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
static __thread const dh_hook_options *g_pending_options;
static dh_hook_options g_slot_options[DH_THUNK_COUNT];
static NSDictionary *g_slot_targets[DH_THUNK_COUNT];
static _Atomic int g_slot_published[DH_THUNK_COUNT];
static _Atomic uint64_t g_slot_inflight[DH_THUNK_COUNT];
static void dh_prepare_slot_options(int slot);
static BOOL dh_addr_is_executable(uint64_t addr);
int dh_thunk_is_inline_patched(uint64_t address) {
    int found=0;
    pthread_mutex_lock(&g_install_lock);
    int count=atomic_load(&g_next_slot); if (count>DH_THUNK_COUNT) count=DH_THUNK_COUNT;
    for (int i=0;i<count;i++)
        if (g_slots[i].used && g_slots[i].kind==DH_HOOK_INLINE &&
            (uint64_t)(uintptr_t)g_slots[i].target==address) { found=1;break; }
    pthread_mutex_unlock(&g_install_lock);
    return found;
}
static int dh_unsafe_runtime_symbol(const char *symbol) {
    if (!symbol) return 0;
    if (symbol[0] == '_') symbol++;
    if(DHFlowOwnsImport(symbol))return 1;
    static const char *names[] = {"malloc", "calloc", "realloc", "free", "valloc", "posix_memalign",
        "aligned_alloc", "malloc_zone_malloc", "malloc_zone_calloc", "malloc_zone_realloc",
        "malloc_zone_free", "objc_msgSend", "objc_retain", "objc_release", NULL};
    for (unsigned i = 0; names[i]; i++) if (!strcmp(symbol, names[i])) return 1;
    return 0;
}
int dh_thunk_has_import(const char *name) {
    int found=0;pthread_mutex_lock(&g_install_lock);int n=atomic_load(&g_next_slot);
    for(int i=0;i<n && i<DH_THUNK_COUNT;i++)if(g_slots[i].used && g_slots[i].kind==DH_HOOK_IMPORT && !strcmp(g_slots[i].import_symbol,name)) {found=1;break;}
    pthread_mutex_unlock(&g_install_lock);return found;
}

void dh_thunk_options_default(dh_hook_options *o) {
    memset(o, 0, sizeof(*o)); o->ptr_arg = -1; o->len_arg = -1;
}

int dh_thunk_validate_options(const dh_hook_options *o, char *err, size_t errsz) {
    const char *failure = NULL;
    if (!o) failure = "hook options required";
    else if (o->ptr_arg < -1 || o->ptr_arg > 8 || o->len_arg < -1 || o->len_arg > 8 ||
             (o->ptr_arg >= 0 && (o->max_bytes < 1 || o->max_bytes > DH_THUNK_CAPTURE_MAX)))
        failure = "capture_memory register/length/budget invalid";
    else if (o->capture_after && o->ptr_arg < 0) failure = "capture_after requires capture_memory";
    else if (dh_thunk_validate_capture_multi(o->capture_multi)) failure = "capture_multi invalid or outside budget";
    else if (dh_thunk_validate_capture_ret_multi(o->capture_ret_multi)) failure = "capture_ret_multi accepts only x0/x1 within budget";
    else if (o->argument_count > 32) failure = "ABI supports at most 32 fixed arguments";
    else if (o->abi_declared) {
        for (unsigned int i = 0; i < o->argument_count; i++) {
            char type[2] = {o->argument_types[i], 0};
            if (!dh_method_arg_type(type)) { failure = "ABI argument must be a fixed GPR scalar/pointer"; break; }
        }
        char ret[2] = {o->return_type, 0};
        if (!failure && o->return_type != 'v' && !dh_method_arg_type(ret)) failure = "ABI return must be void or a GPR scalar/pointer";
        if (!failure && o->return_type == 'v' && o->capture_ret_multi[0]) failure = "void ABI has no return registers to capture";
    }
    if (failure) { if (err && errsz) snprintf(err, errsz, "%s", failure); return -1; }
    return 0;
}

int dh_thunk_install_configured(dh_hook_kind kind, const char *owner, const char *name,
    uint64_t address, int classMethod, const char *label, const dh_hook_options *options,
    char *err, size_t errsz) {
    if (err && errsz) err[0] = 0;
    if (dh_thunk_validate_options(options, err, errsz)) return -6;
    if (kind != DH_HOOK_METHOD && dh_unsafe_runtime_symbol(name)) {
        if (err && errsz) snprintf(err, errsz, "%s",DHFlowOwnsImport(name)?"GCD import is owned by bounded async capture; restart before changing ownership":"allocator/runtime hooks are unsafe because the event handler allocates");
        return -6;
    }
    int post = options->capture_return || options->capture_after || options->capture_ret_multi[0];
    if (kind == DH_HOOK_METHOD && post && !options->fixed_abi) {
        if (err && errsz) snprintf(err, errsz, "method post ABI requires post_abi=fixed-nonvariadic; runtime metadata does not identify variadic methods");
        return -6;
    }
    if (kind != DH_HOOK_METHOD && post && !options->abi_declared) {
        if (err && errsz) snprintf(err, errsz, "C post capture requires an explicit fixed-GPR abi declaration; unknown/variadic ABI is entry-only");
        return -6;
    }
    if (kind == DH_HOOK_METHOD && post) {
        if (dh_thunk_method_post_supported(owner, name, classMethod) != 1) {
            if (err && errsz) snprintf(err, errsz, "method post ABI unsupported (floating/aggregate/unknown or argument budget); use entry-only");
            return -6;
        }
        Class cls = objc_getClass(owner);
        Method m = classMethod ? class_getClassMethod(cls, sel_registerName(name)) : class_getInstanceMethod(cls, sel_registerName(name));
        char *ret = m ? method_copyReturnType(m) : NULL;
        int voidWindow = ret && ret[0] == 'v' && options->capture_ret_multi[0];
        free(ret);
        if (voidWindow) { if (err && errsz) snprintf(err, errsz, "void method ABI has no return registers to capture"); return -6; }
    }
    g_pending_options = options;
    int slot = kind == DH_HOOK_METHOD ? dh_thunk_install_method(owner, name, classMethod)
        : kind == DH_HOOK_INLINE ? dh_thunk_install_inline(owner, name, address, label, err, errsz)
        : dh_thunk_install_import(name, label);
    g_pending_options = NULL;
    return slot;
}

static void dh_prepare_slot_options(int slot) {
    dh_slot_t *s = &g_slots[slot];
    dh_hook_options defaults;
    dh_thunk_options_default(&defaults);
    const dh_hook_options *o = g_pending_options ?: &defaults;
    g_slot_options[slot] = *o;
    if (s->kind != DH_HOOK_METHOD) {
        s->method_arg_count = o->abi_declared ? o->argument_count : 0;
        s->method_simple_gpr = o->abi_declared;
        s->return_type[0] = o->abi_declared ? o->return_type : '?';
        for (unsigned i = 0; i < s->method_arg_count; i++) s->argument_types[i][0] = o->argument_types[i];
    }
    unsigned registers = s->kind == DH_HOOK_METHOD ? 6 : 8;
    s->method_stack_bytes = 0;
    memset(s->method_stack_args, 0, sizeof(s->method_stack_args));
    if (s->method_simple_gpr) {
        for (unsigned i = registers; i < s->method_arg_count && i < 32; i++) {
            unsigned size = dh_method_arg_size(s->argument_types[i]);
            unsigned offset = dh_method_stack_offset(s->method_stack_bytes, size);
            s->method_stack_args[i - registers].offset = offset;
            s->method_stack_args[i - registers].size = size;
            s->method_stack_args[i - registers].object = dh_method_arg_type(s->argument_types[i]) == 2;
            s->method_stack_bytes = offset + size;
        }
    }
    atomic_store(&s->describe_args, o->describe_args);
    atomic_store(&s->capture_ptr_arg, o->ptr_arg);
    atomic_store(&s->capture_len_arg, o->len_arg);
    atomic_store(&s->capture_max_bytes, o->max_bytes);
    atomic_store(&s->capture_return, o->capture_return);
    atomic_store(&s->capture_after, o->capture_after);
    strlcpy(s->capture_multi, o->capture_multi, sizeof(s->capture_multi));
    strlcpy(s->capture_ret_multi, o->capture_ret_multi, sizeof(s->capture_ret_multi));
    atomic_store(&s->capture_multi_ready, o->capture_multi[0] ? 2 : 0);
    atomic_store(&s->capture_ret_multi_ready, o->capture_ret_multi[0] ? 2 : 0);
    g_dh_thunk_post[slot] = o->capture_return || o->capture_after || o->capture_ret_multi[0];
    g_dh_thunk_stack_bytes[slot] = s->method_stack_bytes;
    g_slot_targets[slot] = DHTargetIdentity(s->target ?: g_dh_thunk_orig[slot]);
}

NSDictionary *dh_thunk_metadata(int slot) {
    if (slot < 0 || slot >= DH_THUNK_COUNT || !g_slots[slot].used) return @{};
    dh_slot_t *s = &g_slots[slot];
    BOOL known = s->kind == DH_HOOK_METHOD || g_slot_options[slot].abi_declared;
    BOOL post = known && s->method_simple_gpr && s->method_arg_count <= 32 &&
        (s->return_type[0] == 'v' || dh_method_arg_type(s->return_type));
    return @{@"hookId": [NSString stringWithFormat:@"%@:hook:%d", DHProcessGeneration(), slot],
        @"processGeneration": DHProcessGeneration(), @"targetIdentity": g_slot_targets[slot] ?: @{},
        @"configurationImmutable": @YES, @"callStackMode": @"libunwind-context-CFI; deferred-symbolication",
        @"inFlight": [NSString stringWithFormat:@"%llu", atomic_load(&g_slot_inflight[slot])],
        @"importBindingPolicy": s->kind == DH_HOOK_IMPORT ? @"resolved-symbol; present-and-future-images; interposers-not-preserved; write-coverage-not-guaranteed" : @"not-applicable",
        @"abi": @{@"source": s->kind == DH_HOOK_METHOD ? @"objc-runtime" : known ? @"client-declaration" : @"unknown",
            @"argumentCount": known ? @(s->method_arg_count) : (id)[NSNull null],
            @"argumentMapping": s->method_simple_gpr ? @"fixed-gpr" : @"opaque-registers",
            @"returnType": @(s->return_type), @"stackBytes": @(s->method_stack_bytes),
            @"postSupported": @(post), @"stackForwarding": @(post),
            @"fixedSignatureAsserted": @(s->kind == DH_HOOK_METHOD ? g_slot_options[slot].fixed_abi : known),
            @"variadicDetection": @NO,
            @"floatAggregatePost": @NO, @"variadicPost": @NO, @"exceptionUnwind": @NO,
            @"hardInlineUnhook": @NO}};
}

#if defined(__arm64__) || defined(__aarch64__)

// ---- thunk 表 + 蹦床 (arm64) ----
// 每个槽位固定 32B，先保存原 x16/x17，再用 x17 传 slot 并进入公共桥。
// Inline context veneer 已完成同一次压栈，从槽位 +4 进入；方法/导入从 +0 进入。
__asm__(
".section __TEXT,__text\n"
".p2align 5\n"
".globl _dh_thunk_table\n"
"_dh_thunk_table:\n"
".cfi_startproc\n"
".set _dht_idx, 0\n"
".rept 256\n"
".cfi_def_cfa sp, 0\n"
"  stp x16, x17, [sp, #-16]!\n"
".cfi_def_cfa_offset 16\n"
"  movz x17, #_dht_idx\n"
"  b _dh_thunk_trampoline\n"
"  .space 20\n"
"  .set _dht_idx, _dht_idx + 1\n"
".endr\n"
".cfi_endproc\n"
".globl _dh_thunk_trampoline\n"
"_dh_thunk_trampoline:\n"
".cfi_startproc\n"
".cfi_def_cfa sp, 16\n"
"  sub  sp, sp, #0x450\n"
".cfi_def_cfa_offset 0x460\n"
"  stp  x0, x1, [sp, #0x00]\n"
"  stp  x2, x3, [sp, #0x10]\n"
"  stp  x4, x5, [sp, #0x20]\n"
"  stp  x6, x7, [sp, #0x30]\n"
"  stp  x8, x17, [sp, #0x40]\n"
"  stp  q0, q1, [sp, #0x50]\n"
"  stp  q2, q3, [sp, #0x70]\n"
"  stp  q4, q5, [sp, #0x90]\n"
"  stp  q6, q7, [sp, #0xB0]\n"
"  str  x30, [sp, #0xD0]\n"

"  str x9, [sp, #0x178]\n"
"  str x10, [sp, #0x180]\n"
"  add x9, sp, #0x130\n"
"  stp x0, x1, [x9, #0]\n"
"  stp x2, x3, [x9, #16]\n"
"  stp x4, x5, [x9, #32]\n"
"  stp x6, x7, [x9, #48]\n"
"  str x8, [x9, #64]\n"
"  str x11, [x9, #88]\n"
"  stp x12, x13, [x9, #96]\n"
"  stp x14, x15, [x9, #112]\n"
"  stp x16, x17, [x9, #128]\n"
"  stp x18, x19, [x9, #144]\n"
"  stp x20, x21, [x9, #160]\n"
"  stp x22, x23, [x9, #176]\n"
"  stp x24, x25, [x9, #192]\n"
"  stp x26, x27, [x9, #208]\n"
"  stp x28, x29, [x9, #224]\n"
"  str x30, [x9, #240]\n"
"  ldr x10, [sp, #0x450]\n"
"  ldr x11, [sp, #0x458]\n"
"  stp x10, x11, [x9, #128]\n"
"  add x10, sp, #0x460\n"
"  str x10, [x9, #248]\n"
"  ldr x10, [sp, #0xD0]\n"
"  add x11, sp, #0x460\n"
#if defined(__arm64e__)
"  pacib x10, x11\n"
#endif
"  str x10, [x9, #256]\n"
".cfi_offset 30, -0x230\n"
"  mrs x10, nzcv\n"
"  str x10, [x9, #264]\n"
"  mrs x10, fpcr\n"
"  str x10, [x9, #272]\n"
"  mrs x10, fpsr\n"
"  str x10, [x9, #280]\n"
"  stp q0, q1, [x9, #288]\n"
"  stp q2, q3, [x9, #320]\n"
"  stp q4, q5, [x9, #352]\n"
"  stp q6, q7, [x9, #384]\n"
"  stp q8, q9, [x9, #416]\n"
"  stp q10, q11, [x9, #448]\n"
"  stp q12, q13, [x9, #480]\n"
"  stp q14, q15, [x9, #512]\n"
"  stp q16, q17, [x9, #544]\n"
"  stp q18, q19, [x9, #576]\n"
"  stp q20, q21, [x9, #608]\n"
"  stp q22, q23, [x9, #640]\n"
"  stp q24, q25, [x9, #672]\n"
"  stp q26, q27, [x9, #704]\n"
"  stp q28, q29, [x9, #736]\n"
"  stp q30, q31, [x9, #768]\n"
"  adrp x16, _g_dh_thunk_orig@PAGE\n"
"  add  x16, x16, _g_dh_thunk_orig@PAGEOFF\n"
"  add  x16, x16, x17, lsl #3\n"
"  ldar x16, [x16]\n"
#if defined(__arm64e__)
"  xpaci x16\n"
#endif
"  str  x16, [sp, #0xD8]\n"
"  mov  x0, x17\n"
"  add  x1, sp, #0\n"
"  add  x2, sp, #0x460\n"
"  mov  x3, x30\n"
"  add x4, sp, #0x130\n"
"  bl   _dh_thunk_handler\n"
"  str  x0, [sp, #0x128]\n"
"  ldr x0, [sp, #0x48]\n"
"  ldr x1, [sp, #0xD8]\n"
"  add x2, sp, #0x130\n"
"  ldr x3, [sp, #0x128]\n"
"  bl _dh_live_claim\n"
"  cbz x0, Ldh_thunk_normal_restore\n"
".cfi_remember_state\n"
"  ldr x1, [x0]\n"
"  mov sp, x1\n"
".cfi_undefined 30\n"
"  b _dh_live_bridge\n"
".cfi_restore_state\n"
"Ldh_thunk_normal_restore:\n"
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
"  ldr  x16, [sp, #0xD8]\n"
"  adrp x15, _g_dh_thunk_post@PAGE\n"
"  add  x15, x15, _g_dh_thunk_post@PAGEOFF\n"
"  ldrb w15, [x15, x17]\n"
"  cbnz w15, 1f\n"
".cfi_remember_state\n"
"  add  sp, sp, #0x460\n"
".cfi_def_cfa_offset 0\n"
"  br   x16\n"
"// post \u8def\u5f84: \u9700\u8981\u8fd4\u56de\u503c\u7684\u69fd\u4f4d\u3002\u5148\u8c03\u539f\u51fd\u6570, \u4fdd\u5b58 x0/x1/q0/q1, \u8ba9 C \u8bb0\u5f55\u4e00\u6b21, \u518d\u539f\u6837\u8fd4\u56de\u3002\n"
"// \u4ee3\u4ef7\u662f\u8fd9\u5c42\u6808\u5e27\u8981\u4e00\u76f4\u7559\u5230\u539f\u51fd\u6570\u8fd4\u56de (\u800c\u4e0d\u662f\u5c3e\u8c03\u7528), \u56e0\u6b64\u53ea\u5bf9\u4ed8\u8d39\u69fd\u4f4d\u542f\u7528\u3002\n"
".cfi_restore_state\n"
"1:\n"
"  stp  x16, x30, [sp, #0xD0]\n"

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
"  sub  sp, sp, #0x100\n"
".cfi_def_cfa_offset 0x560\n"
"  adrp x9, _g_dh_thunk_stack_bytes@PAGE\n"
"  add  x9, x9, _g_dh_thunk_stack_bytes@PAGEOFF\n"
"  ldrh w9, [x9, x17, lsl #1]\n"
"  add  x10, sp, #0x560\n"
"  mov  x11, sp\n"
"  cbz  x9, 3f\n"
"2:\n"
"  ldrb w12, [x10], #1\n"
"  strb w12, [x11], #1\n"
"  subs x9, x9, #1\n"
"  b.ne 2b\n"
"3:\n"
"  blr  x16\n"
"  add  sp, sp, #0x100\n"
".cfi_def_cfa_offset 0x460\n"
"  str  x0, [sp, #0x00]\n"
"  str  x1, [sp, #0x08]\n"
"  stp  q0, q1, [sp, #0x50]\n"
"  stp  q2, q3, [sp, #0x70]\n"
"  ldp  x8, x17, [sp, #0x40]\n"
"  mov  x0, x17\n"
"  add  x1, sp, #0\n"
"  ldp  x2, x3, [sp, #0xD0]\n"
"  add  x4, sp, #0xE0\n"
"  ldr  x5, [sp, #0x128]\n"
"  bl   _dh_thunk_post_handler\n"
"  ldr  x0, [sp, #0x00]\n"
"  ldr  x1, [sp, #0x08]\n"
"  ldp  q0, q1, [sp, #0x50]\n"
"  ldp  q2, q3, [sp, #0x70]\n"
"  ldr  x30, [sp, #0xD8]\n"
"  add  sp, sp, #0x460\n"
".cfi_def_cfa_offset 0\n"
"  ret\n"
".cfi_endproc\n"
".globl _dh_live_bridge\n"
"_dh_live_bridge:\n"
".cfi_startproc\n"
".cfi_undefined 30\n"
"  mov x19, x0\n"
"  bl _dh_live_run\n"
"  cbnz x0, 8f\n"
"  ldr x16, [x19, #8]\n"
"  mov sp, x16\n"
"  ldr x19, [x19, #168]\n"
"  b Ldh_thunk_normal_restore\n"
"8:\n"
"  mov x17, x0\n"
"  ldr x16, [x17, #248]\n"
"  mov sp, x16\n"
".cfi_def_cfa sp, 0\n"
"  ldp q0, q1, [x17, #288]\n"
"  ldp q2, q3, [x17, #320]\n"
"  ldp q4, q5, [x17, #352]\n"
"  ldp q6, q7, [x17, #384]\n"
"  ldp q8, q9, [x17, #416]\n"
"  ldp q10, q11, [x17, #448]\n"
"  ldp q12, q13, [x17, #480]\n"
"  ldp q14, q15, [x17, #512]\n"
"  ldp q16, q17, [x17, #544]\n"
"  ldp q18, q19, [x17, #576]\n"
"  ldp q20, q21, [x17, #608]\n"
"  ldp q22, q23, [x17, #640]\n"
"  ldp q24, q25, [x17, #672]\n"
"  ldp q26, q27, [x17, #704]\n"
"  ldp q28, q29, [x17, #736]\n"
"  ldp q30, q31, [x17, #768]\n"
"  ldr x16, [x17, #272]\n"
"  msr fpcr, x16\n"
"  ldr x16, [x17, #280]\n"
"  msr fpsr, x16\n"
"  ldr x16, [x17, #264]\n"
"  msr nzcv, x16\n"
"  ldr x30, [x17, #256]\n"
"  ldp x0, x1, [x17, #0]\n"
"  ldp x2, x3, [x17, #16]\n"
"  ldp x4, x5, [x17, #32]\n"
"  ldp x6, x7, [x17, #48]\n"
"  ldp x8, x9, [x17, #64]\n"
"  ldp x10, x11, [x17, #80]\n"
"  ldp x12, x13, [x17, #96]\n"
"  ldp x14, x15, [x17, #112]\n"
"  ldp x18, x19, [x17, #144]\n"
"  ldp x20, x21, [x17, #160]\n"
"  ldp x22, x23, [x17, #176]\n"
"  ldp x24, x25, [x17, #192]\n"
"  ldp x26, x27, [x17, #208]\n"
"  ldp x28, x29, [x17, #224]\n"
"  ldp x16, x17, [x17, #128]\n"
"  ret\n"
".cfi_endproc\n"
);

extern void dh_thunk_table(void);   // asm label; 取地址即表基址
static inline void *dh_slot_addr(int i) { return (uint8_t *)dh_thunk_table + (size_t)i * 32; }

#define DH_THUNK_ARM64 1
#else
static inline void *dh_slot_addr(int i) { (void)i; return NULL; }
#define DH_THUNK_ARM64 0
#endif

// 线程内重入保护: 处理器会调 Foundation(可能再触发被 hook 的底层函数), 用 TLS 标志防无限递归。
static __thread int g_in_thunk = 0;
int dh_thunk_in_handler(void) {return g_in_thunk;}
int dh_thunk_post_frame(uint64_t pc,uint64_t sp,uint64_t callerSP) {
#if DH_THUNK_ARM64
    extern void dh_thunk_trampoline(void),dh_live_bridge(void);
    uint64_t start=(uint64_t)ptrauth_strip((void *)dh_thunk_trampoline,ptrauth_key_function_pointer);
    uint64_t end=(uint64_t)ptrauth_strip((void *)dh_live_bridge,ptrauth_key_function_pointer);
    return pc>=start && pc<end && (sp+0x560==callerSP || sp+0x460==callerSP);
#else
    return 0;
#endif
}

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

static NSString *dh_describe_arg(uint64_t v, NSDictionary **snapshot) {
    if (snapshot) *snapshot = nil;
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
            NSUInteger take = MIN(data.length, (NSUInteger)256);
            if (snapshot) *snapshot = @{@"kind": @"NSData", @"length": [NSString stringWithFormat:@"%lu", (unsigned long)data.length],
                @"capturedLength": @(take), @"hex": DHHexFromData([data subdataWithRange:NSMakeRange(0, take)]), @"truncated": @(take < data.length)};
            NSUInteger n = MIN(data.length, (NSUInteger)64);
            NSData *head = n ? [data subdataWithRange:NSMakeRange(0, n)] : [NSData data];
            return [NSString stringWithFormat:@"NSData(%lu) %@%@", (unsigned long)data.length,
                    DHHexFromData(head), data.length > n ? @"…" : @""];
        }
        if ([obj isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)obj;
            NSString *bounded = s.length > 1024 ? [s substringToIndex:1024] : s;
            NSData *utf8 = [bounded dataUsingEncoding:NSUTF8StringEncoding];
            if (snapshot) *snapshot = @{@"kind": @"NSString", @"length": [NSString stringWithFormat:@"%lu", (unsigned long)s.length],
                @"text": bounded, @"hex": DHHexFromData(utf8), @"capturedLength": @(utf8.length), @"truncated": @(bounded.length < s.length)};
            // 返回值常常就是整条签名/header (几百到几千字符), 截到 200 会把要看的字段切掉。
            // 这里放宽到 4000 字符, 与事件 detail 的展示上限一致; 再长的才截断。
            NSString *t = s.length > 4000 ? [[s substringToIndex:4000] stringByAppendingString:@"…"] : s;
            return [NSString stringWithFormat:@"NSString(%lu) %@", (unsigned long)s.length, t];
        }
        // 不执行任意目标对象的 description：它可能有副作用/递归/高开销。
        NSString *name = NSStringFromClass(object_getClass(obj));
        if (snapshot) *snapshot = @{@"kind": @"object", @"class": name ?: @"?", @"address": [NSString stringWithFormat:@"0x%llx", v]};
        return [NSString stringWithFormat:@"<%@: 0x%llx>", name ?: @"?", v];
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

static NSString *dh_hex_u64(uint64_t value) {
    return [NSString stringWithFormat:@"0x%llx", value];
}

static NSDictionary *dh_window(uint64_t pointer, uint64_t requested, int limit,
                                NSString *phase, NSString *reg, BOOL deferred) {
    NSUInteger budget = limit > 0 && limit <= DH_THUNK_CAPTURE_MAX ? (NSUInteger)limit : 256;
    NSUInteger want = (NSUInteger)MIN(requested, (uint64_t)budget);
    NSData *data = deferred ? nil : dh_capture_at(pointer, want);
    NSString *status = deferred ? @"deferred" : !requested ? @"empty" : data.length ? @"captured" : @"unreadable";
    return @{@"phase": phase, @"register": reg, @"address": dh_hex_u64(pointer),
        @"requestedLength": [NSString stringWithFormat:@"%llu", requested],
        @"captureLimit": @(budget), @"capturedLength": @(data.length),
        @"hex": DHHexFromData(data), @"status": status,
        @"truncated": @(!deferred && data.length < requested)};
}

static void dh_add_windows(NSMutableArray *windows, const char *spec, uint64_t *regs,
                           int budget, NSString *phase) {
    if (!spec || !spec[0]) return;
    for (NSString *part in [@(spec) componentsSeparatedByString:@","]) {
        NSString *text = [part stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (!text.length) continue;
        NSArray *fields = [text componentsSeparatedByString:@":"];
        NSString *reg = [fields[0] lowercaseString];
        if ([reg hasPrefix:@"x"]) reg = [reg substringFromIndex:1];
        int index = reg.intValue;
        NSUInteger size = fields.count > 1 ? [fields[1] integerValue] : budget > 0 ? budget : 256;
        [windows addObject:dh_window(regs[index], size, (int)size, phase,
            [NSString stringWithFormat:@"x%d", index], NO)];
    }
}

static NSDictionary *dh_function_context(DHLogEntry *e, int slot, DHCallContext call,
                                         NSString *phase) {
    DHStampEvent(e);
    NSMutableDictionary *c = [e.eventContext mutableCopy];
    c[@"kind"] = @"function"; c[@"phase"] = phase;
    c[@"callId"] = DHCallID(call.id); c[@"parentCallId"] = DHCallID(call.parent);
    [c addEntriesFromDictionary:DHFlowFields(call.async_task)];
    c[@"hookId"] = [NSString stringWithFormat:@"%@:hook:%d", DHProcessGeneration(), slot];
    c[@"slot"] = @(slot); c[@"depth"] = @(call.depth);
    c[@"mechanism"] = g_slots[slot].kind == DH_HOOK_METHOD ? @"objc" : g_slots[slot].kind == DH_HOOK_INLINE ? @"inline" : @"import";
    c[@"pairing"] = call.tracked ? @"paired" : g_dh_thunk_post[slot] ? @"context-unavailable" : @"entry-only";
    c[@"contextComplete"] = @(call.context_trusted && (!g_dh_thunk_post[slot] || call.tracked));
    c[@"parentValidation"]=call.context_trusted?@"verified-or-no-active-scope":@"unverified-unwind; associations suppressed";
    c[@"targetIdentity"] = g_slot_targets[slot] ?: @{};
    if ([phase isEqualToString:@"leave"] && call.started_ns)
        c[@"durationNs"] = [NSString stringWithFormat:@"%llu", DHMonotonicNS() - call.started_ns];
    return c;
}

// token 存在每次汇编帧中。递归、嵌套、同一线程复用均不靠文本/TID 猜配对。
uint64_t dh_thunk_handler(uint64_t slot, uint64_t *gpr, uint64_t caller_sp, uint64_t lr, const DHCPUContext *full) {
    int savedErrno=errno;
    if (slot >= DH_THUNK_COUNT) return 0;
    dh_slot_t *s = &g_slots[slot];
    if (g_in_thunk) {if(g_dh_thunk_post[slot])atomic_fetch_add(&g_slot_inflight[slot],1);return 0;}
    int savedInternal=dh_in_hook;dh_in_hook=1;
    DHRawStack captureStack;dh_unwind_capture(full,(uint64_t)(s->target ?: g_dh_thunk_orig[slot]),&captureStack);
    DHFlowCheck(&captureStack);
    uint64_t guard=0;
    if (g_dh_thunk_post[slot]) {atomic_fetch_add_explicit(&g_slot_inflight[slot],1,memory_order_relaxed);guard=DHFlowGuardBegin((int)slot,caller_sp);}
    if (!atomic_load_explicit(&s->enabled,memory_order_acquire)) {dh_in_hook=savedInternal;errno=savedErrno;return guard;}
    uint64_t hits = atomic_fetch_add_explicit(&s->hits, 1, memory_order_relaxed) + 1;
    g_in_thunk = 1;
    if ([DHLogStore shared].paused) { dh_in_hook=savedInternal; g_in_thunk = 0; errno=savedErrno; return guard; }
    DHCallContext call = dh_call_begin(g_dh_thunk_post[slot], DHMonotonicNS());
    if(guard)DHFlowGuardBind(guard,&call);
    @autoreleasepool {
        const dh_hook_options *o = &g_slot_options[slot];
        DHLogEntry *e = [DHLogEntry new];
        e.category = DHCategoryOther;
        e.algorithm = s->kind == DH_HOOK_METHOD ? @"objc-hook" : s->kind == DH_HOOK_INLINE ? @"inline-hook" : @"import-hook";
        e.operation = @(s->name);
        e.eventContext = dh_function_context(e, (int)slot, call, @"entry");
        NSMutableDictionary *regs = [NSMutableDictionary dictionary];
        for (int i = 0; i < 9; i++) regs[[NSString stringWithFormat:@"x%d", i]] = dh_hex_u64(gpr[i]);
        NSMutableArray *args = [NSMutableArray array], *memory = [NSMutableArray array];
        NSMutableString *detail = [NSMutableString stringWithFormat:@"slot=%llu hits=%llu\ncaller_lr=0x%llx caller_sp=0x%llx\n", slot, hits, lr, caller_sp];
        unsigned registerCount = s->kind == DH_HOOK_METHOD ? 6 : 8;
        unsigned firstRegister = s->kind == DH_HOOK_METHOD ? 2 : 0;
        uint8_t stack[256]; vm_size_t got = 0;
        if (s->method_simple_gpr && s->method_stack_bytes)
            vm_read_overwrite(mach_task_self(), (vm_address_t)caller_sp, s->method_stack_bytes, (vm_address_t)stack, &got);
        if (s->method_simple_gpr) {
            for (unsigned i = 0; i < s->method_arg_count && i < 32; i++) {
                const char *type = s->argument_types[i];
                unsigned size = dh_method_arg_size(type); uint64_t value = 0;
                BOOL readable = YES;
                NSDictionary *location;
                if (i < registerCount) {
                    value = gpr[i + firstRegister];
                    location = @{@"kind": @"register", @"name": [NSString stringWithFormat:@"x%u", i + firstRegister]};
                } else {
                    unsigned offset = s->method_stack_args[i - registerCount].offset;
                    readable = size && offset + size <= got;
                    if (readable) memcpy(&value, stack + offset, size);
                    location = @{@"kind": @"stack", @"offset": @(offset), @"size": @(size)};
                }
                if (size && size < 8) value &= (1ULL << (size * 8)) - 1;
                NSMutableDictionary *arg = [@{@"index": @(i), @"type": @(type), @"location": location,
                    @"status": readable ? @"captured" : @"unreadable"} mutableCopy];
                if (readable) {
                    arg[@"value"] = dh_hex_u64(value);
                    [detail appendFormat:@"arg%u=%@\n", i, arg[@"value"]];
                    if (o->describe_args && dh_method_arg_type(type) == 2) {
                        NSDictionary *object = nil;
                        NSString *description = dh_describe_arg(value, &object);
                        if (object) arg[@"object"] = object;
                        if (description.length) [detail appendFormat:@"  arg%u = %@\n", i, description];
                    }
                }
                [args addObject:arg];
            }
        }
        if (o->ptr_arg >= 0) {
            uint64_t requested = o->len_arg >= 0 ? gpr[o->len_arg] : (uint64_t)o->max_bytes;
            NSDictionary *window = dh_window(gpr[o->ptr_arg], requested, o->max_bytes,
                o->capture_after ? @"leave" : @"entry", [NSString stringWithFormat:@"x%d", o->ptr_arg], o->capture_after);
            [memory addObject:window];
            if (!o->capture_after) e.input = DHDataFromHex(window[@"hex"]);
            else [detail appendString:@"output capture deferred until return\n"];
        }
        dh_add_windows(memory, o->capture_multi, gpr, o->max_bytes, @"entry");
        e.eventPayload = @{@"rawRegisters": regs, @"arguments": args, @"memory": memory,
            @"caller": @{@"lr": dh_hex_u64(lr), @"sp": dh_hex_u64(caller_sp)},
            @"stack":DHStackDictionary(&captureStack),
            @"abi": dh_thunk_metadata((int)slot)[@"abi"]};
        e.detail = detail;
        e.callStack = [NSString stringWithFormat:@"Direct caller (unsymbolicated): %@",dh_hex_u64(lr)];
        e.timestamp = DHTimestampNow();
        [[DHLogStore shared] append:e];
    }
    dh_in_hook=savedInternal; g_in_thunk = 0;
    errno=savedErrno;return call.id;
}

void dh_thunk_post_handler(uint64_t slot, uint64_t *regs, uint64_t orig, uint64_t real_lr,
                           uint64_t *entry_regs, uint64_t token) {
    int savedErrno=errno;
    (void)orig;
    if (slot >= DH_THUNK_COUNT) return;
    DHFlowGuardEnd(token);
    atomic_fetch_sub_explicit(&g_slot_inflight[slot], 1, memory_order_relaxed);
    DHCallContext call = dh_call_end(token); // 软停/暂停后也必须弹出，不能污染后续调用。
    dh_slot_t *s = &g_slots[slot];
    if (!token || (token>>63) || !atomic_load_explicit(&s->enabled, memory_order_acquire) || g_in_thunk) {errno=savedErrno;return;}
    g_in_thunk = 1;
    int savedInternal=dh_in_hook; dh_in_hook=1;
    @autoreleasepool {
        const dh_hook_options *o = &g_slot_options[slot];
        DHLogEntry *e = [DHLogEntry new]; e.category = DHCategoryOther;
        e.algorithm = s->kind == DH_HOOK_METHOD ? @"objc-hook" : s->kind == DH_HOOK_INLINE ? @"inline-hook" : @"import-hook";
        e.operation = @(s->name);
        e.eventContext = dh_function_context(e, (int)slot, call, @"leave");
        NSMutableArray *memory = [NSMutableArray array];
        NSMutableDictionary *value = [@{@"type": @(s->return_type), @"requested": @(o->capture_return),
            @"available": @(o->capture_return && s->return_type[0] != 'v')} mutableCopy];
        NSMutableString *detail = [NSMutableString stringWithFormat:@"slot=%llu return\nx0(ret)=0x%llx x1=0x%llx", slot, regs[0], regs[1]];
        if (o->capture_return && s->return_type[0] != 'v') {
            value[@"value"] = dh_hex_u64(regs[0]);
            if (dh_method_arg_type(s->return_type) == 2) {
                NSDictionary *object = nil;
                NSString *description = dh_describe_arg(regs[0], &object);
                if (object) value[@"object"] = object;
                if (description.length) {
                    e.input = [description dataUsingEncoding:NSUTF8StringEncoding];
                    [detail appendFormat:@"\n  ret = %@", description];
                }
            }
        }
        if (o->capture_after) {
            uint64_t requested = o->len_arg >= 0 ? entry_regs[o->len_arg] : (uint64_t)o->max_bytes;
            NSDictionary *window = dh_window(entry_regs[o->ptr_arg], requested, o->max_bytes,
                @"leave", [NSString stringWithFormat:@"x%d", o->ptr_arg], NO);
            [memory addObject:window]; e.output = DHDataFromHex(window[@"hex"]);
        }
        dh_add_windows(memory, o->capture_ret_multi, regs, o->max_bytes, @"leave");
        e.eventPayload = @{@"rawRegisters": @{@"x0": dh_hex_u64(regs[0]), @"x1": dh_hex_u64(regs[1])},
            @"returnValue": value, @"memory": memory, @"caller": @{@"lr": dh_hex_u64(real_lr)},
            @"abi": dh_thunk_metadata((int)slot)[@"abi"]};
        e.detail = detail;
        e.callStack = [NSString stringWithFormat:@"Direct caller (unsymbolicated): %@",dh_hex_u64(real_lr)];
        e.timestamp = DHTimestampNow();
        [[DHLogStore shared] append:e];
    }
    dh_in_hook=savedInternal; g_in_thunk = 0;errno=savedErrno;
}

void dh_thunk_abandon(unsigned slot,uint64_t token,const char *reason,const DHCallContext *snapshot) {
    if(slot>=DH_THUNK_COUNT)return;
    atomic_fetch_sub(&g_slot_inflight[slot],1);DHCallContext call=dh_call_end(token);
    if(!call.tracked && snapshot && snapshot->id==token)call=*snapshot;
    if(!token || (token>>63))return;
    int saved=dh_in_hook;dh_in_hook=1;
    @autoreleasepool {
        DHLogEntry *e=[DHLogEntry new];e.category=DHCategoryOther;e.algorithm=@"hook-state";e.operation=@(g_slots[slot].name);
        NSMutableDictionary *context=[dh_function_context(e,(int)slot,call,@"aborted") mutableCopy];context[@"pairing"]=@"aborted";e.eventContext=context;
        e.eventPayload=@{@"reason":@(reason),@"returnValue":@{@"available":@NO},@"detection":!strcmp(reason,"thread-exit")?@"pthread-key exit snapshot":@"complete native stack no longer contains the owned post bridge"};
        [[DHLogStore shared] append:e];
    }
    dh_in_hook=saved;
}

// ---- 安装 / 关闭 / 枚举 ----

static int dh_alloc_slot(void) {
    int i = atomic_fetch_add_explicit(&g_next_slot, 1, memory_order_relaxed);
    if (i >= DH_THUNK_COUNT) { atomic_fetch_sub_explicit(&g_next_slot, 1, memory_order_relaxed); return -1; }
    return i;
}

int dh_thunk_install_import(const char *symbol, const char *label) {
    if (!DH_THUNK_ARM64 || !symbol || !symbol[0]) return -1;
    if (strlen(symbol) >= sizeof(g_slots[0].import_symbol) || dh_unsafe_runtime_symbol(symbol)) return -6;
    // Resolve before publishing a persistent fishhook registration. A missing/data symbol
    // must not leave a future-image callback pointing at a recycled thunk slot.
    void *resolved = dlsym(RTLD_DEFAULT, symbol);
    if (!resolved || !dh_addr_is_executable((uint64_t)(uintptr_t)ptrauth_strip(resolved, ptrauth_key_function_pointer))) return -2;
    pthread_mutex_lock(&g_install_lock);
    if(DHFlowOwnsImport(symbol)) {pthread_mutex_unlock(&g_install_lock);return -6;}
    // fishhook 按符号改 GOT: 同一符号装第二次会把 GOT 指向新槽位, 旧槽位从此 0 命中
    // (它还留在 list_hooks 里, 看起来像「装好了却不生效」)。重复安装直接拒绝, 让调用方复用。
    {
        int n = atomic_load_explicit(&g_next_slot, memory_order_relaxed);
        if (n > DH_THUNK_COUNT) n = DH_THUNK_COUNT;
        for (int i = 0; i < n; i++) {
            dh_slot_t *o = &g_slots[i];
            if (!o->used || o->kind != DH_HOOK_IMPORT) continue;
            if (strcmp(o->import_symbol, symbol)) continue;
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
    snprintf(s->import_symbol, sizeof(s->import_symbol), "%s", symbol);
    s->used = 1;
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    atomic_store_explicit(&s->capture_return, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_after, 0, memory_order_relaxed);
    s->capture_multi[0] = '\0';
    atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
    s->capture_ret_multi[0] = 0;
    atomic_store_explicit(&s->capture_ret_multi_ready, 0, memory_order_release);
    g_dh_thunk_post[slot] = 0;
    // One immutable forwarding target for all present/future imports. Per-image
    // interposer chaining is not supported; report this policy in hook metadata.
    g_dh_thunk_orig[slot] = ptrauth_strip(resolved, ptrauth_key_function_pointer);
    dh_prepare_slot_options(slot);
    g_slot_targets[slot] = DHTargetIdentity(g_dh_thunk_orig[slot]);
    atomic_store_explicit(&g_slot_published[slot], 1, memory_order_release);
    struct rebinding rb = { s->import_symbol, dh_slot_addr(slot), NULL };
    if (rebind_symbols(&rb, 1) < 0) {
        // fishhook returns failure only before the registration is published.
        atomic_store_explicit(&g_slot_published[slot], 0, memory_order_release);
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

int dh_thunk_method_post_supported(const char *className, const char *selector, int classMethod) {
    if (!className || !selector) return -1;
    Class cls = objc_getClass(className);
    if (!cls) return -1;
    SEL sel = sel_registerName(selector);
    Method m = nil;
    if (classMethod) {
        Class meta = object_getClass((id)cls);
        if (meta) m = class_getInstanceMethod(meta, sel);
        if (!m) m = class_getClassMethod(cls, sel);
    } else {
        m = class_getInstanceMethod(cls, sel);
    }
    if (!m) return -1;
    unsigned int count = method_getNumberOfArguments(m);
    if (count > 34) return 0; // self/_cmd + 有界 32 个固定 GPR 参数
    for (unsigned int i = 2; i < count; i++) {
        char *type = method_copyArgumentType(m, i);
        int kind = dh_method_arg_type(type);
        free(type);
        if (!kind) return 0;
    }
    char *ret = method_copyReturnType(m);
    int retOK = ret && (ret[0] == 'v' || dh_method_arg_type(ret));
    free(ret);
    if (!retOK) return 0;
    return 1;
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
        // 已退休槽位可能仍有在途调用，不能重写其配置/身份。新安装分配新槽位。
    }
    int slot = dh_alloc_slot();
    if (slot < 0) { pthread_mutex_unlock(&g_install_lock); return -1; }
    dh_slot_t *s = &g_slots[slot];
    snprintf(s->name, sizeof(s->name), "%c[%s %s]", classMethod ? '+' : '-', className, selector);
    s->kind = DH_HOOK_METHOD;
    s->used = 1;
    s->method = (void *)m;
    unsigned int numberOfArgs = method_getNumberOfArguments(m);
    s->method_arg_count = numberOfArgs >= 2 ? numberOfArgs - 2 : 0;
    s->method_simple_gpr = 1;
    s->method_object_gprs = 0;
    s->method_stack_bytes = 0;
    char *returnType = method_copyReturnType(m);
    strlcpy(s->return_type, returnType ?: "?", sizeof(s->return_type));
    free(returnType);
    memset(s->method_stack_args, 0, sizeof(s->method_stack_args));
    for (unsigned int ai = 0; ai < s->method_arg_count; ai++) {
        char *type = method_copyArgumentType(m, ai + 2);
        if (ai < 32) strlcpy(s->argument_types[ai], type ?: "?", sizeof(s->argument_types[ai]));
        int kind = dh_method_arg_type(type);
        unsigned int size = dh_method_arg_size(type);
        free(type);
        if (!kind) s->method_simple_gpr = 0;
        if (kind == 2 && ai < 6) s->method_object_gprs |= (uint8_t)(1u << (ai + 2));
        if (ai >= 6 && ai < 32 && size) {
            unsigned int offset = dh_method_stack_offset(s->method_stack_bytes, size);
            if (offset <= 256 - size) {
                s->method_stack_args[ai - 6].offset = (uint16_t)offset;
                s->method_stack_args[ai - 6].size = (uint8_t)size;
                s->method_stack_args[ai - 6].object = kind == 2;
                s->method_stack_bytes = offset + size;
            }
        }
    }
    s->target = NULL;
    s->saved_len = 0;
    atomic_store_explicit(&s->retired, 0, memory_order_relaxed);
    // method 路径也要清 capture 配置: 槽位可能被 abort/回退复用, 残留的规格会让新 hook 抓错寄存器。
    atomic_store_explicit(&s->capture_ptr_arg, -1, memory_order_relaxed);
    atomic_store_explicit(&s->capture_len_arg, -1, memory_order_relaxed);
    atomic_store_explicit(&s->capture_max_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_return, 0, memory_order_relaxed);
    atomic_store_explicit(&s->capture_after, 0, memory_order_relaxed);
    s->capture_multi[0] = 0;
    atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
    s->capture_ret_multi[0] = 0;
    atomic_store_explicit(&s->capture_ret_multi_ready, 0, memory_order_release);
    g_dh_thunk_post[slot] = 0;
    g_dh_thunk_orig[slot] = (void *)method_getImplementation(m);
    dh_prepare_slot_options(slot);
    atomic_store_explicit(&g_slot_published[slot], 1, memory_order_release);
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    method_setImplementation(m, (IMP)dh_slot_addr(slot));
    pthread_mutex_unlock(&g_install_lock);
    return slot;
}

// ---- 内联 hook (Dobby) ----
// 复用同一张 thunk 表：DobbyHook 把目标函数序言改跳到 thunk[slot]，thunk 记录后尾调用
// DobbyHook 返回的原函数蹦床。参数寄存器/栈保持原样，所以对目标透明（入口观测）。

static BOOL dh_addr_is_executable(uint64_t addr) {return dh_vm_address_executable(addr);}

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
    target = ptrauth_strip(target, ptrauth_key_function_pointer);
    if (!dh_addr_is_executable((uint64_t)(uintptr_t)target)) {
        if (err && errsz) snprintf(err, errsz, "resolved target is not executable code");
        return -2;
    }
    Dl_info identity = {0};
    if (dladdr(target, &identity) && dh_unsafe_runtime_symbol(identity.dli_sname)) {
        if (err && errsz) snprintf(err, errsz, "refusing allocator/runtime hook by resolved address");
        return -4;
    }

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
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "retired inline configurations are immutable; restart the target before installing again");
        return -5;
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
    s->capture_ret_multi[0] = 0;
    atomic_store_explicit(&s->capture_ret_multi_ready, 0, memory_order_release);
    g_dh_thunk_post[slot] = 0;
    g_dh_thunk_orig[slot] = NULL;
    atomic_store_explicit(&s->enabled, 0, memory_order_release);

    dh_prepare_slot_options(slot);

    int rc = DobbyHookWithContext(target, (uint8_t *)dh_slot_addr(slot)+4,
                       (void **)&g_dh_thunk_orig[slot]);
    if (g_dh_thunk_orig[slot])
        __atomic_store_n(&g_dh_thunk_orig[slot], ptrauth_strip(g_dh_thunk_orig[slot], ptrauth_key_function_pointer), __ATOMIC_RELEASE);
    if (rc != 0 || g_dh_thunk_orig[slot] == NULL) {
        if (g_dh_thunk_orig[slot]) {
            // 后端已发布 original，不能证明没有在途跳转；失败槽位也不能复用。
            atomic_store(&g_slot_published[slot],1);
            pthread_mutex_unlock(&g_install_lock);
            if (err && errsz) snprintf(err,errsz,"Dobby activation failed after original publication; disabled slot %d retained, restart target",slot);
            return -4;
        }
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
    atomic_store_explicit(&g_slot_published[slot], 1, memory_order_release);
    atomic_store_explicit(&s->enabled, 1, memory_order_release);
    pthread_mutex_unlock(&g_install_lock);
    return slot;
#endif
}

const char *dh_thunk_inline_backend(void) {
#if DH_HAVE_INLINE
    return "dobby";
#else
    return "unavailable(not-linked)";
#endif
}

int dh_thunk_set_describe(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;   // import hook 走「可打印 C 字符串」判定, method hook 走对象反引用
    atomic_store_explicit(&s->describe_args, on ? 1 : 0, memory_order_relaxed);
    return 0;
}

int dh_thunk_set_capture(int slot, int ptr_arg, int len_arg, int max_bytes) {    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;
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


static void dh_thunk_sync_post(int slot);   // 统一重算 post 标记, 定义见下

int dh_thunk_set_return(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) return -1;
    if (on && s->kind == DH_HOOK_METHOD && (!s->method_simple_gpr || s->method_arg_count > 32)) return -1;
    // 先写槽位字段再发布汇编可见的标记位 (release), 保证 handler 看到 1 时字段已就绪。
    atomic_store_explicit(&s->capture_return, on ? 1 : 0, memory_order_relaxed);
    dh_thunk_sync_post(slot);
    return 0;
}

// capture_after=1: capture_ptr_arg 指向的是「调用之后才写好的输出缓冲」(CCHmac 的 digest 出参、
// CCCrypt 的密文出参)。这种槽位必须走 post 路径, 否则入口抓到的是未初始化内存。
int dh_thunk_set_capture_after(int slot, int on) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) return -1;
    if (on && s->kind == DH_HOOK_METHOD && (!s->method_simple_gpr || s->method_arg_count > 32)) return -1;
    // 只开 after 而不配 capture_memory 是悬空语义(没有 ptr_arg 可读), 直接拒绝而不是让它静默什么都不做。
    if (on && atomic_load_explicit(&s->capture_ptr_arg, memory_order_acquire) < 0) return -2;
    atomic_store_explicit(&s->capture_after, on ? 1 : 0, memory_order_relaxed);
    // 输出缓冲只有返回后才有内容, 必须走 post 路径 —— 由 sync_post 统一决定
    dh_thunk_sync_post(slot);
    return 0;
}
// 多窗口抓取: 一次 hook 同时观察多个寄存器指向的内存。
// 一个 inline 目标只能装一个 hook，没有这个能力就只能卸了重装换寄存器；
// 而 inline 槽位分配后不回收，换一次寄存器就要重启目标进程一次。
// 纯语法校验（不改任何状态）。
// 为什么单独抽出来: 安装 hook 时槽位先分配、参数后校验。如果校验失败才去「撤销安装」,
// 就必须把目标上已经改好的跳转/IMP/GOT 全部回滚 —— 漏一步就是进程级内存安全事件
// (import 的 GOT 仍指向 thunk 而 orig 被清空 → 下一次调用直接跳 NULL)。
// 所以改成「分配槽位之前先把参数校验完」, 校验不过就根本不装。
// 返回 0 = 合法; -1 = 语法错; -2 = 超长。
int dh_thunk_validate_capture_multi(const char *spec) {
    if (!spec || !spec[0]) return 0;
    if (strnlen(spec, 96) >= 96) return -2;
    const char *p = spec;
    int tokens = 0;          // 必须至少解析出一个窗口。
    // 只含分隔符的规格（","、" "、", ,"）在下面会被全部跳过、循环正常结束，
    // 于是 setter 打开 post 路径却一条窗口都产不出来 —— 永久慢路径 + 空输出。
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
            unsigned int size = 0;
            while (*p >= '0' && *p <= '9') {
                if (size > DH_THUNK_CAPTURE_MAX / 10) return -1;
                size = size * 10 + (unsigned int)(*p++ - '0');
                if (size > DH_THUNK_CAPTURE_MAX) return -1;
            }
            if (!size) return -1;
        }
        if (*p && *p != ',' && *p != ' ') return -1;
        tokens++;
        if (tokens > 9) return -1;
    }
    return tokens > 0 ? 0 : -1;
}

// 统一重算 post 标记: 三个能力(capture_return / capture_after / capture_ret_multi)
// 都需要 post 路径(多留一层栈帧到原函数返回)。任一开着就必须走 post, 全关才恢复尾调用。
// 为什么必须集中算: 各 setter 单独置位会导致「关掉 A 却把 B 需要的 post 也关了」,
// 或者「关掉 ret_multi 后 post 永久留着」—— 后者会让槽位再也回不到尾调用,
// 而 inline 槽位不回收, 用户只能重启目标进程。
static void dh_thunk_sync_post(int slot) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return;
    dh_slot_t *s = &g_slots[slot];
    // ret_multi 的「是否有效」看串本身, 不看版本号: 版本号是单调计数器,
    // 清空后也不会回到 0(避免 ABA), 所以 != 0 只说明「设过」而不是「现在开着」。
    int retOn = atomic_load_explicit(&s->capture_ret_multi_ready, memory_order_acquire) != 0
             && s->capture_ret_multi[0] != 0;
    int need = atomic_load_explicit(&s->capture_return, memory_order_relaxed)
            || atomic_load_explicit(&s->capture_after, memory_order_relaxed)
            || retOn;
    g_dh_thunk_post[slot] = need ? 1 : 0;
}

int dh_thunk_set_capture_multi(int slot, const char *spec) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;
    int v = dh_thunk_validate_capture_multi(spec);
    if (v != 0) return v;
    if (!spec || !spec[0]) {
        atomic_store_explicit(&s->capture_multi_ready, 0, memory_order_release);
        s->capture_multi[0] = 0;
        return 0;
    }
    // 用 seqlock 语义而不是 check-then-act: 写端把 ready 从 1 推到 2 (写作中),
    // 拷完再推到 1; 读端读两次 ready, 前后都是 1 且相等才认为读到的是完整串。
    // 原来的「清 0 → 写 → 置 1」在「读端已看到 1、正要去读」时挡不住撕裂。
    // 版本号语义: 写端每次 +2 (稳定值恒为偶数, 写作中为奇数)。
    // 只比较「值是否相同」检测不到同值重写(1→2→1 读端首尾都是 1), 用递增版本号才行。
    atomic_fetch_add_explicit(&s->capture_multi_ready, 1, memory_order_acq_rel);
    strlcpy(s->capture_multi, spec, sizeof(s->capture_multi));
    atomic_fetch_add_explicit(&s->capture_multi_ready, 1, memory_order_release);
    return 0;
}

// 返回值寄存器的多窗口 (post 路径)。用于「函数返回 (status, buffer)」这种 ABI:
// 缓冲在返回后可能立刻被释放, 只能在这里读。
//
// 只接受 x0/x1: AAPCS64 只有这两个寄存器承载整数/指针返回值。post 路径把返回的
// x0/x1 写回快照, 但 x2..x8 仍是**入口**值 —— 允许它们会让 `ret x5 = ...` 这种
// 把入参渲染成返回值的误导性证据出现在 detail 里。
static int dh_validate_ret_regs(const char *spec) {
    if (!spec) return 0;
    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        if (*p == 'x' || *p == 'X') p++;
        if (*p != '0' && *p != '1') return -1;    // 只有 x0/x1 是返回值
        p++;
        if (*p == ':') {
            p++;
            if (!(*p >= '0' && *p <= '9')) return -1;
            while (*p >= '0' && *p <= '9') p++;
        }
        if (*p && *p != ',' && *p != ' ') return -1;
    }
    return 0;
}

int dh_thunk_validate_capture_ret_multi(const char *spec) {
    int result = dh_thunk_validate_capture_multi(spec);
    return result ? result : dh_validate_ret_regs(spec);
}

int dh_thunk_set_capture_ret_multi(int slot, const char *spec) {
    if (slot < 0 || slot >= DH_THUNK_COUNT) return -1;
    dh_slot_t *s = &g_slots[slot];
    if (!s->used) return -1;
    if (atomic_load_explicit(&g_slot_published[slot], memory_order_acquire)) return -3;
    if (spec && spec[0] && s->kind == DH_HOOK_METHOD &&
        (!s->method_simple_gpr || s->method_arg_count > 32)) return -1;
    int v = dh_thunk_validate_capture_multi(spec);
    if (v != 0) return v;
    v = dh_validate_ret_regs(spec);
    if (v != 0) return v;
    if (!spec || !spec[0]) {
        // 清空也要保持版本号单调: 直接把 ready 按回 0 会造出 2 → 0 → 2 的 ABA,
        // 读端首尾都读到 2 会判定一致, 可能用一条撕裂的规格。
        // 所以清空 = 再推进两次, 并把「是否有效」交给 ret_multi[0] == 0 判断。
        atomic_fetch_add_explicit(&s->capture_ret_multi_ready, 1, memory_order_acq_rel);
        s->capture_ret_multi[0] = 0;
        atomic_fetch_add_explicit(&s->capture_ret_multi_ready, 1, memory_order_release);
        dh_thunk_sync_post(slot);
        return 0;
    }
    atomic_fetch_add_explicit(&s->capture_ret_multi_ready, 1, memory_order_acq_rel);
    strlcpy(s->capture_ret_multi, spec, sizeof(s->capture_ret_multi));
    atomic_fetch_add_explicit(&s->capture_ret_multi_ready, 1, memory_order_release);
    dh_thunk_sync_post(slot);
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
    if (!hard) {   // 软停: 停止记录, patch 保留
        atomic_store_explicit(&s->enabled, 0, memory_order_release);
        pthread_mutex_unlock(&g_install_lock);
        return 0;
    }
    if (atomic_load_explicit(&s->retired, memory_order_relaxed)) {
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "slot %d is already hard-unhooked (retired)", slot);
        return 0;
    }
    if (s->kind == DH_HOOK_INLINE) {
        pthread_mutex_unlock(&g_install_lock);
        if (err) snprintf(err, errsz, "hard inline unhook requires thread quiescence; state unchanged, use soft unhook or restart target");
        return -5;
    }
    if (s->kind == DH_HOOK_METHOD) {
        Method m = (Method)s->method;
        IMP orig = (IMP)g_dh_thunk_orig[slot];
        if (!m || !orig) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz, "slot %d has no original IMP", slot);
            return -5;
        }
        if (method_getImplementation(m) != (IMP)dh_slot_addr(slot)) {
            pthread_mutex_unlock(&g_install_lock);
            if (err) snprintf(err, errsz, "method IMP is owned by another patch; refusing to overwrite it");
            return -5;
        }
        atomic_store_explicit(&s->enabled, 0, memory_order_release);
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
        // capture_multi 回填前必须确认 ready: 否则可能报出一个用户从没设过、或写了一半的规格。
        int cmv = atomic_load_explicit(&g_slots[i].capture_multi_ready, memory_order_acquire);
        if (cmv != 0 && !(cmv & 1))
            strlcpy(out[n].capture_multi, g_slots[i].capture_multi, sizeof(out[n].capture_multi));
        else
            out[n].capture_multi[0] = 0;
        int crv = atomic_load_explicit(&g_slots[i].capture_ret_multi_ready, memory_order_acquire);
        if (crv != 0 && !(crv & 1))
            strlcpy(out[n].capture_ret_multi, g_slots[i].capture_ret_multi, sizeof(out[n].capture_ret_multi));
        else
            out[n].capture_ret_multi[0] = 0;
        out[n].capture_ptr_arg   = atomic_load_explicit(&g_slots[i].capture_ptr_arg, memory_order_acquire);
        out[n].capture_len_arg   = atomic_load_explicit(&g_slots[i].capture_len_arg, memory_order_relaxed);
        out[n].capture_max_bytes = atomic_load_explicit(&g_slots[i].capture_max_bytes, memory_order_relaxed);
        out[n].capture_return   = atomic_load_explicit(&g_slots[i].capture_return, memory_order_relaxed);
        out[n].capture_after    = atomic_load_explicit(&g_slots[i].capture_after, memory_order_relaxed);
        out[n].method_arg_count = g_slots[i].method_arg_count;
        out[n].method_simple_gpr = g_slots[i].method_simple_gpr;
        out[n].method_stack_bytes = g_slots[i].method_stack_bytes;
        n++;
    }
    return n;   // 实际写入条数 (跳过被作废的槽)
}

int dh_thunk_live_target(int slot,uint64_t *target,uint64_t *original) {
    int ok=0;pthread_mutex_lock(&g_install_lock);
    if (slot>=0 && slot<DH_THUNK_COUNT && g_slots[slot].used &&
        g_slots[slot].kind==DH_HOOK_INLINE && atomic_load(&g_slots[slot].enabled) && atomic_load(&g_slot_published[slot])) {
        *target=(uint64_t)g_slots[slot].target;*original=(uint64_t)g_dh_thunk_orig[slot];ok=1;
    }
    pthread_mutex_unlock(&g_install_lock);return ok;
}
void dh_thunk_live_post(unsigned slot,const DHCPUContext *result,const DHCPUContext *entry,uint64_t token,uint64_t original) {
    if (slot<DH_THUNK_COUNT && g_dh_thunk_post[slot])
        dh_thunk_post_handler(slot,(uint64_t *)result->x,original,entry->x[30],(uint64_t *)entry->x,token);
}
