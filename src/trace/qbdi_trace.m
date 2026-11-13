// qbdi_trace.m — 见 qbdi_trace.h
//
// 设计边界（第一切片）：
//   * 一次性 VM + 显式函数调用：replay 语义，目标函数会被真实执行一次；有副作用。
//   * 只按 x0-x7 传整数/指针参数；栈参数、浮点参数、结构体返回不做保证。
//   * 指令/时间双预算，回调里达到预算返回 QBDI_STOP（不因为预算而伪装成"执行完成"）。
//   * 不常驻、不跨线程：记录完立即 terminateVM；调用线程阻塞到函数返回或预算触发。

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <string.h>

#import "qbdi_trace.h"

#ifndef DH_HAVE_QBDI
#define DH_HAVE_QBDI 0
#endif

#if DH_HAVE_QBDI
#include "QBDI/VM_C.h"
#include "QBDI/Callback.h"
#include "QBDI/InstAnalysis.h"
#include "QBDI/Memory.h"
#endif

static uint64_t dh_trace_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#if DH_HAVE_QBDI

typedef struct {
    NSMutableArray *insns;
    int             max;
    int             count;
    uint64_t        deadline;
    BOOL            truncated;
    const char     *stop;
} DHTraceCtx;

static VMAction dh_trace_cb(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)gpr; (void)fpr;
    DHTraceCtx *c = (DHTraceCtx *)data;
    if (c->count >= c->max) {
        c->truncated = YES;
        c->stop = "instruction-limit";
        return QBDI_STOP;
    }
    const InstAnalysis *a = qbdi_getInstAnalysis(
        vm, (AnalysisType)(QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY));
    if (a) {
        [c->insns addObject:@{
            @"pc":       @(a->address),
            @"size":     @(a->instSize),
            @"mnemonic": a->mnemonic ? @(a->mnemonic) : @"",
            @"disasm":   a->disassembly ? @(a->disassembly) : @"",
        }];
    }
    c->count++;
    if (dh_trace_now_ns() > c->deadline) {
        c->stop = "time-limit";
        return QBDI_STOP;
    }
    return QBDI_CONTINUE;
}

static void *dh_trace_resolve(NSString *module, NSString *symbol, uint64_t addr, NSString **err) {
    if (addr) return (void *)(uintptr_t)addr;
    if (symbol.length == 0) {
        if (err) *err = @"symbol or addr required";
        return NULL;
    }
    void *handle = NULL;
    if (module.length) {
        const char *prefixes[3] = { "", "/var/jb/usr/lib/", "/usr/lib/" };
        for (int i = 0; i < 3 && !handle; i++) {
            NSString *path = [NSString stringWithFormat:@"%s%@", prefixes[i], module];
            handle = dlopen(path.fileSystemRepresentation, RTLD_LAZY | RTLD_NOLOAD);
            if (!handle) handle = dlopen(path.fileSystemRepresentation, RTLD_LAZY);
        }
        if (!handle && err) {
            *err = [NSString stringWithFormat:@"dlopen(%@) failed: %s", module,
                    dlerror() ?: "unknown"];
        }
    } else {
        handle = dlopen(NULL, RTLD_LAZY);
    }
    void *target = handle ? dlsym(handle, symbol.UTF8String) : NULL;
    if (!target) target = dlsym(RTLD_DEFAULT, symbol.UTF8String);
    if (!target && ![symbol hasPrefix:@"_"]) {
        NSString *u = [@"_" stringByAppendingString:symbol];
        target = dlsym(RTLD_DEFAULT, u.UTF8String);
    }
    if (!target && err) {
        *err = [NSString stringWithFormat:@"symbol %@ not found%@%@", symbol,
                module.length ? @" in " : @"", module.length ? module : @""];
    }
    return target;
}

static BOOL dh_trace_call(VMInstanceRef vm, rword target, const uint64_t *a, int argc, rword *ret) {
    switch (argc) {
        case 0: return qbdi_call(vm, ret, target, 0);
        case 1: return qbdi_call(vm, ret, target, 1, (rword)a[0]);
        case 2: return qbdi_call(vm, ret, target, 2, (rword)a[0], (rword)a[1]);
        case 3: return qbdi_call(vm, ret, target, 3, (rword)a[0], (rword)a[1], (rword)a[2]);
        case 4: return qbdi_call(vm, ret, target, 4, (rword)a[0], (rword)a[1], (rword)a[2], (rword)a[3]);
        case 5: return qbdi_call(vm, ret, target, 5, (rword)a[0], (rword)a[1], (rword)a[2], (rword)a[3], (rword)a[4]);
        case 6: return qbdi_call(vm, ret, target, 6, (rword)a[0], (rword)a[1], (rword)a[2], (rword)a[3], (rword)a[4], (rword)a[5]);
        case 7: return qbdi_call(vm, ret, target, 7, (rword)a[0], (rword)a[1], (rword)a[2], (rword)a[3], (rword)a[4], (rword)a[5], (rword)a[6]);
        case 8: return qbdi_call(vm, ret, target, 8, (rword)a[0], (rword)a[1], (rword)a[2], (rword)a[3], (rword)a[4], (rword)a[5], (rword)a[6], (rword)a[7]);
        default: return false;
    }
}

#endif // DH_HAVE_QBDI

BOOL DHQBDIAvailable(void) {
#if DH_HAVE_QBDI
    return YES;
#else
    return NO;
#endif
}

NSDictionary *DHQBDITraceFunction(NSString *module, NSString *symbol, uint64_t addr,
                                  const uint64_t *args, int argc,
                                  int maxInsns, int maxMs) {
#if !DH_HAVE_QBDI
    (void)module; (void)symbol; (void)addr; (void)args; (void)argc; (void)maxInsns; (void)maxMs;
    return @{@"ok": @NO,
             @"error": @"QBDI is not linked in this slice (vendor QBDI is arm64-only; arm64e builds refuse instead of silently falling back)",
             @"backend": @"unavailable"};
#else
    if (argc < 0) argc = 0;
    if (argc > 8) argc = 8;
    if (maxInsns < 1) maxInsns = 1;
    if (maxInsns > 8192) maxInsns = 8192;
    if (maxMs < 50) maxMs = 50;
    if (maxMs > 10000) maxMs = 10000;

    NSString *err = nil;
    void *target = dh_trace_resolve(module, symbol, addr, &err);
    if (!target) {
        return @{@"ok": @NO, @"error": err ?: @"target not resolved",
                 @"backend": @"qbdi-ios"};
    }

    VMInstanceRef vm = NULL;
    Options opts;
    memset(&opts, 0, sizeof(opts));
    qbdi_initVM(&vm, NULL, NULL, opts);
    if (!vm) {
        return @{@"ok": @NO, @"error": @"qbdi_initVM failed", @"backend": @"qbdi-ios"};
    }

    GPRState *gpr = qbdi_getGPRState(vm);
    uint8_t *stack = NULL;
    if (!gpr || !qbdi_allocateVirtualStack(gpr, 1 << 20, &stack)) {
        qbdi_terminateVM(vm);
        return @{@"ok": @NO, @"error": @"qbdi_allocateVirtualStack failed", @"backend": @"qbdi-ios"};
    }

    NSMutableArray *insns = [NSMutableArray arrayWithCapacity:(NSUInteger)MIN(maxInsns, 512)];
    DHTraceCtx ctx = { insns, maxInsns, 0, dh_trace_now_ns() + (uint64_t)maxMs * 1000000ULL,
                       NO, "completed" };

    BOOL instrumented = qbdi_addInstrumentedModuleFromAddr(vm, (rword)(uintptr_t)target);
    uint32_t cbId = QBDI_INVALID_EVENTID;
    if (instrumented) {
        cbId = qbdi_addCodeCB(vm, QBDI_PREINST, dh_trace_cb, &ctx, 0);
    }

    rword retval = 0;
    BOOL callOk = NO;
    uint64_t started = dh_trace_now_ns();
    if (instrumented && cbId != QBDI_INVALID_EVENTID) {
        callOk = dh_trace_call(vm, (rword)(uintptr_t)target, args, argc, &retval);
    }
    uint64_t elapsedMs = (dh_trace_now_ns() - started) / 1000000ULL;

    qbdi_terminateVM(vm);
    qbdi_alignedFree(stack);

    if (!instrumented) {
        return @{@"ok": @NO,
                 @"error": @"qbdi_addInstrumentedModuleFromAddr failed (target not in an instrumentable module)",
                 @"backend": @"qbdi-ios"};
    }
    if (cbId == QBDI_INVALID_EVENTID) {
        return @{@"ok": @NO, @"error": @"qbdi_addCodeCB failed", @"backend": @"qbdi-ios"};
    }

    NSMutableArray *warnings = [NSMutableArray array];
    [warnings addObject:@"replay: the target function is executed once under QBDI on this thread; its side effects are real."];
    [warnings addObject:@"arguments: only x0-x7 integer/pointer values are seeded; stack arguments and float/vector arguments are not reconstructed."];
    if (ctx.stop && strcmp(ctx.stop, "completed") != 0) {
        [warnings addObject:[NSString stringWithFormat:@"execution stopped early (%s); retval is not the function's return value.", ctx.stop]];
        if (strcmp(ctx.stop, "time-limit") == 0 && ctx.count <= 3) {
            [warnings addObject:@"QBDI cold start / JIT warmup likely: the first trace in a process can exceed a small budget. Retry with max_ms >= 3000 (the engine's default is 3000)."];
        }
    }

    NSMutableDictionary *targetInfo = [NSMutableDictionary dictionary];
    targetInfo[@"addr"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)target];
    if (module.length) targetInfo[@"module"] = module;
    if (symbol.length) targetInfo[@"symbol"] = symbol;

    return @{
        @"ok": @YES,
        @"backend": @"qbdi-ios",
        @"target": targetInfo,
        @"call_ok": callOk ? @YES : @NO,
        @"retval": [NSString stringWithFormat:@"0x%llx", (unsigned long long)retval],
        @"retval_dec": @(retval),
        @"count": @(ctx.count),
        @"truncated": ctx.truncated ? @YES : @NO,
        @"stop_reason": ctx.stop ? @(ctx.stop) : @"completed",
        @"duration_ms": @(elapsedMs),
        @"instructions": insns,
        @"warnings": warnings,
    };
#endif
}
