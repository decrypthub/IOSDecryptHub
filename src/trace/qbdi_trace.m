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
#include <ptrauth.h>
#include <mach/mach.h>
#include <math.h>

#import "qbdi_trace.h"
#import "dh_thunk.h"

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
        c->truncated = YES;
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

static BOOL dh_trace_executable(uint64_t address) {
    vm_address_t region = address; vm_size_t size = 0; natural_t depth = 0;
    for (unsigned i = 0; i < 16; i++) {
        vm_region_submap_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &region, &size, &depth,
            (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS ||
            address < region || address - region >= size) return NO;
        if (!info.is_submap) return (info.protection & VM_PROT_EXECUTE) != 0;
        depth++;
    }
    return NO;
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
    return DHQBDITraceFunctionWithBuffers(module,symbol,addr,args,argc,maxInsns,maxMs,nil);
}

NSDictionary *DHQBDITraceFunctionWithBuffers(NSString *module, NSString *symbol, uint64_t addr,
    const uint64_t *args, int argc, int maxInsns, int maxMs, NSArray *buffers) {
#if !DH_HAVE_QBDI
    (void)module; (void)symbol; (void)addr; (void)args; (void)argc; (void)maxInsns; (void)maxMs; (void)buffers;
    return @{@"ok": @NO,
             @"error": @"QBDI is not linked in this build",
             @"backend": @"unavailable"};
#else
    if (argc < 0 || argc > 8 || (argc && !args))
        return @{@"ok": @NO, @"error": @"trace supports at most eight fixed GPR arguments"};
    if (buffers && (![buffers isKindOfClass:NSArray.class] || buffers.count > 8))
        return @{@"ok": @NO, @"error": @"buffers must be an array of at most eight entries"};
    uint64_t ownedArgs[8]={0}; if (argc) memcpy(ownedArgs,args,argc*sizeof(uint64_t));
    NSMutableArray<NSMutableData *> *ownedBuffers=[NSMutableArray array];
    NSMutableArray<NSNumber *> *bufferArgs=[NSMutableArray array],*bufferSizes=[NSMutableArray array];
    NSMutableSet *seen=[NSMutableSet set]; NSUInteger total=0;
    for (id spec in buffers) {
        if (![spec isKindOfClass:NSDictionary.class]) return @{@"ok": @NO, @"error": @"invalid buffer descriptor"};
        id index=spec[@"arg"],hex=spec[@"hex"];
        if (![index isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)index)==CFBooleanGetTypeID() ||
            !isfinite([index doubleValue]) || [index doubleValue]!=floor([index doubleValue]) ||
            [index integerValue]<0 || [index integerValue]>=argc || [seen containsObject:index] ||
            ![hex isKindOfClass:NSString.class] || [hex length]>16384 || [hex length]%2)
            return @{@"ok": @NO, @"error": @"buffers require unique argument indices, even hex and at most 8192 bytes each"};
        const char *text=[hex UTF8String]; NSUInteger length=[hex length]/2;
        if (!text || strlen(text)!=[hex length]) return @{@"ok": @NO, @"error": @"buffer hex must be ASCII"};
        total+=length;
        if (total>32768) return @{@"ok": @NO, @"error": @"buffer total exceeds 32768 bytes"};
        NSMutableData *data=[NSMutableData dataWithLength:MAX(length,1)]; uint8_t *bytes=data.mutableBytes;
        for (NSUInteger i=0;i<length;i++) {
            unsigned value=0;
            for (unsigned j=0;j<2;j++) {
                char c=text[2*i+j]; unsigned digit=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;
                if (digit>15) return @{@"ok": @NO, @"error": @"invalid buffer hex digit"};
                value=(value<<4)|digit;
            }
            bytes[i]=(uint8_t)value;
        }
        ownedArgs[[index integerValue]]=(uint64_t)(uintptr_t)data.mutableBytes;
        [seen addObject:index];[ownedBuffers addObject:data];[bufferArgs addObject:index];[bufferSizes addObject:@(length)];
    }
    if (maxInsns < 1) maxInsns = 1;
    if (maxInsns > 8192) maxInsns = 8192;
    if (maxMs < 50) maxMs = 50;
    if (maxMs > 10000) maxMs = 10000;

    NSString *err = nil;
    void *target = dh_trace_resolve(module, symbol, addr, &err);
    target = ptrauth_strip(target, ptrauth_key_function_pointer);
    if (!target) {
        return @{@"ok": @NO, @"error": err ?: @"target not resolved",
                 @"backend": @"qbdi-ios"};
    }
    if (!dh_trace_executable((uint64_t)(uintptr_t)target))
        return @{@"ok": @NO, @"error": @"trace target is not an executable mapping", @"backend": @"qbdi-ios"};
    if (dh_thunk_is_inline_patched((uint64_t)(uintptr_t)target))
        return @{@"ok": @NO, @"error": @"trace target has a retained Inline patch; restart the target and re-resolve its original code first", @"backend": @"qbdi-ios"};

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
        callOk = dh_trace_call(vm, (rword)(uintptr_t)target, ownedArgs, argc, &retval);
    }
    uint64_t elapsedMs = (dh_trace_now_ns() - started) / 1000000ULL;

    qbdi_terminateVM(vm);
    qbdi_alignedFree(stack);
    NSMutableArray *bufferResults=[NSMutableArray array];
    static const char digits[]="0123456789abcdef";
    for (NSUInteger i=0;i<ownedBuffers.count;i++) {
        NSUInteger length=bufferSizes[i].unsignedIntegerValue;
        NSMutableData *encoded=[NSMutableData dataWithLength:length*2];char *text=encoded.mutableBytes;
        const uint8_t *bytes=ownedBuffers[i].bytes;
        for (NSUInteger j=0;j<length;j++) { text[2*j]=digits[bytes[j]>>4];text[2*j+1]=digits[bytes[j]&15]; }
        NSString *hex=[[NSString alloc] initWithData:encoded encoding:NSASCIIStringEncoding] ?: @"";
        [bufferResults addObject:@{@"arg":bufferArgs[i],@"length":@(length),@"afterHex":hex}];
    }

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
        @"executionMode": @"replay", @"contextComplete": @NO,
        @"pointerAuthentication": @(
#if defined(QBDI_PTRAUTH)
            YES
#else
            NO
#endif
        ),
        @"target": targetInfo,
        @"call_ok": callOk ? @YES : @NO,
        @"retval_valid": @(callOk && ctx.count>0 && ctx.stop && strcmp(ctx.stop,"completed")==0),
        @"retval": [NSString stringWithFormat:@"0x%llx", (unsigned long long)retval],
        @"retval_dec": @(retval),
        @"count": @(ctx.count),
        @"truncated": ctx.truncated ? @YES : @NO,
        @"stop_reason": ctx.stop ? @(ctx.stop) : @"completed",
        @"duration_ms": @(elapsedMs),
        @"instructions": insns,
        @"buffers": bufferResults,
        @"warnings": warnings,
    };
#endif
}
