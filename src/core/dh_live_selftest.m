#import "dh_hook_selftest.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "log_store.h"
#import "../trace/qbdi_live.h"
#include <ptrauth.h>
#include <errno.h>
#include <string.h>
#if DH_HAVE_INLINE && DH_HAVE_QBDI
static volatile unsigned liveCounter;
__attribute__((noinline,optnone)) uint64_t IDHLivePacked(
    uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h,
    uint8_t i,BOOL j,void *k,int32_t l,uint16_t m,int8_t n,uint64_t o) {
    int incoming=errno;liveCounter++;errno=EOVERFLOW;
    return a+b+c+d+e+f+g+h+i+j+(uint64_t)(uintptr_t)k+(uint64_t)l+m+(uint64_t)n+o+incoming;
}
__attribute__((noinline,optnone)) uint64_t IDHLivePackedDriver(void) {
    return IDHLivePacked(1,2,3,4,5,6,7,8,0xab,YES,(void *)0x12340000,-123,0x9876,-7,0x1122334455667788ULL);
}
__attribute__((noinline,optnone)) double IDHLiveFloating(double a,double b,double c) {liveCounter++;return a*b+c;}
typedef struct {uint64_t a,b,c;} IDHLiveAggregateResult;
__attribute__((noinline,optnone)) IDHLiveAggregateResult IDHLiveAggregate(uint64_t n) {liveCounter++;return (IDHLiveAggregateResult){n,n+1,n+2};}
extern uint64_t IDHLiveScratchDriver(void),IDHLiveScratchTarget(void);
__asm__(
".text\n.p2align 5\n.globl _IDHLiveScratchTarget\n_IDHLiveScratchTarget:\n.cfi_startproc\n"
"eor x0,x16,x17\nret\n.space 56\n.cfi_endproc\n"
".globl _IDHLiveScratchDriver\n_IDHLiveScratchDriver:\n.cfi_startproc\n"
#if defined(__arm64e__)
"pacibsp\n"
#endif
"stp x29,x30,[sp,#-16]!\n.cfi_def_cfa_offset 16\n.cfi_offset 29,-16\n.cfi_offset 30,-8\n"
"mov x29,sp\nmov x16,#0x1234\nmov x17,#0x5678\nbl _IDHLiveScratchTarget\n"
"ldp x29,x30,[sp],#16\n.cfi_def_cfa_offset 0\n"
#if defined(__arm64e__)
"retab\n"
#else
"ret\n"
#endif
".cfi_endproc\n");
static uint64_t raw_address(void *address) {return (uint64_t)ptrauth_strip(address,ptrauth_key_function_pointer);}
static void check(BOOL condition,NSString *message) {if (!condition) [NSException raise:@"IDHLiveFixture" format:@"%@",message];}
static NSDictionary *arm(int slot,unsigned budget) {
    uint64_t target=0,original=0;check(dh_thunk_live_target(slot,&target,&original),@"live target lookup");
    NSDictionary *r=DHLiveArm(slot,target,original,budget,10000,0);check([r[@"ok"] boolValue],r[@"error"]?:@"arm failed");return r;
}
#endif
NSDictionary *DHLiveBackendSelfTest(void) {
#if !(DH_HAVE_INLINE && DH_HAVE_QBDI)
    return @{@"pass":@NO,@"error":@"live backend not linked"};
#else
    NSMutableArray *tests=[NSMutableArray array],*traces=[NSMutableArray array],*slots=[NSMutableArray array];
    NSMutableDictionary *result=[@{@"pass":@NO,@"scope":@"IDH-owned normally-returning fixtures only",@"restartRequired":@YES} mutableCopy];
    @try {
        check(![DHLogStore shared].paused && ![[DHLogStore shared] isPausedForCategory:DHCategoryOther],@"resume all/other first");
        errno=EAGAIN;uint64_t reference=IDHLivePackedDriver();
        dh_hook_options options;dh_thunk_options_default(&options);options.capture_return=1;options.abi_declared=1;
        options.argument_count=15;options.return_type='Q';memcpy(options.argument_types,"QQQQQQQQCB^iScQ",15);
        char error[512]={0};int slot=dh_thunk_install_configured(DH_HOOK_INLINE,NULL,NULL,raw_address((void *)IDHLivePacked),0,"IDH-live-packed",&options,error,sizeof(error));
        check(slot>=0,@(error));[slots addObject:@(slot)];
        NSDictionary *armed=arm(slot,4096);liveCounter=0;errno=EAGAIN;
        uint64_t actual=IDHLivePackedDriver();int actualErrno=errno;
        NSDictionary *trace=DHLiveRead(armed[@"traceId"],0,1);[traces addObject:trace];
        result[@"packedReference"]=[NSString stringWithFormat:@"0x%llx",reference];
        result[@"packedActual"]=[NSString stringWithFormat:@"0x%llx",actual];
        result[@"packedCounter"]=@(liveCounter);result[@"packedErrno"]=@(actualErrno);
        check(actual==reference && liveCounter==1 && actualErrno==EOVERFLOW,@"packed original execution/errno was not exactly once");
        check([trace[@"callCompleted"] boolValue] && [trace[@"executionMode"] isEqual:@"live"] && ![trace[@"syntheticCall"] boolValue],@"not a completed live call");
        NSData *stack=DHDataFromHex(trace[@"entryStack"][@"hex"]);check(stack.length>=32,@"missing original stack bytes");
        const uint8_t *bytes=stack.bytes;uint64_t pointer=0;memcpy(&pointer,bytes+8,8);
        check(bytes[0]==0xab && bytes[1]==1 && pointer==0x12340000,@"real packed-stack offsets changed");
        check([trace[@"stack"][@"frames"] count]>=4 && [trace[@"stack"][@"complete"] boolValue] && ![trace[@"stack"][@"error"] intValue],@"caller unwind did not reach the thread root");
        [tests addObject:@"exactly-once-original-thread-stack-15-args-and-errno"];
        [tests addObject:@"original-caller-unwind"];
        dh_hook_options entry;dh_thunk_options_default(&entry);
        int floating=dh_thunk_install_configured(DH_HOOK_INLINE,NULL,NULL,raw_address((void *)IDHLiveFloating),0,"IDH-live-floating",&entry,error,sizeof(error));
        check(floating>=0,@(error));[slots addObject:@(floating)];armed=arm(floating,4096);liveCounter=0;
        double value=IDHLiveFloating(1.25,2,4);trace=DHLiveRead(armed[@"traceId"],0,1);[traces addObject:trace];
        check(value==6.5 && liveCounter==1 && [trace[@"callCompleted"] boolValue] && [trace[@"entry"][@"q0_q31"] count]==32,@"SIMD real call/return was changed");
        [tests addObject:@"real-SIMD-input-and-return"];
        int aggregate=dh_thunk_install_configured(DH_HOOK_INLINE,NULL,NULL,raw_address((void *)IDHLiveAggregate),0,"IDH-live-aggregate",&entry,error,sizeof(error));
        check(aggregate>=0,@(error));[slots addObject:@(aggregate)];armed=arm(aggregate,4096);liveCounter=0;
        IDHLiveAggregateResult aggregateValue=IDHLiveAggregate(13);trace=DHLiveRead(armed[@"traceId"],0,1);[traces addObject:trace];
        check(aggregateValue.a==13 && aggregateValue.b==14 && aggregateValue.c==15 && liveCounter==1 && [trace[@"callCompleted"] boolValue],@"hidden x8 result pointer or original output memory changed");
        [tests addObject:@"hidden-X8-aggregate-output-on-original-stack"];
        int scratch=dh_thunk_install_configured(DH_HOOK_INLINE,NULL,NULL,raw_address((void *)IDHLiveScratchTarget),0,"IDH-live-scratch",&entry,error,sizeof(error));
        check(scratch>=0,@(error));[slots addObject:@(scratch)];armed=arm(scratch,4096);
        uint64_t scratchValue=IDHLiveScratchDriver();trace=DHLiveRead(armed[@"traceId"],0,1);[traces addObject:trace];
        check(scratchValue==(0x1234^0x5678) && [trace[@"entry"][@"gpr"][@"x16"] isEqual:@"0x1234"] &&
            [trace[@"entry"][@"gpr"][@"x17"] isEqual:@"0x5678"] && [trace[@"callCompleted"] boolValue],@"entry veneer lost original x16/x17");
        [tests addObject:@"original-IP0-IP1-before-entry-veneer"];
        armed=arm(slot,4);liveCounter=0;errno=EAGAIN;actual=IDHLivePackedDriver();trace=DHLiveRead(armed[@"traceId"],0,1);[traces addObject:trace];
        check(actual==reference && liveCounter==1 && [trace[@"callCompleted"] boolValue] && [trace[@"recordingTruncated"] boolValue] && [trace[@"count"] intValue]==4,@"record budget aborted or repeated a real call");
        [tests addObject:@"record-budget-never-aborts-original-call"];
        armed=arm(slot,32);liveCounter=0;NSDictionary *cancelled=DHLiveCancel(armed[@"traceId"]);
        check([cancelled[@"ok"] boolValue] && liveCounter==0,@"pending cancellation executed target");
        [tests addObject:@"cancel-pending-without-execution"];
        result[@"pass"]=@YES;
    } @catch (NSException *exception) {result[@"error"]=exception.reason?:@"live fixture exception";}
    @finally {for (NSNumber *slot in slots) dh_thunk_disable(slot.intValue);}
    result[@"passed"]=tests;result[@"traces"]=traces;result[@"slots"]=slots;return result;
#endif
}
