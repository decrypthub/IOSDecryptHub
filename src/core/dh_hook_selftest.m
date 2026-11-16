#import "dh_hook_selftest.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_call_context.h"
#import "log_store.h"
#include <unistd.h>
#include <string.h>

typedef struct { uint64_t x, y, z; } IDHABIAggregate;
static dispatch_semaphore_t probeEntered, probeResume, probeDone;
static NSString *const probeObject = @"abi-probe";
@interface IDHABIProbe : NSObject
- (uint64_t)sum:(uint64_t)a b:(uint64_t)b c:(uint64_t)c d:(uint64_t)d e:(uint64_t)e f:(uint64_t)f
    g:(BOOL)g h:(BOOL)h object:(id)object j:(uint32_t)j k:(uint16_t)k pointer:(void *)pointer m:(int8_t)m n:(uint64_t)n o:(uint64_t)o;
- (uint64_t)inner:(uint64_t)n;
- (uint64_t)outer:(uint64_t)n;
- (uint64_t)recursive:(uint64_t)n;
- (void)fill:(void *)buffer length:(uint64_t)n value:(uint8_t)value;
- (double)floating:(double)value;
- (IDHABIAggregate)aggregate:(uint64_t)value;
- (uint64_t)waitValue:(uint64_t)value;
@end
@implementation IDHABIProbe
- (uint64_t)sum:(uint64_t)a b:(uint64_t)b c:(uint64_t)c d:(uint64_t)d e:(uint64_t)e f:(uint64_t)f
    g:(BOOL)g h:(BOOL)h object:(id)object j:(uint32_t)j k:(uint16_t)k pointer:(void *)pointer m:(int8_t)m n:(uint64_t)n o:(uint64_t)o {
    return a+b+c+d+e+f+g+100*h+(object == probeObject ? 123 : 0)+j+k+(uint64_t)(uintptr_t)pointer+(uint64_t)m+n+o;
}
- (uint64_t)inner:(uint64_t)n { return n+7; }
- (uint64_t)outer:(uint64_t)n {
    DHLogEntry *e = [DHLogEntry new]; e.category = DHCategoryDigest; e.algorithm = @"idh-abi-probe"; e.operation = @"observation";
    [[DHLogStore shared] append:e]; return [self inner:n]*3;
}
- (uint64_t)recursive:(uint64_t)n { return n ? [self recursive:n-1]+1 : 10; }
- (void)fill:(void *)buffer length:(uint64_t)n value:(uint8_t)value { if (buffer) memset(buffer,value,(size_t)MIN(n,32)); }
- (double)floating:(double)value { return value*2.0; }
- (IDHABIAggregate)aggregate:(uint64_t)value { return (IDHABIAggregate){value,value+1,value+2}; }
- (uint64_t)waitValue:(uint64_t)value {
    dispatch_semaphore_signal(probeEntered);
    dispatch_semaphore_wait(probeResume,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC)); return value+5;
}
@end

static uint64_t probe_sum(IDHABIProbe *p) {
    return [p sum:1 b:2 c:3 d:4 e:5 f:6 g:YES h:NO object:probeObject j:0x12345678 k:0x9876
        pointer:(void *)0x12340000 m:-7 n:0x1122334455667788ULL o:0x9988776655443322ULL];
}
static void require(BOOL condition, NSString *reason) {
    if (!condition) [NSException raise:@"IDHABIProbeFailure" format:@"%@",reason];
}
static uint64_t probe_replacement(id self, SEL selector, uint64_t value) { (void)self; (void)selector; return value+99; }

NSDictionary *DHHookSelfTest(BOOL includeCImport) {
    DHLogStore *store = [DHLogStore shared];
    if (store.paused || [store isPausedForCategory:DHCategoryOther])
        return @{@"pass": @NO, @"error": @"resume global/other capture before explicit self-test; no state changed"};
    dh_hook_info before[DH_THUNK_COUNT]; int count = dh_thunk_list(before,DH_THUNK_COUNT);
    if (count && before[count-1].slot > DH_THUNK_COUNT-12)
        return @{@"pass": @NO, @"error": @"insufficient monotonic hook slots; restart target before self-test"};
    uint64_t since = ((DHLogEntry *)store.snapshot.lastObject).seq;
    NSMutableArray<NSNumber *> *slots = [NSMutableArray array];
    NSMutableArray *passed = [NSMutableArray array], *roots = [NSMutableArray array];
    __block IMP displaced = NULL; __block Method ownershipMethod = NULL;
    __block int importSlot = -1;
    __block NSString *failure = nil;
    dh_hook_options opts; dh_thunk_options_default(&opts); opts.capture_return = 1; opts.describe_args = 1; opts.fixed_abi = 1;
    int (^install)(NSString *,const dh_hook_options *) = ^int(NSString *selector,const dh_hook_options *options) {
        char error[512] = {0}; int slot = dh_thunk_install_configured(DH_HOOK_METHOD,"IDHABIProbe",selector.UTF8String,0,0,NULL,options,error,sizeof(error));
        require(slot>=0,[NSString stringWithFormat:@"install %@: %s",selector,error]); [slots addObject:@(slot)]; return slot;
    };
    @try {
        IDHABIProbe *p = [IDHABIProbe new]; uint64_t original = probe_sum(p);
        install(@"sum:b:c:d:e:f:g:h:object:j:k:pointer:m:n:o:",&opts);
        require(probe_sum(p)==original,@"15 mixed packed-stack arguments changed behavior");
        [passed addObject:@"packed-stack-15"];
        int inner = install(@"inner:",&opts); install(@"outer:",&opts); install(@"recursive:",&opts);
        require([p outer:2]==27 && [p recursive:5]==15,@"nested/recursive return mismatch");
        __block unsigned bad = 0;
        dispatch_apply(8,dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^(size_t i) {
            @autoreleasepool { if ([p outer:i]!=(i+7)*3) __atomic_fetch_add(&bad,1,__ATOMIC_RELAXED); }
        });
        require(!bad && dh_call_parent()==0,@"concurrent contexts/returns changed");
        [passed addObject:@"nested-recursive-concurrent"];
        dh_hook_options output; dh_thunk_options_default(&output);
        output.capture_after=1; output.capture_return=1; output.fixed_abi=1; output.ptr_arg=2; output.len_arg=3; output.max_bytes=32;
        install(@"fill:length:value:",&output); uint8_t bytes[64]; memset(bytes,0xaa,sizeof(bytes));
        [p fill:bytes length:16 value:0x5a]; [p fill:bytes length:0 value:0x5a];
        for (unsigned i=0;i<16;i++) require(bytes[i]==0x5a,@"output buffer changed");
        NSMutableDictionary *entries=[NSMutableDictionary dictionary],*leaves=[NSMutableDictionary dictionary];
        BOOL stack=NO,buffer=NO,empty=NO,observation=NO;
        for (DHLogEntry *e in store.snapshot) {
            if (e.seq<=since) continue;
            NSString *cid=e.eventContext[@"callId"],*phase=e.eventContext[@"phase"];
            if ([e.operation hasPrefix:@"-[IDHABIProbe "] && cid.length) {
                if ([phase isEqual:@"entry"]) entries[cid]=e; else if ([phase isEqual:@"leave"]) leaves[cid]=e;
                if ([phase isEqual:@"entry"] && ![e.eventContext[@"parentCallId"] length]) [roots addObject:cid];
            }
            NSArray *args=e.eventPayload[@"arguments"];
            if (args.count==15) {
                require([args[6][@"location"][@"offset"] intValue]==0 && [args[7][@"location"][@"offset"] intValue]==1 &&
                    [args[8][@"location"][@"offset"] intValue]==8,@"Darwin packed offsets incorrect"); stack=YES;
            }
            if ([e.operation containsString:@"[IDHABIProbe fill:"]) {
                if ([phase isEqual:@"entry"]) require(e.input.length==0,@"after buffer read at entry");
                else {
                    require(![e.eventPayload[@"returnValue"][@"available"] boolValue],@"void return mislabeled as a value");
                    NSArray *memory=e.eventPayload[@"memory"];
                    if (e.output.length==16 && !memcmp(e.output.bytes,bytes,16)) buffer=YES;
                    if ([memory.firstObject[@"status"] isEqual:@"empty"]) empty=YES;
                }
            }
            if ([e.algorithm isEqual:@"idh-abi-probe"]) {
                require([e.eventContext[@"parentCallId"] length]>0,@"observation lost its containing call"); observation=YES;
            }
        }
        require(stack && buffer && empty && observation,@"structured snapshots missing");
        require(entries.count>=20 && entries.count==leaves.count,@"entry/leave count mismatch");
        for (NSString *cid in entries) {
            DHLogEntry *a=entries[cid],*b=leaves[cid];
            require(b && a.threadId==b.threadId && [a.eventContext[@"parentCallId"] isEqual:b.eventContext[@"parentCallId"]],@"call pairing mismatch");
            NSString *parent=a.eventContext[@"parentCallId"];
            if (parent.length) require(entries[parent]!=nil,@"nested parent not found");
        }
        [passed addObject:@"structured-pairing-and-observation"];
        [passed addObject:@"after-zero-length-void-return"];
        char error[512]={0};
        for (NSString *selector in @[@"floating:",@"aggregate:"]) {
            Method method=class_getInstanceMethod(IDHABIProbe.class,NSSelectorFromString(selector)); IMP imp=method_getImplementation(method);
            require(dh_thunk_install_configured(DH_HOOK_METHOD,"IDHABIProbe",selector.UTF8String,0,0,NULL,&opts,error,sizeof(error))==-6 &&
                method_getImplementation(method)==imp,@"unsupported ABI was not rejected before patch");
        }
        dh_hook_options invalid=opts; strlcpy(invalid.capture_ret_multi,"x2:8",sizeof(invalid.capture_ret_multi));
        require(dh_thunk_install_configured(DH_HOOK_METHOD,"IDHABIProbe","inner:",0,0,NULL,&invalid,error,sizeof(error))==-6,@"return window validation too late");
        require(dh_thunk_install_configured(DH_HOOK_IMPORT,NULL,"getpid",0,0,NULL,&opts,error,sizeof(error))==-6,@"unknown C post ABI accepted");
        require(dh_thunk_set_return(inner,0)==-3,@"published configuration changed");
        [passed addObject:@"ABI-and-option-rejection-immutable-config"];
        ownershipMethod=class_getInstanceMethod(IDHABIProbe.class,@selector(inner:));
        displaced=method_setImplementation(ownershipMethod,(IMP)probe_replacement);
        require(dh_thunk_uninstall(inner,1,error,sizeof(error))==-5 && method_getImplementation(ownershipMethod)==(IMP)probe_replacement,@"foreign IMP ownership overwritten");
        method_setImplementation(ownershipMethod,displaced); displaced=NULL;
        [passed addObject:@"ownership-check"];
        probeEntered=dispatch_semaphore_create(0); probeResume=dispatch_semaphore_create(0); probeDone=dispatch_semaphore_create(0);
        int wait=install(@"waitValue:",&opts); __block uint64_t result=0;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^{ result=[p waitValue:37]; dispatch_semaphore_signal(probeDone); });
        require(dispatch_semaphore_wait(probeEntered,dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC))==0,@"in-flight call did not enter");
        require([dh_thunk_metadata(wait)[@"inFlight"] intValue]==1,@"in-flight count missing");
        require(dh_thunk_uninstall(wait,1,error,sizeof(error))==0,@"owned method retirement failed");
        dispatch_semaphore_signal(probeResume);
        require(dispatch_semaphore_wait(probeDone,dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC))==0 && result==42,@"in-flight return changed");
        require([dh_thunk_metadata(wait)[@"inFlight"] intValue]==0,@"in-flight count leaked");
        [passed addObject:@"in-flight-retirement"];
        if (includeCImport) {
            dh_hook_options native; dh_thunk_options_default(&native); native.capture_return=1; native.abi_declared=1; native.return_type='i';
            pid_t expected=getpid();
            importSlot=dh_thunk_install_configured(DH_HOOK_IMPORT,NULL,"getpid",0,0,"IDHABIProbe-getpid",&native,error,sizeof(error));
            require(importSlot>=0 && getpid()==expected,@"declared fixed-C ABI getpid failed");
            NSString *hookID=dh_thunk_metadata(importSlot)[@"hookId"];
            BOOL cEntry=NO,cLeave=NO;
            for (DHLogEntry *event in store.snapshot) {
                if (![event.eventContext[@"hookId"] isEqual:hookID]) continue;
                cEntry |= [event.eventContext[@"phase"] isEqual:@"entry"];
                cLeave |= [event.eventContext[@"phase"] isEqual:@"leave"];
            }
            require(cEntry && cLeave,@"C import returned correctly but was not actually observed");
            dh_thunk_disable(importSlot); [passed addObject:@"declared-C-post"];
        }
    } @catch (NSException *ex) {
        failure=ex.reason ?: @"self-test exception";
    } @finally {
        if (displaced && ownershipMethod) method_setImplementation(ownershipMethod,displaced);
        if (probeResume) dispatch_semaphore_signal(probeResume);
        for (NSNumber *slot in slots) { char error[256]={0}; dh_thunk_uninstall(slot.intValue,1,error,sizeof(error)); }
        if (importSlot>=0) dh_thunk_disable(importSlot);
    }
    return @{@"pass": @(!failure), @"error": failure ?: @"", @"passed": passed,
        @"processGeneration": DHProcessGeneration(), @"rootCallIds": roots,
        @"fixtureSlots": slots, @"CImportSlot": @(importSlot), @"restartRemovesRetainedImport": @(importSlot>=0),
        @"scope": @"IDH-owned synthetic methods; optional getpid only; no business requests/signing oracle"};
}
