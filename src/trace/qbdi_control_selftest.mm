#import <Foundation/Foundation.h>
#import "qbdi_control_selftest.h"
extern "C" {
#import "qbdi_live.h"
#import "qbdi_control.h"
#import "dh_event.h"
#import "dh_flow.h"
#import "log_store.h"
#include "dh_health.h"
}
#include "idh_control_fixture_abi.h"
#include <dlfcn.h>
#include <pthread.h>
#include <ptrauth.h>
#include <errno.h>
#include <string.h>
#include <atomic>
#include "dh_control_breakpoint.h"
#ifndef DH_HAVE_QBDI
#define DH_HAVE_QBDI 0
#endif
static pthread_mutex_t fixtureLock=PTHREAD_MUTEX_INITIALIZER;
static std::atomic<bool> calibrated{false};
static std::atomic<bool> fixtureReady{false};
static void *fixtureHandle;
static void (*fixtureReset)(void);
static unsigned (*fixtureVersion)(void);
static IDHControlFixtureRoot (*fixtureRoot)(unsigned);
static uint64_t (*fixtureInvoke)(unsigned,uint64_t);
static int (*fixtureStats)(uint64_t *,size_t);
static uint64_t (*fixtureAfterPC)(void);
static void require(BOOL ok,NSString *message){if(!ok)[NSException raise:@"IDHControlTest" format:@"%@",message];}
static uint64_t code(void *pointer){return (uint64_t)ptrauth_strip(pointer,ptrauth_key_function_pointer);}
static int address_info(void *pointer,Dl_info *info){int saved=dh_in_hook;dh_in_hook=1;int found=dladdr((void *)code(pointer),info);dh_in_hook=saved;return found;}
static void *symbol(const char *name) {
    int saved=dh_in_hook;dh_in_hook=1;void *value=dlsym(fixtureHandle,name);dh_in_hook=saved;return value?ptrauth_sign_unauthenticated((void *)code(value),ptrauth_key_function_pointer,0):NULL;
}
static void load_fixture(void) {
    if(fixtureReady.load(std::memory_order_acquire))return;
    require(fixtureHandle==NULL,@"owned fixture symbol preparation failed; restart required");Dl_info own={0};address_info((void *)DHControlBackendSelfTest,&own);
    require(own.dli_fname!=NULL,@"fixture owner image unavailable");
    NSString *path=[[@(own.dli_fname) stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"IDHControlFixtures.dylib"];
    int saved=dh_in_hook;dh_in_hook=1;fixtureHandle=dlopen(path.fileSystemRepresentation,RTLD_NOW|RTLD_LOCAL);dh_in_hook=saved;
    if(!fixtureHandle){const char *reason=dlerror();require(NO,[NSString stringWithFormat:@"owned control fixture resource cannot be loaded: %@ (%@)",path,reason?@(reason):@"unknown dyld error"]);}
    fixtureVersion=(unsigned (*)(void))symbol("IDHControlFixtureVersion");fixtureReset=(void (*)(void))symbol("IDHControlFixtureReset");
    fixtureRoot=(IDHControlFixtureRoot (*)(unsigned))symbol("IDHControlFixtureGetRoot");fixtureInvoke=(uint64_t (*)(unsigned,uint64_t))symbol("IDHControlFixtureInvoke");
    fixtureStats=(int (*)(uint64_t *,size_t))symbol("IDHControlFixtureStats");fixtureAfterPC=(uint64_t (*)(void))symbol("IDHControlFixtureAfterPC");
    require(fixtureVersion && fixtureVersion()==1 && fixtureReset && fixtureRoot && fixtureInvoke && fixtureStats && fixtureAfterPC,@"owned control fixture ABI mismatch");
    fixtureReady.store(true,std::memory_order_release);
}
static void stats(uint64_t *out){require(fixtureStats(out,IDH_CF_STATS),@"owned fixture snapshot failed");}
static int prepare(unsigned mode) {
    dh_hook_options options;dh_thunk_options_default(&options);options.capture_return=1;options.abi_declared=1;options.argument_count=1;options.argument_types[0]='Q';options.return_type='Q';
    NSDictionary *r=DHLiveControlPrepare(code((void *)fixtureRoot(mode)),&options);require([r[@"ok"] boolValue],r[@"error"]?:@"owned control root preparation failed");return [r[@"slot"] intValue];
}
static void validate_delta(const uint64_t *before,const uint64_t *after,const uint64_t *baseline) {
    for(unsigned i=0;i<IDH_CF_THREAD;i++)require(after[i]-before[i]==baseline[i],[NSString stringWithFormat:@"original owned fixture side effects changed at field %u",i]);
}
static NSDictionary *validate_trace(NSString *identifier,unsigned mode,unsigned budget,const uint64_t *baseline) {
    NSDictionary *trace=DHLiveRead(identifier,0,1);BOOL outside=mode>=IDH_CF_CPP_OUT && mode<=IDH_CF_SIGJUMP_OUT;
    require(outside?[trace[@"state"] isEqual:@"nonlocal-exit"]:[trace[@"callCompleted"] boolValue],trace[@"stopReason"]?:@"owned control call did not complete");
    require(![trace[@"syntheticCall"] boolValue] && [trace[@"executionMode"] isEqual:@"live-native-control"],@"not an original live control trace");
    require([trace[@"controlFlow"][@"coverageGaps"] unsignedIntValue]==0 && [trace[@"controlFlow"][@"eventsLost"] unsignedIntValue]==0,@"owned control trace has an unaccounted continuation or event gap");
    require(dh_call_parent()==0 && [DHFlowState()[@"threadGuardCount"] unsignedIntValue]==0,@"nonlocal exit left an owned call/guard active");
    unsigned entries=0,leaves=0,aborted=0;
    for(DHLogEntry *entry in [DHLogStore shared].snapshot)if([entry.eventContext[@"callId"] isEqual:trace[@"callId"]]) {
        require(entry.threadId==[trace[@"threadId"] unsignedLongLongValue],@"deferred event lost the original owner thread");
        entries+=[entry.eventContext[@"phase"] isEqual:@"entry"];leaves+=[entry.eventContext[@"phase"] isEqual:@"leave"];aborted+=[entry.eventContext[@"phase"] isEqual:@"aborted"];
    }
    require(entries==1 && (outside?(aborted==1 && leaves==0):(leaves==1 && aborted==0)),@"original structured entry/leave/abort pairing is incomplete");
    if(budget==1)require([trace[@"count"] unsignedIntValue]==1 && [trace[@"recordingTruncated"] boolValue],@"record budget did not stop recording independently");
    if(!outside && budget>1) {
        unsigned seen=0;uint64_t marker=fixtureAfterPC();Dl_info rootImage={0};address_info((void *)fixtureRoot(mode),&rootImage);
        uint64_t original=strtoull([trace[@"originalTrampoline"] UTF8String],NULL,0);
        for(unsigned offset=0;offset<[trace[@"count"] unsignedIntValue];offset+=256) {
            NSDictionary *page=DHLiveRead(identifier,offset,256);
            for(NSDictionary *row in page[@"instructions"]) {
                uint64_t pc=strtoull([row[@"pc"] UTF8String],NULL,0);if(pc==marker)seen++;
                Dl_info image={0};address_info((void *)pc,&image);
                require(image.dli_fbase==rootImage.dli_fbase || (pc>=original && pc<original+128),@"native helper instructions unexpectedly expanded outside the root module");
            }
        }
        require(seen==baseline[IDH_CF_AFTER],@"actual instructions did not continue through every owned catch/jump");
    }
    return trace;
}
static NSDictionary *run(BOOL full) {
    NSMutableArray *traces=[NSMutableArray array],*passed=[NSMutableArray array],*slots=[NSMutableArray array];
    NSMutableDictionary *result=[@{@"ok":@NO,@"pass":@NO,@"restartRequired":@(full),@"scope":@"owned standard C/C++/ObjC native boundaries; original calls, never replay"} mutableCopy];
    NSString *pending=nil;
    int legacyInline=-1;
    try {
      @try {
        require(![DHLogStore shared].paused && ![[DHLogStore shared] isPausedForCategory:DHCategoryOther],@"resume global/other capture before the owned live fixture");
        require(![DHFlowState()[@"enabled"] boolValue],@"disable the async window before owned control calibration");
        require(![DHLiveState()[@"armedOrRunning"] boolValue] && (!full || [DHLiveState()[@"retainedSessions"] unsignedIntValue]==0),@"full control selftest requires eight unused sessions in a fresh process");
        load_fixture();fixtureReset();
        uint64_t baseline[IDH_CF_MODES][IDH_CF_STATS]={0},values[IDH_CF_MODES]={0};int errnos[IDH_CF_MODES]={0};
        unsigned modes=full?IDH_CF_MODES:1;
        for(unsigned mode=0;mode<modes;mode++) {
            uint64_t before[IDH_CF_STATS]={0},after[IDH_CF_STATS]={0};stats(before);errno=EAGAIN;
            values[mode]=fixtureInvoke(mode,7);errnos[mode]=errno;stats(after);
            require(values[mode]==(mode==IDH_CF_COMPOSITE?165:16),@"native fixture baseline value differs from the independent expected result");
            for(unsigned i=0;i<IDH_CF_STATS;i++)baseline[mode][i]=after[i]-before[i];
        }
        require(baseline[0][IDH_CF_CPP_CLEANUPS] && baseline[0][IDH_CF_FINALLY] && baseline[0][IDH_CF_AFTER]==10 && baseline[0][IDH_CF_NATIVE_CALLS]==2,@"owned native fixture baseline did not exercise every required path");
        if(full) {
            dh_hook_options options;dh_thunk_options_default(&options);options.capture_return=1;options.abi_declared=1;options.argument_count=1;options.argument_types[0]='Q';options.return_type='Q';char error[256]={0};
            legacyInline=dh_thunk_install_configured(DH_HOOK_INLINE,NULL,NULL,code(symbol("IDHControlFixtureCount")),0,"owned legacy Inline interaction",&options,error,sizeof(error));require(legacyInline>=0,@(error));
        }
        for(unsigned mode=0;mode<modes;mode++){int slot=prepare(mode);[slots addObject:@(slot)];}
        unsigned order[]={IDH_CF_COMPOSITE,IDH_CF_CPP_OUT,IDH_CF_OBJC_OUT,IDH_CF_JUMP_OUT,IDH_CF_SIGJUMP_OUT,IDH_CF_COMPOSITE,IDH_CF_NORMAL};
        unsigned count=full?7:1;
        for(unsigned i=0;i<count;i++) {
            unsigned mode=order[i],budget=i==6?1:8192;int slot=[slots[mode] intValue];
            NSDictionary *armed=DHLiveControlArm(slot,budget,10000,0);require([armed[@"ok"] boolValue],armed[@"error"]?:@"control arm failed");pending=armed[@"traceId"];
            uint64_t before[IDH_CF_STATS]={0},after[IDH_CF_STATS]={0};stats(before);errno=EAGAIN;
            uint64_t value=fixtureInvoke(mode,7);int actualErrno=errno;stats(after);
            require(value==values[mode] && actualErrno==errnos[mode],@"original result or errno changed under control tracing");validate_delta(before,after,baseline[mode]);
            NSDictionary *trace=validate_trace(pending,mode,budget,baseline[mode]);[traces addObject:trace];pending=nil;
            if(mode==IDH_CF_COMPOSITE && legacyInline>=0) {
                unsigned entry=0,leave=0;
                for(DHLogEntry *e in [DHLogStore shared].snapshot)if([e.eventContext[@"slot"] intValue]==legacyInline && [e.eventContext[@"parentCallId"] isEqual:trace[@"callId"]]) {
                    entry+=[e.eventContext[@"phase"] isEqual:@"entry"];leave+=[e.eventContext[@"phase"] isEqual:@"leave"];
                }
                require(entry==1 && leave==1,@"ordinary Inline child lost its exact controlled parent/return pairing");
            }
            require([trace[@"threadId"] unsignedLongLongValue]==after[IDH_CF_THREAD],@"fixture moved to a different native thread");
            require([dh_thunk_metadata(slot)[@"inFlight"] longLongValue]==0,@"owned control slot remained in flight");
            // Exercise the retained physical patches with no armed VM. This
            // includes actual ObjC rethrow at a relocated link instruction.
            stats(before);errno=EAGAIN;value=fixtureInvoke(mode,7);actualErrno=errno;stats(after);
            require(value==values[mode] && actualErrno==errnos[mode],@"inactive native forwarding changed the original call");validate_delta(before,after,baseline[mode]);
            [passed addObject:@(mode)];
        }
        if(full) {
            NSDictionary *armed=DHLiveControlArm([slots[0] intValue],8192,10000,0);require([armed[@"ok"] boolValue],armed[@"error"]?:@"pending control arm failed");pending=armed[@"traceId"];
            require([DHLiveCancel(pending)[@"ok"] boolValue],@"pending control cancellation failed");pending=nil;
            uint64_t before[IDH_CF_STATS]={0},after[IDH_CF_STATS]={0};stats(before);require(fixtureInvoke(0,7)==values[0],@"cancelled capture changed native forwarding");stats(after);validate_delta(before,after,baseline[0]);
            [passed addObject:@"pending-cancel-original-continues"];
        }
        calibrated.store(true,std::memory_order_release);result[@"ok"]=@YES;result[@"pass"]=@YES;
        result[@"proof"]=@{@"insideAfterInstructionsPerComposite":@10,@"outsideOriginalCatchesAndJumps":@(full?4:0),@"originalSideEffectsAndErrno":@YES,@"inactiveRetainedPatches":@YES,@"nativeHelperInstructionsUnexpanded":@YES,@"sessionBudgetUnchanged":@8};
      } @catch(NSException *exception){result[@"error"]=exception.reason?:@"owned control fixture exception";}
    } catch(...) {result[@"error"]=@"C++ exception escaped an owned fixture catch";}
    if(pending)DHLiveCancel(pending);
    if(full)for(NSNumber *slot in slots)dh_thunk_disable(slot.intValue);
    if(legacyInline>=0)dh_thunk_disable(legacyInline);
    result[@"passed"]=passed;result[@"traces"]=traces;result[@"slots"]=slots;result[@"legacyInlineSlot"]=@(legacyInline);return result;
}
NSDictionary *DHControlEnsureCalibrated(void) {
#if !(DH_HAVE_INLINE && DH_HAVE_QBDI)
    return @{@"ok":@NO,@"error":@"native control backend is not linked"};
#else
    pthread_mutex_lock(&fixtureLock);NSDictionary *result=calibrated.load(std::memory_order_acquire)?@{@"ok":@YES,@"calibrated":@YES}:run(NO);pthread_mutex_unlock(&fixtureLock);return result;
#endif
}
NSDictionary *DHControlBackendSelfTestWithBreakpoints(BOOL force) {
#if !(DH_HAVE_INLINE && DH_HAVE_QBDI)
    return @{@"ok":@NO,@"pass":@NO,@"error":@"native control backend is not linked"};
#else
    pthread_mutex_lock(&fixtureLock);
    if(force && ([DHControlState()[@"attempted"] boolValue] || [DHLiveState()[@"retainedSessions"] unsignedIntValue])){pthread_mutex_unlock(&fixtureLock);return @{@"ok":@NO,@"pass":@NO,@"error":@"forced Mach checkpoint selftest requires a fresh unprepared process"};}
    dh_control_breakpoint_force_for_selftest(force);NSMutableDictionary *result=[run(YES) mutableCopy];dh_control_breakpoint_force_for_selftest(0);
    result[@"breakpointBackend"]=DHControlBreakpointState();
    if(force && [result[@"ok"] boolValue] && ![result[@"breakpointBackend"][@"handled"] unsignedLongLongValue]){result[@"ok"]=@NO;result[@"pass"]=@NO;result[@"error"]=@"forced native Mach checkpoints were not actually observed";}
    pthread_mutex_unlock(&fixtureLock);return result;
#endif
}
NSDictionary *DHControlBackendSelfTest(void){return DHControlBackendSelfTestWithBreakpoints(NO);}
NSDictionary *DHControlBackendState(void) {
    NSMutableDictionary *state=[DHControlState() mutableCopy];[state addEntriesFromDictionary:DHLiveState()];BOOL ready=calibrated.load(std::memory_order_acquire);state[@"ownedCalibrationPassed"]=@(ready);state[@"ownedFixtureResourceLoaded"]=@(fixtureReady.load(std::memory_order_acquire));if(ready)state[@"reason"]=@"owned native control calibration passed";return state;
}
