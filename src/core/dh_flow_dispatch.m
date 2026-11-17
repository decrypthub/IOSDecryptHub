#import "dh_flow_dispatch.h"
#import "dh_flow.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_unwind.h"
#include "dh_dispatch_callout_abi.h"
#include "dh_health.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include <string.h>

// Apple libdispatch init.c: _dispatch_client_callout(void*, dispatch_function_t).
// It is not exported on the tested phones. Learn the actual caller of an owned
// public source callback, then require the complete recognized A64 call prefix.
// No source/continuation/queue private field or address offset is read.
typedef void (*ClientCallout)(void *,dispatch_function_t);
static void *original;
static uintptr_t target,agentBase;
static uintptr_t candidateCaller,candidateStart,candidateEnd;
static uint32_t candidateWords[8];
static int adapter=-1;
static pthread_mutex_t prepareLock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic BOOL ready,enabled,attempted;
static _Atomic uint64_t forwarded,selectedAttempts;
static char reason[256]="not prepared";
static _Atomic(uintptr_t) probeContext,probeFunction;
static _Atomic unsigned probeEntries,probeMismatches;
static _Atomic BOOL ownedTest;

@interface DHDispatchEntryProbe:NSObject {
@public uint64_t marker,caller;unsigned calls,failures;
    dispatch_semaphore_t wake,cancelled;
    NSMutableArray *observations;
}
@end
@implementation DHDispatchEntryProbe
@end
static DHDispatchEntryProbe *new_probe(void) {
    DHDispatchEntryProbe *p=[DHDispatchEntryProbe new];p->marker=0x484449535043414cULL;p->wake=dispatch_semaphore_create(0);p->cancelled=dispatch_semaphore_create(0);p->observations=[NSMutableArray array];return p;
}
static uintptr_t raw(void *p) {return (uintptr_t)ptrauth_strip(p,ptrauth_key_function_pointer);}
static void client_callout(void *context,dispatch_function_t function) {
    ClientCallout call=(ClientCallout)__atomic_load_n(&original,__ATOMIC_ACQUIRE);
    int saved=errno;
    BOOL matchingContext=(uintptr_t)context==atomic_load(&probeContext) && atomic_load(&probeContext);
    if(!matchingContext && (!atomic_load(&ready) || !atomic_load(&enabled) || !DHFlowCallbackCaptureActive())){errno=saved;call(context,function);return;}
    atomic_fetch_add(&forwarded,1);
    BOOL probe=(uintptr_t)context==atomic_load(&probeContext) && raw((void *)function)==atomic_load(&probeFunction);
    if((uintptr_t)context==atomic_load(&probeContext) && atomic_load(&probeContext)) {
        if(probe)atomic_fetch_add(&probeEntries,1);else atomic_fetch_add(&probeMismatches,1);
    }
    if(!atomic_load(&ready) || !atomic_load(&enabled) || !DHFlowCallbackCaptureActive()) {
        errno=saved;call(context,function);return;
    }
    DHFlowBoundary();
    if(dh_call_async()){errno=saved;call(context,function);return;}
    // Never turn IDH's own log/HTTP/fixture work into App roots. Only an explicit
    // owned calibration on this dedicated queue may bypass this image check.
    Dl_info image={0};int internal=dh_in_hook;dh_in_hook=1;
    BOOL app=dladdr((void *)raw((void *)function),&image) && image.dli_fname && strstr(image.dli_fname,".app/") && (uintptr_t)image.dli_fbase!=agentBase;
    dh_in_hook=internal;
    BOOL fixture=probe && atomic_load(&ownedTest);
    if(!app && !fixture){errno=saved;call(context,function);return;}
    char queue[128];strlcpy(queue,dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL)?:"",sizeof(queue));
    atomic_fetch_add(&selectedAttempts,1);
    if(fixture)DHFlowSetOwnedFixtureScope(YES);
    @try {
        errno=saved;
        DHFlowRunEntry("libdispatch.client-callout",queue,__builtin_return_address(0),(void *)function,^{call(context,function);});
    } @finally {if(fixture)DHFlowSetOwnedFixtureScope(NO);}
}
__attribute__((noinline)) static void probe_event(void *context) {
    DHDispatchEntryProbe *p=(__bridge DHDispatchEntryProbe *)context;p->caller=raw(__builtin_return_address(0));
    if(p->marker!=0x484449535043414cULL)p->failures++;
    p->calls++;NSDictionary *fields=DHFlowFields(dh_call_async());
    [p->observations addObject:@{@"task":fields[@"asyncTaskId"]?:@"",@"registration":fields[@"asyncRegistrationId"]?:@"",@"context":[NSString stringWithFormat:@"0x%llx",(uint64_t)context],@"thread":@(pthread_mach_thread_np(pthread_self()))}];
    errno=E2BIG;dispatch_semaphore_signal(p->wake);
}
static BOOL tick(dispatch_source_t source,DHDispatchEntryProbe *probe) {
    dispatch_source_merge_data(source,1);
    return dispatch_semaphore_wait(probe->wake,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0;
}
static void drain(dispatch_queue_t queue) {dispatch_sync(queue,^{});}
static BOOL validate_callout(uintptr_t caller,uintptr_t *entry) {
    candidateCaller=caller;uint64_t start=0,end=0;if(!caller || !dh_unwind_bounds(caller-4,&start,&end))return NO;
    candidateStart=start;candidateEnd=end;if(end<=start || end-start>128)return NO;
    uint32_t words[8]={0};vm_size_t got=0;
    if(vm_read_overwrite(mach_task_self(),start,sizeof(words),(vm_address_t)words,&got)!=KERN_SUCCESS || got!=sizeof(words))return NO;
    memcpy(candidateWords,words,sizeof(words));
    // Exact context/function call sequence and return, including PAC variant.
    // Unsupported compiler/runtime forms are reported without patching them.
    // The observed modern macOS runtime has the same typed call with a compact
    // FP/LR-only frame and no in-function catch paths. Require its exact extent.
    BOOL good=dh_dispatch_callout_prefix_valid(start,end,caller,words);
    if(!good)return NO;
    Dl_info info={0};int internal=dh_in_hook;dh_in_hook=1;BOOL image=dladdr((void *)start,&info) && info.dli_fname && strstr(info.dli_fname,"/libdispatch.dylib");dh_in_hook=internal;
    if(!image)return NO;*entry=(uintptr_t)start;return YES;
}
static BOOL prepare(void) {
    if(atomic_load(&ready))return YES;
    if(atomic_exchange(&attempted,YES)){strlcpy(reason,"partial private dispatcher preparation retained; restart before retry",sizeof(reason));return NO;}
    if(!dh_thunk_inline_available()){strlcpy(reason,"native Inline backend unavailable",sizeof(reason));return NO;}
    Dl_info own={0};int internal=dh_in_hook;dh_in_hook=1;dladdr((void *)prepare,&own);dh_in_hook=internal;agentBase=(uintptr_t)own.dli_fbase;
    DHDispatchEntryProbe *probe=new_probe();
    dispatch_queue_t queue=dispatch_queue_create("com.iosdecrypthub.dispatch-entry.calibration",DISPATCH_QUEUE_SERIAL);
    dispatch_source_t source=dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD,0,0,queue);
    dispatch_set_context(source,(__bridge void *)probe);dispatch_source_set_event_handler_f(source,probe_event);
    // The source's cancellation block owns the fixture context until disposal,
    // even if a scheduler timeout lets the control operation return earlier.
    dispatch_source_set_cancel_handler(source,^{dispatch_semaphore_signal(probe->cancelled);});dispatch_resume(source);
    BOOL ok=NO;
    @try {
        if(!tick(source,probe)){strlcpy(reason,"owned source did not execute before calibration",sizeof(reason));return NO;}drain(queue);
        if(!validate_callout(probe->caller,&target)){strlcpy(reason,"owned callback caller is not a recognized complete two-pointer libdispatch ABI",sizeof(reason));return NO;}
        adapter=dh_thunk_install_adapter(target,(void *)client_callout,&original,"libdispatch private callout","void(void*, dispatch_function_t)",reason,sizeof(reason));
        if(adapter<0)return NO;
        atomic_store(&probeContext,(uintptr_t)(__bridge void *)probe);atomic_store(&probeFunction,raw((void *)probe_event));
        unsigned before=atomic_load(&probeEntries);
        if(!tick(source,probe)){strlcpy(reason,"typed private dispatcher original callback timed out",sizeof(reason));return NO;}drain(queue);
        ok=probe->calls==2 && !probe->failures && atomic_load(&probeEntries)==before+1 && !atomic_load(&probeMismatches);
        strlcpy(reason,ok?"owned source proved exact context/function and original repeat forwarding":"typed private dispatcher original argument/count mismatch",sizeof(reason));atomic_store(&ready,ok);
        return ok;
    } @finally {
        dispatch_source_cancel(source);dispatch_semaphore_wait(probe->cancelled,dispatch_time(DISPATCH_TIME_NOW,5000000000));drain(queue);
        atomic_store(&probeContext,0);atomic_store(&probeFunction,0);
    }
}
NSDictionary *DHDispatchEntryState(void) {
    pthread_mutex_lock(&prepareLock);
    NSMutableArray *words=[NSMutableArray array];for(unsigned i=0;i<8;i++)[words addObject:[NSString stringWithFormat:@"0x%08x",candidateWords[i]]];
    NSDictionary *state=@{@"processGeneration":DHProcessGeneration(),@"ready":@(atomic_load(&ready)),@"enabled":@(atomic_load(&enabled)),@"attempted":@(atomic_load(&attempted)),@"reason":@(reason),@"retainedUntilRestart":@(adapter>=0),@"adapter":adapter>=0?dh_thunk_adapter_metadata(adapter):@{},@"targetIdentity":target?DHTargetIdentity((void *)target):@{},@"observedForwarded":@(atomic_load(&forwarded)),@"selectedAttempts":@(atomic_load(&selectedAttempts)),@"probeEntries":@(atomic_load(&probeEntries)),@"probeMismatches":@(atomic_load(&probeMismatches)),@"candidateCaller":[NSString stringWithFormat:@"0x%llx",(uint64_t)candidateCaller],@"candidateStart":[NSString stringWithFormat:@"0x%llx",(uint64_t)candidateStart],@"candidateEnd":[NSString stringWithFormat:@"0x%llx",(uint64_t)candidateEnd],@"candidateWords":words};
    pthread_mutex_unlock(&prepareLock);return state;
}
NSDictionary *DHDispatchEntryConfigure(BOOL on) {
    if(pthread_mutex_trylock(&prepareLock))return @{@"ok":@NO,@"error":@"private dispatcher preparation busy"};
    BOOL ok=!on || prepare();if(ok)atomic_store(&enabled,on);NSString *error=@(reason);pthread_mutex_unlock(&prepareLock);
    return ok?@{@"ok":@YES,@"state":DHDispatchEntryState()}:@{@"ok":@NO,@"error":error,@"state":DHDispatchEntryState()};
}
NSDictionary *DHDispatchEntrySelfTest(void) {
    if([DHFlowState()[@"enabled"] boolValue])return @{@"ok":@NO,@"error":@"refuses to replace an active async window"};
    if(pthread_mutex_trylock(&prepareLock))return @{@"ok":@NO,@"error":@"private dispatcher preparation busy"};
    BOOL ok=NO;NSMutableArray *groups=[NSMutableArray array];NSDictionary *result;
    @try {
        if(!prepare())return @{@"ok":@NO,@"error":@(reason)};
        [groups addObject:@"actual-owned-source-caller-recognized-typed-two-pointer-ABI"];
        DHDispatchEntryProbe *probe=new_probe();
        dispatch_queue_t queue=dispatch_queue_create("com.iosdecrypthub.dispatch-entry.fixture",DISPATCH_QUEUE_SERIAL);
        dispatch_source_t source=dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD,0,0,queue);
        dispatch_set_context(source,(__bridge void *)probe);dispatch_source_set_event_handler_f(source,probe_event);dispatch_source_set_cancel_handler(source,^{dispatch_semaphore_signal(probe->cancelled);});dispatch_resume(source);
        atomic_store(&probeContext,(uintptr_t)(__bridge void *)probe);atomic_store(&probeFunction,raw((void *)probe_event));atomic_store(&ownedTest,YES);
        unsigned first=[DHFlowState()[@"retained"] unsignedIntValue];
        @try {
            atomic_store(&enabled,NO);if(!tick(source,probe))return @{@"ok":@NO,@"error":@"default-off original callback timeout"};drain(queue);
            if([probe->observations[0][@"task"] length])return @{@"ok":@NO,@"error":@"disabled private adapter fabricated task"};
            [groups addObject:@"default-off-preserves-original-context-and-work"];
            NSDictionary *flow=DHFlowConfigureWithAPIs(YES,YES,4,10000,nil,@[@"dispatch-entry.fixture"],@[@"libdispatch.client-callout"]);
            if(![flow[@"ok"] boolValue])return flow;atomic_store(&enabled,YES);
            if(!tick(source,probe))return @{@"ok":@NO,@"error":@"first real private delivery timeout"};drain(queue);
            if(!tick(source,probe))return @{@"ok":@NO,@"error":@"repeated real private delivery timeout"};drain(queue);
            DHFlowConfigure(NO,NO,1,1,nil,nil);atomic_store(&enabled,NO);
            if(!tick(source,probe))return @{@"ok":@NO,@"error":@"disabled-after-capture callback timeout"};drain(queue);
            NSArray *tasks=DHFlowRead(first,8,0)[@"tasks"];
            ok=tasks.count==2 && probe->calls==4 && !probe->failures && !atomic_load(&probeMismatches);
            NSMutableSet *ids=[NSMutableSet set];for(NSDictionary *task in tasks){[ids addObject:task[@"asyncTaskId"]];ok&=[task[@"state"] isEqual:@"completed"] && [task[@"edge"] isEqual:@"observed-callback-entry; registration-unobserved"] && ![task[@"registrationId"] length] && ![task[@"asyncSubmittedByCallId"] length];}
            ok&=ids.count==2 && [probe->observations[1][@"task"] length] && [probe->observations[2][@"task"] length] && ![probe->observations[3][@"task"] length];
            if(ok){[groups addObject:@"preexisting-source-real-repeated-callbacks-without-invented-registration"];[groups addObject:@"disable-keeps-original-work-and-no-new-task"];}
            result=@{@"ok":@(ok),@"passed":groups,@"tasks":tasks,@"observations":[probe->observations copy]};
        } @finally {
            atomic_store(&enabled,NO);DHFlowConfigure(NO,NO,1,1,nil,nil);
            dispatch_source_cancel(source);dispatch_semaphore_wait(probe->cancelled,dispatch_time(DISPATCH_TIME_NOW,5000000000));drain(queue);
            atomic_store(&ownedTest,NO);atomic_store(&probeContext,0);atomic_store(&probeFunction,0);
        }
    } @finally {pthread_mutex_unlock(&prepareLock);}
    return result?:@{@"ok":@NO,@"error":@"private dispatcher selftest incomplete"};
}
