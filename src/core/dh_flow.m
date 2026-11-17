#import "dh_flow.h"
#import "dh_flow_sources.h"
#import "dh_flow_timers.h"
#import "dh_event.h"
#import "dh_call_context.h"
#import "log_store.h"
#import "fishhook.h"
#include "dh_health.h"
#include "../trace/qbdi_live.h"
#include <pthread.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <ptrauth.h>
#include <errno.h>
#include <string.h>
#include <objc/runtime.h>

extern void dh_thunk_abandon(unsigned slot,uint64_t token,const char *reason,const DHCallContext *saved);
extern int dh_thunk_post_frame(uint64_t pc,uint64_t sp,uint64_t callerSP);
extern int dh_thunk_in_handler(void);
extern int dh_thunk_has_import(const char *name);
enum { FLOW_CAP=1024,FLOW_PENDING=64,FLOW_DEPTH=8 };
typedef struct {int slot;uint64_t token,sp;DHCallContext saved;} FlowGuard;
typedef struct FlowTask {
    uint64_t id,parent,call,submitted,started,finished,submitThread,thread,caller,callback,creationCaller;
    uint64_t scopeSP,*cookie; struct FlowTask *previous;
    void *context;dispatch_function_t function;
    int state,depth;unsigned associationGaps; // 1 pending, 2 running, 3 completed, 4 aborted
    char api[64],queue[128],terminal[64],callbackLabel[192];DHRawStack stack;
    uint64_t registration,delivery;
    unsigned edgeKind;uint64_t enteredCall;
    uint64_t checkedCookie,checkedScopeSP,checkedBodyPC,checkedBodySP;
} FlowTask;
typedef struct {
    uint64_t parent,call,caller,callback,creationCaller,when,thread,window;
    char queue[128],callbackLabel[192];
} FlowOrigin;
enum { FLOW_REGISTRATIONS=128 };
typedef struct {
    uint64_t id,window,invoked,captured,retired;
    BOOL active;FlowOrigin origin;DHRawStack stack;
    char api[64],originalQueue[128],terminal[64];
} FlowRegistration;
static pthread_mutex_t flowLock=PTHREAD_MUTEX_INITIALIZER;
static FlowTask tasks[FLOW_CAP];static unsigned taskCount,pending,windowCount,windowLimit;
static FlowRegistration registrations[FLOW_REGISTRATIONS];static unsigned registrationCount,windowRegistrations;
static uint64_t deadline,bodyStart,bodyEnd;static BOOL enabled,captureRoots;static _Atomic int installed;
static _Atomic int gateOn;
static _Atomic int claiming;
static char excludedQueues[8][128];static unsigned excludedCount;
static char rootQueues[8][128];static unsigned rootQueueCount;
static char rootAPIs[8][128];static unsigned rootAPICount;
static char rootCallbacks[8][128];static unsigned rootCallbackCount;static _Atomic uint64_t rootCallbackMisses;
static uint64_t windowStarted;static char stopReason[32]="disabled";
static _Atomic uint64_t rootQueueMisses,queueExclusions;
static _Atomic uint64_t rootAPIMisses;
static _Atomic uint64_t abandoned,unverified,guardOverflow,rejected,hiddenToken;
static _Atomic uint64_t skippedBlocks;
enum { FLOW_DIAGNOSTICS=16,FLOW_DIAGNOSTIC_REASONS=6 };
static const char *diagnosticReasons[]={"frame-budget","unwind-error","unwind-incomplete","stopped-before-guard","stopped-before-async-scope","wrapper-not-observed"};
typedef struct {uint64_t sequence,thread,when,task,anchor;unsigned reason;DHRawStack stack;} FlowDiagnostic;
static FlowDiagnostic diagnostics[FLOW_DIAGNOSTICS];static uint64_t diagnosticSequence,reasonCounts[FLOW_DIAGNOSTIC_REASONS];
static _Atomic uint64_t verifiedPartial;
static uintptr_t specialInvoke;static void *agentBase;
static uint64_t specialAsyncStart,specialAsyncEnd;
static unsigned specialCreated,windowSpecialCreated;
static _Atomic uint64_t specialUnresolved;
static const char specialBindingKey;
static void task_unresolved(FlowTask *task,const char *reason);
@interface DHFlowBlockBinding:NSObject {
@public FlowTask *task;BOOL submitted,started,reused;uintptr_t invoke,caller;
}
@end
@implementation DHFlowBlockBinding
- (void)dealloc {if(task)task_unresolved(task,"block-released-without-observed-start");}
@end
static __thread FlowGuard guards[64];static __thread unsigned guardCount;
static __thread int busy;static __thread FlowTask *current;
static __thread BOOL ownedFixtureScope;
static __thread int atTaskEntry;
typedef struct {FlowGuard guards[64];unsigned count;FlowTask *current;} FlowExitState;
static __thread FlowExitState *exitState;
static pthread_key_t exitKey;static pthread_once_t keyOnce=PTHREAD_ONCE_INIT;
static void task_end(FlowTask *task,BOOL normal,const char *reason);
static void on_exit(void *opaque) {
    // Darwin may dispose compiler TLV storage before pthread-key destructors.
    FlowExitState *state=opaque;exitState=state;busy=1;
    while (state->count) {FlowGuard g=state->guards[--state->count];dh_thunk_abandon(g.slot,g.token,"thread-exit",&g.saved);atomic_fetch_add(&abandoned,1);}
    current=state->current;
    while (current) {FlowTask *t=current;current=t->previous;task_end(t,NO,"thread-exit");}dh_call_set_async(0);guardCount=0;busy=0;
    exitState=NULL;pthread_setspecific(exitKey,NULL);free(state);
}
static void make_key(void) {pthread_key_create(&exitKey,on_exit);}
static void register_thread(void) {pthread_once(&keyOnce,make_key);if(!exitState){exitState=calloc(1,sizeof(*exitState));if(exitState)pthread_setspecific(exitKey,exitState);}}
static void mirror(void) {if(exitState){exitState->count=guardCount;memcpy(exitState->guards,guards,guardCount*sizeof(*guards));exitState->current=current;}}
static NSString *task_id(uint64_t token) {return token?[NSString stringWithFormat:@"%@:async:%llu",DHProcessGeneration(),token]:@"";}
static NSString *registration_id(uint64_t token) {return token?[NSString stringWithFormat:@"%@:registration:%llu",DHProcessGeneration(),token]:@"";}
static NSString *queue_text(const char *label) {
    size_t length=strnlen(label,128);
    for(unsigned drop=0;drop<4 && drop<=length;drop++) {
        NSString *text=[[NSString alloc] initWithBytes:label length:length-drop encoding:NSUTF8StringEncoding];if(text)return text;
    }
    return @"<invalid-or-truncated-UTF8-queue>";
}
NSDictionary *DHFlowFields(uint64_t token) {
    if (!token || token>FLOW_CAP) return @{@"asyncTaskId":@"",@"asyncParentTaskId":@"",@"asyncSubmittedByCallId":@""};
    FlowTask *t=&tasks[token-1];NSMutableDictionary *result=[@{@"asyncTaskId":task_id(token),@"asyncParentTaskId":task_id(t->parent),@"asyncSubmittedByCallId":DHCallID(t->call)} mutableCopy];
    if(t->registration)result[@"asyncRegistrationId"]=registration_id(t->registration);
    if(t->edgeKind==2)result[@"asyncEnteredByCallId"]=DHCallID(t->enteredCall);return result;
}
static void task_event(FlowTask *task,NSString *phase) {
    int saved=dh_in_hook;dh_in_hook=1;busy++;
    @autoreleasepool {
        DHLogEntry *e=[DHLogEntry new];e.category=DHCategoryOther;e.algorithm=task->edgeKind==2?@"runtime-callback-entry":task->registration?@"registered-callback":@"gcd-async";e.operation=@(task->api);
        DHStampEvent(e);NSMutableDictionary *c=[e.eventContext mutableCopy];c[@"kind"]=@"async-task";c[@"phase"]=phase;
        c[@"parentCallId"]=@"";[c addEntriesFromDictionary:DHFlowFields(task->id)];e.eventContext=c;
        e.eventPayload=@{@"queue":queue_text(task->queue),@"submissionThreadId":@(task->submitThread),@"executionThreadId":@(task->thread),@"edge":task->edgeKind==2?@"observed-callback-entry; registration-unobserved":task->registration?@"registered-handler-to-callback":@"observed-submit-to-execute",@"registrationId":registration_id(task->registration),@"terminalReason":@(task->terminal)};
        [[DHLogStore shared] append:e];
    }
    busy--;dh_in_hook=saved;
}
static void uncertain_boundary(const DHRawStack *stack,unsigned reason,uint64_t anchor) {
    int savedErrno=errno;
    uint64_t thread=0;pthread_threadid_np(NULL,&thread);
    pthread_mutex_lock(&flowLock);atomic_fetch_add(&unverified,1);reasonCounts[reason]++;
    uint64_t sequence=++diagnosticSequence;FlowDiagnostic *record=&diagnostics[(sequence-1)%FLOW_DIAGNOSTICS];
    *record=(FlowDiagnostic){.sequence=sequence,.thread=thread,.when=DHMonotonicNS(),.task=current?current->id:0,.anchor=anchor,.reason=reason,.stack=*stack};
    pthread_mutex_unlock(&flowLock);dh_call_set_trust(0);errno=savedErrno;
}
void DHFlowCheck(const DHRawStack *stack) {
    if (busy || dh_live_current()) return;
    if(!guardCount && !current) {dh_call_set_trust(1);return;}
    if (!stack->complete || stack->error || stack->truncated) {
        // Presence proves a live owned scope even when frames above it cannot
        // be recovered. Absence in a partial walk never proves an exit.
        BOOL allPresent=YES;
        for(unsigned n=0;n<guardCount;n++) {
            BOOL found=NO;for(unsigned i=0;i<stack->count;i++)if(dh_thunk_post_frame(stack->pc[i],stack->sp[i],guards[n].sp)){found=YES;break;}
            allPresent&=found;
        }
        if(current) {
            BOOL found=NO;if(current->cookie && *current->cookie==current->id)
                for(unsigned i=0;i<stack->count;i++)if(stack->pc[i]>=bodyStart && stack->pc[i]<bodyEnd && stack->sp[i]==current->scopeSP){found=YES;break;}
            allPresent&=found;
        }
        if(allPresent){atomic_fetch_add(&verifiedPartial,1);dh_call_set_trust(1);return;}
        uncertain_boundary(stack,stack->error?1:stack->truncated?0:2,current?current->scopeSP:guardCount?guards[guardCount-1].sp:0);return;
    }
    // A normal libunwind stop can still occur below a known frame (e.g. codec stubs).
    // Absence is evidence of exit only after the walk has actually passed its anchor.
    uint64_t lastSP=stack->count?stack->sp[stack->count-1]:0;
    for(unsigned n=0;n<guardCount;n++) {
        BOOL found=NO;for(unsigned i=0;i<stack->count;i++)if(dh_thunk_post_frame(stack->pc[i],stack->sp[i],guards[n].sp)){found=YES;break;}
        if(!found && lastSP<=guards[n].sp){uncertain_boundary(stack,3,guards[n].sp);return;}
    }
    if(current) {
        if(!current->scopeSP){uncertain_boundary(stack,4,0);return;}
        BOOL found=NO;for(unsigned i=0;i<stack->count;i++)if(stack->pc[i]>=bodyStart && stack->pc[i]<bodyEnd && stack->sp[i]==current->scopeSP){found=YES;break;}
        if(!found && lastSP<=current->scopeSP){uncertain_boundary(stack,4,current->scopeSP);return;}
    }
    dh_call_set_trust(1);
    int saved=errno;busy++;
    while (guardCount) {
        FlowGuard g=guards[guardCount-1];BOOL live=NO;
        for (unsigned i=0;i<stack->count;i++) if (dh_thunk_post_frame(stack->pc[i],stack->sp[i],g.sp)) {live=YES;break;}
        if (live) break;
        guardCount--;mirror();dh_thunk_abandon(g.slot,g.token,"nonlocal-exit-observed-at-boundary",&g.saved);atomic_fetch_add(&abandoned,1);
    }
    while (current) {
        FlowTask *task=current;BOOL live=NO;
        if (task->cookie && *task->cookie==task->id)
            for (unsigned i=0;i<stack->count;i++) if (stack->pc[i]>=bodyStart && stack->pc[i]<bodyEnd && stack->sp[i]==task->scopeSP) {live=YES;break;}
        if (live) break;
        if(!atTaskEntry) {
            // A probe inside App/native code is not an authoritative callback exit.
            // Suppress uncertain associations; normal/exception wrapper exit or a
            // verified subsequent callback entry owns terminal accounting.
            pthread_mutex_lock(&flowLock);task->associationGaps++;pthread_mutex_unlock(&flowLock);
            uncertain_boundary(stack,5,task->scopeSP);mirror();busy--;errno=saved;return;
        }
        task->checkedCookie=task->cookie?*task->cookie:0;task->checkedScopeSP=task->scopeSP;
        for(unsigned i=0;i<stack->count;i++)if(stack->pc[i]>=bodyStart && stack->pc[i]<bodyEnd){task->checkedBodyPC=stack->pc[i];task->checkedBodySP=stack->sp[i];break;}
        current=task->previous;task_end(task,NO,task->checkedCookie!=task->id?"scope-cookie-replaced-at-boundary":"wrapper-frame-absent-at-complete-boundary");
    }
    mirror();dh_call_set_async(current?current->id:0);busy--;errno=saved;
}
void DHFlowBoundary(void) {
    if (busy || dh_thunk_in_handler() || dh_live_current() || (!guardCount && !current)) return;
    int saved=errno;DHRawStack stack;dh_unwind_current(&stack);DHFlowCheck(&stack);errno=saved;
}
uint64_t DHFlowGuardBegin(int slot,uint64_t sp) {
    uint64_t token=(1ULL<<63)|(atomic_fetch_add(&hiddenToken,1)+1);register_thread();
    if (guardCount==64) {atomic_fetch_add(&guardOverflow,1);return token;}
    guards[guardCount++]=(FlowGuard){.slot=slot,.token=token,.sp=sp};mirror();return token;
}
void DHFlowGuardBind(uint64_t guard,const DHCallContext *call) {for (unsigned i=guardCount;i>0;i--) if (guards[i-1].token==guard) {guards[i-1].token=call->id;guards[i-1].saved=*call;break;}mirror();}
void DHFlowGuardEnd(uint64_t token) {
    if (!token) return;
    for (unsigned i=guardCount;i>0;i--) if (guards[i-1].token==token) {memmove(guards+i-1,guards+i,(guardCount-i)*sizeof(*guards));guardCount--;break;}
    mirror();if(!guardCount && !current)dh_call_set_trust(1);
}
static void task_end(FlowTask *task,BOOL normal,const char *reason) {
    pthread_mutex_lock(&flowLock);BOOL active=task->state<=2;
    if (active) {task->state=normal?3:4;strlcpy(task->terminal,reason,sizeof(task->terminal));task->finished=DHMonotonicNS();if(pending)pending--;task->cookie=NULL;}
    pthread_mutex_unlock(&flowLock);if(active)task_event(task,normal?@"complete":@"aborted");
}
static void task_unresolved(FlowTask *task,const char *reason) {
    int savedErrno=errno;
    pthread_mutex_lock(&flowLock);BOOL pendingTask=task->state==1;
    if(pendingTask){task->state=5;strlcpy(task->terminal,reason,sizeof(task->terminal));task->finished=DHMonotonicNS();if(pending)pending--;atomic_fetch_add(&specialUnresolved,1);}
    pthread_mutex_unlock(&flowLock);if(pendingTask)task_event(task,@"unresolved");errno=savedErrno;
}
// Metadata bounds and the actual wrapper SP identify a live async scope, not a thread ID guess.
__attribute__((noinline,optnone)) void DHAsyncExecute(FlowTask *task,dispatch_block_t body) {
    int entryErrno=errno;volatile uint64_t cookie=task->id;atTaskEntry=1;DHFlowBoundary();atTaskEntry=0;register_thread();
    DHRawStack stack;dh_unwind_current(&stack);uint64_t sp=0;
    for (unsigned i=0;i<stack.count;i++) if(stack.pc[i]>=bodyStart && stack.pc[i]<bodyEnd) {sp=stack.sp[i];break;}
    pthread_mutex_lock(&flowLock);task->scopeSP=sp;task->cookie=(uint64_t *)&cookie;task->previous=current;task->state=2;
    task->started=DHMonotonicNS();pthread_threadid_np(NULL,&task->thread);pthread_mutex_unlock(&flowLock);
    current=task;mirror();dh_call_set_async(task->id);task_event(task,@"start");BOOL normal=NO;errno=entryErrno;
    @try {body();normal=YES;}
    @finally {
        int finalErrno=errno;DHFlowBoundary();current=task->previous;mirror();dh_call_set_async(current?current->id:0);task_end(task,normal,normal?"normal-return":"exception-unwinding-wrapper");errno=finalErrno;
    }
}
static BOOL prepare_origin(const char *api,const char *label,void *caller,void *callback,uintptr_t creationCaller,BOOL runtimeEntry,const char *callbackLabel,FlowOrigin *out) {
    if (!atomic_load(&gateOn) || busy || dh_in_hook || dh_live_current()) return NO;
    int saved=errno;caller=ptrauth_strip(caller,ptrauth_key_function_pointer);
    Dl_info origin={0};int internalCaller=dh_in_hook;dh_in_hook=1;dladdr(caller,&origin);dh_in_hook=internalCaller;
    if(origin.dli_fbase==agentBase && strcmp(label,"com.iosdecrypthub.flow.fixture") && !ownedFixtureScope) {errno=saved;return NO;}
    DHFlowBoundary();uint64_t parent=dh_call_async(),call=dh_call_parent();
    pthread_mutex_lock(&flowLock);
    if (!enabled || DHMonotonicNS()>deadline) {if(enabled)strlcpy(stopReason,"expired",sizeof(stopReason));enabled=NO;atomic_store(&gateOn,0);pthread_mutex_unlock(&flowLock);errno=saved;return NO;}
    BOOL roots=captureRoots;pthread_mutex_unlock(&flowLock);
    if (!parent && !call) {
        if (!roots) {errno=saved;return NO;}
        Dl_info info={0};int internal=dh_in_hook;dh_in_hook=1;BOOL app=dladdr(caller,&info) && info.dli_fname && strstr(info.dli_fname,".app/");dh_in_hook=internal;
        if (!app && !runtimeEntry) {errno=saved;return NO;}
    }
    pthread_mutex_lock(&flowLock);
    for(unsigned i=0;i<excludedCount;i++)if(strcasestr(label,excludedQueues[i])) {atomic_fetch_add(&queueExclusions,1);pthread_mutex_unlock(&flowLock);errno=saved;return NO;}
    // Select graph roots, including roots submitted by a synchronous hook. Once
    // selected, children may change queues without severing their observed edge.
    if(!parent && rootQueueCount) {
        BOOL match=NO;for(unsigned i=0;i<rootQueueCount;i++)if(strcasestr(label,rootQueues[i])){match=YES;break;}
        if(!match){atomic_fetch_add(&rootQueueMisses,1);pthread_mutex_unlock(&flowLock);errno=saved;return NO;}
    }
    if(!parent && rootAPICount) {
        BOOL match=NO;for(unsigned i=0;i<rootAPICount;i++)if(strcasestr(api,rootAPIs[i])){match=YES;break;}
        if(!match){atomic_fetch_add(&rootAPIMisses,1);pthread_mutex_unlock(&flowLock);errno=saved;return NO;}
    }
    if(!parent && rootCallbackCount) {
        BOOL match=NO;for(unsigned i=0;i<rootCallbackCount;i++)if(callbackLabel && strcasestr(callbackLabel,rootCallbacks[i])){match=YES;break;}
        if(!match){atomic_fetch_add(&rootCallbackMisses,1);pthread_mutex_unlock(&flowLock);errno=saved;return NO;}
    }
    memset(out,0,sizeof(*out));strlcpy(out->callbackLabel,callbackLabel?:"",sizeof(out->callbackLabel));out->parent=parent;out->call=call;out->caller=(uint64_t)caller;out->callback=(uint64_t)ptrauth_strip(callback,ptrauth_key_function_pointer);out->creationCaller=creationCaller;out->when=DHMonotonicNS();out->window=windowStarted;
    pthread_threadid_np(NULL,&out->thread);strlcpy(out->queue,label,sizeof(out->queue));pthread_mutex_unlock(&flowLock);errno=saved;return YES;
}
static FlowTask *reserve_task(const char *api,const FlowOrigin *origin,uint64_t registration,const DHRawStack *sourceStack,BOOL runtimeEntry) {
    int saved=errno;pthread_mutex_lock(&flowLock);unsigned depth=origin->parent?tasks[origin->parent-1].depth+1:0;
    if (!enabled || origin->window!=windowStarted || DHMonotonicNS()>deadline || taskCount==FLOW_CAP || pending>=FLOW_PENDING || windowCount>=windowLimit || depth>=FLOW_DEPTH) {
        atomic_fetch_add(&rejected,1);pthread_mutex_unlock(&flowLock);errno=saved;return NULL;
    }
    FlowTask *t=&tasks[taskCount++];t->id=taskCount;t->parent=origin->parent;t->call=origin->call;t->depth=depth;t->state=1;t->caller=origin->caller;t->callback=origin->callback;t->creationCaller=origin->creationCaller;t->submitted=origin->when;t->submitThread=origin->thread;t->registration=registration;t->delivery=registration?DHMonotonicNS():0;pending++;windowCount++;
    t->edgeKind=runtimeEntry?2:registration?1:0;if(runtimeEntry){t->enteredCall=t->call;t->call=0;t->delivery=DHMonotonicNS();}
    strlcpy(t->api,api,sizeof(t->api));strlcpy(t->queue,origin->queue,sizeof(t->queue));strlcpy(t->callbackLabel,origin->callbackLabel,sizeof(t->callbackLabel));
    if(windowCount==windowLimit || taskCount==FLOW_CAP){strlcpy(stopReason,taskCount==FLOW_CAP?"record-capacity":"task-budget",sizeof(stopReason));atomic_store(&gateOn,0);}
    pthread_mutex_unlock(&flowLock);
    int internal=dh_in_hook;dh_in_hook=1;busy++;DHRawStack raw;
    if(sourceStack)raw=*sourceStack;else dh_unwind_current(&raw);
    if (raw.count>32) {raw.count=32;raw.complete=0;raw.truncated=1;raw.stopReason=DH_UNWIND_FRAME_LIMIT;}
    pthread_mutex_lock(&flowLock);t->stack=raw;pthread_mutex_unlock(&flowLock);
    task_event(t,runtimeEntry?@"callback-entry":registration?@"delivery":@"submit");busy--;dh_in_hook=internal;errno=saved;return t;
}
static FlowTask *select_task(const char *api,dispatch_queue_t queue,void *caller,void *callback,uintptr_t creationCaller) {
    if(!DHFlowCallbackCaptureActive())return NULL;
    int saved=errno;FlowOrigin origin;BOOL selected=prepare_origin(api,dispatch_queue_get_label(queue)?:"",caller,callback,creationCaller,NO,NULL,&origin);
    FlowTask *task=selected?reserve_task(api,&origin,0,NULL,NO):NULL;errno=saved;return task;
}
int DHFlowCallbackCaptureActive(void) {return atomic_load(&gateOn) && !busy && !dh_in_hook && !dh_live_current();}
uint64_t DHFlowRegisterCallback(const char *api,const char *queue,void *caller,void *callback) {return DHFlowRegisterNamedCallback(api,queue,caller,callback,NULL);}
uint64_t DHFlowRegisterNamedCallback(const char *api,const char *queue,void *caller,void *callback,const char *label) {
    int saved=errno;FlowOrigin origin;if(!prepare_origin(api,queue?:"",caller,callback,0,NO,label,&origin)){errno=saved;return 0;}
    DHRawStack raw;busy++;dh_unwind_current(&raw);busy--;
    if(raw.count>32){raw.count=32;raw.complete=0;raw.truncated=1;raw.stopReason=DH_UNWIND_FRAME_LIMIT;}
    pthread_mutex_lock(&flowLock);uint64_t token=0;
    if(enabled && origin.window==windowStarted && DHMonotonicNS()<=deadline && registrationCount<FLOW_REGISTRATIONS && windowRegistrations<windowLimit) {
        FlowRegistration *r=&registrations[registrationCount++];r->id=token=registrationCount;r->window=windowStarted;r->active=YES;r->origin=origin;r->stack=raw;
        strlcpy(r->api,api,sizeof(r->api));strlcpy(r->originalQueue,origin.queue,sizeof(r->originalQueue));windowRegistrations++;
    } else atomic_fetch_add(&rejected,1);
    pthread_mutex_unlock(&flowLock);errno=saved;return token;
}
void DHFlowRetireCallback(uint64_t token,const char *reason) {
    if(!token || token>FLOW_REGISTRATIONS)return;int saved=errno;pthread_mutex_lock(&flowLock);
    if(token<=registrationCount && registrations[token-1].active){FlowRegistration *r=&registrations[token-1];r->active=NO;r->retired=DHMonotonicNS();strlcpy(r->terminal,reason,sizeof(r->terminal));}
    pthread_mutex_unlock(&flowLock);errno=saved;
}
void DHFlowUpdateCallbackQueue(uint64_t token,const char *queue) {
    if(!token || token>FLOW_REGISTRATIONS)return;int saved=errno;pthread_mutex_lock(&flowLock);
    if(token<=registrationCount)strlcpy(registrations[token-1].origin.queue,queue?:"",128);
    pthread_mutex_unlock(&flowLock);errno=saved;
}
int DHFlowRegistrationState(uint64_t token) {
    int state=0;pthread_mutex_lock(&flowLock);
    if(token && token<=registrationCount && registrations[token-1].active)state=registrations[token-1].window==windowStarted?1:2;
    pthread_mutex_unlock(&flowLock);return state;
}
void DHFlowAdapterInternalBegin(void) {busy++;}
void DHFlowAdapterInternalEnd(void) {busy--;}
void DHFlowSetOwnedFixtureScope(BOOL on) {ownedFixtureScope=on;}
void DHFlowRunCallback(uint64_t token,dispatch_block_t body) {
    if(!token || token>FLOW_REGISTRATIONS){body();return;}int saved=errno;FlowRegistration copy={0};BOOL selected=NO,capture=DHFlowCallbackCaptureActive();
    pthread_mutex_lock(&flowLock);
    if(token<=registrationCount){FlowRegistration *r=&registrations[token-1];r->invoked++;selected=capture && r->active && r->window==windowStarted && enabled && DHMonotonicNS()<=deadline;copy=*r;}
    pthread_mutex_unlock(&flowLock);
    FlowTask *task=selected?reserve_task(copy.api,&copy.origin,token,&copy.stack,NO):NULL;
    if(task){pthread_mutex_lock(&flowLock);registrations[token-1].captured++;pthread_mutex_unlock(&flowLock);}
    errno=saved;if(task)DHAsyncExecute(task,body);else body();
}
void DHFlowRunEntry(const char *api,const char *queue,void *caller,void *callback,dispatch_block_t body) {
    int saved=errno;pthread_mutex_lock(&flowLock);BOOL roots=captureRoots;pthread_mutex_unlock(&flowLock);
    FlowOrigin origin;BOOL selected=roots && prepare_origin(api,queue?:"",caller,callback,0,YES,NULL,&origin);
    FlowTask *task=selected?reserve_task(api,&origin,0,NULL,YES):NULL;errno=saved;if(task)DHAsyncExecute(task,body);else body();
}
static void (*original_async)(dispatch_queue_t,dispatch_block_t);
static void (*original_after)(dispatch_time_t,dispatch_queue_t,dispatch_block_t);
static void (*original_group)(dispatch_group_t,dispatch_queue_t,dispatch_block_t);
static void (*original_async_f)(dispatch_queue_t,void *,dispatch_function_t);
static void (*original_after_f)(dispatch_time_t,dispatch_queue_t,void *,dispatch_function_t);
static void (*original_group_f)(dispatch_group_t,dispatch_queue_t,void *,dispatch_function_t);
static __typeof__(&dispatch_group_notify) original_notify;
static __typeof__(&dispatch_group_notify_f) original_notify_f;
static __typeof__(&dispatch_block_notify) original_block_notify;
static __typeof__(&dispatch_block_create) original_create;
static __typeof__(&dispatch_block_create_with_qos_class) original_create_qos;
static uintptr_t block_invoke(dispatch_block_t b) {
    uintptr_t bits=0;if(b)memcpy(&bits,(const char *)(__bridge const void *)b+16,8);
    return (uintptr_t)ptrauth_strip((void *)bits,ptrauth_key_function_pointer);
}
static BOOL plain_block(dispatch_block_t b) {
    if(!b || !atomic_load(&gateOn) || busy || dh_in_hook)return NO;uintptr_t invoke=block_invoke(b);if(invoke==specialInvoke) {atomic_fetch_add(&skippedBlocks,1);return NO;}
    Dl_info info={0};int saved=dh_in_hook;dh_in_hook=1;
    BOOL known=dladdr((void *)invoke,&info) && (info.dli_fbase==agentBase || (info.dli_fname && strstr(info.dli_fname,".app/")));dh_in_hook=saved;
    if(!known)atomic_fetch_add(&skippedBlocks,1);return known;
}
uintptr_t DHFlowCallbackBlockAddress(dispatch_block_t body) {return plain_block(body)?block_invoke(body):0;}
dispatch_block_t DHFlowWrapOneShot(const char *api,const char *queue,void *caller,dispatch_block_t body) {
    int saved=errno;uintptr_t callback=DHFlowCallbackBlockAddress(body);FlowOrigin origin;
    BOOL selected=callback && prepare_origin(api,queue?:"",caller,(void *)callback,0,NO,NULL,&origin);
    FlowTask *task=selected?reserve_task(api,&origin,0,NULL,NO):NULL;errno=saved;
    return task?^{DHAsyncExecute(task,body);}:body;
}
static FlowTask *block_task(const char *api,dispatch_queue_t q,dispatch_block_t b,void *caller) {
    if(!b || busy || dh_in_hook || dh_live_current())return NULL;
    if(block_invoke(b)!=specialInvoke)return plain_block(b)?select_task(api,q,caller,(void *)block_invoke(b),0):NULL;
    DHFlowBlockBinding *binding=objc_getAssociatedObject(b,&specialBindingKey);
    if(!binding){if(atomic_load(&gateOn))atomic_fetch_add(&skippedBlocks,1);return NULL;}
    // Keep the exact dispatch-block object at submission. Only a uniquely
    // observed first submission may bind its public-create inner callback.
    pthread_mutex_lock(&flowLock);BOOL reused=binding->submitted;binding->submitted=YES;
    FlowTask *lost=NULL;if(reused){binding->reused=YES;if(!binding->started){lost=binding->task;binding->task=NULL;}}
    pthread_mutex_unlock(&flowLock);
    if(lost)task_unresolved(lost,"block-reused-before-observed-start");
    if(reused || dispatch_block_testcancel(b))return NULL;
    FlowTask *t=select_task(api,q,caller,(void *)binding->invoke,binding->caller);
    pthread_mutex_lock(&flowLock);BOOL raced=binding->reused || binding->started;if(!raced)binding->task=t;pthread_mutex_unlock(&flowLock);
    if(t && raced)task_unresolved(t,"block-executed-or-reused-during-submission");
    return NULL; // Original outer object always goes to libdispatch unchanged.
}
static dispatch_block_t create_block(dispatch_block_flags_t flags,dispatch_qos_class_t qos,int priority,dispatch_block_t b,BOOL withQoS,void *caller) {
    int entryErrno=errno;
    if(!plain_block(b)){errno=entryErrno;return withQoS?original_create_qos(flags,qos,priority,b):original_create(flags,b);}
    pthread_mutex_lock(&flowLock);BOOL bounded=enabled && DHMonotonicNS()<=deadline && specialCreated<FLOW_CAP && windowSpecialCreated<windowLimit;
    if(bounded){specialCreated++;windowSpecialCreated++;}pthread_mutex_unlock(&flowLock);
    if(!bounded){errno=entryErrno;return withQoS?original_create_qos(flags,qos,priority,b):original_create(flags,b);}
    DHFlowBlockBinding *binding=[DHFlowBlockBinding new];binding->invoke=block_invoke(b);binding->caller=(uintptr_t)ptrauth_strip(caller,ptrauth_key_function_pointer);
    dispatch_block_t inner=^{
        int callbackErrno=errno;
        uintptr_t callerPC=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_function_pointer);
        BOOL asyncInvoker=callerPC>=specialAsyncStart && callerPC<specialAsyncEnd;
        pthread_mutex_lock(&flowLock);FlowTask *t=(!binding->started && !binding->reused)?binding->task:NULL;
        binding->started=YES;binding->task=NULL;pthread_mutex_unlock(&flowLock);
        if(t && !asyncInvoker){task_unresolved(t,"block-executed-outside-calibrated-async-invoker");t=NULL;}
        errno=callbackErrno;if(t)DHAsyncExecute(t,b);else b();
    };
    errno=entryErrno;
    dispatch_block_t outer=withQoS?original_create_qos(flags,qos,priority,inner):original_create(flags,inner);
    int finalErrno=errno;
    if(outer)objc_setAssociatedObject(outer,&specialBindingKey,binding,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    errno=finalErrno;return outer;
}
static __attribute__((ns_returns_retained)) dispatch_block_t wrap_create(dispatch_block_flags_t flags,dispatch_block_t b) {return create_block(flags,0,0,b,NO,__builtin_return_address(0));}
static __attribute__((ns_returns_retained)) dispatch_block_t wrap_create_qos(dispatch_block_flags_t flags,dispatch_qos_class_t qos,int priority,dispatch_block_t b) {return create_block(flags,qos,priority,b,YES,__builtin_return_address(0));}
static void wrap_async(dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=block_task("dispatch_async",q,b,__builtin_return_address(0));errno=saved;if(t)original_async(q,^{DHAsyncExecute(t,b);});else original_async(q,b);}
static void wrap_after(dispatch_time_t when,dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=block_task("dispatch_after",q,b,__builtin_return_address(0));errno=saved;if(t)original_after(when,q,^{DHAsyncExecute(t,b);});else original_after(when,q,b);}
static void wrap_group(dispatch_group_t g,dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=block_task("dispatch_group_async",q,b,__builtin_return_address(0));errno=saved;if(t)original_group(g,q,^{DHAsyncExecute(t,b);});else original_group(g,q,b);}
static void invoke_f(void *p) {FlowTask *t=p;DHAsyncExecute(t,^{t->function(t->context);});}
static void wrap_async_f(dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_async_f",q,__builtin_return_address(0),(void *)f,0);if(t){t->context=c;t->function=f;original_async_f(q,t,invoke_f);}else original_async_f(q,c,f);}
static void wrap_after_f(dispatch_time_t w,dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_after_f",q,__builtin_return_address(0),(void *)f,0);if(t){t->context=c;t->function=f;original_after_f(w,q,t,invoke_f);}else original_after_f(w,q,c,f);}
static void wrap_group_f(dispatch_group_t g,dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_group_async_f",q,__builtin_return_address(0),(void *)f,0);if(t){t->context=c;t->function=f;original_group_f(g,q,t,invoke_f);}else original_group_f(g,q,c,f);}
static void wrap_notify(dispatch_group_t group,dispatch_queue_t queue,dispatch_block_t body) {
    int saved=errno;FlowTask *task=block_task("dispatch_group_notify",queue,body,__builtin_return_address(0));errno=saved;
    if(task)original_notify(group,queue,^{DHAsyncExecute(task,body);});else original_notify(group,queue,body);
}
static void wrap_notify_f(dispatch_group_t group,dispatch_queue_t queue,void *context,dispatch_function_t body) {
    int saved=errno;FlowTask *task=select_task("dispatch_group_notify_f",queue,__builtin_return_address(0),(void *)body,0);errno=saved;
    if(task){task->context=context;task->function=body;original_notify_f(group,queue,task,invoke_f);}else original_notify_f(group,queue,context,body);
}
static void wrap_block_notify(dispatch_block_t dependency,dispatch_queue_t queue,dispatch_block_t notification) {
    int saved=errno;FlowTask *task=block_task("dispatch_block_notify",queue,notification,__builtin_return_address(0));errno=saved;
    if(task)original_block_notify(dependency,queue,^{DHAsyncExecute(task,notification);});else original_block_notify(dependency,queue,notification);
}
static void *symbol(const char *name) {void *p=dlsym(RTLD_DEFAULT,name);return p?ptrauth_sign_unauthenticated(ptrauth_strip(p,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0):NULL;}
static const char *ownedImports[]={"dispatch_async","dispatch_after","dispatch_group_async","dispatch_async_f","dispatch_after_f","dispatch_group_async_f","dispatch_block_create","dispatch_block_create_with_qos_class","dispatch_group_notify","dispatch_group_notify_f","dispatch_block_notify"};
int DHFlowOwnsImport(const char *name) {if((!atomic_load(&installed) && !atomic_load(&claiming)) || !name)return 0;for(unsigned i=0;i<sizeof(ownedImports)/sizeof(*ownedImports);i++)if(!strcmp(name,ownedImports[i]))return 1;return DHFlowSourceOwnsImport(name) || DHFlowTimerOwnsImport(name);}
static NSDictionary *claim_error(NSString *message) {atomic_store(&claiming,0);return @{@"ok":@NO,@"error":message};}
NSDictionary *DHFlowState(void) {
    pthread_mutex_lock(&flowLock);
    NSMutableArray *filters=[NSMutableArray array],*includes=[NSMutableArray array],*apis=[NSMutableArray array];for(unsigned i=0;i<excludedCount;i++)[filters addObject:@(excludedQueues[i])];for(unsigned i=0;i<rootQueueCount;i++)[includes addObject:@(rootQueues[i])];for(unsigned i=0;i<rootAPICount;i++)[apis addObject:@(rootAPIs[i])];
    const char *reason=(!strcmp(stopReason,"capturing") && DHMonotonicNS()>deadline)?"expired":stopReason;
    NSMutableDictionary *uncertain=[NSMutableDictionary dictionary];for(unsigned i=0;i<FLOW_DIAGNOSTIC_REASONS;i++)uncertain[@(diagnosticReasons[i])]=@(reasonCounts[i]);
    NSDictionary *r=@{@"enabled":@(atomic_load(&gateOn) && DHMonotonicNS()<=deadline),@"installed":@(installed),@"captureRoots":@(captureRoots),@"retained":@(taskCount),@"pendingOrRunning":@(pending),@"windowAccepted":@(windowCount),@"maxRecords":@1024,@"maxPending":@64,@"maxDepth":@8,@"retainedRegistrations":@(registrationCount),@"windowRegistrations":@(windowRegistrations),@"maxRegistrations":@(FLOW_REGISTRATIONS),
        @"abandonedCalls":@(atomic_load(&abandoned)),@"unverifiedBoundaries":@(atomic_load(&unverified)),@"unverifiedReasonCounts":uncertain,@"verifiedPartialBoundaries":@(atomic_load(&verifiedPartial)),@"retainedBoundaryDiagnostics":@(MIN(diagnosticSequence,(uint64_t)FLOW_DIAGNOSTICS)),@"guardOverflows":@(atomic_load(&guardOverflow)),@"rejectedTasks":@(atomic_load(&rejected)),@"skippedSpecialOrUnknownBlocks":@(atomic_load(&skippedBlocks)),@"specialBindingsCreated":@(specialCreated),@"specialUnresolved":@(atomic_load(&specialUnresolved)),@"queueExclude":filters,@"rootQueueInclude":includes,@"windowStopReason":@(reason),@"windowStartedNs":[NSString stringWithFormat:@"%llu",windowStarted],@"windowDeadlineNs":[NSString stringWithFormat:@"%llu",deadline],@"rootQueueMisses":@(atomic_load(&rootQueueMisses)),@"queueExclusions":@(atomic_load(&queueExclusions)),@"threadGuardCount":@(guardCount),@"threadAsyncTaskId":task_id(dh_call_async()),@"sourceAdapters":DHFlowSourceState()};
    NSMutableArray *callbacks=[NSMutableArray array];for(unsigned i=0;i<rootCallbackCount;i++)[callbacks addObject:@(rootCallbacks[i])];
    NSMutableDictionary *result=[r mutableCopy];result[@"rootCallbackInclude"]=callbacks;result[@"rootCallbackMisses"]=@(atomic_load(&rootCallbackMisses));result[@"rootAPIInclude"]=apis;result[@"rootAPIMisses"]=@(atomic_load(&rootAPIMisses));pthread_mutex_unlock(&flowLock);return result;
}
NSDictionary *DHFlowConfigure(BOOL on,BOOL roots,unsigned budget,unsigned ms,NSArray *excluded,NSArray *included) {
    return DHFlowConfigureWithAPIs(on,roots,budget,ms,excluded,included,nil);
}
NSDictionary *DHFlowConfigureWithAPIs(BOOL on,BOOL roots,unsigned budget,unsigned ms,NSArray *excluded,NSArray *included,NSArray *apis) {return DHFlowConfigureWithCallbacks(on,roots,budget,ms,excluded,included,apis,nil);}
NSDictionary *DHFlowConfigureWithCallbacks(BOOL on,BOOL roots,unsigned budget,unsigned ms,NSArray *excluded,NSArray *included,NSArray *apis,NSArray *callbacks) {
    if (on && (!budget || budget>256 || !ms || ms>60000)) return @{@"ok":@NO,@"error":@"async window requires 1..256 tasks / 1..60000ms"};
    for(id filters in @[(excluded?:@[]),(included?:@[]),(apis?:@[]),(callbacks?:@[])]) {
    if(![filters isKindOfClass:NSArray.class] || [filters count]>8)return @{@"ok":@NO,@"error":@"queue filters require at most eight substrings"};
    for(id value in filters)if(![value isKindOfClass:NSString.class] || ![value length] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>127 || strlen([value UTF8String])!=[value lengthOfBytesUsingEncoding:NSUTF8StringEncoding])return @{@"ok":@NO,@"error":@"queue filter must be a nonempty NUL-free string up to 127 UTF8 bytes"};
    }
    if (on && !installed) {
        int expected=0;if(!atomic_compare_exchange_strong(&claiming,&expected,1))return @{@"ok":@NO,@"error":@"GCD ownership installation is busy"};
        size_t sourceCount=0;const struct rebinding *sourceBindings=DHFlowSourceBindings(&sourceCount);
        if(!sourceBindings || sourceCount>16)return claim_error(@"dispatch source forwarding symbols unavailable");
        size_t timerCount=0;const struct rebinding *timerBindings=DHFlowTimerBindings(&timerCount);
        if(!timerBindings || timerCount>6)return claim_error(@"RunLoop timer forwarding symbols unavailable");
        for(unsigned i=0;i<sizeof(ownedImports)/sizeof(*ownedImports);i++)if(dh_thunk_has_import(ownedImports[i]))return claim_error(@"a dynamic Import hook already owns a GCD submission; restart before enabling flow capture");
        for(size_t i=0;i<sourceCount;i++)if(dh_thunk_has_import(sourceBindings[i].name))return claim_error(@"a dynamic Import hook already owns a dispatch source adapter; restart before enabling flow capture");
        for(size_t i=0;i<timerCount;i++)if(dh_thunk_has_import(timerBindings[i].name))return claim_error(@"a dynamic Import hook already owns a RunLoop adapter; restart before enabling flow capture");
        original_create=symbol("dispatch_block_create");original_create_qos=symbol("dispatch_block_create_with_qos_class");
        if(!original_create || !original_create_qos)return claim_error(@"GCD public block constructors unavailable");
        dispatch_block_t special=original_create(0,^{});specialInvoke=block_invoke(special);
        Dl_info own={0};int internal=dh_in_hook;dh_in_hook=1;dladdr((void *)DHFlowConfigure,&own);dh_in_hook=internal;agentBase=own.dli_fbase;
        if (!dh_unwind_bounds((uint64_t)ptrauth_strip((void *)DHAsyncExecute,ptrauth_key_function_pointer),&bodyStart,&bodyEnd)) return claim_error(@"async wrapper unwind metadata unavailable");
        original_async=symbol("dispatch_async");original_after=symbol("dispatch_after");original_group=symbol("dispatch_group_async");
        original_async_f=symbol("dispatch_async_f");original_after_f=symbol("dispatch_after_f");original_group_f=symbol("dispatch_group_async_f");
        if (!original_async || !original_after || !original_group || !original_async_f || !original_after_f || !original_group_f) return claim_error(@"GCD public forwarding symbols unavailable");
        original_notify=symbol("dispatch_group_notify");original_notify_f=symbol("dispatch_group_notify_f");original_block_notify=symbol("dispatch_block_notify");
        if(!original_notify || !original_notify_f || !original_block_notify)return claim_error(@"GCD public notification symbols unavailable");
        // Distinguish an actual GCD async invocation from calling the same
        // dispatch-block directly after enqueueing it. No private layout/offsets.
        __block uintptr_t directPC=0,asyncPC=0;
        dispatch_block_t direct=original_create(0,^{directPC=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_function_pointer);});direct();
        dispatch_semaphore_t ready=dispatch_semaphore_create(0);
        dispatch_queue_t calibration=dispatch_queue_create("com.iosdecrypthub.flow.calibration",DISPATCH_QUEUE_SERIAL);
        dispatch_block_t async=original_create(0,^{asyncPC=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_function_pointer);dispatch_semaphore_signal(ready);});
        original_async(calibration,async);
        if(dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,5000000000)) || !asyncPC || !dh_unwind_bounds(asyncPC,&specialAsyncStart,&specialAsyncEnd) || (directPC>=specialAsyncStart && directPC<specialAsyncEnd))return claim_error(@"GCD async/direct block invokers cannot be distinguished");
        struct rebinding binds[]={{"dispatch_async",wrap_async,NULL},{"dispatch_after",wrap_after,NULL},{"dispatch_group_async",wrap_group,NULL},{"dispatch_async_f",wrap_async_f,NULL},{"dispatch_after_f",wrap_after_f,NULL},{"dispatch_group_async_f",wrap_group_f,NULL},{"dispatch_block_create",wrap_create,NULL},{"dispatch_block_create_with_qos_class",wrap_create_qos,NULL},{"dispatch_group_notify",wrap_notify,NULL},{"dispatch_group_notify_f",wrap_notify_f,NULL},{"dispatch_block_notify",wrap_block_notify,NULL}};
        DHFlowTimerPrepare();
        struct rebinding combined[32];size_t primaryCount=sizeof(binds)/sizeof(*binds);
        memcpy(combined,binds,sizeof(binds));memcpy(combined+primaryCount,sourceBindings,sourceCount*sizeof(*sourceBindings));
        memcpy(combined+primaryCount+sourceCount,timerBindings,timerCount*sizeof(*timerBindings));
        if (rebind_symbols(combined,primaryCount+sourceCount+timerCount)<0) return claim_error(@"GCD rebinding registration failed");installed=YES;atomic_store(&claiming,0);
    }
    pthread_mutex_lock(&flowLock);
    if(!on) {
        if(!strcmp(stopReason,"capturing"))strlcpy(stopReason,DHMonotonicNS()>deadline?"expired":"disabled",sizeof(stopReason));
        enabled=NO;atomic_store(&gateOn,0);pthread_mutex_unlock(&flowLock);return @{ @"ok":@YES,@"state":DHFlowState() };
    }
    enabled=YES;captureRoots=roots;windowCount=0;windowSpecialCreated=0;windowRegistrations=0;windowLimit=budget;excludedCount=(unsigned)excluded.count;
    for(unsigned i=0;i<excludedCount;i++)strlcpy(excludedQueues[i],[excluded[i] UTF8String],128);
    rootQueueCount=(unsigned)included.count;for(unsigned i=0;i<rootQueueCount;i++)strlcpy(rootQueues[i],[included[i] UTF8String],128);
    rootAPICount=(unsigned)apis.count;for(unsigned i=0;i<rootAPICount;i++)strlcpy(rootAPIs[i],[apis[i] UTF8String],128);
    rootCallbackCount=(unsigned)callbacks.count;for(unsigned i=0;i<rootCallbackCount;i++)strlcpy(rootCallbacks[i],[callbacks[i] UTF8String],128);
    windowStarted=DHMonotonicNS();deadline=windowStarted+(uint64_t)ms*1000000;strlcpy(stopReason,on?"capturing":"disabled",sizeof(stopReason));atomic_store(&gateOn,on && taskCount<FLOW_CAP);if(on && taskCount==FLOW_CAP)strlcpy(stopReason,"record-capacity",sizeof(stopReason));pthread_mutex_unlock(&flowLock);
    return @{@"ok":@YES,@"state":DHFlowState(),@"coverage":@"six public GCD submission imports, three group/block notification imports, two public block constructors and bounded dispatch source/RunLoop timer adapters; selected plain App blocks/function callbacks and uniquely observed first submissions of blocks created during capture; original dispatch-block metadata preserved; unknown/preexisting/reused blocks have no guessed execution edge; no Swift/NSOperation/private scheduling coverage"};
}
NSDictionary *DHFlowRead(unsigned offset,unsigned limit,uint64_t token) {
    NSMutableArray *out=[NSMutableArray array];pthread_mutex_lock(&flowLock);unsigned total=taskCount;
    for (unsigned i=offset;i<total && out.count<limit;i++) {
        FlowTask *t=&tasks[i];if(token && t->id!=token)continue;
        NSMutableDictionary *d=[DHFlowFields(t->id) mutableCopy];d[@"state"]=t->state==1?@"pending":t->state==2?@"running":t->state==3?@"completed":t->state==4?@"aborted":@"unresolved";
        d[@"callbackLabel"]=@(t->callbackLabel);d[@"api"]=@(t->api);d[@"queue"]=queue_text(t->queue);d[@"submissionThreadId"]=@(t->submitThread);d[@"executionThreadId"]=@(t->thread);d[@"depth"]=@(t->depth);
        d[@"submissionCallerPC"]=[NSString stringWithFormat:@"0x%llx",t->caller];d[@"callbackPC"]=[NSString stringWithFormat:@"0x%llx",t->callback];
        d[@"terminalReason"]=@(t->terminal);
        d[@"associationGaps"]=@(t->associationGaps);d[@"dispatchBlockMetadataPreserved"]=@(t->creationCaller!=0);if(t->creationCaller)d[@"blockCreationCallerPC"]=[NSString stringWithFormat:@"0x%llx",t->creationCaller];
        d[@"registrationId"]=registration_id(t->registration);d[@"edge"]=t->edgeKind==2?@"observed-callback-entry; registration-unobserved":t->registration?@"registered-handler-to-callback":@"observed-submit-to-execute";
        if(t->registration || t->edgeKind==2)d[@"deliveryObservedNs"]=[NSString stringWithFormat:@"%llu",t->delivery];
        if(t->state==4)d[@"scopeEvidence"]=@{@"cookie":[NSString stringWithFormat:@"%llu",t->checkedCookie],@"scopeSP":[NSString stringWithFormat:@"0x%llx",t->checkedScopeSP],@"observedWrapperPC":[NSString stringWithFormat:@"0x%llx",t->checkedBodyPC],@"observedWrapperSP":[NSString stringWithFormat:@"0x%llx",t->checkedBodySP]};
        d[@"submittedNs"]=[NSString stringWithFormat:@"%llu",t->submitted];d[@"startedNs"]=[NSString stringWithFormat:@"%llu",t->started];d[@"finishedNs"]=[NSString stringWithFormat:@"%llu",t->finished];
        // Submit stack is published before forwarding; do not resolve mutable in-flight records.
        if(t->state>=2)d[@"submissionStack"]=DHStackDictionary(&t->stack);[out addObject:d];
    }
    pthread_mutex_unlock(&flowLock);
    for(NSMutableDictionary *d in out){d[@"submissionCallerIdentity"]=DHTargetIdentity((void *)(uintptr_t)strtoull([d[@"submissionCallerPC"] UTF8String],NULL,16));d[@"callbackIdentity"]=DHTargetIdentity((void *)(uintptr_t)strtoull([d[@"callbackPC"] UTF8String],NULL,16));if(d[@"blockCreationCallerPC"])d[@"blockCreationCallerIdentity"]=DHTargetIdentity((void *)(uintptr_t)strtoull([d[@"blockCreationCallerPC"] UTF8String],NULL,16));}
    return @{@"tasks":out,@"retained":@(total),@"nextOffset":offset+limit<total?@(offset+limit):(id)NSNull.null,@"state":DHFlowState(),@"unknownTask":@(token && out.count==0)};
}

NSDictionary *DHFlowDiagnostics(unsigned offset,unsigned limit) {
    FlowDiagnostic copy[4];unsigned copied=0;limit=MIN(limit,4U);
    pthread_mutex_lock(&flowLock);uint64_t total=diagnosticSequence;unsigned retained=(unsigned)MIN(total,(uint64_t)FLOW_DIAGNOSTICS);
    uint64_t first=total-retained+1;
    for(unsigned i=offset;i<retained && copied<limit;i++)copy[copied++]=diagnostics[(first+i-1)%FLOW_DIAGNOSTICS];
    pthread_mutex_unlock(&flowLock);NSMutableArray *out=[NSMutableArray array];
    for(unsigned i=0;i<copied;i++) {FlowDiagnostic *d=&copy[i];[out addObject:@{
        @"id":[NSString stringWithFormat:@"%llu",d->sequence],@"reason":@(diagnosticReasons[d->reason]),@"threadId":@(d->thread),@"monotonicNs":[NSString stringWithFormat:@"%llu",d->when],
        @"candidateTaskId":task_id(d->task),@"expectedAnchorSP":[NSString stringWithFormat:@"0x%llx",d->anchor],@"stack":DHResolveStack(DHStackDictionary(&d->stack),YES),
        @"association":@"suppressed; candidate identity is diagnostic only"}];}
    return @{@"processGeneration":DHProcessGeneration(),@"retained":@(retained),@"total":[NSString stringWithFormat:@"%llu",total],@"overwritten":[NSString stringWithFormat:@"%llu",total-retained],@"records":out,@"nextOffset":offset+copied<retained?@(offset+copied):(id)NSNull.null};
}

NSDictionary *DHFlowRegistrations(unsigned offset,unsigned limit) {
    FlowRegistration copy[8];unsigned copied=0;limit=MIN(limit,8U);
    pthread_mutex_lock(&flowLock);unsigned retained=registrationCount;
    for(unsigned i=offset;i<retained && copied<limit;i++)copy[copied++]=registrations[i];
    pthread_mutex_unlock(&flowLock);NSMutableArray *out=[NSMutableArray array];
    for(unsigned i=0;i<copied;i++) {
        FlowRegistration *r=&copy[i];FlowOrigin *o=&r->origin;
        [out addObject:@{@"registrationId":registration_id(r->id),@"api":@(r->api),@"active":@(r->active),@"terminalReason":@(r->terminal),
            @"asyncParentTaskId":task_id(o->parent),@"registeredByCallId":DHCallID(o->call),@"registrationThreadId":@(o->thread),
            @"registeredNs":[NSString stringWithFormat:@"%llu",o->when],@"retiredNs":[NSString stringWithFormat:@"%llu",r->retired],
            @"queueAtRegistration":queue_text(r->originalQueue),@"currentKnownQueue":queue_text(o->queue),@"observedInvocations":@(r->invoked),@"capturedInvocations":@(r->captured),
            @"callbackLabel":@(o->callbackLabel),@"callbackIdentity":DHTargetIdentity((void *)(uintptr_t)o->callback),@"registrationCallerIdentity":DHTargetIdentity((void *)(uintptr_t)o->caller),
            @"registrationStack":DHResolveStack(DHStackDictionary(&r->stack),YES),@"edge":@"registered-handler-to-callback; not an observed enqueue"}];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"retained":@(retained),@"maxRecords":@(FLOW_REGISTRATIONS),@"registrations":out,@"nextOffset":offset+copied<retained?@(offset+copied):(id)NSNull.null};
}
