#import "dh_flow.h"
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

extern void dh_thunk_abandon(unsigned slot,uint64_t token,const char *reason,const DHCallContext *saved);
extern int dh_thunk_post_frame(uint64_t pc,uint64_t sp,uint64_t callerSP);
extern int dh_thunk_in_handler(void);
extern int dh_thunk_has_import(const char *name);
enum { FLOW_CAP=1024,FLOW_PENDING=64,FLOW_DEPTH=8 };
typedef struct {int slot;uint64_t token,sp;DHCallContext saved;} FlowGuard;
typedef struct FlowTask {
    uint64_t id,parent,call,submitted,started,finished,submitThread,thread,caller;
    uint64_t scopeSP,*cookie; struct FlowTask *previous;
    void *context;dispatch_function_t function;
    int state,depth;unsigned associationGaps; // 1 pending, 2 running, 3 completed, 4 aborted
    char api[32],queue[128],terminal[64];DHRawStack stack;
    uint64_t checkedCookie,checkedScopeSP,checkedBodyPC,checkedBodySP;
} FlowTask;
static pthread_mutex_t flowLock=PTHREAD_MUTEX_INITIALIZER;
static FlowTask tasks[FLOW_CAP];static unsigned taskCount,pending,windowCount,windowLimit;
static uint64_t deadline,bodyStart,bodyEnd;static BOOL enabled,captureRoots;static _Atomic int installed;
static _Atomic int gateOn;
static _Atomic int claiming;
static char excludedQueues[8][128];static unsigned excludedCount;
static _Atomic uint64_t abandoned,unverified,guardOverflow,rejected,hiddenToken;
static _Atomic uint64_t skippedBlocks;
static uintptr_t specialInvoke;static void *agentBase;
static __thread FlowGuard guards[64];static __thread unsigned guardCount;
static __thread int busy;static __thread FlowTask *current;
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
static NSString *queue_text(const char *label) {
    size_t length=strnlen(label,128);
    for(unsigned drop=0;drop<4 && drop<=length;drop++) {
        NSString *text=[[NSString alloc] initWithBytes:label length:length-drop encoding:NSUTF8StringEncoding];if(text)return text;
    }
    return @"<invalid-or-truncated-UTF8-queue>";
}
NSDictionary *DHFlowFields(uint64_t token) {
    if (!token || token>FLOW_CAP) return @{@"asyncTaskId":@"",@"asyncParentTaskId":@"",@"asyncSubmittedByCallId":@""};
    FlowTask *t=&tasks[token-1];return @{@"asyncTaskId":task_id(token),@"asyncParentTaskId":task_id(t->parent),@"asyncSubmittedByCallId":DHCallID(t->call)};
}
static void task_event(FlowTask *task,NSString *phase) {
    int saved=dh_in_hook;dh_in_hook=1;busy++;
    @autoreleasepool {
        DHLogEntry *e=[DHLogEntry new];e.category=DHCategoryOther;e.algorithm=@"gcd-async";e.operation=@(task->api);
        DHStampEvent(e);NSMutableDictionary *c=[e.eventContext mutableCopy];c[@"kind"]=@"async-task";c[@"phase"]=phase;
        c[@"parentCallId"]=@"";[c addEntriesFromDictionary:DHFlowFields(task->id)];e.eventContext=c;
        e.eventPayload=@{@"queue":queue_text(task->queue),@"submissionThreadId":@(task->submitThread),@"executionThreadId":@(task->thread),@"edge":@"observed-submit-to-execute",@"terminalReason":@(task->terminal)};
        [[DHLogStore shared] append:e];
    }
    busy--;dh_in_hook=saved;
}
void DHFlowCheck(const DHRawStack *stack) {
    if (busy || dh_live_current()) return;
    if(!guardCount && !current) {dh_call_set_trust(1);return;}
    if (!stack->complete || stack->error || stack->truncated) {atomic_fetch_add(&unverified,1);dh_call_set_trust(0);return;}
    // A normal libunwind stop can still occur below a known frame (e.g. codec stubs).
    // Absence is evidence of exit only after the walk has actually passed its anchor.
    uint64_t lastSP=stack->count?stack->sp[stack->count-1]:0;
    for(unsigned n=0;n<guardCount;n++) {
        BOOL found=NO;for(unsigned i=0;i<stack->count;i++)if(dh_thunk_post_frame(stack->pc[i],stack->sp[i],guards[n].sp)){found=YES;break;}
        if(!found && lastSP<=guards[n].sp){atomic_fetch_add(&unverified,1);dh_call_set_trust(0);return;}
    }
    if(current) {
        BOOL found=NO;for(unsigned i=0;i<stack->count;i++)if(stack->pc[i]>=bodyStart && stack->pc[i]<bodyEnd && stack->sp[i]==current->scopeSP){found=YES;break;}
        if(!found && lastSP<=current->scopeSP){atomic_fetch_add(&unverified,1);dh_call_set_trust(0);return;}
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
            atomic_fetch_add(&unverified,1);dh_call_set_trust(0);mirror();busy--;errno=saved;return;
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
static FlowTask *select_task(const char *api,dispatch_queue_t queue,void *caller) {
    if (!atomic_load(&gateOn) || busy || dh_in_hook || dh_live_current()) return NULL;
    int saved=errno;caller=ptrauth_strip(caller,ptrauth_key_function_pointer);
    const char *label=dispatch_queue_get_label(queue)?:"";Dl_info origin={0};int internalCaller=dh_in_hook;dh_in_hook=1;dladdr(caller,&origin);dh_in_hook=internalCaller;
    if(origin.dli_fbase==agentBase && strcmp(label,"com.iosdecrypthub.flow.fixture")) {errno=saved;return NULL;}
    DHFlowBoundary();uint64_t parent=dh_call_async(),call=dh_call_parent();
    pthread_mutex_lock(&flowLock);
    if (!enabled || DHMonotonicNS()>deadline) {enabled=NO;atomic_store(&gateOn,0);pthread_mutex_unlock(&flowLock);errno=saved;return NULL;}
    BOOL roots=captureRoots;pthread_mutex_unlock(&flowLock);
    if (!parent && !call) {
        if (!roots) {errno=saved;return NULL;}
        Dl_info info={0};int internal=dh_in_hook;dh_in_hook=1;BOOL app=dladdr(caller,&info) && info.dli_fname && strstr(info.dli_fname,".app/");dh_in_hook=internal;
        if (!app) {errno=saved;return NULL;}
    }
    pthread_mutex_lock(&flowLock);unsigned depth=parent?tasks[parent-1].depth+1:0;
    for(unsigned i=0;i<excludedCount;i++)if(strcasestr(label,excludedQueues[i])) {pthread_mutex_unlock(&flowLock);errno=saved;return NULL;}
    if (!enabled || DHMonotonicNS()>deadline || taskCount==FLOW_CAP || pending>=FLOW_PENDING || windowCount>=windowLimit || depth>=FLOW_DEPTH) {
        atomic_fetch_add(&rejected,1);pthread_mutex_unlock(&flowLock);errno=saved;return NULL;
    }
    FlowTask *t=&tasks[taskCount++];t->id=taskCount;t->parent=parent;t->call=call;t->depth=depth;t->state=1;t->caller=(uint64_t)caller;t->submitted=DHMonotonicNS();pending++;windowCount++;
    pthread_threadid_np(NULL,&t->submitThread);strlcpy(t->api,api,sizeof(t->api));strlcpy(t->queue,dispatch_queue_get_label(queue)?:"",sizeof(t->queue));
    if(windowCount==windowLimit || taskCount==FLOW_CAP)atomic_store(&gateOn,0);
    pthread_mutex_unlock(&flowLock);
    int internal=dh_in_hook;dh_in_hook=1;busy++;dh_unwind_current(&t->stack);
    if (t->stack.count>32) {t->stack.count=32;t->stack.complete=0;t->stack.truncated=1;}
    task_event(t,@"submit");busy--;dh_in_hook=internal;errno=saved;return t;
}
static void (*original_async)(dispatch_queue_t,dispatch_block_t);
static void (*original_after)(dispatch_time_t,dispatch_queue_t,dispatch_block_t);
static void (*original_group)(dispatch_group_t,dispatch_queue_t,dispatch_block_t);
static void (*original_async_f)(dispatch_queue_t,void *,dispatch_function_t);
static void (*original_after_f)(dispatch_time_t,dispatch_queue_t,void *,dispatch_function_t);
static void (*original_group_f)(dispatch_group_t,dispatch_queue_t,void *,dispatch_function_t);
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
static void wrap_async(dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=plain_block(b)?select_task("dispatch_async",q,__builtin_return_address(0)):NULL;errno=saved;if(t)original_async(q,^{DHAsyncExecute(t,b);});else original_async(q,b);}
static void wrap_after(dispatch_time_t when,dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=plain_block(b)?select_task("dispatch_after",q,__builtin_return_address(0)):NULL;errno=saved;if(t)original_after(when,q,^{DHAsyncExecute(t,b);});else original_after(when,q,b);}
static void wrap_group(dispatch_group_t g,dispatch_queue_t q,dispatch_block_t b) {int saved=errno;FlowTask *t=plain_block(b)?select_task("dispatch_group_async",q,__builtin_return_address(0)):NULL;errno=saved;if(t)original_group(g,q,^{DHAsyncExecute(t,b);});else original_group(g,q,b);}
static void invoke_f(void *p) {FlowTask *t=p;DHAsyncExecute(t,^{t->function(t->context);});}
static void wrap_async_f(dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_async_f",q,__builtin_return_address(0));if(t){t->context=c;t->function=f;original_async_f(q,t,invoke_f);}else original_async_f(q,c,f);}
static void wrap_after_f(dispatch_time_t w,dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_after_f",q,__builtin_return_address(0));if(t){t->context=c;t->function=f;original_after_f(w,q,t,invoke_f);}else original_after_f(w,q,c,f);}
static void wrap_group_f(dispatch_group_t g,dispatch_queue_t q,void *c,dispatch_function_t f) {FlowTask *t=select_task("dispatch_group_async_f",q,__builtin_return_address(0));if(t){t->context=c;t->function=f;original_group_f(g,q,t,invoke_f);}else original_group_f(g,q,c,f);}
static void *symbol(const char *name) {void *p=dlsym(RTLD_DEFAULT,name);return p?ptrauth_sign_unauthenticated(ptrauth_strip(p,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0):NULL;}
static const char *ownedImports[]={"dispatch_async","dispatch_after","dispatch_group_async","dispatch_async_f","dispatch_after_f","dispatch_group_async_f"};
int DHFlowOwnsImport(const char *name) {if((!atomic_load(&installed) && !atomic_load(&claiming)) || !name)return 0;for(unsigned i=0;i<6;i++)if(!strcmp(name,ownedImports[i]))return 1;return 0;}
static NSDictionary *claim_error(NSString *message) {atomic_store(&claiming,0);return @{@"ok":@NO,@"error":message};}
NSDictionary *DHFlowState(void) {
    pthread_mutex_lock(&flowLock);
    NSMutableArray *filters=[NSMutableArray array];for(unsigned i=0;i<excludedCount;i++)[filters addObject:@(excludedQueues[i])];
    NSDictionary *r=@{@"enabled":@(enabled && DHMonotonicNS()<=deadline && windowCount<windowLimit),@"installed":@(installed),@"captureRoots":@(captureRoots),@"retained":@(taskCount),@"pendingOrRunning":@(pending),@"windowAccepted":@(windowCount),@"maxRecords":@1024,@"maxPending":@64,@"maxDepth":@8,
        @"abandonedCalls":@(atomic_load(&abandoned)),@"unverifiedBoundaries":@(atomic_load(&unverified)),@"guardOverflows":@(atomic_load(&guardOverflow)),@"rejectedTasks":@(atomic_load(&rejected)),@"skippedSpecialOrUnknownBlocks":@(atomic_load(&skippedBlocks)),@"queueExclude":filters,@"threadGuardCount":@(guardCount),@"threadAsyncTaskId":task_id(dh_call_async())};
    pthread_mutex_unlock(&flowLock);return r;
}
NSDictionary *DHFlowConfigure(BOOL on,BOOL roots,unsigned budget,unsigned ms,NSArray *excluded) {
    if (on && (!budget || budget>256 || !ms || ms>60000)) return @{@"ok":@NO,@"error":@"async window requires 1..256 tasks / 1..60000ms"};
    if(excluded && (![excluded isKindOfClass:NSArray.class] || excluded.count>8))return @{@"ok":@NO,@"error":@"queue_exclude requires at most eight substrings"};
    for(id value in excluded)if(![value isKindOfClass:NSString.class] || ![value length] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>127 || strlen([value UTF8String])!=[value lengthOfBytesUsingEncoding:NSUTF8StringEncoding])return @{@"ok":@NO,@"error":@"queue exclusion must be a nonempty NUL-free string up to 127 UTF8 bytes"};
    if (on && !installed) {
        int expected=0;if(!atomic_compare_exchange_strong(&claiming,&expected,1))return @{@"ok":@NO,@"error":@"GCD ownership installation is busy"};
        for(unsigned i=0;i<6;i++)if(dh_thunk_has_import(ownedImports[i]))return claim_error(@"a dynamic Import hook already owns a GCD submission; restart before enabling flow capture");
        dispatch_block_t special=dispatch_block_create(0,^{});specialInvoke=block_invoke(special);
        Dl_info own={0};int internal=dh_in_hook;dh_in_hook=1;dladdr((void *)DHFlowConfigure,&own);dh_in_hook=internal;agentBase=own.dli_fbase;
        if (!dh_unwind_bounds((uint64_t)ptrauth_strip((void *)DHAsyncExecute,ptrauth_key_function_pointer),&bodyStart,&bodyEnd)) return claim_error(@"async wrapper unwind metadata unavailable");
        original_async=symbol("dispatch_async");original_after=symbol("dispatch_after");original_group=symbol("dispatch_group_async");
        original_async_f=symbol("dispatch_async_f");original_after_f=symbol("dispatch_after_f");original_group_f=symbol("dispatch_group_async_f");
        if (!original_async || !original_after || !original_group || !original_async_f || !original_after_f || !original_group_f) return claim_error(@"GCD public forwarding symbols unavailable");
        struct rebinding binds[]={{"dispatch_async",wrap_async,NULL},{"dispatch_after",wrap_after,NULL},{"dispatch_group_async",wrap_group,NULL},{"dispatch_async_f",wrap_async_f,NULL},{"dispatch_after_f",wrap_after_f,NULL},{"dispatch_group_async_f",wrap_group_f,NULL}};
        if (rebind_symbols(binds,6)<0) return claim_error(@"GCD rebinding registration failed");installed=YES;atomic_store(&claiming,0);
    }
    pthread_mutex_lock(&flowLock);enabled=on;captureRoots=roots;windowCount=0;windowLimit=budget;excludedCount=(unsigned)excluded.count;
    for(unsigned i=0;i<excludedCount;i++)strlcpy(excludedQueues[i],[excluded[i] UTF8String],128);
    deadline=DHMonotonicNS()+(uint64_t)ms*1000000;atomic_store(&gateOn,on);pthread_mutex_unlock(&flowLock);
    return @{@"ok":@YES,@"state":DHFlowState(),@"coverage":@"six public GCD submission imports; selected plain App blocks and function callbacks; calibrated dispatch-block and unknown/system invoke blocks pass through unchanged; no Swift tasks/NSOperation/private scheduling coverage"};
}
NSDictionary *DHFlowRead(unsigned offset,unsigned limit,uint64_t token) {
    NSMutableArray *out=[NSMutableArray array];pthread_mutex_lock(&flowLock);unsigned total=taskCount;
    for (unsigned i=offset;i<total && out.count<limit;i++) {
        FlowTask *t=&tasks[i];if(token && t->id!=token)continue;
        NSMutableDictionary *d=[DHFlowFields(t->id) mutableCopy];d[@"state"]=t->state==1?@"pending":t->state==2?@"running":t->state==3?@"completed":@"aborted";
        d[@"api"]=@(t->api);d[@"queue"]=queue_text(t->queue);d[@"submissionThreadId"]=@(t->submitThread);d[@"executionThreadId"]=@(t->thread);d[@"depth"]=@(t->depth);
        d[@"submissionCallerPC"]=[NSString stringWithFormat:@"0x%llx",t->caller];
        d[@"terminalReason"]=@(t->terminal);
        d[@"associationGaps"]=@(t->associationGaps);
        if(t->state==4)d[@"scopeEvidence"]=@{@"cookie":[NSString stringWithFormat:@"%llu",t->checkedCookie],@"scopeSP":[NSString stringWithFormat:@"0x%llx",t->checkedScopeSP],@"observedWrapperPC":[NSString stringWithFormat:@"0x%llx",t->checkedBodyPC],@"observedWrapperSP":[NSString stringWithFormat:@"0x%llx",t->checkedBodySP]};
        d[@"submittedNs"]=[NSString stringWithFormat:@"%llu",t->submitted];d[@"startedNs"]=[NSString stringWithFormat:@"%llu",t->started];d[@"finishedNs"]=[NSString stringWithFormat:@"%llu",t->finished];
        // Submit stack is published before forwarding; do not resolve mutable in-flight records.
        if(t->state>=2)d[@"submissionStack"]=DHStackDictionary(&t->stack);[out addObject:d];
    }
    pthread_mutex_unlock(&flowLock);
    for(NSMutableDictionary *d in out)d[@"submissionCallerIdentity"]=DHTargetIdentity((void *)(uintptr_t)strtoull([d[@"submissionCallerPC"] UTF8String],NULL,16));
    return @{@"tasks":out,@"retained":@(total),@"nextOffset":offset+limit<total?@(offset+limit):(id)NSNull.null,@"state":DHFlowState(),@"unknownTask":@(token && out.count==0)};
}
