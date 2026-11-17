#import "dh_flow_swift.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_call_context.h"
#import "dh_flow.h"
#import "dh_unwind.h"
#include "dh_health.h"
#include "dh_vm_map.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include <mach/mach.h>
#include <string.h>
#include <unistd.h>

// Swift 5.5+ runtime ABI, not the Objective-C/C calling convention. Only the
// published two-pointer creation result and initial AsyncContext are read;
// AsyncTask/Job, task allocator, TaskLocal and executor objects stay opaque.
// Sources: swiftlang/swift swift-5.7-RELEASE Runtime/Concurrency.h,
// ABI/Task.h, Runtime/Config.h, ABI/MetadataValues.h.
#define SW __attribute__((swiftcall))
#define AS __attribute__((swiftasynccall))
#define AC __attribute__((swift_async_context))
#define SC __attribute__((swift_context))
typedef struct SwiftContext SwiftContext;
typedef void AS (*SwiftFinish)(AC SwiftContext *,SC void *);
#if __has_feature(ptrauth_calls)
#define SW_PARENT __ptrauth(ptrauth_key_process_independent_data,1,0xbda2)
#define SW_RESUME __ptrauth(ptrauth_key_function_pointer,1,0xd707)
#else
#define SW_PARENT
#define SW_RESUME
#endif
struct SwiftContext {SwiftContext *SW_PARENT parent;SwiftFinish SW_RESUME resume;};
typedef struct {void *task;SwiftContext *context;} SwiftPair;
typedef struct {void *identity,*implementation;} SwiftExecutor;
typedef SwiftPair SW (*SwiftCreate)(size_t,void *,const void *,void *,void *);
typedef SwiftPair SW (*SwiftCommon)(size_t,void *,const void *,void *,void *,size_t);
typedef void *SW (*SwiftCurrent)(void);
typedef void SW (*SwiftRun)(void *,SwiftExecutor);
typedef void *SW (*SwiftRetain)(void *);
typedef void SW (*SwiftRelease)(void *);
typedef void SW (*SwiftEnqueue)(void *);
typedef void SW (*SwiftDelay)(uint64_t,void *);
typedef void SW (*SwiftDeadline)(int64_t,int64_t,int64_t,int64_t,int,void *);
enum {SW_TASKS=512,SW_FINISHES=4,SW_WINDOW=128};
enum {SW_EVENTS=1024,SW_CREATED=1,SW_ENQUEUED,SW_JOB_ENTRY,SW_JOB_RETURN,SW_CURRENT,SW_COMPLETION,SW_RECOVERED,SW_CONFIRMED};
typedef struct {uint64_t sequence,task,when,recorded,thread,run,job,word0,word1;unsigned kind,api;} SwiftEvent;
static SwiftEvent swiftEvents[SW_EVENTS];static uint64_t swiftEventSequence;
typedef struct {
    uint64_t id,parent,creatorDomain,createdCall,createdAsync,flags,created,returned,published,createdThread,caller,entry,context,task,finish,birthTicket;
    uint64_t observations,firstObserved,lastObserved,lastThread,enqueues,jobEntries,jobReturns;
    uint64_t completion,completionThread,completionRun,confirmed;
    BOOL common,fixture,valid,birthWitness,completionHadError,completionAdopted;unsigned invalidated;
} SwiftRecord;
static pthread_mutex_t swiftLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t prepareLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reasonLock=PTHREAD_MUTEX_INITIALIZER;
static SwiftRecord records[SW_TASKS];static _Atomic unsigned recordCount;static unsigned windowCount,windowLimit;
static _Atomic int ready,enabled,preparing,attempted,ownedCapture;
static _Atomic int captureGate;
static _Atomic unsigned activeRecords;
static _Atomic unsigned retainedAdapters;
static uint64_t deadline,windowStarted,rejected,unsupported,earlyCompletion,birthMissing;
static char reason[256]="not prepared";
static _Atomic(SwiftCurrent) getCurrent;
static void *createOriginal,*commonOriginal,*runOriginal,*enqueueOriginal[4];
static _Atomic BOOL enqueueAvailable[4];
static void *finishOriginal[SW_FINISHES],*finishTarget[SW_FINISHES];static _Atomic unsigned finishCount;
static void *runtimeBase,*fixtureBase,*fixtureHandle;
static _Atomic uint64_t nextRun;
static __thread uint64_t currentRun;
static __thread void *currentJob;
static __thread int internal;
static __thread uint64_t currentCreation;
static _Atomic uint64_t creationSequence;
enum {SW_BIRTHS=128};
typedef struct {uint64_t task,ticket,when;} SwiftBirth;
static SwiftBirth births[SW_BIRTHS];static uint64_t birthSequence,birthOverwritten;
static _Atomic unsigned fixtureMask,fixtureFailures,fixtureRelease;
static void *fixtureTasks[7];static uint64_t fixtureLocals[7];static unsigned fixturePhases[7];
static uint64_t fixtureTokens[7];
static uint64_t fixtureFirstThread[7],fixtureLastThread[7];static BOOL fixtureCrossThread[7];
typedef void (*SwiftNotice)(void *,int32_t,uint64_t,int64_t);
typedef int32_t (*SwiftGate)(void *);
typedef int32_t (*SwiftFixtureStart)(void *,SwiftNotice,SwiftGate);
static SwiftFixtureStart fixtureStart,fixtureFast;
static _Atomic uint64_t fastSeen;
static _Atomic unsigned fastDone,fastFailures;
static unsigned fastAdopted;
static void set_reason(const char *value) {pthread_mutex_lock(&reasonLock);strlcpy(reason,value?:"unknown",sizeof(reason));pthread_mutex_unlock(&reasonLock);}
static NSString *status_text(void) {char value[256];pthread_mutex_lock(&reasonLock);memcpy(value,reason,sizeof(value));pthread_mutex_unlock(&reasonLock);return @(value);}
static int install_adapter(uint64_t address,void *relay,void **original,const char *owner,const char *signature) {
    char error[256]={0};int result=dh_thunk_install_adapter(address,relay,original,owner,signature,error,sizeof(error));if(result<0)set_reason(error);else atomic_fetch_add(&retainedAdapters,1);return result;
}
typedef struct {uint64_t task,context,target,when,thread,run,confirmed,birthTicket;BOOL hadError;} SwiftCompletion;
enum {SW_COMPLETIONS=128};
static SwiftCompletion unbound[SW_COMPLETIONS];static uint64_t unboundSequence;
static uintptr_t code(void *p) {return (uintptr_t)ptrauth_strip(p,ptrauth_key_function_pointer);}
static int address_info(void *address,Dl_info *info) {int saved=dh_in_hook;dh_in_hook=1;int result=dladdr((void *)code(address),info);dh_in_hook=saved;return result;}
static void *lookup_symbol(void *handle,const char *name) {int saved=dh_in_hook;dh_in_hook=1;void *p=dlsym(handle,name);dh_in_hook=saved;return p;}
static void *symbol(const char *name) {void *p=lookup_symbol(RTLD_DEFAULT,name);return p?ptrauth_sign_unauthenticated((void *)code(p),ptrauth_key_function_pointer,0):NULL;}
static uint64_t thread_id(void) {uint64_t t=0;pthread_threadid_np(NULL,&t);return t;}
// Caller holds swiftLock. Hits append only this fixed-size POD record; JSON,
// symbolication and disk/network I/O belong to readers.
static void event_locked(unsigned kind,uint64_t task,uint64_t when,uint64_t thread,uint64_t run,uint64_t job,uint64_t word0,uint64_t word1,unsigned api) {
    uint64_t seq=++swiftEventSequence;swiftEvents[(seq-1)%SW_EVENTS]=(SwiftEvent){.sequence=seq,.task=task,.when=when?:DHMonotonicNS(),.recorded=DHMonotonicNS(),.thread=thread?:thread_id(),.run=run,.job=job,.word0=word0,.word1=word1,.kind=kind,.api=api};
}
static uint64_t runtime_domain(void) {int saved=errno;uint64_t d=getCurrent?(uint64_t)getCurrent():0;errno=saved;return d;}
static NSString *identifier(uint64_t id) {return id?[NSString stringWithFormat:@"%@:swift:%llu",DHProcessGeneration(),id]:@"";}
static SwiftRecord *find_locked(uint64_t task) {
    for(unsigned i=recordCount;i>0;i--){SwiftRecord *r=&records[i-1];if(r->task==task && !r->invalidated && !r->completion)return r;}return NULL;
}
static uint64_t birth_locked(uint64_t task) {for(unsigned i=0;i<SW_BIRTHS;i++)if(births[i].task==task && births[i].ticket)return births[i].ticket;return 0;}
static void discard_births(uint64_t ticket) {
    if(!ticket)return;pthread_mutex_lock(&swiftLock);for(unsigned i=0;i<SW_BIRTHS;i++)if(births[i].ticket==ticket)births[i].ticket=0;pthread_mutex_unlock(&swiftLock);
}
static void retire_unobserved_creation(SwiftPair pair,unsigned watermark) {
    if(!pair.task || !atomic_load(&activeRecords))return;
    pthread_mutex_lock(&swiftLock);SwiftRecord *r=find_locked((uint64_t)pair.task);
    if(r && r->id<=watermark){r->invalidated=1;if(r->valid)atomic_fetch_sub(&activeRecords,1);}
    pthread_mutex_unlock(&swiftLock);
}
static int finish_index(uint64_t address) {for(unsigned i=0;i<finishCount;i++)if((uint64_t)finishTarget[i]==address)return (int)i;return -1;}
static uint64_t initial_finish(SwiftContext *context) {
    uint64_t fields[2]={0};vm_size_t got=0;
    if(!context || vm_read_overwrite(mach_task_self(),(vm_address_t)context,sizeof(fields),(vm_address_t)fields,&got)!=KERN_SUCCESS || got!=sizeof(fields))return 0;
    if(ptrauth_strip((void *)fields[0],ptrauth_key_process_independent_data))return 0;
    return code((void *)fields[1]); // identity only; never call a copied PAC pointer
}
static void observe_creation(SwiftPair pair,size_t flags,void *entry,void *caller,uint64_t parent,uint64_t creatorDomain,uint64_t call,uint64_t async,BOOL common,uint64_t began,uint64_t returned,uint64_t ticket) {
    if(!pair.task)return;int saved=errno;if(internal){errno=saved;return;}internal++;
    uint64_t target=initial_finish(pair.context),when=DHMonotonicNS();Dl_info source={0};
    uintptr_t entryAddress=common?code(entry):(uintptr_t)ptrauth_strip(entry,ptrauth_key_process_independent_data);
    address_info((void *)entryAddress,&source);BOOL fixture=source.dli_fbase && source.dli_fbase==fixtureBase;
    pthread_mutex_lock(&swiftLock);
    // Completion may have won this mutex after the earlier metadata read.
    // Publication time is sampled while holding the same lock as completion
    // entry, so an already recorded final continuation cannot fall into a gap.
    when=DHMonotonicNS();
    BOOL birthWitness=ticket && birth_locked((uint64_t)pair.task)==ticket;
    SwiftRecord *old=find_locked((uint64_t)pair.task);
    // create() can forward through create_common(); the inner and outer return
    // describe the same creation. A later creation retires a reused address.
    if(!common)for(unsigned i=recordCount;i>0;i--) {
        SwiftRecord *inner=&records[i-1];
        if(inner->task==(uint64_t)pair.task && inner->context==(uint64_t)pair.context && inner->created>=began && inner->createdThread==thread_id() && inner->common) {
            pthread_mutex_unlock(&swiftLock);internal--;errno=saved;return;
        }
    }
    if(old){old->invalidated=1;if(old->valid)atomic_fetch_sub(&activeRecords,1);}
    BOOL selected=(atomic_load(&preparing)?fixture:atomic_load(&captureGate) && when<=deadline) && began>=windowStarted;
    if(atomic_load(&ownedCapture) && !fixture)selected=NO;
    if(atomic_load(&enabled) && when>deadline){atomic_store(&enabled,0);atomic_store(&captureGate,0);}
    if(selected && !fixture && !parent) {
        Dl_info origin={0};address_info(caller,&origin);
        selected=origin.dli_fname && strstr(origin.dli_fname,".app/") && origin.dli_fbase!=runtimeBase;
    }
    if(selected && recordCount<SW_TASKS && windowCount<windowLimit && target) {
        SwiftRecord *r=&records[recordCount++];*r=(SwiftRecord){.id=recordCount,.parent=parent,.creatorDomain=creatorDomain,.createdCall=call,.createdAsync=async,.flags=flags,.created=began,.returned=returned,.published=when,.createdThread=thread_id(),.caller=code(caller),.entry=entryAddress,.context=(uint64_t)pair.context,.task=(uint64_t)pair.task,.finish=target,.common=common,.fixture=fixture,.birthTicket=ticket,.birthWitness=birthWitness,.valid=birthWitness && finish_index(target)>=0};windowCount++;
        // A running task can finish before create() returns to its caller. The
        // original return still owns this exact task/context pair. Adopt only
        // an actual final-continuation entry inside this native invocation;
        // this never infers parenthood from a thread or timestamp.
        for(unsigned i=0;i<SW_COMPLETIONS;i++) {
            SwiftCompletion c=unbound[i];
            if(birthWitness && c.birthTicket==ticket && c.task==r->task && c.context==r->context && c.target==r->finish && c.when>=began && c.when<=when) {
                r->completion=c.when;r->completionThread=c.thread;r->completionRun=c.run;r->confirmed=c.confirmed;r->completionHadError=c.hadError;r->completionAdopted=YES;break;
            }
        }
        if(finish_index(target)<0)unsupported++;
        if(!birthWitness)birthMissing++;
        if(r->valid && !r->completion)atomic_fetch_add(&activeRecords,1);
        event_locked(SW_CREATED,r->id,r->returned,r->createdThread,currentRun,r->task,0,0,0);
        if(r->completionAdopted) {
            event_locked(SW_RECOVERED,r->id,r->completion,r->completionThread,r->completionRun,r->task,0,0,0);
            if(r->confirmed)event_locked(SW_CONFIRMED,r->id,r->confirmed,r->completionThread,r->completionRun,r->task,0,0,0);
        }
        if(windowCount==windowLimit || recordCount==SW_TASKS)atomic_store(&captureGate,0);
    } else if(selected)rejected++;
    pthread_mutex_unlock(&swiftLock);internal--;errno=saved;
}
uint64_t DHSwiftCurrentToken(void) {
    if(!getCurrent || internal || !atomic_load(&activeRecords))return 0;int saved=errno;uint64_t task=runtime_domain();if(!task){errno=saved;return 0;}
    pthread_mutex_lock(&swiftLock);SwiftRecord *r=find_locked(task);uint64_t token=r && r->valid?r->id:0;pthread_mutex_unlock(&swiftLock);errno=saved;return token;
}
static SwiftPair SW create_task(size_t flags,void *options,const void *type,void *entry,void *context) {
    int incoming=errno;
    SwiftCreate original=(SwiftCreate)__atomic_load_n(&createOriginal,__ATOMIC_ACQUIRE);
    if(internal || (!atomic_load(&preparing) && !atomic_load(&captureGate))) {
        unsigned watermark=atomic_load(&recordCount);
        uint64_t previous=currentCreation;currentCreation=0;SwiftPair pair;
        @try {pair=original(flags,options,type,entry,context);}@finally {currentCreation=previous;}int saved=errno;
        if(!internal)retire_unobserved_creation(pair,watermark);errno=saved;return pair;
    }
    uint64_t began=DHMonotonicNS();
    if(!internal)DHFlowBoundary();uint64_t domain=runtime_domain();
    uint64_t parent=DHSwiftCurrentToken(),call=dh_call_parent(),async=dh_call_async();void *caller=__builtin_return_address(0);
    uint64_t ticket=atomic_fetch_add(&creationSequence,1)+1,previous=currentCreation;currentCreation=ticket;SwiftPair pair;BOOL returnedNormally=NO;
    @try {errno=incoming;pair=original(flags,options,type,entry,context);returnedNormally=YES;}
    @finally {int final=errno;currentCreation=previous;if(!returnedNormally)discard_births(ticket);errno=final;}
    int saved=errno;uint64_t returned=DHMonotonicNS();
    observe_creation(pair,flags,entry,caller,parent,domain,call,async,NO,began,returned,ticket);discard_births(ticket);errno=saved;return pair;
}
static SwiftPair SW create_common(size_t flags,void *options,const void *type,void *entry,void *context,size_t size) {
    int incoming=errno;
    SwiftCommon original=(SwiftCommon)__atomic_load_n(&commonOriginal,__ATOMIC_ACQUIRE);
    if(internal || (!atomic_load(&preparing) && !atomic_load(&captureGate))) {
        unsigned watermark=atomic_load(&recordCount);
        uint64_t previous=currentCreation;currentCreation=0;SwiftPair pair;
        @try {pair=original(flags,options,type,entry,context,size);}@finally {currentCreation=previous;}int saved=errno;
        if(!internal)retire_unobserved_creation(pair,watermark);errno=saved;return pair;
    }
    uint64_t began=DHMonotonicNS();
    if(!internal)DHFlowBoundary();uint64_t domain=runtime_domain();
    uint64_t parent=DHSwiftCurrentToken(),call=dh_call_parent(),async=dh_call_async();void *caller=__builtin_return_address(0);
    uint64_t ticket=atomic_fetch_add(&creationSequence,1)+1,previous=currentCreation;currentCreation=ticket;SwiftPair pair;BOOL returnedNormally=NO;
    @try {errno=incoming;pair=original(flags,options,type,entry,context,size);returnedNormally=YES;}
    @finally {int final=errno;currentCreation=previous;if(!returnedNormally)discard_births(ticket);errno=final;}
    int saved=errno;uint64_t returned=DHMonotonicNS();
    observe_creation(pair,flags,entry,caller,parent,domain,call,async,YES,began,returned,ticket);discard_births(ticket);errno=saved;return pair;
}
static void observe_finish(unsigned index,SwiftContext *context,void *error) {
    if(!atomic_load(&captureGate) && !atomic_load(&preparing) && !atomic_load(&activeRecords))return;
    int saved=errno;uint64_t task=runtime_domain(),when=DHMonotonicNS();pthread_mutex_lock(&swiftLock);
    SwiftRecord *r=find_locked(task);
    if(r && r->valid && r->context==(uint64_t)context && r->finish==(uint64_t)finishTarget[index]) {
        r->completion=when;r->completionThread=thread_id();r->completionRun=currentRun;r->completionHadError=error!=NULL;
        atomic_fetch_sub(&activeRecords,1);
        event_locked(SW_COMPLETION,r->id,when,r->completionThread,currentRun,(uint64_t)currentJob,0,0,0);
    } else if(task) {
        uint64_t birth=birth_locked(task);
        if(birth)unbound[unboundSequence++%SW_COMPLETIONS]=(SwiftCompletion){.task=task,.context=(uint64_t)context,.target=(uint64_t)finishTarget[index],.when=when,.thread=thread_id(),.run=currentRun,.hadError=error!=NULL,.birthTicket=birth};
        earlyCompletion++;
    }
    pthread_mutex_unlock(&swiftLock);errno=saved;
}
#define FINISH(N) static void AS finish_##N(AC SwiftContext *c,SC void *error) { \
    SwiftFinish original=(SwiftFinish)__atomic_load_n(&finishOriginal[N],__ATOMIC_ACQUIRE);observe_finish(N,c,error); \
    __attribute__((musttail)) return original(c,error);}
FINISH(0) FINISH(1) FINISH(2) FINISH(3)
static void *finishRelays[SW_FINISHES]={(void *)finish_0,(void *)finish_1,(void *)finish_2,(void *)finish_3};
static void SW run_job(void *job,SwiftExecutor executor) {
    SwiftRun original=(SwiftRun)__atomic_load_n(&runOriginal,__ATOMIC_ACQUIRE);
    if(!atomic_load(&captureGate) && !atomic_load(&preparing) && !atomic_load(&activeRecords)){original(job,executor);return;}
    uint64_t previous=currentRun,id=atomic_fetch_add(&nextRun,1)+1;void *previousJob=currentJob;currentRun=id;currentJob=job;
    int saved=errno;pthread_mutex_lock(&swiftLock);SwiftRecord *r=find_locked((uint64_t)job);uint64_t recorded=r && r->valid?r->id:0;if(recorded)r->jobEntries++;
    event_locked(SW_JOB_ENTRY,recorded,0,0,id,(uint64_t)job,(uint64_t)executor.identity,(uint64_t)executor.implementation,0);pthread_mutex_unlock(&swiftLock);errno=saved;
    BOOL returned=NO;
    @try {original(job,executor);returned=YES;}
    @finally {
        saved=errno;
        if(returned) {
            pthread_mutex_lock(&swiftLock);
            if(recorded)records[recorded-1].jobReturns++;
            for(unsigned i=0;i<recordCount;i++) {
                SwiftRecord *t=&records[i];
                if(t->completion && t->completionRun==id && !t->confirmed){t->confirmed=DHMonotonicNS();event_locked(SW_CONFIRMED,t->id,t->confirmed,0,id,(uint64_t)job,0,0,0);}
            }
            for(unsigned i=0;i<SW_COMPLETIONS;i++)if(unbound[i].run==id && unbound[i].when && !unbound[i].confirmed)unbound[i].confirmed=DHMonotonicNS();
            event_locked(SW_JOB_RETURN,recorded,0,0,id,(uint64_t)job,(uint64_t)executor.identity,(uint64_t)executor.implementation,0);
            pthread_mutex_unlock(&swiftLock);
        }
        currentRun=previous;currentJob=previousJob;errno=saved;
    }
}
static void observe_enqueue(void *job,unsigned api,uint64_t word0,uint64_t word1) {
    if(!atomic_load(&activeRecords) && !currentCreation)return;
    int saved=errno;pthread_mutex_lock(&swiftLock);SwiftRecord *r=find_locked((uint64_t)job);
    if(currentCreation && (atomic_load(&captureGate) || atomic_load(&preparing))) {
        unsigned slot=SW_BIRTHS;
        for(unsigned i=0;i<SW_BIRTHS;i++)if(births[i].task==(uint64_t)job && births[i].ticket){slot=i;break;}
        if(slot==SW_BIRTHS){for(unsigned i=0;i<SW_BIRTHS;i++)if(!births[i].ticket){slot=i;break;}}
        if(slot==SW_BIRTHS){slot=(unsigned)(birthSequence++%SW_BIRTHS);birthOverwritten++;}
        if(births[slot].ticket!=currentCreation || births[slot].task!=(uint64_t)job)births[slot]=(SwiftBirth){.task=(uint64_t)job,.ticket=currentCreation,.when=DHMonotonicNS()};
    }
    if(r && r->valid){r->enqueues++;event_locked(SW_ENQUEUED,r->id,0,0,currentRun,(uint64_t)job,word0,word1,api);}
    pthread_mutex_unlock(&swiftLock);errno=saved;
}
static void SW enqueue_global(void *job) {observe_enqueue(job,1,0,0);((SwiftEnqueue)__atomic_load_n(&enqueueOriginal[0],__ATOMIC_ACQUIRE))(job);}
static void SW enqueue_main(void *job) {observe_enqueue(job,2,0,0);((SwiftEnqueue)__atomic_load_n(&enqueueOriginal[1],__ATOMIC_ACQUIRE))(job);}
static void SW enqueue_delay(uint64_t delay,void *job) {observe_enqueue(job,3,delay,0);((SwiftDelay)__atomic_load_n(&enqueueOriginal[2],__ATOMIC_ACQUIRE))(delay,job);}
static void SW enqueue_deadline(int64_t s,int64_t ns,int64_t ts,int64_t tns,int clock,void *job) {observe_enqueue(job,4,(uint64_t)s,(uint64_t)ns);((SwiftDeadline)__atomic_load_n(&enqueueOriginal[3],__ATOMIC_ACQUIRE))(s,ns,ts,tns,clock,job);}
static BOOL install_finish(uint64_t address) {
    if(finish_index(address)>=0)return YES;
    if(finishCount==SW_FINISHES)return NO;
    Dl_info info={0};address_info((void *)address,&info);
    // The runtime itself put this typed final continuation in an owned initial
    // context. Unwind procedure ranges can coalesce leaf functions and are not
    // independent function-start metadata. Use the actual function pointer,
    // same runtime image and current executable mapping, then verify forwarding
    // with the owned tasks. No nearest-symbol or guessed offset is accepted.
    if(!address || address%4 || info.dli_fbase!=runtimeBase || !dh_vm_address_executable(address)){set_reason("owned final continuation is outside the current executable Swift runtime");return NO;}
    unsigned i=finishCount;finishTarget[i]=(void *)address;
    if(install_adapter(address,finishRelays[i],&finishOriginal[i],"Swift task completion","swiftasync void(AsyncContext*, swift_context Error*)")<0)return NO;
    finishCount++;return YES;
}
static _Atomic unsigned manualCalls;
static void AS manual_body(AC SwiftContext *c,SC void *closure) {(void)closure;atomic_fetch_add(&manualCalls,1);return c->resume(c,NULL);}
static void fixture_notice(void *opaque,int32_t phase,uint64_t local,int64_t value) {
    (void)opaque;int saved=errno;uint64_t task=runtime_domain();unsigned role=(unsigned)phase/10;
    if(phase==99 || !task || role<1 || role>7){atomic_fetch_add(&fixtureFailures,1);errno=saved;return;}
    uint64_t token=DHSwiftCurrentToken();pthread_mutex_lock(&swiftLock);unsigned i=role-1;
    if(fixtureTasks[i] && fixtureTasks[i]!=(void *)task)atomic_fetch_add(&fixtureFailures,1);
    fixtureTasks[i]=(void *)task;fixtureLocals[i]=local;fixturePhases[i]++;
    uint64_t thread=thread_id();if(!fixtureFirstThread[i])fixtureFirstThread[i]=thread;else if(fixtureFirstThread[i]!=thread)fixtureCrossThread[i]=YES;fixtureLastThread[i]=thread;
    if(token){if(fixtureTokens[i] && fixtureTokens[i]!=token)atomic_fetch_add(&fixtureFailures,1);fixtureTokens[i]=token;}
    BOOL expected=((role==1 && phase!=13)||role==2||role==4||role==6||role==7);
    if(local!=(expected?0x4848:0) || (phase==11 && value!=14) || ((phase==14 || phase==15 || phase==61) && value!=1))atomic_fetch_add(&fixtureFailures,1);
    pthread_mutex_unlock(&swiftLock);
    (void)DHSwiftFieldsCurrent();
    if(phase%10==0)atomic_fetch_or(&fixtureMask,1u<<i);
    if(phase==13)atomic_fetch_or(&fixtureMask,1u<<7);errno=saved;
}
static int32_t fixture_gate(void *opaque) {(void)opaque;return atomic_load(&fixtureRelease);}
static void wait_tick(void) {
    if(NSThread.isMainThread)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.005]];else usleep(5000);
}
static BOOL load_fixture(void) {
    if(fixtureStart)return YES;Dl_info own={0};address_info((void *)load_fixture,&own);
    NSString *path=[[@(own.dli_fname?:"") stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"IDHSwiftFixtures.dylib"];
    int savedInternal=dh_in_hook;dh_in_hook=1;fixtureHandle=dlopen(path.fileSystemRepresentation,RTLD_NOW|RTLD_LOCAL);dh_in_hook=savedInternal;
    if(!fixtureHandle){char message[256];snprintf(message,sizeof(message),"owned Swift fixture unavailable: %.180s",dlerror()?:"unknown");set_reason(message);return NO;}
    void *start=lookup_symbol(fixtureHandle,"idh_swift_fixture_start"),*fast=lookup_symbol(fixtureHandle,"idh_swift_fixture_fast");
    fixtureStart=start?(SwiftFixtureStart)ptrauth_sign_unauthenticated((void *)code(start),ptrauth_key_function_pointer,0):NULL;
    fixtureFast=fast?(SwiftFixtureStart)ptrauth_sign_unauthenticated((void *)code(fast),ptrauth_key_function_pointer,0):NULL;
    Dl_info f={0};if(fixtureStart)address_info((void *)fixtureStart,&f);fixtureBase=f.dli_fbase;
    if(!fixtureStart || !fixtureFast || !fixtureBase){set_reason("owned Swift fixture entry missing");return NO;}return YES;
}
static BOOL install_runtime(void) {
    if(!dh_thunk_inline_available()){set_reason("typed native Swift backend not linked");return NO;}
    getCurrent=(SwiftCurrent)symbol("swift_task_getCurrent");SwiftCommon common=(SwiftCommon)symbol("swift_task_create_common");SwiftRun run=(SwiftRun)symbol("swift_job_run");
    SwiftRetain retain=(SwiftRetain)symbol("swift_retain");SwiftRelease release=(SwiftRelease)symbol("swift_release");
    if(!getCurrent || !common || !run || !retain || !release){set_reason("required Swift runtime ABI symbols unavailable");return NO;}
    if(runtime_domain()){set_reason("owned Swift preparation must run outside an existing Swift Task");return NO;}
    Dl_info runtime={0};address_info((void *)getCurrent,&runtime);runtimeBase=runtime.dli_fbase;
    // Create suspended owned tasks; no application object or private Job layout.
    SwiftPair a=common(0,NULL,NULL,(void *)manual_body,NULL,32);retain(a.task);
    SwiftPair b=common(0,NULL,NULL,(void *)manual_body,retain(a.task),32);retain(b.task);
    BOOL calibrated=runtime_domain()==0 && a.context && b.context && install_finish(initial_finish(a.context)) && install_finish(initial_finish(b.context));
    run(b.task,(SwiftExecutor){0});release(b.task);run(a.task,(SwiftExecutor){0});release(a.task);
    if(!calibrated)return NO;
    if(atomic_load(&manualCalls)!=2 || runtime_domain()!=0){set_reason("owned Swift original final continuation/current-task restoration failed");return NO;}
    struct {const char *symbol;void *relay;void **original;const char *signature;} adapters[]={
        {"swift_task_create",(void *)create_task,&createOriginal,"swiftcall Pair(flags, options, metadata, entry, context)"},
        {"swift_task_create_common",(void *)create_common,&commonOriginal,"swiftcall Pair(flags, options, metadata, entry, context, size)"},
        {"swift_job_run",(void *)run_job,&runOriginal,"swiftcall void(Job*, ExecutorRef{identity, witness})"},
        {"swift_task_enqueueGlobal",(void *)enqueue_global,&enqueueOriginal[0],"swiftcall void(Job*)"},
        {"swift_task_enqueueMainExecutor",(void *)enqueue_main,&enqueueOriginal[1],"swiftcall void(Job*)"},
        {"swift_task_enqueueGlobalWithDelay",(void *)enqueue_delay,&enqueueOriginal[2],"swiftcall void(uint64, Job*)"},
        {"swift_task_enqueueGlobalWithDeadline",(void *)enqueue_deadline,&enqueueOriginal[3],"swiftcall void(int64, int64, int64, int64, int, Job*)"}};
    for(unsigned i=0;i<sizeof(adapters)/sizeof(*adapters);i++) {
        void *p=symbol(adapters[i].symbol);
        // Deadline enqueue was added after the first concurrency runtime. A
        // missing optional entry is reported; its ABI is never guessed.
        if(!p && i==6)continue;
        if(!p){set_reason("required Swift scheduler export is unavailable");return NO;}
        if(install_adapter(code(p),adapters[i].relay,adapters[i].original,"Swift runtime scheduler",adapters[i].signature)<0)return NO;
        if(i>=3)enqueueAvailable[i-3]=YES;
    }
    if(!dh_call_set_runtime_domain_provider(runtime_domain)){set_reason("another immutable runtime domain provider owns synchronous contexts");return NO;}return YES;
}
static BOOL run_fixture(BOOL calibration,unsigned budget,BOOL disablePending) {
    atomic_store(&fixtureMask,0);atomic_store(&fixtureFailures,0);atomic_store(&fixtureRelease,0);
    pthread_mutex_lock(&swiftLock);memset(fixtureTasks,0,sizeof(fixtureTasks));memset(fixturePhases,0,sizeof(fixturePhases));memset(fixtureTokens,0,sizeof(fixtureTokens));memset(fixtureFirstThread,0,sizeof(fixtureFirstThread));memset(fixtureLastThread,0,sizeof(fixtureLastThread));memset(fixtureCrossThread,0,sizeof(fixtureCrossThread));windowStarted=DHMonotonicNS();windowCount=0;windowLimit=budget;deadline=windowStarted+20000000000ULL;pthread_mutex_unlock(&swiftLock);
    atomic_store(&preparing,calibration);atomic_store(&enabled,!calibration);atomic_store(&captureGate,!calibration);BOOL ok=NO;
    @try {
        if(fixtureStart(NULL,fixture_notice,fixture_gate)!=1)return NO;
        uint64_t until=DHMonotonicNS()+10000000000ULL;
        while((atomic_load(&fixtureMask)&127)!=127 && DHMonotonicNS()<until)wait_tick();
        if((atomic_load(&fixtureMask)&127)!=127){set_reason("owned Swift fixture did not reach all task gates");return NO;}
        unsigned published=0;
        while(DHMonotonicNS()<until) {
            published=0;pthread_mutex_lock(&swiftLock);
            for(unsigned role=0;role<7;role++)for(unsigned i=0;i<recordCount;i++) {
                SwiftRecord *r=&records[i];if(r->fixture && r->created>=windowStarted && r->task==(uint64_t)fixtureTasks[role])published++;
            }
            pthread_mutex_unlock(&swiftLock);if(published==MIN(budget,7))break;wait_tick();
        }
        if(published!=MIN(budget,7)){set_reason("owned Swift creations not published within the selected budget");return NO;}
        // All compiler-generated tasks remain suspended behind the owned gate.
        // Learn only these actual final continuations, then publish adapters.
        uint64_t targets[SW_FINISHES]={0};unsigned count=0;
        pthread_mutex_lock(&swiftLock);
        for(unsigned i=0;i<recordCount;i++)if(records[i].fixture && records[i].created>=windowStarted && !records[i].valid) {
            BOOL duplicate=NO;for(unsigned j=0;j<count;j++)duplicate|=targets[j]==records[i].finish;
            if(!duplicate && count<SW_FINISHES)targets[count++]=records[i].finish;
        }
        pthread_mutex_unlock(&swiftLock);
        for(unsigned i=0;i<count;i++)if(!calibration || !install_finish(targets[i]))return NO;
        pthread_mutex_lock(&swiftLock);for(unsigned i=0;i<recordCount;i++)if(records[i].fixture && records[i].birthWitness && !records[i].valid && finish_index(records[i].finish)>=0){records[i].valid=YES;if(!records[i].completion && !records[i].invalidated)atomic_fetch_add(&activeRecords,1);}pthread_mutex_unlock(&swiftLock);
        if(disablePending){atomic_store(&enabled,0);atomic_store(&captureGate,0);}
        atomic_store(&fixtureRelease,1);
        while(!(atomic_load(&fixtureMask)&128) && DHMonotonicNS()<until)wait_tick();
        if(!(atomic_load(&fixtureMask)&128)){set_reason("owned Swift fixture did not finish");return NO;}
        for(unsigned retry=0;retry<200;retry++) {
            unsigned completed=0;pthread_mutex_lock(&swiftLock);
            for(unsigned role=0;role<7;role++)for(unsigned i=0;i<recordCount;i++) {
                SwiftRecord *r=&records[i];if(r->task==(uint64_t)fixtureTasks[role] && r->fixture && r->created>=windowStarted && r->valid && r->completion && r->confirmed && r->id==fixtureTokens[role])completed++;
            }
            pthread_mutex_unlock(&swiftLock);if(completed==MIN(budget,7)){ok=YES;break;}wait_tick();
        }
        ok=ok && !atomic_load(&fixtureFailures);set_reason(ok?"owned Swift ABI, completion, resume and TaskLocal fixture passed":"owned Swift fixture identity/completion evidence incomplete");
    } @finally {atomic_store(&fixtureRelease,1);atomic_store(&preparing,0);atomic_store(&enabled,0);atomic_store(&captureGate,0);}
    return ok;
}
static void fast_notice(void *opaque,int32_t phase,uint64_t local,int64_t value) {
    (void)opaque;
    if(!runtime_domain() || local){atomic_fetch_add(&fastFailures,1);return;}
    if(phase==80 && value>=0 && value<64) {
        uint64_t bit=1ULL<<value;if(atomic_fetch_or(&fastSeen,bit)&bit)atomic_fetch_add(&fastFailures,1);
        (void)DHSwiftFieldsCurrent();
    } else if(phase==82 && value==14304)atomic_store(&fastDone,1);
    else atomic_fetch_add(&fastFailures,1);
}
static BOOL run_fast_fixture(void) {
    atomic_store(&fastSeen,0);atomic_store(&fastDone,0);atomic_store(&fastFailures,0);fastAdopted=0;
    pthread_mutex_lock(&swiftLock);windowStarted=DHMonotonicNS();windowCount=0;windowLimit=SW_WINDOW;deadline=windowStarted+10000000000ULL;pthread_mutex_unlock(&swiftLock);
    atomic_store(&enabled,1);atomic_store(&captureGate,1);BOOL ok=NO;
    @try {
        if(fixtureFast(NULL,fast_notice,fixture_gate)!=1)return NO;
        uint64_t until=DHMonotonicNS()+5000000000ULL;
        while(!atomic_load(&fastDone) && DHMonotonicNS()<until)wait_tick();
        for(unsigned retry=0;retry<200;retry++) {
            unsigned count=0,complete=0,adopted=0;pthread_mutex_lock(&swiftLock);
            for(unsigned i=0;i<recordCount;i++) {
                SwiftRecord *r=&records[i];if(r->fixture && r->created>=windowStarted){count++;complete+=r->completion && r->confirmed;adopted+=r->completionAdopted;}
            }
            pthread_mutex_unlock(&swiftLock);
            if(count==65 && complete==65){fastAdopted=adopted;ok=YES;break;}wait_tick();
        }
        ok=ok && atomic_load(&fastDone) && atomic_load(&fastSeen)==UINT64_MAX && !atomic_load(&fastFailures);
        if(!ok)set_reason("fast Swift task original results or observed lifetimes incomplete");
    } @finally {atomic_store(&enabled,0);atomic_store(&captureGate,0);}
    return ok;
}
static NSArray *fixture_role_evidence(void) {
    uint64_t tokens[7],first[7],last[7],locals[7];BOOL crossed[7];unsigned phases[7];
    pthread_mutex_lock(&swiftLock);memcpy(tokens,fixtureTokens,sizeof(tokens));memcpy(first,fixtureFirstThread,sizeof(first));memcpy(last,fixtureLastThread,sizeof(last));memcpy(locals,fixtureLocals,sizeof(locals));memcpy(crossed,fixtureCrossThread,sizeof(crossed));memcpy(phases,fixturePhases,sizeof(phases));pthread_mutex_unlock(&swiftLock);
    NSMutableArray *out=[NSMutableArray array];for(unsigned i=0;i<7;i++)[out addObject:@{@"role":@(i+1),@"swiftTaskId":identifier(tokens[i]),@"firstObservedThreadId":@(first[i]),@"lastObservedThreadId":@(last[i]),@"observedAcrossNativeThreads":@(crossed[i]),@"observedPhases":@(phases[i]),@"lastOwnedTaskLocalValue":@(locals[i])}];return out;
}
NSDictionary *DHSwiftSelfTest(void) {
    if(pthread_mutex_trylock(&prepareLock))return @{@"ok":@NO,@"reason":@"Swift preparation/selftest already active"};
    BOOL ok=NO;
    @try {
        if(atomic_load(&enabled))return @{@"ok":@NO,@"reason":@"refuses to replace active Swift capture"};
        atomic_store(&ownedCapture,1);
#if TARGET_OS_IPHONE
        if(@available(iOS 15.0,*)){}else return @{@"ok":@NO,@"reason":@"Swift concurrency fixture requires iOS 15 or later"};
#endif
        if(!load_fixture())return @{@"ok":@NO,@"reason":status_text()};
        if(!atomic_load(&ready)) {
            if(atomic_exchange(&attempted,1))return @{@"ok":@NO,@"reason":@"partial Swift preparation is retained; restart before retrying"};
            if(!install_runtime())return @{@"ok":@NO,@"reason":status_text()};
        }
        BOOL language=run_fixture(YES,SW_WINDOW,NO);
        NSArray *languageRoles=fixture_role_evidence();
        language=language && [languageRoles[1][@"observedAcrossNativeThreads"] boolValue];
        BOOL pending=language && run_fixture(NO,SW_WINDOW,YES);
        BOOL budget=pending && run_fixture(NO,2,NO);
        BOOL fast=budget && run_fast_fixture();
        ok=language && pending && budget && fast;
        atomic_store(&ready,ok);
        return @{@"ok":@(ok),@"state":DHSwiftState(),@"proof":@{@"compilerGeneratedTasksPerRun":@7,@"languageAndRuntime":@(language),@"languageRoles":languageRoles,@"pendingAfterDisable":@(pending),@"budgetPreservesOriginalWork":@(budget),@"fastTasks":@65,@"fastOriginalResultsAndLifetimes":@(fast),@"actualCompletionBeforeCreationPublication":@(fastAdopted),@"taskMask":@(atomic_load(&fixtureMask)),@"failures":@(atomic_load(&fixtureFailures)),@"runtimeCompletionTargets":@(finishCount),@"manualABICalls":@(atomic_load(&manualCalls))}};
    } @finally {atomic_store(&ownedCapture,0);pthread_mutex_unlock(&prepareLock);}
}
NSDictionary *DHSwiftConfigure(BOOL on,unsigned budget,unsigned milliseconds) {
    if(on && !atomic_load(&ready)){NSDictionary *test=DHSwiftSelfTest();if(![test[@"ok"] boolValue])return test;}
    if(pthread_mutex_trylock(&prepareLock))return @{@"ok":@NO,@"reason":@"Swift preparation/selftest is active"};
    pthread_mutex_lock(&swiftLock);
    if(on && recordCount==SW_TASKS){pthread_mutex_unlock(&swiftLock);pthread_mutex_unlock(&prepareLock);return @{@"ok":@NO,@"reason":@"Swift task record capacity reached; restart before a new window"};}
    if(on) {windowStarted=DHMonotonicNS();deadline=windowStarted+MIN(MAX(milliseconds,1),60000)*1000000ULL;windowLimit=MIN(MAX(budget,1),SW_WINDOW);windowCount=0;}
    atomic_store(&enabled,on);atomic_store(&captureGate,on);pthread_mutex_unlock(&swiftLock);pthread_mutex_unlock(&prepareLock);return @{@"ok":@YES,@"state":DHSwiftState()};
}
NSDictionary *DHSwiftFieldsCurrent(void) {
    if(!getCurrent || internal || (!atomic_load(&activeRecords) && !atomic_load(&captureGate) && !atomic_load(&preparing)))return @{};int saved=errno;uint64_t task=runtime_domain();if(!task){errno=saved;return @{};}
    uint64_t id=0,parent=0,call=0,async=0;pthread_mutex_lock(&swiftLock);SwiftRecord *r=find_locked(task);
    if(r && r->valid) {r->observations++;r->lastObserved=DHMonotonicNS();if(!r->firstObserved)r->firstObserved=r->lastObserved;r->lastThread=thread_id();id=r->id;parent=r->parent;call=r->createdCall;async=r->createdAsync;event_locked(SW_CURRENT,id,r->lastObserved,r->lastThread,currentRun,(uint64_t)currentJob,0,0,0);}
    pthread_mutex_unlock(&swiftLock);
    NSDictionary *out=id?@{@"swiftTaskId":identifier(id),@"swiftCreatedByTaskId":identifier(parent),@"swiftCreatedByCallId":DHCallID(call),@"swiftCreatedByAsyncToken":@(async),@"swiftCreatedByAsyncTaskId":DHFlowFields(async)[@"asyncTaskId"],@"swiftAssociationResolved":@YES,@"swiftIdentityBasis":@"authoritative swift_task_getCurrent + observed creation lifetime"}:@{@"swiftAssociationResolved":@NO,@"swiftIdentityBasis":@"runtime Task present; selected validated creation lifetime unavailable"};errno=saved;return out;
}
NSDictionary *DHSwiftFieldsForToken(uint64_t token) {
    if(!token || token>SW_TASKS)return @{};
    SwiftRecord r={0};pthread_mutex_lock(&swiftLock);if(token<=recordCount)r=records[token-1];pthread_mutex_unlock(&swiftLock);
    if(!r.id || !r.valid)return @{};
    return @{@"swiftTaskId":identifier(r.id),@"swiftCreatedByTaskId":identifier(r.parent),@"swiftCreatedByCallId":DHCallID(r.createdCall),@"swiftCreatedByAsyncToken":@(r.createdAsync),@"swiftCreatedByAsyncTaskId":DHFlowFields(r.createdAsync)[@"asyncTaskId"],@"swiftAssociationResolved":@YES,@"swiftIdentityBasis":@"snapshot of authoritative current-task creation lifetime at paired call entry"};
}
NSDictionary *DHSwiftState(void) {
    pthread_mutex_lock(&swiftLock);unsigned complete=0,confirmed=0,invalid=0;
    for(unsigned i=0;i<recordCount;i++){complete+=records[i].completion!=0;confirmed+=records[i].confirmed!=0;invalid+=records[i].invalidated!=0;}
    NSDictionary *out=@{@"processGeneration":DHProcessGeneration(),@"ready":@(atomic_load(&ready)),@"enabled":@(atomic_load(&enabled)),@"preparing":@(atomic_load(&preparing)),@"reason":status_text(),@"recordCapacity":@(SW_TASKS),@"retained":@(recordCount),@"windowCapacity":@(SW_WINDOW),@"windowLimit":@(windowLimit),@"activeRecordedTasks":@(atomic_load(&activeRecords)),@"captureActive":@(atomic_load(&captureGate) && DHMonotonicNS()<=deadline),@"windowStartedNs":[NSString stringWithFormat:@"%llu",windowStarted],@"deadlineNs":[NSString stringWithFormat:@"%llu",deadline],@"windowCount":@(windowCount),@"completionEntries":@(complete),@"nativeJobReturnConfirmed":@(confirmed),@"invalidated":@(invalid),@"rejected":@(rejected),@"unsupportedCompletion":@(unsupported),@"missingInitialEnqueueWitness":@(birthMissing),@"birthWitnessOverwritten":@(birthOverwritten),@"untrackedCompletionEntries":@(earlyCompletion),@"finishTargets":@(finishCount),@"nativeAdaptersRetained":@(atomic_load(&retainedAdapters)),@"patchesRetainedUntilRestart":@(atomic_load(&retainedAdapters)!=0),@"eventCapacity":@(SW_EVENTS),@"eventLatestSeq":@(swiftEventSequence),@"eventOverwritten":@(swiftEventSequence>SW_EVENTS?swiftEventSequence-SW_EVENTS:0),@"enqueueEntries":@{@"global":@(enqueueAvailable[0]),@"main":@(enqueueAvailable[1]),@"delay":@(enqueueAvailable[2]),@"deadline":@(enqueueAvailable[3])}};
    pthread_mutex_unlock(&swiftLock);return out;
}
NSDictionary *DHSwiftRead(unsigned offset,unsigned limit) {
    limit=MIN(MAX(limit,1),16);SwiftRecord copy[16];pthread_mutex_lock(&swiftLock);unsigned total=recordCount,start=MIN(offset,total),count=MIN(limit,total-start);memcpy(copy,records+start,count*sizeof(*copy));pthread_mutex_unlock(&swiftLock);
    NSMutableArray *rows=[NSMutableArray array];for(unsigned i=0;i<count;i++) {
        SwiftRecord r=copy[i];[rows addObject:@{@"swiftTaskId":identifier(r.id),@"createdBySwiftTaskId":identifier(r.parent),@"creationRelation":r.parent?@"observed-creator-task":r.creatorDomain?@"creator-runtime-task-unrecorded":@"native-caller",@"createdByCallId":DHCallID(r.createdCall),@"createdByAsyncToken":@(r.createdAsync),@"createdByAsyncTaskId":DHFlowFields(r.createdAsync)[@"asyncTaskId"],@"taskAddress":[NSString stringWithFormat:@"0x%llx",r.task],@"initialContextAddress":[NSString stringWithFormat:@"0x%llx",r.context],@"flags":[NSString stringWithFormat:@"0x%llx",r.flags],@"creationAPI":r.common?@"swift_task_create_common":@"swift_task_create",@"entryKind":r.common?@"async-function":@"async-closure-descriptor",@"entryIdentity":DHTargetIdentity((void *)r.entry),@"creationCaller":DHTargetIdentity((void *)r.caller),@"completionTarget":DHTargetIdentity((void *)r.finish),@"identityValidated":@(r.valid),@"initialEnqueueWitness":@(r.birthWitness),@"creationTicket":[NSString stringWithFormat:@"%llu",r.birthTicket],@"fixture":@(r.fixture),@"creationInvocationNs":[NSString stringWithFormat:@"%llu",r.created],@"creationReturnedNs":[NSString stringWithFormat:@"%llu",r.returned],@"creationThreadId":@(r.createdThread),@"creationObservationNs":[NSString stringWithFormat:@"%llu",r.published],@"completionObservedBeforeCreationPublication":@(r.completionAdopted),@"runtimeObservations":@(r.observations),@"lastThreadId":@(r.lastThread),@"firstObservedNs":[NSString stringWithFormat:@"%llu",r.firstObserved],@"lastObservedNs":[NSString stringWithFormat:@"%llu",r.lastObserved],@"observedEnqueues":@(r.enqueues),@"nativeJobEntries":@(r.jobEntries),@"nativeJobReturns":@(r.jobReturns),@"completionObservedNs":[NSString stringWithFormat:@"%llu",r.completion],@"completionThreadId":@(r.completionThread),@"completionHadSwiftError":@(r.completionHadError),@"completionJobRun":@(r.completionRun),@"completionConfirmedByOriginalJobReturn":@(r.confirmed!=0),@"invalidatedByObservedCreation":@(r.invalidated!=0),@"state":r.invalidated?@"unresolved-address-reused":r.confirmed?@"completed":r.completion?@"runtime-completion-entry":r.valid?@"created":!r.birthWitness?@"unresolved-initial-enqueue":@"unresolved-completion-target"}];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"tasks":rows,@"total":@(total),@"offset":@(start),@"nextOffset":start+count<total?@(start+count):NSNull.null};
}
NSDictionary *DHSwiftEvents(uint64_t after,unsigned limit,uint64_t task) {
    limit=MIN(MAX(limit,1),64);SwiftEvent copy[64];unsigned count=0;
    pthread_mutex_lock(&swiftLock);uint64_t last=swiftEventSequence,first=last>=SW_EVENTS?last-SW_EVENTS+1:1;
    uint64_t scanned=MIN(after,last),begin=MAX(scanned+1,first);
    for(uint64_t seq=begin;seq<=last && count<limit;seq++) {
        SwiftEvent e=swiftEvents[(seq-1)%SW_EVENTS];scanned=seq;if(e.sequence==seq && (!task || e.task==task))copy[count++]=e;
    }
    pthread_mutex_unlock(&swiftLock);
    const char *phases[]={"unknown","create-return-observed","enqueue-observed","native-job-entry","native-job-return","current-task-observed","runtime-completion-entry","completion-recovered","completion-confirmed"};
    const char *apis[]={"","swift_task_enqueueGlobal","swift_task_enqueueMainExecutor","swift_task_enqueueGlobalWithDelay","swift_task_enqueueGlobalWithDeadline"};
    NSMutableArray *rows=[NSMutableArray array];for(unsigned i=0;i<count;i++) {
        SwiftEvent e=copy[i];[rows addObject:@{@"schemaVersion":@2,@"kind":@"swift-task",@"processGeneration":DHProcessGeneration(),@"schedulerSeq":@(e.sequence),@"sequenceScope":@"swift-scheduler-ring",@"phase":@(phases[e.kind<=SW_CONFIRMED?e.kind:0]),@"swiftTaskId":identifier(e.task),@"monotonicNs":[NSString stringWithFormat:@"%llu",e.when],@"recordedNs":[NSString stringWithFormat:@"%llu",e.recorded],@"threadId":@(e.thread),@"nativeJobRunId":e.run?[NSString stringWithFormat:@"%@:swift-job:%llu",DHProcessGeneration(),e.run]:@"",@"jobAddress":[NSString stringWithFormat:@"0x%llx",e.job],@"api":@(apis[e.api<5?e.api:0]),@"word0":[NSString stringWithFormat:@"0x%llx",e.word0],@"word1":[NSString stringWithFormat:@"0x%llx",e.word1]}];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"events":rows,@"oldestSeq":@(last?first:0),@"latestSeq":@(last),@"overwritten":@(last>SW_EVENTS?last-SW_EVENTS:0),@"nextAfterSeq":scanned<last?@(scanned):NSNull.null};
}
