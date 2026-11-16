#import "qbdi_live.h"
#import "dh_thunk.h"
#import "dh_unwind.h"
#import "dh_event.h"
#import "log_store.h"
#include "dh_health.h"
#include <stdatomic.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ptrauth.h>
#ifndef DH_HAVE_QBDI
#define DH_HAVE_QBDI 0
#endif
#if DH_HAVE_QBDI
#include "QBDI/VM_C.h"
#include "QBDI/InstAnalysis.h"
#endif

enum { LIVE_ARMED=1,LIVE_RUNNING,LIVE_DONE,LIVE_CANCELLED,LIVE_FAILED };
typedef struct {
    uint64_t pc,sp,nzcv,x[31];
    __uint128_t q[32]; uint64_t fpcr,fpsr;
    char mnemonic[32],disassembly[128];
} DHLiveInstruction;
typedef struct {
    DHLiveTransfer transfer;
    DHCPUContext entry,exit;
    DHRawStack stack;
    _Atomic int state;
    int slot,savedErrno,guestErrno,callOK,truncated;
    uint64_t target,original,threadFilter,threadID,token,started,finished;
    unsigned capacity,count,timeBudget,transfers;
    void *mapping; size_t mappingSize;
    char stop[40];
    DHLiveInstruction *records;
    uint8_t stackBytes[256];vm_size_t stackLength;
#if DH_HAVE_QBDI
    VMInstanceRef vm;
#endif
} DHLiveSession;
_Static_assert(offsetof(DHLiveSession,entry)==16,"assembly fallback entry layout");
static pthread_mutex_t sessionLock=PTHREAD_MUTEX_INITIALIZER;
static DHLiveSession *sessions[8];
static unsigned sessionCount;
static _Atomic(DHLiveSession *) armedSession;
static __thread int inLive;
extern void dh_thunk_live_post(unsigned slot, const DHCPUContext *result,
    const DHCPUContext *entry, uint64_t token, uint64_t original);

BOOL DHLiveAvailable(void) { return DH_HAVE_QBDI!=0; }
static uint64_t rawcode(uint64_t p) {
    return (uint64_t)ptrauth_strip((void *)(uintptr_t)p,ptrauth_key_function_pointer);
}
#if DH_HAVE_QBDI
static VMAction live_instruction(VMInstanceRef vm,GPRState *g,FPRState *f,void *opaque) {
    DHLiveSession *s=opaque;
    if (s->count>=s->capacity || DHMonotonicNS()-s->started>(uint64_t)s->timeBudget*1000000) {
        if (!s->truncated) strlcpy(s->stop,s->count>=s->capacity?"record-limit":"record-time-limit",sizeof(s->stop));
        s->truncated=1;
        // 只停止记录，绝不 STOP 正在发生的原调用或重放它的副作用。
        return QBDI_CONTINUE;
    }
    const InstAnalysis *a=qbdi_getInstAnalysis(vm,(AnalysisType)(QBDI_ANALYSIS_INSTRUCTION|QBDI_ANALYSIS_DISASSEMBLY));
    DHLiveInstruction *r=&s->records[s->count++];
    r->pc=a?a->address:g->pc;r->sp=g->sp;r->nzcv=g->nzcv;memcpy(r->x,&g->x0,sizeof(r->x));
    memcpy(r->q,&f->v0,sizeof(r->q));r->fpcr=f->fpcr;r->fpsr=f->fpsr;
    if (a) {strlcpy(r->mnemonic,a->mnemonic?:"",sizeof(r->mnemonic));strlcpy(r->disassembly,a->disassembly?:"",sizeof(r->disassembly));}
    return QBDI_CONTINUE;
}
static VMAction live_transfer(VMInstanceRef vm,const VMState *state,GPRState *g,FPRState *f,void *opaque) {
    (void)vm;(void)state;(void)g;(void)f;((DHLiveSession *)opaque)->transfers++;return QBDI_CONTINUE;
}
#endif
static NSString *trace_id(unsigned index) {return [NSString stringWithFormat:@"%@:trace:%u",DHProcessGeneration(),index];}
static DHLiveSession *find_session(NSString *identifier) {
    for (unsigned i=0;i<sessionCount;i++) if ([identifier isEqual:trace_id(i)]) return sessions[i];
    return NULL;
}
static NSString *hex64(uint64_t value) {return [NSString stringWithFormat:@"0x%llx",value];}
static NSDictionary *cpu_dictionary(const DHCPUContext *cpu) {
    NSMutableDictionary *g=[NSMutableDictionary dictionary];
    for (unsigned i=0;i<31;i++) g[[NSString stringWithFormat:@"x%u",i]]=hex64(cpu->x[i]);
    g[@"sp"]=hex64(cpu->sp);g[@"pc"]=hex64(cpu->pc);g[@"nzcv"]=hex64(cpu->nzcv);
    g[@"fpcr"]=hex64(cpu->fpcr);g[@"fpsr"]=hex64(cpu->fpsr);
    NSMutableArray *simd=[NSMutableArray array];
    for (unsigned i=0;i<32;i++) [simd addObject:[NSString stringWithFormat:@"%016llx%016llx",(uint64_t)(cpu->q[i]>>64),(uint64_t)cpu->q[i]]];
    return @{@"gpr":g,@"q0_q31":simd};
}
NSDictionary *DHLiveArm(int slot,uint64_t target,uint64_t original,unsigned count,unsigned milliseconds,uint64_t threadID) {
#if !DH_HAVE_QBDI
    return @{@"ok":@NO,@"error":@"QBDI live backend is unavailable"};
#else
    if (!count || count>8192 || milliseconds<1 || milliseconds>10000)
        return @{@"ok":@NO,@"error":@"live record budget requires 1..8192 instructions / 1..10000 milliseconds"};
    if ([DHLogStore shared].paused || [[DHLogStore shared] isPausedForCategory:DHCategoryOther])
        return @{@"ok":@NO,@"error":@"resume global/other capture before arming a live trace"};
    pthread_mutex_lock(&sessionLock);
    DHLiveSession *active=atomic_load(&armedSession);
    if (sessionCount>=8 || (active && atomic_load(&active->state)<=LIVE_RUNNING)) {
        pthread_mutex_unlock(&sessionLock);return @{@"ok":@NO,@"error":@"live session busy or eight retained sessions reached; cancel pending capture or restart target"};
    }
    DHLiveSession *s=calloc(1,sizeof(*s));
    if (!s) {pthread_mutex_unlock(&sessionLock);return @{@"ok":@NO,@"error":@"live allocation failed"};}
    s->capacity=count;s->timeBudget=milliseconds;s->target=target;s->original=original;s->slot=slot;s->threadFilter=threadID;
    s->records=calloc(count,sizeof(DHLiveInstruction));
    size_t page=(size_t)getpagesize(),usable=2*1024*1024;s->mappingSize=usable+2*page;
    s->mapping=mmap(NULL,s->mappingSize,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    BOOL ready=s->records && s->mapping!=MAP_FAILED && !mprotect((char *)s->mapping+page,usable,PROT_READ|PROT_WRITE);
    if (ready) {
        s->transfer.analysisTop=(char *)s->mapping+page+usable;
        Options options;memset(&options,0,sizeof(options));qbdi_initVM(&s->vm,NULL,NULL,options);
        ready=s->vm && qbdi_addInstrumentedModuleFromAddr(s->vm,target);
        if (ready) {
            qbdi_addInstrumentedRange(s->vm,original,original+128);
            ready=qbdi_addCodeCB(s->vm,QBDI_PREINST,live_instruction,s,0)!=QBDI_INVALID_EVENTID &&
                qbdi_addVMEventCB(s->vm,(VMEvent)(QBDI_EXEC_TRANSFER_CALL|QBDI_EXEC_TRANSFER_RETURN),live_transfer,s)!=QBDI_INVALID_EVENTID;
        }
    }
    if (!ready) {
        if (s->vm) qbdi_terminateVM(s->vm);
        if (s->mapping && s->mapping!=MAP_FAILED) munmap(s->mapping,s->mappingSize);
        free(s->records);free(s);pthread_mutex_unlock(&sessionLock);
        return @{@"ok":@NO,@"error":@"live VM/range/callback preparation failed before arming; target not executed"};
    }
    unsigned index=sessionCount++;sessions[index]=s;strlcpy(s->stop,"awaiting-real-call",sizeof(s->stop));
    atomic_store(&s->state,LIVE_ARMED);atomic_store_explicit(&armedSession,s,memory_order_release);
    pthread_mutex_unlock(&sessionLock);
    return @{@"ok":@YES,@"traceId":trace_id(index),@"executionMode":@"live-next-call",@"state":@"armed",
        @"slot":@(slot),@"target":hex64(target),@"recordBudget":@(count),@"normalReturnRequired":@YES};
#endif
}
DHLiveTransfer *dh_live_claim(uint64_t slot,uint64_t original,const DHCPUContext *entry,uint64_t token) {
#if DH_HAVE_QBDI
    int savedErrno=errno;
    DHLiveSession *s=atomic_load_explicit(&armedSession,memory_order_acquire);
    if (!s || inLive || !token || s->slot!=slot || original!=s->original) return NULL;
    uint64_t threadID=0;pthread_threadid_np(NULL,&threadID);
    if (s->threadFilter && s->threadFilter!=threadID) return NULL;
    int expected=LIVE_ARMED;
    if (!atomic_compare_exchange_strong(&s->state,&expected,LIVE_RUNNING)) return NULL;
    s->entry=*entry;s->entry.pc=s->target;s->token=token;s->threadID=threadID;s->savedErrno=savedErrno;
    s->transfer.thunkSP=(uintptr_t)entry-0x130;
    uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    size_t length=pthread_get_stacksize_np(pthread_self());
    if (entry->sp>=top-length && entry->sp<top)
        vm_read_overwrite(mach_task_self(),entry->sp,MIN((size_t)256,top-entry->sp),(vm_address_t)s->stackBytes,&s->stackLength);
    dh_unwind_capture(&s->entry,s->target,&s->stack);
    return &s->transfer;
#else
    (void)slot;(void)original;(void)entry;(void)token;return NULL;
#endif
}
DHCPUContext *dh_live_run(DHLiveTransfer *transfer) {
#if DH_HAVE_QBDI
    DHLiveSession *s=(DHLiveSession *)transfer;
    GPRState *g=qbdi_getGPRState(s->vm);FPRState *f=qbdi_getFPRState(s->vm);
    memset(g,0,sizeof(*g));memcpy(&g->x0,s->entry.x,sizeof(s->entry.x));
    g->sp=s->entry.sp;g->pc=s->original;g->nzcv=s->entry.nzcv;
    memcpy(&f->v0,s->entry.q,sizeof(s->entry.q));f->fpcr=s->entry.fpcr;f->fpsr=s->entry.fpsr;
    int internal=dh_in_hook;dh_in_hook=1;inLive=1;s->started=DHMonotonicNS();s->guestErrno=s->savedErrno;errno=s->savedErrno;
    // QBDI 按执行块备份 guest errno；仅设置宿主 TLS 不会初始化它。
    qbdi_setErrno(s->vm,(uint32_t)s->savedErrno);
    s->callOK=qbdi_run(s->vm,s->original,rawcode(s->entry.x[30]));
    s->guestErrno=(int)qbdi_getErrno(s->vm);
    int returnedErrno=s->guestErrno;s->finished=DHMonotonicNS();
    s->exit=s->entry;memcpy(s->exit.x,&g->x0,sizeof(s->exit.x));s->exit.sp=g->sp;s->exit.pc=rawcode(g->pc);s->exit.nzcv=g->nzcv;
    memcpy(s->exit.q,&f->v0,sizeof(s->exit.q));s->exit.fpcr=f->fpcr;s->exit.fpsr=f->fpsr;
    qbdi_terminateVM(s->vm);s->vm=NULL;inLive=0;
    if (!s->callOK && !s->count) {
        strlcpy(s->stop,"not-executed-native-forward",sizeof(s->stop));atomic_store(&s->state,LIVE_FAILED);
        dh_in_hook=internal;errno=s->savedErrno;return NULL;
    }
    if (!s->truncated) strlcpy(s->stop,"normal-return",sizeof(s->stop));
    dh_thunk_live_post(s->slot,&s->exit,&s->entry,s->token,s->original);
    atomic_store_explicit(&s->state,LIVE_DONE,memory_order_release);
    dh_in_hook=internal;errno=returnedErrno;return &s->exit;
#else
    (void)transfer;return NULL;
#endif
}
NSDictionary *DHLiveRead(NSString *identifier,unsigned offset,unsigned limit) {
    pthread_mutex_lock(&sessionLock);DHLiveSession *s=find_session(identifier);pthread_mutex_unlock(&sessionLock);
    if (!s) return @{@"ok":@NO,@"error":@"traceId not retained in this process generation"};
    int state=atomic_load_explicit(&s->state,memory_order_acquire);
    NSString *name=state==LIVE_ARMED?@"armed":state==LIVE_RUNNING?@"running":state==LIVE_DONE?@"completed":state==LIVE_CANCELLED?@"cancelled":@"failed";
    NSMutableDictionary *r=[@{@"ok":@YES,@"traceId":identifier,@"state":name,@"executionMode":@"live",
        @"processGeneration":DHProcessGeneration(),@"slot":@(s->slot),@"syntheticCall":@NO,@"inputPointerSubstitution":@NO} mutableCopy];
    if (state==LIVE_ARMED || state==LIVE_RUNNING) return r; // 不读取正在写的快照。
    r[@"stopReason"]=state==LIVE_CANCELLED?@"cancelled-before-call":@(s->stop);r[@"recordingTruncated"]=@(s->truncated!=0);r[@"count"]=@(s->count);
    if (state!=LIVE_DONE) return r;
    BOOL returned=s->callOK && s->exit.pc==rawcode(s->entry.x[30]) && s->exit.sp==s->entry.sp;
    r[@"callCompleted"]=@(returned);r[@"threadId"]=@(s->threadID);r[@"callId"]=DHCallID(s->token);
    r[@"target"]=hex64(s->target);r[@"originalTrampoline"]=hex64(s->original);
    r[@"durationNs"]=hex64(s->finished-s->started);r[@"nativeTransferEvents"]=@(s->transfers);
    r[@"coverage"]=@"target module plus original trampoline; native transfers counted, not expanded";
    r[@"contextCoverage"]=@"x0-x30, original SP/stack, q0-q31, NZCV/FPCR/FPSR, original thread/TLS; no synthetic argument call";
    r[@"entry"]=cpu_dictionary(&s->entry);r[@"exit"]=cpu_dictionary(&s->exit);
    r[@"entryErrno"]=@(s->savedErrno);r[@"exitErrno"]=@(s->guestErrno);
#if DH_HAVE_QBDI && defined(QBDI_PTRAUTH)
    r[@"pointerAuthentication"]=@YES;
#else
    r[@"pointerAuthentication"]=@NO;
#endif
    r[@"entryStack"]=@{@"address":hex64(s->entry.sp),@"hex":DHHexFromData([NSData dataWithBytes:s->stackBytes length:s->stackLength]),@"capturedBytes":@(s->stackLength)};
    r[@"stack"]=DHResolveStack(DHStackDictionary(&s->stack),YES);
    NSMutableArray *records=[NSMutableArray array];limit=MIN(MAX(limit,1),256);unsigned end=MIN(s->count,offset+limit);
    for (unsigned i=offset;i<end;i++) {
        DHLiveInstruction *p=&s->records[i];NSMutableArray *registers=[NSMutableArray array];
        NSMutableArray *simd=[NSMutableArray array];
        for (unsigned j=0;j<31;j++) [registers addObject:hex64(p->x[j])];
        for (unsigned j=0;j<32;j++) [simd addObject:[NSString stringWithFormat:@"%016llx%016llx",(uint64_t)(p->q[j]>>64),(uint64_t)p->q[j]]];
        [records addObject:@{@"index":@(i),@"pc":hex64(p->pc),@"sp":hex64(p->sp),@"nzcv":hex64(p->nzcv),
            @"x0_x30":registers,@"q0_q31":simd,@"fpcr":hex64(p->fpcr),@"fpsr":hex64(p->fpsr),@"mnemonic":@(p->mnemonic),@"disassembly":@(p->disassembly)}];
    }
    r[@"instructions"]=records;r[@"offset"]=@(offset);r[@"nextOffset"]=end<s->count?@(end):[NSNull null];return r;
}
NSDictionary *DHLiveCancel(NSString *identifier) {
    pthread_mutex_lock(&sessionLock);DHLiveSession *s=find_session(identifier);
    if (!s) {pthread_mutex_unlock(&sessionLock);return @{@"ok":@NO,@"error":@"unknown traceId"};}
    int expected=LIVE_ARMED;BOOL cancelled=atomic_compare_exchange_strong(&s->state,&expected,LIVE_CANCELLED);
#if DH_HAVE_QBDI
    if (cancelled && s->vm) {qbdi_terminateVM(s->vm);s->vm=NULL;}
#endif
    pthread_mutex_unlock(&sessionLock);
    return @{@"ok":@(cancelled),@"error":cancelled?@"":@"only pending capture can be cancelled; an executing native call is never aborted"};
}
