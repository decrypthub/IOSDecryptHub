#import "qbdi_control.h"
#import "qbdi_live.h"
#import "dh_health.h"
#import "dh_event.h"
#include "dh_control_breakpoint.h"
#include "dh_vm_map.h"
#include <stdatomic.h>
#include <pthread.h>
#include <ptrauth.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <unwind.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#ifndef DH_HAVE_QBDI
#define DH_HAVE_QBDI 0
#endif
#if DH_HAVE_QBDI
#include "QBDI/VM_C.h"
extern unsigned qbdi_idhOriginalA64Version(void);
extern unsigned qbdi_idhNativeHandoffOption(void);
extern int qbdi_idhSetOriginalA64Reader(int (*)(uint64_t,uint32_t *));
#endif

extern void *g_dh_thunk_orig[DH_THUNK_COUNT];
extern void *dh_live_control_claim(uint64_t,const DHCPUContext *);
extern void *dh_live_control_resume(void *,const DHCPUContext *,uint64_t,unsigned);
extern void dh_live_control_escape(void *,const char *,unsigned);
enum {CE_NATIVE=1,CE_RETURN,CE_LANDING,CE_LANDING_NATIVE,CE_JUMP_ENTRY,CE_JUMP_RESUME,
    CE_ESCAPE,CE_GAP,CE_ROOT_RETURN,CE_ENV_RETIRED,CE_PUBLIC_INSTALL,CE_SETJMP_RETURN,CE_SETJMP_ENTRY};
typedef struct {
    _Atomic uint64_t sequence,target;
    _Atomic uint32_t word,kind;
} ControlBoundary;
static ControlBoundary boundaries[DH_THUNK_COUNT];
static _Atomic(DHControlSession *) owner;
static pthread_mutex_t prepareLock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic int attempted,prepared;
static char prepareReason[256]="not prepared";
static void *personalityOriginal[2];
static uint64_t noreturnTargets[12];static unsigned noreturnCount;
static uint64_t captureTargets[3];static unsigned captureTargetCount;

// Environment identities are *observed calls*, not jmp_buf layouts or guessed
// lifetimes. Atomic POD slots also cover a native signal handler without first
// allocating compiler TLS. Session objects/tickets are never reused.
enum {CONTROL_ENVIRONMENTS=128};
typedef struct {
    _Atomic uint64_t sequence,thread,environment,pc,sp,owner,ticket;
} ControlEnvironment;
typedef struct {uint64_t sequence,thread,environment,pc,sp,owner,ticket;} EnvironmentSnapshot;
static ControlEnvironment environments[CONTROL_ENVIRONMENTS];
static _Atomic uint64_t environmentSequence;
static uint64_t raw(uint64_t pointer) {return (uint64_t)ptrauth_strip((void *)(uintptr_t)pointer,ptrauth_key_function_pointer);}
static uint64_t native_symbol(const char *name) {int saved=dh_in_hook;dh_in_hook=1;uint64_t pointer=raw((uint64_t)dlsym(RTLD_DEFAULT,name));dh_in_hook=saved;return pointer;}

int dh_control_publish(unsigned slot,uint64_t target,unsigned kind,const uint8_t *bytes,unsigned length) {
    if(slot>=DH_THUNK_COUNT || !bytes || length<4 || !target || target%4 || kind<DH_CONTROL_ROOT || kind>DH_CONTROL_LONGJMP)return 0;
    ControlBoundary *b=&boundaries[slot];uint32_t word;memcpy(&word,bytes,4);
    atomic_fetch_add_explicit(&b->sequence,1,memory_order_acq_rel);
    atomic_store_explicit(&b->target,target,memory_order_relaxed);atomic_store_explicit(&b->word,word,memory_order_relaxed);
    atomic_store_explicit(&b->kind,kind,memory_order_relaxed);atomic_fetch_add_explicit(&b->sequence,1,memory_order_release);return 1;
}
void dh_control_unpublish(unsigned slot) {
    if(slot>=DH_THUNK_COUNT)return;ControlBoundary *b=&boundaries[slot];
    atomic_fetch_add_explicit(&b->sequence,1,memory_order_acq_rel);atomic_store(&b->kind,0);atomic_store(&b->target,0);
    atomic_fetch_add_explicit(&b->sequence,1,memory_order_release);
}
unsigned dh_control_boundary_kind(unsigned slot) {
    if(slot>=DH_THUNK_COUNT)return 0;return atomic_load_explicit(&boundaries[slot].kind,memory_order_acquire);
}
uint64_t dh_control_breakpoint_entry(uint64_t pc) {
    for(unsigned i=0;i<DH_THUNK_COUNT;i++) {
        ControlBoundary *b=&boundaries[i];uint64_t before=atomic_load_explicit(&b->sequence,memory_order_acquire);
        if(!before || before&1)continue;
        unsigned kind=atomic_load_explicit(&b->kind,memory_order_relaxed);
        if((kind==DH_CONTROL_ROOT || kind==DH_CONTROL_CHECKPOINT) && atomic_load_explicit(&b->target,memory_order_relaxed)==pc && before==atomic_load_explicit(&b->sequence,memory_order_acquire))return dh_thunk_native_context_entry(i);
    }
    return 0;
}
static int original_instruction(uint64_t pc,uint32_t *word) {
    for(unsigned i=0;i<DH_THUNK_COUNT;i++) {
        ControlBoundary *b=&boundaries[i];uint64_t before=atomic_load_explicit(&b->sequence,memory_order_acquire);
        if(!before || before&1)continue;
        unsigned kind=atomic_load_explicit(&b->kind,memory_order_relaxed);
        uint64_t target=atomic_load_explicit(&b->target,memory_order_relaxed);uint32_t candidate=atomic_load_explicit(&b->word,memory_order_relaxed);
        if((kind==DH_CONTROL_ROOT || kind==DH_CONTROL_CHECKPOINT) && target==pc && before==atomic_load_explicit(&b->sequence,memory_order_acquire)) {*word=candidate;return 1;}
    }
    return 0;
}
static DHControlSession *current_owner(void) {
    DHControlSession *c=atomic_load_explicit(&owner,memory_order_acquire);
    // pthread_self is the public native identity; no private pthread/TLS layout
    // or first-use thread-local allocation is needed on an unrelated thread.
    return c && c->ownerThread==(uintptr_t)pthread_self()?c:NULL;
}
int dh_control_is_owner(void) {return current_owner()!=NULL;}
static DHControlEvent *event(DHControlSession *c,unsigned kind,uint64_t pc,uint64_t sp,uint64_t lr,uint64_t a,uint64_t b) {
    if(c->eventCount==DH_CONTROL_EVENTS){c->eventLost++;return NULL;}
    DHControlEvent *e=&c->events[c->eventCount];*e=(DHControlEvent){.sequence=c->eventCount+1,.when=DHMonotonicNS(),.pc=pc,.sp=sp,.lr=lr,.word0=a,.word1=b,.kind=kind};c->eventCount++;return e;
}
static void gap(DHControlSession *c,const char *reason,uint64_t pc,uint64_t sp) {
    c->gaps++;if(!c->gapReason[0])strlcpy(c->gapReason,reason,sizeof(c->gapReason));event(c,CE_GAP,pc,sp,0,c->gaps,0);
}
static int instrumented(DHControlSession *c,uint64_t pc) {
    for(unsigned i=0;i<c->opaqueCount;i++)if(pc>=c->opaque[i].start && pc<c->opaque[i].end)return 0;
    for(unsigned i=0;i<c->rangeCount;i++)if(pc>=c->ranges[i].start && pc<c->ranges[i].end)return 1;return 0;
}
static int valid_sp(DHControlSession *c,uint64_t sp) {return sp>=c->stackLow && sp<c->stackHigh && !(sp&15);}
static void escape(DHControlSession *c,const char *reason,unsigned observation) {
    if(c!=current_owner() || c->phase==DH_CONTROL_TERMINAL)return;
    event(c,CE_ESCAPE,0,0,0,observation,0);c->phase=DH_CONTROL_TERMINAL;
    // Detachment is POD on the owner thread. JSON/log emission and VM disposal
    // happen after the terminal release on a control reader.
    DHControlSession *expected=c;atomic_compare_exchange_strong_explicit(&owner,&expected,NULL,memory_order_release,memory_order_relaxed);
    dh_live_control_escape(c->transfer,reason,observation);
}
static void prune_spans(DHControlSession *c,uint64_t sp) {
    while(c->spanCount && c->spans[c->spanCount-1].sp<=sp)c->spanCount--;
}
static int checkpoint(DHControlSession *c,uint64_t pc) {
#if DH_HAVE_QBDI
    for(unsigned i=0;i<DH_THUNK_COUNT;i++)if(dh_control_boundary_kind(i)==DH_CONTROL_CHECKPOINT && atomic_load(&boundaries[i].target)==pc)return 1;
    char error[256]={0};dh_hook_options options;dh_thunk_options_default(&options);
    int slot=dh_thunk_install_native_boundary(pc,DH_CONTROL_CHECKPOINT,&options,"QBDI native continuation",error,sizeof(error));
    if(slot<0){gap(c,error[0]?error:"checkpoint installation failed",pc,0);return 0;}return 1;
#else
    (void)c;(void)pc;return 0;
#endif
}
static uint64_t environment_snapshot(uint64_t environment,uint64_t pc,uint64_t sp,DHControlSession *c) {
    uint64_t ticket=atomic_fetch_add_explicit(&environmentSequence,1,memory_order_relaxed)+1;
    ControlEnvironment *e=&environments[(ticket-1)%CONTROL_ENVIRONMENTS];
    // A slot in use by a simultaneous writer is skipped, never spun on from a
    // signal handler. Atomic fields plus the ticket publication prevent tears.
    uint64_t prior=atomic_load_explicit(&e->sequence,memory_order_acquire);
    if(prior&1 || !atomic_compare_exchange_strong_explicit(&e->sequence,&prior,(ticket<<1)|1,memory_order_acq_rel,memory_order_relaxed))return 0;
    atomic_store_explicit(&e->thread,(uintptr_t)pthread_self(),memory_order_relaxed);atomic_store_explicit(&e->environment,environment,memory_order_relaxed);
    atomic_store_explicit(&e->pc,pc,memory_order_relaxed);atomic_store_explicit(&e->sp,sp,memory_order_relaxed);
    atomic_store_explicit(&e->owner,(uintptr_t)c,memory_order_relaxed);atomic_store_explicit(&e->ticket,ticket,memory_order_relaxed);
    atomic_store_explicit(&e->sequence,ticket<<1,memory_order_release);return ticket;
}
static void public_setjmp_return(DHControlSession *c,const DHControlSpan *span) {
    if(!span->environment)return;
    // Canonical continuation comes from the actual public call and its exact
    // original return PC/SP witness. A native implementation's internal
    // same-environment setjmp entry cannot replace it with a helper-frame LR.
    uint64_t ticket=environment_snapshot(span->environment,span->pc,span->sp,c);
    DHControlEvent *e=event(c,CE_SETJMP_RETURN,span->pc,span->sp,0,span->environment,span->ticket);if(e)e->reference=ticket;
}
static int find_environment(uint64_t environment,EnvironmentSnapshot *out) {
    uint64_t thread=(uintptr_t)pthread_self();EnvironmentSnapshot best={0};
    for(unsigned i=0;i<CONTROL_ENVIRONMENTS;i++) {
        ControlEnvironment *e=&environments[i];uint64_t sequence=atomic_load_explicit(&e->sequence,memory_order_acquire);if(!sequence || sequence&1)continue;
        EnvironmentSnapshot r={.sequence=sequence,.thread=atomic_load_explicit(&e->thread,memory_order_relaxed),.environment=atomic_load_explicit(&e->environment,memory_order_relaxed),.pc=atomic_load_explicit(&e->pc,memory_order_relaxed),.sp=atomic_load_explicit(&e->sp,memory_order_relaxed),.owner=atomic_load_explicit(&e->owner,memory_order_relaxed),.ticket=atomic_load_explicit(&e->ticket,memory_order_relaxed)};
        if(sequence!=atomic_load_explicit(&e->sequence,memory_order_acquire) || r.thread!=thread || r.environment!=environment || r.ticket<=best.ticket)continue;best=r;
    }
    *out=best;return best.ticket!=0;
}
static void retire_environments(DHControlSession *c,uint64_t sp) {
    for(unsigned i=0;i<CONTROL_ENVIRONMENTS;i++) {
        ControlEnvironment *e=&environments[i];uint64_t sequence=atomic_load_explicit(&e->sequence,memory_order_acquire);
        if(!sequence || sequence&1 || atomic_load(&e->owner)!=(uintptr_t)c || atomic_load(&e->sp)>=sp)continue;
        // Only the original thread owns this session; a concurrent overwrite
        // changes sequence before owner is cleared.
        if(atomic_compare_exchange_strong_explicit(&e->sequence,&sequence,sequence|1,memory_order_acq_rel,memory_order_relaxed)) {
            atomic_store_explicit(&e->owner,0,memory_order_relaxed);atomic_store_explicit(&e->sequence,sequence+2,memory_order_release);
        }
    }
}
static void observe_jump(DHControlSession *c,const DHCPUContext *cpu) {
    if(c->phase!=DH_CONTROL_NATIVE){
        // A signal may escape an executing VM. Preserve the OS jump and retire
        // its state, but never re-enter/destroy that interrupted engine or
        // pretend that its instruction continuation was observed.
        c->vmAbandoned=1;gap(c,"asynchronous longjmp escaped an executing VM",0,cpu->sp);
        escape(c,"asynchronous-longjmp-unexpanded",5);return;
    }
    EnvironmentSnapshot e={0};int known=find_environment(cpu->x[0],&e);
    DHControlEvent *observed=event(c,CE_JUMP_ENTRY,e.pc,e.sp,raw(cpu->x[30]),cpu->x[0],(uint32_t)cpu->x[1]);if(observed)observed->reference=e.ticket;
    if(!known || e.owner!=(uintptr_t)c || !valid_sp(c,e.sp) || e.sp>=c->rootSP) {
        escape(c,known?"longjmp-outside-observed-root":"longjmp-unobserved-environment",known?2:3);return;
    }
    // An observed setjmp within a native helper remains native; its real
    // enclosing call's continuation resumes the VM after the helper returns.
    if(!instrumented(c,e.pc)){prune_spans(c,e.sp);return;}
    c->jumpPC=e.pc;c->jumpSP=e.sp;c->jumpTicket=e.ticket;c->jumpEnvironment=cpu->x[0];c->jumpRequested=1;
}
static void *forward_cpu(unsigned slot,const DHCPUContext *cpu) {
    DHCPUContext *forward=(DHCPUContext *)cpu;
    forward->pc=raw((uint64_t)__atomic_load_n(&g_dh_thunk_orig[slot],__ATOMIC_ACQUIRE));
    return (void *)((uintptr_t)cpu|1);
}
void *dh_control_boundary_claim(uint64_t slot,const DHCPUContext *cpu) {
    unsigned kind=dh_control_boundary_kind((unsigned)slot);if(!kind)return NULL;
    if(kind==DH_CONTROL_ROOT) {
        void *claimed=dh_live_control_claim(slot,cpu);return claimed?:forward_cpu((unsigned)slot,cpu);
    }
    DHControlSession *c=current_owner();
    if(kind==DH_CONTROL_SETJMP){
        uint64_t ticket=environment_snapshot(cpu->x[0],raw(cpu->x[30]),cpu->sp,c);
        if(c)event(c,CE_SETJMP_ENTRY,atomic_load(&boundaries[slot].target),cpu->sp,raw(cpu->x[30]),cpu->x[0],ticket);
        return forward_cpu((unsigned)slot,cpu);
    }
    if(kind==DH_CONTROL_LONGJMP){if(c)observe_jump(c,cpu);return forward_cpu((unsigned)slot,cpu);}
    if(!c || c->phase!=DH_CONTROL_NATIVE)return forward_cpu((unsigned)slot,cpu);
    uint64_t pc=atomic_load_explicit(&boundaries[slot].target,memory_order_acquire),link=0;unsigned reason=0;
    if(pc==c->rootReturn && cpu->sp==c->rootSP){reason=CE_ROOT_RETURN;link=c->rootTailTicket;c->resumeKind=2;}
    else if(c->jumpRequested && pc==c->jumpPC && cpu->sp==c->jumpSP){reason=CE_JUMP_RESUME;c->jumpRequested=0;prune_spans(c,cpu->sp);c->resumeKind=1;}
    else if(pc==c->padPC && cpu->sp==c->padSP){reason=CE_LANDING;c->padPC=0;prune_spans(c,cpu->sp);c->resumeKind=1;}
    else if(c->spanCount && pc==c->spans[c->spanCount-1].pc && cpu->sp==c->spans[c->spanCount-1].sp){reason=CE_RETURN;link=c->spans[c->spanCount-1].ticket;public_setjmp_return(c,&c->spans[c->spanCount-1]);c->spanCount--;c->resumeKind=1;retire_environments(c,cpu->sp);}
    if(!reason)return forward_cpu((unsigned)slot,cpu);
    DHControlEvent *resumed=event(c,reason,pc,cpu->sp,raw(cpu->x[30]),reason==CE_JUMP_RESUME?c->jumpTicket:link,cpu->x[0]);
    if(resumed && reason==CE_JUMP_RESUME)resumed->reference=c->jumpEnvironment;c->phase=DH_CONTROL_DBI;
    return dh_live_control_resume(c->transfer,cpu,pc,c->resumeKind);
}

typedef _Unwind_Reason_Code (*Personality)(int,_Unwind_Action,_Unwind_Exception_Class,struct _Unwind_Exception *,struct _Unwind_Context *);
static _Unwind_Reason_Code personality(unsigned index,int version,_Unwind_Action action,_Unwind_Exception_Class cls,struct _Unwind_Exception *exception,struct _Unwind_Context *context) {
    Personality original=(Personality)__atomic_load_n(&personalityOriginal[index],__ATOMIC_ACQUIRE);
    DHControlSession *c=current_owner();int tracking=c && c->phase==DH_CONTROL_NATIVE;if(tracking)c->personalityDepth++;
    _Unwind_Reason_Code result=original(version,action,cls,exception,context);
    if(tracking && --c->personalityDepth==0 && c==current_owner() && (action&_UA_CLEANUP_PHASE) && result==_URC_INSTALL_CONTEXT) {
        uint64_t pc=raw(_Unwind_GetIP(context)),sp=_Unwind_GetCFA(context);
        if(!valid_sp(c,sp)){gap(c,"invalid public unwind CFA",pc,sp);return result;}
        if(sp>=c->rootSP){event(c,CE_LANDING_NATIVE,pc,sp,0,(uint64_t)exception,action);escape(c,"exception-outside-observed-root",1);}
        else {
            prune_spans(c,sp);event(c,instrumented(c,pc)?CE_PUBLIC_INSTALL:CE_LANDING_NATIVE,pc,sp,0,(uint64_t)exception,action);
            if(instrumented(c,pc) && checkpoint(c,pc)){c->padPC=pc;c->padSP=sp;}
        }
    }
    return result;
}
static _Unwind_Reason_Code cpp_personality(int v,_Unwind_Action a,_Unwind_Exception_Class c,struct _Unwind_Exception *e,struct _Unwind_Context *x){return personality(0,v,a,c,e,x);}
static _Unwind_Reason_Code objc_personality(int v,_Unwind_Action a,_Unwind_Exception_Class c,struct _Unwind_Exception *e,struct _Unwind_Context *x){return personality(1,v,a,c,e,x);}

int dh_control_prepare(char *error,size_t size) {
#if !DH_HAVE_QBDI
    if(error && size)strlcpy(error,"QBDI control backend is not linked",size);return 0;
#else
    pthread_mutex_lock(&prepareLock);
    if(atomic_load(&attempted)){int ready=atomic_load(&prepared);if(!ready && error && size)strlcpy(error,prepareReason,size);pthread_mutex_unlock(&prepareLock);return ready;}
    atomic_store(&attempted,1);int ok=qbdi_idhOriginalA64Version()==2 && qbdi_idhSetOriginalA64Reader(original_instruction);
    if(!ok)strlcpy(prepareReason,"pinned QBDI control ABI 2 dependency required",sizeof(prepareReason));
    const char *personas[]={"__gxx_personality_v0","__objc_personality_v0"};void *relays[]={(void *)cpp_personality,(void *)objc_personality};
    for(unsigned i=0;ok && i<2;i++) {
        uint64_t target=native_symbol(personas[i]);
        ok=target && dh_thunk_install_adapter(target,relays[i],&personalityOriginal[i],i?"QBDI ObjC personality":"QBDI CXX personality","Itanium five-parameter unwind personality",prepareReason,sizeof(prepareReason))>=0;
        if(!target)strlcpy(prepareReason,"required native unwind personality is unavailable",sizeof(prepareReason));
    }
    const char *jumps[]={"setjmp","_setjmp","longjmp","_longjmp"};
    for(unsigned i=0;ok && i<4;i++) {
        uint64_t target=native_symbol(jumps[i]);dh_hook_options options;dh_thunk_options_default(&options);
        ok=target && dh_thunk_install_native_boundary(target,i<2?DH_CONTROL_SETJMP:DH_CONTROL_LONGJMP,&options,jumps[i],prepareReason,sizeof(prepareReason))>=0;
        if(!target)strlcpy(prepareReason,"required native setjmp/longjmp entry is unavailable",sizeof(prepareReason));
    }
    const char *noReturn[]={"longjmp","_longjmp","siglongjmp","__cxa_throw","__cxa_rethrow","objc_exception_throw","objc_exception_rethrow","_Unwind_Resume",NULL};
    for(unsigned i=0;noReturn[i];i++){uint64_t pc=native_symbol(noReturn[i]);if(pc)noreturnTargets[noreturnCount++]=pc;}
    const char *captures[]={"setjmp","_setjmp","sigsetjmp"};
    for(unsigned i=0;i<3;i++){uint64_t pc=native_symbol(captures[i]);if(pc)captureTargets[captureTargetCount++]=pc;}
    if(ok){strlcpy(prepareReason,"native entries prepared; owned calibration required",sizeof(prepareReason));atomic_store(&prepared,1);}
    else if(error && size)strlcpy(error,prepareReason,size);
    pthread_mutex_unlock(&prepareLock);return ok;
#endif
}
unsigned dh_control_option(void) {
#if DH_HAVE_QBDI
    return qbdi_idhNativeHandoffOption();
#else
    return 0;
#endif
}
int dh_control_initialize(DHControlSession *c,void *vm,void *transfer,uint64_t target,char *error,size_t size) {
    memset(c,0,sizeof(*c));c->enabled=1;c->vm=vm;c->transfer=transfer;c->target=target;
    Dl_info info={0};int savedInternal=dh_in_hook;dh_in_hook=1;int foundImage=dladdr((void *)target,&info);dh_in_hook=savedInternal;
    if(!foundImage || !info.dli_fbase)goto failed;
    const struct mach_header_64 *h=info.dli_fbase;if(h->magic!=MH_MAGIC_64 || h->ncmds>4096 || h->sizeofcmds>(1u<<20))goto failed;
    intptr_t slide=0;int found=0;for(uint32_t i=0;i<_dyld_image_count();i++)if(_dyld_get_image_header(i)==(const struct mach_header *)h){slide=_dyld_get_image_vmaddr_slide(i);found=1;break;}
    if(!found)goto failed;
    const uint8_t *cursor=(const uint8_t *)(h+1),*end=cursor+h->sizeofcmds;
    for(unsigned i=0;i<h->ncmds;i++) {
        if((size_t)(end-cursor)<sizeof(struct load_command))goto failed;const struct load_command *lc=(const void *)cursor;
        if(lc->cmdsize<sizeof(*lc) || lc->cmdsize>(size_t)(end-cursor))goto failed;
        if(lc->cmd==LC_SEGMENT_64) {
            if(lc->cmdsize<sizeof(struct segment_command_64))goto failed;const struct segment_command_64 *segment=(const void *)lc;
            if(segment->initprot&VM_PROT_EXECUTE) {
                if(c->rangeCount==DH_CONTROL_RANGES || !segment->vmsize)goto failed;
                uint64_t start=segment->vmaddr+slide;if(start+segment->vmsize<start)goto failed;
                c->ranges[c->rangeCount++]=(DHControlRange){start,start+segment->vmsize};
            }
        }
        cursor+=lc->cmdsize;
    }
    c->opaqueCount=dh_thunk_opaque_inline_ranges(c->opaque,DH_CONTROL_OPAQUE);if(c->opaqueCount>DH_CONTROL_OPAQUE)goto failed;
#if DH_HAVE_QBDI
    // A legacy 20B veneer first spills IP0/IP1. Transferring after that spill
    // would mistake its temporary SP for the real native call SP. Exit before
    // the entire retained veneer; the original standard native call forwards
    // through its existing adapter and returns to the exact caller checkpoint.
    for(unsigned i=0;i<c->opaqueCount;i++)qbdi_removeInstrumentedRange(c->vm,c->opaque[i].start,c->opaque[i].end);
#endif
    if(instrumented(c,target))return 1;
failed:
    if(error && size)strlcpy(error,"control root executable Mach-O ranges cannot be verified",size);return 0;
}
int dh_control_begin(DHControlSession *c,const DHCPUContext *entry,uint64_t threadID) {
    c->ownerThread=(uintptr_t)pthread_self();c->threadID=threadID;c->rootSP=entry->sp;c->rootReturn=raw(entry->x[30]);
    c->stackHigh=(uintptr_t)pthread_get_stackaddr_np(pthread_self());c->stackLow=c->stackHigh-pthread_get_stacksize_np(pthread_self());
    if(!valid_sp(c,c->rootSP) || !checkpoint(c,c->rootReturn))return 0;
    DHControlSession *empty=NULL;if(!atomic_compare_exchange_strong_explicit(&owner,&empty,c,memory_order_release,memory_order_relaxed))return 0;
    c->phase=DH_CONTROL_DBI;return 1;
}
void dh_control_instruction(DHControlSession *c,uint64_t pc,uint64_t sp,int isReturn) {
    c->lastReturn=isReturn;
    if(c->spanCount && pc==c->spans[c->spanCount-1].pc && sp==c->spans[c->spanCount-1].sp){public_setjmp_return(c,&c->spans[c->spanCount-1]);event(c,CE_RETURN,pc,sp,0,c->spans[c->spanCount-1].ticket,0);c->spanCount--;}
    if(isReturn)retire_environments(c,sp);
}
void dh_control_handoff(DHControlSession *c,const DHCPUContext *cpu) {
    uint64_t pc=raw(cpu->pc),lr=raw(cpu->x[30]),ticket=++c->nextSpan;c->phase=DH_CONTROL_NATIVE;event(c,CE_NATIVE,pc,cpu->sp,lr,c->lastReturn,ticket);
    int noReturn=0;for(unsigned i=0;i<noreturnCount;i++)if(pc==noreturnTargets[i])noReturn=1;
    if(c->lastReturn || noReturn)return;
    if(lr==c->rootReturn && cpu->sp==c->rootSP){c->rootTailTicket=ticket;return;}
    if(!valid_sp(c,cpu->sp) || !instrumented(c,lr)){gap(c,"native call has no owned return continuation",lr,cpu->sp);return;}
    if(c->spanCount==DH_CONTROL_SPANS){gap(c,"native continuation depth budget",lr,cpu->sp);return;}
    uint64_t environment=0;for(unsigned i=0;i<captureTargetCount;i++)if(pc==captureTargets[i])environment=cpu->x[0];
    if(checkpoint(c,lr))c->spans[c->spanCount++]=(DHControlSpan){.pc=lr,.sp=cpu->sp,.ticket=ticket,.environment=environment};
}
void dh_control_finish(DHControlSession *c) {
    if(!c->enabled)return;
    if(c->phase!=DH_CONTROL_TERMINAL && (c->spanCount || c->jumpRequested || c->padPC))gap(c,"native continuation not observed before root return",c->rootReturn,c->rootSP);
    c->phase=DH_CONTROL_TERMINAL;DHControlSession *expected=c;
    atomic_compare_exchange_strong_explicit(&owner,&expected,NULL,memory_order_release,memory_order_relaxed);
}
static NSString *hex(uint64_t value){return [NSString stringWithFormat:@"0x%llx",value];}
NSDictionary *DHControlSnapshot(const DHControlSession *c) {
    NSMutableArray *rows=[NSMutableArray array];const char *names[]={"", "native-handoff","native-return","landing-pad-resumed","native-landing-pad-install","longjmp-entry","longjmp-resumed","nonlocal-exit","coverage-gap","root-native-return","environment-retired","public-landing-pad-install","public-setjmp-return","setjmp-entry"};
    for(unsigned i=0;i<c->eventCount;i++) {
        const DHControlEvent *e=&c->events[i];NSMutableDictionary *row=[@{@"sequence":@(e->sequence),@"kind":@(names[e->kind]),@"observedNs":hex(e->when),@"pc":hex(e->pc),@"sp":hex(e->sp),@"lr":hex(e->lr)} mutableCopy];
        if(e->kind==CE_NATIVE){row[@"transferTicket"]=@(e->word1);row[@"handoffKind"]=e->word0?@"return-to-native":@"native-call-or-tail";}
        else if(e->kind==CE_RETURN || e->kind==CE_ROOT_RETURN){row[@"transferTicket"]=@(e->word0);row[@"x0"]=hex(e->word1);}
        else if(e->kind==CE_PUBLIC_INSTALL || e->kind==CE_LANDING_NATIVE){row[@"exceptionArgument"]=hex(e->word0);row[@"unwindActions"]=@(e->word1);}
        else if(e->kind==CE_LANDING)row[@"landingX0"]=hex(e->word1);
        else if(e->kind==CE_SETJMP_ENTRY){row[@"environment"]=hex(e->word0);row[@"environmentTicket"]=@(e->word1);}
        else if(e->kind==CE_SETJMP_RETURN){row[@"environment"]=hex(e->word0);row[@"transferTicket"]=@(e->word1);row[@"environmentTicket"]=@(e->reference);}
        else if(e->kind==CE_JUMP_ENTRY){row[@"environment"]=hex(e->word0);row[@"environmentTicket"]=@(e->reference);row[@"requestedValue"]=@((int32_t)e->word1);}
        else if(e->kind==CE_JUMP_RESUME){row[@"environment"]=hex(e->reference);row[@"environmentTicket"]=@(e->word0);row[@"restoredX0"]=hex(e->word1);}
        else if(e->kind==CE_ESCAPE)row[@"exitObservation"]=@(e->word0);
        else if(e->kind==CE_GAP)row[@"gapIndex"]=@(e->word0);
        [rows addObject:row];
    }
    return @{@"abi":@"standard-native-C-CXX-ObjC; IP0-IP1-call-boundary-scratch",@"events":rows,@"eventsLost":@(c->eventLost),@"coverageGaps":@(c->gaps),@"firstGapReason":@(c->gapReason),@"interruptedVMRetained":@(c->vmAbandoned!=0),@"privateJumpBufferFieldsRead":@NO,@"continuationsMatchOriginalSP":@YES};
}
NSDictionary *DHControlState(void) {
    char reason[256];pthread_mutex_lock(&prepareLock);strlcpy(reason,prepareReason,sizeof(reason));pthread_mutex_unlock(&prepareLock);
    unsigned roots=0,points=0,observers=0;for(unsigned i=0;i<DH_THUNK_COUNT;i++){unsigned kind=dh_control_boundary_kind(i);roots+=kind==DH_CONTROL_ROOT;points+=kind==DH_CONTROL_CHECKPOINT;observers+=kind==DH_CONTROL_SETJMP || kind==DH_CONTROL_LONGJMP;}
    return @{@"prepared":@(atomic_load(&prepared)!=0),@"attempted":@(atomic_load(&attempted)!=0),@"active":@(atomic_load(&owner)!=NULL),@"reason":@(reason),@"rootScope":@"App/owned fixture code; system helpers remain native",@"retainedRoots":@(roots),@"retainedContinuations":@(points),@"jumpEntries":@(observers),@"patchesRetainedUntilRestart":@YES,@"breakpointBackend":DHControlBreakpointState()};
}
