#import "dh_unwind.h"
#import "dh_event.h"
#include <libunwind.h>
#include <ptrauth.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include "dh_vm_map.h"
#include "dh_unwind_recipe.h"
#include "dh_health.h"

static __typeof(unw_getcontext) *captureContext;
static __typeof(unw_init_local) *initializeCursor;
static __typeof(unw_set_reg) *setRegister;
static __typeof(unw_get_reg) *getRegister;
static __typeof(unw_step) *stepCursor;
static __typeof(unw_get_proc_info) *getProcedure;
static __typeof(unw_get_fpreg) *getFloatRegister;
static __typeof(unw_set_fpreg) *setFloatRegister;
static void *unwindLibrary;
static void *function(const char *name) {
    void *p=dlsym(unwindLibrary,name);
    if (!p) return NULL;
    return ptrauth_sign_unauthenticated(ptrauth_strip(p,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0);
}
__attribute__((constructor)) static void prepare_unwind(void) {
    // 系统 iOS SDK 不提供 libunwind 链接桩；设备上的系统库已在握手时独立验证。
    unwindLibrary=dlopen("/usr/lib/system/libunwind.dylib",RTLD_NOW|RTLD_LOCAL);
    if (!unwindLibrary) return;
    captureContext=function("unw_getcontext");initializeCursor=function("unw_init_local");
    setRegister=function("unw_set_reg");getRegister=function("unw_get_reg");stepCursor=function("unw_step");
    getProcedure=function("unw_get_proc_info");
    getFloatRegister=function("unw_get_fpreg");setFloatRegister=function("unw_set_fpreg");
}
int dh_unwind_available(void) {return captureContext && initializeCursor && setRegister && getRegister && stepCursor && getProcedure;}
int dh_unwind_recipe_available(void) {
#if defined(__arm64__) || defined(__aarch64__)
    return dh_unwind_available() && getFloatRegister && setFloatRegister;
#else
    return 0;
#endif
}
int dh_unwind_bounds(uint64_t pc,uint64_t *start,uint64_t *end) {
    if (!dh_unwind_available()) return 0;
    unw_context_t context;unw_cursor_t cursor;unw_proc_info_t info;
    if (captureContext(&context) || initializeCursor(&cursor,&context) || setRegister(&cursor,UNW_REG_IP,pc) || getProcedure(&cursor,&info)) return 0;
    *start=info.start_ip;*end=info.end_ip;return *start<=pc && pc<*end;
}

static uint64_t code(uint64_t value) {
    return (uint64_t)ptrauth_strip((void *)(uintptr_t)value,ptrauth_key_return_address);
}
enum { DH_UNWIND_RECIPES=32,REJECT_CODE_READ=8,REJECT_CODE_CHANGED,REJECT_REG_SNAPSHOT,REJECT_REG_APPLY,REJECT_COUNT };
static const char *rejectionNames[]={"none","unverified-body","thread-stack-bounds","SP-FP-relation","stack-read","saved-FP","unsigned-return-PC","callsite","code-read","code-changed","register-snapshot","register-application"};
typedef struct {
    uint64_t start,end;uint32_t words[DH_RECIPE_INSNS];DHFrameRecipe recipe;
    char boundary[32];_Atomic int enabled;
    _Atomic uint64_t recovered,rejected[REJECT_COUNT];
} DHUnwindRule;
static DHUnwindRule rules[DH_UNWIND_RECIPES];static _Atomic unsigned ruleCount;
static pthread_mutex_t ruleLock=PTHREAD_MUTEX_INITIALIZER;
static int safe_read(void *unused,uint64_t address,void *output,size_t length) {
    (void)unused;vm_size_t copied=0;
    return length && vm_read_overwrite(mach_task_self(),(vm_address_t)address,(vm_size_t)length,(vm_address_t)output,&copied)==KERN_SUCCESS && copied==length;
}
static int unsigned_executable(void *unused,uint64_t address) {
    (void)unused;return address==code(address) && dh_vm_address_executable(address);
}
NSDictionary *DHUnwindRegisterRecipe(uint64_t start,uint64_t end,NSString *boundary) {
    if(!dh_unwind_recipe_available())return @{@"ok":@NO,@"error":@"canonical unwind recovery requires the native arm64 GPR/FPR unwinder APIs"};
    if(start%4 || end%4 || start>=end || end-start>DH_RECIPE_INSNS*4 ||
       (![boundary isEqual:@"lc_function_starts"] && ![boundary isEqual:@"owned-assembly-fixture"]))
        return @{@"ok":@NO,@"error":@"unverified or oversized function boundary"};
    uint32_t words[DH_RECIPE_INSNS];DHFrameRecipe plan;char error[192]={0};
    if(!unsigned_executable(NULL,start) || !unsigned_executable(NULL,end-4) || !safe_read(NULL,start,words,(size_t)(end-start)))return @{@"ok":@NO,@"error":@"recipe function code must be currently readable and executable"};
    if(!dh_recipe_validate(words,(unsigned)(end-start)/4,&plan,error,sizeof(error)))return @{@"ok":@NO,@"error":@(error)};
    pthread_mutex_lock(&ruleLock);unsigned count=atomic_load(&ruleCount);
    for(unsigned i=0;i<count;i++)if(start<rules[i].end && end>rules[i].start) {
        BOOL same=start==rules[i].start && end==rules[i].end && !memcmp(words,rules[i].words,(size_t)(end-start));
        BOOL enabled=atomic_load(&rules[i].enabled);pthread_mutex_unlock(&ruleLock);return same?@{@"ok":@YES,@"recipeSlot":@(i+1),@"alreadyRegistered":@YES,@"enabled":@(enabled)}:@{@"ok":@NO,@"error":@"recipe range overlaps an immutable registration; restart before replacing it"};
    }
    if(count==DH_UNWIND_RECIPES){pthread_mutex_unlock(&ruleLock);return @{@"ok":@NO,@"error":@"recipe registry capacity exhausted; slots are never reused"};}
    DHUnwindRule *r=&rules[count];r->start=start;r->end=end;r->recipe=plan;memcpy(r->words,words,(size_t)(end-start));strlcpy(r->boundary,boundary.UTF8String,sizeof(r->boundary));
    atomic_store(&r->enabled,1);atomic_store_explicit(&ruleCount,count+1,memory_order_release);pthread_mutex_unlock(&ruleLock);
    return @{@"ok":@YES,@"recipeSlot":@(count+1),@"enabled":@YES,@"instructionSlots":@(plan.count),@"eligiblePoints":@(plan.eligible),@"boundarySource":boundary};
}
NSDictionary *DHUnwindSetRecipeEnabled(unsigned slot,BOOL enabled) {
    if(!slot || slot>atomic_load_explicit(&ruleCount,memory_order_acquire))return @{@"ok":@NO,@"error":@"unknown recipe slot in this process"};
    atomic_store_explicit(&rules[slot-1].enabled,enabled,memory_order_release);return @{@"ok":@YES,@"recipeSlot":@(slot),@"enabled":@(enabled)};
}
NSDictionary *DHUnwindRecipeState(void) {
    unsigned count=atomic_load_explicit(&ruleCount,memory_order_acquire);NSMutableArray *rows=[NSMutableArray array];
    for(unsigned i=0;i<count;i++) {
        DHUnwindRule *r=&rules[i];NSMutableDictionary *rejected=[NSMutableDictionary dictionary];
        for(unsigned j=1;j<REJECT_COUNT;j++)rejected[@(rejectionNames[j])]=@(atomic_load(&r->rejected[j]));
        [rows addObject:@{@"recipeSlot":@(i+1),@"enabled":@((BOOL)atomic_load(&r->enabled)),@"start":[NSString stringWithFormat:@"0x%llx",r->start],@"end":[NSString stringWithFormat:@"0x%llx",r->end],
            @"identity":DHTargetIdentity((void *)(uintptr_t)r->start),@"boundarySource":@(r->boundary),@"instructionSlots":@(r->recipe.count),@"eligiblePoints":@(r->recipe.eligible),@"recoveredSteps":@(atomic_load(&r->recovered)),@"rejections":rejected}];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"backendAvailable":@((BOOL)dh_unwind_recipe_available()),@"recipes":rows,@"maxRecipes":@32,@"maxInstructions":@256,@"maxFrameBytes":@512,
        @"scope":@"read-only canonical unsigned A64 frame recovery with explicit opt-in precedence; no FP scanning or App exception/CFI mutation"};
}
static DHUnwindRule *rule_for_pc(uint64_t pc) {
    unsigned count=atomic_load_explicit(&ruleCount,memory_order_acquire);
    for(unsigned i=0;i<count;i++)if(pc>=rules[i].start && pc<rules[i].end && atomic_load_explicit(&rules[i].enabled,memory_order_acquire))return &rules[i];
    return NULL;
}
typedef struct {uint64_t driverSP,marker20,endMarker;DHRawStack raw;unsigned markerSeen,markerMatched;} DHRecipeFixtureContext;
static __thread DHRecipeFixtureContext *recipeFixture;
typedef struct {uint64_t x[31];unw_fpreg_t d[8];int valid;} DHCursorSnapshot;
static DHCursorSnapshot cursor_snapshot(unw_cursor_t *cursor) {
    DHCursorSnapshot saved={0};
#if defined(__arm64__) || defined(__aarch64__)
    saved.valid=dh_unwind_recipe_available();
    for(unsigned i=0;i<31 && saved.valid;i++){unw_word_t value=0;saved.valid=!getRegister(cursor,(int)i,&value);saved.x[i]=value;}
    for(unsigned i=0;i<8 && saved.valid;i++)saved.valid=!getFloatRegister(cursor,UNW_ARM64_D8+(int)i,&saved.d[i]);
#else
    (void)cursor;
#endif
    return saved;
}
static unsigned repair_cursor(unw_cursor_t *cursor,DHUnwindRule *rule,uint64_t pc,uint64_t sp,DHCursorSnapshot *before,DHRawStack *out) {
    unsigned reason=0;uint32_t bytes[DH_RECIPE_INSNS];uint64_t restored[31],callerSP=0,callerPC=0;
    if(pc%4 || !dh_recipe_eligible(&rule->recipe.points[(pc-rule->start)/4])){reason=DH_RECIPE_BODY_UNVERIFIED;goto failed;}
    if(!before->valid){reason=REJECT_REG_SNAPSHOT;goto failed;}
    if(!safe_read(NULL,rule->start,bytes,(size_t)(rule->end-rule->start))){reason=REJECT_CODE_READ;goto failed;}
    if(memcmp(bytes,rule->words,(size_t)(rule->end-rule->start))){reason=REJECT_CODE_CHANGED;goto failed;}
    reason=dh_recipe_restore(&rule->recipe.points[(pc-rule->start)/4],before->x,sp,before->x[29],out->stackLow,out->stackHigh,safe_read,unsigned_executable,NULL,restored,&callerSP,&callerPC);
    if(reason)goto failed;
#if defined(__arm64__) || defined(__aarch64__)
    // A failed unw_step may have changed its opaque cursor. Reinitialize via
    // the public API, restore the complete GPR snapshot plus nonvolatile FPRs,
    // and refresh IP metadata. Never memcpy/parse a system cursor layout.
    unw_context_t context;
    if(captureContext(&context) || initializeCursor(cursor,&context)){reason=REJECT_REG_APPLY;goto failed;}
    for(unsigned i=0;i<31;i++)if(setRegister(cursor,(int)i,restored[i])){reason=REJECT_REG_APPLY;goto failed;}
    for(unsigned i=0;i<8;i++)if(setFloatRegister(cursor,UNW_ARM64_D8+(int)i,before->d[i])){reason=REJECT_REG_APPLY;goto failed;}
    if(setRegister(cursor,UNW_REG_SP,callerSP) || setRegister(cursor,UNW_REG_IP,callerPC) || setRegister(cursor,UNW_REG_SP,callerSP)){reason=REJECT_REG_APPLY;goto failed;}
    // Some unwinder versions adjust SP while changing IP (old procedure gp).
    // Explicitly set and verify the proven SP after the metadata refresh.
    unw_word_t value=0;
    if(getRegister(cursor,UNW_REG_SP,&value) || value!=callerSP || getRegister(cursor,UNW_REG_IP,&value) || code(value)!=callerPC){reason=REJECT_REG_APPLY;goto failed;}
    for(unsigned i=19;i<31;i++)if(getRegister(cursor,(int)i,&value) || value!=restored[i]){reason=REJECT_REG_APPLY;goto failed;}
    for(unsigned i=0;i<8;i++){unw_fpreg_t d=0;if(getFloatRegister(cursor,UNW_ARM64_D8+(int)i,&d) || memcmp(&d,&before->d[i],sizeof(d))){reason=REJECT_REG_APPLY;goto failed;}}
    if(recipeFixture){recipeFixture->markerSeen++;recipeFixture->markerMatched|=restored[19]==recipeFixture->driverSP && restored[20]==recipeFixture->marker20 && restored[29]==recipeFixture->driverSP;}
    atomic_fetch_add(&rule->recovered,1);out->recipe[out->count-1]=(uint8_t)(rule-rules+1);out->recipeRejection=0;return 1;
#endif
failed:
    if(!reason)reason=REJECT_REG_APPLY;
    atomic_fetch_add(&rule->rejected[reason],1);out->recipeRejection=reason;return 0;
}
const char *dh_unwind_stop_name(unsigned reason) {
    static const char *names[]={"legacy-or-unspecified","backend-unavailable","register-error","frame-cycle","procedure-unavailable","step-error","libunwind-metadata-stop","zero-pc","frame-budget","no-caller","encoded-record-truncated","registered-recipe-refused-before-system-step"};
    return reason<sizeof(names)/sizeof(*names)?names[reason]:"unknown";
}
static void stack_bounds(DHRawStack *out) {
    out->stackHigh=(uint64_t)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    uint64_t length=pthread_get_stacksize_np(pthread_self());
    if(length<=out->stackHigh)out->stackLow=out->stackHigh-length;
}
static void walk_cursor(unw_cursor_t *cursor,DHRawStack *out) {
    uint64_t previousPC=0,previousSP=0;
    while (out->count<DH_STACK_MAX) {
        unw_word_t pc=0,sp=0;
        if ((out->error=getRegister(cursor,UNW_REG_IP,&pc)) ||
            (out->error=getRegister(cursor,UNW_REG_SP,&sp))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
        pc=code(pc);
        out->terminalPC=pc;out->terminalSP=sp;out->terminalFP=0;
#if defined(__arm64__) || defined(__aarch64__)
        unw_word_t fp=0;if(!getRegister(cursor,29,&fp))out->terminalFP=fp;
#endif
        if (!pc) {out->complete=1;out->stopReason=DH_UNWIND_ZERO_PC;return;}
        if (pc==previousPC && sp==previousSP) {out->error=UNW_EBADFRAME;out->stopReason=DH_UNWIND_CYCLE;return;}
        for (unsigned i=0;i<out->count;i++) if (out->pc[i]==pc && out->sp[i]==sp) {out->error=UNW_EBADFRAME;out->stopReason=DH_UNWIND_CYCLE;return;}
        out->pc[out->count]=pc;out->sp[out->count++]=sp;
        previousPC=pc;previousSP=sp;
        DHUnwindRule *rule=rule_for_pc(pc);DHCursorSnapshot before={0};
        out->procedureStart=out->procedureEnd=0;
        if(rule) {
            before=cursor_snapshot(cursor);out->stepResult=0;
            if(repair_cursor(cursor,rule,pc,sp,&before,out)){out->error=0;continue;}
            out->error=UNW_EBADFRAME;out->stopReason=DH_UNWIND_RECIPE_REFUSED;return;
        }
        // 缺少展开信息不是正常线程根，不把它误报为完整栈。
        unw_proc_info_t info;
        if ((out->error=getProcedure(cursor,&info))) {out->stopReason=DH_UNWIND_NO_PROCEDURE;return;}
        out->procedureStart=info.start_ip;out->procedureEnd=info.end_ip;
        int step=stepCursor(cursor);
        out->stepResult=step;
        if (!step) {out->complete=1;out->stopReason=DH_UNWIND_METADATA_STOP;return;}
        if (step<0) {out->error=step;out->stopReason=DH_UNWIND_STEP_ERROR;return;}
    }
    out->truncated=1;out->stopReason=DH_UNWIND_FRAME_LIMIT;
}
void dh_unwind_current(DHRawStack *out) {
    memset(out,0,sizeof(*out));stack_bounds(out);
    if (!dh_unwind_available()) {out->error=UNW_ENOINFO;out->stopReason=DH_UNWIND_BACKEND_UNAVAILABLE;return;}
    unw_context_t context;unw_cursor_t cursor;
    if ((out->error=captureContext(&context)) || (out->error=initializeCursor(&cursor,&context))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
    walk_cursor(&cursor,out);
}
void dh_unwind_capture(const DHCPUContext *entry, uint64_t target, DHRawStack *out) {
    memset(out,0,sizeof(*out));stack_bounds(out);
#if defined(__arm64__) || defined(__aarch64__)
    // 入口的被调函数尚未建立栈帧；从真正 caller 的 callsite 状态开始展开。
    out->pc[0]=code(target); out->sp[0]=entry->sp; out->count=1;
    if (!dh_unwind_available()) {out->error=UNW_ENOINFO;out->stopReason=DH_UNWIND_BACKEND_UNAVAILABLE;return;}
    unw_context_t context; unw_cursor_t cursor;
    if ((out->error=captureContext(&context)) || (out->error=initializeCursor(&cursor,&context))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
    for (int i=0;i<31;i++) if ((out->error=setRegister(&cursor,i,entry->x[i]))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
    if ((out->error=setRegister(&cursor,UNW_REG_SP,entry->sp))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
    uint64_t caller=code(entry->x[30]);
    if (caller<4) { out->complete=1;out->stopReason=DH_UNWIND_NO_CALLER;return; }
    if ((out->error=setRegister(&cursor,UNW_REG_IP,caller-4))) {out->stopReason=DH_UNWIND_REGISTER_ERROR;return;}
    walk_cursor(&cursor,out);
#else
    (void)entry;(void)target;out->error=UNW_EBADREG;
#endif
}
NSString *DHEncodeRawStack(const DHRawStack *stack) {
    char text[DH_STACK_MAX*48+448];int used=snprintf(text,sizeof(text),"IDH_NATIVE_STACK_V3 %u %d %d %d %u %d %llx %llx %llx %llx %llx %llx %llx %u\n",stack->count,stack->complete,stack->truncated,stack->error,stack->stopReason,stack->stepResult,stack->terminalPC,stack->terminalSP,stack->terminalFP,stack->stackLow,stack->stackHigh,stack->procedureStart,stack->procedureEnd,stack->recipeRejection);
    for (unsigned i=0;i<stack->count && used>0 && used<(int)sizeof(text);i++)
        used+=snprintf(text+used,sizeof(text)-used,"%llx %llx %u\n",stack->pc[i],stack->sp[i],stack->recipe[i]);
    return [[NSString alloc] initWithBytes:text length:MIN((size_t)MAX(used,0),sizeof(text)-1) encoding:NSUTF8StringEncoding]?:@"";
}
NSDictionary *DHDecodeRawStack(NSString *text) {
    BOOL v3=[text hasPrefix:@"IDH_NATIVE_STACK_V3 "],v2=[text hasPrefix:@"IDH_NATIVE_STACK_V2 "];
    if (!v3 && !v2 && ![text hasPrefix:@"IDH_NATIVE_STACK_V1 "]) return nil;
    NSArray *lines=[text componentsSeparatedByString:@"\n"];DHRawStack stack={0};unsigned count=0;
    if(v3 || v2) {
        unsigned long long pc=0,sp=0,fp=0,low=0,high=0,start=0,end=0;unsigned version=0,rejection=0;
        int fields=sscanf([lines[0] UTF8String],"IDH_NATIVE_STACK_V%u %u %d %d %d %u %d %llx %llx %llx %llx %llx %llx %llx %u",&version,&count,&stack.complete,&stack.truncated,&stack.error,&stack.stopReason,&stack.stepResult,&pc,&sp,&fp,&low,&high,&start,&end,&rejection);
        if(fields!=(v3?15:14) || count>DH_STACK_MAX || (v3 && rejection>=REJECT_COUNT))return nil;
        stack.recipeRejection=rejection;stack.terminalPC=pc;stack.terminalSP=sp;stack.terminalFP=fp;stack.stackLow=low;stack.stackHigh=high;stack.procedureStart=start;stack.procedureEnd=end;
    } else if(sscanf([lines[0] UTF8String],"IDH_NATIVE_STACK_V1 %u %d %d %d",&count,&stack.complete,&stack.truncated,&stack.error)!=4 || count>DH_STACK_MAX)return nil;
    for (NSUInteger i=1;i<lines.count && stack.count<count;i++) {
        unsigned long long pc=0,sp=0;unsigned slot=0;
        int fields=sscanf([lines[i] UTF8String],"%llx %llx %u",&pc,&sp,&slot);
        if(fields!=(v3?3:2) || slot>DH_UNWIND_RECIPES)break;
        stack.pc[stack.count]=pc;stack.sp[stack.count]=sp;stack.recipe[stack.count++]=(uint8_t)slot;
    }
    if (stack.count!=count) {stack.complete=0;stack.truncated=1;stack.stopReason=DH_UNWIND_RECORD_TRUNCATED;}
    return DHStackDictionary(&stack);
}
NSString *DHStackText(NSDictionary *stack) {
    NSMutableString *text=[NSMutableString string];unsigned index=0;
    for (NSDictionary *frame in stack[@"frames"]) {
        NSDictionary *identity=frame[@"identity"];
        [text appendFormat:@"[%02u] %@ %@ %@ + %@\n",index++,frame[@"pc"],frame[@"symbol"]?[NSString stringWithFormat:@"%@+%@",frame[@"symbol"],frame[@"symbolOffset"]?:@"0"]:@"",[identity[@"image"] lastPathComponent]?:@"",identity[@"rva"]?:@""];
    }
    [text appendFormat:@"unwind complete=%@ truncated=%@ error=%@ stop=%@",stack[@"complete"],stack[@"truncated"],stack[@"error"],stack[@"termination"][@"reason"]?:@"legacy"];return text;
}
NSDictionary *DHStackDictionary(const DHRawStack *s) {
    NSMutableArray *frames=[NSMutableArray arrayWithCapacity:s->count];unsigned recovered=0;
    for (unsigned i=0;i<s->count;i++) {
        NSMutableDictionary *frame=[@{@"pc":[NSString stringWithFormat:@"0x%llx",s->pc[i]],@"sp":[NSString stringWithFormat:@"0x%llx",s->sp[i]]} mutableCopy];
        if(s->recipe[i]){frame[@"unwindRecipeSlot"]=@(s->recipe[i]);frame[@"unwindSource"]=@"validated-canonical-frame-recipe";recovered++;}
        if(i && s->recipe[i-1]){frame[@"pcSemantics"]=@"verified-saved-return-address-minus-4";frame[@"savedReturnAddress"]=[NSString stringWithFormat:@"0x%llx",s->pc[i]+4];}
        [frames addObject:frame];
    }
    return @{@"method":recovered?@"libunwind-with-validated-canonical-frame-recovery":@"libunwind-caller-context-with-thunk-CFI",@"frames":frames,
        @"complete":@(s->complete!=0),@"truncated":@(s->truncated!=0),@"error":@(s->error),@"recoveredSteps":@(recovered),
        @"scope":@"current synchronous native thread; no async/tail-call reconstruction",@"symbolication":@"deferred",
        @"termination":@{@"reason":@(dh_unwind_stop_name(s->stopReason)),@"stepResult":@(s->stepResult),@"pc":[NSString stringWithFormat:@"0x%llx",s->terminalPC],@"sp":[NSString stringWithFormat:@"0x%llx",s->terminalSP],@"fp":[NSString stringWithFormat:@"0x%llx",s->terminalFP],@"procedureStart":[NSString stringWithFormat:@"0x%llx",s->procedureStart],@"procedureEnd":[NSString stringWithFormat:@"0x%llx",s->procedureEnd],@"threadStackLow":[NSString stringWithFormat:@"0x%llx",s->stackLow],@"threadStackHigh":[NSString stringWithFormat:@"0x%llx",s->stackHigh],@"recipeRejection":@(s->recipeRejection<REJECT_COUNT?rejectionNames[s->recipeRejection]:"invalid-record")}};
}
NSDictionary *DHResolveStack(NSDictionary *stack, BOOL currentGeneration) {
    NSMutableDictionary *result=[stack mutableCopy];
    if (!currentGeneration) {result[@"symbolication"]=@"unavailable-for-old-generation";if([stack[@"recoveredSteps"] unsignedIntValue])result[@"recipeMetadata"]=@"unavailable-for-old-generation; slot is scoped to the event processGeneration";return result;}
    NSMutableArray *frames=[NSMutableArray array];
    for (NSDictionary *frame in stack[@"frames"]) {
        uint64_t pc=strtoull([frame[@"pc"] UTF8String],NULL,16);
        NSMutableDictionary *f=[frame mutableCopy];if(frame[@"unwindRecipeSlot"]){unsigned slot=[frame[@"unwindRecipeSlot"] unsignedIntValue];if(slot && slot<=atomic_load_explicit(&ruleCount,memory_order_acquire))f[@"unwindRecipeIdentity"]=DHTargetIdentity((void *)(uintptr_t)rules[slot-1].start);}
        f[@"identity"]=DHTargetIdentity((void *)(uintptr_t)pc);
        Dl_info info={0};int saved=dh_in_hook;dh_in_hook=1;
        if (dladdr((void *)(uintptr_t)pc,&info) && info.dli_sname) {
            f[@"symbol"]=@(info.dli_sname);
            f[@"symbolSource"]=@"dladdr-nearest; not a verified function boundary";
            f[@"symbolOffset"]=[NSString stringWithFormat:@"0x%llx",pc-(uint64_t)info.dli_saddr];
        }
        dh_in_hook=saved;[frames addObject:f];
    }
    result[@"frames"]=frames;result[@"symbolication"]=@"resolved-on-reader-thread";return result;
}

#if defined(__arm64__) || defined(__aarch64__)
// The owned incomplete FDE names a separately signed end-of-chain marker,
// never a raw undefined LR (which arm64e authenticates and traps on). Real
// execution keeps its independent frame record; the caller CFA requires x19.
__attribute__((noinline,optnone,used,visibility("hidden"))) void dh_recipe_fixture_capture(DHRecipeFixtureContext *context) {dh_unwind_current(&context->raw);}
extern unsigned dh_recipe_fixture_driver(DHRecipeFixtureContext *context);
extern void dh_recipe_fixture_driver_end(void),dh_recipe_fixture_gap(void),dh_recipe_fixture_gap_end(void);
__asm__(
".text\n.p2align 2\n.globl _dh_recipe_fixture_gap\n.private_extern _dh_recipe_fixture_gap\n"
"_dh_recipe_fixture_gap:\n.cfi_startproc\n"
"stp x20, x19, [sp, #-48]!\n.cfi_def_cfa_offset 48\n.cfi_offset 19, -40\n.cfi_offset 20, -48\nstp x29, x30, [sp, #32]\n.cfi_offset 29, -16\n.cfi_offset 30, -32\nadd x29, sp, #32\nldr x8, [x0, #16]\nstr x8, [sp, #16]\n"
"mov x19, #0x1919\nmov x20, #0x2020\nbl _dh_recipe_fixture_capture\n"
"ldp x29, x30, [sp, #32]\nldp x20, x19, [sp], #48\nret\n.cfi_endproc\n"
".globl _dh_recipe_fixture_gap_end\n.private_extern _dh_recipe_fixture_gap_end\n_dh_recipe_fixture_gap_end:\n"
".p2align 2\n.globl _dh_recipe_fixture_driver\n.private_extern _dh_recipe_fixture_driver\n"
"_dh_recipe_fixture_driver:\n.cfi_startproc\n"
#if defined(__arm64e__)
"pacibsp\n"
#endif
"stp x29, x30, [sp, #-64]!\n.cfi_def_cfa_offset 64\n.cfi_offset 29, -64\n.cfi_offset 30, -56\n"
"stp x19, x20, [sp, #16]\n.cfi_offset 19, -48\n.cfi_offset 20, -40\n"
"mov x29, sp\nmov x19, sp\n.cfi_def_cfa 19, 64\n"
"mov x20, #0x7a20\nstr x19, [x0]\nstr x20, [x0, #8]\n"
#if defined(__arm64e__)
"mov x8, xzr\npacib x8, x19\nstr x8, [x0, #16]\n"
#else
"str xzr, [x0, #16]\n"
#endif
"bl _dh_recipe_fixture_gap\n"
"mov x8, sp\ncmp x19, x8\ncset w0, eq\nmov x8, #0x7a20\ncmp x20, x8\ncset w8, eq\nand w0, w0, w8\n"
".cfi_def_cfa sp, 64\nldp x19, x20, [sp, #16]\n.cfi_restore 19\n.cfi_restore 20\n"
"ldp x29, x30, [sp], #64\n.cfi_restore 29\n.cfi_restore 30\n.cfi_def_cfa_offset 0\n"
#if defined(__arm64e__)
"autibsp\n"
#endif
"ret\n.cfi_endproc\n"
".globl _dh_recipe_fixture_driver_end\n.private_extern _dh_recipe_fixture_driver_end\n_dh_recipe_fixture_driver_end:\n"
);
__attribute__((noinline,optnone)) static unsigned recipe_fixture_root(DHRecipeFixtureContext *context) {return dh_recipe_fixture_driver(context);}
static int stack_contains(const DHRawStack *stack,uint64_t start,uint64_t end) {for(unsigned i=0;i<stack->count;i++)if(stack->pc[i]>=start && stack->pc[i]<end)return 1;return 0;}
#endif
NSDictionary *DHUnwindRecipeSelfTest(void) {
#if defined(__arm64__) || defined(__aarch64__)
    static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
    if(pthread_mutex_trylock(&lock))return @{@"pass":@NO,@"error":@"unwind recipe selftest is busy"};
    NSMutableDictionary *result=[@{@"pass":@NO} mutableCopy];unsigned slot=0;int previousEnabled=0;
    uint64_t start=code((uint64_t)dh_recipe_fixture_gap),end=code((uint64_t)dh_recipe_fixture_gap_end);
    uint64_t driver=code((uint64_t)dh_recipe_fixture_driver),driverEnd=code((uint64_t)dh_recipe_fixture_driver_end),rootStart=0,rootEnd=0;
    @try {
        if(!dh_unwind_recipe_available() || !dh_unwind_bounds(code((uint64_t)recipe_fixture_root),&rootStart,&rootEnd))[NSException raise:@"IDHUnwindFixture" format:@"native recipe APIs/root unwind metadata unavailable"];
        unsigned count=atomic_load_explicit(&ruleCount,memory_order_acquire);
        for(unsigned i=0;i<count;i++)if(rules[i].start==start && rules[i].end==end){slot=i+1;previousEnabled=atomic_load(&rules[i].enabled);DHUnwindSetRecipeEnabled(slot,NO);break;}
        result[@"fixtureRanges"]=@{@"gapStart":[NSString stringWithFormat:@"0x%llx",start],@"gapEnd":[NSString stringWithFormat:@"0x%llx",end],@"driverStart":[NSString stringWithFormat:@"0x%llx",driver],@"driverEnd":[NSString stringWithFormat:@"0x%llx",driverEnd],@"rootStart":[NSString stringWithFormat:@"0x%llx",rootStart],@"rootEnd":[NSString stringWithFormat:@"0x%llx",rootEnd]};
        DHRecipeFixtureContext baseline={0};
        unsigned baselineReturn=recipe_fixture_root(&baseline);result[@"baseline"]=DHStackDictionary(&baseline.raw);
        if(!baselineReturn || !stack_contains(&baseline.raw,start,end) || stack_contains(&baseline.raw,driver,driverEnd))[NSException raise:@"IDHUnwindFixture" format:@"owned missing-CFI baseline did not stop at the real gap"];
        NSDictionary *registration=DHUnwindRegisterRecipe(start,end,@"owned-assembly-fixture");
        if(![registration[@"ok"] boolValue])[NSException raise:@"IDHUnwindFixture" format:@"%@",registration[@"error"]];
        slot=[registration[@"recipeSlot"] unsignedIntValue];DHUnwindSetRecipeEnabled(slot,YES);
        DHRecipeFixtureContext repaired={0};recipeFixture=&repaired;unsigned original=recipe_fixture_root(&repaired);recipeFixture=NULL;
        BOOL used=NO;for(unsigned i=0;i<repaired.raw.count;i++)used|=repaired.raw.recipe[i]==slot;
        if(!original || !used || !repaired.markerSeen || !repaired.markerMatched || !stack_contains(&repaired.raw,driver,driverEnd) || !stack_contains(&repaired.raw,rootStart,rootEnd) || repaired.raw.error || repaired.raw.truncated || !repaired.raw.complete)
            [NSException raise:@"IDHUnwindFixture" format:@"restored caller GPR/CFA/root not proven (original %u, used %d, marker %u/%u)",original,used,repaired.markerSeen,repaired.markerMatched];
        result[@"repaired"]=DHStackDictionary(&repaired.raw);result[@"recipeSlot"]=@(slot);
        DHUnwindSetRecipeEnabled(slot,NO);DHRecipeFixtureContext disabled={0};
        if(!recipe_fixture_root(&disabled) || stack_contains(&disabled.raw,driver,driverEnd))[NSException raise:@"IDHUnwindFixture" format:@"disabling the recipe changed system CFI or original execution"];
        result[@"disabled"]=DHStackDictionary(&disabled.raw);
        NSDictionary *roundTrip=DHDecodeRawStack(DHEncodeRawStack(&repaired.raw));
        if([roundTrip[@"recoveredSteps"] unsignedIntValue]!=1 || ![roundTrip[@"complete"] boolValue])[NSException raise:@"IDHUnwindFixture" format:@"V3 recovery provenance did not roundtrip"];
        result[@"pass"]=@YES;result[@"passed"]=@[@"real-incomplete-CFI-stop-baseline",@"original-x19-x20-and-caller-FP-restored",@"x19-based-DWARF-CFA-reaches-original-root",@"original-CPU-registers-and-return-unchanged",@"disabled-recipe-keeps-original-metadata-gap",@"V3-provenance-roundtrip"];
    }@catch(NSException *error) {result[@"error"]=error.reason?:@"unwind fixture failed";}
    @finally {recipeFixture=NULL;if(slot)DHUnwindSetRecipeEnabled(slot,previousEnabled);pthread_mutex_unlock(&lock);}
    result[@"state"]=DHUnwindRecipeState();return result;
#else
    return @{@"pass":@NO,@"unsupported":@YES,@"error":@"canonical unwind fixture requires arm64"};
#endif
}
