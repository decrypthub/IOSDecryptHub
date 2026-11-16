#import "dh_unwind.h"
#import "dh_event.h"
#include <libunwind.h>
#include <ptrauth.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include "dh_health.h"

static __typeof(unw_getcontext) *captureContext;
static __typeof(unw_init_local) *initializeCursor;
static __typeof(unw_set_reg) *setRegister;
static __typeof(unw_get_reg) *getRegister;
static __typeof(unw_step) *stepCursor;
static __typeof(unw_get_proc_info) *getProcedure;
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
}
int dh_unwind_available(void) {return captureContext && initializeCursor && setRegister && getRegister && stepCursor && getProcedure;}
int dh_unwind_bounds(uint64_t pc,uint64_t *start,uint64_t *end) {
    if (!dh_unwind_available()) return 0;
    unw_context_t context;unw_cursor_t cursor;unw_proc_info_t info;
    if (captureContext(&context) || initializeCursor(&cursor,&context) || setRegister(&cursor,UNW_REG_IP,pc) || getProcedure(&cursor,&info)) return 0;
    *start=info.start_ip;*end=info.end_ip;return *start<=pc && pc<*end;
}

static uint64_t code(uint64_t value) {
    return (uint64_t)ptrauth_strip((void *)(uintptr_t)value,ptrauth_key_return_address);
}
static void walk_cursor(unw_cursor_t *cursor,DHRawStack *out) {
    uint64_t previousPC=0,previousSP=0;
    while (out->count<DH_STACK_MAX) {
        unw_word_t pc=0,sp=0;
        if ((out->error=getRegister(cursor,UNW_REG_IP,&pc)) ||
            (out->error=getRegister(cursor,UNW_REG_SP,&sp))) return;
        pc=code(pc);
        if (!pc) {out->complete=1;return;}
        if (pc==previousPC && sp==previousSP) {out->error=UNW_EBADFRAME;return;}
        for (unsigned i=0;i<out->count;i++) if (out->pc[i]==pc && out->sp[i]==sp) {out->error=UNW_EBADFRAME;return;}
        out->pc[out->count]=pc;out->sp[out->count++]=sp;
        previousPC=pc;previousSP=sp;
        // 缺少展开信息不是正常线程根，不把它误报为完整栈。
        unw_proc_info_t info;
        if ((out->error=getProcedure(cursor,&info))) return;
        int step=stepCursor(cursor);
        if (!step) {out->complete=1;return;}
        if (step<0) {out->error=step;return;}
    }
    out->truncated=1;
}
void dh_unwind_current(DHRawStack *out) {
    memset(out,0,sizeof(*out));
    if (!dh_unwind_available()) {out->error=UNW_ENOINFO;return;}
    unw_context_t context;unw_cursor_t cursor;
    if ((out->error=captureContext(&context)) || (out->error=initializeCursor(&cursor,&context))) return;
    walk_cursor(&cursor,out);
}
void dh_unwind_capture(const DHCPUContext *entry, uint64_t target, DHRawStack *out) {
    memset(out,0,sizeof(*out));
#if defined(__arm64__) || defined(__aarch64__)
    // 入口的被调函数尚未建立栈帧；从真正 caller 的 callsite 状态开始展开。
    out->pc[0]=code(target); out->sp[0]=entry->sp; out->count=1;
    if (!dh_unwind_available()) {out->error=UNW_ENOINFO;return;}
    unw_context_t context; unw_cursor_t cursor;
    if ((out->error=captureContext(&context)) || (out->error=initializeCursor(&cursor,&context))) return;
    for (int i=0;i<31;i++) if ((out->error=setRegister(&cursor,i,entry->x[i]))) return;
    if ((out->error=setRegister(&cursor,UNW_REG_SP,entry->sp))) return;
    uint64_t caller=code(entry->x[30]);
    if (caller<4) { out->complete=1;return; }
    if ((out->error=setRegister(&cursor,UNW_REG_IP,caller-4))) return;
    walk_cursor(&cursor,out);
#else
    (void)entry;(void)target;out->error=UNW_EBADREG;
#endif
}
NSString *DHEncodeRawStack(const DHRawStack *stack) {
    char text[DH_STACK_MAX*40+128];int used=snprintf(text,sizeof(text),"IDH_NATIVE_STACK_V1 %u %d %d %d\n",stack->count,stack->complete,stack->truncated,stack->error);
    for (unsigned i=0;i<stack->count && used>0 && used<(int)sizeof(text);i++)
        used+=snprintf(text+used,sizeof(text)-used,"%llx %llx\n",stack->pc[i],stack->sp[i]);
    return [[NSString alloc] initWithBytes:text length:MIN((size_t)MAX(used,0),sizeof(text)-1) encoding:NSUTF8StringEncoding]?:@"";
}
NSDictionary *DHDecodeRawStack(NSString *text) {
    if (![text hasPrefix:@"IDH_NATIVE_STACK_V1 "]) return nil;
    NSArray *lines=[text componentsSeparatedByString:@"\n"];DHRawStack stack={0};unsigned count=0;
    if (sscanf([lines[0] UTF8String],"IDH_NATIVE_STACK_V1 %u %d %d %d",&count,&stack.complete,&stack.truncated,&stack.error)!=4 || count>DH_STACK_MAX) return nil;
    for (NSUInteger i=1;i<lines.count && stack.count<count;i++) {
        unsigned long long pc=0,sp=0;
        if (sscanf([lines[i] UTF8String],"%llx %llx",&pc,&sp)!=2) break;
        stack.pc[stack.count]=pc;stack.sp[stack.count++]=sp;
    }
    if (stack.count!=count) {stack.complete=0;stack.truncated=1;}
    return DHStackDictionary(&stack);
}
NSString *DHStackText(NSDictionary *stack) {
    NSMutableString *text=[NSMutableString string];unsigned index=0;
    for (NSDictionary *frame in stack[@"frames"]) {
        NSDictionary *identity=frame[@"identity"];
        [text appendFormat:@"[%02u] %@ %@ %@ + %@\n",index++,frame[@"pc"],frame[@"symbol"]?[NSString stringWithFormat:@"%@+%@",frame[@"symbol"],frame[@"symbolOffset"]?:@"0"]:@"",[identity[@"image"] lastPathComponent]?:@"",identity[@"rva"]?:@""];
    }
    [text appendFormat:@"unwind complete=%@ truncated=%@ error=%@",stack[@"complete"],stack[@"truncated"],stack[@"error"]];return text;
}
NSDictionary *DHStackDictionary(const DHRawStack *s) {
    NSMutableArray *frames=[NSMutableArray arrayWithCapacity:s->count];
    for (unsigned i=0;i<s->count;i++) [frames addObject:@{
        @"pc":[NSString stringWithFormat:@"0x%llx",s->pc[i]],
        @"sp":[NSString stringWithFormat:@"0x%llx",s->sp[i]]}];
    return @{@"method":@"libunwind-caller-context-with-thunk-CFI",@"frames":frames,
        @"complete":@(s->complete!=0),@"truncated":@(s->truncated!=0),@"error":@(s->error),
        @"scope":@"current synchronous native thread; no async/tail-call reconstruction",
        @"symbolication":@"deferred"};
}
NSDictionary *DHResolveStack(NSDictionary *stack, BOOL currentGeneration) {
    NSMutableDictionary *result=[stack mutableCopy];
    if (!currentGeneration) {result[@"symbolication"]=@"unavailable-for-old-generation";return result;}
    NSMutableArray *frames=[NSMutableArray array];
    for (NSDictionary *frame in stack[@"frames"]) {
        uint64_t pc=strtoull([frame[@"pc"] UTF8String],NULL,16);
        NSMutableDictionary *f=[frame mutableCopy];f[@"identity"]=DHTargetIdentity((void *)(uintptr_t)pc);
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
