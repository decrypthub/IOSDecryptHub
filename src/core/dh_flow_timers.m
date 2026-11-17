#import "dh_flow_timers.h"
#import "dh_flow.h"
#import "dh_thunk.h"
#import "dh_event.h"
#include "dh_health.h"
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

enum { TIMER_BINDINGS=64,TIMER_SLOTS=128 };
static pthread_mutex_t timerLock=PTHREAD_MUTEX_INITIALIZER;
static const char timerBindingKey;
static unsigned bindingCount;
static _Atomic uint64_t rejectedBindings,unobservedTimers;
static void *nativeOriginal;
static uintptr_t nativeTarget;
static int nativeAdapter=-1;
static _Atomic int nativeReady;
static char nativeReason[256]="not prepared";
static _Atomic uintptr_t probeTimer,probeInfo;
static _Atomic unsigned probeEntries,probeMismatches;
static Class nativeTimerClasses[2];
static void *factoryOriginals[4];static Method factoryMethods[4];
static _Atomic int factoriesReady;static char factoryReason[256]="not prepared";
static __thread uintptr_t forwardingTimer,forwardingFunction;

@interface DHFlowTimerBinding:NSObject {
@public uint64_t registration;__weak NSTimer *timer;unsigned additions,removals;char lastMode[128];
}
@end
@implementation DHFlowTimerBinding
- (void)dealloc {DHFlowRetireCallback(registration,"timer-object-released");}
@end
static __weak DHFlowTimerBinding *observed[TIMER_BINDINGS];

static __typeof__(&CFRunLoopTimerCreate) original_create;
static __typeof__(&CFRunLoopTimerCreateWithHandler) original_handler;
static __typeof__(&CFRunLoopTimerInvalidate) original_invalidate;
static __typeof__(&CFRunLoopAddTimer) original_add;
static __typeof__(&CFRunLoopRemoveTimer) original_remove;
static __typeof__(&CFRunLoopPerformBlock) original_perform;
typedef void (*NativeFire)(CFRunLoopTimerRef,void *);
typedef struct {uint64_t registration;CFRunLoopTimerCallBack function;} TimerSlot;
static TimerSlot timerSlots[TIMER_SLOTS];

static void mode_label(CFTypeRef mode,char text[128]) {
    strlcpy(text,"runloop:",128);
    if(!mode){strlcat(text,"<manual-or-inactive>",128);return;}
    if(CFGetTypeID(mode)!=CFStringGetTypeID()){strlcat(text,"<mode-set>",128);return;}
    CFIndex used=0,length=CFStringGetLength((CFStringRef)mode);char buffer[104]={0};
    CFStringGetBytes((CFStringRef)mode,CFRangeMake(0,MIN(length,32)),kCFStringEncodingUTF8,'?',false,(UInt8 *)buffer,100,&used);
    buffer[used]=0;strlcat(text,buffer,128);if(length>32)strlcat(text,"~",128);
}
static void current_mode(char text[128]) {
    CFStringRef mode=CFRunLoopCopyCurrentMode(CFRunLoopGetCurrent());mode_label(mode,text);if(mode)CFRelease(mode);
}
static DHFlowTimerBinding *binding(CFRunLoopTimerRef timer) {return objc_getAssociatedObject((__bridge id)timer,&timerBindingKey);}
static DHFlowTimerBinding *bind_timer(CFRunLoopTimerRef timer,uint64_t registration) {
    if(!registration)return nil;
    if(!timer){DHFlowRetireCallback(registration,"timer-create-failed");return nil;}
    DHFlowTimerBinding *entry=[DHFlowTimerBinding new];entry->registration=registration;entry->timer=(__bridge NSTimer *)timer;
    pthread_mutex_lock(&timerLock);
    if(bindingCount==TIMER_BINDINGS){pthread_mutex_unlock(&timerLock);atomic_fetch_add(&rejectedBindings,1);DHFlowRetireCallback(registration,"timer-binding-capacity");return nil;}
    observed[bindingCount++]=entry;strlcpy(entry->lastMode,"runloop:<not-added>",128);pthread_mutex_unlock(&timerLock);
    objc_setAssociatedObject((__bridge id)timer,&timerBindingKey,entry,OBJC_ASSOCIATION_RETAIN_NONATOMIC);return entry;
}
static void invoke_timer(uint64_t registration,CFRunLoopTimerRef timer,dispatch_block_t body) {
    int saved=errno;char mode[128];current_mode(mode);DHFlowUpdateCallbackQueue(registration,mode);errno=saved;
    DHFlowRunCallback(registration,body);int final=errno;
    if(!CFRunLoopTimerIsValid(timer))DHFlowRetireCallback(registration,"timer-invalid-after-callback");errno=final;
}
static void timer_f_invoke(unsigned index,CFRunLoopTimerRef timer,void *info) {
    int saved=errno;pthread_mutex_lock(&timerLock);TimerSlot slot=timerSlots[index];pthread_mutex_unlock(&timerLock);
    errno=saved;invoke_timer(slot.registration,timer,^{
        uintptr_t oldTimer=forwardingTimer,oldFunction=forwardingFunction;
        forwardingTimer=(uintptr_t)timer;forwardingFunction=(uintptr_t)ptrauth_strip((void *)slot.function,ptrauth_key_function_pointer);
        @try {slot.function(timer,info);}@finally {forwardingTimer=oldTimer;forwardingFunction=oldFunction;}
    });
}
#define DH_TIMER_SLOT(N) static void timer_f_##N(CFRunLoopTimerRef timer,void *info) {timer_f_invoke(N,timer,info);}
DH_TIMER_SLOT(0)
DH_TIMER_SLOT(1)
DH_TIMER_SLOT(2)
DH_TIMER_SLOT(3)
DH_TIMER_SLOT(4)
DH_TIMER_SLOT(5)
DH_TIMER_SLOT(6)
DH_TIMER_SLOT(7)
DH_TIMER_SLOT(8)
DH_TIMER_SLOT(9)
DH_TIMER_SLOT(10)
DH_TIMER_SLOT(11)
DH_TIMER_SLOT(12)
DH_TIMER_SLOT(13)
DH_TIMER_SLOT(14)
DH_TIMER_SLOT(15)
DH_TIMER_SLOT(16)
DH_TIMER_SLOT(17)
DH_TIMER_SLOT(18)
DH_TIMER_SLOT(19)
DH_TIMER_SLOT(20)
DH_TIMER_SLOT(21)
DH_TIMER_SLOT(22)
DH_TIMER_SLOT(23)
DH_TIMER_SLOT(24)
DH_TIMER_SLOT(25)
DH_TIMER_SLOT(26)
DH_TIMER_SLOT(27)
DH_TIMER_SLOT(28)
DH_TIMER_SLOT(29)
DH_TIMER_SLOT(30)
DH_TIMER_SLOT(31)
DH_TIMER_SLOT(32)
DH_TIMER_SLOT(33)
DH_TIMER_SLOT(34)
DH_TIMER_SLOT(35)
DH_TIMER_SLOT(36)
DH_TIMER_SLOT(37)
DH_TIMER_SLOT(38)
DH_TIMER_SLOT(39)
DH_TIMER_SLOT(40)
DH_TIMER_SLOT(41)
DH_TIMER_SLOT(42)
DH_TIMER_SLOT(43)
DH_TIMER_SLOT(44)
DH_TIMER_SLOT(45)
DH_TIMER_SLOT(46)
DH_TIMER_SLOT(47)
DH_TIMER_SLOT(48)
DH_TIMER_SLOT(49)
DH_TIMER_SLOT(50)
DH_TIMER_SLOT(51)
DH_TIMER_SLOT(52)
DH_TIMER_SLOT(53)
DH_TIMER_SLOT(54)
DH_TIMER_SLOT(55)
DH_TIMER_SLOT(56)
DH_TIMER_SLOT(57)
DH_TIMER_SLOT(58)
DH_TIMER_SLOT(59)
DH_TIMER_SLOT(60)
DH_TIMER_SLOT(61)
DH_TIMER_SLOT(62)
DH_TIMER_SLOT(63)
DH_TIMER_SLOT(64)
DH_TIMER_SLOT(65)
DH_TIMER_SLOT(66)
DH_TIMER_SLOT(67)
DH_TIMER_SLOT(68)
DH_TIMER_SLOT(69)
DH_TIMER_SLOT(70)
DH_TIMER_SLOT(71)
DH_TIMER_SLOT(72)
DH_TIMER_SLOT(73)
DH_TIMER_SLOT(74)
DH_TIMER_SLOT(75)
DH_TIMER_SLOT(76)
DH_TIMER_SLOT(77)
DH_TIMER_SLOT(78)
DH_TIMER_SLOT(79)
DH_TIMER_SLOT(80)
DH_TIMER_SLOT(81)
DH_TIMER_SLOT(82)
DH_TIMER_SLOT(83)
DH_TIMER_SLOT(84)
DH_TIMER_SLOT(85)
DH_TIMER_SLOT(86)
DH_TIMER_SLOT(87)
DH_TIMER_SLOT(88)
DH_TIMER_SLOT(89)
DH_TIMER_SLOT(90)
DH_TIMER_SLOT(91)
DH_TIMER_SLOT(92)
DH_TIMER_SLOT(93)
DH_TIMER_SLOT(94)
DH_TIMER_SLOT(95)
DH_TIMER_SLOT(96)
DH_TIMER_SLOT(97)
DH_TIMER_SLOT(98)
DH_TIMER_SLOT(99)
DH_TIMER_SLOT(100)
DH_TIMER_SLOT(101)
DH_TIMER_SLOT(102)
DH_TIMER_SLOT(103)
DH_TIMER_SLOT(104)
DH_TIMER_SLOT(105)
DH_TIMER_SLOT(106)
DH_TIMER_SLOT(107)
DH_TIMER_SLOT(108)
DH_TIMER_SLOT(109)
DH_TIMER_SLOT(110)
DH_TIMER_SLOT(111)
DH_TIMER_SLOT(112)
DH_TIMER_SLOT(113)
DH_TIMER_SLOT(114)
DH_TIMER_SLOT(115)
DH_TIMER_SLOT(116)
DH_TIMER_SLOT(117)
DH_TIMER_SLOT(118)
DH_TIMER_SLOT(119)
DH_TIMER_SLOT(120)
DH_TIMER_SLOT(121)
DH_TIMER_SLOT(122)
DH_TIMER_SLOT(123)
DH_TIMER_SLOT(124)
DH_TIMER_SLOT(125)
DH_TIMER_SLOT(126)
DH_TIMER_SLOT(127)
#undef DH_TIMER_SLOT
static CFRunLoopTimerCallBack functions[TIMER_SLOTS]={timer_f_0,timer_f_1,timer_f_2,timer_f_3,timer_f_4,timer_f_5,timer_f_6,timer_f_7,timer_f_8,timer_f_9,timer_f_10,timer_f_11,timer_f_12,timer_f_13,timer_f_14,timer_f_15,timer_f_16,timer_f_17,timer_f_18,timer_f_19,timer_f_20,timer_f_21,timer_f_22,timer_f_23,timer_f_24,timer_f_25,timer_f_26,timer_f_27,timer_f_28,timer_f_29,timer_f_30,timer_f_31,timer_f_32,timer_f_33,timer_f_34,timer_f_35,timer_f_36,timer_f_37,timer_f_38,timer_f_39,timer_f_40,timer_f_41,timer_f_42,timer_f_43,timer_f_44,timer_f_45,timer_f_46,timer_f_47,timer_f_48,timer_f_49,timer_f_50,timer_f_51,timer_f_52,timer_f_53,timer_f_54,timer_f_55,timer_f_56,timer_f_57,timer_f_58,timer_f_59,timer_f_60,timer_f_61,timer_f_62,timer_f_63,timer_f_64,timer_f_65,timer_f_66,timer_f_67,timer_f_68,timer_f_69,timer_f_70,timer_f_71,timer_f_72,timer_f_73,timer_f_74,timer_f_75,timer_f_76,timer_f_77,timer_f_78,timer_f_79,timer_f_80,timer_f_81,timer_f_82,timer_f_83,timer_f_84,timer_f_85,timer_f_86,timer_f_87,timer_f_88,timer_f_89,timer_f_90,timer_f_91,timer_f_92,timer_f_93,timer_f_94,timer_f_95,timer_f_96,timer_f_97,timer_f_98,timer_f_99,timer_f_100,timer_f_101,timer_f_102,timer_f_103,timer_f_104,timer_f_105,timer_f_106,timer_f_107,timer_f_108,timer_f_109,timer_f_110,timer_f_111,timer_f_112,timer_f_113,timer_f_114,timer_f_115,timer_f_116,timer_f_117,timer_f_118,timer_f_119,timer_f_120,timer_f_121,timer_f_122,timer_f_123,timer_f_124,timer_f_125,timer_f_126,timer_f_127};

static void native_fire(CFRunLoopTimerRef timer,void *info) {
    NativeFire original=(NativeFire)__atomic_load_n(&nativeOriginal,__ATOMIC_ACQUIRE);
    int saved=errno;
    if(atomic_load(&probeTimer)==(uintptr_t)timer) {
        if(atomic_load(&probeInfo)==(uintptr_t)info)atomic_fetch_add(&probeEntries,1);else atomic_fetch_add(&probeMismatches,1);
    }
    if(forwardingTimer==(uintptr_t)timer && forwardingFunction==nativeTarget){forwardingTimer=forwardingFunction=0;errno=saved;original(timer,info);return;}
    if(!atomic_load(&nativeReady) || !DHFlowCallbackCaptureActive()){errno=saved;original(timer,info);return;}
    DHFlowTimerBinding *entry=binding(timer);char mode[128];current_mode(mode);
    if(entry && DHFlowRegistrationState(entry->registration)==1){errno=saved;invoke_timer(entry->registration,timer,^{original(timer,info);});return;}
    if(entry && !DHFlowRegistrationState(entry->registration)){errno=saved;original(timer,info);return;}
    atomic_fetch_add(&unobservedTimers,1);errno=saved;
    DHFlowRunEntry("NSTimer.runloop-callback",mode,__builtin_return_address(0),(void *)nativeTarget,^{original(timer,info);});
}

@interface DHFlowTimerCalibration:NSObject
@property unsigned count;
@property(strong) id marker;
@end
@implementation DHFlowTimerCalibration
- (void)tick:(NSTimer *)timer {if(timer.userInfo==self.marker)self.count++;}
@end
static void prepare_native(void) {
    if(nativeAdapter>=0 || !dh_thunk_inline_available()) {
        if(nativeAdapter<0)strlcpy(nativeReason,"Inline backend is not linked; public CF adapters only",sizeof(nativeReason));return;
    }
    void *target=dlsym(RTLD_DEFAULT,"__NSFireTimer");
    if(!target){strlcpy(nativeReason,"Foundation __NSFireTimer symbol unavailable",sizeof(nativeReason));return;}
    nativeTarget=(uintptr_t)ptrauth_strip(target,ptrauth_key_function_pointer);
    nativeAdapter=dh_thunk_install_adapter(nativeTarget,(void *)native_fire,&nativeOriginal,"Foundation timer entry","void(CFRunLoopTimerRef, void*)",nativeReason,sizeof(nativeReason));
    if(nativeAdapter<0)return;
    DHFlowAdapterInternalBegin();
    @try {
        DHFlowTimerCalibration *receiver=[DHFlowTimerCalibration new];receiver.marker=[NSObject new];
        NSTimer *timer=[NSTimer timerWithTimeInterval:1000 target:receiver selector:@selector(tick:) userInfo:receiver.marker repeats:YES];
        nativeTimerClasses[0]=object_getClass(timer);
        CFRunLoopTimerContext context={0};CFRunLoopTimerGetContext((__bridge CFRunLoopTimerRef)timer,&context);
        atomic_store(&probeTimer,(uintptr_t)(__bridge void *)timer);atomic_store(&probeInfo,(uintptr_t)context.info);
        CFStringRef mode=CFSTR("IDHFlowTimerCalibrationMode");CFRunLoopRef loop=CFRunLoopGetCurrent();
        unsigned before=atomic_load(&probeEntries);
        CFRunLoopTimerSetNextFireDate((__bridge CFRunLoopTimerRef)timer,CFAbsoluteTimeGetCurrent()+0.001);
        CFRunLoopAddTimer(loop,(__bridge CFRunLoopTimerRef)timer,mode);CFRunLoopRunInMode(mode,0.02,false);[timer invalidate];
        BOOL targetGood=receiver.count==1 && atomic_load(&probeEntries)==before+1;
        __block unsigned blockCount=0;__block BOOL sameTimer=NO;
        NSTimer *block=[NSTimer timerWithTimeInterval:1000 repeats:YES block:^(NSTimer *actual){blockCount++;sameTimer=(uintptr_t)(__bridge void *)actual==atomic_load(&probeTimer);}];
        nativeTimerClasses[1]=object_getClass(block);
        context=(CFRunLoopTimerContext){0};CFRunLoopTimerGetContext((__bridge CFRunLoopTimerRef)block,&context);
        atomic_store(&probeTimer,(uintptr_t)(__bridge void *)block);atomic_store(&probeInfo,(uintptr_t)context.info);before=atomic_load(&probeEntries);
        CFRunLoopTimerSetNextFireDate((__bridge CFRunLoopTimerRef)block,CFAbsoluteTimeGetCurrent()+0.001);
        CFRunLoopAddTimer(loop,(__bridge CFRunLoopTimerRef)block,mode);CFRunLoopRunInMode(mode,0.02,false);[block invalidate];
        BOOL blockGood=blockCount==1 && sameTimer && atomic_load(&probeEntries)==before+1;
        atomic_store(&nativeReady,targetGood && blockGood && !atomic_load(&probeMismatches));
        strlcpy(nativeReason,atomic_load(&nativeReady)?"owned target/block timer arguments and original callbacks verified":"native timer ABI calibration inconclusive; forwarding retained, no timer entry association",sizeof(nativeReason));
    }@catch(NSException *exception) {strlcpy(nativeReason,"native timer fixture raised; forwarding retained",sizeof(nativeReason));}
    @finally {atomic_store(&probeTimer,0);atomic_store(&probeInfo,0);DHFlowAdapterInternalEnd();}
}

typedef id (*TargetFactory)(__unsafe_unretained id,SEL,NSTimeInterval,__unsafe_unretained id,SEL,__unsafe_unretained id,BOOL);
typedef id (*BlockFactory)(__unsafe_unretained id,SEL,NSTimeInterval,BOOL,void (^)(NSTimer *));
static void observe_factory(id timer,const char *api,void *caller,id target,SEL selector) {
    if(!timer || !atomic_load(&nativeReady))return;
    Class actual=object_getClass(timer);
    if(actual!=nativeTimerClasses[0] && actual!=nativeTimerClasses[1]){atomic_fetch_add(&rejectedBindings,1);return;}
    char label[192];
    if(target && selector)snprintf(label,sizeof(label),"[%s %s]",class_getName(object_getClass(target)),sel_getName(selector));
    else strlcpy(label,strstr(api,".block")?"NSTimer.block":"NSTimer.target-unobserved",sizeof(label));
    uint64_t registration=DHFlowRegisterNamedCallback(api,"runloop:<factory-created>",caller,(void *)nativeTarget,label);
    bind_timer((__bridge CFRunLoopTimerRef)timer,registration);
}
static id target_factory(unsigned index,__unsafe_unretained id cls,SEL command,NSTimeInterval interval,__unsafe_unretained id target,SEL selector,__unsafe_unretained id info,BOOL repeats,void *caller) {
    TargetFactory original=(TargetFactory)__atomic_load_n(&factoryOriginals[index],__ATOMIC_ACQUIRE);
    if(!DHFlowCallbackCaptureActive())return original(cls,command,interval,target,selector,info,repeats);
    int saved=errno;id timer=nil;DHFlowAdapterInternalBegin();
    @try {errno=saved;timer=original(cls,command,interval,target,selector,info,repeats);}
    @finally {saved=errno;DHFlowAdapterInternalEnd();errno=saved;}
    observe_factory(timer,index?"NSTimer.scheduledTimerWithTimeInterval.target":"NSTimer.timerWithTimeInterval.target",caller,target,selector);errno=saved;return timer;
}
static id block_factory(unsigned index,__unsafe_unretained id cls,SEL command,NSTimeInterval interval,BOOL repeats,void (^body)(NSTimer *),void *caller) {
    BlockFactory original=(BlockFactory)__atomic_load_n(&factoryOriginals[index],__ATOMIC_ACQUIRE);
    if(!DHFlowCallbackCaptureActive())return original(cls,command,interval,repeats,body);
    int saved=errno;id timer=nil;DHFlowAdapterInternalBegin();
    @try {errno=saved;timer=original(cls,command,interval,repeats,body);}
    @finally {saved=errno;DHFlowAdapterInternalEnd();errno=saved;}
    observe_factory(timer,index==3?"NSTimer.scheduledTimerWithTimeInterval.block":"NSTimer.timerWithTimeInterval.block",caller,nil,NULL);errno=saved;return timer;
}
static id wrap_target_factory(__unsafe_unretained id cls,SEL command,NSTimeInterval interval,__unsafe_unretained id target,SEL selector,__unsafe_unretained id info,BOOL repeats) {return target_factory(0,cls,command,interval,target,selector,info,repeats,__builtin_return_address(0));}
static id wrap_scheduled_target(__unsafe_unretained id cls,SEL command,NSTimeInterval interval,__unsafe_unretained id target,SEL selector,__unsafe_unretained id info,BOOL repeats) {return target_factory(1,cls,command,interval,target,selector,info,repeats,__builtin_return_address(0));}
static id wrap_block_factory(__unsafe_unretained id cls,SEL command,NSTimeInterval interval,BOOL repeats,void (^body)(NSTimer *)) {return block_factory(2,cls,command,interval,repeats,body,__builtin_return_address(0));}
static id wrap_scheduled_block(__unsafe_unretained id cls,SEL command,NSTimeInterval interval,BOOL repeats,void (^body)(NSTimer *)) {return block_factory(3,cls,command,interval,repeats,body,__builtin_return_address(0));}
static void prepare_factories(void) {
    if(atomic_load(&factoriesReady))return;
    if(!atomic_load(&nativeReady)){strlcpy(factoryReason,"native dispatch is unavailable; no synthetic factory delivery edges",sizeof(factoryReason));return;}
    const char *selectors[]={"timerWithTimeInterval:target:selector:userInfo:repeats:","scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:","timerWithTimeInterval:repeats:block:","scheduledTimerWithTimeInterval:repeats:block:"};
    void *replacements[]={(void *)wrap_target_factory,(void *)wrap_scheduled_target,(void *)wrap_block_factory,(void *)wrap_scheduled_block};
    dh_method_adapter_spec specs[4];for(unsigned i=0;i<4;i++){factoryMethods[i]=class_getClassMethod(NSTimer.class,sel_registerName(selectors[i]));specs[i]=(dh_method_adapter_spec){factoryMethods[i],replacements[i],&factoryOriginals[i],"NSTimer factories"};}
    int status=dh_thunk_install_method_adapters(specs,4,factoryReason,sizeof(factoryReason));atomic_store(&factoriesReady,status==0);
    if(!status)strlcpy(factoryReason,"original target/block factories observed; originals and arguments preserved",sizeof(factoryReason));
}

static CFRunLoopTimerRef wrap_create(CFAllocatorRef allocator,CFAbsoluteTime date,CFTimeInterval interval,CFOptionFlags flags,CFIndex order,CFRunLoopTimerCallBack callback,CFRunLoopTimerContext *context) {
    int saved=errno;uint64_t registration=callback?DHFlowRegisterCallback("CFRunLoopTimerCreate","runloop:<not-added>",__builtin_return_address(0),(void *)callback):0;
    CFRunLoopTimerCallBack replacement=callback;
    if(registration){unsigned index=(unsigned)registration-1;pthread_mutex_lock(&timerLock);timerSlots[index]=(TimerSlot){registration,callback};pthread_mutex_unlock(&timerLock);replacement=functions[index];}
    errno=saved;CFRunLoopTimerRef timer=original_create(allocator,date,interval,flags,order,replacement,context);int final=errno;
    bind_timer(timer,registration);errno=final;return timer;
}
static CFRunLoopTimerRef wrap_handler(CFAllocatorRef allocator,CFAbsoluteTime date,CFTimeInterval interval,CFOptionFlags flags,CFIndex order,void (^handler)(CFRunLoopTimerRef)) {
    int saved=errno;uintptr_t callback=DHFlowCallbackBlockAddress((dispatch_block_t)handler);
    uint64_t registration=callback?DHFlowRegisterCallback("CFRunLoopTimerCreateWithHandler","runloop:<not-added>",__builtin_return_address(0),(void *)callback):0;
    void (^replacement)(CFRunLoopTimerRef)=registration?^(CFRunLoopTimerRef timer){invoke_timer(registration,timer,^{handler(timer);});}:handler;
    errno=saved;CFRunLoopTimerRef timer=original_handler(allocator,date,interval,flags,order,replacement);int final=errno;
    bind_timer(timer,registration);errno=final;return timer;
}
static void wrap_invalidate(CFRunLoopTimerRef timer) {
    int saved=errno;DHFlowTimerBinding *entry=binding(timer);errno=saved;original_invalidate(timer);int final=errno;
    if(entry)DHFlowRetireCallback(entry->registration,"timer-invalidated");errno=final;
}
static void update_mode(CFRunLoopTimerRef timer,CFStringRef mode,BOOL added) {
    DHFlowTimerBinding *entry=binding(timer);if(!entry)return;char text[128];mode_label(mode,text);
    pthread_mutex_lock(&timerLock);if(added)entry->additions++;else entry->removals++;memcpy(entry->lastMode,text,128);pthread_mutex_unlock(&timerLock);
}
static void wrap_add(CFRunLoopRef loop,CFRunLoopTimerRef timer,CFStringRef mode) {int saved=errno;original_add(loop,timer,mode);int final=errno;update_mode(timer,mode,YES);errno=final;(void)saved;}
static void wrap_remove(CFRunLoopRef loop,CFRunLoopTimerRef timer,CFStringRef mode) {original_remove(loop,timer,mode);int final=errno;update_mode(timer,mode,NO);errno=final;}
static void wrap_perform(CFRunLoopRef loop,CFTypeRef mode,dispatch_block_t body) {
    int saved=errno;char text[128];mode_label(mode,text);dispatch_block_t wrapped=DHFlowWrapOneShot("CFRunLoopPerformBlock",text,__builtin_return_address(0),body);errno=saved;original_perform(loop,mode,wrapped);
}
static struct rebinding bindings[]={
 {"CFRunLoopTimerCreate",wrap_create,NULL},{"CFRunLoopTimerCreateWithHandler",wrap_handler,NULL},
 {"CFRunLoopTimerInvalidate",wrap_invalidate,NULL},{"CFRunLoopAddTimer",wrap_add,NULL},
 {"CFRunLoopRemoveTimer",wrap_remove,NULL},{"CFRunLoopPerformBlock",wrap_perform,NULL}
};
static void *symbol(const char *name) {void *p=dlsym(RTLD_DEFAULT,name);return p?ptrauth_sign_unauthenticated(ptrauth_strip(p,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0):NULL;}
const struct rebinding *DHFlowTimerBindings(size_t *count) {
    original_create=symbol("CFRunLoopTimerCreate");original_handler=symbol("CFRunLoopTimerCreateWithHandler");original_invalidate=symbol("CFRunLoopTimerInvalidate");
    original_add=symbol("CFRunLoopAddTimer");original_remove=symbol("CFRunLoopRemoveTimer");original_perform=symbol("CFRunLoopPerformBlock");
    BOOL ready=original_create && original_handler && original_invalidate && original_add && original_remove && original_perform;
    *count=ready?sizeof(bindings)/sizeof(*bindings):0;return ready?bindings:NULL;
}
void DHFlowTimerPrepare(void) {prepare_native();prepare_factories();}
int DHFlowTimerOwnsImport(const char *name) {if(!name)return 0;for(unsigned i=0;i<sizeof(bindings)/sizeof(*bindings);i++)if(!strcmp(name,bindings[i].name))return 1;return 0;}
NSDictionary *DHFlowTimerState(void) {
    pthread_mutex_lock(&timerLock);unsigned count=bindingCount;pthread_mutex_unlock(&timerLock);
    return @{@"bindingsCreated":@(count),@"maxBindings":@(TIMER_BINDINGS),@"rejectedBindings":@(atomic_load(&rejectedBindings)),@"unregisteredTimerEntries":@(atomic_load(&unobservedTimers)),
        @"nativeEntryReady":@(atomic_load(&nativeReady)),@"nativeEntryReason":@(nativeReason),@"nativeAdapterId":@(nativeAdapter),@"nativeCalibrationEntries":@(atomic_load(&probeEntries)),@"nativeCalibrationMismatches":@(atomic_load(&probeMismatches)),@"factoriesReady":@(atomic_load(&factoriesReady)),@"factoryReason":@(factoryReason)};
}
NSDictionary *DHFlowTimerRecords(void) {
    NSMutableArray *copy=[NSMutableArray array],*rows=[NSMutableArray array];pthread_mutex_lock(&timerLock);
    for(unsigned i=0;i<bindingCount;i++){DHFlowTimerBinding *entry=observed[i];if(entry)[copy addObject:entry];}pthread_mutex_unlock(&timerLock);
    for(DHFlowTimerBinding *entry in copy) {
        NSTimer *timer=entry->timer;if(!timer)continue;
        pthread_mutex_lock(&timerLock);unsigned added=entry->additions,removed=entry->removals;NSString *mode=@(entry->lastMode);pthread_mutex_unlock(&timerLock);
        [rows addObject:@{@"registrationToken":@(entry->registration),@"timer":[NSString stringWithFormat:@"0x%llx",(uint64_t)(__bridge void *)timer],@"valid":@(timer.valid),@"additions":@(added),@"removals":@(removed),@"lastObservedMode":mode}];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"state":DHFlowTimerState(),@"liveBindings":rows,@"nativeAdapter":dh_thunk_adapter_metadata(nativeAdapter)?:@{}};
}
