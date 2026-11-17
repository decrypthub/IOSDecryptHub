#import "dh_flow_sources.h"
#import "dh_flow.h"
#include "dh_health.h"
#include <objc/runtime.h>
#include <pthread.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <ptrauth.h>
#include <errno.h>
#include <string.h>

enum { SOURCE_OBJECTS=64,SOURCE_SLOTS=128 };
static pthread_mutex_t sourceLock=PTHREAD_MUTEX_INITIALIZER;
static unsigned sourceObjects;
static _Atomic uint64_t unknownSources,unwrappedHandlers;
static const char sourceBindingKey;
typedef void (*SourceBlockSetter)(dispatch_source_t,dispatch_block_t);
typedef void (*SourceFunctionSetter)(dispatch_source_t,dispatch_function_t);
static __typeof__(&dispatch_source_create) original_create;
static __typeof__(&dispatch_source_cancel) original_cancel;
static __typeof__(&dispatch_set_target_queue) original_target;
static SourceBlockSetter original_block[3];
static SourceFunctionSetter original_function[3];
static const char *blockAPIs[]={"dispatch_source_set_event_handler","dispatch_source_set_cancel_handler","dispatch_source_set_registration_handler"};
static const char *functionAPIs[]={"dispatch_source_set_event_handler_f","dispatch_source_set_cancel_handler_f","dispatch_source_set_registration_handler_f"};

@interface DHFlowSourceBinding:NSObject {
@public char queue[128];uint64_t registrations[3];BOOL cancelRequested;
}
@end
@implementation DHFlowSourceBinding
- (void)dealloc {for(unsigned i=0;i<3;i++)DHFlowRetireCallback(registrations[i],"source-object-released");}
@end

@interface DHFlowSourceHandlerLifetime:NSObject
@property uint64_t registration;
@end
@implementation DHFlowSourceHandlerLifetime
- (void)dealloc {DHFlowRetireCallback(_registration,"source-handler-released");}
@end

typedef struct {uint64_t registration;dispatch_function_t function;} SourceFunctionSlot;
static SourceFunctionSlot functionSlots[SOURCE_SLOTS];
static void source_f_invoke(unsigned index,void *context) {
    pthread_mutex_lock(&sourceLock);SourceFunctionSlot slot=functionSlots[index];pthread_mutex_unlock(&sourceLock);
    DHFlowRunCallback(slot.registration,^{slot.function(context);});
}
#define DH_SOURCE_SLOT(N) static void source_f_##N(void *context) {source_f_invoke(N,context);}
DH_SOURCE_SLOT(0)
DH_SOURCE_SLOT(1)
DH_SOURCE_SLOT(2)
DH_SOURCE_SLOT(3)
DH_SOURCE_SLOT(4)
DH_SOURCE_SLOT(5)
DH_SOURCE_SLOT(6)
DH_SOURCE_SLOT(7)
DH_SOURCE_SLOT(8)
DH_SOURCE_SLOT(9)
DH_SOURCE_SLOT(10)
DH_SOURCE_SLOT(11)
DH_SOURCE_SLOT(12)
DH_SOURCE_SLOT(13)
DH_SOURCE_SLOT(14)
DH_SOURCE_SLOT(15)
DH_SOURCE_SLOT(16)
DH_SOURCE_SLOT(17)
DH_SOURCE_SLOT(18)
DH_SOURCE_SLOT(19)
DH_SOURCE_SLOT(20)
DH_SOURCE_SLOT(21)
DH_SOURCE_SLOT(22)
DH_SOURCE_SLOT(23)
DH_SOURCE_SLOT(24)
DH_SOURCE_SLOT(25)
DH_SOURCE_SLOT(26)
DH_SOURCE_SLOT(27)
DH_SOURCE_SLOT(28)
DH_SOURCE_SLOT(29)
DH_SOURCE_SLOT(30)
DH_SOURCE_SLOT(31)
DH_SOURCE_SLOT(32)
DH_SOURCE_SLOT(33)
DH_SOURCE_SLOT(34)
DH_SOURCE_SLOT(35)
DH_SOURCE_SLOT(36)
DH_SOURCE_SLOT(37)
DH_SOURCE_SLOT(38)
DH_SOURCE_SLOT(39)
DH_SOURCE_SLOT(40)
DH_SOURCE_SLOT(41)
DH_SOURCE_SLOT(42)
DH_SOURCE_SLOT(43)
DH_SOURCE_SLOT(44)
DH_SOURCE_SLOT(45)
DH_SOURCE_SLOT(46)
DH_SOURCE_SLOT(47)
DH_SOURCE_SLOT(48)
DH_SOURCE_SLOT(49)
DH_SOURCE_SLOT(50)
DH_SOURCE_SLOT(51)
DH_SOURCE_SLOT(52)
DH_SOURCE_SLOT(53)
DH_SOURCE_SLOT(54)
DH_SOURCE_SLOT(55)
DH_SOURCE_SLOT(56)
DH_SOURCE_SLOT(57)
DH_SOURCE_SLOT(58)
DH_SOURCE_SLOT(59)
DH_SOURCE_SLOT(60)
DH_SOURCE_SLOT(61)
DH_SOURCE_SLOT(62)
DH_SOURCE_SLOT(63)
DH_SOURCE_SLOT(64)
DH_SOURCE_SLOT(65)
DH_SOURCE_SLOT(66)
DH_SOURCE_SLOT(67)
DH_SOURCE_SLOT(68)
DH_SOURCE_SLOT(69)
DH_SOURCE_SLOT(70)
DH_SOURCE_SLOT(71)
DH_SOURCE_SLOT(72)
DH_SOURCE_SLOT(73)
DH_SOURCE_SLOT(74)
DH_SOURCE_SLOT(75)
DH_SOURCE_SLOT(76)
DH_SOURCE_SLOT(77)
DH_SOURCE_SLOT(78)
DH_SOURCE_SLOT(79)
DH_SOURCE_SLOT(80)
DH_SOURCE_SLOT(81)
DH_SOURCE_SLOT(82)
DH_SOURCE_SLOT(83)
DH_SOURCE_SLOT(84)
DH_SOURCE_SLOT(85)
DH_SOURCE_SLOT(86)
DH_SOURCE_SLOT(87)
DH_SOURCE_SLOT(88)
DH_SOURCE_SLOT(89)
DH_SOURCE_SLOT(90)
DH_SOURCE_SLOT(91)
DH_SOURCE_SLOT(92)
DH_SOURCE_SLOT(93)
DH_SOURCE_SLOT(94)
DH_SOURCE_SLOT(95)
DH_SOURCE_SLOT(96)
DH_SOURCE_SLOT(97)
DH_SOURCE_SLOT(98)
DH_SOURCE_SLOT(99)
DH_SOURCE_SLOT(100)
DH_SOURCE_SLOT(101)
DH_SOURCE_SLOT(102)
DH_SOURCE_SLOT(103)
DH_SOURCE_SLOT(104)
DH_SOURCE_SLOT(105)
DH_SOURCE_SLOT(106)
DH_SOURCE_SLOT(107)
DH_SOURCE_SLOT(108)
DH_SOURCE_SLOT(109)
DH_SOURCE_SLOT(110)
DH_SOURCE_SLOT(111)
DH_SOURCE_SLOT(112)
DH_SOURCE_SLOT(113)
DH_SOURCE_SLOT(114)
DH_SOURCE_SLOT(115)
DH_SOURCE_SLOT(116)
DH_SOURCE_SLOT(117)
DH_SOURCE_SLOT(118)
DH_SOURCE_SLOT(119)
DH_SOURCE_SLOT(120)
DH_SOURCE_SLOT(121)
DH_SOURCE_SLOT(122)
DH_SOURCE_SLOT(123)
DH_SOURCE_SLOT(124)
DH_SOURCE_SLOT(125)
DH_SOURCE_SLOT(126)
DH_SOURCE_SLOT(127)
#undef DH_SOURCE_SLOT
static dispatch_function_t functions[SOURCE_SLOTS]={source_f_0,source_f_1,source_f_2,source_f_3,source_f_4,source_f_5,source_f_6,source_f_7,source_f_8,source_f_9,source_f_10,source_f_11,source_f_12,source_f_13,source_f_14,source_f_15,source_f_16,source_f_17,source_f_18,source_f_19,source_f_20,source_f_21,source_f_22,source_f_23,source_f_24,source_f_25,source_f_26,source_f_27,source_f_28,source_f_29,source_f_30,source_f_31,source_f_32,source_f_33,source_f_34,source_f_35,source_f_36,source_f_37,source_f_38,source_f_39,source_f_40,source_f_41,source_f_42,source_f_43,source_f_44,source_f_45,source_f_46,source_f_47,source_f_48,source_f_49,source_f_50,source_f_51,source_f_52,source_f_53,source_f_54,source_f_55,source_f_56,source_f_57,source_f_58,source_f_59,source_f_60,source_f_61,source_f_62,source_f_63,source_f_64,source_f_65,source_f_66,source_f_67,source_f_68,source_f_69,source_f_70,source_f_71,source_f_72,source_f_73,source_f_74,source_f_75,source_f_76,source_f_77,source_f_78,source_f_79,source_f_80,source_f_81,source_f_82,source_f_83,source_f_84,source_f_85,source_f_86,source_f_87,source_f_88,source_f_89,source_f_90,source_f_91,source_f_92,source_f_93,source_f_94,source_f_95,source_f_96,source_f_97,source_f_98,source_f_99,source_f_100,source_f_101,source_f_102,source_f_103,source_f_104,source_f_105,source_f_106,source_f_107,source_f_108,source_f_109,source_f_110,source_f_111,source_f_112,source_f_113,source_f_114,source_f_115,source_f_116,source_f_117,source_f_118,source_f_119,source_f_120,source_f_121,source_f_122,source_f_123,source_f_124,source_f_125,source_f_126,source_f_127};

static DHFlowSourceBinding *binding(dispatch_source_t source) {return objc_getAssociatedObject((id)source,&sourceBindingKey);}
static void replace_registration(DHFlowSourceBinding *owner,unsigned kind,uint64_t registration) {
    if(!owner)return;
    pthread_mutex_lock(&sourceLock);uint64_t previous=owner->registrations[kind];owner->registrations[kind]=registration;pthread_mutex_unlock(&sourceLock);
    DHFlowRetireCallback(previous,registration?"source-handler-replaced":"source-handler-removed-or-unobserved");
}
static __attribute__((ns_returns_retained)) dispatch_source_t wrap_source_create(dispatch_source_type_t type,uintptr_t handle,uintptr_t mask,dispatch_queue_t queue) {
    int saved=errno;BOOL observe=DHFlowCallbackCaptureActive();
    if(observe && !dh_call_parent() && !dh_call_async()) {
        Dl_info origin={0};int internal=dh_in_hook;dh_in_hook=1;
        BOOL app=dladdr(ptrauth_strip(__builtin_return_address(0),ptrauth_key_function_pointer),&origin) && origin.dli_fname && strstr(origin.dli_fname,".app/");
        dh_in_hook=internal;observe=app || (queue && !strcmp(dispatch_queue_get_label(queue),"com.iosdecrypthub.flow.fixture"));
    }
    errno=saved;
    dispatch_source_t source=original_create(type,handle,mask,queue);int final=errno;
    if(source && observe) {
        pthread_mutex_lock(&sourceLock);BOOL bounded=sourceObjects<SOURCE_OBJECTS;if(bounded)sourceObjects++;pthread_mutex_unlock(&sourceLock);
        if(bounded) {
            DHFlowSourceBinding *owner=[DHFlowSourceBinding new];
            strlcpy(owner->queue,queue?(dispatch_queue_get_label(queue)?:""):"<default-source-target>",sizeof(owner->queue));
            objc_setAssociatedObject((id)source,&sourceBindingKey,owner,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } else atomic_fetch_add(&unknownSources,1);
    }
    errno=final;return source;
}
static void set_block(dispatch_source_t source,dispatch_block_t body,unsigned kind,void *caller) {
    int saved=errno;DHFlowSourceBinding *owner=binding(source);char queue[128]={0};
    if(owner){pthread_mutex_lock(&sourceLock);memcpy(queue,owner->queue,sizeof(queue));pthread_mutex_unlock(&sourceLock);}
    uintptr_t callback=DHFlowCallbackBlockAddress(body);uint64_t registration=0;
    if(callback && owner)registration=DHFlowRegisterCallback(blockAPIs[kind],queue,caller,(void *)callback);
    else if(callback)atomic_fetch_add(&unknownSources,1);
    replace_registration(owner,kind,registration);
    if(!registration){if(body && DHFlowCallbackCaptureActive())atomic_fetch_add(&unwrappedHandlers,1);errno=saved;original_block[kind](source,body);return;}
    DHFlowSourceHandlerLifetime *lifetime=[DHFlowSourceHandlerLifetime new];lifetime.registration=registration;
    dispatch_block_t wrapped=^{DHFlowRunCallback(lifetime.registration,body);};
    errno=saved;original_block[kind](source,wrapped);
}
static void set_function(dispatch_source_t source,dispatch_function_t body,unsigned kind,void *caller) {
    int saved=errno;DHFlowSourceBinding *owner=binding(source);char queue[128]={0};uint64_t registration=0;
    if(owner){pthread_mutex_lock(&sourceLock);memcpy(queue,owner->queue,sizeof(queue));pthread_mutex_unlock(&sourceLock);}
    if(body && owner)registration=DHFlowRegisterCallback(functionAPIs[kind],queue,caller,(void *)body);
    else if(body && DHFlowCallbackCaptureActive())atomic_fetch_add(&unknownSources,1);
    replace_registration(owner,kind,registration);
    if(!registration){if(body && DHFlowCallbackCaptureActive())atomic_fetch_add(&unwrappedHandlers,1);errno=saved;original_function[kind](source,body);return;}
    // Each immutable slot is tied to one non-reused registration. libdispatch
    // still supplies its original context; do not replace do_ctxt.
    unsigned index=(unsigned)registration-1;
    pthread_mutex_lock(&sourceLock);functionSlots[index]=(SourceFunctionSlot){registration,body};pthread_mutex_unlock(&sourceLock);
    errno=saved;original_function[kind](source,functions[index]);
}
static void wrap_event(dispatch_source_t source,dispatch_block_t body) {set_block(source,body,0,__builtin_return_address(0));}
static void wrap_cancel(dispatch_source_t source,dispatch_block_t body) {set_block(source,body,1,__builtin_return_address(0));}
static void wrap_registration(dispatch_source_t source,dispatch_block_t body) {set_block(source,body,2,__builtin_return_address(0));}
static void wrap_event_f(dispatch_source_t source,dispatch_function_t body) {set_function(source,body,0,__builtin_return_address(0));}
static void wrap_cancel_f(dispatch_source_t source,dispatch_function_t body) {set_function(source,body,1,__builtin_return_address(0));}
static void wrap_registration_f(dispatch_source_t source,dispatch_function_t body) {set_function(source,body,2,__builtin_return_address(0));}
static void wrap_source_cancel(dispatch_source_t source) {
    int saved=errno;DHFlowSourceBinding *owner=binding(source);
    if(owner){pthread_mutex_lock(&sourceLock);owner->cancelRequested=YES;pthread_mutex_unlock(&sourceLock);}
    // A request is not cancellation completion. Original in-flight deliveries
    // finish normally; actual handler disposal retires registrations separately.
    errno=saved;original_cancel(source);
}
static void wrap_target(dispatch_object_t object,dispatch_queue_t queue) {
    int saved=errno;DHFlowSourceBinding *owner=objc_getAssociatedObject((id)object,&sourceBindingKey);
    errno=saved;original_target(object,queue);int final=errno;
    if(owner) {
        char label[128];uint64_t registrations[3];strlcpy(label,queue?(dispatch_queue_get_label(queue)?:""):"<default-source-target>",sizeof(label));
        pthread_mutex_lock(&sourceLock);memcpy(owner->queue,label,sizeof(label));memcpy(registrations,owner->registrations,sizeof(registrations));pthread_mutex_unlock(&sourceLock);
        for(unsigned i=0;i<3;i++)DHFlowUpdateCallbackQueue(registrations[i],label);
    }
    errno=final;
}
static struct rebinding bindings[]={
 {"dispatch_source_create",wrap_source_create,NULL},
 {"dispatch_source_set_event_handler",wrap_event,NULL},{"dispatch_source_set_event_handler_f",wrap_event_f,NULL},
 {"dispatch_source_set_cancel_handler",wrap_cancel,NULL},{"dispatch_source_set_cancel_handler_f",wrap_cancel_f,NULL},
 {"dispatch_source_set_registration_handler",wrap_registration,NULL},{"dispatch_source_set_registration_handler_f",wrap_registration_f,NULL},
 {"dispatch_source_cancel",wrap_source_cancel,NULL},{"dispatch_set_target_queue",wrap_target,NULL}
};
static void *symbol(const char *name) {
    void *address=dlsym(RTLD_DEFAULT,name);
    return address?ptrauth_sign_unauthenticated(ptrauth_strip(address,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0):NULL;
}
const struct rebinding *DHFlowSourceBindings(size_t *count) {
    original_create=symbol("dispatch_source_create");original_cancel=symbol("dispatch_source_cancel");original_target=symbol("dispatch_set_target_queue");
    BOOL ready=original_create && original_cancel && original_target;
    for(unsigned i=0;i<3;i++){original_block[i]=symbol(blockAPIs[i]);original_function[i]=symbol(functionAPIs[i]);ready=ready && original_block[i] && original_function[i];}
    *count=ready?sizeof(bindings)/sizeof(*bindings):0;return ready?bindings:NULL;
}
int DHFlowSourceOwnsImport(const char *name) {
    if(!name)return 0;
    for(unsigned i=0;i<sizeof(bindings)/sizeof(*bindings);i++)if(!strcmp(name,bindings[i].name))return 1;return 0;
}
NSDictionary *DHFlowSourceState(void) {
    pthread_mutex_lock(&sourceLock);unsigned count=sourceObjects;pthread_mutex_unlock(&sourceLock);
    return @{@"sourceBindingsCreated":@(count),@"sourceBindingCapacity":@(SOURCE_OBJECTS),@"unobservedSourceTargets":@(atomic_load(&unknownSources)),@"unwrappedSourceHandlers":@(atomic_load(&unwrappedHandlers))};
}

