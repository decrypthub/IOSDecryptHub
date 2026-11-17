#import "dh_control_breakpoint.h"
#include "qbdi_control.h"
#include "dh_health.h"
#include "dh_vm_map.h"
#include <mach/mach.h>
#include "../../build/control-mig/dh_control_mach_client.h"
#include "../../build/control-mig/dh_control_exc_client.h"
#include <pthread.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#if defined(__arm64__) || defined(__aarch64__)
#include <mach/arm/thread_status.h>
#include <mach/arm/exception.h>
extern boolean_t dh_control_mach_server(mach_msg_header_t *,mach_msg_header_t *);
extern kern_return_t mach_vm_write(vm_map_t,mach_vm_address_t,vm_offset_t,mach_msg_type_number_t);
extern uint64_t dh_control_breakpoint_entry(uint64_t);
static mach_port_t receivePort,previousPort;
static exception_behavior_t previousBehavior;
static thread_state_flavor_t previousFlavor;
static pthread_mutex_t prepareLock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic int ready,attempted,forceBreakpoint;
static _Atomic uint64_t handled,forwarded,rejected;
static char reason[256]="not prepared";

// Only the task's BREAKPOINT mask is changed. A task handler that was already
// present retains its original behavior/flavor and is called for every trap
// which is not the exact instruction and slot owned by this backend.
static kern_return_t forward_exception(mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,mach_msg_type_number_t count) {
    if(!MACH_PORT_VALID(previousPort) || count>2)return KERN_FAILURE;
    atomic_fetch_add_explicit(&forwarded,1,memory_order_relaxed);
    exception_behavior_t behavior=previousBehavior & ~MACH_EXCEPTION_CODES;
    exception_data_type_t narrow[2]={0};for(unsigned i=0;i<count;i++)narrow[i]=(exception_data_type_t)codes[i];
    int wide=(previousBehavior&MACH_EXCEPTION_CODES)!=0;
    if(behavior==EXCEPTION_DEFAULT)return wide?dh_control_mach_exception_raise(previousPort,thread,task,exception,codes,count):dh_control_exception_raise(previousPort,thread,task,exception,narrow,count);
    thread_state_data_t original={0},next={0};mach_msg_type_number_t originalCount=THREAD_STATE_MAX,nextCount=THREAD_STATE_MAX;int flavor=previousFlavor;
    kern_return_t result=thread_get_state(thread,flavor,original,&originalCount);if(result!=KERN_SUCCESS)return result;
    if(behavior==EXCEPTION_STATE)
        result=wide?dh_control_mach_exception_raise_state(previousPort,exception,codes,count,&flavor,original,originalCount,next,&nextCount):dh_control_exception_raise_state(previousPort,exception,narrow,count,&flavor,original,originalCount,next,&nextCount);
    else if(behavior==EXCEPTION_STATE_IDENTITY)
        result=wide?dh_control_mach_exception_raise_state_identity(previousPort,thread,task,exception,codes,count,&flavor,original,originalCount,next,&nextCount):dh_control_exception_raise_state_identity(previousPort,thread,task,exception,narrow,count,&flavor,original,originalCount,next,&nextCount);
    else return KERN_FAILURE;
    if(result!=KERN_SUCCESS || nextCount>THREAD_STATE_MAX)return result==KERN_SUCCESS?KERN_INVALID_ARGUMENT:result;
    return thread_set_state(thread,flavor,next,nextCount);
}
static kern_return_t resume_owned(mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,mach_msg_type_number_t count) {
    if(exception!=EXC_BREAKPOINT || count<2 || codes[0]!=EXC_ARM_BREAKPOINT)return KERN_FAILURE;
    int pid=0;if(pid_for_task(task,&pid)!=KERN_SUCCESS || pid!=getpid())return KERN_FAILURE;
    arm_thread_state64_t state={0};mach_msg_type_number_t stateCount=ARM_THREAD_STATE64_COUNT;
    if(thread_get_state(thread,ARM_THREAD_STATE64,(thread_state_t)&state,&stateCount)!=KERN_SUCCESS || stateCount!=ARM_THREAD_STATE64_COUNT)return KERN_FAILURE;
    uint64_t pc=arm_thread_state64_get_pc(state),sp=arm_thread_state64_get_sp(state),entry=dh_control_breakpoint_entry(pc);
    if(!entry)return KERN_FAILURE;
    uint32_t instruction=0;vm_size_t copied=0;
    if(vm_read_overwrite(mach_task_self(),pc,4,(vm_address_t)&instruction,&copied)!=KERN_SUCCESS || copied!=4 || instruction!=(0xd4200000u|(0x4944u<<5)))return KERN_FAILURE;
    // The context thunk normally receives the near island's two-register
    // spill. Make exactly that spill on the stopped thread's actual stack;
    // all remaining GPR/SIMD/flags and native TLS stay on the original thread.
    DHVMMapping mapping=dh_vm_mapping(sp>=16?sp-16:0);
    if((sp&15) || sp<0x10000 || !mapping.found)return KERN_FAILURE;
    DHVMRegion *region=&mapping.steps[mapping.count-1];
    if(!(region->protection&VM_PROT_WRITE) || sp-16<region->start || sp-region->start>region->length)return KERN_FAILURE;
    uint64_t spill[2]={state.__x[16],state.__x[17]};
    kern_return_t result=mach_vm_write(mach_task_self(),sp-16,(vm_offset_t)spill,sizeof(spill));if(result!=KERN_SUCCESS)return result;
    void (*destination)(void)=ptrauth_sign_unauthenticated((void *)entry,ptrauth_key_function_pointer,0);
    arm_thread_state64_set_pc_fptr(state,destination);arm_thread_state64_set_sp(state,sp-16);
    result=thread_set_state(thread,ARM_THREAD_STATE64,(thread_state_t)&state,ARM_THREAD_STATE64_COUNT);
    if(result==KERN_SUCCESS)atomic_fetch_add_explicit(&handled,1,memory_order_relaxed);return result;
}
kern_return_t dh_control_catch_mach_exception_raise(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,mach_msg_type_number_t count) {
    kern_return_t result=KERN_FAILURE;
    if(port==receivePort) {
        result=resume_owned(thread,task,exception,codes,count);
        if(result!=KERN_SUCCESS){atomic_fetch_add_explicit(&rejected,1,memory_order_relaxed);result=forward_exception(thread,task,exception,codes,count);}
    }
    // MIG transferred these identity send rights to this receiver.
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return result;
}
kern_return_t dh_control_catch_mach_exception_raise_state(mach_port_t port,exception_type_t exception,mach_exception_data_t codes,mach_msg_type_number_t count,int *flavor,thread_state_t old,mach_msg_type_number_t oldCount,thread_state_t next,mach_msg_type_number_t *nextCount) {
    (void)port;(void)exception;(void)codes;(void)count;(void)flavor;(void)old;(void)oldCount;(void)next;(void)nextCount;return KERN_FAILURE;
}
kern_return_t dh_control_catch_mach_exception_raise_state_identity(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,mach_msg_type_number_t count,int *flavor,thread_state_t old,mach_msg_type_number_t oldCount,thread_state_t next,mach_msg_type_number_t *nextCount) {
    (void)port;(void)exception;(void)codes;(void)count;(void)flavor;(void)old;(void)oldCount;(void)next;(void)nextCount;
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return KERN_FAILURE;
}
static void *serve(void *unused) {
    (void)unused;dh_in_hook=1;pthread_setname_np("IDH native checkpoints");
    sigset_t signals;sigfillset(&signals);pthread_sigmask(SIG_BLOCK,&signals,NULL);
    kern_return_t stopped;do {stopped=mach_msg_server(dh_control_mach_server,8192,receivePort,0);}while(stopped==MACH_RCV_INTERRUPTED);
    if(atomic_load(&ready))atomic_store(&ready,0);(void)stopped;return NULL;
}
static int no_thread_handlers(void) {
    thread_act_array_t threads=NULL;mach_msg_type_number_t total=0;
    if(task_threads(mach_task_self(),&threads,&total)!=KERN_SUCCESS)return 0;
    int valid=total<=1024;
    for(unsigned i=0;i<total;i++) {
        if(valid) {
            exception_mask_t masks[EXC_TYPES_COUNT];mach_port_t ports[EXC_TYPES_COUNT];exception_behavior_t behaviors[EXC_TYPES_COUNT];thread_state_flavor_t flavors[EXC_TYPES_COUNT];mach_msg_type_number_t count=EXC_TYPES_COUNT;
            if(thread_get_exception_ports(threads[i],EXC_MASK_BREAKPOINT,masks,&count,ports,behaviors,flavors)!=KERN_SUCCESS)valid=0;
            else for(unsigned j=0;j<count;j++)if(MACH_PORT_VALID(ports[j])){valid=0;mach_port_deallocate(mach_task_self(),ports[j]);}
        }
        mach_port_deallocate(mach_task_self(),threads[i]);
    }
    vm_deallocate(mach_task_self(),(vm_address_t)threads,total*sizeof(thread_t));return valid;
}
int dh_control_breakpoint_prepare(char *error,size_t size) {
    pthread_mutex_lock(&prepareLock);int ownsSend=0;if(atomic_load(&attempted))goto finished;atomic_store(&attempted,1);
    if(!no_thread_handlers()){strlcpy(reason,"Mach checkpoints require no existing thread-level breakpoint handler (or more than 1024 threads)",sizeof(reason));goto finished;}
    exception_mask_t masks[EXC_TYPES_COUNT];mach_port_t ports[EXC_TYPES_COUNT];exception_behavior_t behaviors[EXC_TYPES_COUNT];thread_state_flavor_t flavors[EXC_TYPES_COUNT];mach_msg_type_number_t count=EXC_TYPES_COUNT;
    kern_return_t result=task_get_exception_ports(mach_task_self(),EXC_MASK_BREAKPOINT,masks,&count,ports,behaviors,flavors);
    if(result!=KERN_SUCCESS){snprintf(reason,sizeof(reason),"task breakpoint port query failed (Mach %d)",result);goto finished;}
    int valid=1;for(unsigned i=0;i<count;i++)if(MACH_PORT_VALID(ports[i])) {
        exception_behavior_t behavior=behaviors[i]&~MACH_EXCEPTION_CODES;
        if(previousPort || (behavior!=EXCEPTION_DEFAULT && behavior!=EXCEPTION_STATE && behavior!=EXCEPTION_STATE_IDENTITY)){valid=0;mach_port_deallocate(mach_task_self(),ports[i]);}
        else {previousPort=ports[i];previousBehavior=behaviors[i];previousFlavor=flavors[i];}
    }
    if(!valid){strlcpy(reason,"existing task breakpoint handler behavior cannot be forwarded",sizeof(reason));goto failed;}
    if((result=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&receivePort))!=KERN_SUCCESS)goto mach_failed;
    if((result=mach_port_insert_right(mach_task_self(),receivePort,receivePort,MACH_MSG_TYPE_MAKE_SEND))!=KERN_SUCCESS)goto mach_failed;
    ownsSend=1;
    pthread_t worker;if(pthread_create(&worker,NULL,serve,NULL)){strlcpy(reason,"native checkpoint server thread creation failed",sizeof(reason));goto failed;}pthread_detach(worker);
    // previousPort/behavior/flavor are immutable and fully initialized before
    // the task can send the first exception to the already-created receiver.
    if((result=task_set_exception_ports(mach_task_self(),EXC_MASK_BREAKPOINT,receivePort,EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64))!=KERN_SUCCESS)goto mach_failed;
    strlcpy(reason,"owned Mach checkpoints ready; non-owned exceptions retain the previous task handler",sizeof(reason));atomic_store_explicit(&ready,1,memory_order_release);goto finished;
mach_failed:snprintf(reason,sizeof(reason),"native checkpoint port preparation failed (Mach %d)",result);
failed:
    if(MACH_PORT_VALID(receivePort)){mach_port_mod_refs(mach_task_self(),receivePort,MACH_PORT_RIGHT_RECEIVE,-1);if(ownsSend)mach_port_deallocate(mach_task_self(),receivePort);receivePort=MACH_PORT_NULL;}
    if(MACH_PORT_VALID(previousPort)){mach_port_deallocate(mach_task_self(),previousPort);previousPort=MACH_PORT_NULL;}
finished:
    if(!atomic_load(&ready) && error && size)strlcpy(error,reason,size);int ok=atomic_load_explicit(&ready,memory_order_acquire);pthread_mutex_unlock(&prepareLock);return ok;
}
int dh_control_breakpoint_force_for_selftest(int enabled){atomic_store(&forceBreakpoint,enabled!=0);return 1;}
int dh_control_breakpoint_forced(void){return atomic_load(&forceBreakpoint);}
NSDictionary *DHControlBreakpointState(void) {
    pthread_mutex_lock(&prepareLock);int ownsTask=0;unsigned active=atomic_load(&ready);
    if(active){exception_mask_t masks[EXC_TYPES_COUNT];mach_port_t ports[EXC_TYPES_COUNT];exception_behavior_t behaviors[EXC_TYPES_COUNT];thread_state_flavor_t flavors[EXC_TYPES_COUNT];mach_msg_type_number_t count=EXC_TYPES_COUNT;
        if(task_get_exception_ports(mach_task_self(),EXC_MASK_BREAKPOINT,masks,&count,ports,behaviors,flavors)==KERN_SUCCESS)
            for(unsigned i=0;i<count;i++)if(MACH_PORT_VALID(ports[i])){ownsTask|=ports[i]==receivePort && behaviors[i]==(EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES);mach_port_deallocate(mach_task_self(),ports[i]);}}
    NSDictionary *state=@{@"ready":@(active!=0),@"ownsTaskBreakpointPort":@(ownsTask!=0),@"attempted":@(atomic_load(&attempted)!=0),@"forcedForOwnedSelftest":@(atomic_load(&forceBreakpoint)!=0),@"reason":@(reason),@"handled":@(atomic_load(&handled)),@"forwarded":@(atomic_load(&forwarded)),@"unmatched":@(atomic_load(&rejected)),@"previousTaskHandlerRetained":@(MACH_PORT_VALID(previousPort)),@"usesAppSignalHandler":@NO,@"retainedUntilRestart":@(active!=0)};pthread_mutex_unlock(&prepareLock);return state;
}
#else
int dh_control_breakpoint_prepare(char *error,size_t size){if(error && size)strlcpy(error,"native Mach checkpoint architecture unavailable",size);return 0;}
int dh_control_breakpoint_force_for_selftest(int enabled){(void)enabled;return 0;}
int dh_control_breakpoint_forced(void){return 0;}
NSDictionary *DHControlBreakpointState(void){return @{@"ready":@NO,@"attempted":@NO,@"reason":@"native Mach checkpoint architecture unavailable"};}
#endif
