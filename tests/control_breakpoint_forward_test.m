#import <Foundation/Foundation.h>
#include "dh_control_breakpoint.h"
#include "../build/control-mig/dh_control_mach_client.h"
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach/arm/exception.h>
#include <pthread.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <signal.h>
#include <string.h>
__thread int dh_in_hook;
static __thread uint64_t originalTLS=0x494448;
uint64_t dh_control_breakpoint_entry(uint64_t pc){(void)pc;return 0;}
extern boolean_t dh_fixture64_mach_server(mach_msg_header_t *,mach_msg_header_t *);
extern boolean_t dh_fixture32_mach_server(mach_msg_header_t *,mach_msg_header_t *);
static mach_port_t priorPort;
static int narrowProtocol;
static _Atomic unsigned hits;
static uint64_t firstCode;
extern void idh_owned_unknown_breakpoint(void);
__attribute__((naked,noinline)) static uint64_t original_call(void) {
    __asm__ volatile("mov x0,#7\n movi v0.16b,#0x3c\n adds x9,x0,#0\n .globl _idh_owned_unknown_breakpoint\n _idh_owned_unknown_breakpoint:\n brk #0x1234\n b.eq 1f\n umov w9,v0.b[7]\n cmp w9,#0x3c\n b.ne 1f\n add x0,x0,#9\n ret\n 1: mov x0,#0xbad\n ret\n");
}
static kern_return_t state_reply(exception_type_t exception,const int64_t *codes,unsigned count,int *flavor,thread_state_t old,unsigned oldCount,thread_state_t next,unsigned *nextCount) {
    if(exception!=EXC_BREAKPOINT || count!=2 || codes[0]!=EXC_ARM_BREAKPOINT || *flavor!=ARM_THREAD_STATE64 || oldCount!=ARM_THREAD_STATE64_COUNT || *nextCount<ARM_THREAD_STATE64_COUNT)return KERN_FAILURE;
    arm_thread_state64_t *state=(void *)old;uint64_t pc=arm_thread_state64_get_pc(*state);
    if(pc!=(uint64_t)ptrauth_strip((void *)idh_owned_unknown_breakpoint,ptrauth_key_function_pointer))return KERN_FAILURE;
    unsigned seen=atomic_fetch_add(&hits,1);if(!seen)firstCode=codes[1];else if(firstCode!=(uint64_t)codes[1])return KERN_FAILURE;
    memcpy(next,old,sizeof(*state));arm_thread_state64_t *resume=(void *)next;
    void (*after)(void)=ptrauth_sign_unauthenticated((void *)(pc+4),ptrauth_key_function_pointer,0);
    arm_thread_state64_set_pc_fptr(*resume,after);*nextCount=ARM_THREAD_STATE64_COUNT;return KERN_SUCCESS;
}
static kern_return_t default_reply(mach_port_t thread,exception_type_t exception,const int64_t *codes,unsigned count) {
    arm_thread_state64_t old={0},next={0};unsigned oldCount=ARM_THREAD_STATE64_COUNT,nextCount=ARM_THREAD_STATE64_COUNT;int flavor=ARM_THREAD_STATE64;
    kern_return_t result=thread_get_state(thread,flavor,(thread_state_t)&old,&oldCount);
    if(result==KERN_SUCCESS)result=state_reply(exception,codes,count,&flavor,(thread_state_t)&old,oldCount,(thread_state_t)&next,&nextCount);
    return result==KERN_SUCCESS?thread_set_state(thread,flavor,(thread_state_t)&next,nextCount):result;
}
kern_return_t dh_fixture64_catch_mach_exception_raise(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,unsigned count) {
    kern_return_t result=port==priorPort?default_reply(thread,exception,codes,count):KERN_FAILURE;
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return result;
}
kern_return_t dh_fixture64_catch_mach_exception_raise_state(mach_port_t port,exception_type_t exception,mach_exception_data_t codes,unsigned count,int *flavor,thread_state_t old,unsigned oldCount,thread_state_t next,unsigned *nextCount) {
    return port==priorPort?state_reply(exception,codes,count,flavor,old,oldCount,next,nextCount):KERN_FAILURE;
}
kern_return_t dh_fixture64_catch_mach_exception_raise_state_identity(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,mach_exception_data_t codes,unsigned count,int *flavor,thread_state_t old,unsigned oldCount,thread_state_t next,unsigned *nextCount) {
    kern_return_t result=port==priorPort?state_reply(exception,codes,count,flavor,old,oldCount,next,nextCount):KERN_FAILURE;
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return result;
}
kern_return_t dh_fixture32_catch_exception_raise(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,exception_data_t codes,unsigned count) {
    int64_t wide[2]={codes[0],count>1?codes[1]:0};kern_return_t result=port==priorPort?default_reply(thread,exception,wide,count):KERN_FAILURE;
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return result;
}
kern_return_t dh_fixture32_catch_exception_raise_state(mach_port_t port,exception_type_t exception,exception_data_t codes,unsigned count,int *flavor,thread_state_t old,unsigned oldCount,thread_state_t next,unsigned *nextCount) {
    int64_t wide[2]={codes[0],count>1?codes[1]:0};return port==priorPort?state_reply(exception,wide,count,flavor,old,oldCount,next,nextCount):KERN_FAILURE;
}
kern_return_t dh_fixture32_catch_exception_raise_state_identity(mach_port_t port,mach_port_t thread,mach_port_t task,exception_type_t exception,exception_data_t codes,unsigned count,int *flavor,thread_state_t old,unsigned oldCount,thread_state_t next,unsigned *nextCount) {
    int64_t wide[2]={codes[0],count>1?codes[1]:0};kern_return_t result=port==priorPort?state_reply(exception,wide,count,flavor,old,oldCount,next,nextCount):KERN_FAILURE;
    mach_port_deallocate(mach_task_self(),thread);mach_port_deallocate(mach_task_self(),task);return result;
}
static void *serve(void *unused){(void)unused;mach_msg_server(narrowProtocol?dh_fixture32_mach_server:dh_fixture64_mach_server,8192,priorPort,0);return NULL;}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL owned Mach forwarding line %d\n",__LINE__);return 1;}}while(0)
static unsigned refs(mach_port_t port){mach_port_urefs_t value=0;return mach_port_get_refs(mach_task_self(),port,MACH_PORT_RIGHT_SEND,&value)==KERN_SUCCESS?value:0;}
int main(int argc,char **argv){@autoreleasepool{
    const char *mode=argc>1?argv[1]:"default64";char error[256]={0};
    if(!strcmp(mode,"unhandled")){CHECK(dh_control_breakpoint_prepare(error,sizeof(error)));original_call();return 2;}
    narrowProtocol=strstr(mode,"32")!=NULL;
    exception_behavior_t behavior=strstr(mode,"identity")?EXCEPTION_STATE_IDENTITY:strstr(mode,"state")?EXCEPTION_STATE:EXCEPTION_DEFAULT;
    if(!narrowProtocol)behavior|=MACH_EXCEPTION_CODES;
    CHECK(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&priorPort)==KERN_SUCCESS);
    CHECK(mach_port_insert_right(mach_task_self(),priorPort,priorPort,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
    pthread_t server;CHECK(!pthread_create(&server,NULL,serve,NULL));pthread_detach(server);
    mach_port_t owner=mach_thread_self();int threadOnly=!strcmp(mode,"thread-conflict");
    if(threadOnly)CHECK(thread_set_exception_ports(owner,EXC_MASK_BREAKPOINT,priorPort,behavior,ARM_THREAD_STATE64)==KERN_SUCCESS);
    else CHECK(task_set_exception_ports(mach_task_self(),EXC_MASK_BREAKPOINT,priorPort,behavior,ARM_THREAD_STATE64)==KERN_SUCCESS);
    unsigned taskRefs=refs(mach_task_self()),threadRefs=refs(owner);sigset_t maskBefore={0},maskAfter={0};pthread_sigmask(SIG_SETMASK,NULL,&maskBefore);
    for(unsigned i=0;i<101;i++)CHECK(original_call()==16 && originalTLS==0x494448);
    CHECK(atomic_load(&hits)==101 && refs(mach_task_self())==taskRefs && refs(owner)==threadRefs);
    int prepared=dh_control_breakpoint_prepare(error,sizeof(error));
    if(threadOnly)CHECK(!prepared && strstr(error,"thread-level"));else CHECK(prepared);
    for(unsigned i=0;i<137;i++)CHECK(original_call()==16 && originalTLS==0x494448);
    pthread_sigmask(SIG_SETMASK,NULL,&maskAfter);
    CHECK(atomic_load(&hits)==238 && !memcmp(&maskBefore,&maskAfter,sizeof(maskBefore)));
    CHECK(refs(mach_task_self())==taskRefs && refs(owner)==threadRefs);
    NSDictionary *state=DHControlBreakpointState();CHECK([state[@"forwarded"] unsignedIntValue]==(threadOnly?0:137));CHECK(![state[@"handled"] unsignedIntValue]);
    puts([[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:@{@"ok":@YES,@"mode":@(mode),@"originalHandlerCalls":@(atomic_load(&hits)),@"GPR_SIMD_flags_TLS_mask_preserved":@YES,@"identitySendRightsStable":@YES,@"state":state} options:0 error:NULL] encoding:NSUTF8StringEncoding].UTF8String);
    return 0;
}}
