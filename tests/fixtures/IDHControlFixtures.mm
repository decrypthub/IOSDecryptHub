#import <Foundation/Foundation.h>
#include "idh_control_fixture_abi.h"
#include <setjmp.h>
#include <signal.h>
#include <pthread.h>
#include <ptrauth.h>
#include <string.h>
static jmp_buf insideJump,outsideJump,nestedJump;
static sigjmp_buf insideSignal,outsideSignal;
static NSException *marker;
static int identity;
static uint64_t stats[IDH_CF_STATS];
static __thread uint64_t tlsValue=0x494448;
static __thread unsigned recursionDepth;
static void require(bool ok){if(!ok)[NSException raise:@"IDHControlFixture" format:@"owned control-flow fixture failed"];}
struct LocalScope {~LocalScope(){stats[IDH_CF_CPP_CLEANUPS]++;}};
struct SignalMaskScope {
    sigset_t original;
    SignalMaskScope(){require(!pthread_sigmask(SIG_SETMASK,NULL,&original));}
    ~SignalMaskScope(){pthread_sigmask(SIG_SETMASK,&original,NULL);}
};
static void entered(void){stats[IDH_CF_CALLS]++;pthread_threadid_np(NULL,&stats[IDH_CF_THREAD]);}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlFixtureAfter(uint64_t value){stats[IDH_CF_AFTER]++;require(tlsValue==0x494448);return value+9;}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlFixtureThrow(uint64_t value){LocalScope scope;throw idh_control_fixture::Exact{value,&identity};}
static __attribute__((noinline,optnone)) uint64_t rethrow_cpp(uint64_t value) {
    try {LocalScope scope;return IDHControlFixtureThrow(value);}
    catch(const idh_control_fixture::Exact &e){require(e.value==value && e.identity==&identity);stats[IDH_CF_CATCHES]++;throw;}
}
static __attribute__((noinline,optnone)) uint64_t rich_cpp(uint64_t value) {
    entered();try {LocalScope scope;return rethrow_cpp(value);}
    catch(const idh_control_fixture::Exact &e){require(e.value==value && e.identity==&identity);stats[IDH_CF_CATCHES]++;return IDHControlFixtureAfter(e.value);}
}
static __attribute__((noinline,optnone)) uint64_t rich_objc(uint64_t value) {
    entered();@try {
        @try {@throw marker;}
        @catch(NSException *e){require(e==marker);stats[IDH_CF_CATCHES]++;@throw;}
        @finally {stats[IDH_CF_FINALLY]++;}
    } @catch(NSException *e){require(e==marker);stats[IDH_CF_CATCHES]++;return IDHControlFixtureAfter(value);}
    @finally {stats[IDH_CF_FINALLY]++;}
}
static bool blocked(void){sigset_t mask;require(!pthread_sigmask(SIG_SETMASK,NULL,&mask));return sigismember(&mask,SIGUSR1)==1;}
static void set_block(bool block){sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGUSR1);require(!pthread_sigmask(block?SIG_BLOCK:SIG_UNBLOCK,&mask,NULL));}
static __attribute__((noinline,optnone)) uint64_t jump_mask(uint64_t value) {
    entered();volatile unsigned attempts=0;set_block(true);int n=setjmp(insideJump);
    if(!n){require(attempts++==0);set_block(false);longjmp(insideJump,0);}
    require(n==1 && blocked());set_block(false);attempts=0;n=_setjmp(insideJump);
    if(!n){require(attempts++==0);set_block(true);_longjmp(insideJump,(int)value);}
    require(n==(int)value && blocked());set_block(false);return IDHControlFixtureAfter(n);
}
static __attribute__((noinline,optnone)) uint64_t signal_jump_mask(uint64_t value) {
    entered();volatile unsigned attempts=0;set_block(true);int n=sigsetjmp(insideSignal,1);
    if(!n){require(attempts++==0);set_block(false);siglongjmp(insideSignal,0);}
    require(n==1 && blocked());set_block(false);attempts=0;n=sigsetjmp(insideSignal,0);
    if(!n){require(attempts++==0);set_block(true);siglongjmp(insideSignal,(int)value);}
    require(n==(int)value && blocked());set_block(false);return IDHControlFixtureAfter(n);
}
static __attribute__((noinline,optnone)) uint64_t nested_jump(uint64_t value) {
    entered();volatile unsigned attempts=0;int n=setjmp(insideJump);
    if(!n){require(attempts++==0);int m=setjmp(nestedJump);if(!m)longjmp(insideJump,(int)value);require(false);}
    require(n==(int)value);return IDHControlFixtureAfter(n);
}
static __attribute__((noinline,optnone)) uint64_t reuse_jump(uint64_t value) {
    entered();volatile unsigned attempts=0;int n=setjmp(insideJump);if(!n){require(attempts++==0);longjmp(insideJump,0);}
    require(n==1);attempts=0;n=setjmp(insideJump);if(!n){require(attempts++==0);longjmp(insideJump,(int)value);}
    require(n==(int)value);return IDHControlFixtureAfter(n);
}
static __attribute__((noinline,optnone)) uint64_t native_callback(uint64_t value) {
    try {LocalScope scope;return IDHControlFixtureThrow(value);}
    catch(const idh_control_fixture::Exact &e){require(e.identity==&identity);stats[IDH_CF_CATCHES]++;return IDHControlFixtureAfter(e.value);}
}
static __attribute__((noinline,optnone)) uint64_t callback_root(uint64_t value){entered();return IDHControlNativeCall(native_callback,value);}
static __attribute__((noinline,optnone)) uint64_t native_catch(uint64_t value){entered();return IDHControlFixtureAfter(IDHControlNativeCatch(IDHControlFixtureThrow,value));}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlFixtureCount(uint64_t value){entered();return value;}
extern "C" uint64_t IDHControlFixtureAdjacent(uint64_t);
asm(
".text\n.p2align 2\n.globl _IDHControlFixtureAdjacent\n_IDHControlFixtureAdjacent:\n.cfi_startproc\n"
#if defined(__arm64e__)
"pacibsp\n"
#endif
"stp x29,x30,[sp,#-48]!\n.cfi_def_cfa_offset 48\n.cfi_offset 29,-48\n.cfi_offset 30,-40\n"
"stp x19,x20,[sp,#16]\n.cfi_offset 19,-32\n.cfi_offset 20,-24\nstp x21,x22,[sp,#32]\n.cfi_offset 21,-16\n.cfi_offset 22,-8\n"
"mov x29,sp\nbl _IDHControlFixtureCount\nmov x21,x0\nbl _IDHControlNativePair\nmov x19,x0\nmov x20,x1\nmov x0,x21\n"
#if defined(__arm64e__)
"blraaz x19\nblraaz x20\n"
#else
"blr x19\nblr x20\n"
#endif
"bl _IDHControlFixtureAfter\nldp x19,x20,[sp,#16]\nldp x21,x22,[sp,#32]\nldp x29,x30,[sp],#48\n.cfi_def_cfa_offset 0\n"
#if defined(__arm64e__)
"retab\n"
#else
"ret\n"
#endif
".cfi_endproc\n");
static __attribute__((noinline,optnone)) uint64_t recursive(uint64_t value) {
    bool outer=recursionDepth++==0;if(outer)entered();uint64_t result=value?recursive(value-1)+1:0;recursionDepth--;
    return outer?IDHControlFixtureAfter(result):result;
}
static __attribute__((noinline,optnone)) uint64_t composite(uint64_t value) {
    if(!value)return 0;require(composite(0)==0); // real recursive entry through the owned 4B root
    entered();stats[IDH_CF_COMPOSITES]++;
    return rich_cpp(value)+rich_objc(value)+jump_mask(value)+signal_jump_mask(value)+nested_jump(value)+reuse_jump(value)+callback_root(value)+native_catch(value)+IDHControlFixtureAdjacent(value)+recursive(value);
}
static __attribute__((noinline,optnone)) uint64_t cpp_out(uint64_t value){entered();LocalScope scope;return IDHControlFixtureThrow(value);}
static __attribute__((noinline,optnone)) uint64_t objc_out(uint64_t value){entered();@try{@throw marker;}@finally{stats[IDH_CF_FINALLY]++;}return value;}
static __attribute__((noinline,optnone)) uint64_t jump_out(uint64_t value){entered();longjmp(outsideJump,(int)value);}
static __attribute__((noinline,optnone)) uint64_t sigjump_out(uint64_t value){entered();siglongjmp(outsideSignal,(int)value);}
static __attribute__((noinline,optnone)) uint64_t fixture_normal(uint64_t value){entered();return IDHControlFixtureAfter(value);}

extern "C" unsigned IDHControlFixtureVersion(void){return 1;}
extern "C" void IDHControlFixtureReset(void){memset(stats,0,sizeof(stats));IDHControlNativeReset();if(!marker)marker=[NSException exceptionWithName:@"IDHOwnedControlException" reason:@"owned native control fixture" userInfo:nil];}
extern "C" IDHControlFixtureRoot IDHControlFixtureGetRoot(unsigned mode) {
    switch(mode){case IDH_CF_COMPOSITE:return composite;case IDH_CF_CPP_OUT:return cpp_out;case IDH_CF_OBJC_OUT:return objc_out;case IDH_CF_JUMP_OUT:return jump_out;case IDH_CF_SIGJUMP_OUT:return sigjump_out;case IDH_CF_NORMAL:return fixture_normal;default:return NULL;}
}
extern "C" uint64_t IDHControlFixtureInvoke(unsigned mode,uint64_t value) {
    SignalMaskScope mask;
    if(mode==IDH_CF_CPP_OUT){try{cpp_out(value);}catch(const idh_control_fixture::Exact &e){require(e.value==value && e.identity==&identity);stats[IDH_CF_CATCHES]++;return IDHControlFixtureAfter(e.value);}}
    else if(mode==IDH_CF_OBJC_OUT){@try{objc_out(value);}@catch(NSException *e){require(e==marker);stats[IDH_CF_CATCHES]++;return IDHControlFixtureAfter(value);}}
    else if(mode==IDH_CF_JUMP_OUT){int n=setjmp(outsideJump);if(!n)jump_out(value);require(n==(int)value);return IDHControlFixtureAfter(n);}
    else if(mode==IDH_CF_SIGJUMP_OUT){int n=sigsetjmp(outsideSignal,1);if(!n)sigjump_out(value);require(n==(int)value);return IDHControlFixtureAfter(n);}
    else {IDHControlFixtureRoot body=IDHControlFixtureGetRoot(mode);require(body!=NULL);return body(value);}
    require(false);return 0;
}
extern "C" int IDHControlFixtureStats(uint64_t *out,size_t count) {
    if(!out || count<IDH_CF_STATS)return 0;memcpy(out,stats,sizeof(stats));out[IDH_CF_NATIVE_CLEANUPS]=IDHControlNativeCleanups();out[IDH_CF_NATIVE_CALLS]=IDHControlNativeCalls();return 1;
}
extern "C" uint64_t IDHControlFixtureAfterPC(void){return (uint64_t)ptrauth_strip((void *)IDHControlFixtureAfter,ptrauth_key_function_pointer);}
