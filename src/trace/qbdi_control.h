#ifndef DH_QBDI_CONTROL_H
#define DH_QBDI_CONTROL_H
#include "dh_cpu_context.h"
#include "dh_call_context.h"
#include "dh_thunk.h"
#include "dh_flow.h"
#ifdef __cplusplus
extern "C" {
#endif

enum {
    DH_CONTROL_NONE=0,DH_CONTROL_ROOT,DH_CONTROL_CHECKPOINT,
    DH_CONTROL_SETJMP,DH_CONTROL_LONGJMP
};
enum {DH_CONTROL_WAITING=0,DH_CONTROL_DBI,DH_CONTROL_NATIVE,DH_CONTROL_TERMINAL};
enum {DH_CONTROL_EVENTS=256,DH_CONTROL_SPANS=64,DH_CONTROL_RANGES=16};
enum {DH_CONTROL_OPAQUE=DH_THUNK_COUNT+16};
typedef struct {uint64_t start,end;} DHControlRange;
typedef struct {uint64_t pc,sp,ticket,environment;} DHControlSpan;
typedef struct {uint64_t sequence,when,pc,sp,lr,word0,word1,reference;unsigned kind;} DHControlEvent;
typedef DHFlowDetachedGuard DHControlAbortedCall;
typedef struct {
    // Written only by the original thread. The live session's terminal release
    // publishes all snapshots to readers; a running session is never paged.
    void *transfer,*vm;
    uintptr_t ownerThread;
    uint64_t threadID,rootSP,rootReturn,stackLow,stackHigh,target;
    unsigned enabled,phase,resumeKind,lastReturn,rangeCount,spanCount,vmAbandoned;
    unsigned eventCount,eventLost,gaps,personalityDepth,abortCount;
    uint64_t nextSpan,padPC,padSP,jumpPC,jumpSP,jumpTicket,jumpEnvironment,rootTailTicket;
    int jumpRequested;
    DHControlRange ranges[DH_CONTROL_RANGES];
    dh_thunk_code_range opaque[DH_CONTROL_OPAQUE];unsigned opaqueCount;
    DHControlSpan spans[DH_CONTROL_SPANS];
    DHControlEvent events[DH_CONTROL_EVENTS];
    DHControlAbortedCall aborted[DH_CALL_DEPTH_MAX];
    char gapReason[96];
} DHControlSession;

// The thunk registry calls publish before Dobby activates physical code. A
// failed, unpublished patch is retired before its slot can be reused.
int dh_control_publish(unsigned slot,uint64_t target,unsigned kind,const uint8_t *bytes,unsigned length);
void dh_control_unpublish(unsigned slot);
unsigned dh_control_boundary_kind(unsigned slot);
int dh_control_is_owner(void);
void *dh_control_boundary_claim(uint64_t slot,const DHCPUContext *cpu);
int dh_control_prepare(char *error,size_t errorSize);
int dh_control_initialize(DHControlSession *control,void *vm,void *transfer,uint64_t target,char *error,size_t errorSize);
int dh_control_begin(DHControlSession *control,const DHCPUContext *entry,uint64_t threadID);
void dh_control_instruction(DHControlSession *control,uint64_t pc,uint64_t sp,int isReturn);
void dh_control_handoff(DHControlSession *control,const DHCPUContext *cpu);
void dh_control_finish(DHControlSession *control);
unsigned dh_control_option(void);

#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHControlSnapshot(const DHControlSession *control);
NSDictionary *DHControlState(void);
#endif
#ifdef __cplusplus
}
#endif
#endif
