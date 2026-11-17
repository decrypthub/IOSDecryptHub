#ifndef DH_FLOW_H
#define DH_FLOW_H
#include "dh_unwind.h"
#include "dh_call_context.h"
#include <stdint.h>
uint64_t DHFlowGuardBegin(int slot,uint64_t callerSP);
void DHFlowGuardBind(uint64_t guard,const DHCallContext *call);
void DHFlowGuardEnd(uint64_t token);
typedef struct {unsigned slot;uint64_t token;DHCallContext call;} DHFlowDetachedGuard;
// Exact owned root token, not absence from a partial native stack. This path is
// allocation-free and leaves log/JSON emission to the control reader.
unsigned DHFlowGuardDetach(uint64_t rootToken,DHFlowDetachedGuard *out,unsigned capacity);
void DHFlowCheck(const DHRawStack *stack);
void DHFlowBoundary(void);
int DHFlowOwnsImport(const char *symbol);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHFlowFields(uint64_t task);
NSDictionary *DHFlowConfigure(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues,NSArray *rootQueues);
NSDictionary *DHFlowConfigureWithAPIs(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues,NSArray *rootQueues,NSArray *rootAPIs);
NSDictionary *DHFlowConfigureWithCallbacks(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues,NSArray *rootQueues,NSArray *rootAPIs,NSArray *rootCallbacks);
NSDictionary *DHFlowRead(unsigned offset,unsigned limit,uint64_t task);
NSDictionary *DHFlowState(void);
NSDictionary *DHFlowDiagnostics(unsigned offset,unsigned limit);
// Typed scheduler adapters record registration separately from each delivery.
uint64_t DHFlowRegisterCallback(const char *api,const char *queue,void *caller,void *callback);
uint64_t DHFlowRegisterNamedCallback(const char *api,const char *queue,void *caller,void *callback,const char *label);
void DHFlowRunCallback(uint64_t registration,dispatch_block_t body);
// Actual runtime callback entry with no observed registration/enqueue history.
void DHFlowRunEntry(const char *api,const char *queue,void *caller,void *callback,dispatch_block_t body);
dispatch_block_t DHFlowWrapOneShot(const char *api,const char *queue,void *caller,dispatch_block_t body);
// Typed one-shot schedulers keep submission identity even if capture is disabled
// before execution. A callback can claim its prepared token only once.
uint64_t DHFlowPrepareOneShot(const char *api,const char *queue,void *caller,void *callback,const char *label);
void DHFlowRunPreparedOneShot(uint64_t task,dispatch_block_t body);
void DHFlowUnresolvedOneShot(uint64_t task,const char *reason);
void DHFlowRetireCallback(uint64_t registration,const char *reason);
void DHFlowUpdateCallbackQueue(uint64_t registration,const char *queue);
int DHFlowRegistrationState(uint64_t registration); // 0 retired/unknown; 1 this window; 2 another window
void DHFlowAdapterInternalBegin(void);
void DHFlowAdapterInternalEnd(void);
void DHFlowSetOwnedFixtureScope(BOOL enabled);
int DHFlowCallbackCaptureActive(void);
uintptr_t DHFlowCallbackBlockAddress(dispatch_block_t body);
NSDictionary *DHFlowRegistrations(unsigned offset,unsigned limit);
NSDictionary *DHFlowSelfTest(void);
#endif
#endif
