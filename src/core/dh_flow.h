#ifndef DH_FLOW_H
#define DH_FLOW_H
#include "dh_unwind.h"
#include "dh_call_context.h"
#include <stdint.h>
uint64_t DHFlowGuardBegin(int slot,uint64_t callerSP);
void DHFlowGuardBind(uint64_t guard,const DHCallContext *call);
void DHFlowGuardEnd(uint64_t token);
void DHFlowCheck(const DHRawStack *stack);
void DHFlowBoundary(void);
int DHFlowOwnsImport(const char *symbol);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHFlowFields(uint64_t task);
NSDictionary *DHFlowConfigure(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues,NSArray *rootQueues);
NSDictionary *DHFlowConfigureWithAPIs(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues,NSArray *rootQueues,NSArray *rootAPIs);
NSDictionary *DHFlowRead(unsigned offset,unsigned limit,uint64_t task);
NSDictionary *DHFlowState(void);
NSDictionary *DHFlowDiagnostics(unsigned offset,unsigned limit);
// Typed scheduler adapters record registration separately from each delivery.
uint64_t DHFlowRegisterCallback(const char *api,const char *queue,void *caller,void *callback);
void DHFlowRunCallback(uint64_t registration,dispatch_block_t body);
void DHFlowRetireCallback(uint64_t registration,const char *reason);
void DHFlowUpdateCallbackQueue(uint64_t registration,const char *queue);
int DHFlowCallbackCaptureActive(void);
uintptr_t DHFlowCallbackBlockAddress(dispatch_block_t body);
NSDictionary *DHFlowRegistrations(unsigned offset,unsigned limit);
NSDictionary *DHFlowSelfTest(void);
#endif
#endif
