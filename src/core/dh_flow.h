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
NSDictionary *DHFlowConfigure(BOOL enabled,BOOL roots,unsigned budget,unsigned milliseconds,NSArray *excludedQueues);
NSDictionary *DHFlowRead(unsigned offset,unsigned limit,uint64_t task);
NSDictionary *DHFlowState(void);
NSDictionary *DHFlowSelfTest(void);
#endif
#endif
