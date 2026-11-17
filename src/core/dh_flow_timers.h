#ifndef DH_FLOW_TIMERS_H
#define DH_FLOW_TIMERS_H
#import <Foundation/Foundation.h>
#include "fishhook.h"
const struct rebinding *DHFlowTimerBindings(size_t *count);
int DHFlowTimerOwnsImport(const char *name);
void DHFlowTimerPrepare(void);
NSDictionary *DHFlowTimerState(void);
NSDictionary *DHFlowTimerRecords(void);
#endif
