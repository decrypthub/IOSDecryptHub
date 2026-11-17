#ifndef DH_UNWIND_H
#define DH_UNWIND_H
#include "dh_cpu_context.h"
#define DH_STACK_MAX 256
enum {
    DH_UNWIND_UNSPECIFIED=0,DH_UNWIND_BACKEND_UNAVAILABLE,DH_UNWIND_REGISTER_ERROR,
    DH_UNWIND_CYCLE,DH_UNWIND_NO_PROCEDURE,DH_UNWIND_STEP_ERROR,
    DH_UNWIND_METADATA_STOP,DH_UNWIND_ZERO_PC,DH_UNWIND_FRAME_LIMIT,
    DH_UNWIND_NO_CALLER,DH_UNWIND_RECORD_TRUNCATED
};
typedef struct {
    uint64_t pc[DH_STACK_MAX], sp[DH_STACK_MAX];
    unsigned count;
    int error, complete, truncated;
    unsigned stopReason;
    int stepResult;
    uint64_t terminalPC,terminalSP,terminalFP,stackLow,stackHigh,procedureStart,procedureEnd;
} DHRawStack;
const char *dh_unwind_stop_name(unsigned reason);
void dh_unwind_capture(const DHCPUContext *entry, uint64_t target, DHRawStack *out);
int dh_unwind_available(void);
void dh_unwind_current(DHRawStack *out);
int dh_unwind_bounds(uint64_t pc, uint64_t *start, uint64_t *end);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHStackDictionary(const DHRawStack *stack);
NSDictionary *DHResolveStack(NSDictionary *stack, BOOL currentGeneration);
NSString *DHEncodeRawStack(const DHRawStack *stack);
NSDictionary *DHDecodeRawStack(NSString *text);
NSString *DHStackText(NSDictionary *stack);
#endif
#endif
