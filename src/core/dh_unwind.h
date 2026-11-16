#ifndef DH_UNWIND_H
#define DH_UNWIND_H
#include "dh_cpu_context.h"
#define DH_STACK_MAX 256
typedef struct {
    uint64_t pc[DH_STACK_MAX], sp[DH_STACK_MAX];
    unsigned count;
    int error, complete, truncated;
} DHRawStack;
void dh_unwind_capture(const DHCPUContext *entry, uint64_t target, DHRawStack *out);
int dh_unwind_available(void);
void dh_unwind_current(DHRawStack *out);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHStackDictionary(const DHRawStack *stack);
NSDictionary *DHResolveStack(NSDictionary *stack, BOOL currentGeneration);
NSString *DHEncodeRawStack(const DHRawStack *stack);
NSDictionary *DHDecodeRawStack(NSString *text);
NSString *DHStackText(NSDictionary *stack);
#endif
#endif
