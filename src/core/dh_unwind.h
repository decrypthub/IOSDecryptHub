#ifndef DH_UNWIND_H
#define DH_UNWIND_H
#include "dh_cpu_context.h"
#define DH_STACK_MAX 256
enum {
    DH_UNWIND_UNSPECIFIED=0,DH_UNWIND_BACKEND_UNAVAILABLE,DH_UNWIND_REGISTER_ERROR,
    DH_UNWIND_CYCLE,DH_UNWIND_NO_PROCEDURE,DH_UNWIND_STEP_ERROR,
    DH_UNWIND_METADATA_STOP,DH_UNWIND_ZERO_PC,DH_UNWIND_FRAME_LIMIT,
    DH_UNWIND_NO_CALLER,DH_UNWIND_RECORD_TRUNCATED,DH_UNWIND_RECIPE_REFUSED
};
typedef struct {
    uint64_t pc[DH_STACK_MAX], sp[DH_STACK_MAX];
    uint8_t recipe[DH_STACK_MAX]; // step out of this frame used a verified recipe slot
    unsigned count;
    int error, complete, truncated;
    unsigned stopReason;
    int stepResult;
    uint64_t terminalPC,terminalSP,terminalFP,stackLow,stackHigh,procedureStart,procedureEnd;
    unsigned recipeRejection;
} DHRawStack;
const char *dh_unwind_stop_name(unsigned reason);
void dh_unwind_capture(const DHCPUContext *entry, uint64_t target, DHRawStack *out);
int dh_unwind_available(void);
void dh_unwind_current(DHRawStack *out);
int dh_unwind_bounds(uint64_t pc, uint64_t *start, uint64_t *end);
int dh_unwind_recipe_available(void);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHStackDictionary(const DHRawStack *stack);
NSDictionary *DHResolveStack(NSDictionary *stack, BOOL currentGeneration);
NSString *DHEncodeRawStack(const DHRawStack *stack);
NSDictionary *DHDecodeRawStack(NSString *text);
NSString *DHStackText(NSDictionary *stack);
// Reader verifies independent function boundaries before calling this. This
// only registers read-only unwinding data; it never patches App code or CFI.
NSDictionary *DHUnwindRegisterRecipe(uint64_t start,uint64_t end,NSString *boundarySource);
NSDictionary *DHUnwindRecipeState(void);
NSDictionary *DHUnwindSetRecipeEnabled(unsigned slot,BOOL enabled);
NSDictionary *DHUnwindRecipeSelfTest(void);
#endif
#endif
