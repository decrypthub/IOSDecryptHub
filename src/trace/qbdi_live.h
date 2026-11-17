#ifndef DH_QBDI_LIVE_H
#define DH_QBDI_LIVE_H
#include "dh_cpu_context.h"
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif
struct dh_hook_options;
#ifdef __cplusplus
extern "C" {
#endif
// 汇编只依赖前两个字段；会话在进程存活期间保留，不复用正在恢复的 CPU 快照。
typedef struct {
    void *analysisTop;
    uintptr_t thunkSP;
} DHLiveTransfer;
DHLiveTransfer *dh_live_claim(uint64_t slot, uint64_t original, const DHCPUContext *entry, uint64_t token);
DHCPUContext *dh_live_run(DHLiveTransfer *transfer);
int dh_live_current(void);
#ifdef __OBJC__
BOOL DHLiveAvailable(void);
NSDictionary *DHLiveArm(int slot, uint64_t target, uint64_t original, unsigned maxInstructions,
                       unsigned maxMilliseconds, uint64_t threadID);
NSDictionary *DHLiveRead(NSString *traceID, unsigned offset, unsigned limit);
NSDictionary *DHLiveCancel(NSString *traceID);
// Separate native-control mode. Ordinary live-next-call keeps its explicit
// normal-return requirement and the same eight retained-session budget.
NSDictionary *DHLiveControlPrepare(uint64_t address,const struct dh_hook_options *options);
NSDictionary *DHLiveControlArm(int slot,unsigned maxInstructions,unsigned maxMilliseconds,uint64_t threadID);
NSDictionary *DHLiveState(void);
#endif
#ifdef __cplusplus
}
#endif
#endif
