// qbdi_trace.h — QBDI 指令级 trace（JB/越狱版）
//
// 只做「一次显式函数调用 + 有界指令记录」：在调用线程上创建一次性 QBDI VM，
// 把目标函数所在模块加入插桩范围，从入口开始执行并记录前 N 条指令，然后销毁 VM。
// 这是 replay（函数会被真实执行一次），不是 live-entry 采样；副作用与参数限制见返回的 warnings。

#ifndef DH_QBDI_TRACE_H
#define DH_QBDI_TRACE_H

#import <Foundation/Foundation.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 返回一个 JSON-able NSDictionary：
//   ok, error?, target{module,symbol,addr}, call_ok, retval, count, truncated,
//   stop_reason, duration_ms, instructions[{pc,size,mnemonic,disasm}], warnings[]
NSDictionary *DHQBDITraceFunction(NSString *module, NSString *symbol, uint64_t addr,
                                  const uint64_t *args, int argc,
                                  int maxInsns, int maxMs);
// buffers=[{arg:0..7,hex:"..."}]：本次调用拥有的可写副本，退出后释放；无需沿用 App 临时指针。
NSDictionary *DHQBDITraceFunctionWithBuffers(NSString *module, NSString *symbol, uint64_t addr,
    const uint64_t *args, int argc, int maxInsns, int maxMs, NSArray *buffers);

// 当前切片是否实际链接 QBDI；arm64e 链接启用 QBDI_PTRAUTH 的独立构建。
BOOL DHQBDIAvailable(void);

#ifdef __cplusplus
}
#endif

#endif // DH_QBDI_TRACE_H
