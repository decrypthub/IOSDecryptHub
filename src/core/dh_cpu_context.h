#ifndef DH_CPU_CONTEXT_H
#define DH_CPU_CONTEXT_H
#include <stdint.h>
#include <stddef.h>
// 与 thunk 汇编共享的原生入口快照；没有合成参数或虚拟 App 栈。
typedef struct {
    uint64_t x[31], sp, pc, nzcv, fpcr, fpsr;
    __uint128_t q[32];
} DHCPUContext;
_Static_assert(offsetof(DHCPUContext,sp)==248,"SP layout");
_Static_assert(offsetof(DHCPUContext,q)==288 && sizeof(DHCPUContext)==800,"SIMD layout");
#endif
