#ifndef DH_CALL_CONTEXT_H
#define DH_CALL_CONTEXT_H
#include <stdint.h>
#define DH_CALL_DEPTH_MAX 64
typedef struct {
    uint64_t id, parent, started_ns;
    uint32_t depth;
    int tracked;
} DHCallContext;
// 只为会返回到 post 桥的调用入栈。入口尾调用没有可观测出口，不伪造 span。
DHCallContext dh_call_begin(int paired, uint64_t now_ns);
DHCallContext dh_call_end(uint64_t token);
uint64_t dh_call_parent(void);
uint64_t dh_call_context_lost(void);
#endif
