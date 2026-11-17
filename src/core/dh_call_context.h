#ifndef DH_CALL_CONTEXT_H
#define DH_CALL_CONTEXT_H
#include <stdint.h>
#define DH_CALL_DEPTH_MAX 64
typedef struct {
    uint64_t id, parent, started_ns, async_task, runtime_domain, runtime_task;
    uint32_t depth;
    int tracked, context_trusted;
} DHCallContext;
// 只为会返回到 post 桥的调用入栈。入口尾调用没有可观测出口，不伪造 span。
DHCallContext dh_call_begin(int paired, uint64_t now_ns);
DHCallContext dh_call_end(uint64_t token);
uint64_t dh_call_parent(void);
uint64_t dh_call_context_lost(void);
uint64_t dh_call_async(void);
void dh_call_set_async(uint64_t task);
void dh_call_set_async_for_domain(uint64_t task,uint64_t domain);
void dh_call_set_trust(int trusted);
// A runtime may multiplex logical tasks on one native stack. The provider must
// be allocation-free and return its authoritative current identity, including
// unknown/unrecorded tasks. Installation is immutable; zero means no runtime.
typedef uint64_t (*dh_runtime_domain_provider)(void);
int dh_call_set_runtime_domain_provider(dh_runtime_domain_provider provider);
uint64_t dh_call_runtime_domain(void);
void dh_call_bind_runtime_task(DHCallContext *call,uint64_t token);
#endif
