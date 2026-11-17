#include "dh_call_context.h"
#include <stdatomic.h>
static _Atomic uint64_t next_id = 0, lost = 0;
static _Thread_local DHCallContext frames[DH_CALL_DEPTH_MAX];
static _Thread_local unsigned count;
static _Thread_local uint64_t async_task;
static _Thread_local uint64_t async_domain;
static _Thread_local int trusted=1;
static _Atomic(dh_runtime_domain_provider) runtime_provider;

uint64_t dh_call_runtime_domain(void) {
    dh_runtime_domain_provider provider=atomic_load_explicit(&runtime_provider,memory_order_acquire);
    return provider?provider():0;
}
int dh_call_set_runtime_domain_provider(dh_runtime_domain_provider provider) {
    if(!provider)return 0;
    dh_runtime_domain_provider empty=0;
    return atomic_compare_exchange_strong_explicit(&runtime_provider,&empty,provider,memory_order_release,memory_order_acquire) || empty==provider;
}

DHCallContext dh_call_begin(int paired, uint64_t now_ns) {
    DHCallContext c = {0};
    c.id = atomic_fetch_add_explicit(&next_id, 1, memory_order_relaxed) + 1;
    c.runtime_domain=dh_call_runtime_domain();
    c.parent = trusted && count && frames[count-1].runtime_domain==c.runtime_domain ? frames[count - 1].id : 0;
    c.started_ns = now_ns;
    for(unsigned i=count;i>0 && frames[i-1].runtime_domain==c.runtime_domain;i--)c.depth++;
    c.async_task = trusted && async_domain==c.runtime_domain?async_task:0;
    c.context_trusted=trusted;
    if (paired && count < DH_CALL_DEPTH_MAX) {
        c.tracked = 1;
        frames[count++] = c;
    } else if (paired) {
        atomic_fetch_add_explicit(&lost, 1, memory_order_relaxed);
    }
    return c;
}

DHCallContext dh_call_end(uint64_t token) {
    DHCallContext empty = {.id = token};
    if (!token) return empty;
    for (unsigned i = count; i > 0; i--) {
        if (frames[i - 1].id != token) continue;
        DHCallContext c = frames[i - 1];
        if (i != count) atomic_fetch_add_explicit(&lost, count - i, memory_order_relaxed);
        count = i - 1;
        return c;
    }
    return empty; // 溢出/非本线程/非局部退出，不错配其它调用。
}
void dh_call_bind_runtime_task(DHCallContext *call,uint64_t token) {
    if(!call)return;
    call->runtime_task=token;
    for(unsigned i=count;i>0;i--)if(frames[i-1].id==call->id){frames[i-1].runtime_task=token;break;}
}
uint64_t dh_call_parent(void) { return trusted && count && frames[count-1].runtime_domain==dh_call_runtime_domain() ? frames[count - 1].id : 0; }
uint64_t dh_call_context_lost(void) { return atomic_load_explicit(&lost, memory_order_relaxed); }
uint64_t dh_call_async(void) { return trusted && async_domain==dh_call_runtime_domain()?async_task:0; }
void dh_call_set_async(uint64_t task) { async_task = task;async_domain=dh_call_runtime_domain(); }
void dh_call_set_async_for_domain(uint64_t task,uint64_t domain) {async_task=task;async_domain=domain;}
void dh_call_set_trust(int value) {trusted=value;}
