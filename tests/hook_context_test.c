#include "dh_call_context.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
static _Thread_local uint64_t runtime_domain;
static uint64_t domain_provider(void) {return runtime_domain;}

static void *worker(void *unused) {
    (void)unused;
    assert(dh_call_parent() == 0);
    for (unsigned i = 0; i < 100; i++) {
        DHCallContext a = dh_call_begin(1, 100), b = dh_call_begin(1, 110);
        assert(b.parent == a.id && b.depth == 1 && b.id != a.id);
        assert(dh_call_end(b.id).parent == a.id);
        assert(dh_call_end(a.id).started_ns == 100);
        assert(dh_call_parent() == 0);
    }
    return NULL;
}
int main(void) {
    DHCallContext a = dh_call_begin(0, 1);
    assert(!a.tracked && dh_call_parent() == 0);
    DHCallContext frames[DH_CALL_DEPTH_MAX];
    for (unsigned i = 0; i < DH_CALL_DEPTH_MAX; i++) frames[i] = dh_call_begin(1, i);
    DHCallContext overflow = dh_call_begin(1, 99);
    assert(!overflow.tracked && !dh_call_end(overflow.id).tracked);
    assert(dh_call_parent() == frames[DH_CALL_DEPTH_MAX - 1].id);
    for (unsigned i = DH_CALL_DEPTH_MAX; i > 0; i--) assert(dh_call_end(frames[i - 1].id).tracked);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) assert(!pthread_create(&threads[i], NULL, worker, NULL));
    for (unsigned i = 0; i < 4; i++) assert(!pthread_join(threads[i], NULL));
    assert(dh_call_parent() == 0 && dh_call_context_lost() == 1);
    assert(dh_call_set_runtime_domain_provider(domain_provider));
    assert(dh_call_set_runtime_domain_provider(domain_provider));
    runtime_domain=101;dh_call_set_async(51);
    DHCallContext first=dh_call_begin(1,120);
    dh_call_bind_runtime_task(&first,71);
    assert(first.runtime_domain==101 && first.async_task==51 && !first.parent);
    runtime_domain=202;
    assert(!dh_call_parent() && !dh_call_async());
    DHCallContext other=dh_call_begin(1,130);
    assert(other.runtime_domain==202 && !other.parent && !other.async_task && !other.depth);
    DHCallContext nested=dh_call_begin(1,140);
    assert(nested.parent==other.id && nested.depth==1);
    dh_call_set_async(52);assert(dh_call_async()==52);
    dh_call_set_async_for_domain(51,101);assert(!dh_call_async());
    dh_call_end(nested.id);dh_call_end(other.id);
    runtime_domain=101;assert(dh_call_parent()==first.id && dh_call_async()==51);
    assert(dh_call_end(first.id).runtime_task==71);runtime_domain=0;assert(!dh_call_parent() && !dh_call_async());
    puts("PASS: nested/entry-only/overflow contexts and 400 concurrent call pairs");
    puts("PASS: runtime task domain isolates parent/depth/async across reentrant logical tasks");
    return 0;
}
