#include "dh_call_context.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

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
    puts("PASS: nested/entry-only/overflow contexts and 400 concurrent call pairs");
    return 0;
}
