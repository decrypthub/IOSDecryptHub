#if DH_DEVICE_SESSIONS
#import "dh_session_agent.h"
#import "dh_event.h"
#import "dh_health.h"
#import "log_store.h"
#import "../session/idh_session_ipc.h"
#include <os/lock.h>
#include <stdatomic.h>

static dispatch_source_t syncTimer;
static dispatch_source_t syncWake;
static os_unfair_lock stateLock = OS_UNFAIR_LOCK_INIT;
static atomic_bool recording;
static NSString *sessionID;
static NSMutableArray<NSDictionary *> *pending;
static uint64_t nextSequence;
static uint64_t dropped;
static uint64_t sourceDroppedAtStart;
static uint64_t frozenSourceDropped;
static NSUInteger queuePeak;
static BOOL finishing;
static BOOL boundaryRequested;
static NSTimeInterval leaseExpiresAt;

static void attach(NSString *requested, uint64_t sourceDrops) {
    os_unfair_lock_lock(&stateLock);
    if (requested != sessionID && ![requested isEqualToString:sessionID]) {
        sessionID = [requested copy];
        pending = requested ? [NSMutableArray new] : nil;
        nextSequence = dropped = 0;
        sourceDroppedAtStart = sourceDrops;
        queuePeak = 0;
        finishing = boundaryRequested = NO;
        leaseExpiresAt = NSProcessInfo.processInfo.systemUptime + 300;
        atomic_store(&recording, requested != nil);
    }
    os_unfair_lock_unlock(&stateLock);
}

void dh_session_record(DHLogEntry *entry, BOOL update) {
    if (!atomic_load(&recording) || entry.restoredFromJournal) return;
    BOOL wake = NO;
    os_unfair_lock_lock(&stateLock);
    if (atomic_load(&recording) && NSProcessInfo.processInfo.systemUptime < leaseExpiresAt) {
        uint64_t sequence = ++nextSequence;
        if (pending.count < IDH_SESSION_PENDING_CAPACITY) {
            NSDictionary *context = entry.eventContext;
            NSMutableDictionary *summary = [@{
                @"seq": @(sequence), @"timeMs": @(entry.timestampMs), @"sourceSeq": @(entry.seq),
                @"category": @(entry.category), @"update": @(update),
            } mutableCopy];
            for (NSString *key in @[@"kind", @"phase", @"callId", @"parentCallId", @"asyncTaskId"]) {
                id value = context[key];
                if ([value isKindOfClass:NSString.class] && [value length] && [value length] <= 96)
                    summary[key] = value;
            }
            [pending addObject:summary];
            queuePeak = MAX(queuePeak, pending.count);
            wake = pending.count == IDH_SESSION_MAX_BATCH;
        } else {
            dropped++;
        }
    }
    os_unfair_lock_unlock(&stateLock);
    if (wake) dispatch_source_merge_data(syncWake, 1);
}

static void requestBoundary(DHLogStore *store, NSString *requested) {
    os_unfair_lock_lock(&stateLock);
    BOOL schedule = !boundaryRequested && [sessionID isEqualToString:requested];
    if (schedule) boundaryRequested = YES;
    os_unfair_lock_unlock(&stateLock);
    if (!schedule) return;

    [store enqueueSessionBoundary:^{
        uint64_t sourceDrops = store.droppedEventCount;
        os_unfair_lock_lock(&stateLock);
        BOOL applies = [sessionID isEqualToString:requested];
        if (applies) {
            atomic_store(&recording, false);
            frozenSourceDropped = sourceDrops - MIN(sourceDroppedAtStart, sourceDrops);
            finishing = YES;
        }
        os_unfair_lock_unlock(&stateLock);
        if (applies) dispatch_source_merge_data(syncWake, 1);
    }];
}

static BOOL syncAgent(void) {
    int saved = dh_in_hook;
    dh_in_hook = 1;
    @try {
        if (!IDHSessionModeEnabled()) {
            attach(nil, 0);
            return NO;
        }
        DHLogStore *store = [DHLogStore shared];
        uint64_t sourceDrops = store.droppedEventCount;
        NSMutableArray *categories = [NSMutableArray array];
        for (NSInteger category = DHCategoryDigest; category <= DHCategoryOther; category++) {
            if (![store isPausedForCategory:category]) [categories addObject:@(category)];
        }
        os_unfair_lock_lock(&stateLock);
        NSUInteger length = MIN(pending.count, IDH_SESSION_MAX_BATCH);
        NSArray<NSDictionary *> *batch = length ? [pending subarrayWithRange:NSMakeRange(0, length)] : @[];
        uint64_t latest = nextSequence;
        uint64_t sourceDelta = finishing ? frozenSourceDropped : sourceDrops - MIN(sourceDroppedAtStart, sourceDrops);
        NSMutableDictionary *request = [@{
            @"action": @"agent_sync", @"processGeneration": DHProcessGeneration(),
            @"agentBuild": @DH_VERSION_STR, @"paused": @(store.paused), @"enabledCategories": categories,
            @"sessionId": sessionID ?: @"", @"events": batch, @"canConfirmTail": @YES,
            @"dropped": @(dropped), @"sourceDropped": @(sourceDelta), @"queuePeak": @(queuePeak),
        } mutableCopy];
        if (finishing && pending.count == length) request[@"finalSeq"] = @(latest);
        os_unfair_lock_unlock(&stateLock);
        NSDictionary *reply = IDHSessionRequest(request);
        if (![reply[@"ok"] boolValue]) return NO;
        NSString *wanted = [reply[@"sessionId"] isKindOfClass:NSString.class] ? reply[@"sessionId"] : nil;
        if (![wanted isEqualToString:request[@"sessionId"]]) {
            attach(wanted, sourceDrops);
            if ([reply[@"draining"] boolValue]) requestBoundary(store, wanted);
            return NO;
        }
        if ([reply[@"draining"] boolValue]) requestBoundary(store, wanted);

        NSNumber *lastSeq = reply[@"lastSeq"];
        if (![lastSeq isKindOfClass:NSNumber.class]) return NO;
        uint64_t acknowledged = lastSeq.unsignedLongLongValue;
        if (acknowledged > latest) return NO;
        os_unfair_lock_lock(&stateLock);
        NSUInteger count = 0;
        for (NSDictionary *event in pending) {
            if ([event[@"seq"] unsignedLongLongValue] > acknowledged) break;
            count++;
        }
        if (count) [pending removeObjectsInRange:NSMakeRange(0, count)];
        BOOL more = count && (pending.count || (finishing && !request[@"finalSeq"]));
        os_unfair_lock_unlock(&stateLock);
        return more;
    } @finally {
        dh_in_hook = saved;
    }
}

static void drain(void) {
    NSUInteger limit = IDH_SESSION_PENDING_CAPACITY / IDH_SESSION_MAX_BATCH;
    for (NSUInteger batch = 0; batch < limit; batch++) {
        @autoreleasepool {
            if (!syncAgent()) return;
        }
    }
    dispatch_source_merge_data(syncWake, 1);
}

BOOL dh_session_agent_start(void) {
    if (!IDHSessionModeEnabled()) return NO;
    dispatch_queue_t queue = dispatch_queue_create("com.iosdecrypthub.session.agent", DISPATCH_QUEUE_SERIAL);
    syncWake = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, queue);
    dispatch_source_set_event_handler(syncWake, ^{ drain(); });
    dispatch_resume(syncWake);
    syncTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(syncTimer, DISPATCH_TIME_NOW, NSEC_PER_SEC / 2, NSEC_PER_SEC / 10);
    dispatch_source_set_event_handler(syncTimer, ^{ drain(); });
    dispatch_resume(syncTimer);
    return YES;
}
#endif
