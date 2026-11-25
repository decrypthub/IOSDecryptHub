#if DH_DEVICE_SESSIONS
#import "dh_session_agent.h"
#import "dh_event.h"
#import "dh_health.h"
#import "log_store.h"
#import "dh_log_json.h"
#import "mcp_server.h"
#import "http_server.h"
#import "../session/idh_session_ipc.h"
#include <os/lock.h>
#include <stdatomic.h>

static dispatch_source_t syncTimer;
static dispatch_source_t syncWake;
static os_unfair_lock stateLock = OS_UNFAIR_LOCK_INIT;
static atomic_bool recording;
static NSMutableArray<NSDictionary *> *pending;
static uint64_t nextSequence;
static uint64_t dropped;
static NSUInteger queuePeak;

static NSString *clippedText(id value, NSUInteger maxChars) {
    if (![value isKindOfClass:NSString.class] || ![value length]) return nil;
    NSString *s = value;
    return s.length > maxChars ? [[s substringToIndex:maxChars] stringByAppendingString:@"…"] : s;
}

static void setRecordingEnabled(BOOL enabled) {
    os_unfair_lock_lock(&stateLock);
    if (enabled) {
        if (!pending) {
            pending = [NSMutableArray new];
            queuePeak = 0;
        }
        atomic_store(&recording, true);
    } else {
        atomic_store(&recording, false);
        pending = nil;
        queuePeak = 0;
    }
    os_unfair_lock_unlock(&stateLock);
}

void dh_session_agent_prepare(void) {
    if (IDHSessionModeEnabled()) setRecordingEnabled(YES);
}

void dh_session_record(DHLogEntry *entry, BOOL update) {
    if (!atomic_load(&recording) || entry.restoredFromJournal) return;
    BOOL wake = NO;
    os_unfair_lock_lock(&stateLock);
    if (atomic_load(&recording) && pending) {
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
            NSDictionary *fields = dh_log_entry_summary(entry);
            NSString *algo = clippedText(fields[@"algorithm"], 120);
            NSString *op = clippedText(fields[@"operation"], 60);
            NSString *detail = clippedText(fields[@"detail"], 220);
            NSString *preview = clippedText(fields[@"preview"], 220);
            NSString *pubInfo = clippedText(entry.publicKeyInfo, 220);
            if (algo) summary[@"algorithm"] = algo;
            if (op) summary[@"operation"] = op;
            if (detail) summary[@"detail"] = detail;
            if (preview) summary[@"preview"] = preview;
            if (pubInfo) summary[@"publicKeyInfo"] = pubInfo;
            if (entry.input && (entry.input.length || entry.category <= DHCategoryAsymmetric))
                summary[@"inLen"] = @(entry.input.length);
            if (entry.output && (entry.output.length || entry.category <= DHCategoryAsymmetric))
                summary[@"outLen"] = @(entry.output.length);
            if (entry.key.length) {
                summary[@"keyLen"] = @(entry.key.length);
                summary[@"keyHex"] = DHHexFromData([entry.key subdataWithRange:NSMakeRange(0, MIN(entry.key.length, 64))]);
            }
            if (entry.iv.length) {
                summary[@"ivLen"] = @(entry.iv.length);
                summary[@"ivHex"] = DHHexFromData([entry.iv subdataWithRange:NSMakeRange(0, MIN(entry.iv.length, 32))]);
            }
            if (entry.input.length)
                summary[@"inputHex"] = DHHexFromData([entry.input subdataWithRange:NSMakeRange(0, MIN(entry.input.length, 256))]);
            if (entry.output.length)
                summary[@"outputHex"] = DHHexFromData([entry.output subdataWithRange:NSMakeRange(0, MIN(entry.output.length, 256))]);
            [pending addObject:summary];
            queuePeak = MAX(queuePeak, pending.count);
            wake = (pending.count == 1 || pending.count == IDH_SESSION_MAX_BATCH);
        } else {
            dropped++;
        }
    }
    os_unfair_lock_unlock(&stateLock);
    if (wake && syncWake) dispatch_source_merge_data(syncWake, 1);
}

static BOOL syncAgent(void) {
    int saved = dh_in_hook;
    dh_in_hook = 1;
    @try {
        if (!IDHSessionModeEnabled()) {
            setRecordingEnabled(NO);
            return NO;
        }
        DHLogStore *store = [DHLogStore shared];
        NSMutableArray *categories = [NSMutableArray array];
        for (NSInteger category = DHCategoryDigest; category <= DHCategoryOther; category++) {
            if (![store isPausedForCategory:category]) [categories addObject:@(category)];
        }
        os_unfair_lock_lock(&stateLock);
        NSUInteger length = MIN(pending.count, IDH_SESSION_MAX_BATCH);
        if (!length) {
            os_unfair_lock_unlock(&stateLock);
            return NO;
        }
        NSArray<NSDictionary *> *batch = [pending subarrayWithRange:NSMakeRange(0, length)];
        uint64_t latest = nextSequence;
        NSMutableDictionary *request = [@{
            @"action": @"agent_sync", @"processGeneration": DHProcessGeneration(),
            @"agentBuild": @DH_VERSION_STR, @"paused": @(store.paused), @"enabledCategories": categories,
            @"events": batch, @"dropped": @(dropped),
            @"sourceDropped": @(store.droppedEventCount), @"queuePeak": @(queuePeak),
        } mutableCopy];
        os_unfair_lock_unlock(&stateLock);

        while (length > 1) {
            NSData *probe = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
            if (probe.length && probe.length <= IDH_SESSION_MAX_MESSAGE - 4096) break;
            length /= 2;
            request[@"events"] = [batch subarrayWithRange:NSMakeRange(0, length)];
        }

        NSDictionary *reply = IDHSessionRequest(request);
        if (![reply[@"ok"] boolValue]) {
            if ([reply[@"error"] isEqualToString:@"scope_or_mode_disabled"]) setRecordingEnabled(NO);
            return NO;
        }
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
        BOOL more = count && pending.count > 0;
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
    if (syncWake) dispatch_source_merge_data(syncWake, 1);
}

static void performCall(NSDictionary *call) {
    NSString *generation = call[@"processGeneration"];
    if (![generation isKindOfClass:NSString.class] || ![generation isEqualToString:DHProcessGeneration()]) {
        IDHSessionRequest(@{@"action": @"agent_result", @"processGeneration": DHProcessGeneration(),
                            @"id": call[@"id"] ?: @"", @"result": @{@"ok": @NO, @"error": @"stale_generation"}});
        return;
    }
    NSDictionary *message = @{@"jsonrpc": @"2.0", @"id": call[@"id"] ?: @"", @"method": @"tools/call",
                              @"params": @{@"name": call[@"name"] ?: @"", @"arguments": call[@"arguments"] ?: @{}}};
    NSDictionary *handled = [MCPServer handleMessage:message];
    NSDictionary *result = handled[@"result"];
    if (![result isKindOfClass:NSDictionary.class]) result = @{@"ok": @NO, @"error": @"no_result"};
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
    if (!encoded || encoded.length > IDH_SESSION_MAX_MESSAGE / 2)
        result = @{@"ok": @NO, @"error": @"too_large"};
    IDHSessionRequest(@{@"action": @"agent_result", @"processGeneration": DHProcessGeneration(),
                        @"id": call[@"id"] ?: @"", @"result": result});
}

static BOOL announcePresence(void) {
    int saved = dh_in_hook;
    dh_in_hook = 1;
    @try {
        NSMutableDictionary *presence = [@{@"action": @"agent_presence",
                                           @"processGeneration": DHProcessGeneration(),
                                           @"agentBuild": @DH_VERSION_STR} mutableCopy];
        uint16_t httpPort = dh_http_port();
        if (httpPort) presence[@"httpPort"] = @(httpPort);
        NSDictionary *reply = IDHSessionRequest(presence);
        NSDictionary *call = [reply[@"call"] isKindOfClass:NSDictionary.class] ? reply[@"call"] : nil;
        if (call) performCall(call);
        return [reply[@"ok"] boolValue];
    } @finally {
        dh_in_hook = saved;
    }
}

static void tick(void) {
    BOOL inScope = announcePresence();
    if (!inScope || !IDHSessionModeEnabled()) {
        setRecordingEnabled(NO);
        return;
    }
    setRecordingEnabled(YES);
    drain();
}

BOOL dh_session_agent_start(void) {
    dispatch_queue_t queue = dispatch_queue_create("com.iosdecrypthub.session.agent", DISPATCH_QUEUE_SERIAL);
    syncWake = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, queue);
    dispatch_source_set_event_handler(syncWake, ^{ drain(); });
    dispatch_resume(syncWake);
    syncTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(syncTimer, DISPATCH_TIME_NOW, NSEC_PER_SEC / 2, NSEC_PER_SEC / 10);
    dispatch_source_set_event_handler(syncTimer, ^{ tick(); });
    dispatch_resume(syncTimer);
    return IDHSessionModeEnabled();
}
#endif
