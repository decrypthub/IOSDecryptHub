#import "idh_session_service.h"

@interface IDHForward : NSObject
@property (nonatomic, copy) NSString *callID;
@property (nonatomic, copy) NSString *generation;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSDictionary *arguments;
@property (nonatomic, copy) NSDictionary *result;
@property (nonatomic) BOOL delivered;
@property (nonatomic) dispatch_semaphore_t semaphore;
@end

@implementation IDHForward
@end

#import "idh_session_store.h"
#import "idh_device_apps.h"
#import "../src/session/idh_session_ipc.h"
#import "../src/dh_shared.h"
#import <Security/Security.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>

static const NSUInteger defaultMaxRecords = 2000;
static const NSUInteger defaultMaxBytes = 2 * 1024 * 1024;
static const NSTimeInterval defaultRecordSeconds = 300;
static const NSUInteger maxStoredEventsPerApp = 20000;
static const NSTimeInterval heartbeatSeconds = 5;
static const uint64_t maxJSONInteger = 9007199254740991ULL;

static NSString *stringValue(id value, NSUInteger maximum) {
    return [value isKindOfClass:NSString.class] && [value length] && [value length] <= maximum ? value : nil;
}

static NSString *identifier(id value) {
    NSString *text = stringValue(value, 36);
    return text && [[NSUUID alloc] initWithUUIDString:text] ? text.lowercaseString : nil;
}

static NSNumber *integerValue(id value, uint64_t maximum) {
    if (![value isKindOfClass:NSNumber.class]) return nil;
    double number = [value doubleValue];
    return number >= 0 && number <= maximum && floor(number) == number ? @([value unsignedLongLongValue]) : nil;
}

static NSDictionary *failure(NSString *reason) {
    return @{@"ok": @NO, @"error": reason};
}

static NSDictionary *defaultLimits(void) {
    return @{@"maxRecords": @(defaultMaxRecords), @"maxBytes": @(defaultMaxBytes), @"recordSeconds": @((NSUInteger)defaultRecordSeconds)};
}

static NSDictionary *mergeLimits(id changes, NSDictionary *current) {
    if (![changes isKindOfClass:NSDictionary.class] || ![changes count]) return nil;
    NSDictionary *ceilings = defaultLimits();
    NSMutableDictionary *merged = [current mutableCopy];
    for (NSString *key in changes) {
        NSNumber *ceiling = ceilings[key];
        id raw = changes[key];
        if (!ceiling || ![raw isKindOfClass:NSNumber.class] ||
            CFGetTypeID((__bridge CFTypeRef)raw) == CFBooleanGetTypeID()) return nil;
        NSNumber *value = integerValue(raw, ceiling.unsignedLongLongValue);
        if (value.unsignedLongLongValue < ([key isEqualToString:@"maxBytes"] ? 512 : 1)) return nil;
        merged[key] = value;
    }
    return [merged copy];
}

static BOOL scopeContains(NSString *scopePath, NSString *bundle) {
    NSArray *bundles = [NSDictionary dictionaryWithContentsOfFile:scopePath][DH_KEY_BUNDLES];
    return [bundles isKindOfClass:NSArray.class] && [bundles containsObject:bundle];
}

static NSString *bundleForExecutable(NSString *executable) {
    NSString *directory = executable.stringByDeletingLastPathComponent;
    if (![directory.pathExtension isEqualToString:@"app"]) return nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[directory stringByAppendingPathComponent:@"Info.plist"]];
    if (![executable.lastPathComponent isEqual:info[@"CFBundleExecutable"]]) return nil;
    return stringValue(info[@"CFBundleIdentifier"], 255);
}

static NSDictionary *projectEvent(id value, NSString *generation) {
    if (![value isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *input = value;
    NSNumber *seq = integerValue(input[@"seq"], maxJSONInteger);
    NSNumber *sourceSeq = integerValue(input[@"sourceSeq"], maxJSONInteger);
    NSNumber *time = integerValue(input[@"timeMs"], maxJSONInteger);
    NSNumber *category = integerValue(input[@"category"], 8);
    NSNumber *update = integerValue(input[@"update"], 1);
    if (!seq.unsignedLongLongValue || !sourceSeq || !time || !category || !update) return nil;
    NSMutableDictionary *event = [@{@"seq": seq, @"sourceSeq": sourceSeq, @"timeMs": time,
                                    @"category": category, @"update": @(update.boolValue)} mutableCopy];
    if ([@[@"crypto", @"network", @"observation", @"function"] containsObject:input[@"kind"] ?: NSNull.null])
        event[@"kind"] = input[@"kind"];
    if ([@[@"entry", @"leave", @"complete", @"aborted"] containsObject:input[@"phase"] ?: NSNull.null])
        event[@"phase"] = input[@"phase"];
    for (NSString *key in @[@"callId", @"parentCallId", @"asyncTaskId"]) {
        NSString *text = stringValue(input[key], 96);
        NSString *prefix = [generation stringByAppendingString:[key isEqualToString:@"asyncTaskId"] ? @":async:" : @":"];
        if (![text hasPrefix:prefix] || text.length == prefix.length) continue;
        NSString *suffix = [text substringFromIndex:prefix.length];
        if ([suffix rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location == NSNotFound)
            event[key] = text;
    }
    NSString *algo = stringValue(input[@"algorithm"], 128);
    if (algo) event[@"algorithm"] = algo;
    NSString *op = stringValue(input[@"operation"], 64);
    if (op) event[@"operation"] = op;
    for (NSString *key in @[@"detail", @"preview", @"publicKeyInfo"]) {
        NSString *text = stringValue(input[key], 240);
        if (text) event[key] = text;
    }
    for (NSString *key in @[@"inputHex", @"outputHex"]) {
        NSString *text = stringValue(input[key], 512);
        if (text) event[key] = text;
    }
    NSString *keyHex = stringValue(input[@"keyHex"], 128);
    if (keyHex) event[@"keyHex"] = keyHex;
    NSString *ivHex = stringValue(input[@"ivHex"], 64);
    if (ivHex) event[@"ivHex"] = ivHex;
    for (NSString *key in @[@"inLen", @"outLen", @"keyLen", @"ivLen"]) {
        NSNumber *count = integerValue(input[key], maxJSONInteger);
        if (count) event[key] = count;
    }
    return event;
}

@implementation IDHSessionService {
    IDHSessionStore *_store;
    NSString *_managerExecutable;
    NSString *_scopePath;
    NSString *_settingsPath;
    NSString *_settingsRevision;
    NSDictionary *_sessionLimits;
    BOOL _settingsReadable;
    NSMutableDictionary<NSString *, NSNumber *> *_lastAckByGeneration;
    NSMutableOrderedSet<NSString *> *_ackOrder;
    NSMutableDictionary<NSString *, NSDictionary *> *_agents;
    NSMutableDictionary<NSString *, NSDictionary *> *_presence;
    NSMutableDictionary<NSString *, NSDictionary *> *_replaced;
    NSMutableDictionary<NSString *, IDHForward *> *_forwards;
}

- (instancetype)initWithManagerExecutable:(NSString *)path scopePreferences:(NSString *)scopePath {
    self = [super init];
    if (!self) return nil;
    _managerExecutable = [path copy];
    _scopePath = [scopePath copy];
    _lastAckByGeneration = [NSMutableDictionary new];
    _ackOrder = [NSMutableOrderedSet new];
    _agents = [NSMutableDictionary new];
    _presence = [NSMutableDictionary new];
    _replaced = [NSMutableDictionary new];
    _forwards = [NSMutableDictionary new];
    _mcpStatus = @"starting";
    _settingsPath = [IDHSessionStateDirectory stringByAppendingPathComponent:@"session-settings.json"];
    _settingsRevision = @"0";
    _sessionLimits = defaultLimits();
    NSError *settingsError = nil;
    NSData *settings = [NSData dataWithContentsOfFile:_settingsPath options:0 error:&settingsError];
    if (settings) {
        id saved = [NSJSONSerialization JSONObjectWithData:settings options:0 error:NULL];
        if ([saved isKindOfClass:NSDictionary.class]) {
            NSString *revision = identifier(saved[@"revision"]);
            NSDictionary *limits = mergeLimits(saved[@"deviceSession"], _sessionLimits);
            if (revision && limits) {
                _settingsRevision = revision;
                _sessionLimits = limits;
                _settingsReadable = YES;
            }
        }
    } else {
        _settingsReadable = [settingsError.domain isEqualToString:NSCocoaErrorDomain] &&
                            settingsError.code == NSFileReadNoSuchFileError;
    }
    if (!_settingsReadable) NSLog(@"idhjd: saved settings could not be loaded");
    _store = [[IDHSessionStore alloc] initWithPath:[IDHSessionStateDirectory stringByAppendingPathComponent:@"sessions.sqlite3"]];
    if (!_store) return nil;
    return self;
}

- (NSDictionary *)settingsSnapshot {
    if (!_settingsReadable) return failure(@"settings_storage_error");
    return @{@"ok": @YES, @"revision": _settingsRevision, @"deviceSession": _sessionLimits};
}

- (NSDictionary *)updateSettings:(NSDictionary *)request {
    if (!_settingsReadable) return failure(@"settings_storage_error");
    NSString *expected = stringValue(request[@"revision"], 36);
    if (!expected || request.count != 2) return failure(@"invalid_settings");
    if (![_settingsRevision isEqualToString:expected]) return failure(@"revision_conflict");
    NSDictionary *limits = mergeLimits(request[@"deviceSession"], _sessionLimits);
    if (!limits) return failure(@"invalid_settings");
    if ([_sessionLimits isEqualToDictionary:limits]) return [self settingsSnapshot];
    NSString *revision = NSUUID.UUID.UUIDString.lowercaseString;
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"revision": revision, @"deviceSession": limits}
                                                  options:0 error:NULL];
    if (!data || ![data writeToFile:_settingsPath options:NSDataWritingAtomic error:NULL])
        return failure(@"settings_storage_error");
    _settingsRevision = revision;
    _sessionLimits = limits;
    return [self settingsSnapshot];
}

- (void)expirePresence {
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    for (NSString *generation in [_replaced.allKeys copy]) {
        if (now >= [_replaced[generation][@"until"] doubleValue]) [_replaced removeObjectForKey:generation];
    }
    NSMutableArray<NSString *> *stale = [NSMutableArray new];
    for (NSString *generation in _presence) {
        NSDictionary *entry = _presence[generation];
        pid_t pid = [entry[@"pid"] intValue];
        BOOL exited = pid > 1 && kill(pid, 0) == -1 && errno == ESRCH;
        BOOL quiet = now - [entry[@"seen"] doubleValue] > heartbeatSeconds;
        if (exited || quiet || !scopeContains(_scopePath, entry[@"bundleId"])) [stale addObject:generation];
    }
    [_presence removeObjectsForKeys:stale];
}

- (void)expire {
    [self expirePresence];
}

- (NSDictionary *)notePresence:(NSDictionary *)message bundle:(NSString *)bundle pid:(pid_t)pid {
    if (!scopeContains(_scopePath, bundle)) return failure(@"scope_disabled");
    NSString *generation = identifier(message[@"processGeneration"]);
    NSString *build = stringValue(message[@"agentBuild"], 40);
    if (!generation || !build || pid <= 1) return failure(@"invalid_agent_identity");
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    NSMutableArray<NSString *> *replaced = [NSMutableArray new];
    for (NSString *existing in _presence) {
        NSDictionary *old = _presence[existing];
        if ([old[@"pid"] intValue] == pid && ![existing isEqualToString:generation]) {
            _replaced[existing] = @{@"pid": @(pid), @"until": @(now + heartbeatSeconds)};
            [replaced addObject:existing];
        }
    }
    [_presence removeObjectsForKeys:replaced];
    if (!_presence[generation] && _presence.count >= 32) {
        NSString *oldest = nil;
        for (NSString *existing in _presence) {
            if (!oldest || [_presence[existing][@"seen"] doubleValue] < [_presence[oldest][@"seen"] doubleValue])
                oldest = existing;
        }
        if (oldest) [_presence removeObjectForKey:oldest];
    }
    NSDictionary *agentInfo = @{@"bundleId": bundle, @"pid": @(pid),
                                @"processGeneration": generation, @"agentBuild": build, @"seen": @(now)};
    _presence[generation] = agentInfo;
    if (!_agents[bundle] && _agents.count >= 32) [_agents removeObjectForKey:_agents.allKeys.firstObject];
    _agents[bundle] = @{@"info": agentInfo, @"seen": @(now)};
    return @{@"ok": @YES};
}

- (NSArray<NSDictionary *> *)liveProcessesForBundle:(NSString *)bundle {
    NSMutableArray *live = [NSMutableArray new];
    for (NSDictionary *entry in _presence.allValues)
        if ([entry[@"bundleId"] isEqualToString:bundle]) [live addObject:entry];
    return live;
}

- (NSDictionary *)processIdentity:(NSDictionary *)arguments {
    [self expirePresence];
    NSString *bundle = stringValue(arguments[@"bundleId"], 255);
    if (!bundle) return failure(@"invalid_arguments");
    NSString *generation = nil;
    if (arguments[@"processGeneration"]) {
        generation = identifier(arguments[@"processGeneration"]);
        if (!generation) return failure(@"invalid_arguments");
    }
    NSArray<NSDictionary *> *live = [self liveProcessesForBundle:bundle];
    NSDictionary *entry = nil;
    if (!generation) {
        if (live.count == 1) entry = live[0];
        else if (live.count == 0) return failure(@"not_online");
        else return failure(@"process_generation_required");
    } else {
        entry = _presence[generation];
        if (entry && ![entry[@"bundleId"] isEqualToString:bundle]) entry = nil;
    }
    if (!entry) {
        NSDictionary *replaced = generation ? _replaced[generation] : nil;
        if (replaced && NSProcessInfo.processInfo.systemUptime < [replaced[@"until"] doubleValue])
            return failure(@"pid_reused");
        return live.count ? failure(@"stale_generation") : failure(@"not_online");
    }
    pid_t pid = [entry[@"pid"] intValue];
    if (pid > 1 && kill(pid, 0) == -1 && errno == ESRCH) {
        [_presence removeObjectForKey:entry[@"processGeneration"]];
        return failure(@"not_online");
    }
    for (NSDictionary *other in _presence.allValues) {
        if ([other[@"pid"] intValue] == pid &&
            ![other[@"processGeneration"] isEqualToString:entry[@"processGeneration"]])
            return failure(@"pid_reused");
    }
    return @{@"ok": @YES, @"bundleId": bundle, @"pid": @(pid),
             @"processGeneration": entry[@"processGeneration"], @"agentBuild": entry[@"agentBuild"] ?: @""};
}

- (NSDictionary *)beginForwardLocked:(NSString *)name arguments:(NSDictionary *)arguments {
    if (![name isKindOfClass:NSString.class] || !name.length || name.length > 64) return failure(@"invalid_arguments");
    NSDictionary *identity = [self processIdentity:arguments];
    if (![identity[@"ok"] boolValue]) return identity;
    NSString *generation = identity[@"processGeneration"];
    if (_forwards[generation]) return failure(@"busy");
    NSMutableDictionary *forwarded = [arguments mutableCopy] ?: [NSMutableDictionary new];
    [forwarded removeObjectForKey:@"bundleId"];
    [forwarded removeObjectForKey:@"processGeneration"];
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:forwarded options:0 error:NULL];
    if (!encoded || encoded.length > IDH_SESSION_MAX_MESSAGE / 2) return failure(@"too_large");
    IDHForward *call = [IDHForward new];
    call.callID = [NSUUID UUID].UUIDString.lowercaseString;
    call.generation = generation;
    call.name = name;
    call.arguments = forwarded;
    call.semaphore = dispatch_semaphore_create(0);
    _forwards[generation] = call;
    return @{@"ok": @YES, @"generation": generation};
}

- (NSDictionary *)pendingCallForGeneration:(NSString *)generation {
    IDHForward *call = _forwards[generation];
    if (!call || call.delivered) return nil;
    call.delivered = YES;
    return @{@"id": call.callID, @"name": call.name, @"arguments": call.arguments ?: @{},
             @"processGeneration": generation};
}

- (void)completeForward:(NSString *)generation callID:(NSString *)callID result:(NSDictionary *)result {
    IDHForward *call = _forwards[generation];
    if (!call || ![call.callID isEqualToString:callID] || call.result) return;
    call.result = result;
    dispatch_semaphore_signal(call.semaphore);
}

- (NSDictionary *)forwardTool:(NSString *)name arguments:(NSDictionary *)arguments queue:(dispatch_queue_t)queue {
    __block NSDictionary *begun;
    __block IDHForward *call;
    dispatch_sync(queue, ^{
        begun = [self beginForwardLocked:name arguments:arguments];
        if ([begun[@"ok"] boolValue]) call = _forwards[begun[@"generation"]];
    });
    if (![begun[@"ok"] boolValue]) return begun;
    long wait = dispatch_semaphore_wait(call.semaphore, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    __block NSDictionary *result;
    dispatch_sync(queue, ^{
        if (_forwards[call.generation] == call) [_forwards removeObjectForKey:call.generation];
        result = wait == 0 && call.result ? call.result : failure(@"agent_timeout");
    });
    return result;
}

- (NSDictionary *)health {
    [self expirePresence];
    NSArray *entries = [_presence.allValues sortedArrayUsingDescriptors:@[
        [NSSortDescriptor sortDescriptorWithKey:@"bundleId" ascending:YES],
        [NSSortDescriptor sortDescriptorWithKey:@"pid" ascending:YES],
    ]];
    NSMutableArray *apps = [NSMutableArray new];
    for (NSDictionary *entry in entries) {
        [apps addObject:@{@"bundleId": entry[@"bundleId"], @"pid": entry[@"pid"],
                          @"processGeneration": entry[@"processGeneration"]}];
    }
    return @{@"ok": @YES, @"service": @"idhjd", @"version": @1, @"apps": apps};
}

// 以 App 为单位直接接收事件批次：按 processGeneration 幂等去重后直接入库，多 App 并发互不抢锁。
- (NSDictionary *)synchronizeAgent:(NSDictionary *)message bundle:(NSString *)bundle pid:(pid_t)pid {
    if (!IDHSessionModeEnabled() || !scopeContains(_scopePath, bundle)) return failure(@"scope_or_mode_disabled");
    NSString *generation = identifier(message[@"processGeneration"]);
    NSString *build = stringValue(message[@"agentBuild"], 40);
    NSNumber *paused = integerValue(message[@"paused"], 1);
    NSArray *categories = message[@"enabledCategories"];
    if (!generation || !build || !paused || ![categories isKindOfClass:NSArray.class] || categories.count > 9)
        return failure(@"invalid_agent_identity");
    for (id item in categories) if (!integerValue(item, 8)) return failure(@"invalid_category");

    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    NSDictionary *agent = @{@"bundleId": bundle, @"pid": @(pid), @"processGeneration": generation,
                            @"agentBuild": build, @"paused": @(paused.boolValue), @"enabledCategories": categories};
    if (!_agents[bundle] && _agents.count >= 32) [_agents removeObjectForKey:_agents.allKeys.firstObject];
    _agents[bundle] = @{@"info": agent, @"seen": @(now)};

    NSArray *incoming = message[@"events"];
    if (![incoming isKindOfClass:NSArray.class] || incoming.count > IDH_SESSION_MAX_BATCH)
        return failure(@"invalid_batch");

    uint64_t acked = [_lastAckByGeneration[generation] unsignedLongLongValue];
    uint64_t previous = 0;
    NSMutableArray<NSDictionary *> *accepted = [NSMutableArray array];
    for (id item in incoming) {
        NSDictionary *event = projectEvent(item, generation);
        uint64_t seq = [event[@"seq"] unsignedLongLongValue];
        if (!event || seq <= previous) return failure(@"invalid_event");
        previous = seq;
        if (seq <= acked) continue;
        [accepted addObject:event];
        acked = seq;
    }

    if (accepted.count && ![_store appendEvents:accepted forBundle:bundle maxPerApp:maxStoredEventsPerApp])
        return failure(@"storage_error");

    if (![_ackOrder containsObject:generation]) {
        if (_ackOrder.count >= 128) {
            NSString *evicted = _ackOrder.firstObject;
            [_ackOrder removeObjectAtIndex:0];
            [_lastAckByGeneration removeObjectForKey:evicted];
        }
        [_ackOrder addObject:generation];
    }
    _lastAckByGeneration[generation] = @(acked);
    return @{@"ok": @YES, @"lastSeq": @(acked)};
}

- (NSDictionary *)onlineAgentForBundle:(NSString *)bundle {
    [self expirePresence];
    NSArray<NSDictionary *> *live = [self liveProcessesForBundle:bundle];
    if (live.count && scopeContains(_scopePath, bundle)) return live.firstObject;
    NSDictionary *registration = _agents[bundle];
    if (registration && NSProcessInfo.processInfo.systemUptime - [registration[@"seen"] doubleValue] <= heartbeatSeconds &&
        scopeContains(_scopePath, bundle)) return registration[@"info"];
    return nil;
}

- (NSArray<NSDictionary *> *)enrichedAppSummaries {
    [self expirePresence];
    NSArray<NSDictionary *> *summaries = [_store appSummaries];
    if (!summaries) return nil;
    NSMutableArray<NSDictionary *> *out = [NSMutableArray arrayWithCapacity:summaries.count];
    for (NSDictionary *item in summaries) {
        NSMutableDictionary *row = [item mutableCopy];
        NSString *bundle = item[@"bundleId"];
        NSDictionary *live = [self liveProcessesForBundle:bundle].firstObject;
        row[@"running"] = @(live != nil);
        if (live[@"pid"]) row[@"pid"] = live[@"pid"];
        if (live[@"processGeneration"]) row[@"processGeneration"] = live[@"processGeneration"];
        [out addObject:row];
    }
    return out;
}

- (NSDictionary *)statusForBundle:(NSString *)bundle {
    NSDictionary *summary = [_store appSummaryForBundle:bundle];
    BOOL mode = IDHSessionModeEnabled();
    return @{@"ok": @YES, @"modeEnabled": @(mode), @"mcpStatus": self.mcpStatus,
             @"scopeEnabled": @(scopeContains(_scopePath, bundle)),
             @"agent": (mode ? [self onlineAgentForBundle:bundle] : nil) ?: NSNull.null,
             @"settings": [self settingsSnapshot],
             @"summary": summary, @"sessions": @[]};
}

- (NSDictionary *)handleLocalMessage:(NSDictionary *)message executable:(NSString *)executable pid:(pid_t)pid audit:(__unused NSData *)audit {
    if (![integerValue(message[@"protocol"], IDH_SESSION_PROTOCOL) isEqual:@(IDH_SESSION_PROTOCOL)])
        return failure(@"unsupported_protocol");
    NSString *action = stringValue(message[@"action"], 32);
    [self expire];
    if ([action isEqualToString:@"agent_sync"]) {
        NSString *bundle = bundleForExecutable(executable);
        if (!bundle || [bundle isEqualToString:@"com.iosdecrypthub.manager"]) return failure(@"invalid_agent");
        return [self synchronizeAgent:message bundle:bundle pid:pid];
    }
    if ([action isEqualToString:@"agent_presence"]) {
        NSString *bundle = bundleForExecutable(executable);
        if (!bundle || [bundle isEqualToString:@"com.iosdecrypthub.manager"]) return failure(@"invalid_agent");
        NSDictionary *noted = [self notePresence:message bundle:bundle pid:pid];
        if (![noted[@"ok"] boolValue]) return noted;
        NSMutableDictionary *reply = [noted mutableCopy];
        NSString *generation = identifier(message[@"processGeneration"]);
        NSDictionary *call = [self pendingCallForGeneration:generation];
        if (call) reply[@"call"] = call;
        return reply;
    }
    if ([action isEqualToString:@"agent_result"]) {
        NSString *bundle = bundleForExecutable(executable);
        NSString *generation = identifier(message[@"processGeneration"]);
        NSString *callID = identifier(message[@"id"]);
        NSDictionary *entry = generation ? _presence[generation] : nil;
        if (!bundle || !generation || !callID || !entry || [entry[@"pid"] intValue] != pid ||
            ![entry[@"bundleId"] isEqualToString:bundle]) return failure(@"stale_generation");
        NSDictionary *result = [message[@"result"] isKindOfClass:NSDictionary.class] ? message[@"result"] : failure(@"invalid_result");
        [self completeForward:generation callID:callID result:result];
        return @{@"ok": @YES};
    }
    if (![_managerExecutable isEqualToString:executable]) return failure(@"manager_required");
    if ([action isEqualToString:@"registrations"]) {
        NSMutableDictionary *online = [NSMutableDictionary new];
        if (IDHSessionModeEnabled()) {
            for (NSDictionary *entry in _presence.allValues) {
                NSString *bundle = entry[@"bundleId"];
                if (bundle && scopeContains(_scopePath, bundle)) online[bundle] = entry;
            }
            for (NSString *bundle in _agents) {
                if (!online[bundle]) {
                    NSDictionary *agent = [self onlineAgentForBundle:bundle];
                    if (agent) online[bundle] = agent;
                }
            }
        }
        return @{@"ok": @YES, @"agents": online, @"modeEnabled": @(IDHSessionModeEnabled()),
                 @"remoteListen": @(access(IDHSessionRemotePath.fileSystemRepresentation, F_OK) == 0),
                 @"mcpStatus": self.mcpStatus};
    }
    if ([action isEqualToString:@"set_remote_listen"]) {
        NSNumber *enabled = integerValue(message[@"enabled"], 1);
        if (!enabled) return failure(@"invalid_mode");
        const char *path = IDHSessionRemotePath.fileSystemRepresentation;
        if (enabled.boolValue) {
            if (![[NSData data] writeToFile:IDHSessionRemotePath options:NSDataWritingAtomic error:NULL])
                return failure(@"storage_error");
        } else if (unlink(path) && errno != ENOENT) {
            return failure(@"storage_error");
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{ exit(0); });
        return @{@"ok": @YES, @"remoteListen": enabled, @"restarting": @YES};
    }
    if ([action isEqualToString:@"session_settings"]) {
        NSDictionary *settings = message[@"settings"];
        if (![settings isKindOfClass:NSDictionary.class]) return failure(@"invalid_settings");
        return [self updateSettings:settings];
    }
    if ([action isEqualToString:@"set_mode"]) {
        NSNumber *enabled = integerValue(message[@"enabled"], 1);
        if (!enabled) return failure(@"invalid_mode");
        if (enabled.boolValue) {
            if (![[NSData data] writeToFile:IDHSessionModePath options:NSDataWritingAtomic error:NULL])
                return failure(@"storage_error");
        } else {
            if (unlink(IDHSessionModePath.fileSystemRepresentation) && errno != ENOENT) return failure(@"storage_error");
            [_agents removeAllObjects];
        }
        return @{@"ok": @YES};
    }
    if ([action isEqualToString:@"read"])
        return [self read:message[@"tool"] arguments:message[@"arguments"]];
    NSString *bundle = stringValue(message[@"bundleId"], 255);
    if (!bundle) return failure(@"invalid_bundle");
    if ([action isEqualToString:@"status"]) return [self statusForBundle:bundle];
    return failure(@"unknown_action");
}

- (NSDictionary *)read:(NSString *)tool arguments:(NSDictionary *)arguments {
    if (![tool isKindOfClass:NSString.class] || ![arguments isKindOfClass:NSDictionary.class])
        return failure(@"invalid_arguments");
    if ([tool isEqualToString:@"list_installed_apps"]) {
        NSMutableDictionary *base = [idh_apps_list() mutableCopy];
        NSArray *recorded = [self enrichedAppSummaries];
        if (recorded) base[@"recorded"] = recorded;
        return base;
    }
    if ([tool isEqualToString:@"list_sessions"]) {
        NSArray<NSDictionary *> *recorded = [self enrichedAppSummaries];
        if (!recorded) return failure(@"storage_error");
        NSMutableArray *items = [NSMutableArray arrayWithCapacity:recorded.count];
        for (NSDictionary *app in recorded) {
            NSMutableDictionary *entry = [@{
                @"sessionId": app[@"bundleId"],
                @"bundleId": app[@"bundleId"],
                @"status": [app[@"running"] boolValue] ? @"observing" : @"idle",
                @"count": app[@"count"] ?: @0,
                @"lastSeq": app[@"lastSeq"] ?: @0,
                @"createdAtMs": app[@"updatedAtMs"] ?: @0,
                @"byCategory": app[@"byCategory"] ?: @[@0,@0,@0,@0,@0,@0,@0,@0,@0],
            } mutableCopy];
            if (app[@"pid"]) entry[@"pid"] = app[@"pid"];
            if (app[@"processGeneration"]) entry[@"processGeneration"] = app[@"processGeneration"];
            [items addObject:entry];
        }
        return @{@"ok": @YES, @"sessions": items};
    }
    if ([tool isEqualToString:@"get_injection_scope"])
        return @{@"ok": @YES, @"scope": idh_scope_read() ?: @[]};
    if ([tool isEqualToString:@"set_injection_scope"]) {
        id addList = arguments[@"add"];
        id removeList = arguments[@"remove"];
        return idh_scope_apply([addList isKindOfClass:NSArray.class] ? addList : @[],
                               [removeList isKindOfClass:NSArray.class] ? removeList : @[]);
    }
    if ([tool isEqualToString:@"relaunch_app"]) return idh_app_relaunch(arguments[@"bundleId"]);
    if ([tool isEqualToString:@"clear_app_events"]) {
        NSString *bundle = stringValue(arguments[@"bundleId"] ?: arguments[@"bundle_id"], 255);
        if (!bundle) return failure(@"invalid_arguments");
        NSDictionary *cleared = [_store clearEventsForBundle:bundle];
        return cleared ?: failure(@"storage_error");
    }
    if ([tool isEqualToString:@"read_app_events"]) {
        NSString *bundle = stringValue(arguments[@"bundle_id"] ?: arguments[@"bundleId"], 255);
        if (!bundle) return failure(@"invalid_arguments");
        NSNumber *limit = integerValue(arguments[@"limit"] ?: @150, 500);
        if (!limit.unsignedIntegerValue) return failure(@"invalid_pagination");
        NSNumber *after = nil, *before = nil;
        if (arguments[@"after"] != nil) {
            after = integerValue(arguments[@"after"], maxJSONInteger);
            if (!after) return failure(@"invalid_pagination");
        }
        if (arguments[@"before"] != nil) {
            before = integerValue(arguments[@"before"], maxJSONInteger);
            if (!before || !before.unsignedLongLongValue) return failure(@"invalid_pagination");
        }
        NSMutableArray<NSNumber *> *cats = nil;
        if ([arguments[@"categories"] isKindOfClass:NSArray.class]) {
            cats = [NSMutableArray array];
            for (id item in arguments[@"categories"]) {
                NSNumber *c = integerValue(item, 8);
                if (!c) return failure(@"invalid_arguments");
                [cats addObject:c];
            }
        }
        NSDictionary *page = [_store queryEventsForBundle:bundle categories:cats
                                                    after:after before:before limit:limit.unsignedIntegerValue];
        return page ?: failure(@"storage_error");
    }
    return failure(@"unknown_tool");
}
@end
