#import "idh_session_service.h"
#import "idh_session_store.h"
#import "../src/session/idh_session_ipc.h"
#import "../src/dh_shared.h"
#import <Security/Security.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>

static const NSUInteger maxRecords = 2000;
static const NSUInteger maxBytes = 2 * 1024 * 1024;
static const NSTimeInterval waitSeconds = 60;
static const NSTimeInterval recordSeconds = 300;
static const NSTimeInterval heartbeatSeconds = 5;
static const NSTimeInterval drainSeconds = 3;
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

static NSNumber *nowMs(void) {
    return @((uint64_t)(NSDate.date.timeIntervalSince1970 * 1000));
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

static NSDictionary *ended(NSDictionary *session, NSString *reason, BOOL uncertainTail) {
    NSMutableDictionary *value = [session mutableCopy];
    value[@"status"] = @"ended";
    value[@"endReason"] = reason;
    value[@"endedAtMs"] = nowMs();
    value[@"tailUnconfirmed"] = @(uncertainTail);
    return value;
}

static NSDictionary *agentReply(NSDictionary *session) {
    return @{@"ok": @YES, @"sessionId": session[@"sessionId"], @"lastSeq": session[@"lastSeq"],
             @"draining": @([session[@"status"] isEqualToString:@"closing"])};
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
    return event;
}

@implementation IDHSessionService {
    IDHSessionStore *_store;
    NSString *_managerExecutable;
    NSString *_scopePath;
    NSDictionary *_active;
    NSData *_agentAudit;
    NSMutableDictionary<NSString *, NSDictionary *> *_agents;
    NSTimeInterval _openedAt;
    NSTimeInterval _startedAt;
    NSTimeInterval _lastSeen;
    NSTimeInterval _drainUntil;
}

- (instancetype)initWithManagerExecutable:(NSString *)path scopePreferences:(NSString *)scopePath {
    self = [super init];
    if (!self) return nil;
    _managerExecutable = [path copy];
    _scopePath = [scopePath copy];
    _agents = [NSMutableDictionary new];
    _mcpStatus = @"starting";
    _store = [[IDHSessionStore alloc] initWithPath:[IDHSessionStateDirectory stringByAppendingPathComponent:@"sessions.sqlite3"]];
    NSArray *sessions = [_store sessions];
    if (!sessions) return nil;
    for (NSDictionary *session in sessions) {
        if (![session[@"status"] isEqualToString:@"ended"] &&
            ![_store save:ended(session, @"service_restarted", YES) events:@[]]) return nil;
    }
    if (![_store prune]) return nil;
    return self;
}

- (BOOL)end:(NSString *)reason uncertainTail:(BOOL)uncertain {
    if (!_active) return YES;
    if (![_store save:ended(_active, reason, uncertain) events:@[]]) return NO;
    _active = nil;
    _agentAudit = nil;
    return YES;
}

- (void)expire {
    if (!_active) return;
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    int pid = [_active[@"pid"] intValue];
    if (!scopeContains(_scopePath, _active[@"bundleId"])) [self end:@"scope_disabled" uncertainTail:pid > 0];
    else if (pid > 0 && kill(pid, 0) == -1 && errno == ESRCH) [self end:@"target_exited" uncertainTail:YES];
    else if (pid > 0 && now - _lastSeen > heartbeatSeconds) [self end:@"agent_disconnected" uncertainTail:YES];
    else if ([_active[@"status"] isEqualToString:@"closing"] && now >= _drainUntil)
        [self end:@"drain_timeout" uncertainTail:YES];
    else if ([_active[@"status"] isEqualToString:@"waiting"] && now - _openedAt >= waitSeconds)
        [self end:@"agent_timeout" uncertainTail:pid > 0];
    else if ([_active[@"status"] isEqualToString:@"observing"] && now - _startedAt >= recordSeconds)
        [self end:@"deadline" uncertainTail:YES];
}

- (NSDictionary *)synchronizeAgent:(NSDictionary *)message bundle:(NSString *)bundle pid:(pid_t)pid audit:(NSData *)audit {
    if (!IDHSessionModeEnabled() || !scopeContains(_scopePath, bundle)) return failure(@"scope_or_mode_disabled");
    NSString *generation = identifier(message[@"processGeneration"]);
    NSString *build = stringValue(message[@"agentBuild"], 40);
    NSNumber *paused = integerValue(message[@"paused"], 1);
    NSArray *categories = message[@"enabledCategories"];
    if (!generation || !build || !paused || ![categories isKindOfClass:NSArray.class] || categories.count > 9)
        return failure(@"invalid_agent_identity");
    for (id item in categories) if (!integerValue(item, 8)) return failure(@"invalid_category");
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    NSDictionary *agent = @{@"pid": @(pid), @"processGeneration": generation, @"agentBuild": build,
                            @"paused": @(paused.boolValue), @"enabledCategories": categories,
                            @"canConfirmTail": @([integerValue(message[@"canConfirmTail"], 1) boolValue])};
    if (!_agents[bundle] && _agents.count >= 32) [_agents removeObjectForKey:_agents.allKeys.firstObject];
    _agents[bundle] = @{@"info": agent, @"seen": @(now)};
    if (![_active[@"bundleId"] isEqualToString:bundle]) return @{@"ok": @YES};
    if (_agentAudit && (![_agentAudit isEqualToData:audit] ||
                        ![_active[@"processGeneration"] isEqualToString:generation])) return @{@"ok": @YES};

    NSMutableDictionary *session = [_active mutableCopy];
    [session addEntriesFromDictionary:agent];
    if (![session[@"sessionId"] isEqual:message[@"sessionId"]]) {
        if (![_store save:session events:@[]]) return failure(@"storage_error");
        _active = session;
        _agentAudit = audit;
        _lastSeen = now;
        return agentReply(session);
    }

    NSArray *incoming = message[@"events"];
    NSNumber *dropped = integerValue(message[@"dropped"], maxJSONInteger);
    NSNumber *sourceDropped = integerValue(message[@"sourceDropped"], maxJSONInteger);
    NSNumber *queuePeak = integerValue(message[@"queuePeak"] ?: @0, IDH_SESSION_PENDING_CAPACITY);
    NSNumber *finalSeq = integerValue(message[@"finalSeq"], maxJSONInteger);
    BOOL closing = [session[@"status"] isEqualToString:@"closing"];
    if (![incoming isKindOfClass:NSArray.class] || incoming.count > IDH_SESSION_MAX_BATCH || !dropped || !sourceDropped)
        return failure(@"invalid_batch");
    if (!queuePeak || (message[@"finalSeq"] && (!closing || !finalSeq))) return failure(@"invalid_tail_metadata");
    NSMutableArray *events = [NSMutableArray array];
    uint64_t last = [session[@"lastSeq"] unsignedLongLongValue], previous = 0;
    NSUInteger count = [session[@"count"] unsignedIntegerValue];
    NSUInteger bytes = [session[@"bytes"] unsignedIntegerValue];
    BOOL atLimit = NO;
    for (id item in incoming) {
        NSDictionary *event = projectEvent(item, generation);
        uint64_t seq = [event[@"seq"] unsignedLongLongValue];
        if (!event || seq <= previous) return failure(@"invalid_event");
        previous = seq;
        if (seq <= last) continue;
        NSUInteger size = [NSJSONSerialization dataWithJSONObject:event options:0 error:NULL].length;
        if (count == maxRecords || size > maxBytes - bytes) { atLimit = YES; break; }
        [events addObject:event];
        last = seq;
        count++;
        bytes += size;
    }
    BOOL starting = [session[@"status"] isEqualToString:@"waiting"];
    if (starting) {
        session[@"status"] = @"observing";
        session[@"startedAtMs"] = nowMs();
    }
    session[@"lastSeq"] = @(last);
    session[@"count"] = @(count);
    session[@"bytes"] = @(bytes);
    session[@"dropped"] = @(MAX(dropped.unsignedLongLongValue, [session[@"dropped"] unsignedLongLongValue]));
    session[@"sourceDropped"] = @(MAX(sourceDropped.unsignedLongLongValue, [session[@"sourceDropped"] unsignedLongLongValue]));
    session[@"queuePeak"] = @(MAX(queuePeak.unsignedIntegerValue, [session[@"queuePeak"] unsignedIntegerValue]));
    atLimit = atLimit || count >= maxRecords || bytes >= maxBytes;
    BOOL finished = finalSeq && !atLimit;
    if (finished) {
        uint64_t lastProduced = finalSeq.unsignedLongLongValue;
        if (last > lastProduced || count + [session[@"dropped"] unsignedLongLongValue] != lastProduced)
            return failure(@"unverified_tail");
        session[@"finalSeq"] = finalSeq;
    }
    BOOL terminal = atLimit || finished;
    NSDictionary *saved = terminal ? ended(session, finished ? @"user_ended" : @"capacity", !finished) : session;
    if (![saved isEqualToDictionary:_active] && ![_store save:saved events:events]) return failure(@"storage_error");
    _active = terminal ? nil : saved;
    _agentAudit = terminal ? nil : audit;
    if (starting) _startedAt = now;
    _lastSeen = now;
    return terminal ? @{@"ok": @YES} : agentReply(saved);
}

- (NSDictionary *)onlineAgentForBundle:(NSString *)bundle {
    NSDictionary *registration = _agents[bundle];
    if (registration && NSProcessInfo.processInfo.systemUptime - [registration[@"seen"] doubleValue] <= heartbeatSeconds &&
        scopeContains(_scopePath, bundle)) return registration[@"info"];
    return nil;
}

- (NSDictionary *)statusForBundle:(NSString *)bundle {
    NSArray *recent = [_store sessions];
    if (!recent) return failure(@"storage_error");
    NSMutableArray *sessions = [NSMutableArray array];
    for (NSDictionary *session in recent) {
        if ([session[@"bundleId"] isEqualToString:bundle]) [sessions addObject:session];
    }
    BOOL mode = IDHSessionModeEnabled();
    return @{@"ok": @YES, @"modeEnabled": @(mode), @"mcpStatus": mode ? self.mcpStatus : @"disabled",
             @"scopeEnabled": @(scopeContains(_scopePath, bundle)), @"agent": (mode ? [self onlineAgentForBundle:bundle] : nil) ?: NSNull.null,
             @"sessions": sessions};
}

- (NSDictionary *)handleLocalMessage:(NSDictionary *)message executable:(NSString *)executable pid:(pid_t)pid audit:(NSData *)audit {
    if (![integerValue(message[@"protocol"], IDH_SESSION_PROTOCOL) isEqual:@(IDH_SESSION_PROTOCOL)])
        return failure(@"unsupported_protocol");
    NSString *action = stringValue(message[@"action"], 32);
    [self expire];
    if ([action isEqualToString:@"agent_sync"]) {
        NSString *bundle = bundleForExecutable(executable);
        if (!bundle || [bundle isEqualToString:@"com.iosdecrypthub.manager"]) return failure(@"invalid_agent");
        return [self synchronizeAgent:message bundle:bundle pid:pid audit:audit];
    }
    if (![_managerExecutable isEqualToString:executable]) return failure(@"manager_required");
    if ([action isEqualToString:@"registrations"]) {
        NSMutableDictionary *online = [NSMutableDictionary new];
        if (IDHSessionModeEnabled()) {
            for (NSString *bundle in _agents) {
                NSDictionary *agent = [self onlineAgentForBundle:bundle];
                if (agent) online[bundle] = agent;
            }
        }
        return @{@"ok": @YES, @"agents": online};
    }
    if ([action isEqualToString:@"set_mode"]) {
        NSNumber *enabled = integerValue(message[@"enabled"], 1);
        if (!enabled) return failure(@"invalid_mode");
        if (enabled.boolValue) {
            if (![[NSData data] writeToFile:IDHSessionModePath options:NSDataWritingAtomic error:NULL])
                return failure(@"storage_error");
        } else {
            if (![self end:@"mode_disabled" uncertainTail:_agentAudit != nil]) return failure(@"storage_error");
            if (unlink(IDHSessionModePath.fileSystemRepresentation) && errno != ENOENT) return failure(@"storage_error");
            _pairingToken = nil;
            [_agents removeAllObjects];
        }
        return @{@"ok": @YES};
    }
    if ([action isEqualToString:@"pair"]) {
        if (!IDHSessionModeEnabled()) return failure(@"mode_disabled");
        unsigned char bytes[32];
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes) != errSecSuccess)
            return failure(@"pairing_failed");
        _pairingToken = [[NSData dataWithBytes:bytes length:sizeof(bytes)] base64EncodedStringWithOptions:0];
        return @{@"ok": @YES, @"token": _pairingToken};
    }
    if ([action isEqualToString:@"read"])
        return [self read:message[@"tool"] arguments:message[@"arguments"]];
    NSString *bundle = stringValue(message[@"bundleId"], 255);
    if (!bundle) return failure(@"invalid_bundle");
    if ([action isEqualToString:@"status"]) return [self statusForBundle:bundle];
    NSString *sessionID = identifier(message[@"sessionId"]);
    if (!sessionID) return failure(@"invalid_session");
    if ([action isEqualToString:@"start"]) {
        if (!IDHSessionModeEnabled()) return failure(@"mode_disabled");
        if (!scopeContains(_scopePath, bundle)) return failure(@"scope_disabled");
        NSDictionary *existing = [_store session:sessionID];
        if (existing) return [existing[@"bundleId"] isEqualToString:bundle] ?
            @{@"ok": @YES, @"session": existing} : failure(@"session_conflict");
        if (_active) return failure(@"active_session");
        NSDictionary *session = @{@"sessionId": sessionID, @"bundleId": bundle, @"createdAtMs": nowMs(),
                                  @"status": @"waiting", @"count": @0, @"bytes": @0, @"lastSeq": @0,
                                  @"dropped": @0, @"sourceDropped": @0, @"queuePeak": @0};
        if (![_store save:session events:@[]]) return failure(@"storage_error");
        _active = session;
        _openedAt = NSProcessInfo.processInfo.systemUptime;
        if (![_store prune]) NSLog(@"idhjd could not enforce retention; will retry at next start");
        return @{@"ok": @YES, @"session": session};
    }
    if ([action isEqualToString:@"end"]) {
        NSDictionary *session = [_store session:sessionID];
        if (![session[@"bundleId"] isEqualToString:bundle]) return failure(@"unknown_session");
        if ([_active[@"sessionId"] isEqualToString:sessionID] && ![_active[@"status"] isEqualToString:@"closing"]) {
            if (_agentAudit && [_active[@"canConfirmTail"] boolValue]) {
                NSMutableDictionary *closing = [_active mutableCopy];
                closing[@"status"] = @"closing";
                if (![_store save:closing events:@[]]) return failure(@"storage_error");
                _active = closing;
                _drainUntil = NSProcessInfo.processInfo.systemUptime + drainSeconds;
            } else if (![self end:@"user_ended" uncertainTail:_agentAudit != nil]) {
                return failure(@"storage_error");
            }
        }
        return @{@"ok": @YES};
    }
    return failure(@"unknown_action");
}

- (NSDictionary *)read:(NSString *)tool arguments:(NSDictionary *)arguments {
    if (![tool isKindOfClass:NSString.class] || ![arguments isKindOfClass:NSDictionary.class])
        return failure(@"invalid_arguments");
    if ([tool isEqualToString:@"list_sessions"]) {
        NSArray *sessions = [_store sessions];
        return sessions ? @{@"ok": @YES, @"sessions": sessions} : failure(@"storage_error");
    }
    if (![tool isEqualToString:@"get_session"] && ![tool isEqualToString:@"read_session_events"])
        return failure(@"unknown_tool");
    NSString *sessionID = identifier(arguments[@"session_id"]);
    NSDictionary *session = sessionID ? [_store session:sessionID] : nil;
    if (!session) return failure(@"unknown_session");
    if ([tool isEqualToString:@"get_session"]) return @{@"ok": @YES, @"session": session};
    NSNumber *after = integerValue(arguments[@"after_seq"] ?: @0, maxJSONInteger);
    NSNumber *limit = integerValue(arguments[@"limit"] ?: @100, 100);
    if (!after || !limit.unsignedIntegerValue) return failure(@"invalid_pagination");
    NSArray *rows = [_store eventsForSession:sessionID after:after.unsignedLongLongValue limit:limit.unsignedIntegerValue];
    if (!rows) return failure(@"storage_error");
    NSNumber *cursor = rows.lastObject[@"seq"] ?: after;
    return @{@"ok": @YES, @"session": session, @"events": rows, @"nextAfterSeq": cursor,
             @"hasMore": @([session[@"lastSeq"] unsignedLongLongValue] > cursor.unsignedLongLongValue)};
}
@end
