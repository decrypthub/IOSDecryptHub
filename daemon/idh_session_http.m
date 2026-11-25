#import "idh_session_http.h"
#import "idh_session_service.h"
#import "idh_device_apps.h"
#import "panel_html.h"
#import "../src/session/idh_session_ipc.h"
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static NSArray *tools(void) {
    return @[
        @{@"name": @"list_installed_apps", @"description": @"List installed apps, current injection scope, and per-app stored event summaries.",
          @"inputSchema": @{@"type": @"object", @"properties": @{}}},
        @{@"name": @"read_app_events", @"description": @"Read an app's stored events. Omit after/before to read the latest slice; pass before=oldestSeq to page older events, or after=latestSeq to poll newer events.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"bundle_id"], @"properties": @{
              @"bundle_id": @{@"type": @"string", @"description": @"App bundle identifier"},
              @"categories": @{@"type": @"array", @"items": @{@"type": @"integer", @"minimum": @0, @"maximum": @8}},
              @"after": @{@"type": @"integer", @"minimum": @0},
              @"before": @{@"type": @"integer", @"minimum": @1},
              @"limit": @{@"type": @"integer", @"minimum": @1, @"maximum": @500},
          }}},
        @{@"name": @"clear_app_events", @"description": @"Delete all stored events on the device for one app bundle.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"bundleId"], @"properties": @{
              @"bundleId": @{@"type": @"string"},
          }}},
        @{@"name": @"get_injection_scope", @"description": @"Read the enabled bundle list the loader injects into.",
          @"inputSchema": @{@"type": @"object", @"properties": @{}}},
        @{@"name": @"set_injection_scope", @"description": @"Add or remove bundle IDs from the injection scope (writes take effect on next app launch).",
          @"inputSchema": @{@"type": @"object", @"properties": @{
              @"add": @{@"type": @"array", @"items": @{@"type": @"string"}},
              @"remove": @{@"type": @"array", @"items": @{@"type": @"string"}},
          }}},
        @{@"name": @"relaunch_app", @"description": @"Kill a target app by bundle ID and reopen it so scope changes apply.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"bundleId"], @"properties": @{
              @"bundleId": @{@"type": @"string"},
          }}},
        @{@"name": @"get_process_identity",
          @"description": @"Read one live process. Multiple processes of one app are selected by processGeneration.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"bundleId"], @"properties": @{
              @"bundleId": @{@"type": @"string"},
              @"processGeneration": @{@"type": @"string"},
          }}},
    ];
}

static void sendHTTP(int fd, int code, NSString *description, NSDictionary *value);
static void sendData(int fd, NSString *type, NSData *body);

static NSString *queryValue(NSString *query, NSString *key) {
    for (NSString *part in [query componentsSeparatedByString:@"&"]) {
        NSRange split = [part rangeOfString:@"="];
        if (split.location == NSNotFound) continue;
        if ([[part substringToIndex:split.location] isEqualToString:key])
            return [part substringFromIndex:NSMaxRange(split)];
    }
    return nil;
}

static void sendBody(int fd, int code, NSString *description, NSString *type, NSData *body) {
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 %d %@\r\nContent-Length: %lu\r\nContent-Type: %@\r\n"
         "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        code, description, (unsigned long)body.length, type];
    NSData *data = [header dataUsingEncoding:NSUTF8StringEncoding];
    if (IDHSessionWriteBytes(fd, data.bytes, data.length) && body.length)
        IDHSessionWriteBytes(fd, body.bytes, body.length);
}

static void sendResult(int fd, NSDictionary *value) {
    BOOL ok = [value[@"ok"] boolValue];
    sendHTTP(fd, ok ? 200 : 400, ok ? @"OK" : @"Error", value);
}

static NSString *targetPath(NSString *target) {
    NSRange split = [target rangeOfString:@"?"];
    return split.location == NSNotFound ? target : [target substringToIndex:split.location];
}

static NSString *targetQuery(NSString *target) {
    NSRange split = [target rangeOfString:@"?"];
    return split.location == NSNotFound ? @"" : [target substringFromIndex:NSMaxRange(split)];
}

static BOOL parseToolsRoute(NSString *path, NSString **bundle, NSString **toolPath) {
    NSArray<NSString *> *parts = [path componentsSeparatedByString:@"/"];
    if (parts.count < 6 || parts.firstObject.length || ![parts[1] isEqualToString:@"api"] ||
        ![parts[2] isEqualToString:@"apps"] || ![parts[4] isEqualToString:@"tools"]) return NO;
    NSString *bundlePart = [parts[3] stringByRemovingPercentEncoding];
    NSString *tool = [[parts subarrayWithRange:NSMakeRange(5, parts.count - 5)] componentsJoinedByString:@"/"];
    if (!bundlePart.length || !tool.length) return NO;
    if (bundle) *bundle = bundlePart;
    if (toolPath) *toolPath = tool;
    return YES;
}

static BOOL allowedToolPath(NSString *toolPath, NSString *method) {
    if ([method isEqualToString:@"GET"]) {
        return [toolPath isEqualToString:@"files"] ||
               [toolPath isEqualToString:@"files/preview"] ||
               [toolPath isEqualToString:@"files/download"] ||
               [toolPath isEqualToString:@"symbols"] ||
               [toolPath isEqualToString:@"symbols/images"] ||
               [toolPath isEqualToString:@"dump/images"] ||
               [toolPath isEqualToString:@"dump/status"] ||
               [toolPath isEqualToString:@"dump/download"] ||
               [toolPath isEqualToString:@"dump/image"];
    }
    return [method isEqualToString:@"POST"] && [toolPath isEqualToString:@"dump"];
}

static int connectLoopback(uint16_t port) {
    int upstream = socket(AF_INET, SOCK_STREAM, 0);
    if (upstream < 0) return -1;
    struct timeval timeout = { .tv_sec = 20, .tv_usec = 0 };
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(upstream, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    while (connect(upstream, (struct sockaddr *)&address, sizeof(address)) < 0) {
        if (errno == EINTR) continue;
        close(upstream);
        return -1;
    }
    return upstream;
}

static void relayUpstreamResponse(int client, int upstream) {
    char bytes[16384];
    for (;;) {
        ssize_t count = recv(upstream, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        if (!IDHSessionWriteBytes(client, bytes, (size_t)count)) break;
    }
}

static void serveToolProxy(int fd, NSString *method, NSString *target, NSString *path,
                           NSDictionary<NSString *, NSString *> *headers,
                           NSMutableData *incoming, NSUInteger bodyOffset,
                           IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSString *bundle = nil;
    NSString *toolPath = nil;
    if (!parseToolsRoute(path, &bundle, &toolPath)) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (![method isEqualToString:@"GET"] && ![method isEqualToString:@"POST"]) {
        sendHTTP(fd, 405, @"Method Not Allowed", nil);
        return;
    }
    if (!allowedToolPath(toolPath, method)) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (headers[@"transfer-encoding"]) {
        sendHTTP(fd, 400, @"Bad Request", nil);
        return;
    }
    unsigned long long length = 0;
    if (headers[@"content-length"]) {
        NSScanner *scanner = [NSScanner scannerWithString:headers[@"content-length"]];
        if (![scanner scanUnsignedLongLong:&length] || !scanner.isAtEnd || length > 1024 * 1024) {
            sendHTTP(fd, 400, @"Bad Request", nil);
            return;
        }
    }
    NSMutableData *body = [NSMutableData dataWithLength:(NSUInteger)length];
    if (length) {
        NSUInteger buffered = MIN((NSUInteger)length, incoming.length - bodyOffset);
        [incoming getBytes:body.mutableBytes range:NSMakeRange(bodyOffset, buffered)];
        if (!IDHSessionReadBytes(fd, (char *)body.mutableBytes + buffered, (size_t)length - buffered)) return;
    }

    __block NSDictionary *identity;
    dispatch_sync(stateQueue, ^{
        identity = [service read:@"get_process_identity" arguments:@{@"bundleId": bundle}];
    });
    if (![identity[@"ok"] boolValue]) {
        sendResult(fd, identity);
        return;
    }
    NSNumber *portNumber = identity[@"httpPort"];
    if (![portNumber isKindOfClass:NSNumber.class] || portNumber.unsignedIntegerValue < 1024 ||
        portNumber.unsignedIntegerValue > 65535) {
        sendHTTP(fd, 503, @"Service Unavailable", @{@"ok": @NO, @"error": @"process_tools_unavailable"});
        return;
    }
    int upstream = connectLoopback((uint16_t)portNumber.unsignedIntegerValue);
    if (upstream < 0) {
        sendHTTP(fd, 503, @"Service Unavailable", @{@"ok": @NO, @"error": @"process_tools_unreachable"});
        return;
    }

    NSString *query = targetQuery(target);
    NSString *upstreamTarget = [NSString stringWithFormat:@"/api/%@%@", toolPath,
                                query.length ? [NSString stringWithFormat:@"?%@", query] : @""];
    NSMutableString *request = [NSMutableString stringWithFormat:
        @"%@ %@ HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nAccept: */*\r\nConnection: close\r\n",
        method, upstreamTarget, (unsigned)portNumber.unsignedIntegerValue];
    if (headers[@"content-type"]) [request appendFormat:@"Content-Type: %@\r\n", headers[@"content-type"]];
    if (length || [method isEqualToString:@"POST"])
        [request appendFormat:@"Content-Length: %llu\r\n", length];
    [request appendString:@"\r\n"];
    NSData *headerData = [request dataUsingEncoding:NSUTF8StringEncoding];
    BOOL sent = IDHSessionWriteBytes(upstream, headerData.bytes, headerData.length);
    if (sent && length) sent = IDHSessionWriteBytes(upstream, body.bytes, body.length);
    if (sent) relayUpstreamResponse(fd, upstream);
    close(upstream);
}

static BOOL serveSessions(int fd, NSString *target, IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSString *path = targetPath(target);
    if (![path isEqualToString:@"/api/sessions"]) return NO;
    __block NSDictionary *value;
    dispatch_sync(stateQueue, ^{ value = [service read:@"list_sessions" arguments:@{}]; });
    sendResult(fd, value);
    return YES;
}

static BOOL serveApps(int fd, NSString *target, IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSString *path = targetPath(target);
    NSString *query = targetQuery(target);
    NSArray<NSString *> *parts = [path componentsSeparatedByString:@"/"];
    if (parts.count < 3 || parts.firstObject.length || ![parts[1] isEqualToString:@"api"] ||
        ![parts[2] isEqualToString:@"apps"]) return NO;
    if (parts.count == 3) {
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{ value = [service read:@"list_installed_apps" arguments:@{}]; });
        sendResult(fd, value);
        return YES;
    }
    BOOL eventsRoute = parts.count == 5 && [parts[4] isEqualToString:@"events"];
    BOOL iconRoute = parts.count == 5 && [parts[4] isEqualToString:@"icon"];
    if (!eventsRoute && !iconRoute) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return YES;
    }
    NSString *bundle = [parts[3] stringByRemovingPercentEncoding];
    if (!bundle.length) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return YES;
    }
    if (iconRoute) {
        __block NSData *png;
        dispatch_sync(stateQueue, ^{ png = idh_app_icon(bundle); });
        if (png.length) sendData(fd, @"image/png", png);
        else sendHTTP(fd, 404, @"Not Found", nil);
        return YES;
    }
    NSString *after = queryValue(query, @"after");
    NSString *before = queryValue(query, @"before");
    NSString *limit = queryValue(query, @"limit");
    NSString *catsRaw = [queryValue(query, @"categories") stringByRemovingPercentEncoding];
    NSMutableDictionary *arguments = [@{@"bundle_id": bundle} mutableCopy];
    if (after.length) arguments[@"after"] = @([after longLongValue]);
    if (before.length) arguments[@"before"] = @([before longLongValue]);
    if (limit.length) arguments[@"limit"] = @([limit longLongValue]);
    if (catsRaw.length) {
        NSMutableArray<NSNumber *> *cats = [NSMutableArray array];
        for (NSString *tok in [catsRaw componentsSeparatedByString:@","]) {
            if (!tok.length) continue;
            NSScanner *sc = [NSScanner scannerWithString:tok];
            NSInteger c = -1;
            if (![sc scanInteger:&c] || !sc.isAtEnd || c < 0 || c > 8) {
                sendHTTP(fd, 400, @"Bad Request", @{@"ok": @NO, @"error": @"invalid_categories"});
                return YES;
            }
            [cats addObject:@(c)];
        }
        if (cats.count) arguments[@"categories"] = cats;
    }
    __block NSDictionary *value;
    dispatch_sync(stateQueue, ^{ value = [service read:@"read_app_events" arguments:arguments]; });
    sendResult(fd, value);
    return YES;
}

static void sendData(int fd, NSString *type, NSData *body) {
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nContent-Type: %@\r\n"
         "Cache-Control: private, max-age=300\r\nConnection: close\r\n\r\n",
        (unsigned long)body.length, type];
    NSData *data = [header dataUsingEncoding:NSUTF8StringEncoding];
    if (IDHSessionWriteBytes(fd, data.bytes, data.length) && body.length)
        IDHSessionWriteBytes(fd, body.bytes, body.length);
}

static void sendHTTP(int fd, int code, NSString *description, NSDictionary *value) {
    NSData *body = value ? [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL] : nil;
    NSString *challenge = code == 401 ? @"WWW-Authenticate: Bearer\r\n" : @"";
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 %d %@\r\nContent-Length: %lu\r\nContent-Type: application/json\r\n"
         "Cache-Control: no-store\r\nConnection: close\r\n%@\r\n",
        code, description, (unsigned long)body.length, challenge];
    NSData *data = [header dataUsingEncoding:NSUTF8StringEncoding];
    if (IDHSessionWriteBytes(fd, data.bytes, data.length) && body.length)
        IDHSessionWriteBytes(fd, body.bytes, body.length);
}

static NSDictionary *rpcError(id identity, NSInteger code, NSString *reason) {
    return @{@"jsonrpc": @"2.0", @"id": identity ?: NSNull.null,
             @"error": @{@"code": @(code), @"message": reason}};
}

static NSDictionary *rpc(NSDictionary *request, IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSString *method = request[@"method"];
    id identity = request[@"id"];
    if (![identity isKindOfClass:NSNumber.class] && ![identity isKindOfClass:NSString.class]) identity = nil;
    if (![request[@"jsonrpc"] isEqual:@"2.0"] || ![method isKindOfClass:NSString.class])
        return rpcError(identity, -32600, @"Invalid Request");
    NSDictionary *parameters = request[@"params"] ?: @{};
    if (![parameters isKindOfClass:NSDictionary.class]) return rpcError(identity, -32602, @"Invalid params");
    if ([method isEqualToString:@"notifications/initialized"] && !identity) return nil;
    if (!identity) return rpcError(nil, -32600, @"Request ID required");
    NSDictionary *result;
    if ([method isEqualToString:@"initialize"]) {
        NSString *protocol = [@[@"2024-11-05", @"2025-03-26", @"2025-06-18"] containsObject:parameters[@"protocolVersion"] ?: NSNull.null]
            ? parameters[@"protocolVersion"] : @"2025-03-26";
        result = @{@"protocolVersion": protocol, @"serverInfo": @{@"name": @"idhjd", @"version": @"1"},
                   @"capabilities": @{@"tools": @{}}};
    } else if ([method isEqualToString:@"ping"]) {
        result = @{};
    } else if ([method isEqualToString:@"tools/list"]) {
        result = @{@"tools": tools()};
    } else if ([method isEqualToString:@"tools/call"]) {
        __block NSDictionary *value;
        NSString *name = [parameters[@"name"] isKindOfClass:NSString.class] ? parameters[@"name"] : @"";
        dispatch_sync(stateQueue, ^{ value = [service read:name arguments:parameters[@"arguments"] ?: @{}]; });
        if ([value[@"error"] isEqualToString:@"unknown_tool"])
            value = [service forwardTool:name arguments:
                [parameters[@"arguments"] isKindOfClass:NSDictionary.class] ? parameters[@"arguments"] : @{}
                queue:stateQueue];
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
        NSString *text = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
        result = @{@"content": @[@{@"type": @"text", @"text": text ?: @"{}"}],
                   @"structuredContent": value, @"isError": @(![value[@"ok"] boolValue])};
    } else {
        return rpcError(identity, -32601, @"Method not found");
    }
    return @{@"jsonrpc": @"2.0", @"id": identity, @"result": result};
}

static void sendSettings(int fd, NSDictionary *result) {
    if ([result[@"ok"] boolValue]) sendHTTP(fd, 200, @"OK", result);
    else if ([result[@"error"] isEqualToString:@"revision_conflict"]) sendHTTP(fd, 409, @"Conflict", result);
    else if ([result[@"error"] isEqualToString:@"settings_storage_error"]) sendHTTP(fd, 500, @"Storage Error", result);
    else sendHTTP(fd, 400, @"Bad Request", result);
}

void IDHSessionHandleHTTP(int fd, IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSMutableData *incoming = [NSMutableData new];
    NSData *separator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange end = NSMakeRange(NSNotFound, 0);
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 2;
    while (end.location == NSNotFound && incoming.length < 8192 &&
           NSProcessInfo.processInfo.systemUptime < deadline) {
        char bytes[2048];
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return;
        [incoming appendBytes:bytes length:(size_t)count];
        end = [incoming rangeOfData:separator options:0 range:NSMakeRange(0, incoming.length)];
    }
    if (end.location == NSNotFound || end.location > 8192) {
        sendHTTP(fd, 400, @"Bad Request", nil);
        return;
    }
    NSString *header = [[NSString alloc] initWithData:[incoming subdataWithRange:NSMakeRange(0, end.location)]
                                             encoding:NSUTF8StringEncoding];
    NSArray<NSString *> *lines = [header componentsSeparatedByString:@"\r\n"];
    NSArray *requestLine = [lines.firstObject componentsSeparatedByString:@" "];
    if (requestLine.count != 3) {
        sendHTTP(fd, 400, @"Bad Request", nil);
        return;
    }
    NSString *method = requestLine[0];
    NSString *target = requestLine[1];
    NSString *path = targetPath(target);
    if ([method isEqualToString:@"GET"] && ([path isEqualToString:@"/"] || [path isEqualToString:@"/index.html"])) {
        NSData *page = [NSData dataWithBytes:kDHDaemonPanelHTML length:kDHDaemonPanelHTML_len];
        sendBody(fd, 200, @"OK", @"text/html; charset=utf-8", page);
        return;
    }
    if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/health"]) {
        __block NSDictionary *health;
        dispatch_sync(stateQueue, ^{ health = [service health]; });
        sendHTTP(fd, 200, @"OK", health);
        return;
    }
    BOOL sessionRead = [method isEqualToString:@"GET"] && [path isEqualToString:@"/api/sessions"];
    BOOL settingsRoute = [target isEqualToString:@"/api/session-settings"];
    BOOL settingsRead = settingsRoute && [method isEqualToString:@"GET"];
    BOOL toolsRoute = parseToolsRoute(path, nil, nil);
    BOOL appsRead = [method isEqualToString:@"GET"] && [path hasPrefix:@"/api/apps"] && !toolsRoute;
    BOOL scopeRoute = [path isEqualToString:@"/api/injection-scope"];
    BOOL scopeRead = scopeRoute && [method isEqualToString:@"GET"];
    BOOL relaunchRoute = [method isEqualToString:@"POST"] && [path isEqualToString:@"/api/apps/relaunch"];
    BOOL clearRoute = [method isEqualToString:@"POST"] && [path isEqualToString:@"/api/apps/clear"];
    if (!sessionRead && !settingsRoute && !appsRead && !scopeRoute && !relaunchRoute && !clearRoute &&
        !toolsRoute && ![path isEqualToString:@"/api/mcp"]) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (!sessionRead && !settingsRead && !appsRead && !scopeRead && !toolsRoute && ![method isEqualToString:@"POST"]) {
        sendHTTP(fd, 405, @"Method Not Allowed", nil);
        return;
    }
    NSMutableDictionary<NSString *, NSString *> *headers = [NSMutableDictionary new];
    for (NSUInteger index = 1; index < lines.count; index++) {
        NSString *line = lines[index];
        NSRange split = [line rangeOfString:@":"];
        if (split.location == NSNotFound) {
            sendHTTP(fd, 400, @"Bad Request", nil);
            return;
        }
        NSString *key = [line substringToIndex:split.location].lowercaseString;
        if (headers[key]) {
            sendHTTP(fd, 400, @"Bad Request", nil);
            return;
        }
        headers[key] = [[line substringFromIndex:NSMaxRange(split)]
                       stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    }
    if (headers[@"origin"]) {
        sendHTTP(fd, 401, @"Unauthorized", nil);
        return;
    }
    if (toolsRoute) {
        serveToolProxy(fd, method, target, path, headers, incoming, NSMaxRange(end), service, stateQueue);
        return;
    }
    if (settingsRead) {
        __block NSDictionary *snapshot;
        dispatch_sync(stateQueue, ^{ snapshot = [service settingsSnapshot]; });
        sendSettings(fd, snapshot);
        return;
    }
    if (sessionRead) {
        if (!serveSessions(fd, target, service, stateQueue)) sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (appsRead) {
        if (!serveApps(fd, target, service, stateQueue)) sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (scopeRead) {
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{ value = @{@"ok": @YES, @"scope": idh_scope_read() ?: @[]}; });
        sendResult(fd, value);
        return;
    }
    NSScanner *scanner = [NSScanner scannerWithString:headers[@"content-length"] ?: @""];
    unsigned long long length = 0;
    if (headers[@"transfer-encoding"] || ![scanner scanUnsignedLongLong:&length] || !scanner.isAtEnd ||
        !length || length > (settingsRoute ? 4096 : IDH_SESSION_MAX_MESSAGE)) {
        sendHTTP(fd, 400, @"Bad Request", nil);
        return;
    }
    NSUInteger offset = NSMaxRange(end);
    NSUInteger buffered = MIN((NSUInteger)length, incoming.length - offset);
    NSMutableData *body = [NSMutableData dataWithLength:(NSUInteger)length];
    [incoming getBytes:body.mutableBytes range:NSMakeRange(offset, buffered)];
    if (!IDHSessionReadBytes(fd, (char *)body.mutableBytes + buffered, (size_t)length - buffered)) return;
    id request = [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL];
    if (settingsRoute) {
        if (![request isKindOfClass:NSDictionary.class]) {
            sendSettings(fd, @{@"error": @"invalid_settings"});
            return;
        }
        __block NSDictionary *saved;
        dispatch_sync(stateQueue, ^{ saved = [service updateSettings:request]; });
        sendSettings(fd, saved);
        return;
    }
    if (scopeRoute || relaunchRoute || clearRoute) {
        if (![request isKindOfClass:NSDictionary.class]) {
            sendHTTP(fd, 400, @"Bad Request", nil);
            return;
        }
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{
            if (scopeRoute) {
                value = idh_scope_apply([request[@"add"] isKindOfClass:NSArray.class] ? request[@"add"] : @[],
                                        [request[@"remove"] isKindOfClass:NSArray.class] ? request[@"remove"] : @[]);
            } else if (relaunchRoute) {
                value = idh_app_relaunch(request[@"bundleId"]);
            } else {
                value = [service read:@"clear_app_events" arguments:@{@"bundleId": request[@"bundleId"] ?: @""}];
            }
        });
        sendResult(fd, value);
        return;
    }
    if (![request isKindOfClass:NSDictionary.class]) {
        sendHTTP(fd, 400, @"Bad Request", @{@"jsonrpc": @"2.0", @"id": NSNull.null,
                 @"error": @{@"code": @(-32700), @"message": @"Parse error"}});
        return;
    }
    NSDictionary *reply = rpc(request, service, stateQueue);
    if (reply) sendHTTP(fd, 200, @"OK", reply);
    else sendHTTP(fd, 202, @"Accepted", nil);
}
