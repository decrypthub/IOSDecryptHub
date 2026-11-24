#import "idh_session_http.h"
#import "idh_session_service.h"
#import "idh_device_apps.h"
#import "panel_html.h"
#import "../src/session/idh_session_ipc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>

static void sendData(int fd, NSString *type, NSData *body);

static BOOL processIdentityCall(NSDictionary *request) {
    if (![request[@"method"] isEqualToString:@"tools/call"]) return NO;
    NSDictionary *parameters = request[@"params"];
    return [parameters isKindOfClass:NSDictionary.class] &&
        [parameters[@"name"] isEqualToString:@"get_process_identity"];
}

static NSArray *tools(void) {
    NSDictionary *identity = @{@"type": @"string", @"description": @"Session ID returned by list_sessions"};
    return @[
        @{@"name": @"list_sessions", @"description": @"List recent device observation sessions.",
          @"inputSchema": @{@"type": @"object", @"properties": @{}}},
        @{@"name": @"get_session", @"description": @"Read a session and its completion and loss status.",
          @"inputSchema": @{@"type": @"object", @"properties": @{@"session_id": identity}, @"required": @[@"session_id"]}},
        @{@"name": @"read_session_events", @"description": @"Page through retained event summaries in ascending session sequence.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"session_id"], @"properties": @{
              @"session_id": identity, @"after_seq": @{@"type": @"integer", @"minimum": @0},
              @"limit": @{@"type": @"integer", @"minimum": @1, @"maximum": @100},
          }}},
        @{@"name": @"list_installed_apps", @"description": @"List installed apps with running state and the current injection scope.",
          @"inputSchema": @{@"type": @"object", @"properties": @{}}},
        @{@"name": @"get_injection_scope", @"description": @"Read the enabled bundle list the loader injects into.",
          @"inputSchema": @{@"type": @"object", @"properties": @{}}},
        @{@"name": @"set_injection_scope", @"description": @"Add or remove bundle IDs from the injection scope (writes take effect on next app launch).",
          @"inputSchema": @{@"type": @"object", @"properties": @{
              @"add": @{@"type": @"array", @"items": @{@"type": @"string"}},
              @"remove": @{@"type": @"array", @"items": @{@"type": @"string"}},
          }}},
        @{@"name": @"read_app_events", @"description": @"Page through one app's merged event timeline across all its sessions.",
          @"inputSchema": @{@"type": @"object", @"required": @[@"bundle_id"], @"properties": @{
              @"bundle_id": @{@"type": @"string", @"description": @"App bundle identifier"},
              @"after": @{@"type": @"integer", @"minimum": @0},
              @"limit": @{@"type": @"integer", @"minimum": @1, @"maximum": @500},
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
    int code = ok ? 200 : ([value[@"error"] isEqualToString:@"unknown_session"] ? 404 : 400);
    sendHTTP(fd, code, ok ? @"OK" : @"Error", value);
}

static NSString *targetPath(NSString *target) {
    NSRange split = [target rangeOfString:@"?"];
    return split.location == NSNotFound ? target : [target substringToIndex:split.location];
}

static NSString *targetQuery(NSString *target) {
    NSRange split = [target rangeOfString:@"?"];
    return split.location == NSNotFound ? @"" : [target substringFromIndex:NSMaxRange(split)];
}

static BOOL serveSessions(int fd, NSString *target, IDHSessionService *service, dispatch_queue_t stateQueue) {
    NSString *path = targetPath(target);
    NSString *query = targetQuery(target);
    NSArray<NSString *> *parts = [path componentsSeparatedByString:@"/"];
    if (parts.count < 3 || parts.firstObject.length || ![parts[1] isEqualToString:@"api"] ||
        ![parts[2] isEqualToString:@"sessions"]) return NO;
    if (parts.count == 3) {
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{ value = [service read:@"list_sessions" arguments:@{}]; });
        sendResult(fd, value);
        return YES;
    }
    if (parts.count > 5 || !parts[3].length || (parts.count == 5 && ![parts[4] isEqualToString:@"events"])) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return YES;
    }
    NSString *sessionID = parts[3];
    if (parts.count == 4) {
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{ value = [service read:@"get_session" arguments:@{@"session_id": sessionID}]; });
        sendResult(fd, value);
        return YES;
    }
    NSString *after = queryValue(query, @"after_seq");
    NSString *limit = queryValue(query, @"limit");
    NSMutableDictionary *arguments = [@{@"session_id": sessionID} mutableCopy];
    if (after) arguments[@"after_seq"] = @([after longLongValue]);
    if (limit) arguments[@"limit"] = @([limit longLongValue]);
    __block NSDictionary *value;
    dispatch_sync(stateQueue, ^{ value = [service read:@"read_session_events" arguments:arguments]; });
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
        dispatch_sync(stateQueue, ^{ value = idh_apps_list(); });
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
    NSString *limit = queryValue(query, @"limit");
    NSMutableDictionary *arguments = [@{@"bundle_id": bundle} mutableCopy];
    if (after) arguments[@"after"] = @([after longLongValue]);
    if (limit) arguments[@"limit"] = @([limit longLongValue]);
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
    BOOL sessionRead = [method isEqualToString:@"GET"] &&
        ([path isEqualToString:@"/api/sessions"] || [path hasPrefix:@"/api/sessions/"]);
    BOOL settingsRoute = [target isEqualToString:@"/api/session-settings"];
    BOOL settingsRead = settingsRoute && [method isEqualToString:@"GET"];
    BOOL appsRead = [method isEqualToString:@"GET"] && [path hasPrefix:@"/api/apps"];
    BOOL scopeRoute = [path isEqualToString:@"/api/injection-scope"];
    BOOL scopeRead = scopeRoute && [method isEqualToString:@"GET"];
    BOOL relaunchRoute = [method isEqualToString:@"POST"] && [path isEqualToString:@"/api/apps/relaunch"];
    if (!sessionRead && !settingsRoute && !appsRead && !scopeRoute && !relaunchRoute &&
        ![path isEqualToString:@"/api/mcp"]) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (!sessionRead && !settingsRead && !appsRead && !scopeRead && ![method isEqualToString:@"POST"]) {
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
    if (scopeRoute || relaunchRoute) {
        if (![request isKindOfClass:NSDictionary.class]) {
            sendHTTP(fd, 400, @"Bad Request", nil);
            return;
        }
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{
            value = scopeRoute
                ? idh_scope_apply([request[@"add"] isKindOfClass:NSArray.class] ? request[@"add"] : @[],
                                  [request[@"remove"] isKindOfClass:NSArray.class] ? request[@"remove"] : @[])
                : idh_app_relaunch(request[@"bundleId"]);
        });
        sendResult(fd, value);
        return;
    }
    if (![request isKindOfClass:NSDictionary.class]) {
        sendHTTP(fd, 200, @"OK", rpcError(nil, -32700, @"Invalid JSON-RPC message"));
        return;
    }
    NSDictionary *reply;
    if (processIdentityCall(request)) {
        NSDictionary *parameters = request[@"params"];
        NSDictionary *arguments = [parameters isKindOfClass:NSDictionary.class] ? parameters[@"arguments"] : nil;
        if (![arguments isKindOfClass:NSDictionary.class]) arguments = @{};
        __block NSDictionary *value;
        dispatch_sync(stateQueue, ^{ value = [service processIdentity:arguments]; });
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
        NSString *text = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
        NSDictionary *result = @{@"content": @[@{@"type": @"text", @"text": text ?: @"{}"}],
                                 @"structuredContent": value, @"isError": @(![value[@"ok"] boolValue])};
        reply = @{@"jsonrpc": @"2.0", @"id": request[@"id"] ?: NSNull.null, @"result": result};
    } else {
        reply = rpc(request, service, stateQueue);
    }
    sendHTTP(fd, reply ? 200 : 202, reply ? @"OK" : @"Accepted", reply);
}
