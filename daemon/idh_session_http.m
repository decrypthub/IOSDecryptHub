#import "idh_session_http.h"
#import "idh_session_service.h"
#import "../src/session/idh_session_ipc.h"
#include <errno.h>
#include <sys/socket.h>

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
    ];
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
        dispatch_sync(stateQueue, ^{ value = [service read:parameters[@"name"] arguments:parameters[@"arguments"] ?: @{}]; });
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
        NSString *text = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
        result = @{@"content": @[@{@"type": @"text", @"text": text ?: @"{}"}],
                   @"structuredContent": value, @"isError": @(![value[@"ok"] boolValue])};
    } else {
        return rpcError(identity, -32601, @"Method not found");
    }
    return @{@"jsonrpc": @"2.0", @"id": identity, @"result": result};
}

static BOOL tokenMatches(NSString *authorization, NSString *token) {
    if (!token.length || ![authorization hasPrefix:@"Bearer "]) return NO;
    NSData *supplied = [[authorization substringFromIndex:7] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *expected = [token dataUsingEncoding:NSUTF8StringEncoding];
    if (supplied.length != expected.length) return NO;
    const unsigned char *a = supplied.bytes;
    const unsigned char *b = expected.bytes;
    unsigned char difference = 0;
    for (NSUInteger i = 0; i < expected.length; i++) difference |= a[i] ^ b[i];
    return difference == 0;
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
    if (requestLine.count != 3 || ![requestLine[1] isEqualToString:@"/api/mcp"]) {
        sendHTTP(fd, 404, @"Not Found", nil);
        return;
    }
    if (![requestLine[0] isEqualToString:@"POST"]) {
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
    __block BOOL authorized;
    dispatch_sync(stateQueue, ^{ authorized = IDHSessionModeEnabled() && tokenMatches(headers[@"authorization"], service.pairingToken); });
    if (!authorized || headers[@"origin"]) {
        sendHTTP(fd, 401, @"Unauthorized", nil);
        return;
    }
    NSScanner *scanner = [NSScanner scannerWithString:headers[@"content-length"] ?: @""];
    unsigned long long length = 0;
    if (headers[@"transfer-encoding"] || ![scanner scanUnsignedLongLong:&length] || !scanner.isAtEnd ||
        !length || length > IDH_SESSION_MAX_MESSAGE) {
        sendHTTP(fd, 400, @"Bad Request", nil);
        return;
    }
    NSUInteger offset = NSMaxRange(end);
    NSUInteger buffered = MIN((NSUInteger)length, incoming.length - offset);
    NSMutableData *body = [NSMutableData dataWithLength:(NSUInteger)length];
    [incoming getBytes:body.mutableBytes range:NSMakeRange(offset, buffered)];
    if (!IDHSessionReadBytes(fd, (char *)body.mutableBytes + buffered, (size_t)length - buffered)) return;
    id request = [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL];
    NSDictionary *reply = [request isKindOfClass:NSDictionary.class] ? rpc(request, service, stateQueue)
        : rpcError(nil, -32700, @"Invalid JSON-RPC message");
    sendHTTP(fd, reply ? 200 : 202, reply ? @"OK" : @"Accepted", reply);
}
