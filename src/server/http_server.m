// http_server.m - IOSDecryptHub 本地 HTTP 服务
//
// 设计:
//   - 一个 socket 监听端口, 一个 accept 队列, 每个连接 dispatch 到处理队列
//   - 每个连接一次性读 header (限 64KB), 没有 keep-alive 也没有 chunked
//   - JSON 用 NSJSONSerialization
//   - HTML / 公众号物料来自 web_index_html.h 与 web_wechat_png.h
//
// 安全声明: 本服务无认证, 把 key/iv/明文都暴露给任何能连接的人.
// 仅供调试时在可信网络上使用.

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import "http_server.h"
#import "log_store.h"
#import "web_index_html.h"
#import "web_wechat_png.h"
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_noise.h"
#import "dh_spoof.h"
#import "ui_float.h"
#import "dump_manager.h"
#import "dh_symtab.h"
#import "dh_files.h"
#import "dh_log_json.h"
#import "mcp_server.h"
#import "hook_network.h"

#define DH_HTTP_PORT_FIRST  8088
#define DH_HTTP_PORT_LAST   8108
#define DH_HTTP_BACKLOG     16
#define DH_HTTP_MAX_HEADER  (64 * 1024)
#define DH_HTTP_MAX_BODY    (2 * 1024 * 1024)   // 配置导入请求体上限
#ifndef DH_VERSION_STR
#define DH_VERSION_STR "0.0.0"   // 兜底; 正常由 Makefile -D 注入(单一真相源)
#endif
#define DH_HTTP_VERSION     DH_VERSION_STR

static int        gListenFD = -1;
static uint16_t   gPort     = 0;
static NSString  *gURL      = nil;
static dispatch_queue_t gAcceptQ = NULL;
static dispatch_queue_t gWorkerQ = NULL;
static dispatch_semaphore_t gConcurrency = NULL;  // 限制同时处理的连接数, 防 slow-client 耗尽 fd

#define DH_HTTP_MAX_CONCURRENCY 8


// ============================================================
// 工具
// ============================================================
static NSString *get_local_ip(void) {
    struct ifaddrs *ifa = NULL, *p = NULL;
    NSString *best = nil;
    NSString *fallback = nil;
    if (getifaddrs(&ifa) == 0) {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            NSString *ifn = [NSString stringWithUTF8String:p->ifa_name];
            NSString *ip  = [NSString stringWithUTF8String:buf];
            // 优先 Wi-Fi (en0) -> 蜂窝 (pdp_ip0) -> 其它
            if ([ifn isEqualToString:@"en0"]) { best = ip; break; }
            if ([ifn hasPrefix:@"en"] && !best) best = ip;
            if (!fallback) fallback = ip;
        }
        freeifaddrs(ifa);
    }
    if (best) return best;
    if (fallback) return fallback;
    // fail-loud(info): 没有任何非回环 IP, 服务只能本地访问 —— 明示而非假装一切正常.
    dh_health_note_localonly();
    return @"127.0.0.1";
}

static NSString *url_decode(NSString *s) {
    return [s stringByRemovingPercentEncoding] ?: s;
}

static NSDictionary *parse_query(NSString *qs) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    if (qs.length == 0) return out;
    for (NSString *kv in [qs componentsSeparatedByString:@"&"]) {
        NSRange eq = [kv rangeOfString:@"="];
        if (eq.location == NSNotFound) {
            out[url_decode(kv)] = @"";
        } else {
            NSString *k = [kv substringToIndex:eq.location];
            NSString *v = [kv substringFromIndex:eq.location + 1];
            out[url_decode(k)] = url_decode(v);
        }
    }
    return out;
}

// ============================================================
// I/O helpers
// ============================================================
static BOOL write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        if (n == 0) return NO;
        p += n; left -= (size_t)n;
    }
    return YES;
}

// extraHeaders: 每行需自带 "\r\n" 结尾; 传 nil 表示无额外头。
static void send_response_ex(int fd, int status, NSString *statusMsg, NSString *contentType,
                             NSData *body, NSString *extraHeaders) {
    NSMutableString *headers = [NSMutableString string];
    [headers appendFormat:@"HTTP/1.1 %d %@\r\n", status, statusMsg];
    if (contentType) [headers appendFormat:@"Content-Type: %@\r\n", contentType];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Access-Control-Allow-Origin: *\r\n"];
    if (extraHeaders) [headers appendString:extraHeaders];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    write_all(fd, hd.bytes, hd.length);
    if (body.length) write_all(fd, body.bytes, body.length);
}

static void send_response(int fd, int status, NSString *statusMsg, NSString *contentType, NSData *body) {
    send_response_ex(fd, status, statusMsg, contentType, body, nil);
}

static void send_json(int fd, int status, id obj) {
    NSError *jerr = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:obj ?: @{} options:0 error:&jerr];
    if (!body) {
        // fail-loud: 序列化失败返回 500 + 明确错误, 而不是静默回空让客户端以为「无数据」.
        DH_ERR(@"JSON 序列化失败: %@", jerr.localizedDescription);
        NSData *eb = [@"{\"error\":\"json encode failed\"}" dataUsingEncoding:NSUTF8StringEncoding];
        send_response(fd, 500, @"Error", @"application/json; charset=utf-8", eb);
        return;
    }
    send_response(fd, status, status == 200 ? @"OK" : @"Error", @"application/json; charset=utf-8", body);
}

static void send_text(int fd, int status, NSString *msg) {
    NSData *body = [(msg ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    send_response(fd, status, status == 200 ? @"OK" : @"Error", @"text/plain; charset=utf-8", body);
}

// ============================================================
// 路由 handlers
// ============================================================
// 日志条目 JSON 成型已抽到 dh_log_json.h (与 mcp_server 共用): dh_log_entry_summary / dh_log_entry_detail

static void handle_stats(int fd) {
    DHLogStore *s = [DHLogStore shared];
    // 由分类表派生, 不再硬编码平行数组; 顺便给前端 categoryNames 让它也别硬编码 CAT_CLS。
    NSInteger nCat = dh_log_category_count();
    NSMutableArray *byCat = [NSMutableArray arrayWithCapacity:nCat];
    NSMutableArray *pausedByCat = [NSMutableArray arrayWithCapacity:nCat];
    NSMutableArray *catNames = [NSMutableArray arrayWithCapacity:nCat];
    for (NSInteger c = 0; c < nCat; c++) {
        [byCat addObject:@([s countForCategory:(DHCategory)c])];
        [pausedByCat addObject:@([s isPausedForCategory:(DHCategory)c])];
        [catNames addObject:@(dh_log_category_name(c))];
    }
    NSMutableDictionary *capture = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        capture[[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    const char *hsum = dh_health_summary();
    // 落盘日志字节数: 每条日志已实时写入沙箱文件(App 闪退/被检测杀掉后, 重启仍可经 /download 取全量),
    // 前端据此提示「数据已落盘」并标出可下载大小, 形成崩溃可闭环的取证链路。含已滚动归档的备份段。
    unsigned long long logBytes = [s totalLogBytes];
    send_json(fd, 200, @{
        @"total":       @(s.totalCount),
        @"paused":      @(s.paused),
        @"byCategory":  byCat,
        @"pausedByCat": pausedByCat,
        @"categoryNames": catNames,   // 前端据此派生 CAT_CLS, 不再硬编码分类名数组
        @"capture":     capture,
        @"port":        @(gPort),
        @"version":     @DH_HTTP_VERSION,
        @"logBytes":    @(logBytes),
        @"pipeline":    [s pipelineStats],   // 背压/丢弃/RSS: 用于长时间运行稳定性观测
        @"noiseCount":  @[@([s noiseCountForBoard:DHNoiseBoardCrypto]), @([s noiseCountForBoard:DHNoiseBoardSys])],
        @"noiseEnabled": @[@(dh_noise_enabled_for_board(DHNoiseBoardCrypto)), @(dh_noise_enabled_for_board(DHNoiseBoardSys))],
        @"process":     [s processInfo],
        @"health":      @{
            @"hookFails":     @(dh_health_hook_fail_count()),
            @"persistFailed": dh_health_persist_failed() ? @YES : @NO,
            @"httpFailed":    dh_health_http_failed() ? @YES : @NO,
            @"localOnly":     dh_health_local_only() ? @YES : @NO,
            @"summary":       (hsum && hsum[0]) ? [NSString stringWithUTF8String:hsum] : @"",
        },
    });
}

static void handle_logs_list(int fd, NSDictionary *q) {
    NSInteger cat    = q[@"cat"]    ? [q[@"cat"] integerValue] : -1;
    NSString *kw     = q[@"q"]      ?: @"";
    uint64_t  since  = q[@"since"]  ? (uint64_t)[q[@"since"] longLongValue]  : 0;   // 仅取 seq > since (键集分页: 增量取新)
    uint64_t  before = q[@"before"] ? (uint64_t)[q[@"before"] longLongValue] : 0;   // 仅取 seq < before (键集分页: 翻更早)
    NSInteger lim    = q[@"limit"]  ? [q[@"limit"] integerValue] : 500;
    if (lim <= 0 || lim > 5000) lim = 500;
    NSUInteger minSize = q[@"minSize"] ? (NSUInteger)[q[@"minSize"] integerValue] : 0;
    NSUInteger maxSize = q[@"maxSize"] ? (NSUInteger)[q[@"maxSize"] integerValue] : 0;

    NSArray *src = [[DHLogStore shared] snapshotMatching:kw category:cat minInputSize:minSize maxInputSize:maxSize];
    // 最新在前; since/before 为游标, 二者择一 (前端不会同时传)
    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0 && (NSInteger)out.count < lim; i--) {
        DHLogEntry *e = src[i];
        if (since  && e.seq <= since)  continue;
        if (before && e.seq >= before) continue;
        [out addObject:dh_log_entry_summary(e)];
    }
    send_json(fd, 200, out);
}

static void handle_log_detail(int fd, NSString *seqStr) {
    uint64_t seq = (uint64_t)[seqStr longLongValue];
    DHLogEntry *e = [[DHLogStore shared] entryWithSeq:seq];
    if (!e) { send_json(fd, 404, @{@"error": @"not found"}); return; }
    send_json(fd, 200, dh_log_entry_detail(e));
}

static void handle_clear(int fd, NSDictionary *q) {
    if (q[@"cat"]) [[DHLogStore shared] clearCategory:[q[@"cat"] integerValue]];   // 清空本类
    else           [[DHLogStore shared] clearAll];                                 // 清空全部(含落盘)
    send_json(fd, 200, @{@"ok": @YES});
}

// 噪点日志 —— 按板块独立桶; board=crypto|sys
static DHNoiseBoard parse_noise_board(NSDictionary *q) {
    NSString *b = q[@"board"];
    if ([b isEqualToString:@"sys"]) return DHNoiseBoardSys;
    return DHNoiseBoardCrypto;
}

static void handle_noise_list(int fd, NSDictionary *q) {
    DHNoiseBoard board = parse_noise_board(q);
    NSString *kw     = q[@"q"]      ?: @"";
    uint64_t  since  = q[@"since"]  ? (uint64_t)[q[@"since"] longLongValue]  : 0;
    uint64_t  before = q[@"before"] ? (uint64_t)[q[@"before"] longLongValue] : 0;
    NSInteger lim    = q[@"limit"]  ? [q[@"limit"] integerValue] : 500;
    if (lim <= 0 || lim > 5000) lim = 500;

    NSArray *src = [[DHLogStore shared] snapshotNoiseMatching:kw board:board];
    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0 && (NSInteger)out.count < lim; i--) {
        DHLogEntry *e = src[i];
        if (since  && e.seq <= since)  continue;
        if (before && e.seq >= before) continue;
        [out addObject:dh_log_entry_summary(e)];
    }
    send_json(fd, 200, out);
}

static void handle_noise_clear(int fd, NSDictionary *q) {
    [[DHLogStore shared] clearNoiseForBoard:parse_noise_board(q)];
    send_json(fd, 200, @{@"ok": @YES});
}

static void handle_noise_patterns_get(int fd, NSDictionary *q) {
    DHNoiseBoard board = parse_noise_board(q);
    send_json(fd, 200, @{
        @"board":    (board == DHNoiseBoardSys) ? @"sys" : @"crypto",
        @"enabled":  @(dh_noise_enabled_for_board(board)),
        @"patterns": dh_noise_patterns_for_board(board),
    });
}

static void handle_noise_patterns_set(int fd, NSDictionary *q) {
    DHNoiseBoard board = parse_noise_board(q);
    NSString *op = q[@"op"] ?: @"";
    if ([op isEqualToString:@"add"]) {
        NSString *text = q[@"text"];
        if (text.length) dh_noise_add_pattern_for_board(board, text);
    } else if ([op isEqualToString:@"remove"]) {
        NSString *text = q[@"text"];
        if (text.length) dh_noise_remove_pattern_for_board(board, text);
    } else if ([op isEqualToString:@"enable"]) {
        BOOL on = [(q[@"on"] ?: @"1") isEqualToString:@"1"];
        dh_noise_set_enabled_for_board(board, on);
    }
    handle_noise_patterns_get(fd, q);   // 回当前(已更新)状态
}

static void handle_pause(int fd, NSDictionary *q) {
    BOOL p = [(q[@"paused"] ?: @"1") isEqualToString:@"1"];
    DHLogStore *s = [DHLogStore shared];
    if (q[@"cat"]) {
        NSInteger cat = [q[@"cat"] integerValue];
        if (cat == -2) {                                // 加密组(摘要/HMAC/对称/非对称)
            for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) [s setPaused:p forCategory:(DHCategory)c];
        } else if (cat == -3) {                         // 系统组(文件+模块)
            [s setPaused:p forCategory:DHCategoryFile];
            [s setPaused:p forCategory:DHCategorySystem];
        } else {                                        // 单类
            [s setPaused:p forCategory:(DHCategory)cat];
        }
        send_json(fd, 200, @{@"paused": @(p), @"cat": @(cat)});
    } else {                                            // 全局总开关
        s.paused = p;
        send_json(fd, 200, @{@"paused": @(p)});
    }
}

// 捕获开关 —— 哪些子类型被记录(持久化在沙箱)。
static void handle_capture_get(int fd) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        d[[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    send_json(fd, 200, d);
}
static void handle_capture_set(int fd, NSDictionary *q) {
    NSString *sub = q[@"sub"];
    if (!sub) { send_json(fd, 400, @{@"error": @"missing sub"}); return; }
    int idx = -1;
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        if ([sub isEqualToString:[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]]) { idx = i; break; }
    if (idx < 0) { send_json(fd, 400, @{@"error": @"unknown sub"}); return; }
    BOOL on = [(q[@"on"] ?: @"1") isEqualToString:@"1"];
    dh_capture_set_sub((dh_cap_sub)idx, on ? 1 : 0);
    send_json(fd, 200, @{@"sub": sub, @"on": @(on)});
}

// 伪装/绕过配置 —— 越狱隐藏 / 反调试 / 改机(持久化在沙箱 .dh_spoof.conf)。
static void handle_spoof_get(int fd) {
    send_json(fd, 200, dh_spoof_snapshot());
}
static void handle_spoof_set(int fd, NSDictionary *q) {
    NSString *group = q[@"group"] ?: @"";
    NSString *op    = q[@"op"] ?: @"";
    BOOL on = [(q[@"on"] ?: @"1") isEqualToString:@"1"];
    NSString *text  = q[@"text"];
    if ([group isEqualToString:@"jb"]) {
        if      ([op isEqualToString:@"enable"])       dh_spoof_jb_set_on(on);
        else if ([op isEqualToString:@"add_path"]      && text.length) dh_spoof_jb_add_path(text);
        else if ([op isEqualToString:@"remove_path"]   && text.length) dh_spoof_jb_remove_path(text);
        else if ([op isEqualToString:@"add_scheme"]    && text.length) dh_spoof_jb_add_scheme(text);
        else if ([op isEqualToString:@"remove_scheme"] && text.length) dh_spoof_jb_remove_scheme(text);
        else if ([op isEqualToString:@"add_image"]     && text.length) dh_spoof_jb_add_image(text);
        else if ([op isEqualToString:@"remove_image"]  && text.length) dh_spoof_jb_remove_image(text);
    } else if ([group isEqualToString:@"anti"]) {
        if ([op isEqualToString:@"enable"]) dh_spoof_anti_debug_set_on(on);
    } else if ([group isEqualToString:@"device"]) {
        if      ([op isEqualToString:@"enable"]) dh_spoof_device_set_on(on);
        else if ([op isEqualToString:@"set"] && q[@"key"]) dh_spoof_device_set_value(q[@"key"], q[@"value"] ?: @"");
        else if ([op isEqualToString:@"randomize"]) dh_spoof_device_randomize();
    }
    handle_spoof_get(fd);   // 回当前(已更新)状态
}

// 配置导入/导出 —— 把捕获开关 / 噪声规则 / 伪装绕过规则打包成一份 JSON, 便于分享与跨 App 复用。
static void handle_settings_export(int fd) {
    NSMutableDictionary *cap = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        cap[[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    send_json(fd, 200, @{
        @"dh_settings_version": @1,
        @"capture": cap,
        @"noise":   dh_noise_export(),
        @"spoof":   dh_spoof_snapshot(),
    });
}
static void handle_settings_import(int fd, NSString *body) {
    NSData *data = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *root = data.length ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (![root isKindOfClass:[NSDictionary class]]) { send_json(fd, 400, @{@"error": @"配置 JSON 无效"}); return; }
    NSMutableArray *applied = [NSMutableArray array];
    NSDictionary *cap = root[@"capture"];
    if ([cap isKindOfClass:[NSDictionary class]]) {
        for (int i = 0; i < DH_CAP_SUB_COUNT; i++) {
            NSString *nm = [NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)];
            if (cap[nm] != nil) dh_capture_set_sub((dh_cap_sub)i, [cap[nm] boolValue]);
        }
        [applied addObject:@"capture"];
    }
    if ([root[@"noise"] isKindOfClass:[NSDictionary class]]) { dh_noise_import(root[@"noise"]); [applied addObject:@"noise"]; }
    if ([root[@"spoof"] isKindOfClass:[NSDictionary class]]) { dh_spoof_import(root[@"spoof"]); [applied addObject:@"spoof"]; }
    send_json(fd, 200, @{ @"ok": @YES, @"applied": applied });
}

// 日志保留/落盘配置 —— 每类内存保留条数 + 单文件滚动上限。持久化在沙箱 .dh_logcfg.conf。
static void handle_config_get(int fd) {
    DHLogStore *s = [DHLogStore shared];
    send_json(fd, 200, @{
        @"maxEntries":   @([s maxPerCategory]),     // 每类内存保留条数
        @"maxFileBytes": @([s maxLogFileBytes]),    // 单文件滚动上限, 0=不限
        @"backups":      @(3),                       // 额外保留的滚动备份段数 (固定)
        @"logBytes":     @([s totalLogBytes]),       // 当前落盘总大小 (含备份)
    });
}
static void handle_config_set(int fd, NSDictionary *q) {
    DHLogStore *s = [DHLogStore shared];
    if (q[@"maxEntries"]) {
        NSInteger n = [q[@"maxEntries"] integerValue];
        if (n > 0) [s setMaxPerCategory:(NSUInteger)n];
    }
    if (q[@"maxFileBytes"]) {
        long long n = [q[@"maxFileBytes"] longLongValue];
        if (n >= 0) [s setMaxLogFileBytes:(unsigned long long)n];   // 0=不限
    }
    handle_config_get(fd);   // 回当前(已更新)配置
}

// 按板块下载: 把某分类(或 -2 加密组)的内存日志导出为纯文本附件。
static void handle_logs_download(int fd, NSDictionary *q) {
    NSInteger cat = q[@"cat"] ? [q[@"cat"] integerValue] : -1;
    NSString *text = [[DHLogStore shared] exportTextForCategory:cat];
    NSData *body = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendFormat:@"Content-Disposition: attachment; filename=iosdecrypthub-cat%ld.log\r\n", (long)cat];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;
    write_all(fd, body.bytes, body.length);
}

// 审查日志(诊断): 进程信息 + hook 安装结果 + 按板块的错误事件时间线。board<0=全部板块。
// 注意: NSString 的 %s 按系统默认 C 编码解释 UTF-8 会乱码, 含中文的 C 串先 stringWithUTF8String 再 %@。
static NSString *diag_text(NSInteger board) {
    DHLogStore *s = [DHLogStore shared];
    NSDictionary *pi = [s processInfo];
    NSMutableString *t = [NSMutableString string];
    [t appendString:@"==== IOSDecryptHub 审查日志 (diagnostic) ====\n"];
    [t appendFormat:@"版本: %s\n", DH_HTTP_VERSION];
    [t appendFormat:@"应用: %@ (%@)  PID %@\n", pi[@"appName"] ?: @"", pi[@"bundleId"] ?: @"", pi[@"pid"] ?: @"?"];
    [t appendFormat:@"系统: %@   设备: %@   物理内存: %@ MB\n",
        pi[@"systemVersion"] ?: @"", pi[@"deviceModel"] ?: @"", pi[@"physicalMemoryMB"] ?: @"?"];
    [t appendFormat:@"服务端口: %d   监听: %@\n", gPort, gURL ?: @""];
    const char *unh = dh_health_hook_unhooked();
    if (unh && unh[0])
        [t appendFormat:@"未挂上的符号(多为该 App 未调用此 API, 属正常): %s\n", unh];   // 符号名为 ASCII
    const char *hsum = dh_health_summary();
    NSString *hs = (hsum && hsum[0]) ? [NSString stringWithUTF8String:hsum] : nil;
    [t appendFormat:@"健康摘要: %@\n", hs ?: @"正常"];
    [t appendFormat:@"---- 事件时间线 (%@) ----\n", board < 0 ? @"全部板块" : @"本板块"];
    NSString *timeline = [NSString stringWithUTF8String:dh_diag_dump((int)board)];
    [t appendString:timeline ?: @""];
    [t appendString:@"==== END ====\n"];
    return t;
}
static void handle_diag(int fd, NSDictionary *q) {
    NSInteger board = q[@"board"] ? [q[@"board"] integerValue] : -1;
    send_text(fd, 200, diag_text(board));
}
static void handle_diag_download(int fd, NSDictionary *q) {
    NSInteger board = q[@"board"] ? [q[@"board"] integerValue] : -1;
    NSData *body = [diag_text(board) dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendFormat:@"Content-Disposition: attachment; filename=iosdecrypthub-diag-%ld.log\r\n", (long)board];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;
    write_all(fd, body.bytes, body.length);
}

static void handle_download(int fd) {
    NSString *base = [[DHLogStore shared] logFilePath];
    NSFileManager *fm = [NSFileManager defaultManager];
    // 按时序拼接: 最旧的滚动备份 .3 → .2 → .1 → 当前段。只收实际存在的段。
    NSMutableArray<NSString *> *segs = [NSMutableArray array];
    for (int i = 3; i >= 1; i--) {
        NSString *p = [base stringByAppendingFormat:@".%d", i];
        if ([fm fileExistsAtPath:p]) [segs addObject:p];
    }
    if ([fm fileExistsAtPath:base]) [segs addObject:base];
    if (segs.count == 0) { send_text(fd, 404, @"log file not present yet"); return; }

    unsigned long long total = 0;
    for (NSString *p in segs) {
        NSDictionary *a = [fm attributesOfItemAtPath:p error:nil];
        if (a) total += [(NSNumber *)a[NSFileSize] unsignedLongLongValue];
    }

    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %llu\r\n", total];
    [headers appendString:@"Content-Disposition: attachment; filename=decrypt_helper.log\r\n"];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;

    // 64KB 分块, 逐段串流, 避免一次性把整个日志文件吃进内存
    for (NSString *path in segs) {
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
        if (!fh) {
            // fail-loud: header(含 Content-Length) 已发出但某段打不开, 连接会被中断而非静默补 0。
            DH_ERR(@"下载: 无法读取日志段 %@, 连接将中断", path);
            return;
        }
        @try {
            while (1) {
                NSData *chunk = [fh readDataOfLength:64 * 1024];
                if (chunk.length == 0) break;
                if (!write_all(fd, chunk.bytes, chunk.length)) {
                    DH_ERR(@"下载: 发送数据块失败(客户端可能已断开), 连接中断");
                    [fh closeFile];
                    return;
                }
            }
        } @catch (NSException *e) {
            DH_ERR(@"下载: 读取日志段异常: %@", e.reason);
        }
        [fh closeFile];
    }
}

static void handle_appicon(int fd) {
    NSData *png = dh_host_app_icon_png();
    if (!png) { send_text(fd, 404, @"no app icon"); return; }
    send_response(fd, 200, @"OK", @"image/png", png);
}

// ---- 砸壳 (dump / 脱壳) ----
static void handle_dump_images(int fd) {
    send_json(fd, 200, [[DHDumpManager shared] listImagesDict]);
}

static void handle_dump_start(int fd, NSDictionary *q) {
    NSString *mode = q[@"mode"] ?: @"ipa";
    BOOL ok = [[DHDumpManager shared] startDump:mode];
    if (!ok) { send_json(fd, 409, @{@"started": @NO, @"error": @"已有任务在进行或 mode 非法"}); return; }
    send_json(fd, 200, @{@"started": @YES, @"mode": mode});
}

static void handle_dump_status(int fd) {
    send_json(fd, 200, [[DHDumpManager shared] statusDict]);
}

// 流式发送磁盘文件作为附件下载; 复用于整包产物(bin/ipa)和单镜像即时下载。
static void send_file_as_download(int fd, NSString *path, NSString *downloadName) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (!attrs) { send_text(fd, 404, @"文件丢失"); return; }
    unsigned long long total = [(NSNumber *)attrs[NSFileSize] unsignedLongLongValue];

    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: application/octet-stream\r\n"];
    [headers appendFormat:@"Content-Length: %llu\r\n", total];
    [headers appendFormat:@"Content-Disposition: attachment; filename=%@\r\n", downloadName];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) { DH_ERR(@"下载: 无法读取 %@, 连接将中断", path); return; }
    @try {
        while (1) {
            NSData *chunk = [fh readDataOfLength:64 * 1024];
            if (chunk.length == 0) break;
            if (!write_all(fd, chunk.bytes, chunk.length)) {
                DH_ERR(@"下载: 发送数据块失败(客户端可能已断开)");
                break;
            }
        }
    } @catch (NSException *e) {
        DH_ERR(@"下载: 读取文件异常: %@", e.reason);
    }
    [fh closeFile];
}

static void handle_dump_download(int fd, NSDictionary *q) {
    NSString *kind = [q[@"kind"] isEqualToString:@"bin"] ? @"bin" : @"ipa";
    NSString *path = [[DHDumpManager shared] artifactPathForKind:kind];
    if (!path) { send_text(fd, 404, @"砸壳产物尚未就绪"); return; }
    send_file_as_download(fd, path, [path lastPathComponent]);
}

// 单镜像即时下载: 无需跑整包任务, 现砸现传, 发完删临时文件。
static void handle_dump_image_download(int fd, NSDictionary *q) {
    NSString *name = q[@"name"];
    if (name.length == 0 || [name rangeOfString:@"/"].location != NSNotFound
                          || [name rangeOfString:@".."].location != NSNotFound) {
        send_text(fd, 400, @"非法 name 参数"); return;
    }
    NSError *err = nil;
    NSString *tmpPath = [[DHDumpManager shared] decryptImageNamed:name error:&err];
    if (!tmpPath) { send_text(fd, 404, err.localizedDescription ?: @"砸壳失败"); return; }
    send_file_as_download(fd, tmpPath, [name stringByAppendingString:@"-decrypted"]);
    [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
}

// ---- 宿主沙盒文件浏览 (只读) ----
static void handle_files_list(int fd, NSDictionary *q) {
    NSError *err = nil;
    NSDictionary *d = dh_files_list_dict(q[@"path"], &err);
    if (!d) {
        NSInteger code = err.code;
        send_json(fd, (code >= 400 && code < 600) ? (int)code : 400,
                  @{@"error": err.localizedDescription ?: @"error"});
        return;
    }
    send_json(fd, 200, d);
}

static void handle_files_preview(int fd, NSDictionary *q) {
    NSUInteger limit = q[@"limit"] ? (NSUInteger)[q[@"limit"] integerValue] : 65536;
    NSError *err = nil;
    NSDictionary *d = dh_files_preview_dict(q[@"path"], limit, &err);
    if (!d) {
        NSInteger code = err.code;
        send_json(fd, (code >= 400 && code < 600) ? (int)code : 400,
                  @{@"error": err.localizedDescription ?: @"error"});
        return;
    }
    send_json(fd, 200, d);
}

static void handle_files_download(int fd, NSDictionary *q) {
    NSError *err = nil;
    NSString *abs = dh_files_resolve_file(q[@"path"], &err);
    if (!abs) {
        send_text(fd, err.code == 404 ? 404 : 400, err.localizedDescription ?: @"error");
        return;
    }
    NSString *rel = q[@"path"] ?: @"download";
    send_file_as_download(fd, abs, [rel lastPathComponent]);
}

// ---- 符号导入表(可 hook 观测) ----
// fishhook 只能改导入符号表 —— 这几个端点把各 image 的导入(undefined)符号暴露给面板, 让使用者
// 当场看清「哪些可被 fishhook 拦截」, 尤其 TLS 明文接口是否在导入表里(不在=多半静态链接)。
// C 回调把符号名收进 NSMutableArray。
static void sym_name_collect_cb(const char *name, void *ctx) {
    NSMutableArray *a = (__bridge NSMutableArray *)ctx;
    if (name) [a addObject:[NSString stringWithUTF8String:name] ?: @"?"];
}

// GET /api/symbols/images —— 列出有导入符号的 image(主程序优先), 给「符号」页下拉用。
static void handle_symbols_images(int fd) {
    int n = dh_symtab_image_count();
    NSMutableArray *arr = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        char nm[256]; int isMain = 0;
        dh_symtab_image_name(i, nm, sizeof(nm), &isMain);
        int imports = dh_symtab_imports(i, NULL, 0, NULL, NULL);   // 只计数
        if (imports <= 0) continue;
        [arr addObject:@{
            @"idx":     @(i),
            @"name":    [NSString stringWithUTF8String:nm] ?: @"?",
            @"main":    isMain ? @YES : @NO,
            @"imports": @(imports),
        }];
    }
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL am = [a[@"main"] boolValue], bm = [b[@"main"] boolValue];
        if (am != bm) return am ? NSOrderedAscending : NSOrderedDescending;   // 主程序排最前
        return [a[@"name"] caseInsensitiveCompare:b[@"name"]];
    }];
    send_json(fd, 200, @{@"images": arr});
}

// GET /api/symbols?img=N&q=&limit= —— 某 image 的导入符号列表(可子串过滤)。出现在导入表里的都是 fishhook 候选。
static void handle_symbols(int fd, NSDictionary *q) {
    int n = dh_symtab_image_count();
    int idx = q[@"img"] ? [q[@"img"] intValue] : 0;
    if (idx < 0 || idx >= n) { send_json(fd, 400, @{@"error": @"bad img index"}); return; }
    NSString *kw = q[@"q"] ?: @"";
    int limit = q[@"limit"] ? [q[@"limit"] intValue] : 300;
    if (limit <= 0 || limit > 2000) limit = 300;

    char nm[256]; int isMain = 0;
    dh_symtab_image_name(idx, nm, sizeof(nm), &isMain);
    NSMutableArray *syms = [NSMutableArray array];
    const char *qc = kw.length ? kw.UTF8String : NULL;
    int total = dh_symtab_imports(idx, qc, limit, sym_name_collect_cb, (__bridge void *)syms);
    send_json(fd, 200, @{
        @"idx":     @(idx),
        @"name":    [NSString stringWithUTF8String:nm] ?: @"?",
        @"main":    isMain ? @YES : @NO,
        @"total":   @(total),
        @"shown":   @(syms.count),
        @"symbols": syms,
    });
}

// ============================================================
// MCP (Model Context Protocol) — Streamable HTTP 传输
//
// POST /api/mcp  接收单条 JSON-RPC 消息或批量数组。
//   - 通知(无 id): 回 202 Accepted, 空体。
//   - 请求: 按 Accept 头协商 —— 含 text/event-stream 则以单帧 SSE 返回, 否则 application/json。
//   - initialize 应答带 Mcp-Session-Id 头。
// GET  /api/mcp  不提供服务端主动推流, 回 405 (Streamable HTTP 允许)。
// ============================================================

// 会话头 (所有 MCP 应答都带, 客户端后续请求回带即可)
static NSString *mcp_session_header(void) {
    return [NSString stringWithFormat:@"Mcp-Session-Id: %@\r\n", [MCPServer sessionId]];
}

// 把 JSON 对象作为应答发出: wantsSSE 时包成单帧 SSE, 否则普通 JSON。
static void send_mcp(int fd, id jsonObj, BOOL wantsSSE) {
    NSError *jerr = nil;
    NSData *jd = [NSJSONSerialization dataWithJSONObject:jsonObj options:0 error:&jerr];
    if (!jd) {
        DH_ERR(@"MCP JSON 序列化失败: %@", jerr.localizedDescription);
        send_response(fd, 500, @"Error", @"application/json; charset=utf-8",
                      [@"{\"error\":\"json encode failed\"}" dataUsingEncoding:NSUTF8StringEncoding]);
        return;
    }
    if (wantsSSE) {
        NSString *js = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] ?: @"{}";
        NSData *frame = [[NSString stringWithFormat:@"event: message\ndata: %@\n\n", js]
                         dataUsingEncoding:NSUTF8StringEncoding];
        send_response_ex(fd, 200, @"OK", @"text/event-stream", frame, mcp_session_header());
    } else {
        send_response_ex(fd, 200, @"OK", @"application/json; charset=utf-8", jd, mcp_session_header());
    }
}

static void handle_mcp(int fd, NSString *body, BOOL wantsSSE) {
    NSError *jerr = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:[body dataUsingEncoding:NSUTF8StringEncoding]
                                             options:0 error:&jerr];
    if (!obj) {
        send_mcp(fd, @{@"jsonrpc": @"2.0", @"id": [NSNull null],
                       @"error": @{@"code": @(-32700), @"message": @"Parse error"}}, wantsSSE);
        return;
    }

    // 批量数组: 逐条处理, 收集有应答的; 全是通知则 202。
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *responses = [NSMutableArray array];
        for (id msg in (NSArray *)obj) {
            if (![msg isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *r = [MCPServer handleMessage:msg];
            if (r) [responses addObject:r];
        }
        if (responses.count == 0) {
            send_response_ex(fd, 202, @"Accepted", nil, [NSData data], mcp_session_header());
        } else {
            send_mcp(fd, responses, wantsSSE);
        }
        return;
    }

    if (![obj isKindOfClass:[NSDictionary class]]) {
        send_mcp(fd, @{@"jsonrpc": @"2.0", @"id": [NSNull null],
                       @"error": @{@"code": @(-32600), @"message": @"Invalid Request"}}, wantsSSE);
        return;
    }

    NSDictionary *response = [MCPServer handleMessage:(NSDictionary *)obj];
    if (!response) {
        // 通知: 无应答体
        send_response_ex(fd, 202, @"Accepted", nil, [NSData data], mcp_session_header());
        return;
    }
    send_mcp(fd, response, wantsSSE);
}

static void handle_index(int fd) {
    NSData *body = [NSData dataWithBytes:kDHIndexHTML length:kDHIndexHTML_len];   // 字节数组, 非 NUL 结尾
    send_response(fd, 200, @"OK", @"text/html; charset=utf-8", body);
}

static void handle_wechat_png(int fd) {
    NSData *body = [NSData dataWithBytes:kDHWeChatPNG length:kDHWeChatPNG_len];
    send_response(fd, 200, @"OK", @"image/png", body);
}

// ============================================================
// 请求 dispatch
// ============================================================
static void handle_connection(int fd) {
    // 设置读超时, 防止恶意连接卡死
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    NSMutableData *buf = [NSMutableData data];
    char tmp[4096];
    BOOL gotHeader = NO;
    while (buf.length < DH_HTTP_MAX_HEADER) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        [buf appendBytes:tmp length:(NSUInteger)n];
        if (memmem(buf.bytes, buf.length, "\r\n\r\n", 4)) { gotHeader = YES; break; }
    }
    if (!gotHeader) { close(fd); return; }

    NSString *req = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding];
    if (!req) { close(fd); return; }
    NSArray *lines = [req componentsSeparatedByString:@"\r\n"];
    if (lines.count == 0) { close(fd); return; }
    NSArray *parts = [lines[0] componentsSeparatedByString:@" "];
    if (parts.count < 3) { send_text(fd, 400, @"bad request"); close(fd); return; }
    NSString *method = parts[0];
    NSString *target = parts[1];

    NSString *path; NSString *qs;
    NSRange qrange = [target rangeOfString:@"?"];
    if (qrange.location == NSNotFound) { path = target; qs = @""; }
    else { path = [target substringToIndex:qrange.location]; qs = [target substringFromIndex:qrange.location + 1]; }
    NSDictionary *q = parse_query(qs);

    // Accept 头: MCP 传输据此协商 application/json vs text/event-stream (SSE)。
    BOOL acceptsSSE = NO;
    for (NSString *line in lines) {
        if ([[line lowercaseString] hasPrefix:@"accept:"]) {
            acceptsSSE = ([line rangeOfString:@"text/event-stream"].location != NSNotFound);
            break;
        }
    }

    // 读取请求体(POST import 等需要): 头部已在 buf 中(以 \r\n\r\n 分隔), 按 Content-Length 补齐剩余字节。
    NSString *reqBody = @"";
    if ([method isEqualToString:@"POST"]) {
        const void *he = memmem(buf.bytes, buf.length, "\r\n\r\n", 4);
        if (he) {
            NSUInteger headerLen = (const char *)he - (const char *)buf.bytes + 4;
            NSUInteger clen = 0;
            for (NSString *line in lines) {
                if ([[line lowercaseString] hasPrefix:@"content-length:"])
                    { clen = (NSUInteger)[[line substringFromIndex:15] integerValue]; break; }
            }
            if (clen > DH_HTTP_MAX_BODY) clen = DH_HTTP_MAX_BODY;
            NSMutableData *bodyData = [NSMutableData dataWithBytes:(const char *)buf.bytes + headerLen
                                                           length:buf.length - headerLen];
            while (bodyData.length < clen) {
                ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
                if (n < 0) { if (errno == EINTR) continue; break; }
                if (n == 0) break;
                [bodyData appendBytes:tmp length:(NSUInteger)n];
            }
            if (bodyData.length) reqBody = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding] ?: @"";
        }
    }

    @try {
        if ([method isEqualToString:@"GET"]) {
            if ([path isEqualToString:@"/"] || [path isEqualToString:@"/index.html"]) {
                handle_index(fd);
            } else if ([path isEqualToString:@"/wechat-follow.png"]) {
                handle_wechat_png(fd);
            } else if ([path isEqualToString:@"/api/stats"]) {
                handle_stats(fd);
            } else if ([path isEqualToString:@"/api/logs"]) {
                handle_logs_list(fd, q);
            } else if ([path isEqualToString:@"/api/logs/download"]) {
                handle_logs_download(fd, q);
            } else if ([path isEqualToString:@"/api/noise"]) {
                handle_noise_list(fd, q);
            } else if ([path isEqualToString:@"/api/noise/patterns"]) {
                handle_noise_patterns_get(fd, q);
            } else if ([path isEqualToString:@"/api/capture"]) {
                handle_capture_get(fd);
            } else if ([path isEqualToString:@"/api/spoof"]) {
                handle_spoof_get(fd);
            } else if ([path isEqualToString:@"/api/settings/export"]) {
                handle_settings_export(fd);
            } else if ([path isEqualToString:@"/api/config"]) {
                handle_config_get(fd);
            } else if ([path hasPrefix:@"/api/logs/"]) {
                handle_log_detail(fd, [path substringFromIndex:[@"/api/logs/" length]]);
            } else if ([path isEqualToString:@"/download"]) {
                handle_download(fd);
            } else if ([path isEqualToString:@"/api/dump/images"]) {
                handle_dump_images(fd);
            } else if ([path isEqualToString:@"/api/dump/status"]) {
                handle_dump_status(fd);
            } else if ([path isEqualToString:@"/api/dump/download"]) {
                handle_dump_download(fd, q);
            } else if ([path isEqualToString:@"/api/dump/image"]) {
                handle_dump_image_download(fd, q);
            } else if ([path isEqualToString:@"/api/appicon"]) {
                handle_appicon(fd);
            } else if ([path isEqualToString:@"/api/diag"]) {
                handle_diag(fd, q);
            } else if ([path isEqualToString:@"/api/diag/download"]) {
                handle_diag_download(fd, q);
            } else if ([path isEqualToString:@"/api/symbols/images"]) {
                handle_symbols_images(fd);
            } else if ([path isEqualToString:@"/api/symbols"]) {
                handle_symbols(fd, q);
            } else if ([path isEqualToString:@"/api/files"]) {
                handle_files_list(fd, q);
            } else if ([path isEqualToString:@"/api/files/preview"]) {
                handle_files_preview(fd, q);
            } else if ([path isEqualToString:@"/api/files/download"]) {
                handle_files_download(fd, q);
            } else if ([path isEqualToString:@"/favicon.ico"]) {
                send_response(fd, 204, @"No Content", @"image/x-icon", [NSData data]);
            } else if ([path isEqualToString:@"/api/mcp"]) {
                // MCP over Streamable HTTP: 本服务不提供 GET 主动推流, 按规范回 405。
                send_response_ex(fd, 405, @"Method Not Allowed", @"text/plain; charset=utf-8",
                                 [@"MCP endpoint accepts POST only" dataUsingEncoding:NSUTF8StringEncoding],
                                 @"Allow: POST, OPTIONS\r\n");
            } else {
                send_text(fd, 404, @"not found");
            }
        } else if ([method isEqualToString:@"POST"]) {
            if ([path isEqualToString:@"/api/clear"]) {
                handle_clear(fd, q);
            } else if ([path isEqualToString:@"/api/noise/clear"]) {
                handle_noise_clear(fd, q);
            } else if ([path isEqualToString:@"/api/noise/patterns"]) {
                handle_noise_patterns_set(fd, q);
            } else if ([path isEqualToString:@"/api/pause"]) {
                handle_pause(fd, q);
            } else if ([path isEqualToString:@"/api/capture"]) {
                handle_capture_set(fd, q);
            } else if ([path isEqualToString:@"/api/spoof"]) {
                handle_spoof_set(fd, q);
            } else if ([path isEqualToString:@"/api/settings/import"]) {
                handle_settings_import(fd, reqBody);
            } else if ([path isEqualToString:@"/api/config"]) {
                handle_config_set(fd, q);
            } else if ([path isEqualToString:@"/api/dump"]) {
                handle_dump_start(fd, q);
            } else if ([path isEqualToString:@"/api/mcp"]) {
                handle_mcp(fd, reqBody, acceptsSSE);
            } else {
                send_text(fd, 404, @"not found");
            }
        } else if ([method isEqualToString:@"OPTIONS"]) {
            NSMutableString *h = [NSMutableString string];
            [h appendString:@"HTTP/1.1 204 No Content\r\n"];
            [h appendString:@"Access-Control-Allow-Origin: *\r\n"];
            [h appendString:@"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"];
            [h appendString:@"Access-Control-Allow-Headers: *\r\n"];
            [h appendString:@"Connection: close\r\n\r\n"];
            NSData *hd = [h dataUsingEncoding:NSUTF8StringEncoding];
            write_all(fd, hd.bytes, hd.length);
        } else {
            send_text(fd, 405, @"method not allowed");
        }
    } @catch (NSException *ex) {
        send_text(fd, 500, [NSString stringWithFormat:@"server error: %@", ex.reason]);
    }
    close(fd);
}

// ============================================================
// listen + accept loop
// ============================================================
static int try_bind(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    dh_net_mark_internal_fd(fd);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, DH_HTTP_BACKLOG) != 0) { close(fd); return -1; }
    return fd;
}

static void accept_loop(void) {
    useconds_t backoff = 0;
    while (gListenFD >= 0) {
        struct sockaddr_in client = {0};
        socklen_t clen = sizeof(client);
        int cfd = accept(gListenFD, (struct sockaddr *)&client, &clen);
        if (cfd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (gListenFD < 0) break;
            // EMFILE/ENFILE: fd 耗尽, 指数退避避免 100% CPU
            if (errno == EMFILE || errno == ENFILE) {
                backoff = backoff ? MIN(backoff * 2, (useconds_t)500 * 1000) : 50 * 1000;
                usleep(backoff);
            } else {
                usleep(50 * 1000);
            }
            continue;
        }
        dh_net_mark_internal_fd(cfd);
        backoff = 0;
        int yes = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        // 拿信号量, 超出并发上限就在 accept 线程上等; 这反向给客户端施加压力
        dispatch_semaphore_wait(gConcurrency, DISPATCH_TIME_FOREVER);
        dispatch_async(gWorkerQ, ^{
            handle_connection(cfd);
            dispatch_semaphore_signal(gConcurrency);
        });
    }
}

void dh_http_start(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        for (uint16_t p = DH_HTTP_PORT_FIRST; p <= DH_HTTP_PORT_LAST; p++) {
            int fd = try_bind(p);
            if (fd >= 0) { gListenFD = fd; gPort = p; break; }
        }
        if (gListenFD < 0) {
            NSLog(@"[IOSDecryptHub] HTTP 服务启动失败: %s..%s 端口都被占用", "8088", "8108");
            dh_health_http_fail("端口 8088..8108 全被占用, 本地服务不可用");
            return;
        }
        NSString *ip = get_local_ip();
        gURL = [NSString stringWithFormat:@"http://%@:%u/", ip, (unsigned)gPort];
        gAcceptQ = dispatch_queue_create("com.decrypthelper.http.accept", DISPATCH_QUEUE_SERIAL);
        gWorkerQ = dispatch_queue_create("com.decrypthelper.http.worker", DISPATCH_QUEUE_CONCURRENT);
        gConcurrency = dispatch_semaphore_create(DH_HTTP_MAX_CONCURRENCY);
        dispatch_async(gAcceptQ, ^{ accept_loop(); });
        dh_health_http_ok();
        NSLog(@"[IOSDecryptHub] HTTP 服务已启动: %@", gURL);
    });
}

uint16_t  dh_http_port(void)  { return gPort; }
NSString *dh_http_url(void)   { return gURL ?: @"(not running)"; }
