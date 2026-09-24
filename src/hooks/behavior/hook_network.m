// hook_network.m — 网络抓包 (进程内, TLS 之上, 无需代理/证书/绕 pinning)
//
// 核心原则: 请求一发出就先落一条日志, 有没有响应都不丢包 —— 响应/错误到了再原子替换补全。
//
// 路径:
//   1) swizzle -[<真实任务类> resume]                —— 所有 NSURLSession 任务的请求「先记」入口。
//      每个 task 首个 resume 立刻记一条【只有请求】的完整日志并挂到 task 上, 此刻已落库/落盘。
//      真实 resume 实现在私有具体子类上, 故运行时探测该类再换实现 (打基类会漏)。这一步保证
//      即便请求超时无响应、进程被杀、或走 delegate 无回调, 请求也永远留档。
//   2) swizzle completion-handler 建任务方法  —— 响应/错误到达时, 用【请求+响应】完整条目原子
//      替换 (1) 先记的那条 (保持 seq/位置), 而非新增, 因此不重复、也不丢。覆盖 data /
//      upload(fromData/fromFile) / download 的 completionHandler 调用 (绝大多数 App)。
//      HTTPBody 必须在建任务时快照: 发出请求后原对象上的 body 经常变 nil。download 响应落地为
//      文件(不读内容, 只补响应头/状态码); fromFile 上传体读文件前缀作快照。
//   3) swizzle NSURLConnection 便捷方法              —— 老 API (async/sync 便捷方法)的请求↔响应配对。
//   4) fishhook SSL_write(_ex) / SSL_read(_ex)       —— App 自带 TLS 栈(bundle OpenSSL/BoringSSL、
//      走 import slot)的明文收发。系统 TLS 不经 App import, 多不命中属正常。
//   5) fishhook BSD socket 全家族 + fd 跟踪           —— 自研明文 HTTP/协议栈、TLS ClientHello SNI
//      (socket/accept/close/send/sendto/sendmsg/recv/recvfrom/recvmsg/read/write)。
//   6) fishhook Network.framework + ObjC WebSocket   —— nw_connection_send/receive 明文，
//      以及 NSURLSessionWebSocketTask 的发送/接收/心跳帧。
//
// 替换靠 DHLogStore replaceNetworkEntry:with: (串行队列内换整条不可变对象引用, 读侧零竞态)。
// 全部受 dh_capture_sub_enabled(DH_CAP_NETWORK) 开关控制, 记入 DHCategoryNetwork。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/time.h>
#import <sys/socket.h>
#import <sys/uio.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <pthread.h>
#include <errno.h>
#include <stdatomic.h>
#import "fishhook.h"
#import "log_store.h"
#import "hook_network.h"
#define DH_BOARD DH_DIAG_SYS
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// 挂在 task 上的「先记的请求条目」(eager entry): resume 一发出请求就记一条只有请求的日志并挂这里,
// 响应/错误到达时用完整条目原子替换它。既保证「无响应也留档」, 又不重复记。既是去重标志也是替换句柄。
static const void *kDHNetEntry = &kDHNetEntry;
// 建任务时快照的请求字段, 挂在 task 上。completion 时 HTTPBody 往往已被 URLSession 转成 stream 清掉。
static const void *kDHNetSnap = &kDHNetSnap;
// -[NSMutableURLRequest setHTTPBody:] 当时的副本, 防止 getter 随后返回 nil。
static const void *kDHSetHTTPBody = &kDHSetHTTPBody;

// 请求时刻的 ms/tid —— 配对事件用它做锚点(而非响应到达时刻), 否则慢请求会跳出关联时间窗。
static uint64_t dh_now_ms(void) { struct timeval tv; gettimeofday(&tv, NULL); return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000; }
static uint64_t dh_cur_tid(void) { uint64_t t = 0; pthread_threadid_np(NULL, &t); return t; }

// 建任务瞬间的请求快照。必须在调用 orig 之前取 HTTPBody, 发出去之后原对象上的 body 经常变 nil。
@interface DHNetSnap : NSObject
@property (copy)   NSString *method;
@property (copy)   NSString *url;
@property (copy)   NSDictionary *headers;
@property (strong) NSData *body;
// 请求体缺失时的诚实注记 (如 HTTPBodyStream 未快照), 拼在请求段末尾, 避免被误读成「空 body」。
@property (copy)   NSString *bodyNote;
// 响应段注记 (如下载落地文件名/大小), 拼在响应段末尾。
@property (copy)   NSString *respNote;
// 下载落地文件前缀预览 (走 output 通道, 与请求体 body 槽位无关)。
@property (strong) NSData *dlPreview;
@property (copy)   NSString *callStack;
@property (assign) uint64_t tsMs;
@property (assign) uint64_t tid;
@end
@implementation DHNetSnap
@end

static NSDictionary *dh_merge_headers(NSDictionary *base, NSDictionary *extra) {
    if (!base.count) return extra.count ? [extra copy] : nil;
    if (!extra.count) return [base copy];
    NSMutableDictionary *h = [base mutableCopy];
    [h addEntriesFromDictionary:extra];
    return h;
}

static DHNetSnap *dh_snap_from_request(NSURLRequest *req, id session) {
    DHNetSnap *s = [DHNetSnap new];
    s.method = req.HTTPMethod ?: @"GET";
    s.url = req.URL.absoluteString ?: @"";
    NSMutableDictionary *h = [NSMutableDictionary dictionary];
    if ([session isKindOfClass:[NSURLSession class]]) {
        NSDictionary *add = ((NSURLSession *)session).configuration.HTTPAdditionalHeaders;
        if (add.count) [h addEntriesFromDictionary:add];
    }
    if (req.allHTTPHeaderFields.count) [h addEntriesFromDictionary:req.allHTTPHeaderFields];
    s.headers = h;
    NSData *body = req.HTTPBody;
    if (!body.length) body = objc_getAssociatedObject(req, kDHSetHTTPBody);
    s.body = body;
    // HTTPBodyStream 的字节读出来就会消耗原流 (系统随后还要用它发包), 且超长流无法无损重建,
    // 故只做诚实标注、不读内容。AFNetworking multipart 等上传走的正是这条路。
    if (!body.length && req.HTTPBodyStream)
        s.bodyNote = @"[request body carried by HTTPBodyStream — not captured]";
    s.callStack = DHCallStackFiltered();
    s.tsMs = dh_now_ms();
    s.tid = dh_cur_tid();
    return s;
}

static void dh_attach_snap(id task, DHNetSnap *snap) {
    if (task && snap) objc_setAssociatedObject(task, kDHNetSnap, snap, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static void (*orig_setHTTPBody)(id, SEL, NSData *) = NULL;
static void swz_setHTTPBody(id self, SEL _cmd, NSData *body) {
    if (body) objc_setAssociatedObject(self, kDHSetHTTPBody, body, OBJC_ASSOCIATION_COPY_NONATOMIC);
    if (orig_setHTTPBody) orig_setHTTPBody(self, _cmd, body);
}

// ============================================================
// 记录
// ============================================================

// 单向记录 (SSL send/recv 用)。
// 通用 socket 层会经过 read/write/sendmsg 等高频入口, 记录期间再触发被 hook 的
// Foundation/socket 调用会造成递归。这里用线程局部深度闸门, 只影响本 dylib 自己的
// 日志构造, 不影响原 API 的正常调用。
static _Thread_local int g_dh_net_log_depth = 0;
static void net_log(NSString *algo, NSString *op, NSString *detail, NSData *body) {
    if (g_dh_net_log_depth || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    g_dh_net_log_depth++;
    @try {
        DHLogEntry *e = [DHLogEntry new];
        e.category = DHCategoryNetwork; e.algorithm = algo; e.operation = op;
        e.detail = detail ?: @""; e.input = body;
        e.timestamp = DHTimestampNow(); e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    } @finally {
        g_dh_net_log_depth--;
    }
}

// ============================================================
// 通用 socket 抓取辅助
//
// 目标不是“看见所有密文”, 而是把不同 App 自行实现网络栈时暴露的明文边界统一接住:
//   socket/accept/close : 维护 fd 生命周期, 只为后续 read/write 变体限定作用域
//   send/sendto/sendmsg/write : 明文 HTTP/WebSocket/JSON 等可读 payload, 以及 TLS SNI
//   recv/recvfrom/recvmsg/read : 明文响应 payload
//
// 只记录“像文本”的 payload 且最多 8KB, TLS 密文/随机二进制直接跳过。这样既能覆盖
// 自研明文协议, 也不会把每个 App 的媒体流、压缩包和大二进制块灌进日志。
// ============================================================

#define DH_NET_FD_MAX       4096
#define DH_NET_PAYLOAD_MAX  (8 * 1024)

static NSString *dh_sni_from_client_hello(const uint8_t *b, size_t n);

enum {
    DH_NET_FD_UNKNOWN  = 0,
    DH_NET_FD_SOCKET   = 1,
    DH_NET_FD_INTERNAL = 2,
};

static _Atomic uint8_t g_dh_fd_state[DH_NET_FD_MAX];

static void dh_net_set_fd_state(int fd, uint8_t state) {
    if (fd >= 0 && fd < DH_NET_FD_MAX)
        atomic_store_explicit(&g_dh_fd_state[fd], state, memory_order_relaxed);
}

void dh_net_mark_internal_fd(int fd) {
    dh_net_set_fd_state(fd, DH_NET_FD_INTERNAL);
}

static BOOL dh_net_is_external_socket_fd(int fd) {
    if (fd < 0 || fd >= DH_NET_FD_MAX) return NO;
    return atomic_load_explicit(&g_dh_fd_state[fd], memory_order_relaxed) == DH_NET_FD_SOCKET;
}

static BOOL dh_net_is_internal_fd(int fd) {
    if (fd < 0 || fd >= DH_NET_FD_MAX) return NO;
    return atomic_load_explicit(&g_dh_fd_state[fd], memory_order_relaxed) == DH_NET_FD_INTERNAL;
}

static NSData *dh_net_prefix_data(const void *bytes, size_t len) {
    if (!bytes || len == 0) return nil;
    size_t n = MIN(len, (size_t)DH_NET_PAYLOAD_MAX);
    return [NSData dataWithBytes:bytes length:n];
}

// 廉价文本判定: 前 256B 不允许出现 NUL/常见控制字节, 并且必须满足以下之一:
//   1) ASCII 可见字符占比 >= 70%, 且至少含一个字母/数字;
//   2) 剩余字节是合法 UTF-8(应对中文 JSON/表单, 不把高字节随机流当文本)。
// 这样能挡住随机密文、TLS frame 和大多数二进制协议, 同时保留 HTTP/JSON/表单明文。
static BOOL dh_net_payload_is_text(const uint8_t *p, size_t len) {
    if (!p || len < 2) return NO;
    if (len >= 6 && p[0] == 0x16 && p[1] == 0x03) return NO;   // TLS record
    size_t sample = MIN(len, (size_t)256);
    size_t bad = 0, asciiVisible = 0, alnum = 0;
    for (size_t i = 0; i < sample; i++) {
        uint8_t c = p[i];
        if (c == 0) return NO;
        if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) {
            bad++;
        } else if (c >= 0x20 && c <= 0x7e) {
            asciiVisible++;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
                alnum++;
        }
    }
    if (bad > sample / 32) return NO;
    if (alnum == 0) return NO;
    if (asciiVisible * 100 >= sample * 70) return YES;
    NSString *utf8 = [[NSString alloc] initWithBytes:p length:len encoding:NSUTF8StringEncoding];
    return utf8 != nil;
}

static void dh_net_capture_outbound(int fd, const void *bytes, size_t len,
                                    NSString *algo, NSString *sniAlgo, NSString *detail) {
    (void)fd;
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK) || !bytes || len == 0) return;
    const uint8_t *p = (const uint8_t *)bytes;
    if (len >= 6 && p[0] == 0x16 && p[1] == 0x03) {
        NSString *sni = dh_sni_from_client_hello(p, MIN(len, (size_t)4096));
        if (sni.length)
            net_log(sniAlgo, @"sni", [NSString stringWithFormat:@"%@ %@", detail, sni], nil);
        return;
    }
    if (!dh_net_payload_is_text(p, len)) return;
    net_log(algo, @"send", [NSString stringWithFormat:@"%@ len=%zu", detail, len],
            dh_net_prefix_data(bytes, len));
}

static void dh_net_capture_inbound(int fd, const void *bytes, size_t len,
                                   NSString *algo, NSString *detail) {
    (void)fd;
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK) || !bytes || len == 0) return;
    if (!dh_net_payload_is_text((const uint8_t *)bytes, len)) return;
    net_log(algo, @"recv", [NSString stringWithFormat:@"%@ len=%zu", detail, len],
            dh_net_prefix_data(bytes, len));
}

static void net_append_headers(NSMutableString *d, NSDictionary *hdrs) {
    if (!hdrs.count) return;
    for (id k in hdrs) [d appendFormat:@"%@: %@\n", k, hdrs[k]];
}

// 构造一条网络 entry (不落库): input=请求体 / output=响应体。
// tsMs/tid 为「请求构建时刻」的值(不是响应到达时刻), 保证与算 Header 的 crypto 落在同一时间窗/线程。
// detail 用 \x1e 分成「纯请求 / 纯响应 / 错误」三段, 请求段只有 METHOD URL + Header: value, 不加任何标签。
// 响应三元(respData/resp/err)全 nil 时即「只有请求」的条目 —— 无响应也照样成条, 绝不因此丢弃。
static DHLogEntry *dh_net_make_entry(NSString *method, NSString *urlStr, NSDictionary *reqHdrs, NSData *reqBody,
                                     NSString *bodyNote, NSData *respData, NSURLResponse *resp, NSString *respNote,
                                     NSError *err, NSString *callStack,
                                     uint64_t tsMs, uint64_t tid) {
    NSMutableString *req = [NSMutableString stringWithFormat:@"%@ %@\n", method ?: @"GET", urlStr ?: @"?"];
    net_append_headers(req, reqHdrs);
    if (bodyNote.length) [req appendFormat:@"%@\n", bodyNote];
    NSMutableString *respPart = [NSMutableString string];
    if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
        [respPart appendFormat:@"%ld\n", (long)http.statusCode];
        net_append_headers(respPart, http.allHeaderFields);
    }
    if (respNote.length) [respPart appendFormat:@"%@\n", respNote];
    NSString *errPart = err.localizedDescription ?: @"";
    NSString *d = [NSString stringWithFormat:@"%@\x1e%@\x1e%@", req, respPart, errPart];

    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryNetwork;
    e.algorithm = @"HTTP";
    e.operation = method ?: @"GET";
    e.detail    = d;
    e.input       = reqBody;      // 请求体
    e.output      = respData;     // 响应体
    e.timestamp   = DHTimestampNow();
    e.timestampMs = tsMs;         // 请求时刻 (供 correlate_request 锚点)
    e.threadId    = tid;          // 请求线程
    e.callStack   = callStack ?: DHCallStackFiltered();
    return e;
}

// 一次性追加一条完整配对记录 (无 task 身份可挂时用: NSURLConnection 便捷方法等)。
static void net_log_pair(NSString *method, NSString *urlStr, NSDictionary *reqHdrs, NSData *reqBody,
                         NSData *respData, NSURLResponse *resp, NSError *err, NSString *callStack,
                         uint64_t tsMs, uint64_t tid) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    [[DHLogStore shared] append:dh_net_make_entry(method, urlStr, reqHdrs, reqBody, nil,
                                                  respData, resp, nil, err, callStack, tsMs, tid)];
}

// ============================================================
// 1) completion-handler 建任务 (请求↔响应配对)
// ============================================================
typedef void (^DHDataCH)(NSData *, NSURLResponse *, NSError *);

static id (*orig_dtReqCH)(id, SEL, NSURLRequest *, DHDataCH) = NULL;
static id (*orig_dtURLCH)(id, SEL, NSURL *, DHDataCH) = NULL;
static id (*orig_upReqCH)(id, SEL, NSURLRequest *, NSData *, DHDataCH) = NULL;
static id (*orig_dtReq)(id, SEL, NSURLRequest *) = NULL;
static id (*orig_upReq)(id, SEL, NSURLRequest *, NSData *) = NULL;

// 下载任务 completion 块签名: (下载落地临时文件 URL, 响应, 错误)。响应体是磁盘文件, 不读内容,
// 只配对 URL+状态码+响应头(请求仍完整), 把「请求-only」升级成「请求↔响应」记录。
typedef void (^DHDownloadCH)(NSURL *, NSURLResponse *, NSError *);
static id (*orig_dlReqCH)(id, SEL, NSURLRequest *, DHDownloadCH) = NULL;
static id (*orig_dlURLCH)(id, SEL, NSURL *, DHDownloadCH) = NULL;
// 断点续传下载: 入参是 resume data(二进制 blob), 此刻拿不到 URLRequest。
static id (*orig_dlResumeCH)(id, SEL, NSData *, DHDownloadCH) = NULL;
// 文件上传: body 是磁盘文件, 建任务时读一段前缀当请求体快照 (完整文件可能是大视频, 必须限长)。
static id (*orig_upFileCH)(id, SEL, NSURLRequest *, NSURL *, DHDataCH) = NULL;
static id (*orig_upFile)(id, SEL, NSURLRequest *, NSURL *) = NULL;

// fromFile 上传体前缀上限: 只取头部足够分析(magic/头部结构), 避免把整段大文件塞进日志内存。
#define DH_NET_MAX_FILE_BODY (1 * 1024 * 1024)

// 读文件 URL 前缀作请求体快照。用 NSFileHandle readDataOfLength: 只读头部, 不映射整文件;
// 全程 @try/@catch, 任何异常静默降级返回 nil (不崩宿主)。
static NSData *dh_body_from_fileurl(NSURL *fileURL) {
    if (![fileURL isKindOfClass:[NSURL class]] || !fileURL.isFileURL) return nil;
    NSData *out = nil;
    @try {
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingFromURL:fileURL error:NULL];
        if (fh) {
            out = [fh readDataOfLength:DH_NET_MAX_FILE_BODY];
            @try { [fh closeFile]; } @catch (__unused NSException *e) {}
        }
    } @catch (__unused NSException *e) { out = nil; }
    return out.length ? out : nil;
}

// dataTaskWithURL:/downloadTaskWithURL: 没有 NSURLRequest, 用 URL 直接造快照, 让 resume 与
// completion 共用同一份请求锚点(时刻/调用栈/URL), 保证「请求先记、响应后配」两步落到同一条。
static DHNetSnap *dh_snap_from_url(NSURL *url, NSString *method) {
    DHNetSnap *s = [DHNetSnap new];
    s.method = method ?: @"GET";
    s.url = url.absoluteString ?: @"";
    s.headers = nil;
    s.body = nil;
    s.callStack = DHCallStackFiltered();
    s.tsMs = dh_now_ms();
    s.tid = dh_cur_tid();
    return s;
}

// 响应/错误到达: 构造「请求+响应」完整条目, 原子替换 resume 时先记的「只有请求」条目 (kDHNetEntry)。
// 若该 task 没有先记条目(极少数: resume 没命中), 退化为直接追加一条完整记录, 绝不丢包。
static void dh_net_enrich(id task, DHNetSnap *snap, NSData *respData, NSURLResponse *resp, NSError *err) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    NSURLRequest *cur = [task isKindOfClass:[NSURLSessionTask class]] ? [(NSURLSessionTask *)task currentRequest] : nil;
    NSDictionary *hdrs = dh_merge_headers(snap.headers, cur.allHTTPHeaderFields);
    NSData *body = snap.body ?: cur.HTTPBody;
    if (!body.length) body = objc_getAssociatedObject(cur, kDHSetHTTPBody);
    DHLogEntry *full = dh_net_make_entry(snap.method, snap.url, hdrs, body, snap.bodyNote,
                                         respData, resp, snap.respNote, err, snap.callStack, snap.tsMs, snap.tid);
    DHLogEntry *eager = task ? objc_getAssociatedObject(task, kDHNetEntry) : nil;
    if (eager) {
        [[DHLogStore shared] replaceNetworkEntry:eager with:full];
        objc_setAssociatedObject(task, kDHNetEntry, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    } else {
        [[DHLogStore shared] append:full];
    }
}

// -[NSURLSession dataTaskWithRequest:completionHandler:]
// 建任务时挂快照; resume 会先记「只有请求」的条目; 这里响应到达时原子替换成完整条目。
static id swz_dtReqCH(id self, SEL _cmd, NSURLRequest *req, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtReqCH(self, _cmd, req, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_dtReqCH(self, _cmd, req, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession dataTaskWithURL:completionHandler:]
static id swz_dtURLCH(id self, SEL _cmd, NSURL *url, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtURLCH(self, _cmd, url, ch);
    DHNetSnap *snap = dh_snap_from_url(url, @"GET");
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_dtURLCH(self, _cmd, url, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]
static id swz_upReqCH(id self, SEL _cmd, NSURLRequest *req, NSData *bodyData, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_upReqCH(self, _cmd, req, bodyData, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    if (bodyData.length) snap.body = bodyData;
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_upReqCH(self, _cmd, req, bodyData, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// 无 completion 的建任务: 只快照 body/头, 响应仍走 resume 兜底(只有请求)。
static id swz_dtReq(id self, SEL _cmd, NSURLRequest *req) {
    if (!orig_dtReq) return nil;
    id task = orig_dtReq(self, _cmd, req);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap))
        dh_attach_snap(task, dh_snap_from_request(req, self));
    return task;
}

static id swz_upReq(id self, SEL _cmd, NSURLRequest *req, NSData *bodyData) {
    if (!orig_upReq) return nil;
    id task = orig_upReq(self, _cmd, req, bodyData);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap)) {
        DHNetSnap *snap = dh_snap_from_request(req, self);
        if (bodyData.length) snap.body = bodyData;
        dh_attach_snap(task, snap);
    }
    return task;
}

// 下载落地文件预览上限: 只读头部作 output 预览(magic/文本头), 不把整文件塞进日志内存。
// 落盘 blob 另有 64KB 上限, 这里取同样量级。
#define DH_NET_MAX_DOWNLOAD_PREVIEW (64 * 1024)

// 下载完成: 读落地文件前缀作响应体预览 + 文件名/大小注记。必须在原 ch 被调用前同步读完,
// 系统随后可能删除该临时文件。全程 @try/@catch, 失败降级为原来的 nil(只配对状态码)。
static void dh_snap_download_preview(DHNetSnap *snap, NSURL *location, NSURLResponse *resp) {
    if (!snap || !location.isFileURL) return;
    @try {
        NSString *name = resp.suggestedFilename ?: location.lastPathComponent ?: @"?";
        unsigned long long size = 0;
        NSNumber *sz = nil;
        if ([location getResourceValue:&sz forKey:NSURLFileSizeKey error:NULL] && sz)
            size = sz.unsignedLongLongValue;
        NSData *head = dh_body_from_fileurl(location);
        if (head.length > DH_NET_MAX_DOWNLOAD_PREVIEW)
            head = [head subdataWithRange:NSMakeRange(0, DH_NET_MAX_DOWNLOAD_PREVIEW)];
        // dh_body_from_fileurl 上限 1MB, 这里再压到 64KB 预览。
        snap.dlPreview = head.length ? head : nil;
        snap.respNote = [NSString stringWithFormat:@"[download] %@ (%llu bytes%@)", name, size,
                         head.length ? @", head preview captured" : @""];
    } @catch (__unused NSException *e) {}
}

// -[NSURLSession downloadTaskWithRequest:completionHandler:] —— 响应落地为文件, 取 64KB 前缀
// 作响应体预览, 仍把 resume 先记的「只有请求」条目原子替换成完整条目。
static id swz_dlReqCH(id self, SEL _cmd, NSURLRequest *req, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlReqCH(self, _cmd, req, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlReqCH(self, _cmd, req, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession downloadTaskWithURL:completionHandler:]
static id swz_dlURLCH(id self, SEL _cmd, NSURL *url, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlURLCH(self, _cmd, url, ch);
    DHNetSnap *snap = dh_snap_from_url(url, @"GET");
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlURLCH(self, _cmd, url, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession downloadTaskWithResumeData:completionHandler:] —— 断点续传下载。
// 建任务时请求对象还没解析出来（入参是 resume data），所以只挂空快照 + 说明，
// 真正的 METHOD/URL/Header 由 resume 时的兜底路径补上；响应照常配对为完整条目。
static id swz_dlResumeCH(id self, SEL _cmd, NSData *resumeData, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlResumeCH(self, _cmd, resumeData, ch);
    DHNetSnap *snap = dh_snap_from_request(nil, self);
    snap.bodyNote = @"[resume] 断点续传下载，请求体不适用";
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlResumeCH(self, _cmd, resumeData, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession uploadTaskWithRequest:fromFile:completionHandler:] —— 请求体取自磁盘文件前缀。
static id swz_upFileCH(id self, SEL _cmd, NSURLRequest *req, NSURL *fileURL, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_upFileCH(self, _cmd, req, fileURL, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    if (!snap.body.length) { NSData *fb = dh_body_from_fileurl(fileURL); if (fb.length) snap.body = fb; }
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_upFileCH(self, _cmd, req, fileURL, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// 无 completion 的 fromFile 上传: 只快照请求(含文件前缀 body), 响应走 resume 兜底(只有请求)。
static id swz_upFile(id self, SEL _cmd, NSURLRequest *req, NSURL *fileURL) {
    if (!orig_upFile) return nil;
    id task = orig_upFile(self, _cmd, req, fileURL);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap)) {
        DHNetSnap *snap = dh_snap_from_request(req, self);
        if (!snap.body.length) { NSData *fb = dh_body_from_fileurl(fileURL); if (fb.length) snap.body = fb; }
        dh_attach_snap(task, snap);
    }
    return task;
}

static BOOL swz_instance(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

// ============================================================
// 2) resume: 请求一发出就先记一条「只有请求」的条目 (无响应也留档)
// ============================================================
// 每个 task 首次 resume 时立刻记录请求并把该条目挂到 task(kDHNetEntry)。这条日志此刻已完整落库/落盘,
// 即使随后请求超时无响应、宿主进程被杀、或走 delegate 无回调, 请求都不会丢。响应/错误到达时(见
// dh_net_enrich)再用完整条目原子替换本条 —— 有响应则补全, 没有就永远保留为「只有请求」。
static void (*orig_task_resume)(id, SEL) = NULL;
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if (dh_capture_sub_enabled(DH_CAP_NETWORK) &&
            !objc_getAssociatedObject(self, kDHNetEntry)) {   // 每个 task 只在首个 resume 记一次
            NSURLSessionTask *task = (NSURLSessionTask *)self;
            NSURLRequest *req = task.currentRequest ?: task.originalRequest;
            DHNetSnap *snap = objc_getAssociatedObject(self, kDHNetSnap);
            NSString *urlStr = snap.url.length ? snap.url : req.URL.absoluteString;
            if (urlStr.length) {
                NSString *method = snap.method ?: (req.HTTPMethod ?: @"GET");
                NSDictionary *hdrs = dh_merge_headers(snap.headers, req.allHTTPHeaderFields);
                NSData *body = snap.body ?: req.HTTPBody;
                if (!body.length) body = objc_getAssociatedObject(req, kDHSetHTTPBody);
                // WebSocket 任务不走 data/upload 建任务 swizzle、无 completion 配对, resume 兜底是
                // 唯一记录点: 握手请求能留档, 但 101 之后的消息帧不在覆盖内, 诚实标注。
                NSString *note = snap.bodyNote;
                if (!note.length && [self respondsToSelector:@selector(sendMessage:completionHandler:)])
                    note = @"[websocket handshake — message frames not captured]";
                // 只记请求段(响应/错误留空); 保留请求时刻/线程/调用栈, 便于与 crypto 关联。
                DHLogEntry *eager = dh_net_make_entry(method, urlStr, hdrs, body, note,
                                                      nil, nil, nil, nil,
                                                      snap.callStack ?: DHCallStackFiltered(),
                                                      snap.tsMs ? snap.tsMs : dh_now_ms(),
                                                      snap.tid ? snap.tid : dh_cur_tid());
                objc_setAssociatedObject(self, kDHNetEntry, eager, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                [[DHLogStore shared] append:eager];
            }
        }
    } @catch (__unused NSException *ex) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// resume 兜底装载: -[NSURLSessionTask resume] 的真实实现常落在私有具体子类
// (__NSCFURLSessionTask / __NSCFLocalDownloadTask ...)上, 直接 swizzle 基类会打空 → delegate
// 型任务的请求全部漏抓。这里造一个不 resume 的探针任务, 沿其类继承链向上找「自身真正实现 resume」
// 的那个类再换实现, 与 FLEX/AFNetworking 同法。全程 @try/@catch, 失败回退基类。
static void install_resume_hook(void) {
    Class baseCls = NSClassFromString(@"NSURLSessionTask");
    Class implCls = baseCls;
    @try {
        NSURLSession *sess = [NSURLSession sharedSession];
        // 用 dataTaskWithURL: (未被本模块 swizzle、绝不 resume)造探针, 只为读它的具体类。
        id probe = [sess dataTaskWithURL:[NSURL URLWithString:@"http://127.0.0.1/"]];
        if (probe) {
            Class c = object_getClass(probe);
            while (c && c != [NSObject class]) {
                unsigned int n = 0;
                Method *ms = class_copyMethodList(c, &n);
                BOOL found = NO;
                for (unsigned int i = 0; i < n; i++)
                    if (method_getName(ms[i]) == @selector(resume)) { found = YES; break; }
                if (ms) free(ms);
                if (found) { implCls = c; break; }
                c = class_getSuperclass(c);
            }
            @try { [probe cancel]; } @catch (__unused NSException *e) {}
        }
    } @catch (__unused NSException *e) { implCls = baseCls; }
    if (!implCls) implCls = baseCls;

    Method m = implCls ? class_getInstanceMethod(implCls, @selector(resume)) : NULL;
    if (m) {
        orig_task_resume = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)swz_task_resume);
    } else {
        dh_health_hook_fail(DH_DIAG_SYS, "-[NSURLSessionTask resume]");
    }
}

static void install_urlsession_hook(void) {
    // 配对: 在「shared session 的真实类」上换 completion 建任务方法 (custom session 同为该私有类)
    Class sc = object_getClass([NSURLSession sharedSession]) ?: NSClassFromString(@"NSURLSession");
    swz_instance(sc, @selector(dataTaskWithRequest:completionHandler:),          (IMP)swz_dtReqCH, (IMP *)&orig_dtReqCH);
    swz_instance(sc, @selector(dataTaskWithURL:completionHandler:),              (IMP)swz_dtURLCH, (IMP *)&orig_dtURLCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromData:completionHandler:),(IMP)swz_upReqCH, (IMP *)&orig_upReqCH);
    swz_instance(sc, @selector(dataTaskWithRequest:),                         (IMP)swz_dtReq, (IMP *)&orig_dtReq);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromData:),            (IMP)swz_upReq, (IMP *)&orig_upReq);
    // 下载 / 文件上传 completion 建任务 (响应配对 + fromFile 请求体快照)
    swz_instance(sc, @selector(downloadTaskWithRequest:completionHandler:),      (IMP)swz_dlReqCH, (IMP *)&orig_dlReqCH);
    swz_instance(sc, @selector(downloadTaskWithURL:completionHandler:),          (IMP)swz_dlURLCH, (IMP *)&orig_dlURLCH);
    swz_instance(sc, @selector(downloadTaskWithResumeData:completionHandler:),   (IMP)swz_dlResumeCH, (IMP *)&orig_dlResumeCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromFile:completionHandler:),(IMP)swz_upFileCH, (IMP *)&orig_upFileCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromFile:),                 (IMP)swz_upFile, (IMP *)&orig_upFile);

    Class mreq = NSClassFromString(@"NSMutableURLRequest");
    if (!swz_instance(mreq, @selector(setHTTPBody:), (IMP)swz_setHTTPBody, (IMP *)&orig_setHTTPBody))
        dh_health_hook_fail(DH_DIAG_SYS, "-[NSMutableURLRequest setHTTPBody:]");

    // 兜底: resume (delegate 型任务的请求) —— 定位真实实现类, 避免打空基类
    install_resume_hook();
}

// ============================================================
// 2.5) NSURLSessionWebSocketTask —— WebSocket 帧 (通用, 不依赖具体 App)
//
// resume 兜底只能记录握手请求; 101 之后的帧不经过 data/upload completion。这里在
// 发送/接收两个公开入口上做 record-only swizzle, 只记录消息内容, 不改写、不延迟、
// 不干预 completion 调用。帧内容同样限长 8KB。
// ============================================================
typedef void (^DHWSErrorCompletion)(NSError *);
typedef void (^DHWSMessageCompletion)(NSURLSessionWebSocketMessage *, NSError *);

static void dh_ws_log_message(id message, NSString *op, NSString *detail) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK) || !message) return;
    NSData *body = nil;
    NSString *kind = @"unknown";
    @try {
        if ([message respondsToSelector:@selector(data)]) {
            NSData *d = [message data];
            if (d.length) { body = d; kind = @"data"; }
        }
        if (!body.length && [message respondsToSelector:@selector(string)]) {
            NSString *s = [message string];
            if (s.length) { body = [s dataUsingEncoding:NSUTF8StringEncoding]; kind = @"string"; }
        }
    } @catch (__unused NSException *e) {}
    if (!body.length) return;
    net_log(@"WS", op, [NSString stringWithFormat:@"%@ kind=%@ len=%lu", detail, kind,
                        (unsigned long)body.length],
            dh_net_prefix_data(body.bytes, body.length));
}

static void (*orig_ws_send)(id, SEL, NSURLSessionWebSocketMessage *, DHWSErrorCompletion) = NULL;
static void swz_ws_send(id self, SEL _cmd, NSURLSessionWebSocketMessage *message,
                        DHWSErrorCompletion completion) {
    dh_ws_log_message(message, @"send", @"ws");
    if (orig_ws_send) orig_ws_send(self, _cmd, message, completion);
}

static void (*orig_ws_receive)(id, SEL, DHWSMessageCompletion) = NULL;
static void swz_ws_receive(id self, SEL _cmd, DHWSMessageCompletion completion) {
    if (!completion) {
        if (orig_ws_receive) orig_ws_receive(self, _cmd, completion);
        return;
    }
    DHWSMessageCompletion wrapped = ^(NSURLSessionWebSocketMessage *message, NSError *error) {
        dh_ws_log_message(message, @"recv", @"ws");
        completion(message, error);
    };
    if (orig_ws_receive) orig_ws_receive(self, _cmd, wrapped);
}

static void (*orig_ws_ping)(id, SEL, DHWSErrorCompletion) = NULL;
static void swz_ws_ping(id self, SEL _cmd, DHWSErrorCompletion completion) {
    if (dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"WS", @"ping", @"ws ping", nil);
    if (orig_ws_ping) orig_ws_ping(self, _cmd, completion);
}

static Class dh_impl_class_for_selector(Class start, SEL sel) {
    for (Class c = start; c && c != [NSObject class]; c = class_getSuperclass(c)) {
        unsigned int n = 0;
        Method *ms = class_copyMethodList(c, &n);
        BOOL found = NO;
        for (unsigned int i = 0; i < n; i++) {
            if (method_getName(ms[i]) == sel) { found = YES; break; }
        }
        if (ms) free(ms);
        if (found) return c;
    }
    return nil;
}

static void install_websocket_hooks(void) {
    Class cls = NSClassFromString(@"NSURLSessionWebSocketTask");
    if (!cls) return;   // 低版本系统没有该类, 保持原行为

    // webSocketTaskWithURL: 返回的是私有具体子类；方法常被该子类自己实现，
    // 只打抽象基类会像旧的 NSURLSessionTask.resume 一样完全打空。
    Class probeClass = nil;
    @try {
        NSURLSessionWebSocketTask *probe =
            [[NSURLSession sharedSession] webSocketTaskWithURL:[NSURL URLWithString:@"ws://127.0.0.1:1/"]];
        if (probe) probeClass = object_getClass(probe);
        @try { [probe cancelWithCloseCode:NSURLSessionWebSocketCloseCodeNormalClosure reason:nil]; }
        @catch (__unused NSException *e) {}
    } @catch (__unused NSException *e) {}

    Class sendCls = dh_impl_class_for_selector(probeClass ?: cls, @selector(sendMessage:completionHandler:)) ?: cls;
    Class recvCls = dh_impl_class_for_selector(probeClass ?: cls, @selector(receiveMessageWithCompletionHandler:)) ?: cls;
    Class pingCls = dh_impl_class_for_selector(probeClass ?: cls, @selector(sendPingWithPongReceiveHandler:)) ?: cls;
    swz_instance(sendCls, @selector(sendMessage:completionHandler:),
                 (IMP)swz_ws_send, (IMP *)&orig_ws_send);
    swz_instance(recvCls, @selector(receiveMessageWithCompletionHandler:),
                 (IMP)swz_ws_receive, (IMP *)&orig_ws_receive);
    swz_instance(pingCls, @selector(sendPingWithPongReceiveHandler:),
                 (IMP)swz_ws_ping, (IMP *)&orig_ws_ping);
}

// ============================================================
// 3) SSL_write / SSL_read 明文 (fishhook, best-effort; void* 占位 SSL 免依赖)
// ============================================================
static int (*orig_SSL_write)(void *, const void *, int) = NULL;
static int (*orig_SSL_read)(void *, void *, int) = NULL;

static int hooked_SSL_write(void *ssl, const void *buf, int num) {
    if (num > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"send", [NSString stringWithFormat:@"SSL=%p len=%d", ssl, num],
                [NSData dataWithBytes:buf length:(NSUInteger)num]);
    return orig_SSL_write ? orig_SSL_write(ssl, buf, num) : 0;
}
static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int r = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : 0;
    if (r > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"recv", [NSString stringWithFormat:@"SSL=%p len=%d", ssl, r],
                [NSData dataWithBytes:buf length:(NSUInteger)r]);
    return r;
}

// OpenSSL 1.1.1+ 的 *_ex 变体: 成功返回 1, 实际收发字节写入出参。BoringSSL/新 OpenSSL 常走这两个,
// 只 hook SSL_write/read 会漏。未被 App 导入时 fishhook 不会绑定, orig 保持 NULL, hook 亦不触发。
static int (*orig_SSL_write_ex)(void *, const void *, size_t, size_t *) = NULL;
static int (*orig_SSL_read_ex)(void *, void *, size_t, size_t *) = NULL;

static int hooked_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    int r = orig_SSL_write_ex ? orig_SSL_write_ex(ssl, buf, num, written) : 0;
    if (r == 1 && buf && written && *written > 0 && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"send", [NSString stringWithFormat:@"SSL=%p len=%zu", ssl, *written],
                [NSData dataWithBytes:buf length:*written]);
    return r;
}
static int hooked_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    int r = orig_SSL_read_ex ? orig_SSL_read_ex(ssl, buf, num, readbytes) : 0;
    if (r == 1 && buf && readbytes && *readbytes > 0 && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"recv", [NSString stringWithFormat:@"SSL=%p len=%zu", ssl, *readbytes],
                [NSData dataWithBytes:buf length:*readbytes]);
    return r;
}
static void install_ssl_hooks(void) {
    struct rebinding r[] = {
        {"SSL_write",    hooked_SSL_write,    (void **)&orig_SSL_write},
        {"SSL_read",     hooked_SSL_read,     (void **)&orig_SSL_read},
        {"SSL_write_ex", hooked_SSL_write_ex, (void **)&orig_SSL_write_ex},
        {"SSL_read_ex",  hooked_SSL_read_ex,  (void **)&orig_SSL_read_ex},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r) / sizeof(r[0]));
}

// ============================================================
// 3.5) 自研网络栈兜底: 原生 socket + Apple SecureTransport + Network.framework
//
// 为什么需要这一层: 部分 App(iOS 版 B站等)用内嵌 BoringSSL/Cronet + 裸 BSD socket 发请求,
// 既不经过 NSURLSession / NSURLConnection, 也不调用 OpenSSL 的 SSL_write —— 上面的 1)~3)
// 对它完全隐形(实测: 登录 POST 只能看到 connect/getaddrinfo 命中, 报文一个字节都拿不到)。
// 这一层不解密, 只回答「谁在连、连到哪、TLS 对端是谁」:
//   - getaddrinfo : 域名解析 (知道 App 访问了哪些主机)
//   - connect     : fd → ip:port
//   - send        : 嗅 TLS ClientHello 的 SNI(握手段是明文), 把连接和域名对上号
//   - SSLWrite/SSLRead : Apple SecureTransport 的明文读写(注意与 OpenSSL 的 SSL_write 命名不同)
//   - nw_connection_send : Network.framework 的发送入口
// 全部受 DH_CAP_NETWORK 开关控制, 与既有事件同一条时间线。
// ============================================================

typedef int32_t DHOSStatus;   // Apple OSStatus

static NSString *dh_sockaddr_str(const struct sockaddr *sa) {
    if (!sa) return nil;
    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
        if (!inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host))) return nil;
        port = ntohs(v4->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        if (!inet_ntop(AF_INET6, &v6->sin6_addr, host, sizeof(host))) return nil;
        port = ntohs(v6->sin6_port);
    } else {
        return [NSString stringWithFormat:@"family=%d", sa->sa_family];
    }
    return [NSString stringWithFormat:@"%s:%u", host, (unsigned)port];
}

// 从 TLS ClientHello 里解 SNI。只读握手明文段, 不做任何解密。
// 尽力而为: 完整 ClientHello 被拆成多次 send 时(极罕见)返回 nil, 不做分片缓存。
static NSString *dh_sni_from_client_hello(const uint8_t *b, size_t n) {
    if (!b || n < 6) return nil;
    if (b[0] != 0x16 || b[1] != 0x03) return nil;    // TLS handshake record
    if (b[5] != 0x01) return nil;                    // ClientHello
    size_t i = 9;                                    // record(5) + handshake header(4)
    if (i + 34 > n) return nil;
    i += 2 + 32;                                     // client_version + random
    i += 1 + (size_t)b[i];                           // session_id
    if (i + 2 > n) return nil;
    size_t cs = ((size_t)b[i] << 8) | (size_t)b[i + 1];
    i += 2 + cs;                                     // cipher_suites
    if (i + 1 > n) return nil;
    i += 1 + (size_t)b[i];                           // compression_methods
    if (i + 2 > n) return nil;
    size_t ext_total = ((size_t)b[i] << 8) | (size_t)b[i + 1];
    i += 2;
    size_t end = i + ext_total;
    if (end > n) end = n;
    while (i + 4 <= end) {
        uint16_t etype = (uint16_t)(((uint16_t)b[i] << 8) | (uint16_t)b[i + 1]);
        size_t elen = ((size_t)b[i + 2] << 8) | (size_t)b[i + 3];
        i += 4;
        if (i + elen > end) break;
        if (etype == 0x0000 && elen >= 5) {          // server_name (SNI)
            const uint8_t *e = b + i;
            size_t nlen = ((size_t)e[3] << 8) | (size_t)e[4];
            if (e[2] == 0x00 && 5 + nlen <= elen) {
                return [[NSString alloc] initWithBytes:e + 5 length:nlen encoding:NSUTF8StringEncoding];
            }
        }
        i += elen;
    }
    return nil;
}

static int (*orig_dh_socket)(int, int, int) = NULL;
static int (*orig_dh_close)(int) = NULL;
static int (*orig_dh_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*orig_dh_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*orig_dh_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static ssize_t (*orig_dh_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_dh_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_dh_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*orig_dh_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_dh_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*orig_dh_recvmsg)(int, struct msghdr *, int) = NULL;
static ssize_t (*orig_dh_read)(int, void *, size_t) = NULL;
static ssize_t (*orig_dh_write)(int, const void *, size_t) = NULL;

static _Thread_local uint8_t g_dh_iov_buf[DH_NET_PAYLOAD_MAX];

static size_t dh_net_collect_iov(const struct iovec *iov, int iovcnt, size_t limit, uint8_t *out) {
    if (!iov || iovcnt <= 0 || !out || limit == 0) return 0;
    size_t total = 0;
    for (int i = 0; i < iovcnt && total < limit; i++) {
        const void *base = iov[i].iov_base;
        size_t left = iov[i].iov_len;
        if (!base || left == 0) continue;
        size_t take = MIN(left, limit - total);
        memcpy(out + total, base, take);
        total += take;
    }
    return total;
}

static int hooked_dh_socket(int domain, int type, int protocol) {
    int fd = orig_dh_socket ? orig_dh_socket(domain, type, protocol) : -1;
    if (fd >= 0) dh_net_set_fd_state(fd, DH_NET_FD_SOCKET);
    return fd;
}

static int hooked_dh_close(int fd) {
    int r = orig_dh_close ? orig_dh_close(fd) : -1;
    if (r == 0) dh_net_set_fd_state(fd, DH_NET_FD_UNKNOWN);
    return r;
}

static int hooked_dh_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    int cfd = orig_dh_accept ? orig_dh_accept(fd, addr, len) : -1;
    if (cfd >= 0) dh_net_set_fd_state(cfd, DH_NET_FD_SOCKET);
    return cfd;
}

static int hooked_dh_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int r = orig_dh_connect ? orig_dh_connect(fd, addr, len) : -1;
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !dh_net_is_internal_fd(fd)) {
        NSString *s = dh_sockaddr_str(addr);
        NSString *result = r == 0 ? @"ok" : (errno == EINPROGRESS ? @"in_progress"
                                            : [NSString stringWithFormat:@"errno=%d", errno]);
        if (s.length) net_log(@"SOCKET", @"connect",
                              [NSString stringWithFormat:@"fd=%d %@ result=%@", fd, s, result], nil);
    }
    return r;
}

static int hooked_dh_getaddrinfo(const char *node, const char *service,
                                 const struct addrinfo *hints, struct addrinfo **res) {
    int r = orig_dh_getaddrinfo ? orig_dh_getaddrinfo(node, service, hints, res) : EAI_FAIL;
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && node && node[0]) {
        net_log(@"DNS", @"resolve",
                [NSString stringWithFormat:@"%s%s%s rc=%d", node,
                 (service && service[0]) ? " " : "", (service && service[0]) ? service : "", r], nil);
    }
    return r;
}

// send/sendto/sendmsg/write 统一走这里: 先执行原调用, 再只对实际写出的字节做
// TLS SNI 或文本 payload 记录。失败调用不产生业务错误, 也不污染事件流。
static ssize_t hooked_dh_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t r = orig_dh_send ? orig_dh_send(fd, buf, len, flags) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd))
        dh_net_capture_outbound(fd, buf, (size_t)r, @"SOCKET", @"TLS",
                                [NSString stringWithFormat:@"fd=%d", fd]);
    return r;
}

static ssize_t hooked_dh_sendto(int fd, const void *buf, size_t len, int flags,
                                const struct sockaddr *dest, socklen_t destLen) {
    ssize_t r = orig_dh_sendto ? orig_dh_sendto(fd, buf, len, flags, dest, destLen) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd)) {
        NSString *peer = dh_sockaddr_str(dest);
        dh_net_capture_outbound(fd, buf, (size_t)r, @"SOCKET", @"TLS",
                                [NSString stringWithFormat:@"fd=%d%@%@", fd,
                                 peer.length ? @" " : @"", peer ?: @""]);
    }
    return r;
}

static ssize_t hooked_dh_sendmsg(int fd, const struct msghdr *msg, int flags) {
    ssize_t r = orig_dh_sendmsg ? orig_dh_sendmsg(fd, msg, flags) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd) && msg) {
        size_t n = dh_net_collect_iov(msg->msg_iov, (int)msg->msg_iovlen,
                                      MIN((size_t)r, (size_t)DH_NET_PAYLOAD_MAX), g_dh_iov_buf);
        if (n) dh_net_capture_outbound(fd, g_dh_iov_buf, n, @"SOCKET", @"TLS",
                                       [NSString stringWithFormat:@"fd=%d", fd]);
    }
    return r;
}

static ssize_t hooked_dh_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t r = orig_dh_recv ? orig_dh_recv(fd, buf, len, flags) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd))
        dh_net_capture_inbound(fd, buf, (size_t)r, @"SOCKET",
                               [NSString stringWithFormat:@"fd=%d", fd]);
    return r;
}

static ssize_t hooked_dh_recvfrom(int fd, void *buf, size_t len, int flags,
                                  struct sockaddr *src, socklen_t *srcLen) {
    ssize_t r = orig_dh_recvfrom ? orig_dh_recvfrom(fd, buf, len, flags, src, srcLen) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd))
        dh_net_capture_inbound(fd, buf, (size_t)r, @"SOCKET",
                               [NSString stringWithFormat:@"fd=%d", fd]);
    return r;
}

static ssize_t hooked_dh_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t r = orig_dh_recvmsg ? orig_dh_recvmsg(fd, msg, flags) : -1;
    if (r > 0 && !dh_net_is_internal_fd(fd) && msg) {
        size_t n = dh_net_collect_iov(msg->msg_iov, (int)msg->msg_iovlen,
                                      MIN((size_t)r, (size_t)DH_NET_PAYLOAD_MAX), g_dh_iov_buf);
        if (n) dh_net_capture_inbound(fd, g_dh_iov_buf, n, @"SOCKET",
                                      [NSString stringWithFormat:@"fd=%d", fd]);
    }
    return r;
}

// read/write 是文件与 socket 共用入口。只在 socket()/accept() 明确登记过的 fd 上工作,
// 文件 fd 直接跳过, 不把普通文件 I/O 变成网络事件。
static ssize_t hooked_dh_read(int fd, void *buf, size_t len) {
    ssize_t r = orig_dh_read ? orig_dh_read(fd, buf, len) : -1;
    if (r > 0 && dh_net_is_external_socket_fd(fd))
        dh_net_capture_inbound(fd, buf, (size_t)r, @"SOCKET",
                               [NSString stringWithFormat:@"fd=%d", fd]);
    return r;
}

static ssize_t hooked_dh_write(int fd, const void *buf, size_t len) {
    ssize_t r = orig_dh_write ? orig_dh_write(fd, buf, len) : -1;
    if (r > 0 && dh_net_is_external_socket_fd(fd))
        dh_net_capture_outbound(fd, buf, (size_t)r, @"SOCKET", @"TLS",
                                [NSString stringWithFormat:@"fd=%d", fd]);
    return r;
}

static void install_socket_hooks(void) {
    struct rebinding r[] = {
        {"socket",     hooked_dh_socket,     (void **)&orig_dh_socket},
        {"close",      hooked_dh_close,      (void **)&orig_dh_close},
        {"accept",     hooked_dh_accept,     (void **)&orig_dh_accept},
        {"connect",    hooked_dh_connect,    (void **)&orig_dh_connect},
        {"getaddrinfo",hooked_dh_getaddrinfo,(void **)&orig_dh_getaddrinfo},
        {"send",       hooked_dh_send,       (void **)&orig_dh_send},
        {"sendto",     hooked_dh_sendto,     (void **)&orig_dh_sendto},
        {"sendmsg",    hooked_dh_sendmsg,    (void **)&orig_dh_sendmsg},
        {"recv",       hooked_dh_recv,       (void **)&orig_dh_recv},
        {"recvfrom",   hooked_dh_recvfrom,   (void **)&orig_dh_recvfrom},
        {"recvmsg",    hooked_dh_recvmsg,    (void **)&orig_dh_recvmsg},
        {"read",       hooked_dh_read,       (void **)&orig_dh_read},
        {"write",      hooked_dh_write,      (void **)&orig_dh_write},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    // 只把真正拿到原实现的符号登记为 dlsym 重定向。否则目标用 dlsym 拿到 wrapper
    // 时会调用一个没有 fallback 的桩函数, 可能直接破坏宿主行为。
    struct rebinding active[sizeof(r) / sizeof(r[0])];
    size_t nactive = 0;
    if (orig_dh_socket)     active[nactive++] = r[0];
    if (orig_dh_close)      active[nactive++] = r[1];
    if (orig_dh_accept)     active[nactive++] = r[2];
    if (orig_dh_connect)    active[nactive++] = r[3];
    if (orig_dh_getaddrinfo)active[nactive++] = r[4];
    if (orig_dh_send)       active[nactive++] = r[5];
    if (orig_dh_sendto)     active[nactive++] = r[6];
    if (orig_dh_sendmsg)    active[nactive++] = r[7];
    if (orig_dh_recv)       active[nactive++] = r[8];
    if (orig_dh_recvfrom)   active[nactive++] = r[9];
    if (orig_dh_recvmsg)    active[nactive++] = r[10];
    if (orig_dh_read)       active[nactive++] = r[11];
    if (orig_dh_write)      active[nactive++] = r[12];
    if (nactive) dh_dlsym_register_rebindings(active, nactive);
}

static DHOSStatus (*orig_dh_SSLWrite)(void *, const void *, size_t, size_t *) = NULL;
static DHOSStatus (*orig_dh_SSLRead)(void *, void *, size_t, size_t *) = NULL;

static DHOSStatus hooked_dh_SSLWrite(void *ctx, const void *data, size_t len, size_t *processed) {
    DHOSStatus r = orig_dh_SSLWrite ? orig_dh_SSLWrite(ctx, data, len, processed) : -1;
    if (r == 0 && dh_capture_sub_enabled(DH_CAP_NETWORK) && data && processed && *processed > 0) {
        net_log(@"TLS-ST", @"send", [NSString stringWithFormat:@"ctx=%p len=%zu", ctx, *processed],
                [NSData dataWithBytes:data length:*processed]);
    }
    return r;
}

static DHOSStatus hooked_dh_SSLRead(void *ctx, void *data, size_t len, size_t *processed) {
    DHOSStatus r = orig_dh_SSLRead ? orig_dh_SSLRead(ctx, data, len, processed) : -1;
    if (r == 0 && dh_capture_sub_enabled(DH_CAP_NETWORK) && data && processed && *processed > 0) {
        net_log(@"TLS-ST", @"recv", [NSString stringWithFormat:@"ctx=%p len=%zu", ctx, *processed],
                [NSData dataWithBytes:data length:*processed]);
    }
    return r;
}

static void install_securetransport_hooks(void) {
    struct rebinding r[] = {
        {"SSLWrite", hooked_dh_SSLWrite, (void **)&orig_dh_SSLWrite},
        {"SSLRead",  hooked_dh_SSLRead,  (void **)&orig_dh_SSLRead},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r) / sizeof(r[0]));
}

static _Thread_local uint8_t g_dh_nw_buf[DH_NET_PAYLOAD_MAX];

static size_t dh_net_collect_dispatch_data(dispatch_data_t content, uint8_t *out, size_t limit) {
    if (!content || !out || limit == 0) return 0;
    __block size_t total = 0;
    dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset,
                                       const void *buffer, size_t size) {
        (void)region; (void)offset;
        if (total >= limit) return false;
        size_t take = MIN(size, limit - total);
        if (take && buffer) {
            memcpy(out + total, buffer, take);
            total += take;
        }
        return total < limit;
    });
    return total;
}

static void (*orig_dh_nw_send)(void *, dispatch_data_t, void *, bool, void *) = NULL;

static void hooked_dh_nw_send(void *conn, dispatch_data_t content, void *ctx, bool complete, void *ch) {
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && content) {
        size_t n = dh_net_collect_dispatch_data(content, g_dh_nw_buf, sizeof(g_dh_nw_buf));
        if (n) {
            NSString *detail = [NSString stringWithFormat:@"conn=%p", conn];
            if (n >= 6 && g_dh_nw_buf[0] == 0x16 && g_dh_nw_buf[1] == 0x03) {
                NSString *sni = dh_sni_from_client_hello(g_dh_nw_buf, n);
                if (sni.length)
                    net_log(@"TLS-NW", @"sni", [detail stringByAppendingFormat:@" %@", sni], nil);
            } else if (dh_net_payload_is_text(g_dh_nw_buf, n)) {
                // Network.framework 的 TLS 在上层终结, 这里看到的通常是应用明文。
                net_log(@"NW", @"send", [detail stringByAppendingFormat:@" len=%zu", n],
                        dh_net_prefix_data(g_dh_nw_buf, n));
            }
        }
    }
    if (orig_dh_nw_send) orig_dh_nw_send(conn, content, ctx, complete, ch);
}

typedef void (^DHNWReceiveCompletion)(dispatch_data_t, void *, bool, void *);
static void (*orig_dh_nw_receive)(void *, uint32_t, uint32_t, DHNWReceiveCompletion) = NULL;

static void hooked_dh_nw_receive(void *conn, uint32_t minimum, uint32_t maximum,
                                 DHNWReceiveCompletion completion) {
    if (!completion) {
        if (orig_dh_nw_receive) orig_dh_nw_receive(conn, minimum, maximum, completion);
        return;
    }
    DHNWReceiveCompletion wrapped = ^(dispatch_data_t content, void *context, bool complete, void *error) {
        if (dh_capture_sub_enabled(DH_CAP_NETWORK) && content) {
            size_t n = dh_net_collect_dispatch_data(content, g_dh_nw_buf, sizeof(g_dh_nw_buf));
            if (n && dh_net_payload_is_text(g_dh_nw_buf, n)) {
                net_log(@"NW", @"recv",
                        [NSString stringWithFormat:@"conn=%p len=%zu", conn, n],
                        dh_net_prefix_data(g_dh_nw_buf, n));
            }
        }
        completion(content, context, complete, error);
    };
    if (orig_dh_nw_receive) orig_dh_nw_receive(conn, minimum, maximum, wrapped);
}

static void install_nw_hooks(void) {
    struct rebinding r[] = {
        {"nw_connection_send",    hooked_dh_nw_send,    (void **)&orig_dh_nw_send},
        {"nw_connection_receive", hooked_dh_nw_receive, (void **)&orig_dh_nw_receive},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    struct rebinding active[2];
    size_t nactive = 0;
    if (orig_dh_nw_send)    active[nactive++] = r[0];
    if (orig_dh_nw_receive) active[nactive++] = r[1];
    if (nactive) dh_dlsym_register_rebindings(active, nactive);
}

// ============================================================
// 4) NSURLConnection 兜底 (老 API, 部分 SDK 仍用; 只覆盖两个便捷方法, 不碰 delegate 型以免与
//    便捷方法内部连接双记)。注意块参数顺序是 (response, data, error), 与 NSURLSession 相反。
// ============================================================
typedef void (^DHConnCH)(NSURLResponse *, NSData *, NSError *);

static BOOL swz_class_method(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

// +[NSURLConnection sendAsynchronousRequest:queue:completionHandler:]
static void (*orig_conn_async)(id, SEL, NSURLRequest *, id, DHConnCH) = NULL;
static void swz_conn_async(id self, SEL _cmd, NSURLRequest *req, id queue, DHConnCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) {
        if (orig_conn_async) orig_conn_async(self, _cmd, req, queue, ch);
        return;
    }
    DHNetSnap *snap = dh_snap_from_request(req, nil);
    DHConnCH wrapped = ^(NSURLResponse *resp, NSData *data, NSError *err) {
        @try {
            net_log_pair(snap.method, snap.url, snap.headers, snap.body,
                         data, resp, err, snap.callStack, snap.tsMs, snap.tid);
        } @catch (__unused NSException *e) {}
        ch(resp, data, err);
    };
    if (orig_conn_async) orig_conn_async(self, _cmd, req, queue, wrapped);
}

// +[NSURLConnection sendSynchronousRequest:returningResponse:error:]
static NSData *(*orig_conn_sync)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **) = NULL;
static NSData *swz_conn_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **respOut, NSError **errOut) {
    if (!orig_conn_sync) return nil;
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_conn_sync(self, _cmd, req, respOut, errOut);
    DHNetSnap *snap = dh_snap_from_request(req, nil);
    NSData *data = orig_conn_sync(self, _cmd, req, respOut, errOut);
    @try {
        NSURLResponse *resp = respOut ? *respOut : nil;
        NSError *err = errOut ? *errOut : nil;
        net_log_pair(snap.method, snap.url, snap.headers, snap.body,
                     data, resp, err, snap.callStack, snap.tsMs, snap.tid);
    } @catch (__unused NSException *e) {}
    return data;
}

static void install_nsurlconnection_hook(void) {
    Class conn = NSClassFromString(@"NSURLConnection");
    if (!conn) return;   // 系统可能已下线该类
    swz_class_method(conn, @selector(sendAsynchronousRequest:queue:completionHandler:),
                     (IMP)swz_conn_async, (IMP *)&orig_conn_async);
    swz_class_method(conn, @selector(sendSynchronousRequest:returningResponse:error:),
                     (IMP)swz_conn_sync, (IMP *)&orig_conn_sync);
}

// ============================================================
void dh_install_network_hooks(void) {
    install_urlsession_hook();
    install_websocket_hooks();
    install_nsurlconnection_hook();
    install_ssl_hooks();
    install_securetransport_hooks();
    install_socket_hooks();
    install_nw_hooks();
}
