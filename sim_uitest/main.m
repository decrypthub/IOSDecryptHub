// sim_uitest/main.m — IOSDecryptHub 交互式测试台
// 顶部 segment 分 tab(加解密 / 系统), 每个 tab 的按钮触发对应一类系统调用,
// 便于在注入的 dylib 里逐个观察 hook 效果。不把所有按钮堆在一页。
//
// 自动化测试通道: 注册 URL scheme "dhtest", xcrun simctl openurl <dev> dhtest://md5
// 会通过 sendActionsForControlEvents: 模拟点击对应按钮(即使该 tab 当前隐藏)。

#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <WebKit/WebKit.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>

extern int ptrace(int, pid_t, caddr_t, int);
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

// 运行时从注入的 dylib 取真实服务地址(端口在 8088..8108 间自动顺延), 避免写死端口
static NSString *gUrlHint = @"";
static NSString *dh_real_url(void) {
    NSString *(*fn)(void) = (NSString *(*)(void))dlsym(RTLD_DEFAULT, "dh_http_url");
    if (!fn) return nil;
    NSString *u = fn();
    return (u && ![u hasPrefix:@"("]) ? u : nil;
}

// ==================== 算法触发(加解密 tab) ====================
static const char *kMsg = "decrypt-helper interactive test sample";

static void do_digest(int which) {
    const char *m = kMsg; size_t n = strlen(m);
    if      (which == 0) { unsigned char d[CC_MD5_DIGEST_LENGTH];    CC_MD5(m, (CC_LONG)n, d); }
    else if (which == 1) { unsigned char d[CC_SHA1_DIGEST_LENGTH];   CC_SHA1(m, (CC_LONG)n, d); }
    else if (which == 2) { unsigned char d[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(m, (CC_LONG)n, d); }
    else                 { unsigned char d[CC_SHA512_DIGEST_LENGTH]; CC_SHA512(m, (CC_LONG)n, d); }
}
static void do_hmac(void) {
    const char *k = "secret-key", *m = kMsg;
    unsigned char o[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k, strlen(k), m, strlen(m), o);
}
static void do_sym(CCAlgorithm alg, size_t keyLen, size_t blockLen) {
    unsigned char key[32] = {0}, iv[16] = {0};
    for (size_t i = 0; i < keyLen;   i++) key[i] = (unsigned char)i;
    for (size_t i = 0; i < blockLen; i++) iv[i]  = (unsigned char)(i + 0x10);
    const char *m = kMsg; unsigned char out[256]; size_t mv = 0;
    CCCrypt(kCCEncrypt, alg, kCCOptionPKCS7Padding, key, keyLen,
            blockLen ? iv : NULL, m, strlen(m), out, sizeof(out), &mv);
}
static void do_rc4(void) {
    unsigned char key[16]; for (int i = 0; i < 16; i++) key[i] = (unsigned char)i;
    const char *m = kMsg; unsigned char out[256]; size_t mv = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, key, sizeof(key), NULL, m, strlen(m), out, sizeof(out), &mv);
}
static SecKeyRef gRSA = NULL;
static SecKeyRef rsa_key(void) {
    if (gRSA) return gRSA;
    NSDictionary *p = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @2048 };
    gRSA = SecKeyCreateRandomKey((CFDictionaryRef)p, NULL);
    return gRSA;
}
static void do_rsa_sign(void) {
    SecKeyRef pk = rsa_key(); if (!pk) return;
    CFDataRef d = CFDataCreate(NULL, (const UInt8 *)kMsg, strlen(kMsg));
    CFDataRef s = SecKeyCreateSignature(pk, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, d, NULL);
    if (s) CFRelease(s);
    CFRelease(d);
}
static void do_rsa_enc(void) {
    SecKeyRef pk = rsa_key(); if (!pk) return;
    SecKeyRef pub = SecKeyCopyPublicKey(pk); if (!pub) return;
    CFDataRef d = CFDataCreate(NULL, (const UInt8 *)kMsg, strlen(kMsg));
    CFDataRef c = SecKeyCreateEncryptedData(pub, kSecKeyAlgorithmRSAEncryptionOAEPSHA256, d, NULL);
    if (c) CFRelease(c);
    CFRelease(d); CFRelease(pub);
}
static void do_pbkdf(void) {
    unsigned char dk[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, "user-password", strlen("user-password"),
                         (const uint8_t *)"saltsalt", 8, kCCPRFHmacAlgSHA256, 10000, dk, sizeof(dk));
}
static void do_keychain(void) {
    NSString *svc = @"com.taisuii.cryptotesthost.keychain";
    NSString *acct = @"idh-demo";
    NSDictionary *base = @{ (id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrService: svc,
                            (id)kSecAttrAccount: acct,
                            (id)kSecAttrAccessGroup: @"com.taisuii.cryptotesthost" };
    SecItemDelete((__bridge CFDictionaryRef)base);
    NSMutableDictionary *add = [base mutableCopy];
    add[(id)kSecValueData] = [@"idh-keychain-demo" dataUsingEncoding:NSUTF8StringEncoding];
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    NSMutableDictionary *query = [base mutableCopy];
    query[(id)kSecReturnData] = @YES;
    query[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &out);
    if (out) CFRelease(out);
    NSDictionary *update = @{ (id)kSecValueData: [@"idh-keychain-demo-2" dataUsingEncoding:NSUTF8StringEncoding] };
    SecItemUpdate((__bridge CFDictionaryRef)base, (__bridge CFDictionaryRef)update);
    SecItemDelete((__bridge CFDictionaryRef)base);
    // 留一条不删的持久条目, 给面板「当前条目」直接查看验证
    NSDictionary *persist = @{ (id)kSecClass: (id)kSecClassGenericPassword,
                               (id)kSecAttrService: svc,
                               (id)kSecAttrAccount: @"idh-demo-persist",
                               (id)kSecAttrAccessGroup: @"com.taisuii.cryptotesthost",
                               (id)kSecValueData: [@"idh-keychain-persist" dataUsingEncoding:NSUTF8StringEncoding] };
    SecItemAdd((__bridge CFDictionaryRef)persist, NULL);
}
static void do_bigdata(void) {
    size_t n = 128 * 1024;
    unsigned char *b = malloc(n), *c = malloc(n + 16);
    if (b && c) {
        memset(b, 'A', n);
        unsigned char key[16] = {0}, iv[16] = {0}; size_t mv = 0;
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv, b, n, c, n + 16, &mv);
    }
    free(b); free(c);
}

// ==================== 文件触发(文件 tab) ====================
static NSString *test_file_path(void) {
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return [[p firstObject] stringByAppendingPathComponent:@"iosdh_test.txt"];
}
static void do_file_write(void) {
    NSString *p = test_file_path();
    int fd = open(p.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *data = "IOSDecryptHub file hook test - 文件操作测试数据\n";
        write(fd, data, strlen(data));
        close(fd);
    }
}
static void do_file_read(void) {
    NSString *p = test_file_path();
    int fd = open(p.UTF8String, O_RDONLY);
    if (fd >= 0) { char buf[256]; read(fd, buf, sizeof(buf)); close(fd); }
}
static void do_file_delete(void) {
    NSString *p = test_file_path();
    unlink(p.UTF8String);
}
static void do_file_rename(void) {
    NSString *from = test_file_path();
    NSString *to = [from stringByAppendingPathExtension:@"bak"];
    [@"rename test" writeToFile:from atomically:YES encoding:NSUTF8StringEncoding error:nil];
    rename(from.UTF8String, to.UTF8String);
}

// ==================== 系统触发(系统 tab) ====================
// ---------- 真机无人值守验收用的状态快照 ----------
// 真机上没有 curl/netstat，也读不到统一日志，出问题只能靠猜。宿主自己把关键事实
// 写进 Documents/dh_status.json（root 可通过 SSH 读容器），把"猜"变成"看"：
//   injected_images   已加载镜像里的注入痕迹（decrypt_helper / ellekit ...）
//   local_8088        本地 8088 是否可连 —— 区分"引擎没监听"与"局域网到不了"
//   engine_config_access  沙盒视角能否读到越狱插件目录（本身就是一条能力结论）
static BOOL dh_can_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    BOOL ok = (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    close(fd);
    return ok;
}

static NSString *dh_status_path(void) {
    // 构造函数阶段（进程刚起、UI 还没初始化）取容器目录：HOME 最可靠，兜底 Documents
    const char *home = getenv("HOME");
    NSString *dir = home ? [NSString stringWithUTF8String:home] : nil;
    if (dir.length == 0) dir = test_file_path().stringByDeletingLastPathComponent;
    return [dir stringByAppendingPathComponent:@"dh_status.json"];
}

// 权限自检：把"以什么身份跑、越狱路径能否读/写、失败的真实原因"写进状态文件。
// 为什么需要它：产品里"保存失败"这类提示不带原因，只能靠猜；这里把 uid / 推导出的
// 越狱根 / 逐项可读可写 / 原子写的 NSError 原样带回来。
static NSDictionary *dh_selfcheck(void) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"uid"] = @(getuid());
    out[@"euid"] = @(geteuid());

    Dl_info info = {0};
    NSString *root = nil;
    if (dladdr((const void *)&dh_selfcheck, &info) != 0 && info.dli_fname) {
        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        for (int i = 0; i < 3; i++) path = [path stringByDeletingLastPathComponent];
        root = path;
    }
    out[@"bootstrap_root"] = root.length ? root : @"(nil)";

    NSMutableArray *probes = [NSMutableArray array];
    NSArray<NSString *> *dirs = @[
        root.length > 1 ? [root stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub/config"] : @"/var/jb/usr/lib/IOSDecryptHub/config",
        @"/var/jb/usr/lib/IOSDecryptHub/config",
        @"/usr/lib/IOSDecryptHub/config",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *dir in dirs) {
        NSMutableDictionary *probe = [NSMutableDictionary dictionary];
        probe[@"dir"] = dir;
        probe[@"exists"] = @([fm fileExistsAtPath:dir]);
        probe[@"writable"] = @([fm isWritableFileAtPath:dir]);
        NSString *tmp = [dir stringByAppendingPathComponent:@".dh_selftest.plist"];
        NSError *serErr = nil;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:@{@"selftest": @YES}
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serErr];
        NSError *writeErr = nil;
        BOOL ok = NO;
        if (data) ok = [data writeToFile:tmp options:NSDataWritingAtomic error:&writeErr];
        probe[@"atomic_write_ok"] = @(ok);
        if (ok) [fm removeItemAtPath:tmp error:nil];
        if (!ok && writeErr) {
            probe[@"write_error"] = [NSString stringWithFormat:@"%@ [%@ %ld, underlying=%@ %ld]",
                writeErr.localizedDescription, writeErr.domain, (long)writeErr.code,
                writeErr.userInfo[NSUnderlyingErrorKey] ? [(NSError *)writeErr.userInfo[NSUnderlyingErrorKey] domain] : @"-",
                writeErr.userInfo[NSUnderlyingErrorKey] ? (long)[(NSError *)writeErr.userInfo[NSUnderlyingErrorKey] code] : 0];
        }
        [probes addObject:probe];
    }
    out[@"write_probes"] = probes;
    return out;
}

static NSString *gPluginLoad = @"pending";
static void dh_ensure_plugin(void);
static void dh_write_status(void) {
    @autoreleasepool {
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        out[@"time"] = @([[NSDate date] timeIntervalSince1970]);
        out[@"pid"] = @(getpid());

        NSMutableArray *images = [NSMutableArray array];
        const char *marks[] = { "decrypt_helper", "IOSDecryptHub", "ellekit", "substrate" };
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            for (int j = 0; j < 4; j++) {
                if (strstr(name, marks[j])) { [images addObject:@(name)]; break; }
            }
        }
        out[@"injected_images"] = images;
        out[@"injected"] = @(images.count > 0);
        out[@"image_count"] = @(count);
        out[@"local_8088"] = @(dh_can_connect(8088));

        NSMutableDictionary *access = [NSMutableDictionary dictionary];
        NSArray *paths = @[ @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist",
                            @"/usr/lib/IOSDecryptHub/config/enabledBundles.plist" ];
        for (NSString *path in paths) {
            access[path] = @{ @"exists": @([[NSFileManager defaultManager] fileExistsAtPath:path]),
                              @"readable": @([[NSFileManager defaultManager] isReadableFileAtPath:path]) };
        }
        out[@"engine_config_access"] = access;
        out[@"documents"] = test_file_path().stringByDeletingLastPathComponent;
        out[@"pluginLoad"] = gPluginLoad ?: @"pending";
        out[@"selfcheck"] = dh_selfcheck();

        NSData *data = [NSJSONSerialization dataWithJSONObject:out
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:nil];
        [data writeToFile:dh_status_path() atomically:YES];
    }
}

// 进程一启动就写一次：真机常出现"URL 拉起只进后台、UI 不初始化"的情况，
// 放到构造函数里才能保证无论前台/后台都拿到注入与端口的第一手事实。
__attribute__((constructor))
static void dh_status_boot_probe(void) {
    dh_ensure_plugin();
    dh_write_status();
}

static void do_dlopen(void) {
    void *h1 = dlopen("/usr/lib/libsqlite3.dylib", RTLD_LAZY); if (h1) dlclose(h1);
    void *h2 = dlopen("/usr/lib/libz.dylib", RTLD_LAZY);       if (h2) dlclose(h2);
}
static void do_dlsym(void) {
    // 走 dlsym 路径调用 CC_MD5 / CCCrypt —— 验证 dlsym hook 重定向到 wrapper
    unsigned char *(*md5_fn)(const void *, CC_LONG, unsigned char *) =
        (unsigned char *(*)(const void *, CC_LONG, unsigned char *))dlsym(RTLD_DEFAULT, "CC_MD5");
    if (md5_fn) {
        unsigned char d[CC_MD5_DIGEST_LENGTH];
        md5_fn(kMsg, (CC_LONG)strlen(kMsg), d);
    }
    CCCryptorStatus (*crypt_fn)(CCOperation, CCAlgorithm, CCOptions,
                                const void *, size_t, const void *,
                                const void *, size_t, void *, size_t, size_t *) =
        (CCCryptorStatus (*)(CCOperation, CCAlgorithm, CCOptions,
                             const void *, size_t, const void *,
                             const void *, size_t, void *, size_t, size_t *))dlsym(RTLD_DEFAULT, "CCCrypt");
    if (crypt_fn) {
        unsigned char key[16] = {0}, iv[16] = {0}, out[256]; size_t mv = 0;
        crypt_fn(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv,
                 kMsg, strlen(kMsg), out, sizeof(out), &mv);
    }
}
// ==================== 网络矩阵(抓包覆盖测试) ====================
// 目标: 本地回显服务器 tests/net_echo_server.py (默认 127.0.0.1:8099)。
// 每个用例 path 均带唯一 case= 标记, 便于用 query_events 按 url 反查核对。
// DH_ECHO_PORT 环境变量可改端口; DH_TRIGGER=netall 一次跑完全部。
static NSString *net_echo_base(void) {
    NSString *p = [[NSProcessInfo processInfo].environment[@"DH_ECHO_PORT"] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!p.length) p = @"8099";
    return [NSString stringWithFormat:@"http://127.0.0.1:%@/", p];
}
static void net_fire(NSURLSession *sess, NSString *method, NSString *path,
                     NSDictionary *headers, NSData *body, NSTimeInterval timeout,
                     dispatch_group_t g) {
    NSURL *u = [NSURL URLWithString:[net_echo_base() stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = method;
    if (timeout > 0) req.timeoutInterval = timeout;
    for (NSString *k in headers) [req setValue:headers[k] forHTTPHeaderField:k];
    req.HTTPBody = body;
    if (g) dispatch_group_enter(g);
    NSURLSessionDataTask *t = [sess dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { if (g) dispatch_group_leave(g); }];
    [t resume];
}
static void do_net_matrix(void) {
    NSString *base = net_echo_base();
    dispatch_group_t g = dispatch_group_create();
    NSURLSession *shared = [NSURLSession sharedSession];
    NSData *json = [@"{\"probe\":\"matrix\",\"secret\":\"s3cr3t\"}" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *form = [@"user=alice&pass=s3cr3t" dataUsingEncoding:NSUTF8StringEncoding];

    net_fire(shared, @"GET",    @"echo?case=get-query&foo=bar&secret=s3cr3t",
             @{@"X-Case": @"get-query", @"X-Validator": @"matrix-get"}, nil, 0, g);
    net_fire(shared, @"POST",   @"echo?case=post-json",
             @{@"Content-Type": @"application/json", @"X-Case": @"post-json"}, json, 0, g);
    net_fire(shared, @"POST",   @"echo?case=post-form",
             @{@"Content-Type": @"application/x-www-form-urlencoded", @"X-Case": @"post-form"}, form, 0, g);
    net_fire(shared, @"PUT",    @"echo?case=put", @{@"X-Case": @"put"}, json, 0, g);
    net_fire(shared, @"DELETE", @"echo?case=delete", @{@"X-Case": @"delete"}, nil, 0, g);
    net_fire(shared, @"PATCH",  @"echo?case=patch", @{@"X-Case": @"patch"}, json, 0, g);
    net_fire(shared, @"HEAD",   @"echo?case=head", @{@"X-Case": @"head"}, nil, 0, g);
    net_fire(shared, @"OPTIONS",@"echo?case=options", @{@"X-Case": @"options"}, nil, 0, g);

    // 大 body (100KB, 低于 1MB 快照上限, 应完整记录)
    NSMutableData *big = [NSMutableData dataWithLength:100 * 1024];
    memset(big.mutableBytes, 'A', big.length);
    net_fire(shared, @"POST", @"echo?case=post-big", @{@"X-Case": @"post-big"}, big, 0, g);

    // dataTaskWithURL (无 NSMutableURLRequest 对象, 疑似缺口)
    if (g) dispatch_group_enter(g);
    NSURLSessionDataTask *tURL = [shared dataTaskWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=data-url"]]
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [tURL resume];

    // 自定义 session (非 shared, 走另一条 swizzle 分支)
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *custom = [NSURLSession sessionWithConfiguration:cfg];
    net_fire(custom, @"GET", @"echo?case=custom-session", @{@"X-Case": @"custom-session"}, nil, 0, g);

    // upload fromData / fromFile
    if (g) dispatch_group_enter(g);
    NSMutableURLRequest *upReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=upload-data"]]];
    upReq.HTTPMethod = @"POST";
    [upReq setValue:@"upload-data" forHTTPHeaderField:@"X-Case"];
    NSURLSessionUploadTask *up1 = [shared uploadTaskWithRequest:upReq fromData:json
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [up1 resume];
    NSString *tmpF = [NSTemporaryDirectory() stringByAppendingPathComponent:@"dh_upload.txt"];
    [@"upload-file-body-s3cr3t" writeToFile:tmpF atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (g) dispatch_group_enter(g);
    NSMutableURLRequest *upReq2 = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=upload-file"]]];
    upReq2.HTTPMethod = @"POST";
    [upReq2 setValue:@"upload-file" forHTTPHeaderField:@"X-Case"];
    NSURLSessionUploadTask *up2 = [shared uploadTaskWithRequest:upReq2 fromFile:[NSURL fileURLWithPath:tmpF]
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [up2 resume];

    // download task (request / URL 两种构造)
    if (g) dispatch_group_enter(g);
    NSURLRequest *dlReq = [NSURLRequest requestWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=download-req"]]];
    NSURLSessionDownloadTask *dl1 = [shared downloadTaskWithRequest:dlReq
        completionHandler:^(NSURL *loc, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [dl1 resume];
    if (g) dispatch_group_enter(g);
    NSURLSessionDownloadTask *dl2 = [shared downloadTaskWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=download-url"]]
        completionHandler:^(NSURL *loc, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [dl2 resume];

    // 大响应下载 (1MB, 测响应截断)
    if (g) dispatch_group_enter(g);
    NSURLSessionDownloadTask *dlBig = [shared downloadTaskWithURL:[NSURL URLWithString:[base stringByAppendingString:@"big?case=download-big"]]
        completionHandler:^(NSURL *loc, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [dlBig resume];

    // 重定向 / 错误状态 / 超时(错误路径)
    net_fire(shared, @"GET", @"redirect?case=redirect", @{@"X-Case": @"redirect"}, nil, 0, g);
    net_fire(shared, @"GET", @"status/404?case=status-404", @{@"X-Case": @"status-404"}, nil, 0, g);
    net_fire(shared, @"GET", @"status/500?case=status-500", @{@"X-Case": @"status-500"}, nil, 0, g);
    net_fire(shared, @"GET", @"delay?ms=3000&case=timeout", @{@"X-Case": @"timeout"}, nil, 1.0, g);

    // HTTPBodyStream (疑似缺口: hook 只快照 HTTPBody, 流式 body 可能记不到)
    if (g) dispatch_group_enter(g);
    NSMutableURLRequest *stReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[base stringByAppendingString:@"echo?case=body-stream"]]];
    stReq.HTTPMethod = @"POST";
    [stReq setValue:@"body-stream" forHTTPHeaderField:@"X-Case"];
    stReq.HTTPBodyStream = [NSInputStream inputStreamWithData:json];
    NSURLSessionDataTask *stT = [shared dataTaskWithRequest:stReq
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { dispatch_group_leave(g); }];
    [stT resume];

    // 并发 5 路
    for (int i = 0; i < 5; i++)
        net_fire(shared, @"GET", [NSString stringWithFormat:@"echo?case=concurrent&i=%d", i],
                 @{@"X-Case": @"concurrent"}, nil, 0, g);

    // WebSocket (iOS 13+, 疑似缺口: hook 大概率无覆盖, 只记录能否建连)
    if (@available(iOS 13.0, *)) {
        if (g) dispatch_group_enter(g);
        NSString *wsBase = [base stringByReplacingOccurrencesOfString:@"http://" withString:@"ws://"];
        NSURLSessionWebSocketTask *ws = [shared webSocketTaskWithURL:[NSURL URLWithString:[wsBase stringByAppendingString:@"ws"]]];
        [ws resume];
        [ws sendMessage:[[NSURLSessionWebSocketMessage alloc] initWithString:@"hello-ws-matrix"]
            completionHandler:^(NSError *e) {
                if (e) { dispatch_group_leave(g); return; }
                [ws receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage *m, NSError *e2) {
                    [ws cancelWithCloseCode:NSURLSessionWebSocketCloseCodeNormalClosure reason:nil];
                    dispatch_group_leave(g);
                }];
            }];
    }

    long r = dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)));
    NSLog(@"[netmatrix] DONE wait=%ld (0=全部回调返回)", r);
}

static void do_network(void) {
    // 模拟微博 X-Validator 场景: SHA256(body) -> base64 设为请求头, 供 correlate_request 反查命中。
    NSData *body = [@"{\"probe\":\"network-capture\",\"secret\":\"s3cr3t\"}" dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char dg[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(body.bytes, (CC_LONG)body.length, dg);   // 被 hook -> 产生一条 SHA256 事件, output=dg
    NSString *validator = [[NSData dataWithBytes:dg length:sizeof(dg)] base64EncodedStringWithOptions:0];

    // 只打 dylib 自己的回环 HTTP 服务，测试不依赖公网。端口可能因本机占用而顺延，
    // 所以优先使用 dh_http_url() 返回的真实地址。
    NSURL *serviceURL = [NSURL URLWithString:dh_real_url() ?: @""];
    NSNumber *servicePort = serviceURL.port ?: @8088;
    NSString *baseURL = [NSString stringWithFormat:@"http://127.0.0.1:%@/", servicePort];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:baseURL]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:validator forHTTPHeaderField:@"X-Validator"];   // = base64(SHA256(body))
    req.HTTPBody = body;
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) { /* 结果无所谓 */ }];
    [t resume];
}

// ==================== 伪装/绕过自检(自检 tab) ====================
// 每项直接调用检测手法, 反推伪装是否生效, 返回可读结果。同时这些调用会被 dylib 观测并落日志。

static NSString *chk_jailbreak_files(void) {
    const char *paths[] = { "/Applications/Cydia.app", "/bin/bash", "/etc/apt", "/var/jb", "/usr/sbin/sshd" };
    NSMutableString *s = [NSMutableString stringWithString:@"[越狱文件探测]\n"];
    for (int i = 0; i < 5; i++) {
        struct stat st;
        BOOL visible = (access(paths[i], F_OK) == 0) || (stat(paths[i], &st) == 0);
        [s appendFormat:@"  %s → %@\n", paths[i], visible ? @"可见!(未隐藏)" : @"已隐藏"];
    }
    return s;
}

static NSString *chk_url_schemes(void) {
    NSArray<NSString *> *schemes = @[ @"cydia", @"sileo", @"filza", @"zbra" ];
    NSMutableString *s = [NSMutableString stringWithString:@"[URL Scheme 探测 canOpenURL]\n"];
    UIApplication *app = [UIApplication sharedApplication];
    for (NSString *sc in schemes) {
        NSURL *u = [NSURL URLWithString:[sc stringByAppendingString:@"://package"]];
        BOOL can = [app canOpenURL:u];
        [s appendFormat:@"  %@:// → %@\n", sc, can ? @"可打开!(未隐藏)" : @"已隐藏(canOpenURL=NO)"];
    }
    return s;
}

static NSString *chk_dyld_images(void) {
    const char *marks[] = { "decrypt_helper", "substrate", "TweakInject", "libhooker", "ellekit" };
    uint32_t cnt = _dyld_image_count();
    int hits = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        for (int j = 0; j < 5; j++) if (strstr(n, marks[j])) { hits++; break; }
    }
    return [NSString stringWithFormat:@"[dyld image 遍历]\n  已加载 %u 个 image, 命中注入标记 %d 个 → %@\n",
            cnt, hits, hits == 0 ? @"注入痕迹已隐藏" : @"仍可见!"];
}

static NSString *chk_antidebug(void) {
    NSMutableString *s = [NSMutableString stringWithString:@"[反调试]\n"];
    int p = ptrace(31 /*PT_DENY_ATTACH*/, 0, 0, 0);
    [s appendFormat:@"  ptrace(PT_DENY_ATTACH) → 返回 %d %@\n", p, p == 0 ? @"(空转,已绕过)" : @"(未绕过)"];
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info; size_t sz = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, NULL, 0) == 0) {
        BOOL traced = (info.kp_proc.p_flag & P_TRACED) != 0;
        [s appendFormat:@"  sysctl P_TRACED → %@\n", traced ? @"被跟踪!" : @"未被跟踪(已清)"];
    }
    return s;
}

static NSString *chk_device_info(void) {
    NSMutableString *s = [NSMutableString stringWithString:@"[设备信息(改机开则为伪造值)]\n"];
    UIDevice *d = [UIDevice currentDevice];
    [s appendFormat:@"  UIDevice.systemVersion = %@\n", d.systemVersion];
    [s appendFormat:@"  UIDevice.name = %@\n", d.name];
    [s appendFormat:@"  IDFV = %@\n", d.identifierForVendor.UUIDString];
    char m[64] = {0}; size_t ml = sizeof(m);
    if (sysctlbyname("hw.machine", m, &ml, NULL, 0) == 0) [s appendFormat:@"  sysctl hw.machine = %s\n", m];
    struct utsname un; if (uname(&un) == 0) [s appendFormat:@"  uname.machine = %s\n", un.machine];
    NSUUID *idfa = [[ASIdentifierManager sharedManager] advertisingIdentifier];
    [s appendFormat:@"  IDFA = %@\n", idfa.UUIDString];
    return s;
}

// ==================== 测试台 VC ====================
@interface TestVC : UIViewController <WKNavigationDelegate, WKScriptMessageHandler, WKURLSchemeHandler>
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) NSMutableDictionary<NSString *, UIButton *> *btnMap;
@property (nonatomic, strong) NSMutableArray<UIScrollView *> *tabScrolls;
@property (nonatomic, strong) UISegmentedControl *seg;
@property (nonatomic, strong) UITextView *checkOut;
@property (nonatomic, strong) WKWebView *wkWebView;
@property (nonatomic, assign) BOOL wkMessageSeen;
- (BOOL)triggerByKey:(NSString *)key;
- (BOOL)triggerScenarioById:(NSString *)scenarioId;
- (void)runWebKitSuite;
@end

@implementation TestVC
- (void)viewDidLoad {
    [super viewDidLoad];
    dh_write_status();
    [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *timer) {
        (void)timer;
        dh_write_status();
    }];
    self.btnMap = [NSMutableDictionary dictionary];
    self.tabScrolls = [NSMutableArray array];
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.09 blue:0.13 alpha:1.0];

    UILabel *title = [UILabel new];
    title.text = @"IOSDecryptHub 测试台";
    title.font = [UIFont systemFontOfSize:21 weight:UIFontWeightBold];
    title.textColor = [UIColor whiteColor];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    self.status = [UILabel new];
    self.status.text = @"选 tab, 点按钮触发对应系统调用, 看悬浮窗计数 / Web 面板";
    self.status.font = [UIFont systemFontOfSize:12];
    self.status.numberOfLines = 0;
    self.status.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    self.status.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.status];

    self.seg = [[UISegmentedControl alloc] initWithItems:@[@"加解密", @"系统", @"伪装自检"]];
    self.seg.selectedSegmentIndex = 0;
    self.seg.translatesAutoresizingMaskIntoConstraints = NO;
    [self.seg addTarget:self action:@selector(onSeg:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:self.seg];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor      constraintEqualToAnchor:g.topAnchor constant:12],
        [title.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [title.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.status.topAnchor      constraintEqualToAnchor:title.bottomAnchor constant:6],
        [self.status.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.status.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.seg.topAnchor      constraintEqualToAnchor:self.status.bottomAnchor constant:10],
        [self.seg.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.seg.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
    ]];

    UIColor *green  = [UIColor colorWithRed:0.34 green:0.83 blue:0.39 alpha:1.0];
    UIColor *blue   = [UIColor colorWithRed:0.35 green:0.65 blue:1.00 alpha:1.0];
    UIColor *orange = [UIColor colorWithRed:0.94 green:0.64 blue:0.36 alpha:1.0];
    UIColor *purple = [UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1.0];
    UIColor *mint   = [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0];
    UIColor *red    = [UIColor colorWithRed:0.95 green:0.45 blue:0.45 alpha:1.0];
    UIColor *pink   = [UIColor colorWithRed:1.00 green:0.62 blue:0.74 alpha:1.0];

    // --- tab 0: 加解密 ---
    UIStackView *t0 = [self addTabStack];
    [self addGroup:t0 title:@"摘要" color:green buttons:@[@"MD5",@"SHA1",@"SHA256",@"SHA512"]
              sels:@[@"onMD5",@"onSHA1",@"onSHA256",@"onSHA512"] keys:@[@"md5",@"sha1",@"sha256",@"sha512"]];
    [self addGroup:t0 title:@"HMAC" color:blue buttons:@[@"HMAC-SHA256"] sels:@[@"onHMAC"] keys:@[@"hmac"]];
    [self addGroup:t0 title:@"对称加密" color:orange buttons:@[@"AES-CBC",@"3DES",@"DES",@"RC4"]
              sels:@[@"onAES",@"on3DES",@"onDES",@"onRC4"] keys:@[@"aes",@"3des",@"des",@"rc4"]];
    [self addGroup:t0 title:@"非对称" color:purple buttons:@[@"RSA 签名",@"RSA 加密"]
              sels:@[@"onRSASign",@"onRSAEnc"] keys:@[@"rsasign",@"rsaenc"]];
    [self addGroup:t0 title:@"密钥派生" color:mint buttons:@[@"PBKDF2"] sels:@[@"onPBKDF"] keys:@[@"pbkdf"]];
    [self addGroup:t0 title:@"压测 / 综合" color:red buttons:@[@"128KB 大数据",@"全部跑一遍"]
              sels:@[@"onBig",@"onAll"] keys:@[@"big",@"all"]];

    // --- tab 1: 系统(文件 + 模块加载) ---
    UIStackView *t1 = [self addTabStack];
    [self addGroup:t1 title:@"Keychain" color:pink buttons:@[@"增查改删"]
              sels:@[@"onKeychain"] keys:@[@"keychain"]];
    [self addGroup:t1 title:@"文件操作" color:orange buttons:@[@"写文件",@"读文件",@"删除",@"重命名"]
              sels:@[@"onFWrite",@"onFRead",@"onFDel",@"onFRename"] keys:@[@"fwrite",@"fread",@"fdel",@"frename"]];
    [self addGroup:t1 title:@"动态库" color:purple buttons:@[@"dlopen 模块", @"dlsym 符号"]
              sels:@[@"onDlopen",@"onDlsym"] keys:@[@"dlopen",@"dlsym"]];
    [self addGroup:t1 title:@"网络矩阵" color:mint buttons:@[@"全部请求跑一遍"] sels:@[@"onNetAll"] keys:@[@"netall"]];
    [self addGroup:t1 title:@"WebKit 宿主侧观测" color:blue buttons:@[@"WKWebView 全链路"]
              sels:@[@"onWebKit"] keys:@[@"webkit"]];

    // --- tab 2: 伪装自检(验证越狱绕过 / 改机 / 注入隐藏是否生效) ---
    UIStackView *t2 = [self addTabStack];
    [self addGroup:t2 title:@"越狱绕过" color:green buttons:@[@"越狱文件探测",@"URL Scheme",@"dyld 遍历"]
              sels:@[@"onChkJB",@"onChkURL",@"onChkDyld"] keys:@[@"chkjb",@"chkurl",@"chkdyld"]];
    [self addGroup:t2 title:@"反调试 / 改机" color:orange buttons:@[@"反调试",@"设备信息",@"全部自检"]
              sels:@[@"onChkAnti",@"onChkDevice",@"onChkAll"] keys:@[@"chkanti",@"chkdevice",@"chkall"]];
    UILabel *rl = [UILabel new];
    rl.text = @"自检结果(这些调用也会被 dylib 观测并落日志):";
    rl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    rl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [t2 addArrangedSubview:rl];
    self.checkOut = [UITextView new];
    self.checkOut.editable = NO;
    self.checkOut.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.09 alpha:1.0];
    self.checkOut.textColor = [UIColor colorWithRed:0.80 green:0.86 blue:0.90 alpha:1.0];
    self.checkOut.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.checkOut.layer.cornerRadius = 8;
    self.checkOut.text = @"点上面按钮运行自检…\n";
    [self.checkOut.heightAnchor constraintEqualToConstant:300].active = YES;
    [t2 addArrangedSubview:self.checkOut];

    self.tabScrolls[0].hidden = NO;   // 默认显示加解密

    __weak typeof(self) ws = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *u = dh_real_url();
        gUrlHint = u ?: @"";
        if (u) ws.status.text = [NSString stringWithFormat:@"选 tab 点按钮触发, 看悬浮窗 / 浏览器 %@", u];
    });
    // 启动后发一次网络请求, 触发网络抓包 hook (即便无外网, resume 已在请求发出前被 swizzle 捕获)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        do_network();
        unsigned char d[CC_MD5_DIGEST_LENGTH]; CC_MD5("iPhone", 6, d);   // 噪声验证: 应进 crypto 噪声桶而非主流
    });
    // 精确触发: DH_TRIGGER=<按键 key 或 baseline.* 场景 id>, 启动后触发单个动作,
    // 供自动化测试无人值守使用(免 simctl openurl 确认框)。
    NSString *oneShot = [[NSProcessInfo processInfo].environment[@"DH_TRIGGER"] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (oneShot.length) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (![ws triggerByKey:oneShot]) NSLog(@"[DH_TRIGGER] 未知 key: %@", oneShot);
        });
    }
    // 截图/自动化: DH_AUTOTEST=1 启动后自动触发各类调用(免 simctl openurl 确认框)
    if ([[NSProcessInfo processInfo].environment[@"DH_AUTOTEST"] isEqualToString:@"1"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            for (NSString *k in @[@"md5",@"sha1",@"sha256",@"sha512",@"hmac",@"aes",@"3des",@"des",@"rc4",
                                  @"rsasign",@"rsaenc",@"pbkdf",@"big",
                                  @"keychain",@"fwrite",@"fread",@"fdel",@"frename",@"dlopen",@"dlsym",
                                  @"webkit",
                                  @"chkjb",@"chkurl",@"chkdyld",@"chkanti",@"chkdevice"])
                [ws triggerByKey:k];
        });
    }
}

- (UIStackView *)addTabStack {
    UIScrollView *sv = [UIScrollView new];
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    sv.hidden = YES;
    [self.view addSubview:sv];
    UIStackView *stack = [UIStackView new];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 10;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [sv addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor      constraintEqualToAnchor:self.seg.bottomAnchor constant:12],
        [sv.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],
        [stack.topAnchor      constraintEqualToAnchor:sv.topAnchor],
        [stack.leadingAnchor  constraintEqualToAnchor:sv.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor constant:-16],
        [stack.bottomAnchor   constraintEqualToAnchor:sv.bottomAnchor constant:-16],
        [stack.widthAnchor    constraintEqualToAnchor:sv.widthAnchor constant:-32],
    ]];
    [self.tabScrolls addObject:sv];
    return stack;
}

- (void)onSeg:(UISegmentedControl *)s {
    for (NSUInteger i = 0; i < self.tabScrolls.count; i++)
        self.tabScrolls[i].hidden = (i != (NSUInteger)s.selectedSegmentIndex);
}

- (void)addGroup:(UIStackView *)parent title:(NSString *)t color:(UIColor *)c
         buttons:(NSArray<NSString *> *)titles sels:(NSArray<NSString *> *)sels
            keys:(NSArray<NSString *> *)keys {
    UILabel *gl = [UILabel new];
    gl.text = t;
    gl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    gl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [parent addArrangedSubview:gl];
    UIStackView *row = nil;
    for (NSUInteger i = 0; i < titles.count; i++) {
        if (i % 2 == 0) {
            row = [UIStackView new];
            row.axis = UILayoutConstraintAxisHorizontal;
            row.spacing = 10;
            row.distribution = UIStackViewDistributionFillEqually;
            [parent addArrangedSubview:row];
        }
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
        b.backgroundColor = [c colorWithAlphaComponent:0.22];
        b.layer.cornerRadius = 10;
        b.layer.borderWidth = 1.0;
        b.layer.borderColor = [c colorWithAlphaComponent:0.6].CGColor;
        [b.heightAnchor constraintEqualToConstant:46].active = YES;
        [b addTarget:self action:NSSelectorFromString(sels[i]) forControlEvents:UIControlEventTouchUpInside];
        [row addArrangedSubview:b];
        self.btnMap[keys[i]] = b;
    }
    if (titles.count % 2 == 1) [row addArrangedSubview:[UIView new]];  // 单数补占位, 末按钮不撑满
}

- (BOOL)triggerByKey:(NSString *)key {
    dh_write_status();
    if ([key hasPrefix:@"baseline."]) return [self triggerScenarioById:key];
    if ([key isEqualToString:@"netall"]) { do_net_matrix(); [self flash:@"网络矩阵"]; return YES; }
    if ([key isEqualToString:@"webkit"]) { [self runWebKitSuite]; [self flash:@"WKWebView 全链路"]; return YES; }
    if ([key isEqualToString:@"sessionburst"]) {
        for (NSUInteger index = 0; index < 192; index++) do_digest(2);
        [self flash:@"会话摘要突发"];
        return YES;
    }
    UIButton *b = self.btnMap[key.lowercaseString];
    if (!b) return NO;
    [b sendActionsForControlEvents:UIControlEventTouchUpInside];
    return YES;
}

- (BOOL)triggerScenarioById:(NSString *)scenarioId {
    if (![scenarioId isKindOfClass:NSString.class]) return NO;
    NSLog(@"[scenario] START %@", scenarioId);
    if ([scenarioId isEqualToString:@"baseline.crypto.digest"]) {
        do_digest(2);
    } else if ([scenarioId isEqualToString:@"baseline.crypto.hmac"]) {
        do_hmac();
    } else if ([scenarioId isEqualToString:@"baseline.crypto.rsa"]) {
        dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); });
    } else if ([scenarioId isEqualToString:@"baseline.keychain.lifecycle"]) {
        do_keychain();
    } else if ([scenarioId isEqualToString:@"baseline.file.lifecycle"]) {
        do_file_write();
        do_file_read();
        do_file_rename();
        NSString *backup = [test_file_path() stringByAppendingPathExtension:@"bak"];
        unlink(backup.UTF8String);
    } else if ([scenarioId isEqualToString:@"baseline.environment.probes"]) {
        (void)chk_antidebug();
    } else if ([scenarioId isEqualToString:@"baseline.injection.visibility"]) {
        (void)chk_dyld_images();
    } else if ([scenarioId isEqualToString:@"baseline.network.request"]) {
        do_network();
    } else if ([scenarioId isEqualToString:@"baseline.network.matrix"]) {
        do_net_matrix();
    } else if ([scenarioId isEqualToString:@"baseline.webkit"]) {
        [self runWebKitSuite];
    } else {
        NSLog(@"[scenario] UNKNOWN %@", scenarioId);
        return NO;
    }
    NSLog(@"[scenario] DONE %@", scenarioId);
    [self flash:scenarioId];
    return YES;
}

// WKWebView 宿主侧确定性场景:
//   navigation -> userScript -> JS message -> evaluateJavaScript -> cookie -> custom scheme
// 网络和 DOM 仍在 WebContent/Networking 进程；这里验证的是 App 进程可见的 Objective-C 边界。
- (void)runWebKitSuite {
    self.wkMessageSeen = NO;
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    WKUserContentController *ucc = [WKUserContentController new];
    [ucc addScriptMessageHandler:self name:@"dh"];
    NSString *source =
        @"window.webkit.messageHandlers.dh.postMessage({fixture:'DH_WK_MSG_001',href:location.href});";
    WKUserScript *script = [[WKUserScript alloc] initWithSource:source
                                                     injectionTime:WKUserScriptInjectionTimeAtDocumentEnd
                                                  forMainFrameOnly:NO];
    [ucc addUserScript:script];
    cfg.userContentController = ucc;
    [cfg setURLSchemeHandler:self forURLScheme:@"dhcustom"];

    WKWebView *wk = [[WKWebView alloc] initWithFrame:CGRectMake(0, 0, 320, 180) configuration:cfg];
    wk.navigationDelegate = self;
    if (@available(iOS 16.4, *)) wk.inspectable = YES;
    [self.view addSubview:wk];
    self.wkWebView = wk;

    NSString *html =
        @"<html><head><title>DH_WK_TITLE</title></head><body>DH_WK_BODY"
         "<script>window.webkit.messageHandlers.dh.postMessage("
         "{fixture:'DH_WK_MSG_001',href:location.href});"
         "fetch('/echo?case=webkit-fetch').then(function(r){return r.text();});"
         "var xhr=new XMLHttpRequest();xhr.open('POST','/echo?case=webkit-xhr');"
         "xhr.setRequestHeader('X-WK-Fixture','DH_WK_XHR_001');xhr.send('DH_WK_XHR_BODY_001');"
         "var ws=new WebSocket('ws://127.0.0.1:8099/ws');"
         "ws.onopen=function(){ws.send('DH_WK_WS_001');};"
         "var es=new EventSource('/events?case=webkit-eventsource');"
         "console.log('DH_WK_CONSOLE_001');"
         "localStorage.setItem('DH_WK_STORAGE_001','storage-value');"
         "crypto.subtle.digest('SHA-256',new TextEncoder().encode('DH_WK_CRYPTO_001'));"
         "if(navigator.sendBeacon)navigator.sendBeacon('/echo?case=webkit-beacon','DH_WK_BEACON_001');"
         "</script></body></html>";
    [wk loadHTMLString:html baseURL:[NSURL URLWithString:@"http://127.0.0.1:8099/"]];
    [wk evaluateJavaScript:@"document.title" completionHandler:^(id result, NSError *error) {
        NSLog(@"[webkit] eval title result=%@ error=%@", result, error);
    }];

    WKHTTPCookieStore *store = cfg.websiteDataStore.httpCookieStore;
    NSHTTPCookie *cookie = [NSHTTPCookie cookieWithProperties:@{
        NSHTTPCookieName:   @"dh_cookie",
        NSHTTPCookieValue:  @"DH_WK_COOKIE_001",
        NSHTTPCookieDomain: @"dh.test",
        NSHTTPCookiePath:   @"/",
    }];
    __weak WKHTTPCookieStore *weakStore = store;
    [store setCookie:cookie completionHandler:^{
        [weakStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
            NSLog(@"[webkit] cookies=%lu", (unsigned long)cookies.count);
            [weakStore deleteCookie:cookie completionHandler:^{
                NSLog(@"[webkit] cookie deleted");
            }];
        }];
    }];
    [cfg.websiteDataStore fetchDataRecordsOfTypes:[NSSet setWithObject:WKWebsiteDataTypeCookies]
                                completionHandler:^(NSArray<WKWebsiteDataRecord *> *records) {
        NSLog(@"[webkit] data records=%lu", (unsigned long)records.count);
    }];

    // 让 HTML 先完成一次 documentEnd message/evaluate，再走自定义 scheme handler。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [wk loadRequest:[NSURLRequest requestWithURL:
            [NSURL URLWithString:@"dhcustom://fixture/page?case=webkit-scheme"]]];
    });
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didStartProvisionalNavigation:(WKNavigation *)navigation {
    NSLog(@"[webkit] didStart %@", webView.URL.absoluteString);
}
- (void)webView:(WKWebView *)webView didCommitNavigation:(WKNavigation *)navigation {
    NSLog(@"[webkit] didCommit %@", webView.URL.absoluteString);
}
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    NSLog(@"[webkit] didFinish %@", webView.URL.absoluteString);
    [webView evaluateJavaScript:@"document.title" completionHandler:^(id result, NSError *error) {
        NSLog(@"[webkit] finish title=%@ error=%@", result, error);
    }];
}
- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    NSLog(@"[webkit] didFail %@", error.localizedDescription);
}
- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    NSLog(@"[webkit] didFailProvisional %@", error.localizedDescription);
}
- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                    decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSLog(@"[webkit] decide %@", navigationAction.request.URL.absoluteString);
    decisionHandler(WKNavigationActionPolicyAllow);
}

#pragma mark - WKScriptMessageHandler

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if ([message.name isEqualToString:@"dh"]) self.wkMessageSeen = YES;
    NSLog(@"[webkit] message name=%@ body=%@", message.name, message.body);
}

#pragma mark - WKURLSchemeHandler

- (void)webView:(WKWebView *)webView startURLSchemeTask:(id<WKURLSchemeTask>)urlSchemeTask {
    NSHTTPURLResponse *response =
        [[NSHTTPURLResponse alloc] initWithURL:urlSchemeTask.request.URL
                                    statusCode:200
                                   HTTPVersion:@"HTTP/1.1"
                                  headerFields:@{@"Content-Type": @"text/html"}];
    [urlSchemeTask didReceiveResponse:response];
    [urlSchemeTask didReceiveData:[@"DH_WK_SCHEME_BODY" dataUsingEncoding:NSUTF8StringEncoding]];
    [urlSchemeTask didFinish];
}

- (void)webView:(WKWebView *)webView stopURLSchemeTask:(id<WKURLSchemeTask>)urlSchemeTask {
    NSLog(@"[webkit] scheme stop %@", urlSchemeTask.request.URL.absoluteString);
}

- (void)flash:(NSString *)name {
    NSString *u = gUrlHint.length ? [@" / 浏览器 " stringByAppendingString:gUrlHint] : @"";
    self.status.text = [NSString stringWithFormat:@"已触发 %@, 看悬浮窗计数%@", name, u];
    self.status.textColor = [UIColor colorWithRed:0.36 green:0.92 blue:0.70 alpha:1.0];
}

// 加解密
- (void)onMD5    { do_digest(0); [self flash:@"MD5"]; }
- (void)onSHA1   { do_digest(1); [self flash:@"SHA1"]; }
- (void)onSHA256 { do_digest(2); [self flash:@"SHA256"]; }
- (void)onSHA512 { do_digest(3); [self flash:@"SHA512"]; }
- (void)onHMAC   { do_hmac();    [self flash:@"HMAC-SHA256"]; }
- (void)onAES    { do_sym(kCCAlgorithmAES, 16, 16);  [self flash:@"AES-128-CBC"]; }
- (void)on3DES   { do_sym(kCCAlgorithm3DES, 24, 8);  [self flash:@"3DES"]; }
- (void)onDES    { do_sym(kCCAlgorithmDES, 8, 8);    [self flash:@"DES"]; }
- (void)onRC4    { do_rc4();      [self flash:@"RC4"]; }
- (void)onRSASign {
    [self flash:@"RSA 签名 (首次生成密钥…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 签名"]; }); });
}
- (void)onRSAEnc {
    [self flash:@"RSA 加密 (首次生成密钥…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_enc(); dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"RSA 加密"]; }); });
}
- (void)onPBKDF  { do_pbkdf();    [self flash:@"PBKDF2-HMAC-SHA256"]; }
- (void)onKeychain { do_keychain(); [self flash:@"Keychain"]; }
- (void)onBig    { do_bigdata();  [self flash:@"128KB 大数据 AES"]; }
- (void)onAll {
    do_digest(0); do_digest(1); do_digest(2); do_digest(3);
    do_hmac(); do_sym(kCCAlgorithmAES, 16, 16); do_sym(kCCAlgorithm3DES, 24, 8);
    do_sym(kCCAlgorithmDES, 8, 8); do_rc4(); do_pbkdf(); do_keychain();
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_rsa_sign(); do_rsa_enc(); });
    [self flash:@"全部算法"];
}
// 文件
- (void)onFWrite   { do_file_write();  [self flash:@"写文件"]; }
- (void)onFRead    { do_file_read();   [self flash:@"读文件"]; }
- (void)onFDel     { do_file_delete(); [self flash:@"删除文件"]; }
- (void)onFRename  { do_file_rename(); [self flash:@"重命名"]; }
// 系统
- (void)onDlopen   { do_dlopen();      [self flash:@"dlopen 模块"]; }
- (void)onDlsym    { do_dlsym();       [self flash:@"dlsym 符号"]; }
- (void)onNetAll {
    [self flash:@"网络矩阵 (约 30 秒…)"];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ do_net_matrix(); dispatch_async(dispatch_get_main_queue(), ^{ [self flash:@"网络矩阵完成"]; }); });
}
- (void)onWebKit {
    [self runWebKitSuite];
    [self flash:@"WKWebView 全链路"];
}
// 伪装自检
- (void)appendCheck:(NSString *)text {
    self.checkOut.text = [self.checkOut.text stringByAppendingString:[text stringByAppendingString:@"\n"]];
    NSRange end = NSMakeRange(self.checkOut.text.length, 0);
    [self.checkOut scrollRangeToVisible:end];
}
- (void)onChkJB     { [self appendCheck:chk_jailbreak_files()]; [self flash:@"越狱文件探测"]; }
- (void)onChkURL    { [self appendCheck:chk_url_schemes()];     [self flash:@"URL Scheme 探测"]; }
- (void)onChkDyld   { [self appendCheck:chk_dyld_images()];     [self flash:@"dyld 遍历"]; }
- (void)onChkAnti   { [self appendCheck:chk_antidebug()];       [self flash:@"反调试自检"]; }
- (void)onChkDevice { [self appendCheck:chk_device_info()];     [self flash:@"设备信息"]; }
- (void)onChkAll {
    self.checkOut.text = @"";
    [self appendCheck:chk_jailbreak_files()];
    [self appendCheck:chk_url_schemes()];
    [self appendCheck:chk_dyld_images()];
    [self appendCheck:chk_antidebug()];
    [self appendCheck:chk_device_info()];
    [self flash:@"全部自检完成"];
}
@end

// ==================== Scene / App ====================
@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation SceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)connectionOptions {
    UIWindowScene *ws = (UIWindowScene *)scene;
    self.window = [[UIWindow alloc] initWithWindowScene:ws];
    self.window.rootViewController = [TestVC new];
    [self.window makeKeyAndVisible];
    if (connectionOptions.URLContexts.count) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self scene:scene openURLContexts:connectionOptions.URLContexts]; });
    }
}
- (void)scene:(UIScene *)scene openURLContexts:(NSSet<UIOpenURLContext *> *)URLContexts {
    TestVC *vc = (TestVC *)self.window.rootViewController;
    if (![vc isKindOfClass:[TestVC class]]) return;
    for (UIOpenURLContext *ctx in URLContexts) {
        NSString *key = ctx.URL.host ?: [ctx.URL.path stringByReplacingOccurrencesOfString:@"/" withString:@""];
        [vc triggerByKey:key];
    }
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions { return YES; }
- (UISceneConfiguration *)application:(UIApplication *)application
        configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession
        options:(UISceneConnectionOptions *)options {
    UISceneConfiguration *cfg = [[UISceneConfiguration alloc] initWithName:@"Default" sessionRole:connectingSceneSession.role];
    cfg.delegateClass = [SceneDelegate class];
    return cfg;
}
@end

static void dh_ensure_plugin(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "decrypt_helper")) {
            gPluginLoad = @"already";
            return;
        }
    }
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithObjects:
        @"/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib",
        @"/usr/lib/IOSDecryptHub/decrypt_helper.dylib", nil];
    NSString *dir = [[NSBundle mainBundle] executablePath].stringByDeletingLastPathComponent;
    for (int i = 0; i < 8 && dir.length > 1; i++) {
        [paths addObject:[dir stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub/decrypt_helper.dylib"]];
        dir = dir.stringByDeletingLastPathComponent;
    }
    NSMutableString *last = [NSMutableString string];
    for (NSString *path in paths) {
        if (dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL)) {
            gPluginLoad = @"ok";
            return;
        }
        const char *err = dlerror();
        [last appendFormat:@"%s | %@", err ?: "?", path];
    }
    gPluginLoad = last.length ? last : @"not-found";
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        dh_ensure_plugin();
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
