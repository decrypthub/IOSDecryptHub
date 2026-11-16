// DHConfigStore.m — 见头文件注释

#import "DHConfigStore.h"
#import "dh_shared.h"
#import "dh_package_update.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>

NSString *_Nullable DHBootstrapRoot(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&DHBootstrapRoot, &info) == 0 || !info.dli_fname) {
        return nil;
    }
    NSString *binaryPath = [NSString stringWithUTF8String:info.dli_fname];
    // App 布局: <bootstrap>/Applications/IOSDecryptHubManager.app/IOSDecryptHubManager
    // 向上三级回到 <bootstrap>
    NSString *root = binaryPath;
    for (int i = 0; i < 3; i++) {
        root = [root stringByDeletingLastPathComponent];
    }
    // "/" 是合法 jbroot（rootHide 在 SSH 视角下 jbroot=/）。
    // 真机 App 里 dladdr 通常是 .jbroot-XXXX，长度 > 1；两种都要认。
    if (root.length == 0) return nil;
    return root;
}

static NSArray<NSString *> *dh_engine_dir_candidates(void) {
    NSMutableArray<NSString *> *dirs = [NSMutableArray array];
    NSString *root = DHBootstrapRoot();
    if (root) {
        [dirs addObject:[root stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub"]];
    }
    [dirs addObject:@"/var/jb/usr/lib/IOSDecryptHub"];
    return dirs;
}

static NSString *_Nullable dh_existing_engine_dir(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    for (NSString *dir in dh_engine_dir_candidates()) {
        if ([fm fileExistsAtPath:dir isDirectory:&isDir] && isDir) return dir;
    }
    return nil;
}

static NSString *_Nullable dh_config_path(void) {
    // 以引擎目录为准：插件装上后目录一定在，名单文件可能还没建。
    // 旧逻辑要求 plist 已存在，且相对路径少了 usr/lib/，roothide 上 /var/jb
    // 又不存在，于是写到 <jbroot>/IOSDecryptHub/config/（父目录不存在）并失败。
    NSString *dir = dh_existing_engine_dir();
    if (dir) {
        return [dir stringByAppendingPathComponent:@"config/enabledBundles.plist"];
    }
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    NSString *root = DHBootstrapRoot();
    if (root) {
        [paths addObject:[root stringByAppendingPathComponent:DH_CONFIG_REL]];
    }
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"];
    return paths.firstObject;
}

// roothide: 绝对 /var/mobile 会被容器重定向；NSHomeDirectory() 才是 App 与
// daemon 共享的真实 /var/mobile。loader prefs 也必须走这个路径，否则 daemon
// 读不到 App 写入的 updaterRequest。
static NSString *dh_loader_prefs_path(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:
        @"Library/Preferences/com.iosdecrypthub.loader.plist"];
}

static NSSet<NSString *> *_Nullable dh_bundles_from_dict(NSDictionary *domain) {
    id value = domain[DH_KEY_BUNDLES];
    if ([value isKindOfClass:[NSArray class]]) return [NSSet setWithArray:value];
    return nil;
}

NSSet<NSString *> *DHReadEnabledBundles(void) {
    @try {
        NSSet *fromHome = dh_bundles_from_dict(
            [NSDictionary dictionaryWithContentsOfFile:dh_loader_prefs_path()]);
        if (fromHome) return fromHome;

        NSSet *fromPrefs = dh_bundles_from_dict(
            [NSDictionary dictionaryWithContentsOfFile:DH_LOADER_PREFS]);
        if (fromPrefs) return fromPrefs;

        CFPreferencesAppSynchronize((__bridge CFStringRef)DH_DOMAIN_LOADER);
        CFPropertyListRef raw = CFPreferencesCopyAppValue(
            (__bridge CFStringRef)DH_KEY_BUNDLES,
            (__bridge CFStringRef)DH_DOMAIN_LOADER);
        id value = CFBridgingRelease(raw);
        if ([value isKindOfClass:[NSArray class]]) return [NSSet setWithArray:value];

        NSSet *fromJb = dh_bundles_from_dict(
            [NSDictionary dictionaryWithContentsOfFile:dh_config_path()]);
        if (fromJb) return fromJb;
    } @catch (__unused NSException *e) {
    }
    return [NSSet set];
}

static void dh_sync_cfprefs(NSArray<NSString *> *values) {
    CFPreferencesSetValue((__bridge CFStringRef)DH_KEY_BUNDLES,
        (__bridge CFPropertyListRef)values,
        (__bridge CFStringRef)DH_DOMAIN_LOADER,
        kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    CFPreferencesSynchronize((__bridge CFStringRef)DH_DOMAIN_LOADER,
        kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
}

static BOOL dh_try_write_jb_config(NSData *data) {
    NSString *path = dh_config_path();
    if (path.length == 0 || !data) return NO;
    NSString *dir = [path stringByDeletingLastPathComponent];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
        withIntermediateDirectories:YES
                         attributes:@{ NSFilePosixPermissions: @0777 }
                              error:&error];
    if (![data writeToFile:path options:NSDataWritingAtomic error:&error]) return NO;
    [[NSFileManager defaultManager] setAttributes:@{
        NSFilePosixPermissions: @0666,
        NSFileProtectionKey: NSFileProtectionNone,
    } ofItemAtPath:path error:nil];
    return YES;
}

// 更新请求多路投递。roothide 下 App 的绝对 /var/mobile 会被容器重定向，
// 必须用 NSHomeDirectory() 拼接才能落到 daemon 能读到的真实路径；同时把请求
// 挂到 loader prefs 的 updaterRequest 键，借用 daemon 已监听的通道触发。
static BOOL dh_write_request_dict(NSDictionary *req) {
    BOOL ok = NO;
    NSString *home = NSHomeDirectory();
    NSArray<NSString *> *paths = @[
        [home stringByAppendingPathComponent:@"Library/Preferences/com.iosdecrypthub.updater.request.plist"],
        [home stringByAppendingPathComponent:@"Library/Caches/com.iosdecrypthub/updater.request.plist"],
        DH_REQUEST_PATH,
        DH_REQUEST_CACHE_PATH,
    ];
    for (NSString *path in paths) {
        @try {
            NSString *dir = [path stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] createDirectoryAtPath:dir
                withIntermediateDirectories:YES
                                 attributes:@{ NSFilePosixPermissions: @0777 }
                                      error:nil];
            if ([req writeToFile:path atomically:YES]) {
                ok = YES;
                [[NSFileManager defaultManager] setAttributes:@{
                    NSFilePosixPermissions: @0666,
                    NSFileProtectionKey: NSFileProtectionNone,
                } ofItemAtPath:path error:nil];
            }
        } @catch (__unused NSException *e) {
        }
    }
    @try {
        NSString *loaderPath = dh_loader_prefs_path();
        NSMutableDictionary *prefs =
            [[NSDictionary dictionaryWithContentsOfFile:loaderPath] mutableCopy]
                ?: [NSMutableDictionary dictionary];
        prefs[@"updaterRequest"] = req;
        if ([prefs writeToFile:loaderPath atomically:YES]) {
            ok = YES;
            [[NSFileManager defaultManager] setAttributes:@{
                NSFilePosixPermissions: @0644,
                NSFileProtectionKey: NSFileProtectionNone,
            } ofItemAtPath:loaderPath error:nil];
        }
    } @catch (__unused NSException *e) {
    }
    return ok;
}

static void dh_request_set_enabled(NSArray<NSString *> *values) {
    NSDictionary *req = @{
        @"action": DH_REQ_SET_ENABLED,
        DH_KEY_BUNDLES: values ?: @[],
        @"time": @([[NSDate date] timeIntervalSince1970]),
    };
    (void)dh_write_request_dict(req);
}

BOOL DHWriteEnabledBundles(NSSet<NSString *> *bundleIDs, NSError **outError) {
    NSArray *values = [[bundleIDs allObjects] sortedArrayUsingSelector:@selector(compare:)];
    NSString *loaderPath = dh_loader_prefs_path();
    // 保留 updaterRequest 等其它键，避免开关 App 时把待处理的更新请求清掉。
    NSMutableDictionary *plist =
        [[NSDictionary dictionaryWithContentsOfFile:loaderPath] mutableCopy]
            ?: [NSMutableDictionary dictionary];
    plist[DH_KEY_BUNDLES] = values;
    @try {
        NSError *error = nil;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist
            format:NSPropertyListXMLFormat_v1_0 options:0 error:&error];
        if (!data) {
            if (outError) *outError = error;
            return NO;
        }
        // prefs 是管理器自己的权威副本；沙盒目标读不到它，还要再写 jb 配置。
        if (![data writeToFile:loaderPath options:NSDataWritingAtomic error:&error]) {
            if (outError) *outError = error;
            return NO;
        }
        [[NSFileManager defaultManager] setAttributes:@{
            NSFilePosixPermissions: @0644,
            NSFileProtectionKey: NSFileProtectionNone,
        } ofItemAtPath:loaderPath error:nil];
        dh_sync_cfprefs(values);
        (void)dh_try_write_jb_config(data);
        dh_request_set_enabled(values);
        return YES;
    } @catch (NSException *e) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"DHManager" code:-12 userInfo:
                @{NSLocalizedDescriptionKey: e.reason ?: @"写入异常"}];
        }
        return NO;
    }
}

NSDictionary *DHReadEngineMeta(void) {
    NSString *dir = dh_existing_engine_dir();
    if (!dir) return @{};
    @try {
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:
            [dir stringByAppendingPathComponent:DH_VERSION_FILE]];
        if ([meta isKindOfClass:[NSDictionary class]]) return meta;
    } @catch (__unused NSException *e) {
    }
    return @{};
}

NSDictionary *DHReadUpdaterState(void) {
    @try {
        NSDictionary *state = [NSDictionary dictionaryWithContentsOfFile:DH_STATE_PATH];
        if ([state isKindOfClass:[NSDictionary class]]) return state;
        NSString *root = DHBootstrapRoot();
        if (root.length) {
            state = [NSDictionary dictionaryWithContentsOfFile:
                [root stringByAppendingPathComponent:DH_JB_STATE_REL]];
            if ([state isKindOfClass:[NSDictionary class]]) return state;
        }
        NSString *dir = dh_existing_engine_dir();
        if (!dir) return @{};
        state = [NSDictionary dictionaryWithContentsOfFile:
            [dir stringByAppendingPathComponent:DH_STATE_FILE]];
        if ([state isKindOfClass:[NSDictionary class]]) return state;
    } @catch (__unused NSException *e) {
    }
    return @{};
}

NSDictionary<NSString *, NSDictionary *> *DHProbeInjectedApps(void) {
    NSMutableDictionary<NSString *, NSDictionary *> *found = [NSMutableDictionary dictionary];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 0.6;
    cfg.timeoutIntervalForResource = 0.6;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    dispatch_group_t group = dispatch_group_create();
    NSLock *lock = [[NSLock alloc] init];
    for (int port = 8088; port <= 8108; port++) {
        NSURL *url = [NSURL URLWithString:
            [NSString stringWithFormat:@"http://127.0.0.1:%d/api/stats", port]];
        if (!url) continue;
        dispatch_group_enter(group);
        [[session dataTaskWithURL:url completionHandler:^(NSData *data,
            NSURLResponse *response, NSError *error) {
            NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
            if (!error && http.statusCode == 200 && data.length) {
                id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                NSString *bid = nil;
                if ([json isKindOfClass:[NSDictionary class]]) {
                    id proc = json[@"process"];
                    if ([proc isKindOfClass:[NSDictionary class]]) bid = proc[@"bundleId"];
                }
                if ([bid isKindOfClass:[NSString class]] && bid.length) {
                    NSDictionary *info = @{
                        @"port": @(port),
                        @"version": ([json[@"version"] isKindOfClass:[NSString class]]
                            ? json[@"version"] : @""),
                    };
                    [lock lock];
                    found[bid] = info;
                    [lock unlock];
                }
            }
            dispatch_group_leave(group);
        }] resume];
    }
    dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)));
    [lock lock];
    NSDictionary *snapshot = [found copy];
    [lock unlock];
    [session invalidateAndCancel];
    return snapshot;
}

BOOL DHWriteUpdateRequest(NSString *action, NSString *_Nullable version) {
    if (DHPackageManagerRequired(action)) return NO;
    NSMutableDictionary *request = [NSMutableDictionary dictionary];
    request[@"action"] = action ?: DH_REQ_NONE;
    request[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    if (version.length) request[@"version"] = version;   // 指定版本安装（历史版本）
    NSDictionary *req = request;
    return dh_write_request_dict(req);
}

static NSString *dh_strip_v(NSString *s) {
    if ([s hasPrefix:@"v"] || [s hasPrefix:@"V"]) return [s substringFromIndex:1];
    return s;
}

NSComparisonResult DHCompareVersions(NSString *left, NSString *right) {
    NSArray<NSString *> *a = [dh_strip_v(left ?: @"") componentsSeparatedByString:@"."];
    NSArray<NSString *> *b = [dh_strip_v(right ?: @"") componentsSeparatedByString:@"."];
    NSUInteger n = MAX(a.count, b.count);
    for (NSUInteger i = 0; i < n; i++) {
        NSInteger x = (i < a.count) ? a[i].integerValue : 0;
        NSInteger y = (i < b.count) ? b[i].integerValue : 0;
        if (x < y) return NSOrderedAscending;
        if (x > y) return NSOrderedDescending;
    }
    return NSOrderedSame;
}

// 必须持有 session：局部变量出作用域即释放，任务会被取消（表现为"没网"）
static NSURLSession *dh_shared_session(void) {
    static NSURLSession *session = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 20;
        cfg.timeoutIntervalForResource = 30;
        session = [NSURLSession sessionWithConfiguration:cfg];
    });
    return session;
}

// 错误信息带上域与码，便于定位（只说"没网"没法排查）
static NSError *dh_net_error(NSError *error) {
    if (!error) return nil;
    NSString *text = [NSString stringWithFormat:@"%@（%@ %ld）",
        error.localizedDescription, error.domain, (long)error.code];
    return [NSError errorWithDomain:error.domain code:error.code
                           userInfo:@{NSLocalizedDescriptionKey: text}];
}

static void dh_fetch_latest_direct(void (^completion)(NSDictionary *_Nullable, NSError *_Nullable)) {
    DHFetchPackageUpdate(^(NSDictionary *info, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{ completion(info, error); });
    });
}

// App 本身在部分越狱环境（roothide 实测）会被网络策略拒绝，NSURLSession 直接返回
// -1020 DataNotAllowed；updater daemon 以 root 运行，网络始终可用。因此更新检查
// 优先让 daemon 做，App 只写请求 + 轮询 state。daemon 不可用时才回退直连。
static void dh_fetch_latest_from_daemon(void (^completion)(NSDictionary *_Nullable, NSError *_Nullable)) {
    NSTimeInterval requestTime = [[NSDate date] timeIntervalSince1970];
    if (!DHWriteUpdateRequest(DH_REQ_CHECK, nil)) {
        dh_fetch_latest_direct(completion);
        return;
    }
    __block NSInteger attempts = 0;
    __block BOOL retried = NO;
    __block BOOL finished = NO;
    __block void (^poll)(void) = nil;
    poll = ^{
        if (finished) { poll = nil; return; }
        attempts++;
        NSDictionary *state = DHReadUpdaterState();
        NSTimeInterval lastCheck = [state[@"lastCheck"] doubleValue];
        if (lastCheck >= requestTime - 0.5) {
            finished = YES;
            poll = nil;   // 断开递归 block 的自引用
            id latest = state[@"latestVersion"];
            id errText = state[@"lastCheckError"];
            if (![errText isKindOfClass:[NSString class]] && [latest isKindOfClass:[NSString class]] && [latest length] > 0) {
                completion(@{@"tag": latest, @"version": dh_strip_v(latest)}, nil);
            } else if ([errText isKindOfClass:[NSString class]] && [errText length] > 0) {
                completion(nil, [NSError errorWithDomain:@"DHManager" code:-20 userInfo:
                    @{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"后台更新服务：%@", errText]}]);
            } else {
                completion(nil, [NSError errorWithDomain:@"DHManager" code:-21 userInfo:
                    @{NSLocalizedDescriptionKey: @"后台更新服务没有返回版本信息"}]);
            }
            return;
        }
        // daemon 可能被周期任务占用或 WatchPaths 合并触发；5 秒后补写一次请求。
        if (!retried && attempts >= 12) {
            retried = YES;
            DHWriteUpdateRequest(DH_REQ_CHECK, nil);
        }
        if (attempts >= 100) {   // 40 秒
            finished = YES;
            poll = nil;
            dh_fetch_latest_direct(completion);
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), poll);
    };
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), poll);
}

void DHFetchLatestRelease(void (^completion)(NSDictionary *_Nullable, NSError *_Nullable)) {
    dh_fetch_latest_from_daemon(completion);
}

BOOL DHWriteRestartRequest(NSString *bundleID) {
    if (bundleID.length == 0) return NO;
    NSDictionary *req = @{
        @"action": DH_REQ_RESTART,
        @"bundle": bundleID,
        @"time": @([[NSDate date] timeIntervalSince1970]),
    };
    return dh_write_request_dict(req);
}

NSString *_Nullable DHPendingUpdateVersion(void) {
    id installedValue = DHReadEngineMeta()[@"version"];
    id latestValue = DHReadUpdaterState()[@"latestVersion"];
    if (![installedValue isKindOfClass:[NSString class]] ||
        ![latestValue isKindOfClass:[NSString class]]) return nil;
    NSString *installed = installedValue;
    NSString *latest = latestValue;
    if (installed.length == 0 || latest.length == 0) return nil;
    NSString *trimmed = [latest stringByTrimmingCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"vV"]];
    if (trimmed.length == 0) return nil;
    return DHCompareVersions(installed, trimmed) == NSOrderedAscending ? trimmed : nil;
}

BOOL DHWriteStopRequest(NSString *bundleID) {
    if (bundleID.length == 0) return NO;
    NSDictionary *req = @{
        @"action": DH_REQ_STOP,
        @"bundle": bundleID,
        @"time": @([[NSDate date] timeIntervalSince1970]),
    };
    return dh_write_request_dict(req);
}

#pragma mark - 历史版本

#define DH_RELEASES_API @"https://api.github.com/repos/decrypthub/IOSDecryptHub/releases?per_page=30"

void DHFetchReleases(void (^completion)(NSArray<NSDictionary *> *_Nullable, NSError *_Nullable)) {
    NSURL *url = [NSURL URLWithString:DH_RELEASES_API];
    NSURLSession *session = dh_shared_session();
    [[session dataTaskWithURL:url completionHandler:^(NSData *_Nullable data,
        __unused NSURLResponse *_Nullable response, NSError *_Nullable error) {
        NSArray<NSDictionary *> *list = nil;
        NSError *err = dh_net_error(error);
        if (!err) {
            @try {
                id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
                if (!err && [json isKindOfClass:[NSArray class]]) {
                    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
                    NSISO8601DateFormatter *parser = [[NSISO8601DateFormatter alloc] init];
                    NSDateFormatter *writer = [[NSDateFormatter alloc] init];
                    writer.dateFormat = @"yyyy-MM-dd";
                    for (id item in (NSArray *)json) {
                        if (![item isKindOfClass:[NSDictionary class]]) continue;
                        NSString *tag = item[@"tag_name"];
                        if (![tag isKindOfClass:[NSString class]] || tag.length == 0) continue;
                        if ([item[@"draft"] boolValue]) continue;
                        NSString *date = @"";
                        NSString *published = item[@"published_at"];
                        if ([published isKindOfClass:[NSString class]]) {
                            NSDate *parsed = [parser dateFromString:published];
                            if (parsed) date = [writer stringFromDate:parsed];
                        }
                        [out addObject:@{ @"tag": tag,
                                          @"version": [tag hasPrefix:@"v"] ? [tag substringFromIndex:1] : tag,
                                          @"date": date }];
                    }
                    list = out;
                } else if (!err) {
                    err = [NSError errorWithDomain:@"DHManager" code:-1 userInfo:
                        @{NSLocalizedDescriptionKey: @"版本列表解析失败"}];
                }
            } @catch (__unused NSException *e) {
                err = [NSError errorWithDomain:@"DHManager" code:-2 userInfo:
                    @{NSLocalizedDescriptionKey: @"版本列表解析失败"}];
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{ completion(list, err); });
    }] resume];
}

BOOL DHOpenPackageManager(void) {
    UIApplication *app = UIApplication.sharedApplication;
    for (NSString *address in @[@"sileo://package/com.iosdecrypthub", @"zbra://"]) {
        NSURL *url = [NSURL URLWithString:address];
        if ([app canOpenURL:url]) { [app openURL:url options:@{} completionHandler:nil]; return YES; }
    }
    return NO;
}
