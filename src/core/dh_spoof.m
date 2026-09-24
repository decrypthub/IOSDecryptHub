// dh_spoof.m — 见 dh_spoof.h。JSON 持久化 + NSRecursiveLock(save 触发的 stat/access 会回调 should_hide_*, 需同线程重入), 热路径总开关 volatile 早退。

#import "dh_spoof.h"
#import "dh_health.h"
#import <stdlib.h>

static NSRecursiveLock *gLock = nil;   // 递归锁: save 时 writeToFile 会触发 stat/access → 回调 should_hide_*, 同线程重入不死锁
static NSString *gConfPath = nil;

// 热路径总开关(无锁 volatile 快读)。清单/字符串值改动都在锁内, 但读开关不必进锁。
static volatile BOOL gJbOn      = YES;
static volatile BOOL gAntiOn    = YES;
static volatile BOOL gDeviceOn  = NO;

static NSMutableArray<NSString *> *gJbPaths   = nil;
static NSMutableArray<NSString *> *gJbSchemes = nil;
static NSMutableArray<NSString *> *gJbImages  = nil;   // 注入痕迹: image 名子串黑名单
static NSMutableDictionary<NSString *, NSString *> *gDevice = nil;   // key→值

static NSArray<NSString *> *kDeviceKeys(void) {
    return @[@"hw_machine", @"hw_model", @"os_version", @"device_name", @"idfv", @"idfa"];
}

static void spoof_set_defaults_locked(void) {
    gJbOn = YES; gAntiOn = YES; gDeviceOn = NO;
    gJbPaths = [@[
        @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
        @"/Applications/Filza.app", @"/Applications/WinterBoard.app", @"/Applications/SBSettings.app",
        // 巨魔/多巴胺生态 + 常见检测写法(注意 B站等 App 会同时查带 s 与不带 s 的 /Application(s))
        @"/Applications/TrollStore.app", @"/Applications/Dopamine.app",
        @"/Application/Cydia.app", @"/Application/Sileo.app", @"/Application/Dopamine.app",
        @"/var/mobile/.installed_trollstore",
        @"/Library/MobileSubstrate", @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        @"/usr/sbin/sshd", @"/usr/bin/ssh", @"/usr/sbin/frida-server",
        @"/usr/bin/cycript", @"/usr/local/bin/cycript", @"/usr/libexec/cydia", @"/usr/libexec/cydia/",
        @"/usr/libexec/sftp-server",
        @"/usr/lib/libjailbreak.dylib", @"/bin/bash", @"/bin/sh",
        @"/etc/apt", @"/private/var/lib/apt", @"/private/var/lib/cydia", @"/private/var/stash",
        @"/private/var/tmp/cydia.log", @"/var/jb", @"/var/binpack",
        // 以下条目取自实测的第三方风控 SDK 检测清单(中国移动 BCE/everisk RiskManage):
        // 它逐条 stat 这些路径, 漏掉任何一条都会被记为「已越狱」。
        @"/.cydia_no_stash", @"/TweakInject/",
        @"/Applications/FlyJB.app", @"/Library/PreferenceBundles/FlyJBPrefs.bundle",
        @"/Library/MobileSubstrate/CydiaSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/Flex.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/xCon.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/OTRLocation.dylib",
        @"/etc/ssh/sshd_config", @"/private/etc/ssh/sshd_config",
        @"/etc/apt/sources.list.d/electra.list", @"/etc/apt/sources.list.d/sileo.sources",
        @"/etc/apt/undecimus/undecimus.list",
        @"/private/var/log/syslog", @"/private/var/mobile/Library/SBSettings/Themes",
        @"/jb/", @"/jb/amfid_payload.dylib", @"/jb/jailbreakd.plist",
        @"/jb/libjailbreak.dylib", @"/jb/lzma", @"/jb/offsets.plist",
    ] mutableCopy];
    gJbSchemes = [@[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator", @"apt-repo"] mutableCopy];
    // 注入痕迹: 自身 dylib 名 + 常见注入框架/越狱 tweak 加载器标记(image 全路径子串匹配)。
    gJbImages = [@[
        @"decrypt_helper", @"IOSDecryptHub", @"MobileSubstrate", @"SubstrateLoader", @"SubstrateInserter", @"substrate",
        @"TweakInject", @"libhooker", @"libsubstitute", @"substitute", @"ellekit", @"RocketBootstrap",
        @"cynject", @"libjailbreak", @"Cephei", @"Choicy", @"DynamicLibraries",
        @"CydiaSubstrate", @"FlyJB", @"xCon", @"OTRLocation", @"Veency",
        // 常见检测名单(实测 B站会查这些): 注入框架 / 伪装类 / 抓包与脚本工具
        @"AppSyncUnified", @"Shadow", @"FridaGadget", @"frida", @"libcycript",
        @"dopamine", @"TrollStore", @"IPAPatch",
    ] mutableCopy];
    gDevice = [NSMutableDictionary dictionary];
    for (NSString *k in kDeviceKeys()) gDevice[k] = @"";
}

// ---- 持久化 ----
static void spoof_save_locked(void) {
    if (!gConfPath) return;
    NSDictionary *root = @{
        @"jb":         @{ @"on": @(gJbOn), @"paths": [gJbPaths copy], @"schemes": [gJbSchemes copy], @"images": [gJbImages copy] },
        @"anti_debug": @{ @"on": @(gAntiOn) },
        @"device":     [@{ @"on": @(gDeviceOn) } mutableCopy],
    };
    NSMutableDictionary *dev = [root[@"device"] mutableCopy];
    for (NSString *k in kDeviceKeys()) dev[k] = gDevice[k] ?: @"";
    NSMutableDictionary *out = [root mutableCopy];
    out[@"device"] = dev;

    NSData *data = [NSJSONSerialization dataWithJSONObject:out
                                                  options:NSJSONWritingPrettyPrinted error:nil];
    if (!data) return;
    int saved = dh_in_hook; dh_in_hook = 1;
    [data writeToFile:gConfPath atomically:YES];
    dh_in_hook = saved;
}

static void spoof_apply_json_locked(NSDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *jb = root[@"jb"];
    if ([jb isKindOfClass:[NSDictionary class]]) {
        if (jb[@"on"]) gJbOn = [jb[@"on"] boolValue];
        if ([jb[@"paths"] isKindOfClass:[NSArray class]])   gJbPaths   = [jb[@"paths"] mutableCopy];
        if ([jb[@"schemes"] isKindOfClass:[NSArray class]]) gJbSchemes = [jb[@"schemes"] mutableCopy];
        if ([jb[@"images"] isKindOfClass:[NSArray class]])  gJbImages  = [jb[@"images"] mutableCopy];
    }
    NSDictionary *anti = root[@"anti_debug"];
    if ([anti isKindOfClass:[NSDictionary class]] && anti[@"on"]) gAntiOn = [anti[@"on"] boolValue];
    NSDictionary *dev = root[@"device"];
    if ([dev isKindOfClass:[NSDictionary class]]) {
        if (dev[@"on"]) gDeviceOn = [dev[@"on"] boolValue];
        for (NSString *k in kDeviceKeys()) {
            id v = dev[k];
            if ([v isKindOfClass:[NSString class]]) gDevice[k] = v;
        }
    }
}

void dh_spoof_load(NSString *confPath) {
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock];
    spoof_set_defaults_locked();
    gConfPath = [confPath copy];
    if (gConfPath) {
        int saved = dh_in_hook; dh_in_hook = 1;
        NSData *data = [NSData dataWithContentsOfFile:gConfPath];
        dh_in_hook = saved;
        if (data.length) {
            NSDictionary *root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            spoof_apply_json_locked(root);
        }
    }
    [gLock unlock];
}

// ---- 越狱隐藏 ----
BOOL dh_spoof_jb_on(void) { return gJbOn; }
void dh_spoof_jb_set_on(BOOL on) {
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock]; gJbOn = on; spoof_save_locked(); [gLock unlock];
}

BOOL dh_spoof_jb_should_hide_path(const char *path) {
    if (!gJbOn || !path || !*path || !gLock) return NO;
    // 热路径守卫: 这个函数在每次 open/stat/access 里都会被调用(宿主启动阶段几千次),
    // 原实现每次都建 NSString + 拿锁 + 35 条模式 × (isEqual + hasPrefix + 子串) 且逐条
    // stringByAppendingString 分配 —— 启动期开销可观。先用纯 C 的锚点子串快速拒绝,
    // 命中不了任何锚点的普通路径直接返回, 不进 Objective-C 层。
    static const char *anchors[] = {
        "/Applications/", "/Application/", "Substrate", "/System/Library/LaunchDaemons",
        "/usr/", "/bin/", "/etc/apt", "/private/var/", "/var/jb", "/var/binpack",
        "installed_trollstore",
        // 风控 SDK 实测检测项对应的锚点(见下方 gJbPaths 注释), 漏一个就会让预过滤误杀。
        ".cydia", "/TweakInject", "/jb/", "/etc/ssh", "PreferenceBundles",
    };
    BOOL maybe = NO;
    for (size_t i = 0; i < sizeof(anchors) / sizeof(anchors[0]); i++) {
        if (strstr(path, anchors[i])) { maybe = YES; break; }
    }
    if (!maybe) return NO;

    NSString *p = [NSString stringWithUTF8String:path];
    if (!p) return NO;
    [gLock lock];
    BOOL hit = NO;
    for (NSString *e in gJbPaths) {
        if (e.length == 0) continue;
        // 子串匹配已经覆盖「精确相等」和「落在配置目录下」两种情况, 少两次字符串操作和一次分配。
        if ([p rangeOfString:e].location != NSNotFound) { hit = YES; break; }
    }
    [gLock unlock];
    return hit;
}

BOOL dh_spoof_jb_should_hide_scheme(const char *scheme) {
    if (!gJbOn || !scheme || !*scheme || !gLock) return NO;
    NSString *s = [NSString stringWithUTF8String:scheme];
    if (!s) return NO;
    s = [s lowercaseString];
    [gLock lock];
    BOOL hit = NO;
    for (NSString *e in gJbSchemes) {
        if (e.length && [s isEqualToString:[e lowercaseString]]) { hit = YES; break; }
    }
    [gLock unlock];
    return hit;
}

NSArray<NSString *> *dh_spoof_jb_paths(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gJbPaths copy]; [gLock unlock]; return r;
}
NSArray<NSString *> *dh_spoof_jb_schemes(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gJbSchemes copy]; [gLock unlock]; return r;
}

static BOOL spoof_list_add(NSMutableArray *arr, NSString *v) {
    if (v.length == 0) return NO;
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock];
    for (NSString *e in arr) if ([e caseInsensitiveCompare:v] == NSOrderedSame) { [gLock unlock]; return NO; }
    [arr addObject:v];
    spoof_save_locked();
    [gLock unlock];
    return YES;
}
static BOOL spoof_list_remove(NSMutableArray *arr, NSString *v) {
    if (v.length == 0 || !gLock) return NO;
    [gLock lock];
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < arr.count; i++)
        if ([arr[i] caseInsensitiveCompare:v] == NSOrderedSame) { idx = i; break; }
    if (idx == NSNotFound) { [gLock unlock]; return NO; }
    [arr removeObjectAtIndex:idx];
    spoof_save_locked();
    [gLock unlock];
    return YES;
}
BOOL dh_spoof_jb_add_path(NSString *p)    { return spoof_list_add(gJbPaths, p); }
BOOL dh_spoof_jb_remove_path(NSString *p) { return spoof_list_remove(gJbPaths, p); }
BOOL dh_spoof_jb_add_scheme(NSString *s)    { return spoof_list_add(gJbSchemes, s); }
BOOL dh_spoof_jb_remove_scheme(NSString *s) { return spoof_list_remove(gJbSchemes, s); }

// 注入痕迹隐藏: image 全路径命中清单子串(不区分大小写)则返回 YES。gate on jb 总开关。
BOOL dh_spoof_should_hide_image(const char *imageName) {
    if (!gJbOn || !imageName || !*imageName || !gLock) return NO;
    NSString *nm = [[NSString stringWithUTF8String:imageName] lowercaseString];
    if (!nm) return NO;
    [gLock lock];
    BOOL hit = NO;
    for (NSString *e in gJbImages) {
        if (e.length && [nm rangeOfString:[e lowercaseString]].location != NSNotFound) { hit = YES; break; }
    }
    [gLock unlock];
    return hit;
}
NSArray<NSString *> *dh_spoof_jb_images(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gJbImages copy]; [gLock unlock]; return r;
}
BOOL dh_spoof_jb_add_image(NSString *s)    { return spoof_list_add(gJbImages, s); }
BOOL dh_spoof_jb_remove_image(NSString *s) { return spoof_list_remove(gJbImages, s); }

// ---- 反调试 ----
BOOL dh_spoof_anti_debug_on(void) { return gAntiOn; }
void dh_spoof_anti_debug_set_on(BOOL on) {
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock]; gAntiOn = on; spoof_save_locked(); [gLock unlock];
}

// ---- 改机 ----
BOOL dh_spoof_device_on(void) { return gDeviceOn; }
void dh_spoof_device_set_on(BOOL on) {
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock]; gDeviceOn = on; spoof_save_locked(); [gLock unlock];
}

NSString *dh_spoof_device_value(NSString *key) {
    if (!gDeviceOn || key.length == 0 || !gLock) return nil;
    [gLock lock];
    NSString *v = gDevice[key];
    [gLock unlock];
    return (v.length > 0) ? v : nil;   // 空串视为「不伪造此项」
}

void dh_spoof_device_set_value(NSString *key, NSString *val) {
    if (key.length == 0 || !gLock) return;
    if (![kDeviceKeys() containsObject:key]) return;
    [gLock lock]; gDevice[key] = val ?: @""; spoof_save_locked(); [gLock unlock];
}

// 内置真实机型表(机型名 / hw.machine / hw.model)—— 一键随机改机用。
void dh_spoof_device_randomize(void) {
    static const char *kModels[][3] = {
        {"iPhone 15 Pro Max", "iPhone16,2", "D84AP"}, {"iPhone 15 Pro", "iPhone16,1", "D83AP"},
        {"iPhone 15 Plus",    "iPhone15,5", "D38AP"}, {"iPhone 15",     "iPhone15,4", "D37AP"},
        {"iPhone 14 Pro Max", "iPhone15,3", "D74AP"}, {"iPhone 14 Pro", "iPhone15,2", "D73AP"},
        {"iPhone 14 Plus",    "iPhone14,8", "D28AP"}, {"iPhone 14",     "iPhone14,7", "D27AP"},
        {"iPhone 13 Pro Max", "iPhone14,3", "D64AP"}, {"iPhone 13 Pro", "iPhone14,2", "D63AP"},
        {"iPhone 13",         "iPhone14,5", "D17AP"}, {"iPhone 13 mini","iPhone14,4", "D16AP"},
        {"iPhone 12",         "iPhone13,2", "D53gAP"},{"iPhone SE (3rd)","iPhone14,6","D49AP"},
    };
    static const char *kOSes[] = { "16.7.8", "17.4.1", "17.5.1", "17.6.1", "18.0.1", "18.1.1", "18.2.1" };
    if (!gLock) gLock = [NSRecursiveLock new];
    uint32_t mi = arc4random_uniform((uint32_t)(sizeof(kModels) / sizeof(kModels[0])));
    uint32_t oi = arc4random_uniform((uint32_t)(sizeof(kOSes) / sizeof(kOSes[0])));
    NSString *idfv = [[NSUUID UUID] UUIDString];
    NSString *idfa = [[NSUUID UUID] UUIDString];
    [gLock lock];
    gDeviceOn = YES;
    gDevice[@"hw_machine"]  = @(kModels[mi][1]);
    gDevice[@"hw_model"]    = @(kModels[mi][2]);
    gDevice[@"os_version"]  = @(kOSes[oi]);
    gDevice[@"device_name"] = @"iPhone";
    gDevice[@"idfv"] = idfv;
    gDevice[@"idfa"] = idfa;
    spoof_save_locked();
    [gLock unlock];
}

NSDictionary *dh_spoof_snapshot(void) {
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock];
    NSDictionary *snap = @{
        @"jb":         @{ @"on": @(gJbOn), @"paths": [gJbPaths copy] ?: @[], @"schemes": [gJbSchemes copy] ?: @[], @"images": [gJbImages copy] ?: @[] },
        @"anti_debug": @{ @"on": @(gAntiOn) },
        @"device":     ({
            NSMutableDictionary *d = [@{ @"on": @(gDeviceOn) } mutableCopy];
            for (NSString *k in kDeviceKeys()) d[k] = gDevice[k] ?: @"";
            d;
        }),
    };
    [gLock unlock];
    return snap;
}

void dh_spoof_import(NSDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return;
    if (!gLock) gLock = [NSRecursiveLock new];
    [gLock lock];
    spoof_apply_json_locked(root);   // 复用加载逻辑: jb/anti_debug/device 各段就地覆盖
    spoof_save_locked();
    [gLock unlock];
}
