// loader.m — IOSDecryptHub 越狱注入加载器
//
// 由 rootless 环境的 ElleKit 加载到 UIKit App（Filter: com.apple.UIKit）。
// 唯一职责：读取偏好设置 → 判断当前 App 是否启用 → dlopen 主 dylib。
// 不包含任何 hook 逻辑。hook 全部由主 dylib 的 constructor 完成。
//
// rootless 路径：
//   /var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <syslog.h>

#define LOADER_TAG      "[IOSDecryptHub]"
#define PREFS_DOMAIN    @"com.iosdecrypthub.loader"
#define PREFS_KEY       @"enabledBundles"
#define PREFS_PATH      @"/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
#define CONFIG_NAME    @"IOSDecryptHub/config/enabledBundles.plist"

// rootless 下 /var/jb 只是引导期别名，宿主沙盒中不一定可见。优先从 loader 的 dyld
// 实际路径推导同一 bootstrap 下的主 dylib，再兼容固定路径。
static NSArray<NSString *> *dh_dylib_candidates(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_dylib_candidates, &info) != 0 && info.dli_fname) {
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *libDir = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if (libDir.length) {
            [paths addObject:[libDir stringByAppendingPathComponent:
                @"IOSDecryptHub/decrypt_helper.dylib"]];
        }
    }
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib"];
    return paths;
}

static NSArray<NSString *> *dh_config_candidates(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_config_candidates, &info) != 0 && info.dli_fname) {
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *libDir = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if (libDir.length) {
            [paths addObject:[libDir stringByAppendingPathComponent:CONFIG_NAME]];
        }
    }
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"];
    return paths;
}

// 读取偏好：判断当前 bundleID 是否在启用列表中
static BOOL dh_should_inject(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return NO;

    // 跳过系统关键进程（避免不必要的开销）
    if ([bundleID hasPrefix:@"com.apple."]) return NO;

    NSArray *enabled = nil;
    @try {
        // 插件自带配置与主 dylib 位于同一越狱授权路径，不受宿主 App 偏好容器隔离。
        NSDictionary *prefs = nil;
        for (NSString *configPath in dh_config_candidates()) {
            prefs = [NSDictionary dictionaryWithContentsOfFile:configPath];
            enabled = prefs[PREFS_KEY];
            if ([enabled isKindOfClass:[NSArray class]]) break;
        }

        // 兼容旧版直接写入 /var/mobile/Library/Preferences 的配置。
        if (![enabled isKindOfClass:[NSArray class]]) {
            prefs = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
            enabled = prefs[PREFS_KEY];
        }

        if (![enabled isKindOfClass:[NSArray class]]) {
            // 通过 cfprefsd 按应用域读取，避免宿主 App 的容器视图隔离共享 plist。
            CFPreferencesAppSynchronize((__bridge CFStringRef)PREFS_DOMAIN);
            CFPropertyListRef value = CFPreferencesCopyAppValue(
                (__bridge CFStringRef)PREFS_KEY,
                (__bridge CFStringRef)PREFS_DOMAIN);
            enabled = CFBridgingRelease(value);
        }

        if (![enabled isKindOfClass:[NSArray class]]) {
            prefs = [[NSUserDefaults standardUserDefaults]
                persistentDomainForName:PREFS_DOMAIN];
            enabled = prefs[PREFS_KEY];
        }
    } @catch (__unused NSException *exception) {
        return NO;
    }
    if (!enabled || ![enabled isKindOfClass:[NSArray class]]) return NO;

    return [enabled containsObject:bundleID];
}

__attribute__((constructor))
static void dh_loader_init(void) {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // 默认不注入任何 App —— 只有用户在设置中明确开启的才注入
        if (!dh_should_inject(bundleID)) {
            return;
        }

        // 不先用 access() 探测：宿主沙盒可能拒绝路径查询，但 dyld 仍可加载由越狱
        // 注入框架授权的镜像。逐个 dlopen 才能得到真实结果。
        for (NSString *dylibPath in dh_dylib_candidates()) {
            syslog(LOG_INFO, LOADER_TAG " 注入 %s → %s",
                   bundleID.UTF8String, dylibPath.UTF8String);
            void *handle = dlopen(dylibPath.fileSystemRepresentation, RTLD_NOW);
            if (handle) return;
        }
        syslog(LOG_ERR, LOADER_TAG " 主 dylib 加载失败 (%s): %s",
               bundleID.UTF8String, dlerror() ?: "unknown error");
    }
}
