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
#define ENGINE_REL      @"usr/lib/IOSDecryptHub/decrypt_helper.dylib"
#define CONFIG_REL      @"usr/lib/IOSDecryptHub/config/enabledBundles.plist"

// 不依赖 /var/jb，也不用 access()/fileExists 探路（宿主沙盒会谎称不存在）。
// loader 实际可能在：
//   <jb>/Library/MobileSubstrate/DynamicLibraries/  （本包安装位置，向上 4 级到 jbroot）
//   <jb>/usr/lib/TweakInject/                       （ElleKit 加载位置，同样向上 4 级）
// 旧逻辑只向上 2 级再拼 IOSDecryptHub/…，仅 TweakInject 布局碰巧正确。
static void dh_add_unique(NSMutableArray<NSString *> *paths, NSString *path) {
    if (path.length && ![paths containsObject:path]) [paths addObject:path];
}

static NSArray<NSString *> *dh_paths_from_loader(NSString *relativeToJbroot) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_paths_from_loader, &info) != 0 && info.dli_fname) {
        NSString *cur = [NSString stringWithUTF8String:info.dli_fname];
        for (int i = 0; i < 4 && cur.length > 1; i++) {
            cur = [cur stringByDeletingLastPathComponent];
        }
        if (cur.length > 1) {
            dh_add_unique(paths, [cur stringByAppendingPathComponent:relativeToJbroot]);
        }
        // 兼容 TweakInject：向上 2 级 = usr/lib，相对路径去掉 usr/lib/ 前缀
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *usrLib = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if ([relativeToJbroot hasPrefix:@"usr/lib/"] && usrLib.length > 1) {
            dh_add_unique(paths, [usrLib stringByAppendingPathComponent:
                [relativeToJbroot substringFromIndex:8]]);
        }
    }
    dh_add_unique(paths, [@"/var/jb/" stringByAppendingString:relativeToJbroot]);
    return paths;
}

static NSArray<NSString *> *dh_dylib_candidates(void) {
    return dh_paths_from_loader(ENGINE_REL);
}

static NSArray<NSString *> *dh_config_candidates(void) {
    return dh_paths_from_loader(CONFIG_REL);
}

// 说明：曾短暂加过"我们自己的组件不注入"的特例（想让管理器 App 里不弹悬浮窗），
// 已撤销 —— 用户反馈里看到的悬浮窗真正原因是"开关被打开了"，不是产品行为异常。
// 开关语义保持处处一致：列在名单里的 App 就会被注入，没有例外。
// 相关：管理器 App 与设置面板同样出现在列表里，可以被显式打开（例如当服务宿主用）。

// 读取偏好：判断当前 bundleID 是否在启用列表中
static BOOL dh_should_inject(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return NO;

    // 跳过系统关键进程（避免不必要的开销）
    if ([bundleID hasPrefix:@"com.apple."]) return NO;


    NSArray *enabled = nil;
    const char *source = "none";
    @try {
#if IDH_ROOT_HIDE
        // Manager 在 RootHide 把应用名单写入 bootstrap 的 mobile home。
        // 系统根目录的旧名单可能还存在，权威副本读不到时使用同一 bootstrap 内的镜像。
        NSArray *preferences = dh_paths_from_loader([PREFS_PATH substringFromIndex:1]);
#else
        NSArray *preferences = @[PREFS_PATH];
#endif
        for (NSString *path in preferences) {
            id value = [NSDictionary dictionaryWithContentsOfFile:path][PREFS_KEY];
            if ([value isKindOfClass:NSArray.class]) {
                enabled = value;
                source = "prefs";
                break;
            }
        }
#if !IDH_ROOT_HIDE
        if (!enabled) {
            CFPropertyListRef value = CFPreferencesCopyAppValue(
                (__bridge CFStringRef)PREFS_KEY,
                (__bridge CFStringRef)PREFS_DOMAIN);
            id list = CFBridgingRelease(value);
            if ([list isKindOfClass:NSArray.class]) {
                enabled = list;
                source = "cfprefs";
            }
        }
#endif
        if (!enabled) {
            for (NSString *configPath in dh_config_candidates()) {
                id value = [NSDictionary dictionaryWithContentsOfFile:configPath][PREFS_KEY];
                if ([value isKindOfClass:NSArray.class]) {
                    enabled = value;
                    source = "jb";
                    break;
                }
            }
        }
    } @catch (__unused NSException *exception) {
        return NO;
    }
    if (!enabled || ![enabled isKindOfClass:[NSArray class]]) return NO;
    BOOL hit = [enabled containsObject:bundleID];
    if (hit) {
        syslog(LOG_NOTICE, LOADER_TAG " 将注入 %s source=%s",
               bundleID.UTF8String, source);
    }
    return hit;
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
