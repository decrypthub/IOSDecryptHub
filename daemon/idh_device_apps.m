// idh_device_apps.m — idhjd 的设备应用管理与注入范围实现。
// 与 updater(daemon/main.m) 是两个进程，这里自包含同语义实现：
// 扫同样的目录、写同样的两份名单、走同样的 kill+uiopen 重启路径。

#import "idh_device_apps.h"
#import "../src/dh_shared.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <unistd.h>

static NSString *idh_bootstrap_root(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&idh_bootstrap_root, &info) == 0 || !info.dli_fname) return nil;
    // <bootstrap>/usr/lib/IOSDecryptHub/idhjd，向上四级；"/" 是合法 jbroot（RootHide）
    NSString *root = [NSString stringWithUTF8String:info.dli_fname];
    for (int i = 0; i < 4; i++) root = [root stringByDeletingLastPathComponent];
    return root.length ? root : nil;
}

static NSString *idh_config_path(void) {
    NSString *root = idh_bootstrap_root();
    return root.length ? [root stringByAppendingPathComponent:DH_CONFIG_REL] : nil;
}

// bundleID -> @{name, execName, appPath, kind}
static NSDictionary *idh_app_map(void) {
    NSMutableDictionary *map = [NSMutableDictionary dictionary];
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableArray *bases = [NSMutableArray arrayWithObject:
            @[@"/var/containers/Bundle/Application", @"user"]];
        NSString *root = idh_bootstrap_root();
        if (root.length > 1) [bases addObject:@[[root stringByAppendingPathComponent:@"Applications"], @"jb"]];
        [bases addObject:@[@"/Applications", @"system"]];
        for (NSArray *base in bases) {
            NSString *basePath = base[0];
            NSString *kind = base[1];
            for (NSString *container in [fm contentsOfDirectoryAtPath:basePath error:nil]) {
                NSString *containerPath = [basePath stringByAppendingPathComponent:container];
                BOOL wantApp = [container.pathExtension.lowercaseString isEqualToString:@"app"];
                NSArray *entries = wantApp ? @[@""] : [fm contentsOfDirectoryAtPath:containerPath error:nil];
                for (NSString *entry in entries) {
                    if (!wantApp && ![entry.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                    NSString *appPath = wantApp ? containerPath : [containerPath stringByAppendingPathComponent:entry];
                    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                        [appPath stringByAppendingPathComponent:@"Info.plist"]];
                    NSString *bid = info[@"CFBundleIdentifier"];
                    NSString *exec = info[@"CFBundleExecutable"];
                    if (!bid.length || !exec.length || map[bid]) continue;
                    NSString *name = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bid;
                    map[bid] = @{@"name": name, @"execName": exec, @"appPath": appPath, @"kind": kind};
                }
            }
        }
    } @catch (__unused NSException *e) {
    }
    return map;
}

// 当前进程表里的可执行名集合（p_comm 16 字节语义与 updater 一致）
static NSSet *idh_running_names(void) {
    NSMutableSet *names = [NSMutableSet set];
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return names;
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return names;
    if (sysctl(mib, 4, procs, &len, NULL, 0) == 0) {
        size_t n = len / sizeof(struct kinfo_proc);
        for (size_t i = 0; i < n; i++) {
            if (procs[i].kp_proc.p_pid <= 1) continue;
            char comm[MAXCOMLEN + 1];
            memcpy(comm, procs[i].kp_proc.p_comm, MAXCOMLEN);
            comm[MAXCOMLEN] = '\0';
            [names addObject:[NSString stringWithUTF8String:comm]];
        }
    }
    free(procs);
    return names;
}

static BOOL idh_name_running(NSString *execName, NSSet *running) {
    if (execName.length <= MAXCOMLEN - 1) return [running containsObject:execName];
    NSString *prefix = [execName substringToIndex:MAXCOMLEN - 1];
    for (NSString *name in running) if ([name hasPrefix:prefix]) return YES;
    return NO;
}

NSDictionary *idh_apps_list(void) {
    NSDictionary *map = idh_app_map();
    NSSet *running = idh_running_names();
    NSMutableArray *apps = [NSMutableArray arrayWithCapacity:map.count];
    for (NSString *bid in map) {
        NSDictionary *meta = map[bid];
        [apps addObject:@{@"bundleId": bid, @"name": meta[@"name"], @"execName": meta[@"execName"],
                          @"kind": meta[@"kind"], @"running": @(idh_name_running(meta[@"execName"], running))}];
    }
    [apps sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] compare:b[@"name"] options:NSCaseInsensitiveSearch];
    }];
    return @{@"ok": @YES, @"apps": apps, @"scope": idh_scope_read() ?: @[]};
}

NSArray *idh_scope_read(void) {
    // loader 权威副本是 prefs plist；读不到再回退 jb config（与 loader 同优先级）
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:DH_LOADER_PREFS];
    id bundles = prefs[DH_KEY_BUNDLES];
    if (![bundles isKindOfClass:NSArray.class]) {
        bundles = [NSArray arrayWithContentsOfFile:idh_config_path() ?: @""];
    }
    if (![bundles isKindOfClass:NSArray.class]) return @[];
    NSMutableArray *scope = [NSMutableArray arrayWithCapacity:[bundles count]];
    for (id item in bundles) {
        if ([item isKindOfClass:NSString.class] && [item length] && ![scope containsObject:item])
            [scope addObject:item];
    }
    return scope;
}

static BOOL idh_valid_bundle(NSString *bid) {
    if (![bid isKindOfClass:NSString.class] || bid.length == 0 || bid.length > 255) return NO;
    if ([bid hasPrefix:@"com.apple."]) return NO;
    NSCharacterSet *bad = [[NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"] invertedSet];
    return [bid rangeOfCharacterFromSet:bad].location == NSNotFound;
}

NSDictionary *idh_scope_apply(NSArray *add, NSArray *remove) {
    NSMutableArray *scope = [idh_scope_read() mutableCopy];
    for (id item in remove) {
        if ([item isKindOfClass:NSString.class]) [scope removeObject:item];
    }
    for (id item in add) {
        if (!idh_valid_bundle(item)) return @{@"ok": @NO, @"error": @"invalid_bundle_id",
                                              @"bundleId": [item isKindOfClass:NSString.class] ? item : @""};
        if (![scope containsObject:item]) [scope addObject:item];
    }
    // prefs plist 保留 updaterRequest 等其它键（与 Manager 写路径同语义）
    NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:DH_LOADER_PREFS] mutableCopy]
        ?: [NSMutableDictionary dictionary];
    prefs[DH_KEY_BUNDLES] = scope;
    if (![prefs writeToFile:DH_LOADER_PREFS atomically:YES])
        return @{@"ok": @NO, @"error": @"prefs_write_failed"};
    NSString *config = idh_config_path();
    if (config.length) {
        [[NSFileManager defaultManager] createDirectoryAtPath:[config stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        if (![scope writeToFile:config atomically:YES])
            return @{@"ok": @NO, @"error": @"config_write_failed", @"scope": scope};
    }
    return @{@"ok": @YES, @"scope": scope};
}

static NSArray *idh_kill_named(NSSet *names) {
    NSMutableArray *killed = [NSMutableArray array];
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return killed;
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return killed;
    if (sysctl(mib, 4, procs, &len, NULL, 0) == 0) {
        pid_t selfPid = getpid();
        size_t n = len / sizeof(struct kinfo_proc);
        for (size_t i = 0; i < n; i++) {
            pid_t pid = procs[i].kp_proc.p_pid;
            if (pid <= 1 || pid == selfPid) continue;
            char comm[MAXCOMLEN + 1];
            memcpy(comm, procs[i].kp_proc.p_comm, MAXCOMLEN);
            comm[MAXCOMLEN] = '\0';
            for (NSString *name in names) {
                const char *want = name.UTF8String;
                if (!want || !want[0]) continue;
                BOOL match = (strlen(want) <= MAXCOMLEN - 1)
                    ? (strcmp(comm, want) == 0) : (strncmp(comm, want, MAXCOMLEN - 1) == 0);
                if (match && kill(pid, SIGKILL) == 0 && ![killed containsObject:name])
                    [killed addObject:name];
            }
        }
    }
    free(procs);
    return killed;
}

static BOOL idh_uiopen(NSString *bundleID) {
    const char *candidates[] = {"/var/jb/usr/bin/uiopen", "/usr/local/bin/uiopen", "/usr/bin/uiopen", NULL};
    NSMutableArray *paths = [NSMutableArray array];
    NSString *root = idh_bootstrap_root();
    if (root.length > 1) [paths addObject:[root stringByAppendingPathComponent:@"usr/bin/uiopen"]];
    for (int i = 0; candidates[i]; i++) [paths addObject:[NSString stringWithUTF8String:candidates[i]]];
    const char *tool = NULL;
    for (NSString *path in paths) {
        if (access(path.fileSystemRepresentation, X_OK) == 0) { tool = path.fileSystemRepresentation; break; }
    }
    if (!tool) return NO;
    pid_t pid = fork();
    if (pid < 0) return NO;
    if (pid == 0) {
        setsid();
        execl(tool, tool, "--bundleid", bundleID.UTF8String, (char *)NULL);
        _exit(127);
    }
    return YES;
}

NSDictionary *idh_app_relaunch(NSString *bundleID) {
    if (![bundleID isKindOfClass:NSString.class] || !bundleID.length || bundleID.length > 255)
        return @{@"ok": @NO, @"error": @"invalid_arguments"};
    NSString *execName = idh_app_map()[bundleID][@"execName"];
    if (!execName.length) return @{@"ok": @NO, @"error": @"unknown_bundle_id"};
    NSArray *killed = idh_kill_named([NSSet setWithObject:execName]);
    BOOL relaunched = idh_uiopen(bundleID);
    return @{@"ok": @YES, @"relaunched": @(relaunched), @"killed": killed};
}

// UIKit 私有类目走 MobileIcons，任意进程可用；idhjd 不链 UIKit，用时 dlopen + NSInvocation。
static id idh_uikit_icon(Class cls, NSString *bid, int format) {
    SEL sel = @selector(_applicationIconImageForBundleIdentifier:format:scale:);
    NSMethodSignature *sig = [cls methodSignatureForSelector:sel];
    if (!sig) return nil;
    NSInvocation *call = [NSInvocation invocationWithMethodSignature:sig];
    call.selector = sel;
    call.target = cls;
    double scale = 3.0;
    [call setArgument:&bid atIndex:2];
    [call setArgument:&format atIndex:3];
    [call setArgument:&scale atIndex:4];
    [call invoke];
    __unsafe_unretained id icon = nil;
    [call getReturnValue:&icon];
    return icon;
}

NSData *idh_app_icon(NSString *bundleId) {
    if (![bundleId isKindOfClass:NSString.class] || !bundleId.length || bundleId.length > 255) return nil;
    static Class UIImageClass;
    static NSData *(*pngOf)(id) = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_LAZY)) return;
        UIImageClass = NSClassFromString(@"UIImage");
        pngOf = (NSData *(*)(id))dlsym(RTLD_DEFAULT, "UIImagePNGRepresentation");
    });
    if (!UIImageClass || !pngOf) return nil;
    for (NSNumber *format in @[@2, @10]) {
        id icon = idh_uikit_icon(UIImageClass, bundleId, format.intValue);
        NSData *png = icon ? pngOf(icon) : nil;
        if (png.length) return png;
    }
    return nil;
}
