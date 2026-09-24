// hook_dyld.m
// 隐藏自身注入痕迹: hook _dyld_get_image_name / dladdr。
//
// 检测注入最常见的手法是遍历已加载 image、对 _dyld_get_image_name(i) 的返回名做黑名单子串匹配
// (查 "MobileSubstrate" / "TweakInject" / 我们自己的 dylib 名 等)。
//
// 采用「改名不删项」策略: 命中隐藏清单时返回一个良性系统库名, 不改 _dyld_image_count、不重排索引。
// 好处: count/header/vmaddr_slide 全程与真实一致, 不打断 fishhook 重绑定与 symtab/macho_dump 的
// 按索引遍历(它们内部也用 _dyld_*), 无索引错位崩溃风险; 而基于「名字子串」的检测被完全挫败。
//
// 边界: 深度检测(读主程序 LC_LOAD_DYLIB 自校验、比对 image 总数)不在此列; getenv 的
// DYLD_INSERT_LIBRARIES 隐藏见 hook_env。gate on dh_spoof 的 jb 总开关。

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import "fishhook.h"
#import "log_store.h"
#import "dh_capture.h"
#import "dh_spoof.h"
#import "dh_dlsym_redirect.h"

// 命中隐藏 image 时对外统一伪装成的良性系统库名。
static const char *kBenignImageName = "/usr/lib/libSystem.B.dylib";

// 可观测: 每个被隐藏的 image 名只记一条日志(去重), 避免 _dyld_get_image_name/dladdr 高频刷屏。
// 不带 callStack —— 否则 backtrace 内部又走 dladdr 递归。gate on ENV_PROBE。
static void dyld_log_hidden_once(const char *name) {
    if (!name || !dh_capture_sub_enabled(DH_CAP_ENV_PROBE)) return;
    static NSMutableSet<NSString *> *seen = nil;
    static dispatch_semaphore_t lk = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ seen = [NSMutableSet set]; lk = dispatch_semaphore_create(1); });
    NSString *n = [NSString stringWithUTF8String:name];
    if (!n) return;
    dispatch_semaphore_wait(lk, DISPATCH_TIME_FOREVER);
    BOOL isNew = ![seen containsObject:n];
    if (isNew) [seen addObject:n];   // 先入集合, 阻断后续(含递归)重复记录
    dispatch_semaphore_signal(lk);
    if (!isNew) return;
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategorySystem;
    e.algorithm = @"dyld-hide";
    e.operation = @"已隐藏 image (改名)";
    e.detail    = n;
    e.timestamp = DHTimestampNow();
    e.callStack = @"";
    [[DHLogStore shared] append:e];
}

static const char *(*orig_dyld_get_image_name)(uint32_t);
static const char *hooked_dyld_get_image_name(uint32_t index) {
    const char *real = orig_dyld_get_image_name(index);
    if (real && dh_spoof_should_hide_image(real)) {
        dyld_log_hidden_once(real);
        return kBenignImageName;
    }
    return real;
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hooked_dladdr(const void *addr, Dl_info *info) {
    int r = orig_dladdr(addr, info);
    if (r != 0 && info && info->dli_fname && dh_spoof_should_hide_image(info->dli_fname)) {
        dyld_log_hidden_once(info->dli_fname);
        info->dli_fname = kBenignImageName;   // 抹掉命中 image 的真实路径, 保持调用成功
    }
    return r;
}

void dh_install_dyld_hooks(void) {
    struct rebinding r[] = {
        {"_dyld_get_image_name", hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"dladdr",               hooked_dladdr,              (void **)&orig_dladdr},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
}
