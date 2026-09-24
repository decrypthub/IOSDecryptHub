// main.m - IOSDecryptHub (Decrypt Helper)
// 注入入口: 在 dylib 被加载时安装所有 hook 并初始化悬浮窗 UI。
// 悬浮窗只负责状态与基础控制，日志查看和分析统一由 Web 控制台完成。

#import <Foundation/Foundation.h>
#if __has_include(<UIKit/UIKit.h>)
#import <UIKit/UIKit.h>
#endif
#import "log_store.h"
#import "ui_float.h"
#import "http_server.h"
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_noise.h"
#import "dh_spoof.h"
#import "hook_webkit.h"

extern void dh_install_digest_hooks(void);
extern void dh_install_hmac_hooks(void);
extern void dh_install_symmetric_hooks(void);
extern void dh_install_asymmetric_hooks(void);
extern void dh_install_kdf_hooks(void);
extern void dh_install_evp_hooks(void);
extern void dh_install_file_hooks(void);
extern void dh_install_system_hooks(void);
extern void dh_install_keychain_hooks(void);
extern void dh_install_env_hooks(void);
extern void dh_install_spoof_objc_hooks(void);
extern void dh_install_dyld_hooks(void);
extern void dh_install_network_hooks(void);
extern void dh_install_webkit_hooks(void);

static void dh_install_all_hooks(void) {
    dh_install_digest_hooks();
    dh_install_hmac_hooks();
    dh_install_symmetric_hooks();
    dh_install_asymmetric_hooks();
    dh_install_kdf_hooks();
    dh_install_evp_hooks();
    dh_install_file_hooks();
    dh_install_system_hooks();
    dh_install_keychain_hooks();
    dh_install_env_hooks();
    dh_install_spoof_objc_hooks();
    dh_install_dyld_hooks();
    dh_install_network_hooks();
    dh_install_webkit_hooks();
}

__attribute__((constructor))
static void dh_bootstrap(void) {
    // 预热 Foundation 的 locale / NSDateFormatter / backtrace, 避免 hook 安装后首次时间格式化
    // 在 hooked_open 内部触发 open/dlopen 递归(与 dh_in_hook 标志双保险).
    (void)DHTimestampNow();
    (void)DHCallStackFiltered();
    // 诊断落盘目录 + 捕获配置, 都在装 hook 前就绪(持久化的开关/诊断从一开始生效)。
    NSString *docsDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    dh_diag_set_dir(docsDir.fileSystemRepresentation);
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "IOSDecryptHub 启动, 开始安装 hook");
    dh_capture_load([docsDir stringByAppendingPathComponent:@".dh_capture.conf"].fileSystemRepresentation);
    dh_noise_load([docsDir stringByAppendingPathComponent:@".dh_noise.conf"]);
    dh_spoof_load([docsDir stringByAppendingPathComponent:@".dh_spoof.conf"]);
    dh_webkit_probe_load([docsDir stringByAppendingPathComponent:@".dh_webkit_probe.conf"]);
    // 安装 hook —— 尽早完成, 否则早期发生的加解密会漏抓.
    dh_install_all_hooks();
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "hook 安装完成 (Digest/HMAC/对称/非对称/KDF/EVP/文件/系统)");
    NSLog(@"[IOSDecryptHub] hook 已全部安装 (Digest / HMAC / 对称 / 非对称 / KDF / EVP / 文件 / 系统 / dlsym)");

    // 本地 HTTP 服务放到后台起: constructor 处在宿主 launch 的看门狗预算里
    // (实测 B站 launch 阶段被 0x8badf00d 杀掉), 起 socket/线程不该抢这段时间。
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        dh_http_start();
    });

#if __has_include(<UIKit/UIKit.h>)
    // UI 必须等 UIApplication 实例化后再做; 用 didFinishLaunching 通知做后置初始化.
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                       object:nil queue:nil usingBlock:^(NSNotification *_) {
        dh_ui_install_floating();
    }];
    // 进入后台/退出前把批量缓冲刷盘, 避免 App 被挂起/终止时丢掉最后一批低价值事件。
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidEnterBackgroundNotification
                                                       object:nil queue:nil usingBlock:^(NSNotification *_) {
        [[DHLogStore shared] flush];
    }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillTerminateNotification
                                                       object:nil queue:nil usingBlock:^(NSNotification *_) {
        [[DHLogStore shared] flush];
    }];
    // 一些 app 加载 dylib 时 UIApplication 已经存在, 直接尝试创建一次, 失败也无所谓.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_ui_install_floating();
    });
#endif

    NSLog(@"[IOSDecryptHub] 日志文件: %@", [[DHLogStore shared] logFilePath]);
}
