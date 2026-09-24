// ui_float.m
// 悬浮窗 - 只显示采集状态、Web 地址和基础控制，不承载日志正文。
//
// 产品决定（2026-09-13）：悬浮窗不带任何引流内容（曾有的"微信搜一搜"整行已移除）。
// Web 面板里的公众号入口是渠道触达，保留，不要在"清理"时一起删掉。
//
// UIKit 隔离: macOS 纯 target 没有 UIKit, 整个文件编译为空, 提供 no-op stub.
// iOS / Mac Catalyst / iOS Simulator 都有 UIKit, 正常走.

#import "ui_float.h"

#if __has_include(<UIKit/UIKit.h>)

#import <UIKit/UIKit.h>
#import "log_store.h"
#import "dh_noise.h"
#import "http_server.h"
#import "dh_health.h"

// 夜间设计系统: 黑底 + 高对比白字 + 少量冷蓝点缀
#define DH_BG       [UIColor colorWithRed:0.035 green:0.039 blue:0.047 alpha:1.0]  // #090a0c
#define DH_ACCENT   [UIColor colorWithRed:0.969 green:0.973 blue:0.984 alpha:1.0]  // #f7f8fb
#define DH_INK      [UIColor colorWithRed:0.969 green:0.973 blue:0.984 alpha:1.0]  // #f7f8fb
#define DH_MUTED    [UIColor colorWithRed:0.690 green:0.722 blue:0.769 alpha:1.0]  // #b0b8c4
#define DH_LINE     [UIColor colorWithRed:0.255 green:0.290 blue:0.349 alpha:1.0]  // #414a59
#define DH_SURFACE  [UIColor colorWithRed:0.090 green:0.106 blue:0.133 alpha:1.0]  // #171b22
#define DH_LINK     [UIColor colorWithRed:0.541 green:0.706 blue:1.000 alpha:1.0]  // #8ab4ff
#define DH_WARN     [UIColor colorWithRed:0.941 green:0.718 blue:0.435 alpha:1.0]  // #f0b76f
#define DH_DANGER   [UIColor colorWithRed:1.000 green:0.608 blue:0.722 alpha:1.0]  // #ff9bb8

// 前向声明 (定义在文件后部)
static UIWindowScene *dh_best_window_scene(void);

@interface DHFloatingController : NSObject
@property (nonatomic, strong) UIWindow    *window;
@property (nonatomic, strong) UIView      *bar;
@property (nonatomic, strong) UIView      *cardView;   // 黑白卡片底 (白底黑边)
@property (nonatomic, strong) UILabel     *titleLabel;
@property (nonatomic, strong) UIButton    *minBtn;
@property (nonatomic, strong) UIImageView *collapsedIcon;   // 缩小态的圆形小图标
@property (nonatomic, strong) UILabel     *statsLabel;
@property (nonatomic, strong) UILabel     *urlLabel;
@property (nonatomic, strong) UIButton    *clearBtn;
@property (nonatomic, strong) UIButton    *pauseBtn;
@property (nonatomic, strong) NSTimer     *statsTimer;
@property (nonatomic, assign) BOOL         collapsed;
@property (nonatomic, assign) CGRect       expandedFrame;
- (void)attachToBestScene;
@end

static DHFloatingController *gFloat = nil;

@implementation DHFloatingController

- (instancetype)init {
    if ((self = [super init])) {
        [self build];
    }
    return self;
}

// 创建悬浮窗并绑定到最佳 scene; 无 scene 时降级到 mainScreen (旧 UIKit)
- (UIWindow *)createFloatingWindow {
    UIWindowScene *scene = dh_best_window_scene();
    if (scene) {
        return [[UIWindow alloc] initWithWindowScene:scene];
    }
    // 旧 UIKit 无 Scene Manifest: 直接用 screen 创建
    return [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
}

- (void)attachToBestScene {
    if (!self.window) return;
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = dh_best_window_scene();
        if (scene && self.window.windowScene != scene) {
            self.window.windowScene = scene;
        }
    }
    self.window.hidden = NO;
    // 不要 makeKeyAndVisible：会抢走宿主 key window，宿主恢复焦点后悬浮窗被盖住或丢掉
}

- (void)build {
    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat W = 252, H = 202;
    // 初始贴右上, 顶部避开灵动岛/刘海 (保守安全值, 拖动后随用户)
    CGRect frame = CGRectMake(screen.size.width - W - 12, 64, W, H);
    self.expandedFrame = frame;

    UIWindow *w = [self createFloatingWindow];
    w.frame = frame;
    w.windowLevel = UIWindowLevelAlert + 1000;
    w.backgroundColor = [UIColor clearColor];
    w.layer.cornerRadius = 8;
    w.layer.masksToBounds = YES;
    w.rootViewController = [UIViewController new];
    w.rootViewController.view.backgroundColor = [UIColor clearColor];
    self.window = w;
    UIView *root = w.rootViewController.view;

    // 夜间卡片: 近黑底 + 1pt 浅描边 (不再用深色毛玻璃)
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, H)];
    card.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    card.backgroundColor = DH_BG;
    card.layer.cornerRadius = 8;
    card.layer.masksToBounds = YES;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor = DH_ACCENT.CGColor;
    [root addSubview:card];
    self.cardView = card;

    // 缩小态的圆形小图标 (SF Symbol 钥匙, 渲染可靠, 不依赖 emoji), 展开态隐藏
    UIImageView *icon = [[UIImageView alloc] initWithFrame:CGRectMake(0, 0, W, H)];
    if (@available(iOS 13.0, *)) {
        UIImageSymbolConfiguration *cfg =
            [UIImageSymbolConfiguration configurationWithPointSize:24 weight:UIImageSymbolWeightSemibold];
        icon.image = [UIImage systemImageNamed:@"key.fill" withConfiguration:cfg];
    }
    icon.tintColor = DH_ACCENT;
    icon.contentMode = UIViewContentModeCenter;
    icon.alpha = 0;
    self.collapsedIcon = icon;
    [root addSubview:icon];

    // 标题栏 (透明, 铺在深色卡面上)
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, 40)];
    bar.backgroundColor = [UIColor clearColor];
    bar.userInteractionEnabled = YES;
    self.bar = bar;
    [root addSubview:bar];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 9, 170, 22)];
    self.titleLabel.text = @"IOSDecryptHub";
    self.titleLabel.textColor = DH_ACCENT;
    self.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    [bar addSubview:self.titleLabel];

    self.minBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.minBtn.frame = CGRectMake(W - 44, 4, 40, 32);   // 44pt 触控区
    [self.minBtn setTitle:@"–" forState:UIControlStateNormal];
    [self.minBtn setTitleColor:DH_MUTED forState:UIControlStateNormal];
    self.minBtn.titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightMedium];
    [self.minBtn addTarget:self action:@selector(toggleCollapsed) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:self.minBtn];

    // 拖动手势 + 缩小态点击展开
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [bar addGestureRecognizer:pan];
    UITapGestureRecognizer *barTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onBarTap)];
    [bar addGestureRecognizer:barTap];
    // 缩小态整个圆形图标也可点击展开
    UITapGestureRecognizer *iconTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onBarTap)];
    icon.userInteractionEnabled = YES;
    [icon addGestureRecognizer:iconTap];

    // 统计文本
    self.statsLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 48, W - 28, 52)];
    self.statsLabel.numberOfLines = 0;
    self.statsLabel.textColor = DH_INK;
    self.statsLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    [root addSubview:self.statsLabel];

    // URL 一行: http://ip:port  (点击复制)
    self.urlLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 104, W - 28, 36)];
    self.urlLabel.numberOfLines = 2;
    self.urlLabel.textColor = DH_LINK;
    self.urlLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.urlLabel.adjustsFontSizeToFitWidth = YES;
    self.urlLabel.minimumScaleFactor = 0.7;
    self.urlLabel.userInteractionEnabled = YES;
    self.urlLabel.text = @"(本地服务启动中…)";
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                          action:@selector(onCopyURL)];
    [self.urlLabel addGestureRecognizer:tap];
    [root addSubview:self.urlLabel];

    // App 内只保留基础控制，日志查看与分析统一在 Web 控制台完成。
    CGFloat by = 142, bw = 109, bh = 40, bx = 12, gap = 10;
    self.pauseBtn = [self makeButton:@"暂停" style:1
                               frame:CGRectMake(bx, by, bw, bh) action:@selector(onTogglePause)];
    self.clearBtn = [self makeButton:@"清空" style:2
                               frame:CGRectMake(bx + bw + gap, by, bw, bh) action:@selector(onClear)];
    [root addSubview:self.pauseBtn];
    [root addSubview:self.clearBtn];

    w.hidden = NO;
    [self attachToBestScene];

    // 定时刷新统计 (1 秒) — block + weak self, 避免 retain cycle; 缩小态不刷新
    __weak typeof(self) weakSelf = self;
    self.statsTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) { [t invalidate]; return; }
        if (strongSelf.collapsed) return;
        [strongSelf refreshStats];
    }];
    [self refreshStats];
}

- (UIButton *)makeButton:(NSString *)t style:(int)style frame:(CGRect)f action:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = f;
    [b setTitle:t forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    b.layer.cornerRadius = 8;
    b.layer.borderWidth = 1.0;
    if (style == 0) {
        // 主操作: 浅底深字 (夜间反白)
        b.backgroundColor = DH_ACCENT;
        [b setTitleColor:DH_BG forState:UIControlStateNormal];
        b.layer.borderColor = DH_ACCENT.CGColor;
    } else if (style == 1) {
        // 次操作: 深灰底浅字
        b.backgroundColor = DH_SURFACE;
        [b setTitleColor:DH_WARN forState:UIControlStateNormal];
        b.layer.borderColor = DH_WARN.CGColor;
    } else {
        // 危险操作: 深底危险色描边
        b.backgroundColor = DH_BG;
        [b setTitleColor:DH_DANGER forState:UIControlStateNormal];
        b.layer.borderColor = DH_DANGER.CGColor;
    }
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

// URL 行样式: 正常 = 冷蓝; 异常 = 浅底深字反白 (fail-loud, 不再用红/蓝)
- (void)applyUrlStyle:(BOOL)error {
    if (error) {
        self.urlLabel.backgroundColor = DH_ACCENT;
        self.urlLabel.textColor = DH_BG;
        self.urlLabel.layer.cornerRadius = 6;
        self.urlLabel.layer.masksToBounds = YES;
    } else {
        self.urlLabel.backgroundColor = [UIColor clearColor];
        self.urlLabel.textColor = DH_LINK;
        self.urlLabel.layer.cornerRadius = 0;
    }
}

- (void)refreshStats {
    DHLogStore *s = [DHLogStore shared];
    NSUInteger d = [s countForCategory:DHCategoryDigest];
    NSUInteger h = [s countForCategory:DHCategoryHMAC];
    NSUInteger sym = [s countForCategory:DHCategorySymmetric];
    NSUInteger asym = [s countForCategory:DHCategoryAsymmetric];
    NSUInteger file = [s countForCategory:DHCategoryFile];
    NSUInteger sys = [s countForCategory:DHCategorySystem];
    NSUInteger noiseCrypto = [s noiseCountForBoard:DHNoiseBoardCrypto];
    NSUInteger noiseSys    = [s noiseCountForBoard:DHNoiseBoardSys];
    NSString *state = s.paused ? @"已暂停" : @"运行中";
    self.statsLabel.text = [NSString stringWithFormat:
        @"%@  总 %lu\n摘要 %lu  HMAC %lu  对称 %lu  RSA %lu\n系统 %lu  加密噪声 %lu  系统噪声 %lu",
        state, (unsigned long)[s totalCount],
        (unsigned long)d, (unsigned long)h, (unsigned long)sym, (unsigned long)asym,
        (unsigned long)(file + sys), (unsigned long)noiseCrypto, (unsigned long)noiseSys];

    // fail-loud: 把健康状态显示出来 —— 服务失败/hook未挂上/落盘失败都用红字明示,
    // 而不是恒显"启动中…"假装一切正常.
    const char *hc = dh_health_summary();
    NSString *health = (hc && hc[0]) ? [NSString stringWithUTF8String:hc] : @"";

    uint16_t port = dh_http_port();
    if (dh_health_http_failed()) {
        [self applyUrlStyle:YES];
        self.urlLabel.text = [NSString stringWithFormat:@"服务失败\n%@", health.length ? health : @"端口被占用"];
    } else if (port > 0) {
        NSString *url = dh_http_url();
        if (dh_health_local_only()) url = [url stringByAppendingString:@" (仅本地)"];
        if (health.length) {
            [self applyUrlStyle:YES];
            self.urlLabel.text = [NSString stringWithFormat:@"%@\n⚠ %@", url, health];
        } else {
            [self applyUrlStyle:NO];
            self.urlLabel.text = [NSString stringWithFormat:@"%@\n(点这里复制)", url];
        }
    } else {
        [self applyUrlStyle:NO];
        self.urlLabel.text = @"(本地服务启动中…)";
    }
}

- (void)onCopyURL {
    NSString *u = dh_http_url();
    if (!u || ![u hasPrefix:@"http"]) return;
    [UIPasteboard generalPasteboard].string = u;
    NSString *original = self.urlLabel.text;
    self.urlLabel.text = @"已复制到剪贴板";
    self.urlLabel.textColor = DH_ACCENT;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        self.urlLabel.textColor = DH_LINK;
        if ([self.urlLabel.text isEqualToString:@"已复制到剪贴板"]) self.urlLabel.text = original;
    });
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:g.view.window];
    if (g.state == UIGestureRecognizerStateChanged) {
        CGRect f = self.window.frame;
        f.origin.x += t.x;
        f.origin.y += t.y;
        CGRect scr = [UIScreen mainScreen].bounds;
        f.origin.x = MAX(0, MIN(scr.size.width  - f.size.width,  f.origin.x));
        f.origin.y = MAX(0, MIN(scr.size.height - f.size.height, f.origin.y));
        self.window.frame = f;
        if (!self.collapsed) self.expandedFrame = f;
        [g setTranslation:CGPointZero inView:g.view.window];
    }
}

- (void)toggleCollapsed {
    self.collapsed = !self.collapsed;
    CGRect target; CGFloat radius;
    if (self.collapsed) {
        // 缩小成一个圆形小图标 (54x54)
        CGFloat D = 54;
        target = CGRectMake(self.window.frame.origin.x, self.window.frame.origin.y, D, D);
        radius = D / 2;
    } else {
        target = self.expandedFrame;
        target.origin.x = self.window.frame.origin.x;
        target.origin.y = self.window.frame.origin.y;
        radius = 8;
    }
    BOOL col = self.collapsed;
    [UIView animateWithDuration:0.30 delay:0 usingSpringWithDamping:0.82 initialSpringVelocity:0
                        options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.window.frame = target;
        self.window.layer.cornerRadius = radius;
        self.cardView.layer.cornerRadius = radius;
        self.collapsedIcon.frame = CGRectMake(0, 0, target.size.width, target.size.height);
        self.collapsedIcon.alpha = col ? 1 : 0;
        self.titleLabel.alpha = col ? 0 : 1;
        self.minBtn.alpha     = col ? 0 : 1;
        self.statsLabel.alpha = col ? 0 : 1;
        self.urlLabel.alpha   = col ? 0 : 1;
        self.pauseBtn.alpha   = col ? 0 : 1;
        self.clearBtn.alpha   = col ? 0 : 1;
    } completion:nil];
}

- (void)onBarTap {
    // 缩小态点击(标题栏或圆形图标)展开; 展开态点击不缩小, 避免误触(缩小用「–」按钮)
    if (self.collapsed) [self toggleCollapsed];
}

- (void)onTogglePause {
    DHLogStore *s = [DHLogStore shared];
    s.paused = !s.paused;
    [self.pauseBtn setTitle:s.paused ? @"恢复" : @"暂停" forState:UIControlStateNormal];
    [self refreshStats];
}

- (void)onClear {
    // 二次确认: 文字变 "再点一次", 3 秒内再点才真正清空, 否则恢复
    if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
        [[DHLogStore shared] clearAll];
        [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
        [self refreshStats];
        return;
    }
    [self.clearBtn setTitle:@"再点一次" forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if ([self.clearBtn.titleLabel.text isEqualToString:@"再点一次"]) {
            [self.clearBtn setTitle:@"清空" forState:UIControlStateNormal];
        }
    });
}

@end

// ---------------------------------------------------------------------------
// 生命周期管理
//
// 覆盖场景:
//   - UIScene 前台 App (iOS 13+, 含 SwiftUI)
//   - 没有 Scene Manifest 的旧 UIKit App (iOS 13 以下或 UIApplicationSceneManifest 缺失)
//   - iPad 多窗口切换 (scene 断开/重连)
//   - 横竖屏旋转
//   - scene 从后台恢复
//
// 策略: 注册通知 → 找到前台 UIWindowScene → 创建/迁移悬浮窗。
// 找不到前台 scene 时降级到 UIApplicationStateActive + 现有 UIWindow。
// ---------------------------------------------------------------------------

// 读取宿主被注入 App 的图标 -> PNG (best-effort): 优先 CFBundleIcons 里最大的一张,
// 退化尝试常见 AppIcon 名。imageNamed 能从 Assets.car 读出真机图标。
NSData *dh_host_app_icon_png(void) {
    UIImage *icon = nil;
    NSBundle *mb = [NSBundle mainBundle];
    NSDictionary *icons = [mb objectForInfoDictionaryKey:@"CFBundleIcons"];
    NSArray *files = icons[@"CFBundlePrimaryIcon"][@"CFBundleIconFiles"];
    for (NSString *n in [files reverseObjectEnumerator]) {
        UIImage *i = [UIImage imageNamed:n];
        if (i) { icon = i; break; }
    }
    if (!icon) {
        for (NSString *n in @[@"AppIcon60x60", @"AppIcon", @"Icon-60", @"Icon", @"icon"]) {
            UIImage *i = [UIImage imageNamed:n];
            if (i) { icon = i; break; }
        }
    }
    if (!icon) return nil;
    NSData *png = UIImagePNGRepresentation(icon);
    if (!png || png.length > 200 * 1024) return nil;
    return png;
}

// 查找最佳前台 UIWindowScene (iOS 13+)
static UIWindowScene *dh_best_window_scene(void) {
    if (@available(iOS 13.0, *)) {
        // 优先: 前台活跃
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundActive) {
                return (UIWindowScene *)s;
            }
        }
        // 次选: 前台非活跃 (即将激活)
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundInactive) {
                return (UIWindowScene *)s;
            }
        }
        // 兜底: 任何 UIWindowScene
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                return (UIWindowScene *)s;
            }
        }
    }
    return nil;
}

// 判断当前环境是否可以创建悬浮窗
static BOOL dh_can_show_floating(void) {
    if (@available(iOS 13.0, *)) {
        // 有 scene 支持: 需要至少一个 UIWindowScene
        if (dh_best_window_scene() != nil) return YES;
        // 没有 scene (旧 UIKit 无 Scene Manifest): 检查 App 是否活跃
        if ([UIApplication sharedApplication].applicationState == UIApplicationStateActive) {
            return YES;
        }
        return NO;
    }
    // iOS 12 及以下: 无 scene 概念, App 活跃即可
    return [UIApplication sharedApplication].applicationState == UIApplicationStateActive;
}

// 尝试创建悬浮窗 (如果条件满足)
static void dh_try_show_floating(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gFloat) {
            [gFloat attachToBestScene];
            return;
        }
        if (!dh_can_show_floating()) return;
        gFloat = [[DHFloatingController alloc] init];
    });
}

// 通知回调: scene 激活 / App 活跃 / 方向变化
static void dh_on_scene_activated(NSNotification *note) {
    (void)note;
    dh_try_show_floating();
}

static void dh_on_app_did_become_active(NSNotification *note) {
    (void)note;
    dh_try_show_floating();
}

// 安装通知监听 + 首次尝试
void dh_ui_install_floating(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        // 注册通知 (幂等: 只在第一次安装)
        static BOOL notifications_installed = NO;
        if (!notifications_installed) {
            notifications_installed = YES;
            NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

            if (@available(iOS 13.0, *)) {
                // UIScene 激活 (覆盖 SwiftUI / 标准 UIKit / iPad 多窗口)
                [nc addObserverForName:UISceneDidActivateNotification
                                object:nil queue:[NSOperationQueue mainQueue]
                            usingBlock:^(NSNotification *note_) { dh_on_scene_activated(note_); }];
                [nc addObserverForName:UISceneDidDisconnectNotification
                                object:nil queue:[NSOperationQueue mainQueue]
                            usingBlock:^(NSNotification *note_) { dh_on_scene_activated(note_); }];
            }

            // 旧 UIKit 无 Scene Manifest 的兜底
            [nc addObserverForName:UIApplicationDidBecomeActiveNotification
                            object:nil queue:[NSOperationQueue mainQueue]
                        usingBlock:^(NSNotification *note_) { dh_on_app_did_become_active(note_); }];
        }

        // 首次尝试 (可能 App 已经活跃)
        dh_try_show_floating();

        // 如果首次失败, 延迟重试几次 (覆盖启动慢的 App)
        if (!gFloat) {
            for (int delay_ms = 500; delay_ms <= 3000; delay_ms += 500) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)(delay_ms * NSEC_PER_MSEC)),
                    dispatch_get_main_queue(), ^{
                    dh_try_show_floating();
                });
            }
        }
    });
}

#else  // !__has_include(<UIKit/UIKit.h>)

// 纯 macOS target 下没有 UIKit, 提供空 stub - 浏览器看 web 面板就够了.
void dh_ui_install_floating(void) {}
NSData *dh_host_app_icon_png(void) { return nil; }

#endif
