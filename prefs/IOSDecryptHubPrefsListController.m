// IOSDecryptHubPrefsListController.m — 设置面板与原生应用选择器

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>

typedef NS_ENUM(NSInteger, PSCellType) {
    PSGroupCell,
    PSLinkCell,
    PSLinkListCell,
    PSListItemCell,
    PSTitleValueCell,
    PSSliderCell,
    PSSwitchCell,
    PSStaticTextCell,
};

@interface PSSpecifier : NSObject
+ (instancetype)preferenceSpecifierNamed:(NSString *)name
                                   target:(id)target
                                      set:(SEL)setter
                                      get:(SEL)getter
                                   detail:(Class)detail
                                     cell:(PSCellType)cell
                                     edit:(Class)edit;
+ (instancetype)groupSpecifierWithName:(NSString *)name;
@property (nonatomic, copy) NSString *identifier;
- (id)propertyForKey:(NSString *)key;
- (void)setProperty:(id)value forKey:(NSString *)key;
@end

@interface PSTableCell : UITableViewCell
- (instancetype)initWithStyle:(UITableViewCellStyle)style
              reuseIdentifier:(NSString *)reuseIdentifier
                    specifier:(PSSpecifier *)specifier;
@end

@interface PSListController : UIViewController {
    NSMutableArray *_specifiers;
}
@property (nonatomic, retain) NSMutableArray *specifiers;
- (NSMutableArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
- (void)reloadSpecifier:(PSSpecifier *)specifier;
@end

static const CGFloat kDHWeChatAspect = 308.0 / 1000.0;
static const CGFloat kDHWeChatPadX = 12.0;
static const CGFloat kDHWeChatPadY = 8.0;

static CGFloat dh_wechat_row_height(CGFloat width) {
    if (width < 1) width = 320;
    CGFloat inner = MAX(width - kDHWeChatPadX * 2, 200);
    return ceil(inner * kDHWeChatAspect) + kDHWeChatPadY * 2;
}

@interface DHWeChatFollowCell : PSTableCell
@property (nonatomic, strong) UIImageView *followView;
@end

@implementation DHWeChatFollowCell

+ (CGFloat)preferredHeightForWidth:(CGFloat)width {
    return dh_wechat_row_height(width);
}

+ (CGFloat)preferredHeightForWidth:(CGFloat)width inTableView:(UITableView *)tableView {
    (void)tableView;
    return dh_wechat_row_height(width);
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style
              reuseIdentifier:(NSString *)reuseIdentifier
                    specifier:(PSSpecifier *)specifier {
    if ((self = [super initWithStyle:style reuseIdentifier:reuseIdentifier specifier:specifier])) {
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        self.separatorInset = UIEdgeInsetsMake(0, 4000, 0, 0);
        self.textLabel.text = nil;
        self.detailTextLabel.text = nil;
        self.imageView.image = nil;

        UIImageView *imageView = [[UIImageView alloc] init];
        imageView.contentMode = UIViewContentModeScaleAspectFit;
        imageView.userInteractionEnabled = YES;
        NSString *path = [[NSBundle bundleForClass:[self class]]
            pathForResource:@"wechat-follow" ofType:@"png"];
        if (path.length) {
            imageView.image = [UIImage imageWithContentsOfFile:path];
        }
        [self.contentView addSubview:imageView];
        self.followView = imageView;

        UITapGestureRecognizer *tap =
            [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dh_copyAccount)];
        [imageView addGestureRecognizer:tap];
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    self.textLabel.text = nil;
    self.detailTextLabel.text = nil;
    self.followView.frame = CGRectInset(self.contentView.bounds, kDHWeChatPadX, kDHWeChatPadY);
}

- (void)dh_copyAccount {
    [UIPasteboard generalPasteboard].string = @"DecryptHub";
    if (@available(iOS 10.0, *)) {
        UINotificationFeedbackGenerator *feedback = [[UINotificationFeedbackGenerator alloc] init];
        [feedback notificationOccurred:UINotificationFeedbackTypeSuccess];
    }
}

@end

// LaunchServices 私有类型只做最小声明，通过运行时加载，不产生链接依赖。
@interface NSObject (DHLaunchServices)
+ (instancetype)defaultWorkspace;
- (NSArray *)allApplications;
- (NSString *)applicationIdentifier;
- (NSString *)localizedName;
- (NSString *)applicationType;
@end

static NSString *const DHPrefsDomain = @"com.iosdecrypthub.loader";
static NSString *const DHEnabledBundlesKey = @"enabledBundles";
static NSString *const DHBundleIDProperty = @"dhBundleID";
static NSString *const DHPrefsPath =
    @"/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist";

// 从 PreferenceBundle 自身二进制路径反推 bootstrap 根目录，不再硬编码 /var/jb。
// 布局: <bootstrap>/Library/PreferenceBundles/IOSDecryptHubPrefs.bundle/IOSDecryptHubPrefs
//    → <bootstrap>/usr/lib/IOSDecryptHub/config/enabledBundles.plist
static NSString *dh_bootstrap_root(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&dh_bootstrap_root, &info) == 0 || !info.dli_fname) {
        return nil;
    }
    NSString *binaryPath = [NSString stringWithUTF8String:info.dli_fname];
    // 向上四级: IOSDecryptHubPrefs → .bundle → PreferenceBundles → Library → <bootstrap>
    NSString *root = binaryPath;
    for (int i = 0; i < 4; i++) {
        root = [root stringByDeletingLastPathComponent];
    }
    if (root.length <= 1) return nil;
    return root;
}

static NSArray<NSString *> *dh_loader_config_paths(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    NSString *root = dh_bootstrap_root();
    if (root) {
        [paths addObject:[root stringByAppendingPathComponent:
            @"usr/lib/IOSDecryptHub/config/enabledBundles.plist"]];
    }
    // 固定路径兜底（dladdr 失败时）
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"];
    return paths;
}

static NSDictionary *dh_loader_config(void) {
    for (NSString *path in dh_loader_config_paths()) {
        NSDictionary *domain = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([domain isKindOfClass:[NSDictionary class]]) return domain;
    }
    return nil;
}

static BOOL dh_write_loader_config(NSDictionary *domain) {
    for (NSString *path in dh_loader_config_paths()) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path] &&
            [domain writeToFile:path atomically:YES]) {
            return YES;
        }
    }
    return NO;
}

@interface IOSDecryptHubPrefsListController : PSListController
@end

@interface IOSDecryptHubAppListController : PSListController
@end

@implementation IOSDecryptHubPrefsListController

- (NSMutableArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (NSString *)title {
    return @"IOSDecryptHub";
}

@end


@implementation IOSDecryptHubAppListController

static NSDictionary<NSString *, NSString *> *dh_apps_from_launch_services(void) {
    static const char *frameworks[] = {
        "/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
        "/System/Library/Frameworks/CoreServices.framework/CoreServices",
        NULL,
    };

    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    for (NSUInteger index = 0; !workspaceClass && frameworks[index]; index++) {
        dlopen(frameworks[index], RTLD_LAZY | RTLD_LOCAL);
        workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    }
    if (!workspaceClass || ![workspaceClass respondsToSelector:@selector(defaultWorkspace)]) {
        return @{};
    }

    NSMutableDictionary<NSString *, NSString *> *apps = [NSMutableDictionary dictionary];
    @try {
        id workspace = [workspaceClass defaultWorkspace];
        NSArray *proxies = [workspace respondsToSelector:@selector(allApplications)]
            ? [workspace allApplications]
            : nil;
        for (id proxy in proxies) {
            NSString *bundleID = [proxy respondsToSelector:@selector(applicationIdentifier)]
                ? [proxy applicationIdentifier]
                : nil;
            if (bundleID.length == 0 || [bundleID hasPrefix:@"com.apple."]) {
                continue;
            }

            NSString *applicationType = [proxy respondsToSelector:@selector(applicationType)]
                ? [proxy applicationType]
                : nil;
            if (applicationType.length > 0 && ![applicationType isEqualToString:@"User"]) {
                continue;
            }

            NSString *name = [proxy respondsToSelector:@selector(localizedName)]
                ? [proxy localizedName]
                : nil;
            apps[bundleID] = name.length > 0 ? name : bundleID;
        }
    } @catch (__unused NSException *exception) {
        return @{};
    }
    return apps;
}

static NSDictionary<NSString *, NSString *> *dh_apps_from_filesystem(void) {
    NSString *root = @"/var/containers/Bundle/Application";
    NSFileManager *manager = [NSFileManager defaultManager];
    NSArray<NSString *> *containers = [manager contentsOfDirectoryAtPath:root error:nil];
    NSMutableDictionary<NSString *, NSString *> *apps = [NSMutableDictionary dictionary];

    for (NSString *container in containers) {
        NSString *containerPath = [root stringByAppendingPathComponent:container];
        NSArray<NSString *> *entries = [manager contentsOfDirectoryAtPath:containerPath error:nil];
        for (NSString *entry in entries) {
            if (![entry.pathExtension.lowercaseString isEqualToString:@"app"]) {
                continue;
            }

            NSString *bundlePath = [containerPath stringByAppendingPathComponent:entry];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *bundleID = info[@"CFBundleIdentifier"];
            if (bundleID.length == 0 || [bundleID hasPrefix:@"com.apple."]) {
                continue;
            }

            NSString *name = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"];
            apps[bundleID] = name.length > 0 ? name : bundleID;
        }
    }
    return apps;
}

static NSDictionary *dh_preferences(void) {
    NSDictionary *domain = dh_loader_config();
    @try {
        if (![domain isKindOfClass:[NSDictionary class]]) {
            domain = [NSDictionary dictionaryWithContentsOfFile:DHPrefsPath];
        }
        if (![domain isKindOfClass:[NSDictionary class]]) {
            CFPropertyListRef value = CFPreferencesCopyValue(
                (__bridge CFStringRef)DHEnabledBundlesKey,
                (__bridge CFStringRef)DHPrefsDomain,
                kCFPreferencesCurrentUser,
                kCFPreferencesAnyHost);
            id enabled = CFBridgingRelease(value);
            if ([enabled isKindOfClass:[NSArray class]]) {
                domain = @{DHEnabledBundlesKey: enabled};
            }
        }
        if (![domain isKindOfClass:[NSDictionary class]]) {
            domain = [[NSUserDefaults standardUserDefaults]
                persistentDomainForName:DHPrefsDomain];
        }
    } @catch (__unused NSException *exception) {
        return @{};
    }
    return [domain isKindOfClass:[NSDictionary class]] ? domain : @{};
}

static NSSet<NSString *> *dh_enabled_bundles(void) {
    NSDictionary *domain = dh_preferences();
    id value = domain[DHEnabledBundlesKey];
    if (![value isKindOfClass:[NSArray class]]) {
        return [NSSet set];
    }
    return [NSSet setWithArray:value];
}

- (NSMutableArray *)specifiers {
    if (_specifiers) {
        return _specifiers;
    }

    NSDictionary<NSString *, NSString *> *apps = dh_apps_from_launch_services();
    if (apps.count == 0) {
        apps = dh_apps_from_filesystem();
    }

    NSMutableArray *specifiers = [NSMutableArray array];
    PSSpecifier *group = [PSSpecifier groupSpecifierWithName:@"已安装的应用"];
    [group setProperty:@"开启后请完全退出并重新启动目标 App。" forKey:@"footerText"];
    [specifiers addObject:group];

    NSArray<NSString *> *bundleIDs = [apps.allKeys sortedArrayUsingComparator:
        ^NSComparisonResult(NSString *left, NSString *right) {
            return [apps[left] localizedCaseInsensitiveCompare:apps[right]];
        }];
    for (NSString *bundleID in bundleIDs) {
        PSSpecifier *specifier = [PSSpecifier
            preferenceSpecifierNamed:apps[bundleID]
            target:self
            set:@selector(setAppEnabled:specifier:)
            get:@selector(isAppEnabled:)
            detail:Nil
            cell:PSSwitchCell
            edit:Nil];
        specifier.identifier = bundleID;
        [specifier setProperty:bundleID forKey:DHBundleIDProperty];
        [specifier setProperty:bundleID forKey:@"appIDForLazyIcon"];
        [specifier setProperty:@YES forKey:@"useLazyIcons"];
        [specifiers addObject:specifier];
    }

    if (bundleIDs.count == 0) {
        PSSpecifier *empty = [PSSpecifier
            preferenceSpecifierNamed:@"未能读取已安装应用"
            target:nil
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [specifiers addObject:empty];
    }

    _specifiers = specifiers;
    return _specifiers;
}

- (NSNumber *)isAppEnabled:(PSSpecifier *)specifier {
    NSString *bundleID = [specifier propertyForKey:DHBundleIDProperty];
    return @([dh_enabled_bundles() containsObject:bundleID]);
}

- (void)setAppEnabled:(NSNumber *)enabled specifier:(PSSpecifier *)specifier {
    NSString *bundleID = [specifier propertyForKey:DHBundleIDProperty];
    if (bundleID.length == 0) {
        return;
    }

    NSMutableSet<NSString *> *enabledBundles = [dh_enabled_bundles() mutableCopy];
    if (enabled.boolValue) {
        [enabledBundles addObject:bundleID];
    } else {
        [enabledBundles removeObject:bundleID];
    }

    NSMutableDictionary *domain = [dh_preferences() mutableCopy];
    domain[DHEnabledBundlesKey] = [enabledBundles.allObjects
        sortedArrayUsingSelector:@selector(compare:)];
    BOOL wrote = NO;
    BOOL synchronized = NO;
    @try {
        NSArray *values = domain[DHEnabledBundlesKey];
        CFPreferencesSetValue(
            (__bridge CFStringRef)DHEnabledBundlesKey,
            (__bridge CFPropertyListRef)values,
            (__bridge CFStringRef)DHPrefsDomain,
            kCFPreferencesCurrentUser,
            kCFPreferencesAnyHost);
        synchronized = CFPreferencesSynchronize(
            (__bridge CFStringRef)DHPrefsDomain,
            kCFPreferencesCurrentUser,
            kCFPreferencesAnyHost);

        // 主门控文件与 dylib 同处越狱授权路径；旧 plist 继续同步用于降级兼容。
        wrote = dh_write_loader_config(domain);
        BOOL wroteLegacy = [domain writeToFile:DHPrefsPath atomically:YES];
        wrote = wrote || wroteLegacy;
    } @catch (__unused NSException *exception) {
        wrote = NO;
        synchronized = NO;
    }
    if (!wrote && !synchronized) {
        [self reloadSpecifier:specifier];
    }
}

- (NSString *)title {
    return @"选择应用";
}

@end
