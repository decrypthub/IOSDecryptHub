// DHRootViewController.m — 主界面：管理与查看注入的 App
//
// 设计取向（按使用逻辑，不按实现）：
//   - 打开就是"我开了哪些 App"；顶部可过滤出「已启用」
//   - 全部应用按首字母分组，右侧有快速导航索引（中文按拼音首字母）
//   - 每行只有图标（R 角）+ 名称 + 开关；取不到图标时用首字母默认图标，绝不空着
//   - 提示文案只留一句真正需要用户做动作的

#import "DHRootViewController.h"
#import "DHSessionViewController.h"
#import "../src/session/idh_session_ipc.h"
#import "DHSettingsViewController.h"
#import "DHConfigStore.h"
#import "DHAppEnumerator.h"

typedef NS_ENUM(NSInteger, DHFilter) {
    DHFilterAll = 0,
    DHFilterEnabled,
};

@interface DHRootViewController () <UISearchResultsUpdating>
@property (nonatomic, copy) NSArray<DHAppInfo *> *allApps;
@property (nonatomic, strong) NSMutableSet<NSString *> *enabled;
@property (nonatomic, copy) NSArray<NSArray<DHAppInfo *> *> *sections;
@property (nonatomic, copy) NSArray<NSString *> *sectionHeaders;
@property (nonatomic, copy) NSArray<NSString *> *sectionIndexes;
@property (nonatomic, copy) NSArray<DHAppInfo *> *matched;
@property (nonatomic, strong) UISearchController *search;
@property (nonatomic, strong) UISegmentedControl *filter;
@property (nonatomic, assign) BOOL searching;
@property (nonatomic, assign) BOOL enabledOnly;
@property (nonatomic, copy, nullable) NSString *freshLatest;   // App 自己刚查到的线上版本
@property (nonatomic, strong) NSMutableArray<NSString *> *pendingRestart;   // 改了开关但还没重启的 App
@property (nonatomic, copy) NSDictionary<NSString *, NSDictionary *> *injected;  // 本机 8088 探测到的已注入 App
@end

@implementation DHRootViewController

#pragma mark - lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    [self loadPendingRestart];
    [self refreshLatestIfStale];
    self.tableView.rowHeight = 56;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.sectionIndexMinimumDisplayRowCount = 12;

    self.filter = [[UISegmentedControl alloc] initWithItems:@[ @"全部", @"已启用" ]];
    self.filter.selectedSegmentIndex = 0;
    [self.filter addTarget:self action:@selector(filterChanged) forControlEvents:UIControlEventValueChanged];
    self.navigationItem.titleView = self.filter;

    // 齿轮按钮（有新版时带一个小橙点，让用户不必主动去翻设置）
    UIButton *gear = [UIButton buttonWithType:UIButtonTypeSystem];
    gear.frame = CGRectMake(0, 0, 30, 30);
    [gear setImage:[UIImage systemImageNamed:@"gearshape"] forState:UIControlStateNormal];
    [gear addTarget:self action:@selector(openSettings) forControlEvents:UIControlEventTouchUpInside];
    UIView *dot = [[UIView alloc] initWithFrame:CGRectMake(24, 1, 8, 8)];
    dot.backgroundColor = [UIColor systemOrangeColor];
    dot.layer.cornerRadius = 4;
    dot.tag = 999;
    [gear addSubview:dot];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:gear];

    self.search = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.search.searchResultsUpdater = self;
    self.search.obscuresBackgroundDuringPresentation = NO;
    self.search.searchBar.placeholder = @"搜索 App";
    self.navigationItem.searchController = self.search;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reload];
    [self prunePendingRestart];
}

// daemon 每 12 小时查一次；App 打开时若距上次检查超过 6 小时就补一次，
// 让"有新版本"这件事不必等周期、也不必用户主动去点检查更新。
// 静默进行：只更新齿轮上的橙点，不弹任何东西。
- (void)refreshLatestIfStale {
    NSTimeInterval lastCheck = [DHReadUpdaterState()[@"lastCheck"] doubleValue];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (lastCheck > 0 && now - lastCheck < 6 * 3600) return;
    DHFetchLatestRelease(^(NSDictionary *_Nullable info, __unused NSError *_Nullable error) {
        NSString *version = info[@"version"];
        if (![version isKindOfClass:[NSString class]] || version.length == 0) return;
        self.freshLatest = version;
        [self refreshUpdateDot];
    });
}

- (BOOL)hasPendingUpdate {
    if (DHPendingUpdateVersion() != nil) return YES;
    NSString *installed = DHReadEngineMeta()[@"version"];
    if (self.freshLatest.length && [installed isKindOfClass:[NSString class]] && installed.length) {
        return DHCompareVersions(installed, self.freshLatest) == NSOrderedAscending;
    }
    return NO;
}

- (void)refreshUpdateDot {
    UIView *dot = [self.navigationItem.rightBarButtonItem.customView viewWithTag:999];
    dot.hidden = ![self hasPendingUpdate];
}

- (void)openSettings {
    DHSettingsViewController *settings = [[DHSettingsViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    [self.navigationController pushViewController:settings animated:YES];
}

- (void)filterChanged {
    self.enabledOnly = (self.filter.selectedSegmentIndex == DHFilterEnabled);
    [self rebuild];
    [self.tableView reloadData];
}

#pragma mark - 数据

- (void)reload {
    // 有新版本就在齿轮上点个橙点：用户不主动翻设置也能知道
    [self refreshUpdateDot];
    self.allApps = DHInstalledApps();
    self.enabled = [[DHReadEnabledBundles() mutableCopy] ?: [NSMutableSet set] mutableCopy];
    [self rebuild];
    [self.tableView reloadData];
    [self refreshInjectedStatus];
}

- (void)refreshInjectedStatus {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *found = IDHSessionModeEnabled() ?
            IDHSessionRequest(@{@"action": @"registrations"})[@"agents"] : DHProbeInjectedApps();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.injected = found;
            [self.tableView reloadData];
        });
    });
}

- (void)updateSearchResultsForSearchController:(__unused UISearchController *)controller {
    [self rebuild];
    [self.tableView reloadData];
}

/// 按「过滤 → 搜索 → 首字母分组」重建分区
- (void)rebuild {
    NSString *query = [self.search.searchBar.text
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    self.searching = query.length > 0;

    NSMutableArray<DHAppInfo *> *pool = [NSMutableArray array];
    for (DHAppInfo *app in self.allApps) {
        if (self.enabledOnly && ![self.enabled containsObject:app.bundleID]) continue;
        if (self.searching &&
            ![app.name localizedCaseInsensitiveContainsString:query] &&
            ![app.bundleID localizedCaseInsensitiveContainsString:query]) continue;
        [pool addObject:app];
    }

    if (self.searching) {   // 搜索结果不分组，直接平铺
        self.sections = @[ pool ];
        self.sectionHeaders = @[ @"" ];
        self.sectionIndexes = @[];
        return;
    }

    NSMutableArray<NSArray<DHAppInfo *> *> *sections = [NSMutableArray array];
    NSMutableArray<NSString *> *headers = [NSMutableArray array];
    NSMutableArray<NSString *> *indexes = [NSMutableArray array];

    // 按（首字母, 名称）排序后分组；中文名字用拼音首字母
    NSArray<DHAppInfo *> *sorted = [pool sortedArrayUsingComparator:^NSComparisonResult(DHAppInfo *l, DHAppInfo *r) {
        NSComparisonResult byLetter = [DHAppIndexLetter(l.name) compare:DHAppIndexLetter(r.name)];
        return byLetter != NSOrderedSame ? byLetter : [l.name localizedCaseInsensitiveCompare:r.name];
    }];
    NSString *current = nil;
    NSMutableArray<DHAppInfo *> *bucket = nil;
    for (DHAppInfo *app in sorted) {
        NSString *letter = DHAppIndexLetter(app.name);
        if (![letter isEqualToString:current]) {
            if (bucket) { [sections addObject:bucket]; [headers addObject:current]; [indexes addObject:current]; }
            bucket = [NSMutableArray array];
            current = letter;
        }
        [bucket addObject:app];
    }
    if (bucket) { [sections addObject:bucket]; [headers addObject:current]; [indexes addObject:current]; }

    self.sections = sections;
    self.sectionHeaders = headers;
    self.sectionIndexes = indexes;
}

#pragma mark - 表格

- (NSInteger)numberOfSectionsInTableView:(__unused UITableView *)tableView { return self.sections.count; }

- (NSInteger)tableView:(__unused UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.sections.count == 0 ? 1 : self.sections[section].count;   // 空态占一行
}

- (NSString *)tableView:(__unused UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (self.sections.count == 0) return nil;
    NSString *header = self.sectionHeaders[section];
    return self.searching ? @"搜索结果" : header;
}

- (NSString *)tableView:(__unused UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    // 只留一句真正需要用户做动作的话，放在"已启用"页（管理开关的地方）
    if (!self.searching && self.enabledOnly && section == 0) {
        return @"改动需要重启目标 App 才生效；点右侧 ⋯ 可重启或停止。";
    }
    return nil;
}

- (NSArray<NSString *> *)sectionIndexTitlesForTableView:(__unused UITableView *)tableView {
    return self.searching ? @[] : self.sectionIndexes;
}

- (NSInteger)tableView:(__unused UITableView *)tableView sectionForSectionIndexTitle:(NSString *)title atIndex:(NSInteger)index {
    return index;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (self.sections.count == 0) {   // 空态
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.numberOfLines = 0;
        cell.textLabel.textColor = [UIColor secondaryLabelColor];
        cell.textLabel.font = [UIFont systemFontOfSize:14];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        if (self.allApps.count == 0) {
            cell.textLabel.text = @"未能读取已安装应用";
        } else if (self.searching) {
            cell.textLabel.text = @"没有匹配的 App";
        } else {
            cell.textLabel.text = @"还没有启用任何 App\n在上面搜索，或从列表里打开开关";
        }
        return cell;
    }

    DHAppInfo *app = self.sections[indexPath.section][indexPath.row];
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"app"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"app"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.detailTextLabel.font = [UIFont systemFontOfSize:11];

        // 附件区：⋯ 菜单 + 开关。⋯ 是可见入口（左滑/长按用户未必发现），
        // 里面按当前状态给"重启 / 停止"或"开启注入"。
        UIView *accessory = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 92, 32)];
        UIButton *more = [UIButton buttonWithType:UIButtonTypeSystem];
        more.frame = CGRectMake(0, 1, 30, 30);
        [more setImage:[UIImage systemImageNamed:@"ellipsis.circle"] forState:UIControlStateNormal];
        more.showsMenuAsPrimaryAction = YES;          // iOS 14+
        [accessory addSubview:more];
        UISwitch *toggle = [[UISwitch alloc] init];
        toggle.frame = CGRectMake(38, 0, 51, 31);
        [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
        [accessory addSubview:toggle];
        cell.accessoryView = accessory;
    }
    UIView *accessory = cell.accessoryView;
    UIButton *more = (UIButton *)accessory.subviews.firstObject;
    UISwitch *toggle = (UISwitch *)accessory.subviews.lastObject;
    more.menu = [self menuForApp:app];               // 每次重建：菜单内容跟着状态走

    cell.textLabel.text = app.name;
    BOOL on = [self.enabled containsObject:app.bundleID];
    // 副标题只留 bundleID；状态标记只在偏离预期时出现：
    // 改了开关没重启 → 需重启；已开启、进程在跑但没注上 → 未注入。
    // 注入正常这类符合预期的状态不再在列表里重复显示。
    if ([self.pendingRestart containsObject:app.bundleID] ||
        (on && DHAppProcessRunning(app) && !self.injected[app.bundleID])) {
        NSMutableAttributedString *subtitle = [[NSMutableAttributedString alloc]
            initWithString:app.bundleID
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }];
        NSString *mark = [self.pendingRestart containsObject:app.bundleID] ? @"　需重启" : @"　未注入";
        [subtitle appendAttributedString:[[NSAttributedString alloc]
            initWithString:mark
                attributes:@{ NSForegroundColorAttributeName: [UIColor systemOrangeColor] }]];
        cell.detailTextLabel.attributedText = subtitle;
    } else {
        cell.detailTextLabel.attributedText = nil;
        cell.detailTextLabel.text = app.bundleID;
    }
    cell.imageView.image = DHAppListIcon(app.bundleID, app.bundlePath, app.name);
    toggle.on = [self.enabled containsObject:app.bundleID];
    toggle.tag = indexPath.section * 10000 + indexPath.row;
    return cell;
}

#pragma mark - 开关

- (void)toggleChanged:(UISwitch *)toggle {
    NSInteger section = toggle.tag / 10000;
    NSInteger row = toggle.tag % 10000;
    if (section >= (NSInteger)self.sections.count) return;
    NSArray<DHAppInfo *> *apps = self.sections[section];
    if (row < 0 || row >= (NSInteger)apps.count) return;
    [self applyEnabled:toggle.on forApp:apps[row] revert:(void (^)(void))^{
        toggle.on = !toggle.on;
    }];
}

#pragma mark - 每行的 ⋯ 菜单（与长按菜单同一份内容）

- (UIMenu *)menuForApp:(DHAppInfo *)app {
    BOOL on = [self.enabled containsObject:app.bundleID];
    __weak typeof(self) weakSelf = self;
    NSMutableArray<UIMenuElement *> *items = [NSMutableArray array];
    if (on) {
        [items addObject:[UIAction actionWithTitle:@"重启" image:[UIImage systemImageNamed:@"arrow.clockwise"]
                                        identifier:nil handler:^(__unused UIAction *a) {
            [weakSelf requestRestartFor:app];
        }]];
        [items addObject:[UIAction actionWithTitle:@"停止" image:[UIImage systemImageNamed:@"stop.circle"]
                                        identifier:nil handler:^(__unused UIAction *a) {
            [weakSelf requestStopFor:app];
        }]];
    } else {
        [items addObject:[UIAction actionWithTitle:@"开启注入" image:[UIImage systemImageNamed:@"checkmark.circle"]
                                        identifier:nil handler:^(__unused UIAction *a) {
            [weakSelf applyEnabled:YES forApp:app revert:nil];
        }]];
    }
    [items addObject:[UIAction actionWithTitle:@"会话" image:[UIImage systemImageNamed:@"list.bullet.rectangle"]
                                    identifier:nil handler:^(__unused UIAction *a) {
        DHSessionViewController *view = [[DHSessionViewController alloc] initWithBundleId:app.bundleID name:app.name];
        [weakSelf.navigationController pushViewController:view animated:YES];
    }]];
    return [UIMenu menuWithChildren:items];
}

- (UIContextMenuConfiguration *)tableView:(__unused UITableView *)tableView
    contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
                                        point:(__unused CGPoint)point {
    if (self.sections.count == 0 || indexPath.section >= (NSInteger)self.sections.count) return nil;
    NSArray<DHAppInfo *> *apps = self.sections[indexPath.section];
    if (indexPath.row >= (NSInteger)apps.count) return nil;
    DHAppInfo *app = apps[indexPath.row];
    return [UIContextMenuConfiguration configurationWithIdentifier:nil previewProvider:nil
        actionProvider:^(__unused NSArray<UIMenuElement *> *suggested) {
        return [self menuForApp:app];
    }];
}

- (void)requestRestartFor:(DHAppInfo *)app {
    // rootHide 上 launchd 能拉起 daemon，但签过名的二进制对引擎目录 EPERM，
    // 拿不到锁就退出，重启请求永远不会被处理。管理器与目标 App 同为 mobile，自己杀+打开。
    [self clearPendingRestart:app.bundleID];
    NSString *bundleID = app.bundleID;
    NSString *name = app.name;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL killed = DHKillAppProcess(app);
        if (killed) [NSThread sleepForTimeInterval:0.4];
        BOOL relaunched = DHRelaunchApp(bundleID);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (relaunched) {
                [self flashRestarted:name];
                return;
            }
            NSString *message = killed
                ? @"已结束它，请手动打开以让改动生效。"
                : @"无法重启该 App。";
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                message:message preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)requestStopFor:(DHAppInfo *)app {
    [self clearPendingRestart:app.bundleID];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        DHKillAppProcess(app);
    });
}

#pragma mark - 开关写入

- (void)applyEnabled:(BOOL)on forApp:(DHAppInfo *)app revert:(void (^)(void))revert {
    NSMutableSet<NSString *> *next = [self.enabled mutableCopy];
    if (on) [next addObject:app.bundleID]; else [next removeObject:app.bundleID];
    NSError *writeErr = nil;
    if (!DHWriteEnabledBundles(next, &writeErr)) {
        if (revert) revert();
        NSString *detail = writeErr.localizedDescription.length
            ? writeErr.localizedDescription : @"请确认插件已正确安装。";
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"保存失败"
            message:[NSString stringWithFormat:@"写入启用名单失败。%@", detail]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    self.enabled = next;
    [self rebuild];
    [self.tableView reloadData];

    // 关掉/打开都只有重启目标 App 才生效。用户不知道这一点，所以由我们来判断：
    // 目标正在运行时自动重启它；没在运行时什么都不做（下次打开自然是新状态）。
    // 这样批量开关多个 App 时不会弹一堆确认框。
    // 不替用户做动作：只在列表顶部告诉他"这个改动需要重启才生效"，并给一个按钮。
    // 目标本来就没在运行的话不用提醒 —— 下次打开自然是新状态。
    NSString *selfBundle = [[NSBundle mainBundle] bundleIdentifier];
    BOOL isSelf = [app.bundleID isEqualToString:selfBundle];
    if (!isSelf && DHAppProcessRunning(app)) {
        [self markPendingRestart:app.bundleID];
    } else {
        [self clearPendingRestart:app.bundleID];
    }
}

#pragma mark - 待重启（开关改了但还没生效）

- (void)loadPendingRestart {
    NSArray *saved = [[NSUserDefaults standardUserDefaults] arrayForKey:@"dhPendingRestart"];
    self.pendingRestart = [NSMutableArray array];
    for (id item in saved) {
        if ([item isKindOfClass:[NSString class]]) [self.pendingRestart addObject:item];
    }
}

- (void)savePendingRestart {
    [[NSUserDefaults standardUserDefaults] setObject:[self.pendingRestart copy] forKey:@"dhPendingRestart"];
}

- (void)markPendingRestart:(NSString *)bundleID {
    if (bundleID.length == 0) return;
    if (![self.pendingRestart containsObject:bundleID]) {
        [self.pendingRestart addObject:bundleID];
        [self savePendingRestart];
    }
    [self.tableView reloadData];
}

- (void)clearPendingRestart:(NSString *)bundleID {
    if ([self.pendingRestart containsObject:bundleID]) {
        [self.pendingRestart removeObject:bundleID];
        [self savePendingRestart];
        [self.tableView reloadData];
    }
}

// 每次进入界面时清理：已经不在运行的 App 不用再提醒（下次打开自然是新状态）
- (void)prunePendingRestart {
    NSMutableDictionary<NSString *, DHAppInfo *> *map = [NSMutableDictionary dictionary];
    for (DHAppInfo *app in self.allApps) map[app.bundleID] = app;
    BOOL changed = NO;
    for (NSString *bundleID in [self.pendingRestart copy]) {
        DHAppInfo *app = map[bundleID];
        if (!app || !DHAppProcessRunning(app)) {
            [self.pendingRestart removeObject:bundleID];
            changed = YES;
        }
    }
    if (changed) [self savePendingRestart];
}

#pragma mark - 重启结果

- (void)flashRestarted:(NSString *)name {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
        message:[NSString stringWithFormat:@"已重启 %@ 以应用改动", name]
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [alert dismissViewControllerAnimated:YES completion:nil]; });
}

@end
