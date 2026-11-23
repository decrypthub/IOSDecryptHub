// DHStatusViewController.m — 设备状态页：服务状态、会话模式、连接方式
//
// 数据全走本机 unix socket（IDHSessionRequest），与设备会话页同一通道。

#import "DHStatusViewController.h"
#import "../src/session/idh_session_ipc.h"

@interface DHStatusViewController ()
@end

@implementation DHStatusViewController {
    NSDictionary *_status;        // registrations 应答：modeEnabled/remoteListen/agents/mcpStatus
    dispatch_queue_t _requests;
    NSTimer *_timer;
    BOOL _loading;
    BOOL _working;
    UILabel *_heroTitle;
    UILabel *_heroDetail;
    UIImageView *_heroIcon;
    UIView *_heroBadge;
}

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        self.title = @"设备状态";
        _requests = dispatch_queue_create("com.iosdecrypthub.manager.status", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self buildHero];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh];
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(__unused NSTimer *t) {
        [weakSelf refresh];
    }];
}

- (void)viewDidDisappear:(BOOL)animated {
    [super viewDidDisappear:animated];
    [_timer invalidate];
    _timer = nil;
}

#pragma mark - hero

- (void)buildHero {
    UIView *hero = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 108)];

    _heroBadge = [[UIView alloc] initWithFrame:CGRectMake(20, 26, 56, 56)];
    _heroBadge.layer.cornerRadius = 16;
    _heroBadge.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    [hero addSubview:_heroBadge];

    _heroIcon = [[UIImageView alloc] initWithFrame:CGRectInset(_heroBadge.bounds, 14, 14)];
    _heroIcon.contentMode = UIViewContentModeScaleAspectFit;
    [_heroBadge addSubview:_heroIcon];

    _heroTitle = [[UILabel alloc] initWithFrame:CGRectMake(92, 30, hero.bounds.size.width - 104, 26)];
    _heroTitle.font = [UIFont systemFontOfSize:20 weight:UIFontWeightSemibold];
    _heroTitle.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [hero addSubview:_heroTitle];

    _heroDetail = [[UILabel alloc] initWithFrame:CGRectMake(92, 56, hero.bounds.size.width - 104, 20)];
    _heroDetail.font = [UIFont systemFontOfSize:13];
    _heroDetail.textColor = [UIColor secondaryLabelColor];
    _heroDetail.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [hero addSubview:_heroDetail];

    self.tableView.tableHeaderView = hero;
    [self updateHero];
}

- (void)updateHero {
    BOOL online = [_status[@"ok"] boolValue];
    NSString *mcp = _status[@"mcpStatus"];
    UIColor *color;
    NSString *symbol, *title;
    if (!online) {
        color = [UIColor systemRedColor];
        symbol = @"antenna.radiowaves.left.and.right.slash";
        title = @"服务不可达";
    } else if ([mcp isEqualToString:@"listening"]) {
        color = [UIColor systemGreenColor];
        symbol = @"antenna.radiowaves.left.and.right";
        title = @"设备服务在线";
    } else {
        color = [UIColor systemOrangeColor];
        symbol = @"exclamationmark.triangle";
        title = [mcp isEqualToString:@"port_busy"] ? @"端口被占用" : @"服务异常";
    }
    _heroIcon.image = [[UIImage systemImageNamed:symbol]
        imageWithConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:26 weight:UIImageSymbolWeightMedium]];
    _heroIcon.tintColor = color;
    _heroBadge.backgroundColor = [color colorWithAlphaComponent:0.14];
    _heroTitle.text = title;

    NSUInteger agents = [_status[@"agents"] count];
    NSString *mode = [_status[@"modeEnabled"] boolValue] ? @"会话模式开启" : @"会话模式关闭";
    _heroDetail.text = online
        ? [NSString stringWithFormat:@"%@ · %lu 个应用注入", mode, (unsigned long)agents]
        : @"无法连接设备守护进程";
}

#pragma mark - data

- (void)refresh {
    if (_loading) return;
    _loading = YES;
    dispatch_async(_requests, ^{
        NSDictionary *status = IDHSessionRequest(@{@"action": @"registrations"});
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_status = status;
            self->_loading = NO;
            [self updateHero];
            [self.tableView reloadData];
        });
    });
}

- (void)perform:(NSDictionary *)message {
    if (_working) return;
    _working = YES;
    dispatch_async(_requests, ^{
        NSDictionary *response = IDHSessionRequest(message);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_working = NO;
            if (![response[@"ok"] boolValue]) {
                UIAlertController *error = [UIAlertController alertControllerWithTitle:@"设备状态"
                    message:@"操作失败，请查看设备服务日志。" preferredStyle:UIAlertControllerStyleAlert];
                [error addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:error animated:YES completion:nil];
            }
            [self refresh];
        });
    });
}

- (UISwitch *)switchForKey:(NSString *)key action:(SEL)action {
    UISwitch *sw = [UISwitch new];
    sw.on = [_status[key] boolValue];
    [sw addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    return sw;
}

- (void)toggleMode:(UISwitch *)sender {
    [self perform:@{@"action": @"set_mode", @"enabled": @(sender.on)}];
}

- (void)toggleRemote:(UISwitch *)sender {
    [self perform:@{@"action": @"set_remote_listen", @"enabled": @(sender.on)}];
}

- (void)iconForCell:(UITableViewCell *)cell name:(NSString *)name color:(UIColor *)color {
    cell.imageView.image = [[UIImage systemImageNamed:name]
        imageWithConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:16 weight:UIImageSymbolWeightMedium]];
    cell.imageView.tintColor = color;
}

#pragma mark - table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 2; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? 3 : 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"状态" : @"连接";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return section == 1 ? @"关闭时通过 USB 连接。" : nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    BOOL online = [_status[@"ok"] boolValue];
    NSString *mcp = _status[@"mcpStatus"];
    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
            cell.textLabel.text = @"设备服务";
            [self iconForCell:cell name:@"gearshape.2" color:[UIColor systemBlueColor]];
            cell.detailTextLabel.text = !online ? @"不可达"
                : [mcp isEqualToString:@"listening"] ? @"在线" : (mcp ?: @"异常");
            cell.detailTextLabel.textColor = !online || ![mcp isEqualToString:@"listening"]
                ? [UIColor systemRedColor] : [UIColor systemGreenColor];
        } else if (indexPath.row == 1) {
            cell.textLabel.text = @"会话模式";
            [self iconForCell:cell name:@"record.circle" color:[UIColor systemPurpleColor]];
            cell.accessoryView = [self switchForKey:@"modeEnabled" action:@selector(toggleMode:)];
        } else {
            cell.textLabel.text = @"已注入应用";
            [self iconForCell:cell name:@"app.badge" color:[UIColor systemTealColor]];
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu",
                                       (unsigned long)[_status[@"agents"] count]];
        }
    } else {
        cell.textLabel.text = @"局域网连接";
        [self iconForCell:cell name:@"network" color:[UIColor systemIndigoColor]];
        cell.accessoryView = [self switchForKey:@"remoteListen" action:@selector(toggleRemote:)];
    }
    return cell;
}

@end
