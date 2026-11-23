// DHStatusViewController.m — 设备状态页：服务状态、会话模式、连接方式
//
// 数据全走本机 unix socket（IDHSessionRequest），与设备会话页同一通道。

#import "DHStatusViewController.h"
#import "../src/session/idh_session_ipc.h"

@implementation DHStatusViewController {
    NSDictionary *_status;        // registrations 应答：modeEnabled/remoteListen/agents/mcpStatus
    dispatch_queue_t _requests;
    NSTimer *_timer;
    BOOL _loading;
    BOOL _working;
}

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        self.title = @"设备状态";
        _requests = dispatch_queue_create("com.iosdecrypthub.manager.status", DISPATCH_QUEUE_SERIAL);
    }
    return self;
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

- (void)refresh {
    if (_loading) return;
    _loading = YES;
    dispatch_async(_requests, ^{
        NSDictionary *status = IDHSessionRequest(@{@"action": @"registrations"});
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_status = status;
            self->_loading = NO;
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
    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
            cell.textLabel.text = @"设备服务";
            NSString *mcp = _status[@"mcpStatus"];
            cell.detailTextLabel.text = !online ? @"不可达"
                : [mcp isEqualToString:@"listening"] ? @"在线" : (mcp ?: @"异常");
        } else if (indexPath.row == 1) {
            cell.textLabel.text = @"会话模式";
            cell.accessoryView = [self switchForKey:@"modeEnabled" action:@selector(toggleMode:)];
        } else {
            cell.textLabel.text = @"已注入应用";
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu",
                                       (unsigned long)[_status[@"agents"] count]];
        }
    } else {
        cell.textLabel.text = @"局域网连接";
        cell.accessoryView = [self switchForKey:@"remoteListen" action:@selector(toggleRemote:)];
    }
    return cell;
}

@end
