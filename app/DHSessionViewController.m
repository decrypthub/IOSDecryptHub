#import "DHSessionViewController.h"
#import "../src/session/idh_session_ipc.h"

static NSString *reasonText(NSString *reason) {
    return @{
        @"agent_timeout": @"等待 Agent 超时", @"target_exited": @"目标 App 已退出",
        @"agent_disconnected": @"Agent 连接超时", @"service_restarted": @"设备服务已重启",
        @"user_ended": @"用户结束", @"deadline": @"达到时间上限", @"capacity": @"达到容量上限",
        @"drain_timeout": @"确认尾部超时",
        @"mode_disabled": @"设备会话模式已关闭", @"scope_disabled": @"应用注入配置已关闭",
        @"active_session": @"手机上已有一个会话，请先结束该会话。",
        @"storage_error": @"保存会话失败，请查看服务日志。",
        @"service_unavailable": @"设备服务不可达。",
    }[reason ?: @""] ?: reason ?: @"";
}

static NSString *categoryText(NSUInteger category) {
    NSArray *names = @[@"摘要算法", @"HMAC", @"对称加密", @"非对称加密", @"文件", @"系统", @"网络", @"钥匙串", @"其他"];
    return category < names.count ? names[category] : @"其他";
}

@implementation DHSessionViewController {
    NSString *_bundleId;
    NSDictionary *_status;
    NSDictionary *_session;
    NSArray<NSDictionary *> *_events;
    NSString *_selected;
    NSTimer *_timer;
    dispatch_queue_t _requests;
    BOOL _loading;
    BOOL _working;
}

- (instancetype)initWithBundleId:(NSString *)bundleId name:(NSString *)name {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _bundleId = [bundleId copy];
        self.title = name.length ? name : @"设备会话";
        _requests = dispatch_queue_create("com.iosdecrypthub.manager.session", DISPATCH_QUEUE_SERIAL);
        _events = @[];
    }
    return self;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh];
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(__unused NSTimer *timer) {
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
    NSString *bundle = _bundleId;
    NSString *selection = _selected;
    dispatch_async(_requests, ^{
        NSDictionary *status = IDHSessionRequest(@{@"action": @"status", @"bundleId": bundle});
        NSArray *sessions = status[@"sessions"];
        NSDictionary *session;
        for (NSDictionary *value in sessions) if ([value[@"sessionId"] isEqual:selection]) { session = value; break; }
        if (!session) session = sessions.firstObject;
        NSDictionary *page;
        if (session) {
            uint64_t last = [session[@"lastSeq"] unsignedLongLongValue];
            page = IDHSessionRequest(@{@"action": @"read", @"tool": @"read_session_events",
                                       @"arguments": @{@"session_id": session[@"sessionId"],
                                                        @"after_seq": @(last > 30 ? last - 30 : 0), @"limit": @100}});
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_status = status;
            self->_session = page[@"session"] ?: session;
            self->_events = page[@"events"] ?: @[];
            self->_loading = NO;
            [self.tableView reloadData];
        });
    });
}

- (void)perform:(NSDictionary *)request {
    if (_working) return;
    _working = YES;
    NSMutableDictionary *message = [request mutableCopy];
    message[@"bundleId"] = _bundleId;
    dispatch_async(_requests, ^{
        NSDictionary *response = IDHSessionRequest(message);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_working = NO;
            if (![response[@"ok"] boolValue]) {
                UIAlertController *error = [UIAlertController alertControllerWithTitle:@"设备会话"
                    message:reasonText(response[@"error"] ?: @"service_unavailable") preferredStyle:UIAlertControllerStyleAlert];
                [error addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:error animated:YES completion:nil];
            } else if (response[@"token"]) {
                [UIPasteboard.generalPasteboard setItems:@[@{@"public.utf8-plain-text": response[@"token"]}]
                    options:@{UIPasteboardOptionLocalOnly: @YES,
                              UIPasteboardOptionExpirationDate: [NSDate dateWithTimeIntervalSinceNow:120]}];
                UIAlertController *copied = [UIAlertController alertControllerWithTitle:@"已复制只读凭证"
                    message:@"通过已授权的调试转发连接本机 8088。重新配对或服务重启后需使用新凭证。"
                    preferredStyle:UIAlertControllerStyleAlert];
                [copied addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:copied animated:YES completion:nil];
            } else if (response[@"session"]) {
                self->_selected = response[@"session"][@"sessionId"];
            }
            [self refresh];
        });
    });
}

- (NSString *)sessionTitle:(NSDictionary *)session {
    if (!session) return @"尚无会话";
    if ([session[@"status"] isEqualToString:@"waiting"]) return @"等待 Agent 确认";
    if ([session[@"status"] isEqualToString:@"observing"]) return @"观察中";
    if ([session[@"status"] isEqualToString:@"closing"]) return @"正在确认尾部";
    return [NSString stringWithFormat:@"已结束 · %@", reasonText(session[@"endReason"])];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 4;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0: return 4;
        case 1: return [_status[@"modeEnabled"] boolValue] ? 3 : 1;
        case 2: return _events.count;
        default: return [_status[@"sessions"] count];
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return @[@"应用状态", @"操作", @"最近写入的摘要", @"会话记录"][section];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.numberOfLines = 0;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    BOOL mode = [_status[@"modeEnabled"] boolValue];
    BOOL active = _session && ![_session[@"status"] isEqualToString:@"ended"];
    if (indexPath.section == 0) {
        switch (indexPath.row) {
            case 0: {
                cell.textLabel.text = @"注入配置";
                cell.detailTextLabel.text = _status ? ([_status[@"scopeEnabled"] boolValue] ? @"已启用" : @"已关闭") : @"设备服务不可达";
                break;
            }
            case 1: {
                cell.textLabel.text = @"Agent";
                NSDictionary *agent = [_status[@"agent"] isKindOfClass:NSDictionary.class] ? _status[@"agent"] : nil;
                if (agent) {
                    NSMutableArray *names = [NSMutableArray array];
                    for (NSNumber *number in agent[@"enabledCategories"]) [names addObject:categoryText(number.unsignedIntegerValue)];
                    NSString *generation = agent[@"processGeneration"];
                    cell.detailTextLabel.text = [NSString stringWithFormat:@"PID %@ · %@ · %@\n%@",
                        agent[@"pid"], agent[@"agentBuild"], [generation substringToIndex:MIN(generation.length, 8)],
                        [agent[@"paused"] boolValue] ? @"源采集已暂停" : [names componentsJoinedByString:@"、"]];
                } else {
                    cell.detailTextLabel.text = @"等待登记";
                }
                break;
            }
            case 2: {
                cell.textLabel.text = [self sessionTitle:_session];
                NSString *tail = [_session[@"tailUnconfirmed"] boolValue] ? @" · 尾部未确认" :
                    (_session[@"finalSeq"] ? @" · 尾部已确认" : @"");
                if (_session) cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ 条 · 摘要丢失 %@ · 源队列丢失 %@%@",
                    _session[@"count"], _session[@"dropped"], _session[@"sourceDropped"],
                    tail];
                break;
            }
            default: {
                cell.textLabel.text = @"MCP";
                NSString *state = _status[@"mcpStatus"] ?: @"";
                cell.detailTextLabel.text = @{@"listening": @"本机 8088 · 只读",
                    @"port_busy": @"8088 被旧进程占用，退出该进程后自动重试",
                    @"disabled": @"设备会话模式已关闭", @"listen_failed": @"本机监听失败",
                    @"starting": @"正在启动"}[state] ?: @"设备服务不可达";
                break;
            }
        }
    } else if (indexPath.section == 1) {
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        cell.textLabel.textColor = [_status[@"ok"] boolValue] ? self.view.tintColor : UIColor.secondaryLabelColor;
        if (indexPath.row == 0) cell.textLabel.text = mode ? @"关闭设备会话模式" : @"启用设备会话模式";
        if (indexPath.row == 1) {
            cell.textLabel.text = active ? @"结束会话" : @"开始会话";
            if ([_session[@"status"] isEqualToString:@"closing"]) {
                cell.textLabel.text = @"正在确认尾部";
                cell.textLabel.textColor = UIColor.secondaryLabelColor;
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            }
        }
        if (indexPath.row == 2) cell.textLabel.text = @"复制 MCP 只读凭证";
    } else if (indexPath.section == 2) {
        NSDictionary *event = _events[indexPath.row];
        cell.textLabel.text = [NSString stringWithFormat:@"#%@ · %@%@", event[@"seq"],
            categoryText([event[@"category"] unsignedIntegerValue]), [event[@"update"] boolValue] ? @" · 更新" : @""];
        cell.detailTextLabel.text = event[@"phase"] ?: event[@"kind"];
    } else {
        NSDictionary *session = _status[@"sessions"][indexPath.row];
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        cell.textLabel.text = [self sessionTitle:session];
        cell.detailTextLabel.text = session[@"sessionId"];
        cell.accessoryType = [session[@"sessionId"] isEqual:_session[@"sessionId"]] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (![_status[@"ok"] boolValue]) return;
    if (indexPath.section == 3) {
        _selected = _status[@"sessions"][indexPath.row][@"sessionId"];
        [self refresh];
        return;
    }
    if (indexPath.section != 1) return;
    switch (indexPath.row) {
        case 0:
            [self perform:@{@"action": @"set_mode", @"enabled": @(![_status[@"modeEnabled"] boolValue])}];
            break;
        case 1:
            if ([_session[@"status"] isEqualToString:@"closing"]) break;
            if (_session && ![_session[@"status"] isEqualToString:@"ended"])
                [self perform:@{@"action": @"end", @"sessionId": _session[@"sessionId"]}];
            else
                [self perform:@{@"action": @"start", @"sessionId": NSUUID.UUID.UUIDString.lowercaseString}];
            break;
        case 2:
            [self perform:@{@"action": @"pair"}];
            break;
    }
}
@end
