// idh_device_apps.h — idhjd 的设备应用管理与注入范围接口。
// 供会话 HTTP(/api/apps, /api/injection-scope, /api/apps/relaunch)与 MCP 工具共用一份实现。
// 全部函数在 stateQueue 上同步调用；只碰文件与进程表，不依赖 updater 请求通道。

#import <Foundation/Foundation.h>

// @{@"ok":@(YES), @"apps":[{bundleId,name,execName,kind,running}], @"scope":[bundleId]}
// kind: "user"(App Store/自签) | "jb"(越狱/procursus 安装) | "system"(不可注入)
NSDictionary *idh_apps_list(void);

// 读取当前注入名单（loader 权威副本 prefs，读不到回退 jb config）
NSArray<NSString *> *idh_scope_read(void);

// {add:[],remove:[]} 合并写入：prefs plist(保留 updaterRequest 等键) + jb config 双写。
// com.apple.* 拒写（loader 本就跳过）。返回 @{@"ok", @"scope"} 或 @{@"ok":@NO,@"error"}
NSDictionary *idh_scope_apply(NSArray *add, NSArray *remove);

// 结束指定 App 进程并用 uiopen 拉起；@{@"ok",@"relaunched",@"killed"}
NSDictionary *idh_app_relaunch(NSString *bundleID);
