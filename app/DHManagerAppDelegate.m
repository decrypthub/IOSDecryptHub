// DHManagerAppDelegate.m — 管理器 App 入口（无 storyboard / 无 scene，纯代码建窗，iOS 14 起可用）

#import <UIKit/UIKit.h>
#import "DHRootViewController.h"
#import "DHStatusViewController.h"

@interface DHManagerAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation DHManagerAppDelegate

- (BOOL)application:(__unused UIApplication *)application
    didFinishLaunchingWithOptions:(__unused NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    DHStatusViewController *status = [[DHStatusViewController alloc] init];
    status.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"设备"
                                                    image:[UIImage systemImageNamed:@"iphone"]
                                                      tag:0];
    DHRootViewController *root = [[DHRootViewController alloc] initWithStyle:UITableViewStyleGrouped];
    root.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"应用"
                                                  image:[UIImage systemImageNamed:@"square.grid.2x2"]
                                                    tag:1];
    UITabBarController *tabs = [[UITabBarController alloc] init];
    tabs.viewControllers = @[
        [[UINavigationController alloc] initWithRootViewController:status],
        [[UINavigationController alloc] initWithRootViewController:root],
    ];
    self.window.rootViewController = tabs;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([DHManagerAppDelegate class]));
    }
}
