// hook_keychain.h
// 直接查看: 在宿主进程内用真实 SecItemCopyMatching 枚举当前有权读到的 Keychain 条目。
// 返回 @{ok, items, statuses, count}; 与 Hook 记录分离, 不产生 hook 事件。
#import <Foundation/Foundation.h>

NSDictionary *dh_keychain_items(NSInteger limit);
