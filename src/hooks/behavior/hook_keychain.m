// hook_keychain.m
// Hook Security.framework 的 Keychain 访问: SecItemCopyMatching / Add / Update / Delete.
//
// Keychain 是 App 最敏感的数据落点(token / 密码 / 设备 ID / refresh token 常存这里)。
// 观测点:
//   - query 字典: kSecClass / Service / Account / AccessGroup / MatchLimit / Return*
//   - CopyMatching 返回的 data(请求 kSecReturnData 时) —— dump 出被读回的原文
//   - Add / Update 写入的 kSecValueData —— dump 出被保存的原文
//
// 边界: Secure Enclave 里的私钥不可导出, 只能观测「被拿去签名/解密」(见 hook_asymmetric),
//       这里不记私钥原文。
//
// 归类: 复用 DHCategorySystem (系统板块), 靠 algorithm 字段区分 (SecItem*)。观测粒度开关 DH_CAP_KEYCHAIN。
// 注入后才加载 Security 的情形同 hook_asymmetric, 不做安装后自检。

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_GENERAL
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// 把 CFString 常量键安全地读成 NSString 值(值可能是 NSString / NSNumber / NSData)。
static NSString *kc_str(NSDictionary *d, CFStringRef key) {
    id v = d[(__bridge NSString *)key];
    if (!v) return nil;
    if ([v isKindOfClass:[NSString class]]) return v;
    if ([v isKindOfClass:[NSNumber class]]) return [(NSNumber *)v stringValue];
    if ([v isKindOfClass:[NSData class]])   return DHHexFromData(v);
    return [v description];
}

// 概括 query / attributes 字典成一行可读描述。
static NSString *kc_summarize(CFDictionaryRef dict) {
    if (!dict) return @"(null)";
    NSDictionary *d = (__bridge NSDictionary *)dict;
    NSMutableArray *parts = [NSMutableArray array];
    NSString *cls = kc_str(d, kSecClass);        if (cls) [parts addObject:[NSString stringWithFormat:@"class=%@", cls]];
    NSString *svc = kc_str(d, kSecAttrService);  if (svc) [parts addObject:[NSString stringWithFormat:@"service=%@", svc]];
    NSString *acc = kc_str(d, kSecAttrAccount);  if (acc) [parts addObject:[NSString stringWithFormat:@"account=%@", acc]];
    NSString *grp = kc_str(d, kSecAttrAccessGroup); if (grp) [parts addObject:[NSString stringWithFormat:@"group=%@", grp]];
    NSString *lim = kc_str(d, kSecMatchLimit);   if (lim) [parts addObject:[NSString stringWithFormat:@"limit=%@", lim]];
    NSMutableArray *ret = [NSMutableArray array];
    if ([d[(__bridge NSString *)kSecReturnData] boolValue])          [ret addObject:@"Data"];
    if ([d[(__bridge NSString *)kSecReturnAttributes] boolValue])    [ret addObject:@"Attributes"];
    if ([d[(__bridge NSString *)kSecReturnRef] boolValue])           [ret addObject:@"Ref"];
    if ([d[(__bridge NSString *)kSecReturnPersistentRef] boolValue]) [ret addObject:@"PersistentRef"];
    if (ret.count) [parts addObject:[NSString stringWithFormat:@"return=%@", [ret componentsJoinedByString:@"|"]]];
    return parts.count ? [parts componentsJoinedByString:@" " ] : @"(空)";
}

// 从 Add/Update 的 attributes 里取被写入的 kSecValueData。
static NSData *kc_value_data(CFDictionaryRef dict) {
    if (!dict) return nil;
    NSDictionary *d = (__bridge NSDictionary *)dict;
    id v = d[(__bridge NSString *)kSecValueData];
    return [v isKindOfClass:[NSData class]] ? v : nil;
}

// 从 CopyMatching 的 result 里提取 data(可能是单个 CFData, 也可能是含 kSecValueData 的字典 / 数组)。
static NSData *kc_extract_result_data(CFTypeRef result) {
    if (!result) return nil;
    CFTypeID tid = CFGetTypeID(result);
    if (tid == CFDataGetTypeID()) {
        return (__bridge NSData *)result;
    }
    if (tid == CFDictionaryGetTypeID()) {
        return kc_value_data((CFDictionaryRef)result);
    }
    if (tid == CFArrayGetTypeID()) {
        NSArray *arr = (__bridge NSArray *)result;
        for (id item in arr) {
            if ([item isKindOfClass:[NSData class]]) return item;
            if ([item isKindOfClass:[NSDictionary class]]) {
                id v = ((NSDictionary *)item)[(__bridge NSString *)kSecValueData];
                if ([v isKindOfClass:[NSData class]]) return v;
            }
        }
    }
    return nil;
}

static void kc_log(NSString *api, NSString *summary, NSData *input, NSData *output, OSStatus st) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryKeychain;   // 独立 Keychain 分类 (被写入/读出的 data 明文在 output)
    e.algorithm = api;
    e.operation = (st == errSecSuccess) ? @"ok" : [NSString stringWithFormat:@"status=%d", (int)st];
    e.detail    = summary;
    e.input     = input;
    e.output    = output;
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ---------- SecItemCopyMatching ----------
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus st = orig_SecItemCopyMatching(query, result);
    if (dh_capture_sub_enabled(DH_CAP_KEYCHAIN)) {
        NSData *out = (st == errSecSuccess && result) ? kc_extract_result_data(*result) : nil;
        kc_log(@"SecItemCopyMatching", kc_summarize(query), nil, out ? [out copy] : nil, st);
    }
    return st;
}

// ---------- SecItemAdd ----------
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus st = orig_SecItemAdd(attributes, result);
    if (dh_capture_sub_enabled(DH_CAP_KEYCHAIN)) {
        NSData *val = kc_value_data(attributes);
        kc_log(@"SecItemAdd", kc_summarize(attributes), val ? [val copy] : nil, nil, st);
    }
    return st;
}

// ---------- SecItemUpdate ----------
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus st = orig_SecItemUpdate(query, attributesToUpdate);
    if (dh_capture_sub_enabled(DH_CAP_KEYCHAIN)) {
        NSData *val = kc_value_data(attributesToUpdate);
        NSString *summary = [NSString stringWithFormat:@"%@ ⇒ %@",
                             kc_summarize(query), kc_summarize(attributesToUpdate)];
        kc_log(@"SecItemUpdate", summary, val ? [val copy] : nil, nil, st);
    }
    return st;
}

// ---------- SecItemDelete ----------
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    OSStatus st = orig_SecItemDelete(query);
    if (dh_capture_sub_enabled(DH_CAP_KEYCHAIN)) {
        kc_log(@"SecItemDelete", kc_summarize(query), nil, nil, st);
    }
    return st;
}

void dh_install_keychain_hooks(void) {
    struct rebinding r[] = {
        {"SecItemCopyMatching", hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemAdd",          hooked_SecItemAdd,          (void **)&orig_SecItemAdd},
        {"SecItemUpdate",       hooked_SecItemUpdate,       (void **)&orig_SecItemUpdate},
        {"SecItemDelete",       hooked_SecItemDelete,       (void **)&orig_SecItemDelete},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 同 hook_asymmetric: Security.framework 可能注入后才加载, 不做安装后自检。
}
