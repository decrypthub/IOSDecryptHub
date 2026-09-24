// hook_spoof_objc.m
// 改机的 ObjC 层: fishhook 改不了 ObjC 方法, 这里用 runtime method swizzle。
//   -[UIDevice systemVersion] / name / identifierForVendor
//   -[NSProcessInfo operatingSystemVersion]  (结构体返回)
//   -[ASIdentifierManager advertisingIdentifier]  (AdSupport, 可能未加载→跳过)
//
// 全部读 dh_spoof_device_*; device 总开关关或对应值为空 → 透传原实现。
// 用 NSClassFromString 定位类, 类不存在(如 mac 上无 UIDevice / 未链接 AdSupport)时安全跳过。
// 边界: 仅本进程内伪装, 跨 App / 服务端画像不受影响(见 dh_spoof 说明)。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "log_store.h"
#define DH_BOARD DH_DIAG_GENERAL
#import "dh_health.h"
#import "dh_spoof.h"
#import "dh_capture.h"

static void spoof_log(NSString *what, NSString *val) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategorySystem;
    e.algorithm = @"spoof-objc";
    e.operation = @"已改机";
    e.detail    = [NSString stringWithFormat:@"%@ → %@", what, val];
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

static BOOL dh_swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

// 关键: 单例(currentDevice/processInfo/sharedManager)实际可能是私有子类, 它自带 IMP。
// 在「名义类」上换 IMP 不影响子类实例的分发, 必须换「单例实例的运行时真实类」。
static Class dh_singleton_class(NSString *clsName, SEL singletonSel) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return nil;
    if (![cls respondsToSelector:singletonSel]) return cls;
    id (*getSingleton)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id inst = getSingleton(cls, singletonSel);
    return inst ? object_getClass(inst) : cls;
}

// ---- UIDevice.systemVersion ----
static NSString *(*orig_systemVersion)(id, SEL);
static NSString *swz_systemVersion(id self, SEL _cmd) {
    NSString *v = dh_spoof_device_value(@"os_version");
    if (v.length) { spoof_log(@"UIDevice.systemVersion", v); return v; }
    return orig_systemVersion(self, _cmd);
}

// ---- UIDevice.name ----
static NSString *(*orig_deviceName)(id, SEL);
static NSString *swz_deviceName(id self, SEL _cmd) {
    NSString *v = dh_spoof_device_value(@"device_name");
    if (v.length) { spoof_log(@"UIDevice.name", v); return v; }
    return orig_deviceName(self, _cmd);
}

// ---- UIDevice.identifierForVendor ----
static NSUUID *(*orig_idfv)(id, SEL);
static NSUUID *swz_idfv(id self, SEL _cmd) {
    NSString *v = dh_spoof_device_value(@"idfv");
    if (v.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:v];
        if (u) { spoof_log(@"UIDevice.identifierForVendor", v); return u; }
    }
    return orig_idfv(self, _cmd);
}

// ---- NSProcessInfo.operatingSystemVersion (struct 返回) ----
static NSOperatingSystemVersion (*orig_osv)(id, SEL);
static NSOperatingSystemVersion swz_osv(id self, SEL _cmd) {
    NSString *v = dh_spoof_device_value(@"os_version");
    if (v.length) {
        NSArray<NSString *> *p = [v componentsSeparatedByString:@"."];
        NSOperatingSystemVersion o = {0, 0, 0};
        if (p.count > 0) o.majorVersion = [p[0] integerValue];
        if (p.count > 1) o.minorVersion = [p[1] integerValue];
        if (p.count > 2) o.patchVersion = [p[2] integerValue];
        spoof_log(@"NSProcessInfo.operatingSystemVersion", v);
        return o;
    }
    return orig_osv(self, _cmd);
}

// ---- ASIdentifierManager.advertisingIdentifier ----
static NSUUID *(*orig_idfa)(id, SEL);
static NSUUID *swz_idfa(id self, SEL _cmd) {
    NSString *v = dh_spoof_device_value(@"idfa");
    if (v.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:v];
        if (u) { spoof_log(@"ASIdentifierManager.advertisingIdentifier", v); return u; }
    }
    return orig_idfa(self, _cmd);
}

// ---- UIApplication.canOpenURL: (越狱 URL scheme 隐藏 + 观测) ----
static void scheme_log(NSString *scheme, NSString *op) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategorySystem;
    e.algorithm = @"canOpenURL";
    e.operation = op;
    e.detail    = [scheme stringByAppendingString:@"://"];
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}
static BOOL (*orig_canOpenURL)(id, SEL, id);
static BOOL swz_canOpenURL(id self, SEL _cmd, id url) {
    NSString *scheme = [url respondsToSelector:@selector(scheme)] ? [url scheme] : nil;
    const char *cs = scheme.UTF8String;
    if (cs && dh_spoof_jb_should_hide_scheme(cs)) {
        scheme_log(scheme, @"已隐藏");
        return NO;   // 隐藏 cydia:// sileo:// filza:// 等越狱 App 探测
    }
    if (scheme.length && dh_capture_sub_enabled(DH_CAP_ENV_PROBE))
        scheme_log(scheme, @"查询");
    return orig_canOpenURL(self, _cmd, url);
}

void dh_install_spoof_objc_hooks(void) {
    BOOL a = NO, b = NO, c = NO, d = NO;
    // 设备伪装默认关闭时「不装」这些 swizzle —— App 的反注入检测会按 IMP 归属判断方法是否被换过
    // (实测中国移动 BCE 的 doSwizzlingHookCheck / methodsForMainImage 就是这类检查), 装了就会被打标记。
    // 关闭时不装, 检测面最小; 真正要用改机时再打开。
    if (dh_spoof_device_on()) {
        // 用单例实例的真实类做 swizzle(处理类簇/私有子类覆盖同名方法的情形)。
        Class uidev = dh_singleton_class(@"UIDevice", @selector(currentDevice));
        a = dh_swizzle(uidev, @selector(systemVersion),       (IMP)swz_systemVersion, (IMP *)&orig_systemVersion);
        dh_swizzle(uidev, @selector(name),                (IMP)swz_deviceName,    (IMP *)&orig_deviceName);
        dh_swizzle(uidev, @selector(identifierForVendor), (IMP)swz_idfv,          (IMP *)&orig_idfv);

        Class pinfo = dh_singleton_class(@"NSProcessInfo", @selector(processInfo));
        b = dh_swizzle(pinfo, @selector(operatingSystemVersion), (IMP)swz_osv, (IMP *)&orig_osv);

        // AdSupport 可能未加载: 类为 nil 时安全跳过(多数用 IDFA 的 App 会早链 AdSupport)。
        Class asim = dh_singleton_class(@"ASIdentifierManager", @selector(sharedManager));
        c = dh_swizzle(asim, @selector(advertisingIdentifier), (IMP)swz_idfa, (IMP *)&orig_idfa);
    }

    // UIApplication.canOpenURL: 越狱 URL scheme 隐藏 —— 只在 jb 开关打开时安装。
    if (dh_spoof_jb_on()) {
        Class uiapp = dh_singleton_class(@"UIApplication", @selector(sharedApplication));
        d = dh_swizzle(uiapp, @selector(canOpenURL:), (IMP)swz_canOpenURL, (IMP *)&orig_canOpenURL);
    }

    char dbg[192];
    snprintf(dbg, sizeof(dbg),
             "spoof-objc swizzle(device=%d jb=%d): UIDevice=%d NSProcessInfo=%d ASIdentifierManager=%d canOpenURL=%d",
             dh_spoof_device_on(), dh_spoof_jb_on(), a, b, c, d);
    dh_diag_append(DH_DIAG_GENERAL, "INFO", dbg);
}
