// hook_system.m
// 系统: hook dlopen 记录运行时载入了哪些动态库; hook dlsym 记录/重定向动态符号解析.
//
// dlsym 路径: p = dlsym(h, "CCCrypt"); p(...); 不经过 import slot, 但 dlsym 本身多为导入符号,
// 可在 dlsym("CCCrypt") 时返回我们的 hooked_CCCrypt(见 dh_dlsym_redirect).
// 注入前已缓存的函数指针无法追溯.
//
// dh_in_hook: 记录用的 backtrace_symbols 可能内部 dlopen/dlsym → 递归, 置标志期间放行.

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_SYS
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    void *h = orig_dlopen(path, mode);
    if (!dh_in_hook && path && *path && dh_capture_sub_enabled(DH_CAP_SYS_DLOPEN)) {
        dh_in_hook = 1;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategorySystem;
        e.algorithm = @"dlopen";
        e.operation = h ? @"loaded" : @"failed";
        e.detail    = [NSString stringWithUTF8String:path];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return h;
}

static NSString *dh_dlsym_handle_desc(void *handle) {
    if (handle == RTLD_DEFAULT) return @"RTLD_DEFAULT";
    if (handle == RTLD_NEXT)    return @"RTLD_NEXT";
    if (handle == RTLD_SELF)     return @"RTLD_SELF";
#if defined(RTLD_MAIN_ONLY)
    if (handle == RTLD_MAIN_ONLY) return @"RTLD_MAIN_ONLY";
#endif
    if (!handle) return @"NULL";
    const char *path = NULL;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if ((void *)mh == handle) {
            path = _dyld_get_image_name(i);
            break;
        }
    }
    if (path) return [NSString stringWithUTF8String:path];
    return [NSString stringWithFormat:@"handle=%p", handle];
}

// OpenSSL 3 初始化/provider load 会 dlsym 自身符号; 若重定向到 wrapper 会崩.
static int dh_dlsym_skip_redirect(void) {
    Dl_info info;
    void *ra = __builtin_return_address(0);
    if (!ra || dladdr(ra, &info) == 0 || !info.dli_fname) return 0;
    const char *f = info.dli_fname;
    return (strstr(f, "libcrypto") || strstr(f, "libssl")) ? 1 : 0;
}

static void *(*orig_dlsym)(void *, const char *);
static void *hooked_dlsym(void *handle, const char *symbol) {
    void *real = orig_dlsym(handle, symbol);
    void *redirect = (!dh_in_hook && !dh_dlsym_skip_redirect() && symbol)
        ? dh_dlsym_redirect_lookup(symbol) : NULL;
    void *out = redirect ? redirect : real;

    if (!dh_in_hook && symbol && *symbol && dh_capture_sub_enabled(DH_CAP_SYS_DLSYM)) {
        dh_in_hook = 1;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategorySystem;
        e.algorithm = @"dlsym";
        if (redirect)      e.operation = @"redirect";
        else if (real)     e.operation = @"resolved";
        else               e.operation = @"failed";
        NSMutableString *detail = [NSMutableString stringWithFormat:@"%@ | %s",
                                   dh_dlsym_handle_desc(handle), symbol];
        if (redirect) [detail appendFormat:@" -> hook %p", redirect];
        else if (real) [detail appendFormat:@" -> %p", real];
        e.detail    = detail;
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return out;
}

void dh_install_system_hooks(void) {
    struct rebinding r[] = {
        {"dlopen", hooked_dlopen, (void **)&orig_dlopen},
        {"dlsym",  hooked_dlsym,  (void **)&orig_dlsym},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_SYS, r[k].name);
}
