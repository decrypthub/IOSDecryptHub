// hook_env.m
// 环境探测观测 + 越狱检测绕过 + 改机(sysctl/uname 层)。
//
// 两类能力(职责分离见 dh_spoof / dh_capture):
//   观测 (DH_CAP_ENV_PROBE, 默认开): 记录 App 在探测什么环境(调试状态/设备指纹/敏感文件)。
//   改写 (按 dh_spoof 开关生效):
//     - 越狱绕过: stat/lstat/access/faccessat/fstatat 命中越狱清单 → errno=ENOENT;
//                 getenv("DYLD_INSERT_LIBRARIES") → 隐藏注入痕迹。
//     - 反调试:   ptrace(PT_DENY_ATTACH) 空转; sysctl(KERN_PROC) 清 P_TRACED; csops 清 CS_DEBUGGED。
//     - 改机:     sysctlbyname(hw.machine/hw.model) 改写返回; uname 改写 machine。
//
// open 的越狱隐藏不在此处(open 已被 hook_file 占用, fishhook 一符号只挂一次),
// 见 hook_file.m 的 hooked_open 里对 dh_spoof_jb_should_hide_path 的调用。
//
// 边界: 仅目标 App 进程内伪装, 非系统级真实改机。sysctlbyname 改写受调用方缓冲区大小约束(仅在能容纳时覆盖)。

#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_GENERAL
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_spoof.h"
#import "dh_dlsym_redirect.h"

// 私有/未公开声明
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define DH_CS_OPS_STATUS 0
#define DH_CS_DEBUGGED   0x10000000
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

static void env_log(NSString *api, NSString *op, NSString *detail) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategorySystem;   // 复用系统板块, 靠 algorithm 区分
    e.algorithm = api;
    e.operation = op;
    e.detail    = detail;
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ================= 反调试: ptrace =================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH && dh_spoof_anti_debug_on()) {
        env_log(@"ptrace", @"已空转", @"PT_DENY_ATTACH 被拦截(反调试绕过)");
        return 0;   // 不透传, 阻止 App 自我拒绝调试
    }
    if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE))
        env_log(@"ptrace", [NSString stringWithFormat:@"request=%d", request], nil);
    return orig_ptrace(request, pid, addr, data);
}

// ================= 反调试: csops =================
static int (*orig_csops)(pid_t, unsigned int, void *, size_t);
static int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int r = orig_csops(pid, ops, useraddr, usersize);
    if (ops == DH_CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        if (dh_spoof_anti_debug_on() && (*flags & DH_CS_DEBUGGED)) {
            *flags &= ~DH_CS_DEBUGGED;
            env_log(@"csops", @"已清 CS_DEBUGGED", @"反调试绕过");
        } else if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE)) {
            env_log(@"csops", [NSString stringWithFormat:@"ops=%u flags=0x%x", ops, *flags], nil);
        }
    }
    return r;
}

// ================= 反调试/观测: sysctl =================
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (r == 0 && name && namelen >= 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        if (dh_spoof_anti_debug_on() && (kp->kp_proc.p_flag & P_TRACED)) {
            kp->kp_proc.p_flag &= ~P_TRACED;
            env_log(@"sysctl", @"已清 P_TRACED", @"KERN_PROC 反调试绕过");
        } else if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE)) {
            env_log(@"sysctl", @"KERN_PROC 查询", @"调试状态探测");
        }
    } else if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE) && name && namelen >= 2) {
        env_log(@"sysctl", [NSString stringWithFormat:@"mib=%d.%d", name[0], name[1]], nil);
    }
    return r;
}

// ================= 改机/观测: sysctlbyname =================
// 把伪造字符串写回 oldp。cap = 调用方缓冲区容量(orig 调用「前」的 *oldlenp), 仅当能容纳才覆盖,
// 避免溢出。注意不能用 orig「后」的 *oldlenp —— 那已被缩成真实值长度(如 "arm64"=6)。
static void env_spoof_str(void *oldp, size_t *oldlenp, size_t cap, NSString *val, NSString *nm) {
    if (!oldp || !oldlenp || val.length == 0) return;
    const char *s = val.UTF8String;
    size_t need = strlen(s) + 1;
    if (need <= cap) {
        memcpy(oldp, s, need);
        *oldlenp = need;
        env_log(@"sysctlbyname", @"已改机", [NSString stringWithFormat:@"%@ → %@", nm, val]);
    }
}
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    size_t cap = oldlenp ? *oldlenp : 0;   // 调用方缓冲区容量, 必须在 orig 前取
    int r = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (r == 0 && name) {
        if (dh_spoof_device_on()) {
            if (strcmp(name, "hw.machine") == 0)
                env_spoof_str(oldp, oldlenp, cap, dh_spoof_device_value(@"hw_machine"), @"hw.machine");
            else if (strcmp(name, "hw.model") == 0)
                env_spoof_str(oldp, oldlenp, cap, dh_spoof_device_value(@"hw_model"), @"hw.model");
        }
        if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE))
            env_log(@"sysctlbyname", [NSString stringWithUTF8String:name] ?: @"?", nil);
    }
    return r;
}

// ================= 改机/观测: uname =================
static int (*orig_uname)(struct utsname *);
static int hooked_uname(struct utsname *buf) {
    int r = orig_uname(buf);
    if (r == 0 && buf) {
        if (dh_spoof_device_on()) {
            NSString *m = dh_spoof_device_value(@"hw_machine");
            if (m.length) {
                strlcpy(buf->machine, m.UTF8String, sizeof(buf->machine));
                env_log(@"uname", @"已改机", [NSString stringWithFormat:@"machine → %@", m]);
            }
        }
        if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE))
            env_log(@"uname", @"查询", nil);
    }
    return r;
}

// ================= 越狱绕过/观测: getenv =================
// 只对 DYLD 相关键动作(隐藏注入痕迹), 避免 hook 高频 getenv 造成刷屏/递归。
static char *(*orig_getenv)(const char *);
static char *hooked_getenv(const char *name) {
    if (name && strstr(name, "DYLD")) {
        if (dh_spoof_jb_on()) {
            env_log(@"getenv", @"已隐藏", [NSString stringWithFormat:@"%s → (null)", name]);
            return NULL;   // 隐藏 DYLD_INSERT_LIBRARIES 等注入痕迹
        }
        if (dh_capture_sub_enabled(DH_CAP_ENV_PROBE))
            env_log(@"getenv", [NSString stringWithUTF8String:name] ?: @"?", nil);
    }
    return orig_getenv(name);
}

// ================= 越狱绕过: stat / lstat / access / faccessat / fstatat =================
// 高频 API: 只在命中越狱清单(即需隐藏)时记录, 不记每次普通探测, 避免刷屏。
static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        env_log(@"stat", @"已隐藏", [NSString stringWithUTF8String:path] ?: @"?");
        errno = ENOENT; return -1;
    }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        env_log(@"lstat", @"已隐藏", [NSString stringWithUTF8String:path] ?: @"?");
        errno = ENOENT; return -1;
    }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        env_log(@"access", @"已隐藏", [NSString stringWithUTF8String:path] ?: @"?");
        errno = ENOENT; return -1;
    }
    return orig_access(path, mode);
}

static int (*orig_faccessat)(int, const char *, int, int);
static int hooked_faccessat(int dirfd, const char *path, int mode, int flag) {
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        env_log(@"faccessat", @"已隐藏", [NSString stringWithUTF8String:path] ?: @"?");
        errno = ENOENT; return -1;
    }
    return orig_faccessat(dirfd, path, mode, flag);
}

static int (*orig_fstatat)(int, const char *, struct stat *, int);
static int hooked_fstatat(int dirfd, const char *path, struct stat *buf, int flag) {
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        env_log(@"fstatat", @"已隐藏", [NSString stringWithUTF8String:path] ?: @"?");
        errno = ENOENT; return -1;
    }
    return orig_fstatat(dirfd, path, buf, flag);
}

void dh_install_env_hooks(void) {
    struct rebinding r[] = {
        {"ptrace",        hooked_ptrace,        (void **)&orig_ptrace},
        {"csops",         hooked_csops,         (void **)&orig_csops},
        {"sysctl",        hooked_sysctl,        (void **)&orig_sysctl},
        {"sysctlbyname",  hooked_sysctlbyname,  (void **)&orig_sysctlbyname},
        {"uname",         hooked_uname,         (void **)&orig_uname},
        {"getenv",        hooked_getenv,        (void **)&orig_getenv},
        {"stat",          hooked_stat,          (void **)&orig_stat},
        {"lstat",         hooked_lstat,         (void **)&orig_lstat},
        {"access",        hooked_access,        (void **)&orig_access},
        {"faccessat",     hooked_faccessat,     (void **)&orig_faccessat},
        {"fstatat",       hooked_fstatat,       (void **)&orig_fstatat},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
}
