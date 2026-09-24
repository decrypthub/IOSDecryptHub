// hook_file.m
// 文件操作监控: open / write / unlink / rename (+ close 仅清理 fd 映射).
// 过滤系统噪音: 只记沙盒路径(Documents/Library/tmp/Caches), 跳过 /System /usr .framework .dylib.
// write 通过 open 建立的 fd->path 映射定位文件名 —— socket/stderr 等不在映射里, 自动被跳过.
//
// 关键: dh_in_hook 递归保护. 系统的 os_log / locale / bundle 解析内部会调 open, 而我们的记录
// 路径(NSDateFormatter 首次初始化等)又会触发这些 → hooked_open 递归死锁. 置标志期间放行.

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <stdarg.h>
#import <errno.h>
#import <sys/mman.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_FILE
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"
#import "dh_spoof.h"

static BOOL dh_is_app_file(const char *p) {
    if (!p || !*p) return NO;
    if (strstr(p, "/System/") || strstr(p, "/usr/") || strstr(p, ".framework") ||
        strstr(p, ".dylib")   || strstr(p, "/var/db/")) return NO;
    // 只认 App 自己的沙盒数据容器(真机 /var/mobile/Containers/Data/Application/...;
    // 模拟器 .../CoreSimulator/Devices/.../data/Containers/Data/Application/...) —— 这样系统级
    // /Library/Preferences/com.apple.*.plist 等不会混进来。/Documents/ /tmp/ 兜底。
    if (strstr(p, "/Containers/Data/Application/")) return YES;
    return (strstr(p, "/Documents/") || strstr(p, "/tmp/")) ? YES : NO;
}

static NSMutableDictionary<NSNumber *, NSString *> *gFdPath = nil;
static dispatch_semaphore_t gFdLock = nil;
static void file_state_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ gFdPath = [NSMutableDictionary dictionary]; gFdLock = dispatch_semaphore_create(1); });
}

static NSString *flags_desc(int flags) {
    NSMutableArray *a = [NSMutableArray array];
    int acc = flags & O_ACCMODE;
    [a addObject:(acc == O_RDONLY ? @"读" : acc == O_WRONLY ? @"写" : @"读写")];
    if (flags & O_CREAT)  [a addObject:@"创建"];
    if (flags & O_APPEND) [a addObject:@"追加"];
    if (flags & O_TRUNC)  [a addObject:@"截断"];
    return [a componentsJoinedByString:@"|"];
}

static void file_log(NSString *op, const char *path, NSString *detail) {
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryFile;
    e.algorithm = op;
    e.operation = detail ?: @"";
    e.detail    = path ? [NSString stringWithUTF8String:path] : nil;
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ---------- open ----------
static int (*orig_open)(const char *, int, ...);
static int hooked_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    // 越狱绕过: 命中越狱清单的路径直接返回不存在(open 已被本文件占用, 故隐藏逻辑内联于此,
    // 不在 hook_env 重复 rebind)。仅非递归路径生效, 防伪装自身记录/写盘触发的 open。
    if (!dh_in_hook && dh_spoof_jb_should_hide_path(path)) {
        dh_in_hook = 1;
        DHLogEntry *e = [DHLogEntry new];
        e.category = DHCategorySystem; e.algorithm = @"open"; e.operation = @"已隐藏";
        e.detail = [NSString stringWithUTF8String:path] ?: @"?";
        e.timestamp = DHTimestampNow(); e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
        errno = ENOENT;
        return -1;
    }
    int fd = orig_open(path, flags, mode);
    if (!dh_in_hook && fd >= 0 && dh_is_app_file(path)) {
        dh_in_hook = 1;
        file_state_init();
        dispatch_semaphore_wait(gFdLock, DISPATCH_TIME_FOREVER);
        gFdPath[@(fd)] = [NSString stringWithUTF8String:path] ?: @"?";   // fd 映射始终维护(write 需要)
        dispatch_semaphore_signal(gFdLock);
        if (dh_capture_sub_enabled(DH_CAP_FILE_OPEN)) file_log(@"open", path, flags_desc(flags));
        dh_in_hook = 0;
    }
    return fd;
}

// ---------- write (只记被跟踪的沙盒文件 fd) ----------
static ssize_t (*orig_write)(int, const void *, size_t);
static ssize_t hooked_write(int fd, const void *buf, size_t n) {
    ssize_t r = orig_write(fd, buf, n);
    if (!dh_in_hook && gFdPath) {
        dh_in_hook = 1;
        dispatch_semaphore_wait(gFdLock, DISPATCH_TIME_FOREVER);
        NSString *path = gFdPath[@(fd)];
        dispatch_semaphore_signal(gFdLock);
        if (path && r > 0 && dh_capture_sub_enabled(DH_CAP_FILE_WRITE)) {
            DHLogEntry *e = [DHLogEntry new];
            e.category  = DHCategoryFile;
            e.algorithm = @"write";
            e.operation = [NSString stringWithFormat:@"%zd bytes", r];
            e.detail    = path;
            e.timestamp = DHTimestampNow();
            e.callStack = DHCallStackFiltered();
            [[DHLogStore shared] append:e];
        }
        dh_in_hook = 0;
    }
    return r;
}

// ---------- read / pread (只 dump 被跟踪的沙盒文件 fd 读出的内容) ----------
// read 超高频: 先查 gFdPath 命中 (未跟踪 fd 直接跳过), 再决定是否 dump。单条内容上限
// 1MB, 防个别巨读撑爆内存/UI。
#define DH_READ_DUMP_CAP (1u << 20)

static void file_log_read(int fd, const void *buf, ssize_t r) {
    if (dh_in_hook || !gFdPath || r <= 0) return;
    dh_in_hook = 1;
    dispatch_semaphore_wait(gFdLock, DISPATCH_TIME_FOREVER);
    NSString *path = gFdPath[@(fd)];
    dispatch_semaphore_signal(gFdLock);
    if (path && dh_capture_sub_enabled(DH_CAP_FILE_READ)) {
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryFile;
        e.algorithm = @"read";
        e.operation = [NSString stringWithFormat:@"%zd bytes", r];
        e.detail    = path;
        NSUInteger cap = (NSUInteger)r < DH_READ_DUMP_CAP ? (NSUInteger)r : DH_READ_DUMP_CAP;
        if (buf && cap) e.input = [NSData dataWithBytes:buf length:cap];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    }
    dh_in_hook = 0;
}

static ssize_t (*orig_read)(int, void *, size_t);
static ssize_t hooked_read(int fd, void *buf, size_t n) {
    ssize_t r = orig_read(fd, buf, n);
    file_log_read(fd, buf, r);
    return r;
}

static ssize_t (*orig_pread)(int, void *, size_t, off_t);
static ssize_t hooked_pread(int fd, void *buf, size_t n, off_t off) {
    ssize_t r = orig_pread(fd, buf, n, off);
    file_log_read(fd, buf, r);
    return r;
}

// ---------- mmap (映射已跟踪 fd 时记路径/长度/offset; 内容惰性分页, 此处只记元数据) ----------
static void *(*orig_mmap)(void *, size_t, int, int, int, off_t);
static void *hooked_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    void *p = orig_mmap(addr, len, prot, flags, fd, off);
    if (!dh_in_hook && gFdPath && fd >= 0 && p != MAP_FAILED) {
        dh_in_hook = 1;
        dispatch_semaphore_wait(gFdLock, DISPATCH_TIME_FOREVER);
        NSString *path = gFdPath[@(fd)];
        dispatch_semaphore_signal(gFdLock);
        if (path && dh_capture_sub_enabled(DH_CAP_FILE_MMAP)) {
            file_log(@"mmap", path.fileSystemRepresentation,
                     [NSString stringWithFormat:@"%zu bytes @ off %lld", len, (long long)off]);
        }
        dh_in_hook = 0;
    }
    return p;
}

// ---------- close (清理 fd 映射, 防 fd 复用误配; 清理不会递归, 无需 dh_in_hook) ----------
static int (*orig_close)(int);
static int hooked_close(int fd) {
    if (gFdPath) {
        dispatch_semaphore_wait(gFdLock, DISPATCH_TIME_FOREVER);
        [gFdPath removeObjectForKey:@(fd)];
        dispatch_semaphore_signal(gFdLock);
    }
    return orig_close(fd);
}

// ---------- unlink / rename ----------
static int (*orig_unlink)(const char *);
static int hooked_unlink(const char *path) {
    int r = orig_unlink(path);
    if (!dh_in_hook && dh_is_app_file(path) && dh_capture_sub_enabled(DH_CAP_FILE_UNLINK)) {
        dh_in_hook = 1; file_log(@"unlink", path, @"删除"); dh_in_hook = 0;
    }
    return r;
}

static int (*orig_rename)(const char *, const char *);
static int hooked_rename(const char *from, const char *to) {
    int r = orig_rename(from, to);
    if (!dh_in_hook && (dh_is_app_file(from) || dh_is_app_file(to)) && dh_capture_sub_enabled(DH_CAP_FILE_RENAME)) {
        dh_in_hook = 1;
        file_log(@"rename", to, [NSString stringWithFormat:@"%s -> %s", from ?: "?", to ?: "?"]);
        dh_in_hook = 0;
    }
    return r;
}

void dh_install_file_hooks(void) {
    struct rebinding r[] = {
        {"open",   hooked_open,   (void **)&orig_open},
        {"write",  hooked_write,  (void **)&orig_write},
        {"read",   hooked_read,   (void **)&orig_read},
        {"pread",  hooked_pread,  (void **)&orig_pread},
        {"mmap",   hooked_mmap,   (void **)&orig_mmap},
        {"close",  hooked_close,  (void **)&orig_close},
        {"unlink", hooked_unlink, (void **)&orig_unlink},
        {"rename", hooked_rename, (void **)&orig_rename},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_FILE, r[k].name);
}
