#import "idh_session_http.h"
#import "idh_session_service.h"
#import "../src/session/idh_session_ipc.h"
#import "../src/dh_shared.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int unixListener(void) {
    struct stat info;
    const char *path = IDHSessionSocketPath.fileSystemRepresentation;
    if (lstat(path, &info) == 0 && (!S_ISSOCK(info.st_mode) || info.st_uid != 0 || unlink(path))) {
        errno = EPERM;
        return -1;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0 && bind(fd, (void *)&address, sizeof(address)) == 0 && chmod(path, 0666) == 0 && listen(fd, 8) == 0)
        return fd;
    if (fd >= 0) close(fd);
    return -1;
}

static int httpListener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(IDH_SESSION_PORT),
                                  .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (!bind(fd, (void *)&address, sizeof(address)) && !listen(fd, 8)) return fd;
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

static void handleLocal(int fd, IDHSessionService *service, dispatch_queue_t stateQueue) {
    pid_t pid = 0;
    uid_t uid;
    gid_t gid;
    socklen_t size = sizeof(pid);
    uint32_t audit[8] = {0};
    socklen_t auditSize = sizeof(audit);
    if (getpeereid(fd, &uid, &gid) || uid != 501 ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) || pid <= 1 ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &audit, &auditSize) || auditSize != sizeof(audit) ||
        audit[5] != (uint32_t)pid) return;
    NSString *executable = IDHSessionExecutablePath(pid);
    NSDictionary *message = executable ? IDHSessionReadFrame(fd) : nil;
    if (!message) return;
    NSData *credential = [NSData dataWithBytes:audit length:sizeof(audit)];
    __block NSDictionary *response;
    dispatch_sync(stateQueue, ^{ response = [service handleLocalMessage:message executable:executable pid:pid audit:credential]; });
    IDHSessionWriteFrame(fd, response);
}

static dispatch_source_t serve(int fd, void (^handler)(int)) {
    fcntl(fd, F_SETFL, O_NONBLOCK);
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    dispatch_semaphore_t workers = dispatch_semaphore_create(8);
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, queue);
    dispatch_source_set_cancel_handler(source, ^{ close(fd); });
    dispatch_source_set_event_handler(source, ^{
        int client = accept(fd, NULL, NULL);
        if (client < 0) return;
        if (dispatch_semaphore_wait(workers, DISPATCH_TIME_NOW)) { close(client); return; }
        fcntl(client, F_SETFL, 0);
        IDHSessionConfigureSocket(client);
        dispatch_async(queue, ^{
            @autoreleasepool { handler(client); }
            close(client);
            dispatch_semaphore_signal(workers);
        });
    });
    dispatch_resume(source);
    return source;
}

int main(void) {
    @autoreleasepool {
        if (geteuid() != 0) return 1;
        umask(0077);
        const char *base = IDHSessionStateDirectory.fileSystemRepresentation;
        struct stat info;
        if ((mkdir(base, 0755) && errno != EEXIST) || lstat(base, &info) ||
            !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022) || chmod(base, 0755)) {
            NSLog(@"idhjd: unable to open the session directory: %s", strerror(errno));
            return 1;
        }
        NSString *lockPath = [IDHSessionStateDirectory stringByAppendingPathComponent:@"service.lock"];
        int serviceLock = open(lockPath.fileSystemRepresentation, O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_WRONLY, 0600);
        if (serviceLock < 0 || flock(serviceLock, LOCK_EX | LOCK_NB)) return 1;
        NSString *prefix = IDHSessionExecutablePath(getpid());
        for (int level = 0; level < 4; level++) prefix = prefix.stringByDeletingLastPathComponent;
        NSString *manager = [prefix stringByAppendingPathComponent:@"Applications/IOSDecryptHubManager.app/IOSDecryptHubManager"];
        char canonical[PATH_MAX];
        if (!manager || !realpath(manager.fileSystemRepresentation, canonical)) {
            NSLog(@"idhjd: installed Manager executable is unavailable");
            return 1;
        }
        // RootHide Manager's home is mobile inside the installed bootstrap.
        NSString *scope = DH_LOADER_PREFS;
#if IDH_ROOT_HIDE
        scope = [prefix stringByAppendingPathComponent:DH_LOADER_PREFS];
#endif
        IDHSessionService *service = [[IDHSessionService alloc] initWithManagerExecutable:@(canonical)
                                                                      scopePreferences:scope];
        if (!service) return 1;
        int fd = unixListener();
        if (fd < 0) { NSLog(@"idhjd: local listener failed: %s", strerror(errno)); return 1; }
        dispatch_queue_t state = dispatch_queue_create("com.iosdecrypthub.session.state", DISPATCH_QUEUE_SERIAL);
        dispatch_source_t local = serve(fd, ^(int client) { handleLocal(client, service, state); });
        __block dispatch_source_t http;
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, state);
        dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, NSEC_PER_SEC, NSEC_PER_SEC / 10);
        dispatch_source_set_event_handler(timer, ^{
            @autoreleasepool {
                [service expire];
                if (!http) {
                    int listener = httpListener();
                    if (listener >= 0) http = serve(listener, ^(int client) { IDHSessionHandleHTTP(client, service, state); });
                    service.mcpStatus = http ? @"listening" : (errno == EADDRINUSE ? @"port_busy" : @"listen_failed");
                }
            }
        });
        dispatch_resume(timer);
        __attribute__((objc_precise_lifetime)) NSArray *listeners = @[local, timer];
        (void)listeners;
        NSLog(@"idhjd: local IPC ready");
        dispatch_main();
    }
}
