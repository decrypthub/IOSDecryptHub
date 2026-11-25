#import "idh_session_ipc.h"
#if DH_DEVICE_SESSIONS
#include "../hooks/behavior/hook_network.h"
#endif
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

NSString *const IDHSessionSocketPath = @"/private/var/run/idhjd-v1.sock";
NSString *const IDHSessionStateDirectory = @"/private/var/db/idhjd-v1";
NSString *const IDHSessionModePath = @"/private/var/db/idhjd-v1/enabled";
NSString *const IDHSessionRemotePath = @"/private/var/db/idhjd-v1/listen-remote";

BOOL IDHSessionModeEnabled(void) {
    struct stat info;
    return lstat(IDHSessionModePath.fileSystemRepresentation, &info) == 0 &&
        info.st_uid == 0 && S_ISREG(info.st_mode) && !(info.st_mode & 022);
}

NSString *IDHSessionExecutablePath(pid_t pid) {
    static int (*pathForPID)(int, void *, uint32_t);
    static dispatch_once_t once;
    dispatch_once(&once, ^{ pathForPID = dlsym(RTLD_DEFAULT, "proc_pidpath"); });
    char path[4096] = {0};
    char canonical[PATH_MAX];
    if (!pathForPID || pathForPID(pid, path, sizeof(path)) <= 0 || !realpath(path, canonical)) return nil;
    return [NSString stringWithUTF8String:canonical];
}

void IDHSessionConfigureSocket(int fd) {
    int yes = 1;
    struct timeval timeout = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static BOOL transfer(int fd, void *bytes, size_t length, BOOL sending) {
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 2;
    size_t offset = 0;
    while (offset < length && NSProcessInfo.processInfo.systemUptime < deadline) {
        char *buffer = (char *)bytes + offset;
        ssize_t count = sending ? send(fd, buffer, length - offset, 0) : recv(fd, buffer, length - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        offset += (size_t)count;
    }
    return offset == length;
}

BOOL IDHSessionReadBytes(int fd, void *bytes, size_t length) {
    return transfer(fd, bytes, length, NO);
}

BOOL IDHSessionWriteBytes(int fd, const void *bytes, size_t length) {
    return transfer(fd, (void *)bytes, length, YES);
}

NSDictionary *IDHSessionReadFrame(int fd) {
    uint32_t header;
    if (!IDHSessionReadBytes(fd, &header, sizeof(header))) return nil;
    uint32_t length = ntohl(header);
    if (length == 0 || length > IDH_SESSION_MAX_MESSAGE) return nil;
    NSMutableData *json = [NSMutableData dataWithLength:length];
    if (!IDHSessionReadBytes(fd, json.mutableBytes, length)) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:json options:0 error:NULL];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

BOOL IDHSessionWriteFrame(int fd, NSDictionary *response) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
    if (!json.length || json.length > IDH_SESSION_MAX_MESSAGE) return NO;
    uint32_t header = htonl((uint32_t)json.length);
    return IDHSessionWriteBytes(fd, &header, sizeof(header)) &&
        IDHSessionWriteBytes(fd, json.bytes, json.length);
}

NSDictionary *IDHSessionRequest(NSDictionary *request) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return nil;
#if DH_DEVICE_SESSIONS
    // 会话批次与确认帧属于 Agent 自身的 IPC，不进入目标的网络记录。
    dh_net_mark_internal_fd(fd);
#endif
    IDHSessionConfigureSocket(fd);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, IDHSessionSocketPath.fileSystemRepresentation, sizeof(address.sun_path));
    uid_t uid;
    gid_t gid;
    NSDictionary *response = nil;
    if (connect(fd, (void *)&address, sizeof(address)) == 0 && getpeereid(fd, &uid, &gid) == 0 && uid == 0) {
        NSMutableDictionary *message = [request mutableCopy];
        message[@"protocol"] = @(IDH_SESSION_PROTOCOL);
        if (IDHSessionWriteFrame(fd, message)) response = IDHSessionReadFrame(fd);
    }
    close(fd);
    return response;
}
