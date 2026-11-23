#import <Foundation/Foundation.h>
#include <sys/types.h>

#define IDH_SESSION_PROTOCOL 1
#define IDH_SESSION_PORT 8088
#define IDH_SESSION_MAX_BATCH 64
#define IDH_SESSION_PENDING_CAPACITY (8 * IDH_SESSION_MAX_BATCH)
#define IDH_SESSION_MAX_MESSAGE (64 * 1024)

extern NSString *const IDHSessionSocketPath;
extern NSString *const IDHSessionStateDirectory;
extern NSString *const IDHSessionModePath;
extern NSString *const IDHSessionRemotePath;

BOOL IDHSessionModeEnabled(void);
NSString *IDHSessionExecutablePath(pid_t pid);
NSDictionary *IDHSessionRequest(NSDictionary *request);
NSDictionary *IDHSessionReadFrame(int fd);
BOOL IDHSessionWriteFrame(int fd, NSDictionary *response);
BOOL IDHSessionReadBytes(int fd, void *bytes, size_t length);
BOOL IDHSessionWriteBytes(int fd, const void *bytes, size_t length);
void IDHSessionConfigureSocket(int fd);
