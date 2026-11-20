#import <Foundation/Foundation.h>
@class IDHSessionService;

void IDHSessionHandleHTTP(int fd, IDHSessionService *service, dispatch_queue_t stateQueue);
