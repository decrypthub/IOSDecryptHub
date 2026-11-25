#import <Foundation/Foundation.h>

@interface IDHSessionService : NSObject
- (instancetype)initWithManagerExecutable:(NSString *)path scopePreferences:(NSString *)scopePath;
@property (nonatomic, copy) NSString *mcpStatus;
- (void)expire;
- (NSDictionary *)health;
- (NSDictionary *)settingsSnapshot;
- (NSDictionary *)updateSettings:(NSDictionary *)request;
- (NSDictionary *)processIdentity:(NSDictionary *)arguments;
- (NSDictionary *)forwardTool:(NSString *)name
                    arguments:(NSDictionary *)arguments
                        queue:(dispatch_queue_t)queue;
- (NSDictionary *)handleLocalMessage:(NSDictionary *)message
                          executable:(NSString *)executable pid:(pid_t)pid audit:(NSData *)audit;
- (NSDictionary *)read:(NSString *)tool arguments:(NSDictionary *)arguments;
@end
