#import <Foundation/Foundation.h>

@interface IDHSessionService : NSObject
- (instancetype)initWithManagerExecutable:(NSString *)path scopePreferences:(NSString *)scopePath;
@property (nonatomic, copy) NSString *mcpStatus;
@property (nonatomic, readonly, copy) NSString *pairingToken;
- (void)expire;
- (NSDictionary *)handleLocalMessage:(NSDictionary *)message
                          executable:(NSString *)executable pid:(pid_t)pid audit:(NSData *)audit;
- (NSDictionary *)read:(NSString *)tool arguments:(NSDictionary *)arguments;
@end
