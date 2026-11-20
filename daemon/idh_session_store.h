#import <Foundation/Foundation.h>

@interface IDHSessionStore : NSObject
- (instancetype)initWithPath:(NSString *)path;
- (BOOL)save:(NSDictionary *)session events:(NSArray<NSDictionary *> *)events;
- (NSArray<NSDictionary *> *)sessions;
- (NSDictionary *)session:(NSString *)sessionID;
- (NSArray<NSDictionary *> *)eventsForSession:(NSString *)sessionID after:(uint64_t)cursor limit:(NSUInteger)limit;
- (BOOL)prune;
@end
