#import <Foundation/Foundation.h>

@interface IDHSessionStore : NSObject
- (instancetype)initWithPath:(NSString *)path;
- (BOOL)appendEvents:(NSArray<NSDictionary *> *)events
           forBundle:(NSString *)bundle
           maxPerApp:(NSUInteger)maxPerApp;
- (NSArray<NSDictionary *> *)appSummaries;
- (NSDictionary *)appSummaryForBundle:(NSString *)bundle;
- (NSDictionary *)queryEventsForBundle:(NSString *)bundle
                            categories:(NSArray<NSNumber *> *)categories
                                 after:(NSNumber *)after
                                before:(NSNumber *)before
                                 limit:(NSUInteger)limit;
- (NSDictionary *)clearEventsForBundle:(NSString *)bundle;
@end
