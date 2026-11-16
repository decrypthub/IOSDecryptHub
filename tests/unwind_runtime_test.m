#import <Foundation/Foundation.h>
#import "dh_thunk.h"
#import "dh_unwind.h"
#import "log_store.h"
#include <stdio.h>
static NSString *insidePost;
@interface IDHUnwindFixture:NSObject
- (uint64_t)inner:(uint64_t)n;
- (uint64_t)outer:(uint64_t)n;
@end
@implementation IDHUnwindFixture
- (uint64_t)inner:(uint64_t)n {return n+1;}
- (uint64_t)outer:(uint64_t)n {insidePost=DHCallStackFiltered();return [self inner:n]*3;}
@end
__attribute__((noinline,optnone)) uint64_t IDHUnwindDriver(IDHUnwindFixture *f) {return [f outer:3]+9;}
int main(void) {@autoreleasepool {
    [DHLogStore shared].paused=NO;[[DHLogStore shared] setPaused:NO forCategory:DHCategoryOther];
    dh_hook_options options;dh_thunk_options_default(&options);options.fixed_abi=1;options.capture_return=1;
    char error[512]={0};
    for (NSString *selector in @[@"inner:",@"outer:"])
        if (dh_thunk_install_configured(DH_HOOK_METHOD,"IDHUnwindFixture",selector.UTF8String,0,0,NULL,&options,error,sizeof(error))<0) {fprintf(stderr,"%s",error);return 1;}
    if (IDHUnwindDriver([IDHUnwindFixture new])!=21) return 2;
    NSDictionary *current=DHResolveStack(DHDecodeRawStack(insidePost),YES);
    if (![current[@"complete"] boolValue] || [current[@"frames"] count]<5) return 5;
    NSDictionary *cut=DHDecodeRawStack(@"IDH_NATIVE_STACK_V1 3 1 0 0\n1 2\n");
    if ([cut[@"complete"] boolValue] || ![cut[@"truncated"] boolValue]) return 6;
    for (DHLogEntry *event in [[DHLogStore shared] snapshot]) {
        if (![event.operation containsString:@"inner:"] || ![event.eventContext[@"phase"] isEqual:@"entry"]) continue;
        NSDictionary *stack=DHResolveStack(event.eventPayload[@"stack"],YES);
        NSData *json=[NSJSONSerialization dataWithJSONObject:stack options:0 error:NULL];
        fwrite(json.bytes,1,json.length,stdout);putchar('\n');
        BOOL driver=NO,bridge=NO;
        for (NSDictionary *frame in stack[@"frames"]) {
            driver|=[frame[@"symbol"] containsString:@"IDHUnwindDriver"];
            bridge|=[frame[@"symbol"] containsString:@"dh_thunk_trampoline"];
        }
        if (![stack[@"complete"] boolValue] || !driver || !bridge || [stack[@"frames"] count]<5) return 3;
        puts("PASS: nested post hooks preserve unwind through the outer bridge to the original driver/root");return 0;
    }
    return 4;
}}
