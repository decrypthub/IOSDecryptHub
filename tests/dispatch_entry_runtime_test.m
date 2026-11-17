#import <Foundation/Foundation.h>
#import "dh_flow_dispatch.h"
#import "dh_flow.h"
#include <assert.h>
int main(void) {@autoreleasepool {
    NSDictionary *before=DHDispatchEntryState();assert(![before[@"ready"] boolValue] && ![before[@"enabled"] boolValue]);
    NSDictionary *test=DHDispatchEntrySelfTest();
    puts([[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:test options:NSJSONWritingPrettyPrinted error:NULL] encoding:NSUTF8StringEncoding].UTF8String);
    if(![test[@"ok"] boolValue]){
        puts([[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:DHDispatchEntryState() options:NSJSONWritingPrettyPrinted error:NULL] encoding:NSUTF8StringEncoding].UTF8String);
        return 1;
    }
    assert([test[@"passed"] count]==4 && [test[@"tasks"] count]==2);
    NSDictionary *after=DHDispatchEntryState();assert([after[@"ready"] boolValue] && ![after[@"enabled"] boolValue] && [after[@"retainedUntilRestart"] boolValue] && ![after[@"probeMismatches"] unsignedLongLongValue]);
    assert([DHDispatchEntryConfigure(YES)[@"ok"] boolValue]);
    assert([DHDispatchEntryConfigure(NO)[@"ok"] boolValue]);
    assert(![DHFlowState()[@"pendingOrRunning"] unsignedIntValue]);
    puts("PASS owned private dispatcher ABI, original context/repeats, preexisting source execution and disable");
    return 0;
}}
