#import <Foundation/Foundation.h>
#import "dh_flow_swift.h"
#include <assert.h>
#include <stdlib.h>
int main(void) {@autoreleasepool {
    NSDictionary *initial=DHSwiftState();assert(![initial[@"ready"] boolValue] && ![initial[@"enabled"] boolValue]);
    NSDictionary *test=DHSwiftSelfTest();
    NSData *data=[NSJSONSerialization dataWithJSONObject:test options:NSJSONWritingPrettyPrinted error:NULL];
    puts([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
    NSMutableArray *diagnostic=[NSMutableArray array];unsigned retained=[DHSwiftState()[@"retained"] unsignedIntValue];
    for(unsigned offset=0;offset<retained;offset+=16)[diagnostic addObjectsFromArray:DHSwiftRead(offset,16)[@"tasks"]];
    [[NSJSONSerialization dataWithJSONObject:diagnostic options:NSJSONWritingPrettyPrinted error:NULL] writeToFile:@"build/swift-task-diagnostic.json" atomically:YES];
    if(![test[@"ok"] boolValue])return 1;
    NSDictionary *page=DHSwiftRead(0,16);NSMutableArray *rows=[NSMutableArray array];unsigned owned=0,completed=0,errors=0;
    for(unsigned offset=0;offset<[page[@"total"] unsignedIntValue];offset+=16) {
        [rows addObjectsFromArray:DHSwiftRead(offset,16)[@"tasks"]];
    }
    for(NSDictionary *r in rows)if([r[@"fixture"] boolValue]) {
        owned++;assert([r[@"identityValidated"] boolValue]);
        assert(strtoull([r[@"completionObservedNs"] UTF8String],NULL,10)>strtoull([r[@"creationInvocationNs"] UTF8String],NULL,10));
        if([r[@"completionConfirmedByOriginalJobReturn"] boolValue])completed++;
        if([r[@"completionHadSwiftError"] boolValue])errors++;
    }
    assert(owned==81 && completed==81 && errors==4);
    assert(![DHSwiftState()[@"activeRecordedTasks"] unsignedIntValue]);
    NSMutableArray *events=[NSMutableArray array];uint64_t after=0;
    for(;;) {
        NSDictionary *batch=DHSwiftEvents(after,64,0);[events addObjectsFromArray:batch[@"events"]];
        if(batch[@"nextAfterSeq"]==NSNull.null)break;after=[batch[@"nextAfterSeq"] unsignedLongLongValue];
    }
    uint64_t last=0;NSMutableDictionary *phases=[NSMutableDictionary dictionary];
    for(NSDictionary *e in events) {
        uint64_t seq=[e[@"schedulerSeq"] unsignedLongLongValue];assert(seq>last);last=seq;
        NSString *task=e[@"swiftTaskId"];if(!task.length)continue;
        if(!phases[task])phases[task]=[NSMutableSet set];[phases[task] addObject:e[@"phase"]];
    }
    unsigned triples=0;
    for(NSSet *set in phases.allValues)if([set containsObject:@"create-return-observed"] && ([set containsObject:@"runtime-completion-entry"] || [set containsObject:@"completion-recovered"]) && [set containsObject:@"completion-confirmed"])triples++;
    assert(triples>=3);
    assert(![DHSwiftState()[@"enabled"] boolValue]);
    assert([DHSwiftConfigure(YES,1,1000)[@"ok"] boolValue]);
    assert(![DHSwiftSelfTest()[@"ok"] boolValue]);
    assert([DHSwiftConfigure(NO,1,1000)[@"ok"] boolValue]);
    puts("PASS actual Swift runtime ABI, seven compiler tasks, Swift errors/cancellation, disabled pending work and strict budget");
    return 0;
}}
