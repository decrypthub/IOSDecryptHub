#import <Foundation/Foundation.h>
#import "dh_flow_operations.h"
#import "log_store.h"
int main(void) {@autoreleasepool {
    [DHLogStore shared].paused=NO;[[DHLogStore shared] setPaused:NO forCategory:DHCategoryOther];
    NSDictionary *result=DHFlowOperationSelfTest();NSData *json=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
    fwrite(json.bytes,1,json.length,stdout);putchar('\n');return [result[@"pass"] boolValue]?0:1;
}}
