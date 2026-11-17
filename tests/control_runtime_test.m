#import <Foundation/Foundation.h>
#import "qbdi_control_selftest.h"
#import "dh_hook_selftest.h"
#import "log_store.h"
#include <string.h>
#include "dh_control_breakpoint.h"
int main(int argc,char **argv){@autoreleasepool{
    [DHLogStore shared].paused=NO;[[DHLogStore shared] setPaused:NO forCategory:DHCategoryOther];
    NSDictionary *result;
    if(argc>1 && (!strcmp(argv[1],"prepared") || !strcmp(argv[1],"breakpoint-prepared"))) {
        dh_control_breakpoint_force_for_selftest(!strcmp(argv[1],"breakpoint-prepared"));
        NSDictionary *calibration=DHControlEnsureCalibrated();NSDictionary *legacy=[calibration[@"ok"] boolValue]?DHLiveBackendSelfTest():@{};
        dh_control_breakpoint_force_for_selftest(0);
        result=@{@"ok":@([calibration[@"ok"] boolValue] && [legacy[@"pass"] boolValue]),@"calibration":calibration,@"originalLiveGate":legacy,@"state":DHControlBackendState()};
    } else result=DHControlBackendSelfTestWithBreakpoints(argc>1 && !strcmp(argv[1],"breakpoint"));
    puts([[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:NULL] encoding:NSUTF8StringEncoding].UTF8String);
    return [result[@"ok"] boolValue]?0:1;
}}
