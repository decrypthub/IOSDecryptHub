// 链接真实 thunk、事件模型和日志持久化；DH_LOG_DIR 必须由驱动提供隔离目录。
#import <Foundation/Foundation.h>
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_hook_selftest.h"
#import "dh_call_context.h"
#import "log_store.h"
#import "dh_log_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); abort(); } } while (0)

typedef struct { uint64_t x, y, z; } IDHAggregate;
static dispatch_semaphore_t entered, resumeCall, done;
static DHLogEntry *networkRequest;
@interface IDHRuntimeFixture : NSObject
- (uint64_t)sum:(uint64_t)a b:(uint64_t)b c:(uint64_t)c d:(uint64_t)d e:(uint64_t)e f:(uint64_t)f
    g:(BOOL)g h:(BOOL)h object:(NSString *)object j:(uint32_t)j k:(uint16_t)k pointer:(void *)pointer
    m:(int8_t)m n:(uint64_t)n o:(uint64_t)o;
- (uint64_t)recursive:(uint64_t)n;
- (uint64_t)inner:(uint64_t)n;
- (uint64_t)outer:(uint64_t)n;
- (uint64_t)fill:(void *)buffer length:(uint64_t)n value:(uint8_t)value;
- (double)floating:(double)value;
- (IDHAggregate)aggregate:(uint64_t)value;
- (uint64_t)waitValue:(uint64_t)value;
- (void)networkOrigin;
@end
@implementation IDHRuntimeFixture
- (uint64_t)sum:(uint64_t)a b:(uint64_t)b c:(uint64_t)c d:(uint64_t)d e:(uint64_t)e f:(uint64_t)f
    g:(BOOL)g h:(BOOL)h object:(NSString *)object j:(uint32_t)j k:(uint16_t)k pointer:(void *)pointer
    m:(int8_t)m n:(uint64_t)n o:(uint64_t)o {
    CHECK(g && !h && j == 0x12345678 && k == 0x9876 && pointer == (void *)0x12340000 && m == -7);
    CHECK([object isEqualToString:@"fixture"]);
    return a+b+c+d+e+f+object.length+j+k+(uint64_t)(intptr_t)pointer+(uint64_t)m+n+o;
}
- (uint64_t)recursive:(uint64_t)n { return n ? [self recursive:n-1] + 1 : 10; }
- (uint64_t)inner:(uint64_t)n { return n + 7; }
- (uint64_t)outer:(uint64_t)n {
    DHLogEntry *e = [DHLogEntry new]; e.category = DHCategoryDigest; e.algorithm = @"fixture-digest";
    e.operation = @"observe"; e.input = [@"synthetic" dataUsingEncoding:NSUTF8StringEncoding];
    [[DHLogStore shared] append:e];
    return [self inner:n] * 3;
}
- (uint64_t)fill:(void *)buffer length:(uint64_t)n value:(uint8_t)value { memset(buffer, value, (size_t)n); return n; }
- (double)floating:(double)value { return value * 2.0; }
- (IDHAggregate)aggregate:(uint64_t)value { return (IDHAggregate){value,value+1,value+2}; }
- (uint64_t)waitValue:(uint64_t)value {
    dispatch_semaphore_signal(entered);
    dispatch_semaphore_wait(resumeCall, DISPATCH_TIME_FOREVER);
    return value + 5;
}
- (void)networkOrigin {
    networkRequest = [DHLogEntry new]; networkRequest.category = DHCategoryNetwork;
    networkRequest.algorithm = @"fixture-network"; networkRequest.operation = @"GET";
    networkRequest.detail = @"GET https://fixture.invalid/request";
    [[DHLogStore shared] append:networkRequest];
}
@end

static int install(NSString *selector, dh_hook_options *options) {
    char error[512] = {0};
    int slot = dh_thunk_install_configured(DH_HOOK_METHOD, "IDHRuntimeFixture", selector.UTF8String, 0, 0, NULL, options, error, sizeof(error));
    if (slot < 0) fprintf(stderr, "%s\n", error);
    CHECK(slot >= 0); return slot;
}
static uint64_t sum(IDHRuntimeFixture *f) {
    return [f sum:1 b:2 c:3 d:4 e:5 f:6 g:YES h:NO object:@"fixture" j:0x12345678 k:0x9876
        pointer:(void *)0x12340000 m:-7 n:0x1122334455667788ULL o:0x9988776655443322ULL];
}
static uint64_t replacement(id self, SEL selector, uint64_t value) { (void)self; (void)selector; return value+99; }
static NSArray *events(void) { return [[DHLogStore shared] snapshot]; }
static void check_pairs(void) {
    NSMutableDictionary *entries = [NSMutableDictionary dictionary], *leaves = [NSMutableDictionary dictionary];
    for (DHLogEntry *e in events()) {
        NSString *call = e.eventContext[@"callId"], *phase = e.eventContext[@"phase"];
        if (!call.length) continue;
        if ([phase isEqual:@"entry"]) entries[call] = e;
        if ([phase isEqual:@"leave"]) leaves[call] = e;
    }
    CHECK(entries.count > 80 && entries.count == leaves.count);
    for (NSString *call in entries) {
        DHLogEntry *a = entries[call], *b = leaves[call];
        CHECK(b && a.threadId == b.threadId);
        CHECK([a.eventContext[@"hookId"] isEqual:b.eventContext[@"hookId"]]);
        CHECK([a.eventContext[@"parentCallId"] isEqual:b.eventContext[@"parentCallId"]]);
        NSString *parent = a.eventContext[@"parentCallId"];
        if (parent.length) CHECK(entries[parent] != nil);
        CHECK(b.eventContext[@"durationNs"] != nil);
    }
}

int main(int argc, char **argv) {
    @autoreleasepool {
        CHECK(getenv("DH_LOG_DIR") && strlen(getenv("DH_LOG_DIR")) > 4);
        DHLogStore *store = [DHLogStore shared];
        if (argc == 3 && strcmp(argv[1], "--restore") == 0) {
            NSString *oldGeneration = @(argv[2]);
            CHECK(![DHProcessGeneration() isEqual:oldGeneration]);
            BOOL oldCall = NO, legacy = NO;
            for (DHLogEntry *e in events()) {
                CHECK(e.restoredFromJournal);
                if ([e.eventContext[@"processGeneration"] isEqual:oldGeneration]) {
                    oldCall = YES;
                    if ([e.eventContext[@"kind"] isEqual:@"function"]) CHECK(e.eventPayload != nil);
                }
                if (!e.eventContext) { legacy = YES; CHECK([dh_log_entry_summary(e)[@"schemaVersion"] intValue] == 1); }
            }
            CHECK(oldCall && legacy);
            puts("PASS: journal preserves old generation/structured payload and legacy schema");
            return 0;
        }
        IDHRuntimeFixture *f = [IDHRuntimeFixture new];
        dh_hook_options options; dh_thunk_options_default(&options);
        options.capture_return = 1; options.describe_args = 1; options.fixed_abi = 1;
        NSString *sumSelector = @"sum:b:c:d:e:f:g:h:object:j:k:pointer:m:n:o:";
        uint64_t baseline = sum(f);
        int sumSlot = install(sumSelector, &options);
        CHECK(sum(f) == baseline);
        CHECK(dh_thunk_set_return(sumSlot, 0) == -3);
        BOOL checkedStack = NO;
        for (DHLogEntry *e in events()) {
            if (![e.eventContext[@"phase"] isEqual:@"entry"]) continue;
            NSArray *args = e.eventPayload[@"arguments"];
            if (args.count != 15) continue;
            CHECK([args[6][@"location"][@"offset"] intValue] == 0);
            CHECK([args[7][@"location"][@"offset"] intValue] == 1);
            CHECK([args[8][@"location"][@"offset"] intValue] == 8);
            CHECK([args[8][@"object"][@"text"] isEqual:@"fixture"]);
            CHECK([args[9][@"value"] isEqual:@"0x12345678"]);
            CHECK([args[12][@"value"] isEqual:@"0xf9"]);
            checkedStack = YES;
        }
        CHECK(checkedStack);
        install(@"inner:", &options); install(@"outer:", &options); install(@"recursive:", &options);
        CHECK([f outer:2] == 27 && [f recursive:6] == 16);
        dispatch_apply(40, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t i) {
            @autoreleasepool { CHECK([f outer:i] == (i+7)*3); }
        });
        CHECK(dh_call_parent() == 0);
        dh_hook_options out; dh_thunk_options_default(&out);
        out.capture_after = 1; out.capture_return = 1; out.ptr_arg = 2; out.len_arg = 3; out.max_bytes = 32; out.fixed_abi = 1;
        install(@"fill:length:value:", &out);
        uint8_t data[16]; memset(data, 0xaa, sizeof(data));
        CHECK([f fill:data length:16 value:0x5a] == 16);
        CHECK([f fill:data length:0 value:0x5a] == 0);
        for (unsigned i = 0; i < sizeof(data); i++) CHECK(data[i] == 0x5a);
        BOOL captured = NO, empty = NO;
        for (DHLogEntry *e in events()) {
            if (![e.operation containsString:@"fill:length:value:"]) continue;
            NSArray *memory = e.eventPayload[@"memory"];
            if ([e.eventContext[@"phase"] isEqual:@"entry"]) CHECK(e.input.length == 0);
            else if (e.output.length == 16) { CHECK(!memcmp(e.output.bytes, data, 16)); captured = YES; }
            else if ([memory[0][@"status"] isEqual:@"empty"]) empty = YES;
        }
        CHECK(captured && empty);
        install(@"networkOrigin", &options); [f networkOrigin];
        NSString *requestParent = networkRequest.eventContext[@"parentCallId"];
        CHECK(requestParent.length > 0);
        DHLogEntry *response = [DHLogEntry new]; response.category = DHCategoryNetwork;
        response.algorithm = @"fixture-network"; response.operation = @"GET";
        response.detail = @"GET https://fixture.invalid/request\x1e" @"200\n";
        [[DHLogStore shared] replaceNetworkEntry:networkRequest with:response];
        (void)events();
        CHECK([response.eventContext[@"parentCallId"] isEqual:requestParent]);
        check_pairs();
        unsigned observations = 0;
        for (DHLogEntry *e in events()) if ([e.algorithm isEqual:@"fixture-digest"]) {
            CHECK([e.eventContext[@"parentCallId"] length] > 0); observations++;
        }
        CHECK(observations >= 40);

        dh_hook_options native; dh_thunk_options_default(&native);
        native.abi_declared = 1; native.return_type = 'i'; native.capture_return = 1;
        pid_t pid = getpid(); char cError[512] = {0};
        dh_hook_info beforeImports[DH_THUNK_COUNT];
        int beforeImportCount = dh_thunk_list(beforeImports, DH_THUNK_COUNT);
        CHECK(dh_thunk_install_configured(DH_HOOK_IMPORT, NULL, "idh_nonexistent_symbol_fixture", 0, 0, NULL, &native, cError, sizeof(cError)) == -2);
        CHECK(dh_thunk_install_configured(DH_HOOK_IMPORT, NULL, "malloc", 0, 0, NULL, &native, cError, sizeof(cError)) == -6);
        CHECK(dh_thunk_list(beforeImports, DH_THUNK_COUNT) == beforeImportCount);
        int importSlot = dh_thunk_install_configured(DH_HOOK_IMPORT, NULL, "getpid", 0, 0, "fixture-getpid", &native, cError, sizeof(cError));
        if (importSlot < 0) fprintf(stderr, "import: %s (%d)\n", cError, importSlot);
        CHECK(importSlot >= 0 && getpid() == pid);
        BOOL cEntry = NO, cLeave = NO;
        for (DHLogEntry *event in store.snapshot) {
            if (![event.eventContext[@"hookId"] isEqual:dh_thunk_metadata(importSlot)[@"hookId"]]) continue;
            cEntry |= [event.eventContext[@"phase"] isEqual:@"entry"];
            cLeave |= [event.eventContext[@"phase"] isEqual:@"leave"];
        }
        CHECK(cEntry && cLeave);
        CHECK(dh_thunk_uninstall(importSlot, 0, cError, sizeof(cError)) == 0);

        char error[512] = {0};
        Method fp = class_getInstanceMethod(IDHRuntimeFixture.class, @selector(floating:));
        IMP original = method_getImplementation(fp);
        CHECK(dh_thunk_install_configured(DH_HOOK_METHOD, "IDHRuntimeFixture", "floating:", 0, 0, NULL, &options, error, sizeof(error)) == -6);
        CHECK(method_getImplementation(fp) == original && [f floating:2] == 4);
        Method agg = class_getInstanceMethod(IDHRuntimeFixture.class, @selector(aggregate:)); original = method_getImplementation(agg);
        CHECK(dh_thunk_install_configured(DH_HOOK_METHOD, "IDHRuntimeFixture", "aggregate:", 0, 0, NULL, &options, error, sizeof(error)) == -6);
        CHECK(method_getImplementation(agg) == original);
        dh_hook_options bad = options;
        strlcpy(bad.capture_ret_multi, "x2:8", sizeof(bad.capture_ret_multi));
        CHECK(dh_thunk_install_configured(DH_HOOK_METHOD, "IDHRuntimeFixture", "floating:", 0, 0, NULL, &bad, error, sizeof(error)) == -6);
        CHECK(dh_thunk_install_configured(DH_HOOK_IMPORT, NULL, "getpid", 0, 0, NULL, &options, error, sizeof(error)) == -6);
        CHECK(dh_thunk_validate_capture_multi("x0:8193") != 0);
        CHECK(dh_thunk_validate_capture_multi("x0:9999999999999999999") != 0);
        CHECK(dh_thunk_uninstall(sumSlot, 1, error, sizeof(error)) == 0 && sum(f) == baseline);
        int fresh = install(sumSelector, &options); CHECK(fresh != sumSlot);
        Method target = class_getInstanceMethod(IDHRuntimeFixture.class, NSSelectorFromString(sumSelector));
        IMP thunk = method_getImplementation(target);
        method_setImplementation(target, (IMP)replacement);
        CHECK(dh_thunk_uninstall(fresh, 1, error, sizeof(error)) == -5);
        CHECK(method_getImplementation(target) == (IMP)replacement);
        method_setImplementation(target, thunk);
        CHECK(dh_thunk_uninstall(fresh, 1, error, sizeof(error)) == 0);

        entered = dispatch_semaphore_create(0); resumeCall = dispatch_semaphore_create(0); done = dispatch_semaphore_create(0);
        int waitSlot = install(@"waitValue:", &options);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            CHECK([f waitValue:37] == 42); dispatch_semaphore_signal(done);
        });
        CHECK(dispatch_semaphore_wait(entered, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC)) == 0);
        CHECK([dh_thunk_metadata(waitSlot)[@"inFlight"] intValue] == 1);
        CHECK(dh_thunk_uninstall(waitSlot, 1, error, sizeof(error)) == 0);
        dispatch_semaphore_signal(resumeCall);
        CHECK(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5*NSEC_PER_SEC)) == 0);
        CHECK([dh_thunk_metadata(waitSlot)[@"inFlight"] intValue] == 0);
        CHECK([f inner:1] == 8 && dh_call_parent() == 0);
        NSDictionary *selfTest = DHHookSelfTest(NO);
        CHECK([selfTest[@"pass"] boolValue]);

        DHLogEntry *last = events().lastObject;
        NSDictionary *bounded = dh_log_entry_detail_bounded(last, 0, NO);
        CHECK(bounded[@"payload"] && [bounded[@"schemaVersion"] intValue] == 2);
        [store flush];
        NSString *legacyLine = [NSString stringWithFormat:@"{\"s\":%llu,\"c\":8,\"a\":\"legacy-fixture\",\"o\":\"legacy\"}\n", last.seq+1];
        NSFileHandle *journal = [NSFileHandle fileHandleForWritingAtPath:store.journalFilePath];
        [journal seekToEndOfFile]; [journal writeData:[legacyLine dataUsingEncoding:NSUTF8StringEncoding]]; [journal closeFile];
        NSString *json = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:@{@"generation": DHProcessGeneration(), @"pass": @YES} options:0 error:nil] encoding:NSUTF8StringEncoding];
        puts("PASS: 15 packed-stack args, recursion, concurrency, output capture, ABI rejection, ownership, in-flight retirement");
        puts(json.UTF8String);
    }
    return 0;
}
