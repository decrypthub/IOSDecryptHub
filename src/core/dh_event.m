#import "dh_event.h"
#import "dh_call_context.h"
#import "log_store.h"
#include <dlfcn.h>
#include <mach/mach_time.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "dh_health.h"
#ifndef DH_VERSION_STR
#define DH_VERSION_STR "dev"
#endif

NSString *DHProcessGeneration(void) {
    static NSString *generation;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ generation = [NSUUID UUID].UUIDString.lowercaseString; });
    return generation;
}
NSString *DHCallID(uint64_t value) {
    return value ? [NSString stringWithFormat:@"%@:%llu", DHProcessGeneration(), value] : @"";
}
uint64_t DHMonotonicNS(void) {
    static mach_timebase_info_data_t tb;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mach_timebase_info(&tb); });
    return (uint64_t)(((__uint128_t)mach_absolute_time() * tb.numer) / tb.denom);
}
void DHStampEvent(DHLogEntry *event) {
    if (event.eventContext) return;
    NSString *kind = event.category <= DHCategoryAsymmetric ? @"crypto"
        : event.category == DHCategoryNetwork ? @"network" : @"observation";
    event.eventContext = @{@"schemaVersion": @2, @"kind": kind, @"phase": @"complete",
        @"processGeneration": DHProcessGeneration(), @"pid": @(getpid()),
        @"agentBuild": @DH_VERSION_STR, @"monotonicNs": [NSString stringWithFormat:@"%llu", DHMonotonicNS()],
        @"parentCallId": DHCallID(dh_call_parent()), @"parentScope": @"active-paired-synchronous-functions"};
}

NSDictionary *DHTargetIdentity(const void *address) {
    Dl_info info = {0};
    NSMutableDictionary *out = [@{@"address": [NSString stringWithFormat:@"0x%llx", (uint64_t)address]} mutableCopy];
    int savedInternal=dh_in_hook; dh_in_hook=1;
    int resolved=address ? dladdr(address,&info) : 0;
    dh_in_hook=savedInternal;
    if (!resolved || !info.dli_fbase) return out;
    out[@"image"] = info.dli_fname ? @(info.dli_fname) : @"";
    out[@"imageBase"] = [NSString stringWithFormat:@"0x%llx", (uint64_t)info.dli_fbase];
    // rva 相对运行时镜像基址，不是 Mach-O vmaddr；可随 UUID 跨 ASLR 复用。
    out[@"rva"] = [NSString stringWithFormat:@"0x%llx", (uint64_t)address - (uint64_t)info.dli_fbase];
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic == MH_MAGIC_64 && header->sizeofcmds <= 1024 * 1024) {
        const uint8_t *p = (const uint8_t *)(header + 1), *end = p + header->sizeofcmds;
        for (uint32_t i = 0; i < header->ncmds && p + sizeof(struct load_command) <= end; i++) {
            const struct load_command *lc = (const void *)p;
            if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end - p)) break;
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                uuid_string_t text; uuid_unparse_lower(((const struct uuid_command *)lc)->uuid, text);
                out[@"imageUUID"] = @(text); break;
            }
            p += lc->cmdsize;
        }
    }
    return out;
}

static id dh_export_value(id value, NSUInteger cap) {
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *a = [NSMutableArray array];
        for (id item in value) [a addObject:dh_export_value(item, cap)];
        return a;
    }
    if (![value isKindOfClass:NSDictionary.class]) return value;
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (NSString *key in value) d[key] = dh_export_value(value[key], cap);
    NSString *hex = d[@"hex"];
    if ([hex isKindOfClass:NSString.class]) {
        NSUInteger n = MIN(hex.length / 2, cap);
        d[@"hex"] = [hex substringToIndex:n * 2];
        d[@"exportedLength"] = @(n);
        d[@"exportTruncated"] = @(n * 2 < hex.length);
    }
    return d;
}
NSDictionary *DHExportPayload(NSDictionary *payload, NSUInteger maxBytes) {
    return payload ? dh_export_value(payload, maxBytes) : @{};
}
