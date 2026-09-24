// hook_hmac.m
// Hook CommonHMAC: CCHmac 一次性 + CCHmacInit/Update/Final 流式
// 把 (key, alg, data) 串起来, 在 Final 时记录完整摘要.

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

static NSString *hmac_alg_name(CCHmacAlgorithm a) {
    switch (a) {
        case kCCHmacAlgSHA1:    return @"HMAC-SHA1";
        case kCCHmacAlgMD5:     return @"HMAC-MD5";
        case kCCHmacAlgSHA256:  return @"HMAC-SHA256";
        case kCCHmacAlgSHA384:  return @"HMAC-SHA384";
        case kCCHmacAlgSHA512:  return @"HMAC-SHA512";
        case kCCHmacAlgSHA224:  return @"HMAC-SHA224";
        default:                return [NSString stringWithFormat:@"HMAC-Alg(%u)", (unsigned)a];
    }
}

static size_t hmac_out_len(CCHmacAlgorithm a) {
    switch (a) {
        case kCCHmacAlgSHA1:    return CC_SHA1_DIGEST_LENGTH;
        case kCCHmacAlgMD5:     return CC_MD5_DIGEST_LENGTH;
        case kCCHmacAlgSHA224:  return CC_SHA224_DIGEST_LENGTH;
        case kCCHmacAlgSHA256:  return CC_SHA256_DIGEST_LENGTH;
        case kCCHmacAlgSHA384:  return CC_SHA384_DIGEST_LENGTH;
        case kCCHmacAlgSHA512:  return CC_SHA512_DIGEST_LENGTH;
        default:                return 0;
    }
}

// ---------- CCHmac 一次性 ----------
static void (*orig_CCHmac)(CCHmacAlgorithm algorithm,
                           const void *key, size_t keyLength,
                           const void *data, size_t dataLength,
                           void *macOut);

static void hooked_CCHmac(CCHmacAlgorithm algorithm,
                          const void *key, size_t keyLength,
                          const void *data, size_t dataLength,
                          void *macOut) {
    orig_CCHmac(algorithm, key, keyLength, data, dataLength, macOut);
    if (!dh_capture_sub_enabled(DH_CAP_HMAC)) return;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryHMAC;
    e.algorithm  = hmac_alg_name(algorithm);
    e.operation  = @"digest";
    e.key        = key ? [NSData dataWithBytes:key length:keyLength] : nil;
    e.input      = data ? [NSData dataWithBytes:data length:dataLength] : nil;
    size_t outLen = hmac_out_len(algorithm);
    e.output     = outLen ? [NSData dataWithBytes:macOut length:outLen] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ---------- streaming ----------
// ctx pointer -> (alg, key, data accumulator)
@interface DHHmacState : NSObject
@property (nonatomic, assign) CCHmacAlgorithm alg;
@property (nonatomic, strong) NSData *key;
@property (nonatomic, strong) NSMutableData *acc;
@end
@implementation DHHmacState
@end

static NSMapTable *gHmacStates = nil;
static dispatch_semaphore_t gHmacLock = nil;
static void hmac_state_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gHmacStates = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory|NSPointerFunctionsOpaquePersonality
                                            valueOptions:NSPointerFunctionsStrongMemory];
        gHmacLock = dispatch_semaphore_create(1);
    });
}

static void (*orig_CCHmacInit)(CCHmacContext *ctx, CCHmacAlgorithm algorithm,
                               const void *key, size_t keyLength);
static void hooked_CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm algorithm,
                              const void *key, size_t keyLength) {
    orig_CCHmacInit(ctx, algorithm, key, keyLength);
    hmac_state_init();
    DHHmacState *s = [DHHmacState new];
    s.alg = algorithm;
    s.key = key ? [NSData dataWithBytes:key length:keyLength] : [NSData data];
    s.acc = [NSMutableData data];
    dispatch_semaphore_wait(gHmacLock, DISPATCH_TIME_FOREVER);
    [gHmacStates setObject:s forKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gHmacLock);
}

static void (*orig_CCHmacUpdate)(CCHmacContext *ctx, const void *data, size_t dataLength);
static void hooked_CCHmacUpdate(CCHmacContext *ctx, const void *data, size_t dataLength) {
    orig_CCHmacUpdate(ctx, data, dataLength);
    if (!data || dataLength == 0) return;
    hmac_state_init();
    dispatch_semaphore_wait(gHmacLock, DISPATCH_TIME_FOREVER);
    DHHmacState *s = [gHmacStates objectForKey:(__bridge id)ctx];
    if (s) [s.acc appendBytes:data length:dataLength];
    dispatch_semaphore_signal(gHmacLock);
}

static void (*orig_CCHmacFinal)(CCHmacContext *ctx, void *macOut);
static void hooked_CCHmacFinal(CCHmacContext *ctx, void *macOut) {
    orig_CCHmacFinal(ctx, macOut);
    hmac_state_init();
    dispatch_semaphore_wait(gHmacLock, DISPATCH_TIME_FOREVER);
    DHHmacState *s = [gHmacStates objectForKey:(__bridge id)ctx];
    [gHmacStates removeObjectForKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gHmacLock);
    if (!s) return;
    if (!dh_capture_sub_enabled(DH_CAP_HMAC)) return;
    size_t outLen = hmac_out_len(s.alg);
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryHMAC;
    e.algorithm  = [hmac_alg_name(s.alg) stringByAppendingString:@" (streaming)"];
    e.operation  = @"digest";
    e.key        = s.key;
    e.input      = [s.acc copy];
    e.output     = outLen ? [NSData dataWithBytes:macOut length:outLen] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

void dh_install_hmac_hooks(void) {
    struct rebinding r[] = {
        {"CCHmac",       hooked_CCHmac,       (void **)&orig_CCHmac},
        {"CCHmacInit",   hooked_CCHmacInit,   (void **)&orig_CCHmacInit},
        {"CCHmacUpdate", hooked_CCHmacUpdate, (void **)&orig_CCHmacUpdate},
        {"CCHmacFinal",  hooked_CCHmacFinal,  (void **)&orig_CCHmacFinal},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 安装后自检(fail-loud): orig 仍为 NULL 即没挂上. CommonCrypto 注入时必已加载.
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_CRYPTO, r[k].name);
}
