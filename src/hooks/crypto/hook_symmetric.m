// hook_symmetric.m
// Hook 对称加密: CCCrypt (一次性) 和 CCCryptorCreate*/CCCryptorUpdate/CCCryptorFinal (流式)
// 算法包括 AES / DES / 3DES / CAST / RC2 / RC4 / Blowfish

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

static NSString *sym_alg_name(CCAlgorithm a) {
    switch (a) {
        case kCCAlgorithmAES:      return @"AES";
        case kCCAlgorithmDES:      return @"DES";
        case kCCAlgorithm3DES:     return @"3DES";
        case kCCAlgorithmCAST:     return @"CAST";
        case kCCAlgorithmRC4:      return @"RC4";
        case kCCAlgorithmRC2:      return @"RC2";
        case kCCAlgorithmBlowfish: return @"Blowfish";
        default: return [NSString stringWithFormat:@"Alg(%u)", (unsigned)a];
    }
}

static NSString *sym_mode_name(CCMode m) {
    switch (m) {
        case kCCModeECB: return @"ECB";
        case kCCModeCBC: return @"CBC";
        case kCCModeCFB: return @"CFB";
        case kCCModeCTR: return @"CTR";
        case kCCModeOFB: return @"OFB";
        case kCCModeRC4: return @"RC4";
        case kCCModeCFB8:return @"CFB8";
        default: return [NSString stringWithFormat:@"Mode(%u)", (unsigned)m];
    }
}

static NSString *sym_pad_name(CCPadding p) {
    switch (p) {
        case ccNoPadding:  return @"NoPad";
        case ccPKCS7Padding: return @"PKCS7";
        default: return [NSString stringWithFormat:@"Pad(%u)", (unsigned)p];
    }
}

static NSString *sym_op_name(CCOperation o) {
    switch (o) {
        case kCCEncrypt: return @"encrypt";
        case kCCDecrypt: return @"decrypt";
        default: return [NSString stringWithFormat:@"op(%u)", (unsigned)o];
    }
}

static NSString *sym_full_name(CCAlgorithm alg, NSInteger keyLenBytes, CCMode mode, CCPadding pad) {
    NSString *algo = sym_alg_name(alg);
    NSInteger bits = keyLenBytes * 8;
    if (alg == kCCAlgorithmAES && (bits == 128 || bits == 192 || bits == 256)) {
        algo = [NSString stringWithFormat:@"AES-%ld", (long)bits];
    }
    return [NSString stringWithFormat:@"%@-%@-%@", algo, sym_mode_name(mode), sym_pad_name(pad)];
}

// =================== CCCrypt 一次性 ===================
static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                       const void *key, size_t keyLength,
                                       const void *iv,
                                       const void *dataIn, size_t dataInLength,
                                       void *dataOut, size_t dataOutAvailable,
                                       size_t *dataOutMoved);

static CCCryptorStatus hooked_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                      const void *key, size_t keyLength,
                                      const void *iv,
                                      const void *dataIn, size_t dataInLength,
                                      void *dataOut, size_t dataOutAvailable,
                                      size_t *dataOutMoved) {
    CCCryptorStatus s = orig_CCCrypt(op, alg, options, key, keyLength, iv,
                                     dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    if (!dh_capture_sub_enabled(DH_CAP_SYMMETRIC)) return s;

    // options 推导 mode/padding (CCCrypt 没显式 mode 参数)
    CCMode mode = (options & kCCOptionECBMode) ? kCCModeECB : kCCModeCBC;
    CCPadding pad = (options & kCCOptionPKCS7Padding) ? ccPKCS7Padding : ccNoPadding;
    // IV 长度按算法 block size 推断 - 简化处理: 8 / 16
    size_t ivLen = (alg == kCCAlgorithmAES) ? 16 : 8;

    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategorySymmetric;
    e.algorithm  = sym_full_name(alg, keyLength, mode, pad);
    e.operation  = sym_op_name(op);
    e.key        = key ? [NSData dataWithBytes:key length:keyLength] : nil;
    e.iv         = (iv && mode != kCCModeECB) ? [NSData dataWithBytes:iv length:ivLen] : nil;
    e.input      = dataIn ? [NSData dataWithBytes:dataIn length:dataInLength] : nil;
    if (s == kCCSuccess && dataOut && dataOutMoved) {
        e.output = [NSData dataWithBytes:dataOut length:*dataOutMoved];
    }
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return s;
}

// =================== CCCryptor 流式 ===================
@interface DHCryptorState : NSObject
@property (nonatomic, copy)   NSString *algoDesc;
@property (nonatomic, copy)   NSString *opDesc;
@property (nonatomic, copy)   NSData   *key;
@property (nonatomic, copy)   NSData   *iv;
@property (nonatomic, strong) NSMutableData *accIn;
@property (nonatomic, strong) NSMutableData *accOut;
@end
@implementation DHCryptorState
@end

static NSMapTable *gCryptorStates = nil;
static dispatch_semaphore_t gCryptorLock = nil;
static void cryptor_state_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCryptorStates = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory|NSPointerFunctionsOpaquePersonality
                                              valueOptions:NSPointerFunctionsStrongMemory];
        gCryptorLock = dispatch_semaphore_create(1);
    });
}

// CCCryptorCreate (old API): options 暗示 mode
static CCCryptorStatus (*orig_CCCryptorCreate)(CCOperation, CCAlgorithm, CCOptions,
                                               const void *, size_t, const void *,
                                               CCCryptorRef *);
static CCCryptorStatus hooked_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
                                              const void *key, size_t keyLength, const void *iv,
                                              CCCryptorRef *cryptorRef) {
    CCCryptorStatus s = orig_CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef);
    if (s != kCCSuccess || !cryptorRef || !*cryptorRef) return s;
    CCMode mode = (options & kCCOptionECBMode) ? kCCModeECB : kCCModeCBC;
    CCPadding pad = (options & kCCOptionPKCS7Padding) ? ccPKCS7Padding : ccNoPadding;
    size_t ivLen = (alg == kCCAlgorithmAES) ? 16 : 8;

    DHCryptorState *st = [DHCryptorState new];
    st.algoDesc = sym_full_name(alg, keyLength, mode, pad);
    st.opDesc   = sym_op_name(op);
    st.key      = key ? [NSData dataWithBytes:key length:keyLength] : nil;
    st.iv       = (iv && mode != kCCModeECB) ? [NSData dataWithBytes:iv length:ivLen] : nil;
    st.accIn    = [NSMutableData data];
    st.accOut   = [NSMutableData data];

    cryptor_state_init();
    dispatch_semaphore_wait(gCryptorLock, DISPATCH_TIME_FOREVER);
    [gCryptorStates setObject:st forKey:(__bridge id)*cryptorRef];
    dispatch_semaphore_signal(gCryptorLock);
    return s;
}

// CCCryptorCreateWithMode: 提供完整 mode + alg + padding
static CCCryptorStatus (*orig_CCCryptorCreateWithMode)(CCOperation, CCMode, CCAlgorithm, CCPadding,
                                                       const void *, const void *, size_t,
                                                       const void *, size_t,
                                                       int, CCModeOptions, CCCryptorRef *);
static CCCryptorStatus hooked_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding pad,
                                                      const void *iv, const void *key, size_t keyLength,
                                                      const void *tweak, size_t tweakLength,
                                                      int numRounds, CCModeOptions options,
                                                      CCCryptorRef *cryptorRef) {
    CCCryptorStatus s = orig_CCCryptorCreateWithMode(op, mode, alg, pad, iv, key, keyLength,
                                                     tweak, tweakLength, numRounds, options, cryptorRef);
    if (s != kCCSuccess || !cryptorRef || !*cryptorRef) return s;
    size_t ivLen = (alg == kCCAlgorithmAES) ? 16 : 8;

    DHCryptorState *st = [DHCryptorState new];
    st.algoDesc = sym_full_name(alg, keyLength, mode, pad);
    st.opDesc   = sym_op_name(op);
    st.key      = key ? [NSData dataWithBytes:key length:keyLength] : nil;
    st.iv       = (iv && mode != kCCModeECB) ? [NSData dataWithBytes:iv length:ivLen] : nil;
    st.accIn    = [NSMutableData data];
    st.accOut   = [NSMutableData data];

    cryptor_state_init();
    dispatch_semaphore_wait(gCryptorLock, DISPATCH_TIME_FOREVER);
    [gCryptorStates setObject:st forKey:(__bridge id)*cryptorRef];
    dispatch_semaphore_signal(gCryptorLock);
    return s;
}

static CCCryptorStatus (*orig_CCCryptorUpdate)(CCCryptorRef, const void *, size_t,
                                                void *, size_t, size_t *);
static CCCryptorStatus hooked_CCCryptorUpdate(CCCryptorRef cryptorRef,
                                              const void *dataIn, size_t dataInLength,
                                              void *dataOut, size_t dataOutAvailable,
                                              size_t *dataOutMoved) {
    CCCryptorStatus s = orig_CCCryptorUpdate(cryptorRef, dataIn, dataInLength,
                                              dataOut, dataOutAvailable, dataOutMoved);
    if (s != kCCSuccess) return s;
    cryptor_state_init();
    dispatch_semaphore_wait(gCryptorLock, DISPATCH_TIME_FOREVER);
    DHCryptorState *st = [gCryptorStates objectForKey:(__bridge id)cryptorRef];
    if (st) {
        // 流式明文累积上限: 大流(整文件流式加解密)会把全部明文驻留内存, 撑爆宿主 OOM 被系统 kill。
        // 到顶即停止追加(记录的明文被截断, 但换来宿主不崩)。
        const NSUInteger CAP = 4 * 1024 * 1024;
        if (dataIn && dataInLength && st.accIn.length < CAP)         [st.accIn appendBytes:dataIn length:dataInLength];
        if (dataOut && dataOutMoved && *dataOutMoved && st.accOut.length < CAP) [st.accOut appendBytes:dataOut length:*dataOutMoved];
    }
    dispatch_semaphore_signal(gCryptorLock);
    return s;
}

static CCCryptorStatus (*orig_CCCryptorFinal)(CCCryptorRef, void *, size_t, size_t *);
static CCCryptorStatus hooked_CCCryptorFinal(CCCryptorRef cryptorRef,
                                             void *dataOut, size_t dataOutAvailable,
                                             size_t *dataOutMoved) {
    CCCryptorStatus s = orig_CCCryptorFinal(cryptorRef, dataOut, dataOutAvailable, dataOutMoved);
    cryptor_state_init();
    dispatch_semaphore_wait(gCryptorLock, DISPATCH_TIME_FOREVER);
    DHCryptorState *st = [gCryptorStates objectForKey:(__bridge id)cryptorRef];
    if (st) {
        if (s == kCCSuccess && dataOut && dataOutMoved && *dataOutMoved) {
            [st.accOut appendBytes:dataOut length:*dataOutMoved];
        }
    }
    dispatch_semaphore_signal(gCryptorLock);
    if (!st) {
        // fail-loud: 这个 cryptorRef 从没被 Create hook 记录过 —— 流式加密被漏抓.
        // 通常意味着 CCCryptorCreate* 没挂上, 或 App 用了未 hook 的创建函数(如 CCCryptorCreateFromData).
        DH_ERR(@"CCCryptorFinal 收到未跟踪的 cryptorRef=%p, 流式加密漏抓", cryptorRef);
        return s;
    }
    if (!dh_capture_sub_enabled(DH_CAP_SYMMETRIC)) return s;

    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategorySymmetric;
    e.algorithm  = [st.algoDesc stringByAppendingString:@" (streaming)"];
    e.operation  = st.opDesc;
    e.key        = st.key;
    e.iv         = st.iv;
    e.input      = [st.accIn copy];
    e.output     = [st.accOut copy];
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return s;
}

static CCCryptorStatus (*orig_CCCryptorRelease)(CCCryptorRef);
static CCCryptorStatus hooked_CCCryptorRelease(CCCryptorRef cryptorRef) {
    cryptor_state_init();
    dispatch_semaphore_wait(gCryptorLock, DISPATCH_TIME_FOREVER);
    [gCryptorStates removeObjectForKey:(__bridge id)cryptorRef];
    dispatch_semaphore_signal(gCryptorLock);
    return orig_CCCryptorRelease(cryptorRef);
}

void dh_install_symmetric_hooks(void) {
    struct rebinding r[] = {
        {"CCCrypt",                 hooked_CCCrypt,                 (void **)&orig_CCCrypt},
        {"CCCryptorCreate",         hooked_CCCryptorCreate,         (void **)&orig_CCCryptorCreate},
        {"CCCryptorCreateWithMode", hooked_CCCryptorCreateWithMode, (void **)&orig_CCCryptorCreateWithMode},
        {"CCCryptorUpdate",         hooked_CCCryptorUpdate,         (void **)&orig_CCCryptorUpdate},
        {"CCCryptorFinal",          hooked_CCCryptorFinal,          (void **)&orig_CCCryptorFinal},
        {"CCCryptorRelease",        hooked_CCCryptorRelease,        (void **)&orig_CCCryptorRelease},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 安装后自检(fail-loud): orig 仍为 NULL 即没挂上. CommonCrypto 注入时必已加载.
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_CRYPTO, r[k].name);
}
