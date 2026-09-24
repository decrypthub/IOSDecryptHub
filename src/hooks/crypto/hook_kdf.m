// hook_kdf.m
// Hook 密钥派生函数: CCKeyDerivationPBKDF (PBKDF2)
//
// 逆向价值: 很多 App 用 PBKDF2 从用户口令派生对称密钥(登录态/本地加密存储)。
// 抓到 password(明文口令) / salt / 迭代次数 / PRF / 派生出的 key, 往往能直接还原其密钥体系。
//
// password 记到 input, salt 记到 iv 字段(算法名已标明是 PBKDF, 不会混淆), 派生 key 记到 output。

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

static const char *prf_name(CCPseudoRandomAlgorithm prf) {
    switch (prf) {
        case kCCPRFHmacAlgSHA1:   return "HMAC-SHA1";
        case kCCPRFHmacAlgSHA224: return "HMAC-SHA224";
        case kCCPRFHmacAlgSHA256: return "HMAC-SHA256";
        case kCCPRFHmacAlgSHA384: return "HMAC-SHA384";
        case kCCPRFHmacAlgSHA512: return "HMAC-SHA512";
        default:                  return "PRF?";
    }
}

static int (*orig_CCKeyDerivationPBKDF)(CCPBKDFAlgorithm, const char *, size_t,
    const uint8_t *, size_t, CCPseudoRandomAlgorithm, unsigned int, uint8_t *, size_t);

static int hooked_CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf, unsigned int rounds,
    uint8_t *derivedKey, size_t derivedKeyLen) {
    int r = orig_CCKeyDerivationPBKDF(algorithm, password, passwordLen,
                                      salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
    if (!dh_capture_sub_enabled(DH_CAP_KDF)) return r;
    @try {
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryOther;
        e.algorithm = [NSString stringWithFormat:@"PBKDF2-%s", prf_name(prf)];
        e.operation = [NSString stringWithFormat:@"derive (rounds=%u)", rounds];
        e.input     = password ? [NSData dataWithBytes:password length:passwordLen] : nil;  // 明文口令
        e.iv        = salt     ? [NSData dataWithBytes:salt length:saltLen] : nil;           // salt
        e.output    = (r == 0 && derivedKey)   // CCKeyDerivationPBKDF: 0 = kCCSuccess
                      ? [NSData dataWithBytes:derivedKey length:derivedKeyLen] : nil;        // 派生出的 key
        e.publicKeyInfo = [NSString stringWithFormat:@"salt=%zuB, dk=%zuB, rounds=%u",
                           saltLen, derivedKeyLen, rounds];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    } @catch (NSException *ex) {
        DH_ERR(@"PBKDF2 记录失败: %@", ex.reason);
    }
    return r;
}

void dh_install_kdf_hooks(void) {
    struct rebinding r[] = {
        {"CCKeyDerivationPBKDF", hooked_CCKeyDerivationPBKDF, (void **)&orig_CCKeyDerivationPBKDF},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 安装后自检(fail-loud): orig 仍为 NULL 即没挂上. CommonCrypto 注入时必已加载.
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_CRYPTO, r[k].name);
}
