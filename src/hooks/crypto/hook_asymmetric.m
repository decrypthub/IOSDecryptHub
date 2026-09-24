// hook_asymmetric.m
// Hook Security.framework 的非对称算法:
//   SecKeyCreateSignature / SecKeyVerifySignature
//   SecKeyCreateEncryptedData / SecKeyCreateDecryptedData
//
// 注: SecKeyAlgorithm 是 CFStringRef 常量, 直接当字符串描述即可.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

static NSString *describe_key(SecKeyRef key) {
    if (!key) return @"(null)";
    NSMutableString *out = [NSMutableString string];
    size_t bytes = SecKeyGetBlockSize(key);
    [out appendFormat:@"blockSize=%lu (≈%lu bits)", (unsigned long)bytes, (unsigned long)(bytes * 8)];
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (attrs) {
        NSDictionary *d = (__bridge_transfer NSDictionary *)attrs;
        NSString *type = d[(__bridge NSString *)kSecAttrKeyType];
        NSString *cls  = d[(__bridge NSString *)kSecAttrKeyClass];
        NSNumber *sz   = d[(__bridge NSString *)kSecAttrKeySizeInBits];
        if (type) [out appendFormat:@" type=%@", type];
        if (cls)  [out appendFormat:@" class=%@", cls];
        if (sz)   [out appendFormat:@" sizeInBits=%@", sz];
    }
    // 尝试导出公钥的外部表示用于指纹
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    if (pub) {
        CFErrorRef err = NULL;
        CFDataRef pubData = SecKeyCopyExternalRepresentation(pub, &err);
        if (pubData) {
            NSData *pd = (__bridge_transfer NSData *)pubData;
            // 取前 24 字节做指纹
            NSUInteger n = MIN(pd.length, 24u);
            [out appendFormat:@" pubFP=%@…", DHHexFromData([pd subdataWithRange:NSMakeRange(0,n)])];
        } else {
            // fail-loud: 导出失败时明确标注, 而非留空让人以为没有公钥
            [out appendFormat:@" pubExportFailed(err=%ld)", err ? (long)CFErrorGetCode(err) : -1L];
        }
        if (err) CFRelease(err);
        CFRelease(pub);
    } else {
        [out appendString:@" pubKeyUnavailable"];
    }
    return out;
}

// ---------- SecKeyCreateSignature ----------
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                              CFDataRef dataToSign, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateSignature(key, algorithm, dataToSign, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"SIGN-%@", (__bridge NSString *)algorithm];
    e.operation  = @"sign";
    e.publicKeyInfo = describe_key(key);
    e.input      = dataToSign ? (__bridge NSData *)dataToSign : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

// ---------- SecKeyVerifySignature ----------
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static Boolean hooked_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                            CFDataRef signedData, CFDataRef signature,
                                            CFErrorRef *error) {
    Boolean ok = orig_SecKeyVerifySignature(key, algorithm, signedData, signature, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return ok;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"VERIFY-%@", (__bridge NSString *)algorithm];
    e.operation  = ok ? @"verify (ok)" : @"verify (fail)";
    e.publicKeyInfo = describe_key(key);
    e.input      = signedData ? (__bridge NSData *)signedData : nil;
    e.output     = signature ? [(__bridge NSData *)signature copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return ok;
}

// ---------- SecKeyCreateEncryptedData ----------
static CFDataRef (*orig_SecKeyCreateEncryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                  CFDataRef plaintext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"ENC-%@", (__bridge NSString *)algorithm];
    e.operation  = @"encrypt";
    e.publicKeyInfo = describe_key(key);
    e.input      = plaintext ? (__bridge NSData *)plaintext : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

// ---------- SecKeyCreateDecryptedData ----------
static CFDataRef (*orig_SecKeyCreateDecryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef hooked_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm,
                                                  CFDataRef ciphertext, CFErrorRef *error) {
    CFDataRef out = orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, error);
    if (!dh_capture_sub_enabled(DH_CAP_ASYMMETRIC)) return out;
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryAsymmetric;
    e.algorithm  = [NSString stringWithFormat:@"DEC-%@", (__bridge NSString *)algorithm];
    e.operation  = @"decrypt";
    e.publicKeyInfo = describe_key(key);
    e.input      = ciphertext ? (__bridge NSData *)ciphertext : nil;
    e.output     = out ? [(__bridge NSData *)out copy] : nil;
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    return out;
}

// ============================================================
// 旧版 Security.framework 非对称 API (SecKeyEncrypt/Decrypt/RawSign/RawVerify)
// 不少国内 SDK(实测: 中国移动 12.5.2 进程里这些符号在导入表里)仍走这套老接口,
// 而上面四个新接口覆盖不到它们 —— 漏掉就会看到「RSA 计数为 0 但报文里明明有 128 字节密文」。
// ============================================================
static NSString *dh_padding_name(SecPadding padding) {
    switch (padding) {
        case kSecPaddingNone:      return @"None";
        case kSecPaddingPKCS1:     return @"PKCS1";
#ifdef kSecPaddingOAEP
        case kSecPaddingOAEP:      return @"OAEP";
#endif
        case kSecPaddingPKCS1MD5:  return @"PKCS1MD5";
        case kSecPaddingPKCS1SHA1: return @"PKCS1SHA1";
        case kSecPaddingPKCS1SHA224: return @"PKCS1SHA224";
        case kSecPaddingPKCS1SHA256: return @"PKCS1SHA256";
        case kSecPaddingPKCS1SHA384: return @"PKCS1SHA384";
        case kSecPaddingPKCS1SHA512: return @"PKCS1SHA512";
        default: return [NSString stringWithFormat:@"padding(%d)", (int)padding];
    }
}

static OSStatus (*orig_SecKeyEncrypt)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *);
static OSStatus hooked_SecKeyEncrypt(SecKeyRef key, SecPadding padding,
                                     const uint8_t *plain, size_t plainLen,
                                     uint8_t *cipher, size_t *cipherLen) {
    OSStatus st = orig_SecKeyEncrypt ? orig_SecKeyEncrypt(key, padding, plain, plainLen, cipher, cipherLen) : errSecUnimplemented;
    if (dh_capture_sub_enabled(DH_CAP_ASYMMETRIC) && plain && plainLen > 0) {
        DHLogEntry *e = [DHLogEntry new];
        e.category   = DHCategoryAsymmetric;
        e.algorithm  = [NSString stringWithFormat:@"ENC-legacy:%@", dh_padding_name(padding)];
        e.operation  = @"encrypt";
        e.publicKeyInfo = describe_key(key);
        e.input      = [NSData dataWithBytes:plain length:plainLen];
        if (st == errSecSuccess && cipher && cipherLen && *cipherLen > 0)
            e.output = [NSData dataWithBytes:cipher length:*cipherLen];
        e.timestamp  = DHTimestampNow();
        e.callStack  = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    }
    return st;
}

static OSStatus (*orig_SecKeyDecrypt)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *);
static OSStatus hooked_SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                                     const uint8_t *cipher, size_t cipherLen,
                                     uint8_t *plain, size_t *plainLen) {
    OSStatus st = orig_SecKeyDecrypt ? orig_SecKeyDecrypt(key, padding, cipher, cipherLen, plain, plainLen) : errSecUnimplemented;
    if (dh_capture_sub_enabled(DH_CAP_ASYMMETRIC) && cipher && cipherLen > 0) {
        DHLogEntry *e = [DHLogEntry new];
        e.category   = DHCategoryAsymmetric;
        e.algorithm  = [NSString stringWithFormat:@"DEC-legacy:%@", dh_padding_name(padding)];
        e.operation  = @"decrypt";
        e.publicKeyInfo = describe_key(key);
        e.input      = [NSData dataWithBytes:cipher length:cipherLen];
        if (st == errSecSuccess && plain && plainLen && *plainLen > 0)
            e.output = [NSData dataWithBytes:plain length:*plainLen];
        e.timestamp  = DHTimestampNow();
        e.callStack  = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    }
    return st;
}

static OSStatus (*orig_SecKeyRawSign)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *);
static OSStatus hooked_SecKeyRawSign(SecKeyRef key, SecPadding padding,
                                     const uint8_t *data, size_t dataLen,
                                     uint8_t *sig, size_t *sigLen) {
    OSStatus st = orig_SecKeyRawSign ? orig_SecKeyRawSign(key, padding, data, dataLen, sig, sigLen) : errSecUnimplemented;
    if (dh_capture_sub_enabled(DH_CAP_ASYMMETRIC) && data && dataLen > 0) {
        DHLogEntry *e = [DHLogEntry new];
        e.category   = DHCategoryAsymmetric;
        e.algorithm  = [NSString stringWithFormat:@"SIGN-legacy:%@", dh_padding_name(padding)];
        e.operation  = @"sign";
        e.publicKeyInfo = describe_key(key);
        e.input      = [NSData dataWithBytes:data length:dataLen];
        if (st == errSecSuccess && sig && sigLen && *sigLen > 0)
            e.output = [NSData dataWithBytes:sig length:*sigLen];
        e.timestamp  = DHTimestampNow();
        e.callStack  = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    }
    return st;
}

static OSStatus (*orig_SecKeyRawVerify)(SecKeyRef, SecPadding, const uint8_t *, size_t, const uint8_t *, size_t);
static OSStatus hooked_SecKeyRawVerify(SecKeyRef key, SecPadding padding,
                                       const uint8_t *data, size_t dataLen,
                                       const uint8_t *sig, size_t sigLen) {
    OSStatus st = orig_SecKeyRawVerify ? orig_SecKeyRawVerify(key, padding, data, dataLen, sig, sigLen) : errSecUnimplemented;
    if (dh_capture_sub_enabled(DH_CAP_ASYMMETRIC) && data && dataLen > 0) {
        DHLogEntry *e = [DHLogEntry new];
        e.category   = DHCategoryAsymmetric;
        e.algorithm  = [NSString stringWithFormat:@"VERIFY-legacy:%@", dh_padding_name(padding)];
        e.operation  = @"verify";
        e.publicKeyInfo = describe_key(key);
        e.input      = [NSData dataWithBytes:data length:dataLen];
        e.output     = sig ? [NSData dataWithBytes:sig length:sigLen] : nil;
        e.timestamp  = DHTimestampNow();
        e.callStack  = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
    }
    return st;
}

void dh_install_asymmetric_hooks(void) {
    struct rebinding r[] = {
        {"SecKeyCreateSignature",     hooked_SecKeyCreateSignature,     (void **)&orig_SecKeyCreateSignature},
        {"SecKeyVerifySignature",     hooked_SecKeyVerifySignature,     (void **)&orig_SecKeyVerifySignature},
        {"SecKeyCreateEncryptedData", hooked_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData},
        {"SecKeyCreateDecryptedData", hooked_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData},
        // 旧版接口: 未导入的进程里 fishhook 不会绑定, orig 保持 NULL, hook 也不会被调用。
        {"SecKeyEncrypt",             hooked_SecKeyEncrypt,             (void **)&orig_SecKeyEncrypt},
        {"SecKeyDecrypt",             hooked_SecKeyDecrypt,             (void **)&orig_SecKeyDecrypt},
        {"SecKeyRawSign",             hooked_SecKeyRawSign,             (void **)&orig_SecKeyRawSign},
        {"SecKeyRawVerify",           hooked_SecKeyRawVerify,           (void **)&orig_SecKeyRawVerify},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 注: 不在此做安装后自检 —— Security.framework 可能在 dylib 注入后才被宿主加载,
    // 此刻 orig 仍为 NULL 是正常的(随后 add-image 回调会补挂), 误报反而违背 fail-loud 初衷.
    // 真正没挂上的情形会在 SecKey* 调用发生却无日志时体现.
}
