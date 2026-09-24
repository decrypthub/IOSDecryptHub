// hook_evp.m
// Hook OpenSSL EVP 对称加解密: Init / Update / Final / CIPHER_CTX_ctrl
//
// 覆盖所有通过 EVP_CIPHER_CTX + EVP_*Update 流转的对称算法(AES/DES/ChaCha20/SM4/...).
// 算法名在 Init 阶段从 EVP_CIPHER 绑定; Update 只带 ctx/in/out, 故必须 hook Init 建立 ctx→cipher 表.
// AEAD(GCM/CCM/ChaCha20-Poly1305): AAD 经 Update(out=NULL) 或 ctrl; tag 经 ctrl / Final.
//
// OpenSSL 可能注入后才 dlopen, 安装后不做 fail-loud 自检(同 SecKey*).

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct engine_st ENGINE;
typedef struct ossl_param_st OSSL_PARAM;

// EVP_CIPHER_CTX_ctrl 常用类型 (OpenSSL 1.1.1+)
// CCM 的 GET_TAG/SET_TAG/SET_IVLEN 是 GCM(=AEAD)的别名, 同值, 故无需单列.
enum {
    DH_EVP_CTRL_GCM_SET_IVLEN  = 0x9,   // = EVP_CTRL_AEAD_SET_IVLEN (CCM 同值)
    DH_EVP_CTRL_GCM_GET_TAG    = 0x10,  // = EVP_CTRL_AEAD_GET_TAG  (CCM 同值)
    DH_EVP_CTRL_GCM_SET_TAG    = 0x11,  // = EVP_CTRL_AEAD_SET_TAG  (CCM 同值)
};

@interface DHEVPCtxState : NSObject
@property (nonatomic, copy)   NSString *cipherName;
@property (nonatomic, copy)   NSString *opDesc;
@property (nonatomic, copy)   NSData   *key;
@property (nonatomic, copy)   NSData   *iv;
@property (nonatomic, copy)   NSData   *tag;
@property (nonatomic, assign) int       keyLenHint;
@property (nonatomic, assign) int       ivLenHint;
@property (nonatomic, strong) NSMutableData *accIn;
@property (nonatomic, strong) NSMutableData *accOut;
@property (nonatomic, strong) NSMutableData *aad;
@end
@implementation DHEVPCtxState
@end

static NSMapTable *gEvpStates = nil;
static dispatch_semaphore_t gEvpLock = nil;

static const char *(*fn_CIPHER_get0_name)(const EVP_CIPHER *);
static const char *(*fn_CIPHER_name)(const EVP_CIPHER *);
static int (*fn_CIPHER_key_length)(const EVP_CIPHER *);
static int (*fn_CIPHER_iv_length)(const EVP_CIPHER *);

#define DH_EVP_RESOLVE(sym) do { \
    if (!orig_##sym) { \
        dh_in_hook = 1; \
        orig_##sym = (typeof(orig_##sym))dlsym(RTLD_DEFAULT, #sym); \
        dh_in_hook = 0; \
    } \
} while (0)

static void evp_map_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gEvpStates = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory | NSPointerFunctionsOpaquePersonality
                                           valueOptions:NSPointerFunctionsStrongMemory];
        gEvpLock = dispatch_semaphore_create(1);
        fn_CIPHER_get0_name = (const char *(*)(const EVP_CIPHER *))dlsym(RTLD_DEFAULT, "EVP_CIPHER_get0_name");
        fn_CIPHER_name      = (const char *(*)(const EVP_CIPHER *))dlsym(RTLD_DEFAULT, "EVP_CIPHER_name");
        fn_CIPHER_key_length = (int (*)(const EVP_CIPHER *))dlsym(RTLD_DEFAULT, "EVP_CIPHER_key_length");
        fn_CIPHER_iv_length  = (int (*)(const EVP_CIPHER *))dlsym(RTLD_DEFAULT, "EVP_CIPHER_iv_length");
    });
}

static NSString *evp_cipher_label(const EVP_CIPHER *cipher) {
    if (!cipher) return nil;
    const char *nm = fn_CIPHER_get0_name ? fn_CIPHER_get0_name(cipher) : NULL;
    if (!nm && fn_CIPHER_name) nm = fn_CIPHER_name(cipher);
    if (nm && nm[0]) return [NSString stringWithUTF8String:nm];
    return [NSString stringWithFormat:@"cipher@%p", cipher];
}

static DHEVPCtxState *evp_state_for(EVP_CIPHER_CTX *ctx, int create) {
    if (!ctx) return nil;
    evp_map_init();
    DHEVPCtxState *st = [gEvpStates objectForKey:(__bridge id)ctx];
    if (!st && create) {
        st = [DHEVPCtxState new];
        st.accIn  = [NSMutableData data];
        st.accOut = [NSMutableData data];
        st.aad    = [NSMutableData data];
        [gEvpStates setObject:st forKey:(__bridge id)ctx];
    }
    return st;
}

static void evp_reset_bufs(DHEVPCtxState *st) {
    [st.accIn setLength:0];
    [st.accOut setLength:0];
    [st.aad setLength:0];
    st.tag = nil;
}

static void evp_apply_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv, int enc) {
    if (!ctx || !dh_capture_sub_enabled(DH_CAP_EVP)) return;
    evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
    DHEVPCtxState *st = evp_state_for(ctx, 1);
    if (cipher) {
        st.cipherName = evp_cipher_label(cipher);
        st.keyLenHint = fn_CIPHER_key_length ? fn_CIPHER_key_length(cipher) : 0;
        st.ivLenHint  = fn_CIPHER_iv_length  ? fn_CIPHER_iv_length(cipher)  : 0;
        evp_reset_bufs(st);
    }
    if (key) {
        size_t kl = st.keyLenHint > 0 ? (size_t)st.keyLenHint : 32;
        st.key = [NSData dataWithBytes:key length:kl];
    }
    if (iv) {
        size_t il = st.ivLenHint > 0 ? (size_t)st.ivLenHint : 16;
        st.iv = [NSData dataWithBytes:iv length:il];
    }
    st.opDesc = enc ? @"encrypt" : @"decrypt";
    dispatch_semaphore_signal(gEvpLock);
}

static void evp_record_update(EVP_CIPHER_CTX *ctx,
                              const unsigned char *in, int inl,
                              const unsigned char *out, int outl) {
    if (!ctx || !dh_capture_sub_enabled(DH_CAP_EVP)) return;
    evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
    DHEVPCtxState *st = evp_state_for(ctx, 0);
    if (st) {
         // AEAD: out==NULL 时 in 为 AAD
        if (in && inl > 0) {
            if (!out) [st.aad appendBytes:in length:(NSUInteger)inl];
            else      [st.accIn appendBytes:in length:(NSUInteger)inl];
        }
        if (out && outl > 0)
            [st.accOut appendBytes:out length:(NSUInteger)outl];
    }
    dispatch_semaphore_signal(gEvpLock);
}

static void evp_record_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    if (!ctx || !ptr || arg <= 0 || !dh_capture_sub_enabled(DH_CAP_EVP)) return;
    if (type != DH_EVP_CTRL_GCM_GET_TAG && type != DH_EVP_CTRL_GCM_SET_TAG)
        return;
    evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
    DHEVPCtxState *st = evp_state_for(ctx, 0);
    if (st) st.tag = [NSData dataWithBytes:ptr length:(NSUInteger)arg];
    dispatch_semaphore_signal(gEvpLock);
}

static void evp_emit_final(EVP_CIPHER_CTX *ctx, int ok) {
    if (!ctx || !dh_capture_sub_enabled(DH_CAP_EVP)) return;
    evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
    DHEVPCtxState *st = evp_state_for(ctx, 0);
    if (!st) {
        dispatch_semaphore_signal(gEvpLock);
        DH_ERR(@"EVP Final 收到未跟踪的 ctx=%p, 可能漏抓 Init", ctx);
        return;
    }
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategorySymmetric;
    e.algorithm = [NSString stringWithFormat:@"[EVP] %@", st.cipherName ?: @"unknown"];
    e.operation = st.opDesc ?: @"cipher";
    e.key       = st.key;
    e.iv        = st.iv;
    e.input     = [st.accIn copy];
    e.output    = [st.accOut copy];
    NSMutableString *detail = [NSMutableString string];
    if (st.aad.length)  [detail appendFormat:@"aad=%@", DHHexFromData(st.aad)];
    if (st.tag.length)  [detail appendFormat:@"%@tag=%@", detail.length ? @"; " : @"", DHHexFromData(st.tag)];
    if (!ok)            [detail appendFormat:@"%@auth=FAIL", detail.length ? @"; " : @""];
    if (detail.length)  e.detail = detail;
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
    evp_reset_bufs(st);
    dispatch_semaphore_signal(gEvpLock);
}

// =================== Init ===================
static int (*orig_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                                      const unsigned char *, const unsigned char *);
static int hooked_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                                     const unsigned char *key, const unsigned char *iv) {
    DH_EVP_RESOLVE(EVP_EncryptInit_ex);
    if (!orig_EVP_EncryptInit_ex) return -1;
    int r = orig_EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, 1);
    return r;
}

static int (*orig_EVP_DecryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                                      const unsigned char *, const unsigned char *);
static int hooked_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                                     const unsigned char *key, const unsigned char *iv) {
    DH_EVP_RESOLVE(EVP_DecryptInit_ex);
    if (!orig_EVP_DecryptInit_ex) return -1;
    int r = orig_EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, 0);
    return r;
}

static int (*orig_EVP_CipherInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                                      const unsigned char *, const unsigned char *, int);
static int hooked_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                                    const unsigned char *key, const unsigned char *iv, int enc) {
    DH_EVP_RESOLVE(EVP_CipherInit_ex);
    if (!orig_EVP_CipherInit_ex) return -1;
    int r = orig_EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, enc);
    return r;
}

static int (*orig_EVP_EncryptInit_ex2)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                                       const unsigned char *, const unsigned char *, const OSSL_PARAM *);
static int hooked_EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                      const unsigned char *key, const unsigned char *iv,
                                      const OSSL_PARAM *params) {
    DH_EVP_RESOLVE(EVP_EncryptInit_ex2);
    if (!orig_EVP_EncryptInit_ex2) return -1;
    int r = orig_EVP_EncryptInit_ex2(ctx, cipher, key, iv, params);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, 1);
    return r;
}

static int (*orig_EVP_DecryptInit_ex2)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                                       const unsigned char *, const unsigned char *, const OSSL_PARAM *);
static int hooked_EVP_DecryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                      const unsigned char *key, const unsigned char *iv,
                                      const OSSL_PARAM *params) {
    DH_EVP_RESOLVE(EVP_DecryptInit_ex2);
    if (!orig_EVP_DecryptInit_ex2) return -1;
    int r = orig_EVP_DecryptInit_ex2(ctx, cipher, key, iv, params);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, 0);
    return r;
}

static int (*orig_EVP_CipherInit_ex2)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                                       const unsigned char *, const unsigned char *, int,
                                       const OSSL_PARAM *);
static int hooked_EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                     const unsigned char *key, const unsigned char *iv, int enc,
                                     const OSSL_PARAM *params) {
    DH_EVP_RESOLVE(EVP_CipherInit_ex2);
    if (!orig_EVP_CipherInit_ex2) return -1;
    int r = orig_EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, params);
    if (r == 1) evp_apply_init(ctx, cipher, key, iv, enc);
    return r;
}

// =================== Update ===================
static int (*orig_EVP_EncryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                                     const unsigned char *, int);
static int hooked_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                                    const unsigned char *in, int inl) {
    DH_EVP_RESOLVE(EVP_EncryptUpdate);
    if (!orig_EVP_EncryptUpdate) return -1;
    int r = orig_EVP_EncryptUpdate(ctx, out, outl, in, inl);
    if (r == 1) {
        int ol = (outl && *outl > 0) ? *outl : 0;
        evp_record_update(ctx, in, inl, out, ol);
    }
    return r;
}

static int (*orig_EVP_DecryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                                       const unsigned char *, int);
static int hooked_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                                    const unsigned char *in, int inl) {
    DH_EVP_RESOLVE(EVP_DecryptUpdate);
    if (!orig_EVP_DecryptUpdate) return -1;
    int r = orig_EVP_DecryptUpdate(ctx, out, outl, in, inl);
    if (r == 1) {
        int ol = (outl && *outl > 0) ? *outl : 0;
        evp_record_update(ctx, in, inl, out, ol);
    }
    return r;
}

static int (*orig_EVP_CipherUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
                                     const unsigned char *, int);
static int hooked_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                                   const unsigned char *in, int inl) {
    DH_EVP_RESOLVE(EVP_CipherUpdate);
    if (!orig_EVP_CipherUpdate) return -1;
    int r = orig_EVP_CipherUpdate(ctx, out, outl, in, inl);
    if (r == 1) {
        int ol = (outl && *outl > 0) ? *outl : 0;
        evp_record_update(ctx, in, inl, out, ol);
    }
    return r;
}

// =================== Final ===================
static int (*orig_EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int hooked_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    DH_EVP_RESOLVE(EVP_EncryptFinal_ex);
    if (!orig_EVP_EncryptFinal_ex) return -1;
    int r = orig_EVP_EncryptFinal_ex(ctx, out, outl);
    if (r == 1 && out && outl && *outl > 0) {
        evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
        DHEVPCtxState *st = evp_state_for(ctx, 0);
        if (st) [st.accOut appendBytes:out length:(NSUInteger)*outl];
        dispatch_semaphore_signal(gEvpLock);
    }
    evp_emit_final(ctx, r == 1);
    return r;
}

static int (*orig_EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int hooked_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    DH_EVP_RESOLVE(EVP_DecryptFinal_ex);
    if (!orig_EVP_DecryptFinal_ex) return -1;
    int r = orig_EVP_DecryptFinal_ex(ctx, out, outl);
    if (r == 1 && out && outl && *outl > 0) {
        evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
        DHEVPCtxState *st = evp_state_for(ctx, 0);
        if (st) [st.accOut appendBytes:out length:(NSUInteger)*outl];
        dispatch_semaphore_signal(gEvpLock);
    }
    evp_emit_final(ctx, r == 1);
    return r;
}

static int (*orig_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int hooked_EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    DH_EVP_RESOLVE(EVP_CipherFinal_ex);
    if (!orig_EVP_CipherFinal_ex) return -1;
    int r = orig_EVP_CipherFinal_ex(ctx, out, outl);
    if (r == 1 && out && outl && *outl > 0) {
        evp_map_init();  // 必须先建锁: 首个 Init 早于任何 evp_state_for, 否则 wait(nil) 崩
    dispatch_semaphore_wait(gEvpLock, DISPATCH_TIME_FOREVER);
        DHEVPCtxState *st = evp_state_for(ctx, 0);
        if (st) [st.accOut appendBytes:out length:(NSUInteger)*outl];
        dispatch_semaphore_signal(gEvpLock);
    }
    evp_emit_final(ctx, r == 1);
    return r;
}

// =================== ctrl ===================
static int (*orig_EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
static int hooked_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    DH_EVP_RESOLVE(EVP_CIPHER_CTX_ctrl);
    if (!orig_EVP_CIPHER_CTX_ctrl) return -1;
    int r = orig_EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
    if (r == 1) evp_record_ctrl(ctx, type, arg, ptr);
    return r;
}

void dh_install_evp_hooks(void) {
    struct rebinding r[] = {
        {"EVP_EncryptInit_ex",    hooked_EVP_EncryptInit_ex,    (void **)&orig_EVP_EncryptInit_ex},
        {"EVP_DecryptInit_ex",    hooked_EVP_DecryptInit_ex,    (void **)&orig_EVP_DecryptInit_ex},
        {"EVP_CipherInit_ex",     hooked_EVP_CipherInit_ex,     (void **)&orig_EVP_CipherInit_ex},
        {"EVP_EncryptInit_ex2",   hooked_EVP_EncryptInit_ex2,   (void **)&orig_EVP_EncryptInit_ex2},
        {"EVP_DecryptInit_ex2",   hooked_EVP_DecryptInit_ex2,   (void **)&orig_EVP_DecryptInit_ex2},
        {"EVP_CipherInit_ex2",    hooked_EVP_CipherInit_ex2,    (void **)&orig_EVP_CipherInit_ex2},
        {"EVP_EncryptUpdate",     hooked_EVP_EncryptUpdate,     (void **)&orig_EVP_EncryptUpdate},
        {"EVP_DecryptUpdate",     hooked_EVP_DecryptUpdate,     (void **)&orig_EVP_DecryptUpdate},
        {"EVP_CipherUpdate",      hooked_EVP_CipherUpdate,      (void **)&orig_EVP_CipherUpdate},
        {"EVP_EncryptFinal_ex",   hooked_EVP_EncryptFinal_ex,   (void **)&orig_EVP_EncryptFinal_ex},
        {"EVP_DecryptFinal_ex",   hooked_EVP_DecryptFinal_ex,   (void **)&orig_EVP_DecryptFinal_ex},
        {"EVP_CipherFinal_ex",    hooked_EVP_CipherFinal_ex,    (void **)&orig_EVP_CipherFinal_ex},
        {"EVP_CIPHER_CTX_ctrl",   hooked_EVP_CIPHER_CTX_ctrl,   (void **)&orig_EVP_CIPHER_CTX_ctrl},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    // 不登记 dlsym 重定向(见 README): OpenSSL 3 provider 初始化会 dlsym 自身 EVP 符号.
    // 不 hook EVP_CIPHER_CTX_free: Mac 实测 fishhook 可能破坏相邻 CTX_new GOT 槽.
}
