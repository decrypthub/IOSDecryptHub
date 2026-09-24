// hook_digest.m
// Hook CommonCrypto 摘要族: MD2/MD4/MD5 + SHA1/224/256/384/512
// 同时 hook 流式 _Init / _Update / _Final, 通过把每个 ctx 关联到一个累积 buffer 上,
// 在 _Final 时一次性产出完整的明文 + 摘要.
//
// 为什么这样做:
//   * 单参数版本 (CC_MD5/CC_SHA256 等) 一次拿到完整 data, 简单.
//   * 流式版本 update 时调用方可能切片喂入, 必须把切片粘起来才能看到完整明文.
//   * 用一个全局 NSMapTable (ctx指针 -> NSMutableData) 关联, _Final 时取出并清理.

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_CRYPTO
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// =================== ctx <-> buffer 关联 ===================
static NSMapTable *gCtxBuffers = nil;     // weak->strong 不合适 (ctx 是裸指针), 用 strong->strong with manual cleanup
static dispatch_semaphore_t gCtxLock = nil;

static void digest_ctx_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCtxBuffers = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory|NSPointerFunctionsOpaquePersonality
                                            valueOptions:NSPointerFunctionsStrongMemory];
        gCtxLock = dispatch_semaphore_create(1);
    });
}

static void digest_ctx_reset(void *ctx) {
    digest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    [gCtxBuffers setObject:[NSMutableData data] forKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gCtxLock);
}

static void digest_ctx_append(void *ctx, const void *data, NSUInteger len) {
    if (!data || len == 0) return;
    digest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    NSMutableData *buf = [gCtxBuffers objectForKey:(__bridge id)ctx];
    if (!buf) {
        buf = [NSMutableData data];
        [gCtxBuffers setObject:buf forKey:(__bridge id)ctx];
    }
    [buf appendBytes:data length:len];
    dispatch_semaphore_signal(gCtxLock);
}

static NSData *digest_ctx_take(void *ctx) {
    digest_ctx_init();
    dispatch_semaphore_wait(gCtxLock, DISPATCH_TIME_FOREVER);
    NSMutableData *buf = [gCtxBuffers objectForKey:(__bridge id)ctx];
    NSData *snap = buf ? [buf copy] : nil;
    [gCtxBuffers removeObjectForKey:(__bridge id)ctx];
    dispatch_semaphore_signal(gCtxLock);
    return snap;
}

// =================== 通用记录函数 ===================
static void log_digest(NSString *algo, NSData *input, const void *md, size_t mdLen) {
    if (!dh_capture_sub_enabled(DH_CAP_DIGEST)) return;   // 捕获开关: 摘要族关闭则源头不记
    DHLogEntry *e = [DHLogEntry new];
    e.category   = DHCategoryDigest;
    e.algorithm  = algo;
    e.operation  = @"digest";
    e.input      = input;
    e.output     = [NSData dataWithBytes:md length:mdLen];
    e.timestamp  = DHTimestampNow();
    e.callStack  = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// =================== one-shot hook ===================
#define DEF_ONESHOT(NAME, ALG_STR, LEN)                                                   \
    static unsigned char *(*orig_##NAME)(const void *, CC_LONG, unsigned char *);          \
    static unsigned char *hooked_##NAME(const void *data, CC_LONG len, unsigned char *md) {\
        unsigned char *r = orig_##NAME(data, len, md);                                     \
        NSData *in = [NSData dataWithBytes:data length:len];                               \
        log_digest(@ALG_STR, in, md, LEN);                                                 \
        return r;                                                                          \
    }

DEF_ONESHOT(CC_MD2,    "MD2",     CC_MD2_DIGEST_LENGTH)
DEF_ONESHOT(CC_MD4,    "MD4",     CC_MD4_DIGEST_LENGTH)
DEF_ONESHOT(CC_MD5,    "MD5",     CC_MD5_DIGEST_LENGTH)
DEF_ONESHOT(CC_SHA1,   "SHA1",    CC_SHA1_DIGEST_LENGTH)
DEF_ONESHOT(CC_SHA224, "SHA224",  CC_SHA224_DIGEST_LENGTH)
DEF_ONESHOT(CC_SHA256, "SHA256",  CC_SHA256_DIGEST_LENGTH)
DEF_ONESHOT(CC_SHA384, "SHA384",  CC_SHA384_DIGEST_LENGTH)
DEF_ONESHOT(CC_SHA512, "SHA512",  CC_SHA512_DIGEST_LENGTH)

// =================== streaming hook 模板 ===================
// CC_<X>_Init(ctx); CC_<X>_Update(ctx, data, len); CC_<X>_Final(md, ctx);
#define DEF_STREAM(NAME, CTX_T, ALG_STR, LEN)                                                          \
    static int (*orig_##NAME##_Init)(CTX_T *);                                                          \
    static int (*orig_##NAME##_Update)(CTX_T *, const void *, CC_LONG);                                 \
    static int (*orig_##NAME##_Final)(unsigned char *, CTX_T *);                                        \
    static int hooked_##NAME##_Init(CTX_T *c) {                                                         \
        int r = orig_##NAME##_Init(c);                                                                  \
        digest_ctx_reset(c);                                                                            \
        return r;                                                                                       \
    }                                                                                                   \
    static int hooked_##NAME##_Update(CTX_T *c, const void *data, CC_LONG len) {                        \
        digest_ctx_append(c, data, len);                                                                \
        return orig_##NAME##_Update(c, data, len);                                                      \
    }                                                                                                   \
    static int hooked_##NAME##_Final(unsigned char *md, CTX_T *c) {                                     \
        int r = orig_##NAME##_Final(md, c);                                                             \
        NSData *full = digest_ctx_take(c);                                                              \
        log_digest(@ALG_STR " (streaming)", full, md, LEN);                                             \
        return r;                                                                                       \
    }

DEF_STREAM(CC_MD2,    CC_MD2_CTX,    "MD2",    CC_MD2_DIGEST_LENGTH)
DEF_STREAM(CC_MD4,    CC_MD4_CTX,    "MD4",    CC_MD4_DIGEST_LENGTH)
DEF_STREAM(CC_MD5,    CC_MD5_CTX,    "MD5",    CC_MD5_DIGEST_LENGTH)
DEF_STREAM(CC_SHA1,   CC_SHA1_CTX,   "SHA1",   CC_SHA1_DIGEST_LENGTH)
DEF_STREAM(CC_SHA224, CC_SHA256_CTX, "SHA224", CC_SHA224_DIGEST_LENGTH)
DEF_STREAM(CC_SHA256, CC_SHA256_CTX, "SHA256", CC_SHA256_DIGEST_LENGTH)
DEF_STREAM(CC_SHA384, CC_SHA512_CTX, "SHA384", CC_SHA384_DIGEST_LENGTH)
DEF_STREAM(CC_SHA512, CC_SHA512_CTX, "SHA512", CC_SHA512_DIGEST_LENGTH)

// =================== 注册 ===================
void dh_install_digest_hooks(void) {
    struct rebinding r[] = {
        // one-shot
        {"CC_MD2",    hooked_CC_MD2,    (void **)&orig_CC_MD2},
        {"CC_MD4",    hooked_CC_MD4,    (void **)&orig_CC_MD4},
        {"CC_MD5",    hooked_CC_MD5,    (void **)&orig_CC_MD5},
        {"CC_SHA1",   hooked_CC_SHA1,   (void **)&orig_CC_SHA1},
        {"CC_SHA224", hooked_CC_SHA224, (void **)&orig_CC_SHA224},
        {"CC_SHA256", hooked_CC_SHA256, (void **)&orig_CC_SHA256},
        {"CC_SHA384", hooked_CC_SHA384, (void **)&orig_CC_SHA384},
        {"CC_SHA512", hooked_CC_SHA512, (void **)&orig_CC_SHA512},
        // streaming - init/update/final * 8
        {"CC_MD2_Init",     hooked_CC_MD2_Init,    (void **)&orig_CC_MD2_Init},
        {"CC_MD2_Update",   hooked_CC_MD2_Update,  (void **)&orig_CC_MD2_Update},
        {"CC_MD2_Final",    hooked_CC_MD2_Final,   (void **)&orig_CC_MD2_Final},
        {"CC_MD4_Init",     hooked_CC_MD4_Init,    (void **)&orig_CC_MD4_Init},
        {"CC_MD4_Update",   hooked_CC_MD4_Update,  (void **)&orig_CC_MD4_Update},
        {"CC_MD4_Final",    hooked_CC_MD4_Final,   (void **)&orig_CC_MD4_Final},
        {"CC_MD5_Init",     hooked_CC_MD5_Init,    (void **)&orig_CC_MD5_Init},
        {"CC_MD5_Update",   hooked_CC_MD5_Update,  (void **)&orig_CC_MD5_Update},
        {"CC_MD5_Final",    hooked_CC_MD5_Final,   (void **)&orig_CC_MD5_Final},
        {"CC_SHA1_Init",    hooked_CC_SHA1_Init,   (void **)&orig_CC_SHA1_Init},
        {"CC_SHA1_Update",  hooked_CC_SHA1_Update, (void **)&orig_CC_SHA1_Update},
        {"CC_SHA1_Final",   hooked_CC_SHA1_Final,  (void **)&orig_CC_SHA1_Final},
        {"CC_SHA224_Init",  hooked_CC_SHA224_Init,    (void **)&orig_CC_SHA224_Init},
        {"CC_SHA224_Update",hooked_CC_SHA224_Update,  (void **)&orig_CC_SHA224_Update},
        {"CC_SHA224_Final", hooked_CC_SHA224_Final,   (void **)&orig_CC_SHA224_Final},
        {"CC_SHA256_Init",  hooked_CC_SHA256_Init,    (void **)&orig_CC_SHA256_Init},
        {"CC_SHA256_Update",hooked_CC_SHA256_Update,  (void **)&orig_CC_SHA256_Update},
        {"CC_SHA256_Final", hooked_CC_SHA256_Final,   (void **)&orig_CC_SHA256_Final},
        {"CC_SHA384_Init",  hooked_CC_SHA384_Init,    (void **)&orig_CC_SHA384_Init},
        {"CC_SHA384_Update",hooked_CC_SHA384_Update,  (void **)&orig_CC_SHA384_Update},
        {"CC_SHA384_Final", hooked_CC_SHA384_Final,   (void **)&orig_CC_SHA384_Final},
        {"CC_SHA512_Init",  hooked_CC_SHA512_Init,    (void **)&orig_CC_SHA512_Init},
        {"CC_SHA512_Update",hooked_CC_SHA512_Update,  (void **)&orig_CC_SHA512_Update},
        {"CC_SHA512_Final", hooked_CC_SHA512_Final,   (void **)&orig_CC_SHA512_Final},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r)/sizeof(r[0]));
    // 安装后自检(fail-loud): 没匹配到的符号其 orig 指针仍为 NULL = 没挂上.
    // CommonCrypto 属 libSystem, 注入时必已加载, 此处检查可靠.
    // 例外: MD2/MD4 已废弃, 新系统(iOS 26+)可能不再导出这些符号, 属 best-effort.
    // 它们没挂上是系统行为而非我们的失效, 不纳入告警 —— 否则常态化误报会淹没真正的告警(狼来了).
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++) {
        if (strstr(r[k].name, "MD2") || strstr(r[k].name, "MD4")) continue;
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(DH_DIAG_CRYPTO, r[k].name);
    }
}
