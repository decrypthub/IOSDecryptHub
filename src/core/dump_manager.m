// dump_manager.m — 见 dump_manager.h
#import "dump_manager.h"
#import "macho_dump.h"
#import "zip_writer.h"
#define DH_BOARD DH_DIAG_DUMP
#import "dh_health.h"

@implementation DHDumpManager {
    dispatch_queue_t _q;
    NSLock          *_lock;
    // 以下状态字段受 _lock 保护
    NSString *_state;     // idle / running / done / error
    NSString *_mode;      // bin / ipa
    int       _progress;  // 0..100
    NSString *_stage;     // 当前阶段文本
    NSString *_error;     // 错误信息
    NSString *_binPath;   // 裸二进制 zip 产物
    NSString *_ipaPath;   // IPA 产物
}

+ (instancetype)shared {
    static DHDumpManager *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DHDumpManager new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("com.decrypthelper.dump", DISPATCH_QUEUE_SERIAL);
        _lock = [NSLock new];
        _state = @"idle";
        _stage = @"";
        _progress = 0;
    }
    return self;
}

// ============================================================
// 工具
// ============================================================
static NSString *docs_dir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

- (NSString *)appBaseName {
    NSString *bp = [[NSBundle mainBundle] bundlePath];
    NSString *base = [[bp lastPathComponent] stringByDeletingPathExtension];   // X.app -> X
    return base.length ? base : @"app";
}

// 砸壳临时目录(放解密后的镜像文件, 供 zw_add_file 流式打包, 用完即删)。
- (NSString *)makeTmpDir {
    NSString *d = [docs_dir() stringByAppendingPathComponent:@".dump_tmp"];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:d error:nil];   // 清掉上次残留
    if (![fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil]) return nil;
    return d;
}
- (void)cleanupTmp:(NSString *)d {
    if (d) [[NSFileManager defaultManager] removeItemAtPath:d error:nil];
}

- (void)progress:(int)p stage:(NSString *)stage {
    [_lock lock];
    _progress = p;
    if (stage) _stage = stage;
    [_lock unlock];
}

- (void)failWith:(NSString *)msg {
    DH_ERR(@"砸壳失败: %@", msg);
    [_lock lock];
    _state = @"error"; _error = msg ?: @"未知错误"; _stage = @"失败";
    [_lock unlock];
}

// ============================================================
// 镜像清单
// ============================================================
- (NSDictionary *)listImagesDict {
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *arr = [NSMutableArray array];
    NSUInteger encCount = 0;
    for (DHDumpImage *im in imgs) {
        if (im.cryptid != 0) encCount++;
        NSDictionary *attrs = [fm attributesOfItemAtPath:im.path error:nil];
        unsigned long long sz = attrs ? [attrs[NSFileSize] unsignedLongLongValue] : 0;
        [arr addObject:@{
            @"name":      im.name ?: @"",
            @"kind":      im.kind ?: @"",
            @"cryptid":   @(im.cryptid),
            @"encrypted": (im.cryptid != 0) ? @YES : @NO,
            @"size":      @(sz),
        }];
    }
    return @{ @"images": arr, @"encryptedCount": @(encCount), @"total": @(imgs.count) };
}

// ============================================================
// 发起任务
// ============================================================
- (BOOL)startDump:(NSString *)mode {
    if (![mode isEqualToString:@"bin"] && ![mode isEqualToString:@"ipa"]) return NO;

    [_lock lock];
    if ([_state isEqualToString:@"running"]) { [_lock unlock]; return NO; }
    _state = @"running"; _mode = mode; _progress = 0; _stage = @"准备中"; _error = nil;
    if ([mode isEqualToString:@"bin"]) _binPath = nil; else _ipaPath = nil;
    [_lock unlock];

    dispatch_async(_q, ^{
        // 整个砸壳 + 打包过程会大量 open/read/write, 在 dh_in_hook=1 下执行,
        // 让 file/system hook 放行不记录, 同时防递归。
        int saved = dh_in_hook;
        dh_in_hook = 1;
        @try {
            if ([mode isEqualToString:@"bin"]) [self runBinDump];
            else                               [self runIpaDump];
        } @catch (NSException *ex) {
            [self failWith:[NSString stringWithFormat:@"异常: %@", ex.reason]];
        } @finally {
            dh_in_hook = saved;
        }
    });
    return YES;
}

// ============================================================
// bin: 裸解密二进制 -> zip
// ============================================================
- (void)runBinDump {
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();

    NSMutableArray<DHDumpImage *> *targets = [NSMutableArray array];
    for (DHDumpImage *im in imgs) if (im.cryptid != 0) [targets addObject:im];
    // 没有加密镜像时, 退化为导出主程序(已是明文), 让用户仍能取到二进制。
    if (targets.count == 0) {
        for (DHDumpImage *im in imgs) if ([im.kind isEqualToString:@"main"]) { [targets addObject:im]; break; }
    }
    if (targets.count == 0) { [self failWith:@"没有可导出的镜像"]; return; }

    NSString *tmpDir = [self makeTmpDir];
    if (!tmpDir) { [self failWith:@"无法创建临时目录"]; return; }

    NSString *outPath = [docs_dir() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%@-decrypted.zip", [self appBaseName]]];
    [[NSFileManager defaultManager] removeItemAtPath:outPath error:nil];

    dh_zip_writer *zw = zw_open(outPath.fileSystemRepresentation);
    if (!zw) { [self cleanupTmp:tmpDir]; [self failWith:@"无法创建输出 zip"]; return; }

    NSUInteger n = targets.count;
    for (NSUInteger i = 0; i < n; i++) {
        DHDumpImage *im = targets[i];
        [self progress:(int)(i * 90 / n) stage:[NSString stringWithFormat:@"砸壳 %@", im.name]];

        // 流式砸壳到临时文件, 再流式加入 zip —— 全程不把镜像整体读进内存。
        NSString *tmp = [tmpDir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%lu_%@.dec", (unsigned long)i, im.name]];
        NSError *err = nil;
        if (!dh_dump_decrypt_image_to_file(im, tmp.fileSystemRepresentation, &err)) {
            zw_abort(zw); [self cleanupTmp:tmpDir];
            [self failWith:[NSString stringWithFormat:@"%@: %@", im.name, err.localizedDescription]]; return;
        }
        // zip 内用相对 bundle 的原始路径(不加 .decrypted 后缀, 保持原名), 保证唯一且有结构
        NSString *rel = ([im.path hasPrefix:bundlePath] && im.path.length > bundlePath.length + 1)
                      ? [im.path substringFromIndex:bundlePath.length + 1] : im.name;
        int rc = zw_add_file(zw, rel.UTF8String, tmp.fileSystemRepresentation, 0755);
        [[NSFileManager defaultManager] removeItemAtPath:tmp error:nil];
        if (rc != 0) { zw_abort(zw); [self cleanupTmp:tmpDir]; [self failWith:@"写入 zip 失败"]; return; }
    }

    [self progress:95 stage:@"收尾打包"];
    if (zw_close(zw) != 0) { [self cleanupTmp:tmpDir]; [self failWith:@"zip 收尾失败"]; return; }
    [self cleanupTmp:tmpDir];

    [_lock lock]; _binPath = outPath; _state = @"done"; _progress = 100; _stage = @"完成"; [_lock unlock];
    NSLog(@"[IOSDecryptHub] 砸壳(bin)完成: %@", outPath);
}

// FairPlay / 签名残渣: 解密版 IPA 既不需要也无法使用它们(重签时本就会被工具剥掉),
// 且 SC_Info/*.supf|.supp|.sinf 常对主进程不可读。打包时直接跳过, 不让一个无关 DRM
// 文件中止整包(参考 frida-ios-dump / TrollDecrypt: 它们复制 bundle 时也不依赖这些)。
static BOOL dh_is_signing_residue(NSString *sub) {
    if ([sub rangeOfString:@"SC_Info/"].location != NSNotFound) return YES;
    NSString *ext = sub.pathExtension.lowercaseString;
    return [ext isEqualToString:@"supf"] || [ext isEqualToString:@"supp"] || [ext isEqualToString:@"sinf"];
}

// ============================================================
// ipa: 脱壳后塞回 .app -> 打包 Payload/*.app -> .ipa
// ============================================================
- (void)runIpaDump {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *appDirName = [bundlePath lastPathComponent];   // X.app
    if (bundlePath.length == 0) { [self failWith:@"无法取得 bundle 路径"]; return; }

    NSString *tmpDir = [self makeTmpDir];
    if (!tmpDir) { [self failWith:@"无法创建临时目录"]; return; }

    NSString *outPath = [docs_dir() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%@-decrypted.ipa", [self appBaseName]]];
    [fm removeItemAtPath:outPath error:nil];

    // 1. 砸壳所有加密镜像 -> 临时文件, 建 原路径 -> 临时解密文件 映射 (不持有 NSData)
    [self progress:5 stage:@"砸壳镜像"];
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();
    NSUInteger encN = 0;
    for (DHDumpImage *im in imgs) if (im.cryptid != 0) encN++;

    NSMutableDictionary<NSString *, NSString *> *decFiles = [NSMutableDictionary dictionary]; // path -> tmpfile
    NSUInteger done = 0, idx = 0;
    for (DHDumpImage *im in imgs) {
        if (im.cryptid == 0) continue;
        NSString *tmp = [tmpDir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%lu_%@.dec", (unsigned long)idx++, im.name]];
        NSError *err = nil;
        if (!dh_dump_decrypt_image_to_file(im, tmp.fileSystemRepresentation, &err)) {
            [self cleanupTmp:tmpDir];
            [self failWith:[NSString stringWithFormat:@"%@: %@", im.name, err.localizedDescription]]; return;
        }
        decFiles[im.path] = tmp;
        done++;
        [self progress:(int)(5 + done * 35 / MAX(encN, (NSUInteger)1))
                  stage:[NSString stringWithFormat:@"砸壳 %@", im.name]];
    }

    // 2. 流式遍历 bundle 目录写 zip (加密镜像用临时解密文件, 其余用原文件, 统一 zw_add_file)
    [self progress:45 stage:@"打包 IPA"];
    dh_zip_writer *zw = zw_open(outPath.fileSystemRepresentation);
    if (!zw) { [self cleanupTmp:tmpDir]; [self failWith:@"无法创建输出 ipa"]; return; }

    NSDirectoryEnumerator *en = [fm enumeratorAtPath:bundlePath];
    NSString *sub;
    NSUInteger fileCount = 0, skipped = 0;
    while ((sub = [en nextObject])) {
        NSString *full = [bundlePath stringByAppendingPathComponent:sub];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:full isDirectory:&isDir]) continue;
        if (isDir) continue;   // zip 不需显式目录项, unzip 会自动建
        if (dh_is_signing_residue(sub)) {   // FairPlay/SC_Info 残渣: 解密 IPA 用不到, 跳过
            skipped++;
            continue;
        }

        NSString *zipPath = [NSString stringWithFormat:@"Payload/%@/%@", appDirName, sub];
        NSString *decTmp = decFiles[full];
        const char *srcPath;
        unsigned perm;
        if (decTmp) {
            srcPath = decTmp.fileSystemRepresentation; perm = 0755;   // 脱壳后的可执行
        } else {
            srcPath = full.fileSystemRepresentation;
            NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
            perm = attrs ? (unsigned)[attrs[NSFilePosixPermissions] unsignedShortValue] : 0644;
            if (perm == 0) perm = 0644;
        }
        int rc = zw_add_file(zw, zipPath.UTF8String, srcPath, perm);
        if (rc < 0) {   // 写流失败 -> zip 已不可用, 必须中止
            zw_abort(zw); [self cleanupTmp:tmpDir];
            [self failWith:[NSString stringWithFormat:@"打包失败(写流中断): %@", sub]]; return;
        }
        if (rc > 0) {   // 源文件读不了(权限/DRM): zip 流仍完好, 跳过该文件 + 记审查日志, 不中止整包
            skipped++;
            dh_diag_append(DH_DIAG_DUMP, "WARN",
                [NSString stringWithFormat:@"打包跳过不可读文件: %@", sub].UTF8String);
            continue;
        }

        if ((++fileCount & 0x3F) == 0) {
            int p = 45 + MIN(50, (int)(fileCount / 20));
            [self progress:p stage:[NSString stringWithFormat:@"打包 %@", sub.lastPathComponent]];
        }
    }
    if (skipped > 0)
        dh_diag_append(DH_DIAG_DUMP, "INFO",
            [NSString stringWithFormat:@"打包完成: 写入 %lu 个文件, 跳过 %lu 个(FairPlay/SC_Info 残渣或不可读, 不影响解密产物)",
             (unsigned long)fileCount, (unsigned long)skipped].UTF8String);

    [self progress:97 stage:@"收尾打包"];
    if (zw_close(zw) != 0) { [self cleanupTmp:tmpDir]; [self failWith:@"ipa 收尾失败"]; return; }
    [self cleanupTmp:tmpDir];

    [_lock lock]; _ipaPath = outPath; _state = @"done"; _progress = 100; _stage = @"完成"; [_lock unlock];
    NSLog(@"[IOSDecryptHub] 砸壳(ipa)完成: %@", outPath);
}

// ============================================================
// 状态 / 产物
// ============================================================
- (NSDictionary *)statusDict {
    [_lock lock];
    NSString *state = _state, *mode = _mode, *stage = _stage, *err = _error, *bp = _binPath, *ip = _ipaPath;
    int prog = _progress;
    [_lock unlock];

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL binReady = bp && [fm fileExistsAtPath:bp];
    BOOL ipaReady = ip && [fm fileExistsAtPath:ip];
    return @{
        @"state":    state ?: @"idle",
        @"mode":     mode ?: @"",
        @"progress": @(prog),
        @"stage":    stage ?: @"",
        @"error":    err ?: @"",
        @"binReady": binReady ? @YES : @NO,
        @"ipaReady": ipaReady ? @YES : @NO,
        @"binName":  binReady ? [bp lastPathComponent] : @"",
        @"ipaName":  ipaReady ? [ip lastPathComponent] : @"",
    };
}

- (NSString *)artifactPathForKind:(NSString *)kind {
    [_lock lock];
    NSString *p = [kind isEqualToString:@"ipa"] ? _ipaPath : _binPath;
    [_lock unlock];
    if (p && [[NSFileManager defaultManager] fileExistsAtPath:p]) return p;
    return nil;
}

// ============================================================
// 单镜像即时下载 (无需跑整包任务)
// ============================================================
- (NSString *)decryptImageNamed:(NSString *)name error:(NSError **)error {
    static NSString *const kErrDomain = @"com.decrypthelper.dump";
    if (name.length == 0) {
        if (error) *error = [NSError errorWithDomain:kErrDomain code:1 userInfo:@{NSLocalizedDescriptionKey: @"缺少 name 参数"}];
        return nil;
    }
    DHDumpImage *target = nil;
    for (DHDumpImage *im in dh_dump_list_images()) {
        if ([im.name isEqualToString:name]) { target = im; break; }
    }
    if (!target) {
        if (error) *error = [NSError errorWithDomain:kErrDomain code:2 userInfo:@{NSLocalizedDescriptionKey: @"未找到该镜像(可能已卸载, 请重新刷新列表)"}];
        return nil;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [docs_dir() stringByAppendingPathComponent:@".dump_tmp_single"];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *outPath = [dir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%08x_%@", arc4random(), target.name]];

    int saved = dh_in_hook;
    dh_in_hook = 1;   // 解密涉及大量 open/read/write, 放行不记录、防递归
    BOOL ok = dh_dump_decrypt_image_to_file(target, outPath.fileSystemRepresentation, error);
    dh_in_hook = saved;
    if (!ok) { [fm removeItemAtPath:outPath error:nil]; return nil; }
    return outPath;
}

@end
