// dh_files.m — 见 dh_files.h
#import "dh_files.h"
#import "dh_health.h"
#import "log_store.h"

static NSArray<NSString *> *kTopDirs(void) {
    return @[ @"Documents", @"Library", @"tmp" ];
}

static NSString *dh_files_container(void) {
    return NSHomeDirectory();
}

// 规范化相对路径: 去首尾空白与 /, 拒绝 .. 与 NUL
static NSString * _Nullable dh_files_norm_rel(NSString * _Nullable rel) {
    if (!rel || rel.length == 0) return @"";
    NSString *p = [rel stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    while ([p hasPrefix:@"/"]) p = [p substringFromIndex:1];
    if (p.length == 0) return @"";
    if ([p containsString:@".."] || [p rangeOfString:@"\0"].location != NSNotFound) return nil;
    return p;
}

static NSString * _Nullable dh_files_resolve_abs(NSString *rel, BOOL mustExist, BOOL mustBeDir, NSError **err) {
    rel = dh_files_norm_rel(rel);
    if (!rel) {
        if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"非法路径"}];
        return nil;
    }
    NSString *root = [dh_files_container() stringByStandardizingPath];
    NSString *abs;
    if (rel.length == 0) {
        abs = root;
    } else {
        NSString *top = [[rel componentsSeparatedByString:@"/"] firstObject];
        if (![kTopDirs() containsObject:top]) {
            if (err) *err = [NSError errorWithDomain:@"dh_files" code:403
                                            userInfo:@{NSLocalizedDescriptionKey: @"仅允许访问 Documents / Library / tmp"}];
            return nil;
        }
        abs = [[root stringByAppendingPathComponent:rel] stringByStandardizingPath];
    }
    if (![abs hasPrefix:root]) {
        if (err) *err = [NSError errorWithDomain:@"dh_files" code:403 userInfo:@{NSLocalizedDescriptionKey: @"路径越界"}];
        return nil;
    }
    BOOL isDir = NO;
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:abs isDirectory:&isDir];
    if (mustExist && !exists) {
        if (err) *err = [NSError errorWithDomain:@"dh_files" code:404 userInfo:@{NSLocalizedDescriptionKey: @"不存在"}];
        return nil;
    }
    if (mustBeDir && exists && !isDir) {
        if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"不是目录"}];
        return nil;
    }
    return abs;
}

static NSString *dh_files_parent_rel(NSString *rel) {
    rel = dh_files_norm_rel(rel) ?: @"";
    if (rel.length == 0) return @"";
    NSRange r = [rel rangeOfString:@"/" options:NSBackwardsSearch];
    if (r.location == NSNotFound) return @"";
    return [rel substringToIndex:r.location];
}

static BOOL dh_files_looks_binary(NSData *d) {
    const unsigned char *b = d.bytes;
    NSUInteger n = MIN(d.length, 8192);
    for (NSUInteger i = 0; i < n; i++) if (b[i] == 0) return YES;
    return NO;
}

static BOOL dh_files_text_ext(NSString *name) {
    NSString *ext = [[name pathExtension] lowercaseString];
    static NSSet *exts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exts = [NSSet setWithArray:@[@"txt",@"log",@"json",@"xml",@"plist",@"md",@"conf",@"cfg",@"ini",
                                     @"csv",@"html",@"htm",@"js",@"m",@"h",@"mm",@"swift",@"py",@"sh",
                                     @"c",@"cpp",@"cc",@"hpp",@"yaml",@"yml",@"properties",@"strings"]];
    });
    return ext.length && [exts containsObject:ext];
}

NSDictionary *dh_files_list_dict(NSString *relPath, NSError **err) {
    int saved = dh_in_hook; dh_in_hook = 1;
    NSDictionary *out = nil;
    @try {
        NSString *rel = dh_files_norm_rel(relPath) ?: @"";
        if (rel.length == 0) {
            NSMutableArray *entries = [NSMutableArray array];
            NSString *root = dh_files_container();
            for (NSString *name in kTopDirs()) {
                NSString *p = [root stringByAppendingPathComponent:name];
                BOOL isDir = NO;
                if ([[NSFileManager defaultManager] fileExistsAtPath:p isDirectory:&isDir] && isDir)
                    [entries addObject:@{ @"name": name, @"type": @"dir" }];
            }
            out = @{ @"path": @"", @"parent": [NSNull null], @"entries": entries };
        } else {
            NSString *abs = dh_files_resolve_abs(rel, YES, YES, err);
            if (!abs) return nil;
            NSError *le = nil;
            NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:abs error:&le];
            if (!names) {
                if (err) *err = le ?: [NSError errorWithDomain:@"dh_files" code:500 userInfo:@{NSLocalizedDescriptionKey: @"读取目录失败"}];
                return nil;
            }
            names = [names sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
            NSMutableArray *entries = [NSMutableArray arrayWithCapacity:names.count];
            NSFileManager *fm = [NSFileManager defaultManager];
            for (NSString *name in names) {
                NSString *fp = [abs stringByAppendingPathComponent:name];
                BOOL isDir = NO;
                if (![fm fileExistsAtPath:fp isDirectory:&isDir]) continue;
                NSMutableDictionary *e = [@{ @"name": name, @"type": isDir ? @"dir" : @"file" } mutableCopy];
                if (!isDir) {
                    NSDictionary *a = [fm attributesOfItemAtPath:fp error:nil];
                    if (a) {
                        e[@"size"] = a[NSFileSize] ?: @0;
                        NSDate *mt = a[NSFileModificationDate];
                        if (mt) e[@"mtime"] = @((long long)[mt timeIntervalSince1970]);
                    }
                }
                [entries addObject:e];
            }
            [entries sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                BOOL ad = [a[@"type"] isEqualToString:@"dir"], bd = [b[@"type"] isEqualToString:@"dir"];
                if (ad != bd) return ad ? NSOrderedAscending : NSOrderedDescending;
                return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
            }];
            NSString *parent = dh_files_parent_rel(rel);
            out = @{
                @"path":   rel,
                @"parent": parent.length ? parent : [NSNull null],
                @"entries": entries,
            };
        }
    } @finally {
        dh_in_hook = saved;
    }
    return out;
}

NSDictionary *dh_files_preview_dict(NSString *relPath, NSUInteger limit, NSError **err) {
    if (limit == 0) limit = 65536;
    if (limit > 512 * 1024) limit = 512 * 1024;

    int saved = dh_in_hook; dh_in_hook = 1;
    NSDictionary *out = nil;
    @try {
        NSString *rel = dh_files_norm_rel(relPath);
        if (!rel || rel.length == 0) {
            if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"缺少 path"}];
            return nil;
        }
        NSString *abs = dh_files_resolve_abs(rel, YES, NO, err);
        if (!abs) return nil;
        BOOL isDir = NO;
        if ([[NSFileManager defaultManager] fileExistsAtPath:abs isDirectory:&isDir] && isDir) {
            if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"不能预览目录"}];
            return nil;
        }
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:abs error:nil];
        unsigned long long total = attrs ? [(NSNumber *)attrs[NSFileSize] unsignedLongLongValue] : 0;
        NSData *data = [NSData dataWithContentsOfFile:abs options:NSDataReadingMappedIfSafe error:err];
        if (!data) return nil;
        BOOL truncated = data.length > limit;
        NSData *slice = truncated ? [data subdataWithRange:NSMakeRange(0, limit)] : data;
        NSString *name = [rel lastPathComponent];
        BOOL asText = !dh_files_looks_binary(slice) || dh_files_text_ext(name);
        NSString *text = asText ? [[NSString alloc] initWithData:slice encoding:NSUTF8StringEncoding] : nil;
        NSString *format = @"text";
        if (!text) {
            format = @"hex";
            text = DHHexDumpFromData(slice);
            if (!text.length) text = @"";
        }
        out = @{
            @"path":      rel,
            @"size":      @(total),
            @"truncated": @(truncated),
            @"format":    format,
            @"text":      text,
        };
    } @finally {
        dh_in_hook = saved;
    }
    return out;
}

NSString *dh_files_resolve_file(NSString *relPath, NSError **err) {
    int saved = dh_in_hook; dh_in_hook = 1;
    NSString *abs = nil;
    @try {
        NSString *rel = dh_files_norm_rel(relPath);
        if (!rel || rel.length == 0) {
            if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"缺少 path"}];
            return nil;
        }
        abs = dh_files_resolve_abs(rel, YES, NO, err);
        if (!abs) return nil;
        BOOL isDir = NO;
        if ([[NSFileManager defaultManager] fileExistsAtPath:abs isDirectory:&isDir] && isDir) {
            if (err) *err = [NSError errorWithDomain:@"dh_files" code:400 userInfo:@{NSLocalizedDescriptionKey: @"不能下载目录"}];
            return nil;
        }
    } @finally {
        dh_in_hook = saved;
    }
    return abs;
}
