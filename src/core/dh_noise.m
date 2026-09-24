// dh_noise.m — 见 dh_noise.h
#import "dh_noise.h"
#import "dh_health.h"
#import "log_store.h"

static NSMutableArray<NSString *> *gPatterns[DHNoiseBoardCount];
static BOOL          gEnabled[DHNoiseBoardCount];
static NSString     *gConfPath = nil;
static NSLock       *gLock     = nil;

static void dh_noise_set_defaults_locked(void) {
    for (int i = 0; i < DHNoiseBoardCount; i++) {
        gEnabled[i]  = YES;
        gPatterns[i] = [NSMutableArray array];
    }
    [gPatterns[DHNoiseBoardCrypto] addObject:@"MGCopyAnswer"];
    [gPatterns[DHNoiseBoardCrypto] addObject:@"iPhone"];   // 只对字面量 "iPhone" 做的 MD5/摘要 多为设备探测噪声
}

// v2 格式:
//   第一行 "v2"
//   [CRYPTO] / enabled / patterns... / -- / [SYS] / enabled / patterns...
static void dh_noise_save_locked(void) {
    if (!gConfPath) return;
    NSMutableString *txt = [NSMutableString stringWithString:@"v2\n"];
    const char *tags[] = { "CRYPTO", "SYS" };
    for (int b = 0; b < DHNoiseBoardCount; b++) {
        [txt appendFormat:@"[%s]\n%d\n", tags[b], gEnabled[b] ? 1 : 0];
        for (NSString *p in gPatterns[b]) [txt appendFormat:@"%@\n", p];
        if (b < DHNoiseBoardCount - 1) [txt appendString:@"--\n"];
    }
    int saved = dh_in_hook; dh_in_hook = 1;
    [txt writeToFile:gConfPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dh_in_hook = saved;
}

static void dh_noise_load_v1(NSArray<NSString *> *lines) {
    if (lines.count < 1) return;
    gEnabled[DHNoiseBoardCrypto] = [lines[0] isEqualToString:@"1"];
    gEnabled[DHNoiseBoardSys]    = YES;
    gPatterns[DHNoiseBoardCrypto] = [NSMutableArray array];
    gPatterns[DHNoiseBoardSys]    = [NSMutableArray array];
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *p = lines[i];
        if (p.length) [gPatterns[DHNoiseBoardCrypto] addObject:p];
    }
}

static void dh_noise_load_v2(NSArray<NSString *> *lines) {
    int board = -1;
    BOOL afterEnabled = NO;
    for (NSString *line in lines) {
        if ([line isEqualToString:@"v2"]) continue;
        if ([line isEqualToString:@"[CRYPTO]"]) { board = DHNoiseBoardCrypto; afterEnabled = NO; gPatterns[board] = [NSMutableArray array]; continue; }
        if ([line isEqualToString:@"[SYS]"])    { board = DHNoiseBoardSys;    afterEnabled = NO; gPatterns[board] = [NSMutableArray array]; continue; }
        if ([line isEqualToString:@"--"]) continue;
        if (board < 0) continue;
        if (!afterEnabled) {
            gEnabled[board] = [line isEqualToString:@"1"];
            afterEnabled = YES;
            continue;
        }
        if (line.length) [gPatterns[board] addObject:line];
    }
}

void dh_noise_load(NSString *confPath) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    dh_noise_set_defaults_locked();
    gConfPath = [confPath copy];
    if (gConfPath) {
        int saved = dh_in_hook; dh_in_hook = 1;
        NSString *txt = [NSString stringWithContentsOfFile:gConfPath encoding:NSUTF8StringEncoding error:nil];
        dh_in_hook = saved;
        if (txt.length) {
            NSArray<NSString *> *lines = [txt componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
            NSMutableArray *trimmed = [NSMutableArray array];
            for (NSString *l in lines) {
                NSString *t = [l stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (t.length) [trimmed addObject:t];
            }
            if (trimmed.count && [trimmed[0] isEqualToString:@"v2"]) dh_noise_load_v2(trimmed);
            else dh_noise_load_v1(trimmed);
        }
    }
    [gLock unlock];
}

BOOL dh_noise_enabled_for_board(DHNoiseBoard board) {
    if (board < 0 || board >= DHNoiseBoardCount) return YES;
    if (!gLock) return gEnabled[board];
    [gLock lock]; BOOL v = gEnabled[board]; [gLock unlock];
    return v;
}

void dh_noise_set_enabled_for_board(DHNoiseBoard board, BOOL on) {
    if (board < 0 || board >= DHNoiseBoardCount) return;
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    gEnabled[board] = on;
    dh_noise_save_locked();
    [gLock unlock];
}

NSArray<NSString *> *dh_noise_patterns_for_board(DHNoiseBoard board) {
    if (board < 0 || board >= DHNoiseBoardCount) return @[];
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gPatterns[board] copy]; [gLock unlock];
    return r;
}

BOOL dh_noise_add_pattern_for_board(DHNoiseBoard board, NSString *pattern) {
    if (board < 0 || board >= DHNoiseBoardCount || pattern.length == 0) return NO;
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    for (NSString *p in gPatterns[board]) {
        if ([p caseInsensitiveCompare:pattern] == NSOrderedSame) { [gLock unlock]; return NO; }
    }
    [gPatterns[board] addObject:pattern];
    dh_noise_save_locked();
    [gLock unlock];
    return YES;
}

BOOL dh_noise_remove_pattern_for_board(DHNoiseBoard board, NSString *pattern) {
    if (board < 0 || board >= DHNoiseBoardCount || !gLock) return NO;
    [gLock lock];
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < gPatterns[board].count; i++) {
        if ([gPatterns[board][i] caseInsensitiveCompare:pattern] == NSOrderedSame) { idx = i; break; }
    }
    if (idx == NSNotFound) { [gLock unlock]; return NO; }
    [gPatterns[board] removeObjectAtIndex:idx];
    dh_noise_save_locked();
    [gLock unlock];
    return YES;
}

BOOL dh_noise_matches_for_board(DHNoiseBoard board, NSString *text) {
    if (board < 0 || board >= DHNoiseBoardCount || text.length == 0 || !gLock) return NO;
    [gLock lock];
    NSArray<NSString *> *pats = [gPatterns[board] copy];
    [gLock unlock];
    if (pats.count == 0) return NO;
    NSString *lower = [text lowercaseString];
    for (NSString *p in pats) {
        if (p.length && [lower isEqualToString:[p lowercaseString]]) return YES;
    }
    return NO;
}

// 只有"确实存在这类噪声语义"的分类才参与噪声判定：
//   File / System → SYS 板块；加解密类 → CRYPTO 板块；
//   其余（网络 / Keychain / 其它）返回 -1 = 不参与 —— 否则 CRYPTO 的规则列表
//   名义上会管到网络条目（历史上 net 曾被归进 CRYPTO 板块）。
DHNoiseBoard dh_noise_board_for_category(NSInteger category) {
    if (category == DHCategoryFile || category == DHCategorySystem) return DHNoiseBoardSys;
    if (category == DHCategoryDigest || category == DHCategoryHMAC ||
        category == DHCategorySymmetric || category == DHCategoryAsymmetric) return DHNoiseBoardCrypto;
    return (DHNoiseBoard)-1;
}

NSDictionary *dh_noise_export(void) {
    if (!gLock) return @{};
    [gLock lock];
    NSDictionary *d = @{
        @"crypto": @{ @"enabled": @(gEnabled[DHNoiseBoardCrypto]),
                      @"patterns": [gPatterns[DHNoiseBoardCrypto] copy] ?: @[] },
        @"sys":    @{ @"enabled": @(gEnabled[DHNoiseBoardSys]),
                      @"patterns": [gPatterns[DHNoiseBoardSys] copy] ?: @[] },
    };
    [gLock unlock];
    return d;
}

void dh_noise_import(NSDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]] || !gLock) return;
    NSArray<NSString *> *keys = @[@"crypto", @"sys"];
    [gLock lock];
    for (int b = 0; b < DHNoiseBoardCount; b++) {
        NSDictionary *bd = root[keys[b]];
        if (![bd isKindOfClass:[NSDictionary class]]) continue;
        if (bd[@"enabled"]) gEnabled[b] = [bd[@"enabled"] boolValue];
        if ([bd[@"patterns"] isKindOfClass:[NSArray class]]) {
            gPatterns[b] = [NSMutableArray array];   // 整组替换
            for (id p in bd[@"patterns"])
                if ([p isKindOfClass:[NSString class]] && [p length]) [gPatterns[b] addObject:p];
        }
    }
    dh_noise_save_locked();
    [gLock unlock];
}
