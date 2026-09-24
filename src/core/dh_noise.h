// dh_noise.h — 噪点特征串管理 (按板块独立: 加解密 / 系统)
//
// 各板块维护独立的启用开关与特征串列表; 与特征串完全相等时改投到该板块的噪声桶,
// 不与其它板块混用。持久化到 Documents/.dh_noise.conf (v2 格式)。

#ifndef DH_NOISE_H
#define DH_NOISE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DHNoiseBoard) {
    DHNoiseBoardCrypto = 0,   // 加解密 (摘要/HMAC/对称/非对称/KDF)
    DHNoiseBoardSys    = 1,   // 系统 (文件读写 + 模块加载)
    DHNoiseBoardCount  = 2,
};

// 从沙箱加载持久化配置(应在安装 hook 之前调用)。
void dh_noise_load(NSString *confPath);

BOOL dh_noise_enabled_for_board(DHNoiseBoard board);
void dh_noise_set_enabled_for_board(DHNoiseBoard board, BOOL on);

NSArray<NSString *> *dh_noise_patterns_for_board(DHNoiseBoard board);
BOOL dh_noise_add_pattern_for_board(DHNoiseBoard board, NSString *pattern);
BOOL dh_noise_remove_pattern_for_board(DHNoiseBoard board, NSString *pattern);

// 对指定板块的特征串做不区分大小写的完全相等匹配。
BOOL dh_noise_matches_for_board(DHNoiseBoard board, NSString * _Nullable text);

// 根据日志分类判定所属噪声板块 (file/system → 系统; 其余加解密类 → 加解密)。
DHNoiseBoard dh_noise_board_for_category(NSInteger category);

// 导入/导出(用于配置分享)。格式: { "crypto": {enabled, patterns:[…]}, "sys": {…} }。
NSDictionary *dh_noise_export(void);
void dh_noise_import(NSDictionary *root);

NS_ASSUME_NONNULL_END

#endif // DH_NOISE_H
