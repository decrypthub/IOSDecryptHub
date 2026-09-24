// dh_log_json.h — 日志条目 -> JSON 字典的共享成型逻辑
//
// http_server (面板 /api/logs) 与 mcp_server (取证工具) 共用同一套字段成型, 避免两处漂移。

#ifndef DH_LOG_JSON_H
#define DH_LOG_JSON_H

#import <Foundation/Foundation.h>
#import "log_store.h"

NS_ASSUME_NONNULL_BEGIN

// 分类数量 (= DHCategoryOther + 1); 供各处遍历派生, 替代硬编码平行数组。
NSInteger dh_log_category_count(void);
// DHCategory -> 短名 ("digest"/"hmac"/"sym"/.../"net"/"keychain"/"other")
const char *dh_log_category_name(NSInteger c);

// 把网络事件 detail 拆成纯请求 / 纯响应 / 错误, 不含 -- Request Headers -- 等标签。
// 新格式: request \\x1e response \\x1e error; 旧格式: >/< 与 -- Status: -- 等。
void dh_net_split_detail(NSString * _Nullable detail,
                         NSString * _Nullable * _Nonnull outReq,
                         NSString * _Nullable * _Nonnull outResp,
                         NSString * _Nullable * _Nonnull outErr,
                         NSInteger * _Nullable outStatus);

// 摘要 (列表用): seq / category / algorithm / operation / timestamp / in-outLen / detail / preview
NSDictionary *dh_log_entry_summary(DHLogEntry *e);

// 详情 (单条用): 摘要 + key/iv/input/output 的 hex / utf8 / hexdump + callStack + publicKeyInfo
NSDictionary *dh_log_entry_detail(DHLogEntry *e);

// 批量导出用的有界详情。blob 保留原始长度，内容最多编码 maxBlobBytes，并用
// <field>Truncated 标记截断；includeDumps=false 可避免 hex 与 hexdump 重复膨胀响应。
NSDictionary *dh_log_entry_detail_bounded(DHLogEntry *e, NSUInteger maxBlobBytes,
                                           BOOL includeDumps);

NS_ASSUME_NONNULL_END

#endif // DH_LOG_JSON_H
