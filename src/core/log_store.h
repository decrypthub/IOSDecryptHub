// log_store.h - IOSDecryptHub
// 公共日志记录中心：所有 hook 模块都把抓到的明文/密文/算法信息丢到这里。
// 严格遵守约束：悬浮窗只用 entry_count 这种统计数据，不显示明细。

#ifndef DECRYPT_HELPER_LOG_STORE_H
#define DECRYPT_HELPER_LOG_STORE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 算法分类 —— 用于过滤和着色
typedef NS_ENUM(NSInteger, DHCategory) {
    DHCategoryDigest = 0,        // MD2/4/5, SHA*
    DHCategoryHMAC,              // HMAC-*
    DHCategorySymmetric,         // AES / DES / 3DES / CAST / RC2 / RC4 / Blowfish
    DHCategoryAsymmetric,        // RSA / EC sign / encrypt / verify / decrypt
    DHCategoryFile,              // open / write / unlink / rename
    DHCategorySystem,            // dlopen 载入模块
    DHCategoryNetwork,           // NSURLSession 请求 / TLS 明文收发
    DHCategoryKeychain,          // SecItem* Keychain 存取 (data 明文在 output)
    DHCategoryOther,
};

// 单条日志
@interface DHLogEntry : NSObject
@property (nonatomic, assign) DHCategory category;
@property (nonatomic, copy)   NSString *algorithm;          // e.g. "MD5" / "AES-128-CBC" / "HMAC-SHA256" / "RSA-SIGN-PKCS1v15-SHA256"
@property (nonatomic, copy)   NSString *operation;          // "encrypt" / "decrypt" / "sign" / "verify" / "digest"
@property (nonatomic, copy, nullable) NSData *key;          // 对称 key / HMAC key (二进制)
@property (nonatomic, copy, nullable) NSData *iv;           // CBC/CTR 等模式的 IV
@property (nonatomic, copy, nullable) NSData *input;        // 输入 (明文/密文/待签数据)
@property (nonatomic, copy, nullable) NSData *output;       // 输出 (摘要/密文/明文/签名)
@property (nonatomic, copy, nullable) NSString *publicKeyInfo;  // RSA 公钥摘要描述
@property (nonatomic, copy, nullable) NSString *detail;         // 通用详情: 文件路径 / 系统库路径等
@property (nonatomic, copy)   NSString *timestamp;          // 格式化时间 (人读)
@property (nonatomic, assign) uint64_t timestampMs;        // 墙钟毫秒 (epoch), 供时间窗关联; 0=legacy 未采集
@property (nonatomic, assign) uint64_t threadId;           // 调用线程 id (pthread_threadid_np); 0=legacy
@property (nonatomic, copy)   NSString *callStack;          // 应用层调用栈 (已过滤)
@property (nonatomic, assign) uint64_t seq;                 // 自增序号
@end

@interface DHLogStore : NSObject

+ (instancetype)shared;

// 写入一条日志 (线程安全)
- (void)append:(DHLogEntry *)entry;

// 网络专用: 用「已含响应」的新条目原子替换先前只记了请求的旧条目 (保持 seq/位置不变)。
// 旧条目保持不可变、绝不原地改写 —— 已取到快照的读者仍持有完整旧对象, 读侧零竞态。
// 仅在串行队列内换引用并重新落盘; 旧条目若已被环形缓冲淘汰则退化为追加新条目。
- (void)replaceNetworkEntry:(DHLogEntry *)oldEntry with:(DHLogEntry *)newEntry;

// 当前所有日志快照 (按 seq 升序; 限制最近 N 条以防 UI 卡顿)
- (NSArray<DHLogEntry *> *)snapshot;
- (NSArray<DHLogEntry *> *)snapshotMatching:(nullable NSString *)keyword
                                   category:(NSInteger)categoryOrMinusOne;

// 单条查询 (用于 web detail 端点)
- (nullable DHLogEntry *)entryWithSeq:(uint64_t)seq;

// 统计
- (NSUInteger)totalCount;
- (NSUInteger)countForCategory:(DHCategory)cat;

// 暂停/恢复 (全局总开关)
@property (atomic, assign) BOOL paused;

// 每类暂停 (高频的文件类可单独停掉, 不影响其它板块继续记录)
- (void)setPaused:(BOOL)paused forCategory:(DHCategory)cat;
- (BOOL)isPausedForCategory:(DHCategory)cat;

// 清空 (内存 + 文件)
- (void)clearAll;
// 仅清某分类的内存日志 (0..7 或 -2 加密组 或 -3 系统组=文件+模块), 不动落盘文件
- (void)clearCategory:(NSInteger)cat;

// ===== 噪点日志 (按板块独立桶: 加解密 / 系统; 与特征串完全相等时改投, 不进主事件流, 仍照常落盘) =====
- (NSArray<DHLogEntry *> *)snapshotNoiseMatching:(nullable NSString *)keyword board:(NSInteger)board;
- (NSUInteger)noiseCountForBoard:(NSInteger)board;
- (void)clearNoiseForBoard:(NSInteger)board;   // 仅清该板块内存, 不动落盘文件

// 日志文件路径 (落盘文件用于 share/导出)
- (NSString *)logFilePath;

// ===== 日志保留/落盘配置 (持久化到沙箱 .dh_logcfg.conf, 重启/重注入仍生效) =====
// 每类内存保留条数 (替代旧的写死 2000)。setter 立即裁剪各桶并存盘。
- (NSUInteger)maxPerCategory;
- (void)setMaxPerCategory:(NSUInteger)n;
// 单个落盘文件滚动上限 (字节); 0 = 不限。超限滚动为 .1/.2/.3 (最多 3 个备份)。setter 存盘。
- (unsigned long long)maxLogFileBytes;
- (void)setMaxLogFileBytes:(unsigned long long)bytes;
// 当前落盘总字节 = 当前段 + 所有滚动备份段之和 (供 /api/stats 与设置页展示)。
- (unsigned long long)totalLogBytes;

// 结构化事件日志路径: 每条非噪点事件追加一行 JSON, 重启/重注入后用于把最近事件回载到内存。
- (NSString *)journalFilePath;

// 立即把文本日志 + 结构化事件日志的缓冲落盘 (进入后台/退出前调用; 线程安全)。
- (void)flush;

// 事件管线健康指标: pending(已派发未处理条数)、dropped(因积压丢弃条数)、
// droppedByCategory(按分类丢弃明细)、rss(宿主进程常驻内存字节)、soft/hardLimit、
// journalBytes(结构化日志大小)、restoredEvents(本次启动回载的事件数)。
// 用于验证「长时间运行不积累」并让上层看到背压发生在什么时候。
- (NSDictionary<NSString *, id> *)pipelineStats;

// 把某分类(0..7, 或 -2=加密组, -3=系统组, -1=全部)的内存日志导出成可读文本, 供「按板块下载」。
- (NSString *)exportTextForCategory:(NSInteger)cat;

// 当前宿主进程信息 (pid/进程名/bundle/系统版本/设备型号), 一次性采集并缓存
- (NSDictionary *)processInfo;

// 大小过滤快照: 按 input 字节数落在 [minBytes, maxBytes] 内保留 (0=该端不限)
- (NSArray<DHLogEntry *> *)snapshotMatching:(nullable NSString *)keyword
                                   category:(NSInteger)categoryOrMinusOne
                               minInputSize:(NSUInteger)minBytes
                               maxInputSize:(NSUInteger)maxBytes;

@end

// ===== 工具函数 =====
NSString *DHHexFromData(NSData * _Nullable d);
NSData   *DHDataFromHex(NSString * _Nullable hex);   // hex -> bytes; 容忍 0x/空白/大小写, 奇数位末尾忽略
NSString *DHHexDumpFromData(NSData * _Nullable d);
NSString *DHUTF8FromData(NSData * _Nullable d);
NSString *DHCallStackFiltered(void);   // 已过滤系统 / 自身的调用栈
NSString *DHTimestampNow(void);

NS_ASSUME_NONNULL_END
#endif
