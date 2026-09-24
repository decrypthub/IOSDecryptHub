// dh_health.h — 进程级「健康状态中心」(fail-loud 基础设施)
//
// 设计目标: 把 hook 没挂上 / 落盘失败 / HTTP 服务失败这类「失效」集中收集,
// 让悬浮窗与 Web 面板能一眼看见、精确定位失效锚点 —— 而不是偷偷兜底造成「时好时坏」。
//
// 纯 C 接口: fishhook.c(纯 C) 与各 ObjC 文件都能调用。内部用 stdatomic + 互斥,
// 零外部依赖, 不引入 Foundation。

#ifndef DH_HEALTH_H
#define DH_HEALTH_H

#ifdef __cplusplus
extern "C" {
#endif

// 诊断板块 —— 审查日志按板块分桶 + 各自落盘, 便于按模块定位问题。
typedef enum {
    DH_DIAG_GENERAL = 0,   // 启动 / 服务 / 落盘 等通用
    DH_DIAG_CRYPTO,        // 加解密
    DH_DIAG_FILE,          // 文件
    DH_DIAG_SYS,           // 系统
    DH_DIAG_DUMP,          // 砸壳
    DH_DIAG_BOARD_COUNT
} dh_diag_board;

// 各 .m 可在 #import "dh_health.h" 之前 #define DH_BOARD DH_DIAG_xxx 指定本文件板块;
// 未指定则归 GENERAL。DH_ERR 据此把错误投到对应板块诊断。
#ifndef DH_BOARD
#define DH_BOARD DH_DIAG_GENERAL
#endif

// 统一错误日志宏 —— 仅在 ObjC 文件(.m)里使用(依赖 NSLog)。
// 双写: 控制台 NSLog + 进程级诊断日志(可在 Web 面板「审查日志」按板块查看/导出溯源)。
// 纯 C 文件(.c)请直接调用 dh_health_* / dh_diag_append, 内部已写 stderr + 诊断日志。
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#define DH_ERR(fmt, ...) do { \
    NSString *_dh_m = [NSString stringWithFormat:(fmt), ##__VA_ARGS__]; \
    NSLog(@"[IOSDecryptHub/ERR] %@", _dh_m); \
    dh_diag_append(DH_BOARD, "ERR", _dh_m.UTF8String); \
} while (0)
#endif

// 线程局部递归保护: hook 记录路径会用 Foundation API(NSDateFormatter/backtrace 等),
// 其内部可能再触发同类系统调用(open/dlopen 被 os_log/locale 内部调用); 置 1 时各 hook
// 直接放行不记录, 防止递归死锁。
extern __thread int dh_in_hook;

// ---- 上报失效 ----
void dh_health_hook_fail(int board, const char *sym);  // 某符号没挂上, 归到 board 板块诊断
void dh_health_persist_fail(int err);           // 日志落盘失败 (errno)
void dh_health_http_fail(const char *reason);   // HTTP 服务起不来
void dh_health_http_ok(void);                   // HTTP 服务成功启动, 清除失败态
void dh_health_note_localonly(void);            // 只拿到 127.0.0.1, 仅本地可访问 (info, 非错误)

// ---- 查询状态 ----
unsigned    dh_health_hook_fail_count(void);
int         dh_health_persist_failed(void);     // 0/1
int         dh_health_http_failed(void);        // 0/1
int         dh_health_local_only(void);         // 0/1

// 给 UI / Web 的简短摘要(顶部红字横幅)。只含真正的运行时失效: 服务失败/落盘失败。
// hook 未挂上不计入此摘要(对真实 App 多为「该 App 没用此 API」的常态, 见 dh_diag_*),
// 避免误报淹没真正的告警。无问题返回 "" (空串)。返回内部静态缓冲, 调用方应尽快拷贝。
const char *dh_health_summary(void);

// ---- 诊断日志(审查日志): 进程级环形缓冲, 收集所有内部错误/事件供开发者复制溯源 ----
// 纯 C, 互斥保护, 不依赖 Foundation。各上报口与 DH_ERR 宏都会写入这里, 形成时间线。
// level 例如 "ERR" / "WARN" / "INFO"; msg 为单行文本(过长会截断)。线程安全。
// 设置诊断落盘目录(传 Documents 路径), 应在装 hook 前调用; 之后各板块追加写
// <dir>/.dh_diag_<board>.log, 重启/崩溃后仍可取。
void dh_diag_set_dir(const char *docsDir);
void dh_diag_append(int board, const char *level, const char *msg);
// 返回诊断全文(board>=0 仅该板块; board<0 全部板块, 每段带小标题)。
// 每行 "[HH:MM:SS] LEVEL: msg"。返回内部静态缓冲, 调用方应尽快拷贝。
const char *dh_diag_dump(int board);
// 未挂上的符号清单(逗号分隔), 供诊断头部展示; 无则返回 ""。
const char *dh_health_hook_unhooked(void);

#ifdef __cplusplus
}
#endif

#endif // DH_HEALTH_H
