// http_server.h - IOSDecryptHub
// 极简本地 HTTP 服务, 用 BSD socket, 暴露 hook 日志给浏览器看 / 筛 / 下载.
//
// 端点:
//   GET  /                   嵌入式单页前端
//   GET  /api/stats          {total, paused, byCategory:[...], port, listen, version}
//   GET  /api/logs?cat=N&q=KW&since=SEQ&limit=N
//                            日志摘要数组 (不含 key/iv/in/out 原文, 只给元信息)
//   GET  /api/logs/:seq      单条详情 (含 hex / hexdump / 调用栈)
//   POST /api/clear          清空
//   POST /api/pause?paused=1 暂停 / 恢复
//   GET  /download           下载 decrypt_helper.log

#ifndef DH_HTTP_SERVER_H
#define DH_HTTP_SERVER_H
#import <Foundation/Foundation.h>

// 启动服务, 自动选 8088..8108 第一个空闲端口
void      dh_http_start(void);
// 返回成功绑定的端口, 0 表示未启动
uint16_t  dh_http_port(void);
// 形如 "http://127.0.0.1:8089/" (越狱版默认只绑回环; 状态目录有 listen-remote 标记才用 Wi-Fi IP)
NSString *dh_http_url(void);
// "loopback" | "any": 端口当前是否只对本机开放。MCP get_stats 报告这个值, 便于上层判断
// 「工具连不上」是网络暴露面被收紧还是服务没起来。
const char *dh_http_listen_mode(void);

#endif
