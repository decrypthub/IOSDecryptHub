// mcp_server.h — MCP (Model Context Protocol) 服务器
//
// 实现 MCP 的 JSON-RPC 2.0 消息层, 通过 HTTP (Streamable HTTP 传输) 暴露给 AI 客户端。
// 支持的方法: initialize / notifications/initialized / ping / tools/list / tools/call。
// 工具: disassemble / analyze_function / list_imports / get_macho_info。

#ifndef MCP_SERVER_H
#define MCP_SERVER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface MCPServer : NSObject

// 处理单条 JSON-RPC 消息。
// 返回应答字典 (调用方序列化为 JSON); 若入参是「通知」(无 id) 则返回 nil, 表示无应答体。
+ (nullable NSDictionary *)handleMessage:(NSDictionary *)message;

// 本进程的 MCP 会话 id (initialize 时下发, 客户端后续请求回带)。
+ (NSString *)sessionId;

@end

NS_ASSUME_NONNULL_END

#endif // MCP_SERVER_H
