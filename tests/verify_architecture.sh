#!/bin/bash

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
    echo "架构检查需要 rg；当前环境未安装或不在 PATH" >&2
    exit 2
fi

PASS=0
FAIL=0

ok(){ printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
ng(){ printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

expect_absent() {
    local label="$1"
    local pattern="$2"
    shift 2
    local output
    output=$(rg -n "$pattern" "$@" 2>/dev/null || true)
    if [[ -z "$output" ]]; then
        ok "$label"
    else
        ng "$label"
        printf '%s\n' "$output"
    fi
}

expect_present() {
    local label="$1"
    local pattern="$2"
    shift 2
    if rg -q "$pattern" "$@"; then ok "$label"; else ng "$label"; fi
}

echo "== Hook 技术边界 =="
expect_absent "无越狱框架 Hook API 调用" \
    'MSHook(Function|MessageEx)[[:space:]]*\(|LHHook(Function|Functions)[[:space:]]*\(' \
    src --glob '!core/capstone/**'
expect_absent "无 Logos %hook" '^[[:space:]]*%hook([[:space:]]|$)' src
expect_absent "共享核心不引入越狱框架头文件" \
    '^[[:space:]]*#[[:space:]]*(include|import).*(substrate|ellekit|libhooker)' src -i
expect_absent "不引入 Frida/Stalker 运行时" \
    '^[[:space:]]*#[[:space:]]*(include|import).*(Frida|Stalker)' src -i
expect_present "Inline/QBDI 后端编入正式 dylib" \
    'DDH_HAVE_INLINE=1 -DDH_HAVE_QBDI=1' Makefile
expect_present "Inline Hook 经统一 thunk 实现" \
    'DobbyHook[[:space:]]*\(' src/core/dh_thunk.m
expect_present "QBDI 经统一控制入口暴露" \
    'DHQBDITraceFunction' src/server/mcp_server.m

echo "== 共享核心边界 =="
expect_absent "共享核心不引用 daemon 接口" \
    '^[[:space:]]*#[[:space:]]*(include|import).*dh_server|xpc_connection_create_mach_service' src
expect_present "存在 fishhook 实现" 'rebind_symbols' src/core/fishhook.c
expect_present "存在 ObjC swizzle 实现" 'method_setImplementation|method_exchangeImplementations' src

echo "== 服务与协议边界 =="
expect_present "HTTP 首选端口保持 8088" '^#define DH_HTTP_PORT_FIRST[[:space:]]+8088$' src/server/http_server.m
expect_present "MCP 路径保持 /api/mcp" '"/api/mcp"' src/server/http_server.m

echo "== 设备会话与应用工具边界 =="
expect_present "设备会话端口固定 8088" \
    '^#define IDH_SESSION_PORT[[:space:]]+8088$' src/session/idh_session_ipc.h
expect_present "会话变体为设备服务保留 8088" \
    'firstPort = DH_HTTP_PORT_FIRST \+ 1' src/server/http_server.m
expect_present "会话上报不阻断进程工具服务" \
    '\(void\)dh_session_agent_start' src/core/main.m
expect_absent "会话模式不跳过程序内 HTTP" \
    'if[[:space:]]*\(dh_session_agent_start[[:space:]]*\([^)]*\)[[:space:]]*\)[[:space:]]*return' src/core/main.m
expect_present "守护进程提供设备面板" 'kDHDaemonPanelHTML' daemon/idh_session_http.m
expect_present "设备健康检查保持免鉴权" 'EqualToString:@"/health"' daemon/idh_session_http.m
expect_present "在线登记独立于采集" 'agent_presence' daemon/idh_session_service.m
expect_present "进程工具经守护进程转发" 'forwardTool' daemon/idh_session_service.h
expect_present "Agent 上报进程工具端口" 'presence\[@"httpPort"\]' src/core/dh_session_agent.m
expect_present "设备服务实现进程身份查询" 'get_process_identity.*processIdentity' daemon/idh_session_service.m
expect_present "进程 HTTP 工具经设备服务代理" 'serveToolProxy' daemon/idh_session_http.m
expect_present "工具代理下载按流转发" 'relayUpstreamResponse' daemon/idh_session_http.m
expect_present "事件按 App 连续归档" 'CREATE TABLE IF NOT EXISTS app_events' daemon/idh_session_store.m
expect_present "事件分页保持有界" 'limit > 500' daemon/idh_session_store.m
expect_present "注入范围拒绝系统 bundle" 'com.apple.' daemon/idh_device_apps.m
expect_present "局域网监听需要显式标记" 'IDHSessionRemotePath' daemon/idhjd.m
expect_present "进程工具跟随 idhjd 的局域网标记" \
    'DH_LISTEN_REMOTE_PATH "/private/var/db/idhjd-v1/listen-remote"' src/server/http_server.m
expect_present "进程工具端口默认只绑回环" \
    'dh_listen_remote_enabled\(\) \? htonl\(INADDR_ANY\) : htonl\(INADDR_LOOPBACK\)' src/server/http_server.m
expect_present "统计接口报告监听范围" 'dh_http_listen_mode' src/server/mcp_server.m

echo "== constructor 顺序 =="
main_file="src/core/main.m"
warm_line=$(rg -n '\(void\)DHTimestampNow[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
hook_line=$(rg -n 'dh_install_all_hooks[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
http_line=$(rg -n 'dh_http_start[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
if [[ -n "$warm_line" && -n "$hook_line" && -n "$http_line" \
      && "$warm_line" -lt "$hook_line" && "$hook_line" -lt "$http_line" ]]; then
    ok "预热 -> 安装 Hook -> HTTP 启动顺序保持不变"
else
    ng "无法确认 constructor 启动顺序"
fi

echo ""
printf '架构检查结果: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
