#!/bin/bash
# device_test.sh — 真机（越狱 L4）验收驱动：SSH 触发场景 + MCP 断言
#
# 不另起测试套件（路线图 §3.1）：
#   - 场景来自 tests/scenarios.json 中 platforms 含 device 的条目，与 macOS/模拟器同源
#   - MCP 工具与参数沿用 tests/mcp_test.sh 的约定
#   - 报告复用 tests/test_helpers.sh 的 dh_write_results（manifest / junit）
#   - 触发走宿主注册的 dhtest:// URL scheme，全程无需手点屏幕
#
# 用法:
#   ./tests/device_test.sh --host 192.168.200.162 --label rootless-ios16.6
#   ./tests/device_test.sh --host 192.168.200.148 --prefix "" --label roothide-ios16.2
#
# 前提: 主包已安装（提供 loader+引擎）且宿主 bundleID 在启用名单里；
#       未满足时脚本会直接给出修复命令（scripts/device_install.sh ...）。

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST=""; PREFIX="/var/jb"; SSH_USER="root"; KEY="$HOME/.ssh/id_dh_test"; LABEL=""
SKIP_LAUNCH=0
BUNDLE_ID="com.taisuii.cryptotesthost"
APP_NAME="CryptoTestHost"
SCENARIOS="$ROOT/tests/scenarios.json"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)        HOST="$2"; shift 2 ;;
        --prefix)      PREFIX="$2"; shift 2 ;;
        --user)        SSH_USER="$2"; shift 2 ;;
        --key)         KEY="$2"; shift 2 ;;
        --label)       LABEL="$2"; shift 2 ;;
        --skip-launch) SKIP_LAUNCH=1; shift ;;
        -h|--help)     sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done
[ -n "$HOST" ] || { echo "缺少 --host"; exit 1; }
[ -n "$LABEL" ] || LABEL="device"

RESULT_DIR="${DH_TEST_RESULTS_DIR:-$ROOT/build/test-results/device-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$RESULT_DIR"
# shellcheck source=tests/test_helpers.sh
source "$ROOT/tests/test_helpers.sh"

ENGINE_DIR="${PREFIX}/usr/lib/IOSDecryptHub"
APP_DIR="${PREFIX}/Applications"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "${SSH_USER}@${HOST}")

PASS=0
FAIL=0
ok(){ printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
ng(){ printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
eq(){ if [[ "$1" = "$2" ]]; then ok "$3"; else ng "$3 (期望=$2 实得=$1)"; fi; }

if command -v jq >/dev/null; then :; else echo "缺少 jq"; exit 2; fi

# ---------- 前置 ----------
echo "[前置] $HOST  prefix=${PREFIX:-/}"
"${SSH[@]}" 'true' 2>/dev/null || { echo "SSH 连不上 $HOST"; exit 2; }

PKG_VERSION="$("${SSH[@]}" "dpkg -l com.iosdecrypthub 2>/dev/null | tail -1" | tr -s ' ' | cut -d' ' -f3)"
[ -n "$PKG_VERSION" ] || { echo "设备上没有 com.iosdecrypthub；先装包：
  ./scripts/device_install.sh --host $HOST --pkg '$ROOT/build/deb/com.iosdecrypthub_<version>_rootless.deb'"; exit 2; }
ok "主包已安装 (版本 $PKG_VERSION)"

"${SSH[@]}" "[ -d '$APP_DIR/$APP_NAME.app' ]" || { echo "测试宿主未安装；先执行：
  ./scripts/device_install.sh --host $HOST${PREFIX:+ --prefix '$PREFIX'}"; exit 2; }
ok "测试宿主已安装"

ENABLED="$("${SSH[@]}" "grep -c '$BUNDLE_ID' '$ENGINE_DIR/config/enabledBundles.plist' 2>/dev/null || echo 0")"
[ "${ENABLED:-0}" -ge 1 ] || { echo "宿主未在启用名单里；先执行：
  ./scripts/device_install.sh --host $HOST --enable"; exit 2; }
ok "宿主在启用名单里"

# 设备事实（写进报告，便于追溯）
{
    "${SSH[@]}" 'uname -a'
    "${SSH[@]}" "grep -A1 -E 'ProductVersion|ProductBuildVersion' /System/Library/CoreServices/SystemVersion.plist 2>/dev/null | grep string | tr -d '\t'"
    "${SSH[@]}" "readlink /var/jb 2>/dev/null || echo '（无 /var/jb）'"
    echo "pkg_version=$PKG_VERSION"
} > "$RESULT_DIR/device.txt" 2>&1
echo "[前置] 设备: $(tr '\n' ' ' < "$RESULT_DIR/device.txt" | cut -c1-140)..."

# ---------- 拉起宿主并等 MCP ----------
# 附着优先：宿主已经在跑（例如用户手点了图标）就直接用，不为难 launchd。
# 程序化前台拉起在锁屏/未解锁时会被 iOS 挂起 —— 进程有、代码不跑，这时只能靠手点。
if dh_device_wait_mcp "$HOST" "$BUNDLE_ID" 3; then
    echo "[启动] 宿主已在运行，直接附着（不重启）"
elif [[ "$SKIP_LAUNCH" -eq 0 ]]; then
    echo "[启动] 拉起宿主并等待 MCP"
    "${SSH[@]}" "killall $APP_NAME 2>/dev/null; (uiopen --url 'dhtest://chkdyld' >/dev/null 2>&1 &)" || true
fi
if ! dh_device_wait_mcp "$HOST" "$BUNDLE_ID" 40; then
    ng "宿主 MCP 未就绪（8088 无响应）"
    echo "      可能原因：loader 未注入（名单/过滤器）、引擎 dlopen 失败、App 未启动"
    echo "      排查：ssh $SSH_USER@$HOST 'syslog | grep IOSDecryptHub'"
    dh_write_results "device-jb" "$PASS" "$FAIL" "device-$LABEL"
    exit 1
fi
ok "宿主 MCP 就绪 (http://$HOST:8088/api/mcp)"

# ---------- 场景 ----------
run_scenario() {
    local id="$1" trigger="$2" timeout_ms="$3"
    shift 3
    local expected=("$@")
    local deadline=$(( $(date +%s%N) / 1000000 + timeout_ms ))
    printf '  ... %s (trigger=%s, 上限 %sms)\n' "$id" "$trigger" "$timeout_ms" >&2
    local snap="$RESULT_DIR/$id.json"

    dh_device_tool "$HOST" clear_events '{"category":"all"}' >/dev/null 2>&1
    # 后台执行：uiopen 会等 App 起来，App 起不来不能把 SSH 会话拖住
    "${SSH[@]}" "(uiopen --url 'dhtest://$trigger' >/dev/null 2>&1 &)" || true

    local found=""
    while :; do
        found="$(dh_device_algorithms "$HOST")"
        if [[ ${#expected[@]} -eq 0 ]]; then
            # 负例（注入可见性）：等一段稳定期，确认没有新事件
            if [[ -n "$found" ]]; then break; fi
            if (( $(date +%s%N) / 1000000 >= deadline )); then break; fi
        else
            local all_seen=1 e
            for e in "${expected[@]}"; do
                grep -qxF "$e" <<< "$found" || { all_seen=0; break; }
            done
            [[ "$all_seen" -eq 1 ]] && break
            if (( $(date +%s%N) / 1000000 >= deadline )); then break; fi
        fi
        sleep 0.3
    done
    dh_device_tool "$HOST" query_events '{"limit":1000}' > "$snap" 2>/dev/null

    if [[ ${#expected[@]} -eq 0 ]]; then
        if [[ -z "$found" ]]; then ok "$id （负例：未产生事件）"
        else ng "$id （负例：本不该有事件，实得: $(tr '\n' ',' <<< "$found")）"; fi
        return
    fi
    local e miss=""
    for e in "${expected[@]}"; do
        grep -qxF "$e" <<< "$found" || miss="$miss $e"
    done
    if [[ -z "$miss" ]]; then ok "$id （$(tr '\n' ',' <<< "$found" | sed 's/,$//')）"
    else ng "$id （缺:$miss / 实得: $(tr '\n' ',' <<< "$found")）"; fi
}

echo "[场景] tests/scenarios.json 中 platforms 含 device 的条目"
while IFS=$'\t' read -r id trigger timeout_ms expected; do
    # shellcheck disable=SC2206
    mapfile -t exp <<< "$expected"
    [[ -z "${exp[0]:-}" ]] && exp=()
    run_scenario "$id" "$trigger" "$timeout_ms" "${exp[@]}"
done < <(python3 - "$SCENARIOS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for s in d["scenarios"]:
    if "device" not in s.get("platforms", []):
        continue
    print("\t".join([s["id"], s["trigger"], str(s.get("timeout_ms", 8000)),
                     "\n".join(s.get("expected_events", []))]))
PY
)

# ---------- 诊断快照与报告 ----------
dh_device_tool "$HOST" get_diag '{}' > "$RESULT_DIR/diagnostics.json" 2>/dev/null || true
dh_device_tool "$HOST" get_stats '{}' > "$RESULT_DIR/stats.json" 2>/dev/null || true
eq "$(jq -r '.result.isError // "missing"' "$RESULT_DIR/diagnostics.json" 2>/dev/null)" "false" "get_diag 可导出"

dh_write_results "device-jb" "$PASS" "$FAIL" "device-$LABEL"
printf 'device 验收(%s): PASS=%d FAIL=%d\n' "$LABEL" "$PASS" "$FAIL"
printf '[results] %s\n' "$RESULT_DIR"
[[ "$FAIL" -eq 0 ]]
