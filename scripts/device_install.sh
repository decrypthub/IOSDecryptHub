#!/bin/bash
# device_install.sh — 把测试宿主装到真机（同一个 sim_uitest，不另起测试工程）
#
# 路线图 §3.1 要求真机验收复用同一测试宿主；本脚本给它加"真机形态"：
#   iphoneos SDK 编译 → ldid 签名 → scp 进 <prefix>/Applications → uicache 注册
# 场景 ID 与 tests/scenarios.json 同源；触发走宿主注册的 dhtest:// URL scheme，
# 因此设备侧可以全程无人值守（不需要手点屏幕）。
#
# 用法:
#   ./scripts/device_install.sh --host 192.168.200.162                 # rootless
#   ./scripts/device_install.sh --host 192.168.200.148 --prefix ""      # roothide（jbroot = /）
#   ./scripts/device_install.sh --host IP --pkg <deb> --enable --launch
#
# 选项:
#   --host IP     设备 IP（必填）
#   --prefix P    越狱前缀：rootless=/var/jb（默认），roothide 传空串
#   --user U      SSH 用户（默认 root）
#   --key PATH    SSH 私钥（默认 ~/.ssh/id_dh_test）
#   --pkg PATH    顺带安装主包 deb（dev 测试包）
#   --enable      把宿主 bundleID 加进启用名单（保留原有条目）
#   --launch      装完拉起宿主并等 MCP 就绪
#   --no-build    跳过编译，用已有产物

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST=""
PREFIX="/var/jb"
SSH_USER="root"
KEY="$HOME/.ssh/id_dh_test"
PKG=""
DO_ENABLE=0
DO_LAUNCH=0
DO_BUILD=1

BUNDLE_ID="com.taisuii.cryptotesthost"
APP_NAME="CryptoTestHost"
BUILD_DIR="$ROOT/build/device"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
MIN_IOS="14.0"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)     HOST="$2"; shift 2 ;;
        --prefix)   PREFIX="$2"; shift 2 ;;
        --user)     SSH_USER="$2"; shift 2 ;;
        --key)      KEY="$2"; shift 2 ;;
        --pkg)      PKG="$2"; shift 2 ;;
        --enable)   DO_ENABLE=1; shift ;;
        --launch)   DO_LAUNCH=1; shift ;;
        --no-build) DO_BUILD=0; shift ;;
        -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
        *) die "未知参数: $1" ;;
    esac
done
[ -n "$HOST" ] || die "缺少 --host（设备 IP）"
[ -f "$KEY" ] || die "找不到 SSH 私钥: $KEY"

APP_DIR="${PREFIX}/Applications"
ENGINE_DIR="${PREFIX}/usr/lib/IOSDecryptHub"

SSH=(ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "${SSH_USER}@${HOST}")
SCP=(scp -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)

info "设备: ${HOST}  prefix=${PREFIX:-/}  host=${APP_DIR}/${APP_NAME}.app"
"${SSH[@]}" 'true' || die "SSH 连不上 ${HOST}"

# ---------- 1) 编译宿主 ----------
if [[ "$DO_BUILD" -eq 1 ]]; then
    SDK="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)"
    [ -n "$SDK" ] || die "找不到 iPhoneOS SDK（需要 Xcode）"
    CC="$(xcrun --find clang)"
    LDid="$(command -v ldid || true)"
    [ -n "$LDid" ] || die "找不到 ldid（brew install ldid）"

    info "编译测试宿主 (iphoneos, arm64, min=${MIN_IOS})..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$APP_BUNDLE"
    # 授予 platform-application：实测普通（无 entitlement）签名的 App 装进
    # <jbroot>/Applications 后只被创建进程、不执行代码（Documents 空、构造函数探针不落盘），
    # 无法用来做验收。沙盒状态差异记在报告里，结论按"平台化 App"口径解读。
    "$CC" -arch arm64 -isysroot "$SDK" -miphoneos-version-min="$MIN_IOS" \
        -fobjc-arc -ObjC -O1 \
        -framework UIKit -framework Foundation -framework Security -framework AdSupport \
        sim_uitest/main.m -o "$APP_BUNDLE/$APP_NAME"
    cp sim_uitest/Info.plist "$APP_BUNDLE/"
    # sim_uitest/Info.plist 是给模拟器用的，里面写着 CFBundleSupportedPlatforms=[iPhoneSimulator]、
    # DTPlatformName=iphonesimulator —— 真机上 LaunchServices 会因此直接拒绝启动（进程都不创建，
    # uicache 却注册成功，表现为"怎么点都没反应"）。设备形态必须改写这两个键。
    python3 - "$APP_BUNDLE/Info.plist" <<'PYEOF'
import plistlib, sys
path = sys.argv[1]
with open(path, 'rb') as fh:
    info = plistlib.load(fh)
info['CFBundleSupportedPlatforms'] = ['iPhoneOS']
info['DTPlatformName'] = 'iphoneos'
with open(path, 'wb') as fh:
    plistlib.dump(info, fh)
print('    Info.plist 平台声明 → iPhoneOS')
PYEOF
    [ -f sim_uitest/AppIcon60x60@2x.png ] && cp sim_uitest/AppIcon60x60@2x.png "$APP_BUNDLE/"
    # 用与产品 App（IOSDecryptHubManager）完全相同的 entitlement 签名：
    # 只有这样，宿主里跑出来的"能否写越狱路径"结论才等于 App 的处境。
    APP_ENT="$ROOT/app/entitlements.plist"
    if [ -f "$APP_ENT" ]; then
        "$LDid" -S"$APP_ENT" "$APP_BUNDLE/$APP_NAME"
    else
        "$LDid" -S "$APP_BUNDLE/$APP_NAME"
    fi
    info "✅ 宿主: $APP_BUNDLE ($(xcrun lipo -archs "$APP_BUNDLE/$APP_NAME"))"
fi

[ -d "$APP_BUNDLE" ] || die "没有宿主产物，去掉 --no-build 重新编译"

# ---------- 2) 推送并注册 ----------
info "推送宿主到设备..."
"${SSH[@]}" "mkdir -p '$APP_DIR'"
"${SCP[@]}" -rq "$APP_BUNDLE" "${SSH_USER}@${HOST}:$APP_DIR/" || die "推送失败"
# scp 会把本地权限一起带过去，而本仓在 SMB 卷上所有文件都是 700 —— mobile 读不了自己的
# bundle，uicache 就不会注册，App 也就起不来（表现为"拉起无进程、无崩溃报告"）。
# bundle 只有三个文件，逐个显式修权限，不依赖设备上是否装了 find。
REMOTE_APP="$APP_DIR/$APP_NAME.app"
"${SSH[@]}" "chmod 0755 '$REMOTE_APP'; chmod 0755 '$REMOTE_APP/$APP_NAME'; chmod 0644 '$REMOTE_APP/Info.plist'; [ -f '$REMOTE_APP/AppIcon60x60@2x.png' ] && chmod 0644 '$REMOTE_APP/AppIcon60x60@2x.png'; chown -R root:wheel '$REMOTE_APP'; ls -l '$REMOTE_APP'"

info "注册到 LaunchServices..."
UICACHE_OUT="$("${SSH[@]}" "uicache -p '$REMOTE_APP'; uicache -l 2>/dev/null | grep -c '$BUNDLE_ID'" 2>&1)"
if printf '%s' "$UICACHE_OUT" | tail -1 | grep -qE '^[1-9]'; then
    info "✅ 已注册: $REMOTE_APP"
else
    die "uicache 未注册成功（uicache -l 里找不到 $BUNDLE_ID）
  uicache 输出: $(printf '%s' "$UICACHE_OUT" | tr '\n' ' ')"
fi

# ---------- 3) 可选：装主包 ----------
if [ -n "$PKG" ]; then
    [ -f "$PKG" ] || die "找不到 deb: $PKG"
    info "安装主包 $(basename "$PKG")..."
    "${SCP[@]}" -q "$PKG" "${SSH_USER}@${HOST}:/var/mobile/dh-devtest.deb"
    "${SSH[@]}" "dpkg -i /var/mobile/dh-devtest.deb; rm -f /var/mobile/dh-devtest.deb"
    "${SSH[@]}" "dpkg -l com.iosdecrypthub | tail -1"
fi

# ---------- 4) 可选：写启用名单 ----------
if [ "$DO_ENABLE" -eq 1 ]; then
    info "把 $BUNDLE_ID 加进启用名单（保留原有条目）..."
    TMP="$(mktemp -d)"
    # 设备上的 plist 工具不可靠（rootless 的 /usr/bin 是 procursus，没有 plutil），
    # 所以拉到 Mac 上用 python3 合并，再推回去 —— 只做文本搬运，不依赖设备工具。
    if "${SSH[@]}" "[ -f '$ENGINE_DIR/config/enabledBundles.plist' ]"; then
        "${SCP[@]}" -q "${SSH_USER}@${HOST}:$ENGINE_DIR/config/enabledBundles.plist" "$TMP/enabled.plist"
    fi
    python3 - "$TMP/enabled.plist" "$BUNDLE_ID" <<'PY'
import plistlib, sys, os
path, bundle = sys.argv[1], sys.argv[2]
data = {"enabledBundles": []}
if os.path.exists(path) and os.path.getsize(path) > 0:
    try:
        with open(path, 'rb') as fh:
            loaded = plistlib.load(fh)
        if isinstance(loaded, dict) and isinstance(loaded.get("enabledBundles"), list):
            data = loaded
    except Exception:
        pass
ids = [x for x in data.get("enabledBundles", []) if isinstance(x, str)]
if bundle not in ids:
    ids.append(bundle)
data["enabledBundles"] = sorted(ids)
with open(path, 'wb') as fh:
    plistlib.dump(data, fh)
print("名单:", data["enabledBundles"])
PY
    "${SSH[@]}" "mkdir -p '$ENGINE_DIR/config'"
    "${SCP[@]}" -q "$TMP/enabled.plist" "${SSH_USER}@${HOST}:$ENGINE_DIR/config/enabledBundles.plist"
    "${SSH[@]}" "chown mobile:mobile '$ENGINE_DIR/config/enabledBundles.plist' 2>/dev/null; chmod 0644 '$ENGINE_DIR/config/enabledBundles.plist'"
    rm -rf "$TMP"
    info "✅ 名单已写入"
fi

# ---------- 5) 可选：拉起并等 MCP ----------
if [ "$DO_LAUNCH" -eq 1 ]; then
    info "拉起宿主..."
    # 用 URL scheme 拉起：既启动 App 又触发一个无害动作（chkdyld = 注入可见性探测）
    "${SSH[@]}" "killall $APP_NAME 2>/dev/null; (uiopen --url 'dhtest://chkdyld' >/dev/null 2>&1 &)" || warn "拉起命令返回非 0"
    MCP="http://${HOST}:8088/api/mcp"
    for i in $(seq 1 60); do
        got="$(curl -sf --max-time 2 -X POST "$MCP" -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' 2>/dev/null \
            | jq -r '.result.structuredContent.process.bundleId // empty' 2>/dev/null || true)"
        if [ "$got" = "$BUNDLE_ID" ]; then
            info "✅ MCP 就绪（宿主已在跑）: $MCP"
            exit 0
        fi
        sleep 0.5
    done
    die "等待 MCP 超时：宿主起来了但 8088 无响应（可能是加载器没注入，检查启用名单与 loader）"
fi

info "完成"
