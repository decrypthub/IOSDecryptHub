#!/bin/bash
# build_deb.sh — 打包 IOSDecryptHub rootless / roothide 越狱 deb
#
# dylib（引擎，由本仓源码编译后落在 vendor/ 下）:
#   vendor/dylib/rootless/decrypt_helper.dylib   (arm64)
#   vendor/dylib/roothide/decrypt_helper.dylib   (arm64 + arm64e)
#
# 包内组件:
#   IOSDecryptHubLoader.dylib  ElleKit 注入加载器（读名单 → dlopen 引擎，无 hook）
#   decrypt_helper.dylib       运行时分析引擎（本仓 src/ 编译产物）
#   IOSDecryptHubManager.app   管理器 App（唯一入口：应用开关 / 更新 / 关于）
#   IOSDecryptHubUpdated       updater daemon，一次性进程（检查/安装/回滚），见 AGENTS.md
#
# 设置面板（PreferenceBundle）已移除：与管理器 App 功能重复，只保留 App 一个入口。
#
# 用法:
#   ./build_deb.sh              # 构建全部目标
#   ./build_deb.sh rootless     # 仅普通 rootless
#   ./build_deb.sh roothide     # 仅 roothide
#
# 前提: macOS + Xcode (xcrun) + dpkg-deb + ldid
# 产物: build/deb/com.iosdecrypthub_<version>_<目标>.deb

set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "[x] 用法: $0 [all|rootless|roothide]" >&2
    exit 1
fi

TARGET="${1:-all}"
case "$TARGET" in
    all|rootless|roothide) ;;
    *)
        echo "[x] 未知目标: $TARGET (可选: all / rootless / roothide)" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/deb"
VENDOR_DIR="$SCRIPT_DIR/vendor/dylib"
VERSION=$(grep '^VERSION' "$SCRIPT_DIR/Makefile" | head -1 | sed 's/.*:= *//')
PKG_NAME="com.iosdecrypthub"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

command -v dpkg-deb >/dev/null 2>&1 || error "需要 dpkg-deb (brew install dpkg)"
command -v xcrun >/dev/null 2>&1 || error "需要 Xcode (xcrun)"
command -v ldid >/dev/null 2>&1 || error "需要 ldid (brew install ldid)"
[ -n "$VERSION" ] || error "无法读取 Makefile VERSION"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --find clang)
LOADER_SRC="$SCRIPT_DIR/src/loader.m"
APP_ICON="$SCRIPT_DIR/app/Icon.png"
APP_WECHAT="$SCRIPT_DIR/app/wechat-follow.png"
APP_SRCS="$SCRIPT_DIR/app/DHManagerAppDelegate.m $SCRIPT_DIR/app/DHRootViewController.m $SCRIPT_DIR/app/DHSettingsViewController.m $SCRIPT_DIR/app/DHVersionsViewController.m $SCRIPT_DIR/app/DHConfigStore.m $SCRIPT_DIR/app/DHAppEnumerator.m"
APP_INFO="$SCRIPT_DIR/app/Info.plist"
APP_ENTITLEMENTS="$SCRIPT_DIR/app/entitlements.plist"
DAEMON_SRC="$SCRIPT_DIR/daemon/main.m"
DAEMON_PLIST_TMPL="$SCRIPT_DIR/daemon/com.iosdecrypthub.updated.plist"
REPO_KEY="$SCRIPT_DIR/repo/iosdecrypthub-archive-keyring.gpg"
APP_NAME="IOSDecryptHubManager"
DAEMON_BIN="IOSDecryptHubUpdated"

compile_loader() {
    local ARCHS="$1"
    local OUT="$2"
    local ARCH_FLAGS=()
    local ARCH
    for ARCH in $ARCHS; do
        ARCH_FLAGS+=( -arch "$ARCH" )
    done
    info "编译越狱加载器 (archs=$ARCHS)..."
    mkdir -p "$(dirname "$OUT")"
    $CC "${ARCH_FLAGS[@]}" -isysroot "$SDK" -miphoneos-version-min=14.0 \
        -dynamiclib -install_name /usr/lib/IOSDecryptHub/IOSDecryptHubLoader.dylib \
        -ObjC -fobjc-arc -Wall -O2 \
        -framework Foundation \
        "$LOADER_SRC" -o "$OUT"
}

compile_app() {
    local ARCHS="$1"
    local OUT="$2"
    local ARCH_FLAGS=()
    local ARCH
    for ARCH in $ARCHS; do
        ARCH_FLAGS+=( -arch "$ARCH" )
    done
    info "编译管理器 App (archs=$ARCHS)..."
    mkdir -p "$(dirname "$OUT")"
    # shellcheck disable=SC2086
    $CC "${ARCH_FLAGS[@]}" -isysroot "$SDK" -miphoneos-version-min=14.0 \
        -ObjC -fobjc-arc -Wall -O2 \
        -I"$SCRIPT_DIR/src" \
        -framework Foundation -framework UIKit -framework CoreGraphics \
        $APP_SRCS -o "$OUT"
}

compile_daemon() {
    local ARCHS="$1"
    local OUT="$2"
    local ARCH_FLAGS=()
    local ARCH
    for ARCH in $ARCHS; do
        ARCH_FLAGS+=( -arch "$ARCH" )
    done
    info "编译 updater daemon (archs=$ARCHS)..."
    mkdir -p "$(dirname "$OUT")"
    $CC "${ARCH_FLAGS[@]}" -isysroot "$SDK" -miphoneos-version-min=14.0 \
        -ObjC -fobjc-arc -Wall -O2 \
        -I"$SCRIPT_DIR/src" \
        -framework Foundation \
        "$DAEMON_SRC" -o "$OUT"
}

verify_macho_arch() {
    local PATH_TO_VERIFY="$1"
    local EXPECTED_ARCH="$2"
    local LABEL="$3"
    local ACTUAL_ARCHS

    ACTUAL_ARCHS=$(xcrun lipo -archs "$PATH_TO_VERIFY")
    [ "$ACTUAL_ARCHS" = "$EXPECTED_ARCH" ] \
        || error "$LABEL 架构错误: 期望 $EXPECTED_ARCH, 实际 $ACTUAL_ARCHS"
}

require_vendor_dylib() {
    local VARIANT="$1"
    local EXPECTED_ARCH="$2"
    local DYLIB="$VENDOR_DIR/$VARIANT/decrypt_helper.dylib"
    [ -f "$DYLIB" ] || error "缺少引擎: $DYLIB
请先在仓库根目录执行 make deb（会自动编译引擎并落到 vendor/dylib/），
或手动把对应架构的 decrypt_helper.dylib 放到该路径。"
    verify_macho_arch "$DYLIB" "$EXPECTED_ARCH" "$VARIANT 主 dylib (vendor)"
    echo "$DYLIB"
}

build_variant() {
    local VARIANT="$1"
    local PREFIX="$2"
    local ARCHITECTURE="$3"
    local MACHO_ARCHS="$4"
    # 管理器 App 与 updater daemon 是独立进程，arm64 单切片即可运行；
    # roothide 用胖切片以匹配其全 arm64e 要求。
    local APP_MACHO_ARCHS="${5:-$MACHO_ARCHS}"

    local STAGE="$BUILD_DIR/stage-$VARIANT"
    local DEB_OUT="$BUILD_DIR/${PKG_NAME}_${VERSION}_${VARIANT}.deb"
    local LOADER_OUT="$BUILD_DIR/_loader-${VARIANT}/IOSDecryptHubLoader.dylib"
    local APP_EXEC="$BUILD_DIR/_app-${VARIANT}/$APP_NAME"
    local DAEMON_OUT="$BUILD_DIR/_daemon-${VARIANT}/$DAEMON_BIN"
    local ENGINE_DYLIB

    ENGINE_DYLIB=$(require_vendor_dylib "$VARIANT" "$MACHO_ARCHS")
    compile_loader "$MACHO_ARCHS" "$LOADER_OUT"
    compile_app "$APP_MACHO_ARCHS" "$APP_EXEC"
    compile_daemon "$APP_MACHO_ARCHS" "$DAEMON_OUT"

    info "打包 $VARIANT (arch=$ARCHITECTURE, prefix=${PREFIX:-/})..."
    rm -rf "$STAGE"
    # SMB 等网络卷 chmod 无效（文件全是 700），dpkg-deb 会拒绝打包：
    # 真正的打包树放在本地临时目录并在那里修正权限；断言仍读 $STAGE（内容一致）。
    local PKG_STAGE="${TMPDIR:-/tmp}/dhstage-$VARIANT"
    rm -rf "$PKG_STAGE"
    mkdir -p "$STAGE/DEBIAN"
    mkdir -p "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries"
    mkdir -p "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub"
    mkdir -p "$STAGE/${PREFIX}/Applications/$APP_NAME.app"
    mkdir -p "$STAGE/${PREFIX}/Library/LaunchDaemons"
    mkdir -p "$STAGE/${PREFIX}/etc/apt/trusted.gpg.d"

    cat > "$STAGE/DEBIAN/control" << CTRL
Package: ${PKG_NAME}
Name: IOSDecryptHub
Version: ${VERSION}
Architecture: ${ARCHITECTURE}
Description: iOS 运行时安全分析工具 — 注入目标 App 后实时查看加解密明文、密钥、文件与网络行为（WebUI + MCP）
Maintainer: IOSDecryptHub
Author: IOSDecryptHub
Section: Tweaks
Depends: ellekit
Conflicts: com.iosdecrypthub.trollstore
CTRL

    cp "$LOADER_OUT" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    cp "$SCRIPT_DIR/Filter.plist" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist"

    cp "$ENGINE_DYLIB" "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
    cp "$SCRIPT_DIR/enabledBundles.default.plist" \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"
    cp "$DAEMON_OUT" "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/$DAEMON_BIN"
    cp "$SCRIPT_DIR/daemon/updated.sh" "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/updated.sh"

    # 仓库公钥装进 APT 信任链：不然现代 APT 会因 Release 未受信任而报 E:
    # （"is not signed"）并拒绝更新索引 —— 用户就永远看不到新版本。
    [ -f "$REPO_KEY" ] || error "缺少仓库公钥: $REPO_KEY"
    cp "$REPO_KEY" "$STAGE/${PREFIX}/etc/apt/trusted.gpg.d/iosdecrypthub.gpg"

    cat > "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/version.plist" << VP
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>version</key>
    <string>${VERSION}</string>
    <key>variant</key>
    <string>${VARIANT}</string>
    <key>arch</key>
    <string>${MACHO_ARCHS}</string>
</dict>
</plist>
VP

    sed "s|@PREFIX@|${PREFIX}|g" "$DAEMON_PLIST_TMPL" \
        > "$STAGE/${PREFIX}/Library/LaunchDaemons/com.iosdecrypthub.updated.plist"

    cp "$APP_EXEC" "$STAGE/${PREFIX}/Applications/$APP_NAME.app/$APP_NAME"
    sed "s/@VERSION@/${VERSION}/g" "$APP_INFO" \
        > "$STAGE/${PREFIX}/Applications/$APP_NAME.app/Info.plist"
    [ -f "$APP_ICON" ] || error "缺少 app/Icon.png (App 图标)"
    [ -f "$APP_WECHAT" ] || error "缺少 app/wechat-follow.png（App 里的公众号引导）"
    # 桌面图标按标准三档出图：只给一张 120×120 时部分系统/缩放档位会渲染成空白
    local APP_ICON_DIR="$STAGE/${PREFIX}/Applications/$APP_NAME.app"
    cp "$APP_WECHAT" "$APP_ICON_DIR/wechat-follow.png"
    cp "$APP_ICON" "$APP_ICON_DIR/Icon.png"
    sips -z 60 60 "$APP_ICON" --out "$APP_ICON_DIR/Icon.png" >/dev/null 2>&1 || true
    sips -z 120 120 "$APP_ICON" --out "$APP_ICON_DIR/Icon@2x.png" >/dev/null 2>&1 || true
    sips -z 180 180 "$APP_ICON" --out "$APP_ICON_DIR/Icon@3x.png" >/dev/null 2>&1 || true
    [ -f "$APP_ICON_DIR/Icon@2x.png" ] || error "App 图标生成失败"
    [ -f "$APP_ICON_DIR/Icon@3x.png" ] || error "App 图标生成失败"

    cat > "$STAGE/DEBIAN/postinst" << POSTINST
#!/bin/sh
set -e
CONFIG_DIR="${PREFIX}/usr/lib/IOSDecryptHub/config"
CONFIG_PATH="\$CONFIG_DIR/enabledBundles.plist"
DEFAULT_PATH="${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"
LEGACY_PATH="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
mkdir -p "\$CONFIG_DIR"
LOADER_PREFS="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
# 沙盒目标读 jb 这份。默认以 prefs(管理器 UI 写的) 为准; 但如果 jb 侧配置比 prefs 新,
# 说明有人直接改了 jb 文件(运维/脚本), 就反向同步回 prefs —— 否则手动加的 App 会被静默还原。
if [ -f "\$LOADER_PREFS" ]; then
    if [ -f "\$CONFIG_PATH" ] && [ "\$CONFIG_PATH" -nt "\$LOADER_PREFS" ]; then
        cp "\$CONFIG_PATH" "\$LOADER_PREFS"
    else
        cp "\$LOADER_PREFS" "\$CONFIG_PATH"
    fi
elif [ ! -f "\$CONFIG_PATH" ]; then
    if [ -f "\$LEGACY_PATH" ]; then
        cp "\$LEGACY_PATH" "\$CONFIG_PATH"
    else
        cp "\$DEFAULT_PATH" "\$CONFIG_PATH"
    fi
fi
chown mobile:mobile "\$CONFIG_DIR" "\$CONFIG_PATH" 2>/dev/null || true
chmod 0777 "\$CONFIG_DIR"
chmod 0666 "\$CONFIG_PATH"
mkdir -p /var/mobile/Library/Caches/com.iosdecrypthub
chown mobile:mobile /var/mobile/Library/Caches/com.iosdecrypthub 2>/dev/null || true
chmod 0777 /var/mobile/Library/Caches/com.iosdecrypthub
# 设备上还没有 prefs 时，从 jb 拷一份给管理器当初始名单。
if [ ! -f "\$LOADER_PREFS" ] && [ -f "\$CONFIG_PATH" ]; then
    cp "\$CONFIG_PATH" "\$LOADER_PREFS"
fi
if [ -f "\$LOADER_PREFS" ]; then
    chown mobile:mobile "\$LOADER_PREFS" 2>/dev/null || true
    chmod 0644 "\$LOADER_PREFS"
fi
rm -f /var/mobile/Library/Preferences/com.iosdecrypthub.enabledBundles.plist
ENGINE_DIR="${PREFIX}/usr/lib/IOSDecryptHub"
# 引擎与 updater 由 root 专属管理（daemon 写，App 只读）
chown root:wheel "\$ENGINE_DIR" "\$ENGINE_DIR"/decrypt_helper.dylib* "\$ENGINE_DIR"/$DAEMON_BIN "\$ENGINE_DIR"/version.plist 2>/dev/null || true
chmod 0755 "\$ENGINE_DIR" "\$ENGINE_DIR"/decrypt_helper.dylib "\$ENGINE_DIR"/$DAEMON_BIN 2>/dev/null || true
chmod 0644 "\$ENGINE_DIR"/version.plist 2>/dev/null || true
# daemon 状态文件（root 写 0644，App 读）
STATE_PATH="\$ENGINE_DIR/state.plist"
if [ ! -f "\$STATE_PATH" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict/></plist>' > "\$STATE_PATH"
fi
chmod 0644 "\$STATE_PATH" 2>/dev/null || true
# 更新请求文件（mobile 可写，daemon 读；launchd WatchPaths 依赖它事先存在）
REQUEST_PATH="/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
if [ ! -f "\$REQUEST_PATH" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict><key>action</key><string>none</string></dict></plist>' > "\$REQUEST_PATH"
fi
chown mobile:mobile "\$REQUEST_PATH" 2>/dev/null || true
chmod 0644 "\$REQUEST_PATH" 2>/dev/null || true
# jb config 请求文件：App 一定能写；updated.sh 会在 daemon 前转交到 REQUEST_PATH。
JB_REQUEST_PATH="${PREFIX}/usr/lib/IOSDecryptHub/config/updater.request.plist"
if [ ! -f "\$JB_REQUEST_PATH" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict><key>action</key><string>none</string></dict></plist>' > "\$JB_REQUEST_PATH"
fi
chown mobile:mobile "\$JB_REQUEST_PATH" 2>/dev/null || true
chmod 0666 "\$JB_REQUEST_PATH" 2>/dev/null || true
# App 共享缓存目录里的请求文件：roothide 下 App 一定可写。
CACHE_REQUEST_PATH="/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist"
if [ ! -f "\$CACHE_REQUEST_PATH" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict><key>action</key><string>none</string></dict></plist>' > "\$CACHE_REQUEST_PATH"
fi
chown mobile:mobile "\$CACHE_REQUEST_PATH" 2>/dev/null || true
chmod 0666 "\$CACHE_REQUEST_PATH" 2>/dev/null || true
# rootHide 在 jbroot=/ 时会把 LaunchDaemon 里的路径改写成 .jbroot-*/...，
# launchd exec 返回 78（实测）。改用 /bin/sh 执行短路径脚本，
# WatchPaths 盯 App 实际写入的 /var/mobile（不要走 .jbroot 前缀）。
LAUNCHD_PLIST="${PREFIX}/Library/LaunchDaemons/com.iosdecrypthub.updated.plist"
printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
    '<plist version="1.0"><dict>' \
    '<key>Label</key><string>com.iosdecrypthub.updated</string>' \
    '<key>ProgramArguments</key><array>' \
    '<string>/bin/sh</string>' \
    "<string>${PREFIX}/usr/lib/IOSDecryptHub/updated.sh</string>" \
    '</array>' \
    '<key>WatchPaths</key><array>' \
    '<string>/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist</string>' \
    '<string>/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist</string>' \
    '<string>/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist</string>' \
    "<string>${PREFIX}/usr/lib/IOSDecryptHub/config/updater.request.plist</string>" \
    '</array>' \
    '<key>StartInterval</key><integer>43200</integer>' \
    '<key>RunAtLoad</key><false/>' \
    '<key>StandardOutPath</key><string>/var/log/iosdecrypthub-updated.log</string>' \
    '<key>StandardErrorPath</key><string>/var/log/iosdecrypthub-updated.log</string>' \
    '</dict></plist>' > "\$LAUNCHD_PLIST"
if command -v launchctl >/dev/null 2>&1; then
    launchctl bootout system "\$LAUNCHD_PLIST" 2>/dev/null || true
    launchctl bootstrap system "\$LAUNCHD_PLIST" 2>/dev/null || launchctl load "\$LAUNCHD_PLIST" 2>/dev/null || true
fi
# 刷新主屏幕图标（失败不阻断安装）
if command -v uicache >/dev/null 2>&1; then
    uicache -p "${PREFIX}/Applications/$APP_NAME.app" 2>/dev/null || true
fi
exit 0
POSTINST
    chmod 0755 "$STAGE/DEBIAN/postinst"

    cat > "$STAGE/DEBIAN/postrm" << POSTRM
#!/bin/sh
set -e
if [ "\$1" = "remove" ]; then
    LAUNCHD_PLIST="${PREFIX}/Library/LaunchDaemons/com.iosdecrypthub.updated.plist"
    if command -v launchctl >/dev/null 2>&1; then
        launchctl bootout system "\$LAUNCHD_PLIST" 2>/dev/null || true
    fi
fi
if [ "\$1" = "purge" ]; then
    rm -rf "${PREFIX}/usr/lib/IOSDecryptHub"
    rm -f "/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
    rm -f "/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
fi
exit 0
POSTRM
    chmod 0755 "$STAGE/DEBIAN/postrm"

    verify_macho_arch \
        "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib" \
        "$MACHO_ARCHS" "$VARIANT 加载器"
    verify_macho_arch \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib" \
        "$MACHO_ARCHS" "$VARIANT 主 dylib"
    verify_macho_arch \
        "$STAGE/${PREFIX}/Applications/$APP_NAME.app/$APP_NAME" \
        "$APP_MACHO_ARCHS" "$VARIANT 管理器 App"
    verify_macho_arch \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/$DAEMON_BIN" \
        "$APP_MACHO_ARCHS" "$VARIANT updater daemon"

    ldid -S "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    ldid -S "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
    ldid -S"$APP_ENTITLEMENTS" "$STAGE/${PREFIX}/Applications/$APP_NAME.app/$APP_NAME"
    ldid -S "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/$DAEMON_BIN"

    cp -R "$STAGE/." "$PKG_STAGE/"
    find "$PKG_STAGE" -type d -exec chmod 0755 {} +
    find "$PKG_STAGE" -type f -exec chmod 0644 {} +
    chmod 0755 "$PKG_STAGE/DEBIAN"
    chmod 0755 "$PKG_STAGE/DEBIAN"/postinst "$PKG_STAGE/DEBIAN"/postrm
    chmod 0755 "$PKG_STAGE/${PREFIX}/Applications/$APP_NAME.app/$APP_NAME"
    chmod 0755 "$PKG_STAGE/${PREFIX}/usr/lib/IOSDecryptHub/$DAEMON_BIN"
    chmod 0755 "$PKG_STAGE/${PREFIX}/usr/lib/IOSDecryptHub/updated.sh"
    # 两个 dylib 用 0755：与 1.24.8 / 1.24.9（线上已验证可用）的权限完全一致，
    # 不引入任何与已验证产物不同的变量。
    chmod 0755 "$PKG_STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    chmod 0755 "$PKG_STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"

    if ! dpkg-deb --build --root-owner-group "$PKG_STAGE" "$DEB_OUT" 2>"$BUILD_DIR/_dpkg-$VARIANT.log"; then
        rm -rf "$PKG_STAGE"
        error "$VARIANT dpkg-deb 失败: $(head -3 "$BUILD_DIR/_dpkg-$VARIANT.log")"
    fi
    rm -rf "$PKG_STAGE"

    local ACTUAL_ARCH ACTUAL_DEPENDS PACKAGE_CONTENTS
    ACTUAL_ARCH=$(dpkg-deb -f "$DEB_OUT" Architecture)
    ACTUAL_DEPENDS=$(dpkg-deb -f "$DEB_OUT" Depends)
    PACKAGE_CONTENTS=$(dpkg-deb -c "$DEB_OUT")

    [ "$ACTUAL_ARCH" = "$ARCHITECTURE" ] || error "$VARIANT 架构错误: 期望 $ARCHITECTURE, 实际 $ACTUAL_ARCH"

    [ "$ACTUAL_DEPENDS" = "ellekit" ] \
        || error "$VARIANT 依赖集合错误: $ACTUAL_DEPENDS"

    if [ "$VARIANT" = "roothide" ]; then
        case "$PACKAGE_CONTENTS" in
            *"./var/jb/"*) error "roothide 包不得包含固定 /var/jb 前缀" ;;
        esac
    fi

    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/enabledBundles.default.plist"*) ;;
        *) error "$VARIANT 缺少内置门控配置模板" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/decrypt_helper.dylib"*) ;;
        *) error "$VARIANT 缺少主 dylib" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"*) ;;
        *) error "$VARIANT 缺少加载器" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/Applications/$APP_NAME.app/$APP_NAME"*) ;;
        *) error "$VARIANT 缺少管理器 App" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/Applications/$APP_NAME.app/Info.plist"*) ;;
        *) error "$VARIANT 缺少 App Info.plist" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/Applications/$APP_NAME.app/wechat-follow.png"*) ;;
        *) error "$VARIANT 缺少 App 内公众号引导图" ;;
    esac

    for ICON_NAME in Icon.png Icon@2x.png Icon@3x.png; do
        case "$PACKAGE_CONTENTS" in
            *"/Applications/$APP_NAME.app/$ICON_NAME"*) ;;
            *) error "$VARIANT 缺少桌面图标 $ICON_NAME" ;;
        esac
    done

    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/$DAEMON_BIN"*) ;;
        *) error "$VARIANT 缺少 updater daemon" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/updated.sh"*) ;;
        *) error "$VARIANT 缺少 updater 包装脚本" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/Library/LaunchDaemons/com.iosdecrypthub.updated.plist"*) ;;
        *) error "$VARIANT 缺少 daemon 启动配置" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/version.plist"*) ;;
        *) error "$VARIANT 缺少引擎版本文件" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/etc/apt/trusted.gpg.d/iosdecrypthub.gpg"*) ;;
        *) error "$VARIANT 缺少仓库公钥（APT 会拒绝更新索引）" ;;
    esac

    grep -q '<string>com.apple.UIKit</string>' \
        "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist" \
        || error "$VARIANT 的 MobileLoader 过滤器未覆盖 UIKit App"

    grep -q '<string>com.iosdecrypthub.updated</string>' \
        "$STAGE/${PREFIX}/Library/LaunchDaemons/com.iosdecrypthub.updated.plist" \
        || error "$VARIANT 的 daemon 启动配置 Label 错误"

    grep -q "<string>${PREFIX}/usr/lib/IOSDecryptHub/updated.sh</string>" \
        "$STAGE/${PREFIX}/Library/LaunchDaemons/com.iosdecrypthub.updated.plist" \
        || error "$VARIANT 的 daemon 可执行路径与前缀不一致"

    grep -q "<string>${VERSION}</string>" \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/version.plist" \
        || error "$VARIANT 的引擎版本文件未写入当前版本"
    grep -q "<string>${VARIANT}</string>" \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/version.plist" \
        || error "$VARIANT 的引擎版本文件未写入变体名"

    grep -q "<string>${VERSION}</string>" \
        "$STAGE/${PREFIX}/Applications/$APP_NAME.app/Info.plist" \
        || error "$VARIANT 的 App Info.plist 未写入当前版本"

    info "✅ $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"
}

mkdir -p "$BUILD_DIR"

case "$TARGET" in
    all)
        build_variant "rootless" "/var/jb" \
            "iphoneos-arm64" "arm64" "arm64"
        build_variant "roothide" "" \
            "iphoneos-arm64e" "arm64 arm64e" "arm64 arm64e"
        ;;
    rootless)
        build_variant "rootless" "/var/jb" \
            "iphoneos-arm64" "arm64" "arm64"
        ;;
    roothide)
        build_variant "roothide" "" \
            "iphoneos-arm64e" "arm64 arm64e" "arm64 arm64e"
        ;;
esac

info "全部完成! 产物在: $BUILD_DIR/"
ls -lh "$BUILD_DIR"/*.deb 2>/dev/null || true
