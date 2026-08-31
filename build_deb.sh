#!/bin/bash
# build_deb.sh — 打包 IOSDecryptHub rootless / roothide 越狱 deb
#
# dylib:
#   vendor/dylib/rootless/decrypt_helper.dylib   (arm64)
#   vendor/dylib/roothide/decrypt_helper.dylib   (arm64 + arm64e)
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
PREFS_SRC="$SCRIPT_DIR/prefs/IOSDecryptHubPrefsListController.m"
PREFS_ICON="$SCRIPT_DIR/prefs/icon.png"
WECHAT_PNG="$SCRIPT_DIR/prefs/wechat-follow.png"

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

compile_prefs() {
    local ARCHS="$1"
    local BUNDLE_DIR="$2"
    local ARCH_FLAGS=()
    local ARCH
    for ARCH in $ARCHS; do
        ARCH_FLAGS+=( -arch "$ARCH" )
    done
    info "编译设置面板 (archs=$ARCHS)..."
    mkdir -p "$BUNDLE_DIR"
    $CC "${ARCH_FLAGS[@]}" -isysroot "$SDK" -miphoneos-version-min=14.0 \
        -bundle \
        -ObjC -fobjc-arc -Wall -O2 \
        -framework Foundation -framework UIKit \
        -undefined dynamic_lookup \
        "$PREFS_SRC" -o "$BUNDLE_DIR/IOSDecryptHubPrefs"
    cp "$SCRIPT_DIR/prefs/Info.plist" "$BUNDLE_DIR/"
    cp "$SCRIPT_DIR/prefs/Root.plist" "$BUNDLE_DIR/"
    [ -f "$PREFS_ICON" ] || error "缺少 prefs/icon.png"
    cp "$PREFS_ICON" "$BUNDLE_DIR/icon.png"
    [ -f "$WECHAT_PNG" ] || error "缺少 prefs/wechat-follow.png"
    cp "$WECHAT_PNG" "$BUNDLE_DIR/wechat-follow.png"
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
    [ -f "$DYLIB" ] || error "缺少成品 dylib: $DYLIB
请先由私有仓执行 make deb，或手动把对应架构的 decrypt_helper.dylib 放到该路径。"
    verify_macho_arch "$DYLIB" "$EXPECTED_ARCH" "$VARIANT 主 dylib (vendor)"
    echo "$DYLIB"
}

build_variant() {
    local VARIANT="$1"
    local PREFIX="$2"
    local ARCHITECTURE="$3"
    local MACHO_ARCHS="$4"

    local STAGE="$BUILD_DIR/stage-$VARIANT"
    local DEB_OUT="$BUILD_DIR/${PKG_NAME}_${VERSION}_${VARIANT}.deb"
    local LOADER_OUT="$BUILD_DIR/_loader-${VARIANT}/IOSDecryptHubLoader.dylib"
    local PREFS_BUNDLE="$BUILD_DIR/_prefs-${VARIANT}/IOSDecryptHubPrefs.bundle"
    local ENGINE_DYLIB

    ENGINE_DYLIB=$(require_vendor_dylib "$VARIANT" "$MACHO_ARCHS")
    compile_loader "$MACHO_ARCHS" "$LOADER_OUT"
    compile_prefs "$MACHO_ARCHS" "$PREFS_BUNDLE"

    info "打包 $VARIANT (arch=$ARCHITECTURE, prefix=${PREFIX:-/})..."
    rm -rf "$STAGE"
    mkdir -p "$STAGE/DEBIAN"
    mkdir -p "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries"
    mkdir -p "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub"
    mkdir -p "$STAGE/${PREFIX}/Library/PreferenceBundles"
    mkdir -p "$STAGE/${PREFIX}/Library/PreferenceLoader/Preferences"

    cat > "$STAGE/DEBIAN/control" << CTRL
Package: ${PKG_NAME}
Name: IOSDecryptHub
Version: ${VERSION}
Architecture: ${ARCHITECTURE}
Description: iOS runtime security analysis tool (dylib injection via jailbreak)
Maintainer: IOSDecryptHub
Author: IOSDecryptHub
Section: Tweaks
Depends: ellekit, preferenceloader
Conflicts: com.iosdecrypthub.trollstore
CTRL

    cp "$LOADER_OUT" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    cp "$SCRIPT_DIR/Filter.plist" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist"

    cp "$ENGINE_DYLIB" "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
    cp "$SCRIPT_DIR/enabledBundles.default.plist" \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"

    cat > "$STAGE/DEBIAN/postinst" << POSTINST
#!/bin/sh
set -e
CONFIG_DIR="${PREFIX}/usr/lib/IOSDecryptHub/config"
CONFIG_PATH="\$CONFIG_DIR/enabledBundles.plist"
DEFAULT_PATH="${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"
LEGACY_PATH="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
mkdir -p "\$CONFIG_DIR"
if [ ! -f "\$CONFIG_PATH" ]; then
    if [ -f "\$LEGACY_PATH" ]; then
        cp "\$LEGACY_PATH" "\$CONFIG_PATH"
    else
        cp "\$DEFAULT_PATH" "\$CONFIG_PATH"
    fi
fi
chown mobile:mobile "\$CONFIG_DIR" "\$CONFIG_PATH" 2>/dev/null || true
chmod 0755 "\$CONFIG_DIR"
chmod 0644 "\$CONFIG_PATH"
exit 0
POSTINST
    chmod 0755 "$STAGE/DEBIAN/postinst"

    cat > "$STAGE/DEBIAN/postrm" << POSTRM
#!/bin/sh
set -e
if [ "\$1" = "purge" ]; then
    rm -rf "${PREFIX}/usr/lib/IOSDecryptHub"
    rm -f "/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
fi
exit 0
POSTRM
    chmod 0755 "$STAGE/DEBIAN/postrm"

    cp -R "$PREFS_BUNDLE" "$STAGE/${PREFIX}/Library/PreferenceBundles/"
    cp "$SCRIPT_DIR/prefs/entry.plist" "$STAGE/${PREFIX}/Library/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"

    verify_macho_arch \
        "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib" \
        "$MACHO_ARCHS" "$VARIANT 加载器"
    verify_macho_arch \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib" \
        "$MACHO_ARCHS" "$VARIANT 主 dylib"
    verify_macho_arch \
        "$STAGE/${PREFIX}/Library/PreferenceBundles/IOSDecryptHubPrefs.bundle/IOSDecryptHubPrefs" \
        "$MACHO_ARCHS" "$VARIANT 设置面板"

    ldid -S "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    ldid -S "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
    ldid -S "$STAGE/${PREFIX}/Library/PreferenceBundles/IOSDecryptHubPrefs.bundle/IOSDecryptHubPrefs"

    dpkg-deb --build --root-owner-group "$STAGE" "$DEB_OUT" >/dev/null 2>&1

    local ACTUAL_ARCH ACTUAL_DEPENDS PACKAGE_CONTENTS
    ACTUAL_ARCH=$(dpkg-deb -f "$DEB_OUT" Architecture)
    ACTUAL_DEPENDS=$(dpkg-deb -f "$DEB_OUT" Depends)
    PACKAGE_CONTENTS=$(dpkg-deb -c "$DEB_OUT")

    [ "$ACTUAL_ARCH" = "$ARCHITECTURE" ] || error "$VARIANT 架构错误: 期望 $ARCHITECTURE, 实际 $ACTUAL_ARCH"

    [ "$ACTUAL_DEPENDS" = "ellekit, preferenceloader" ] \
        || error "$VARIANT 依赖集合错误: $ACTUAL_DEPENDS"

    if [ "$VARIANT" = "roothide" ]; then
        case "$PACKAGE_CONTENTS" in
            *"./var/jb/"*) error "roothide 包不得包含固定 /var/jb 前缀" ;;
        esac
        case "$PACKAGE_CONTENTS" in
            *"./Library/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"*) ;;
            *) error "roothide 设置入口未安装到 jbroot 根路径" ;;
        esac
    else
        case "$PACKAGE_CONTENTS" in
            *"./var/jb/Library/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"*) ;;
            *) error "rootless 设置入口缺少 /var/jb 前缀" ;;
        esac
    fi

    case "$PACKAGE_CONTENTS" in
        *"/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"*) ;;
        *) error "$VARIANT 缺少设置入口" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/PreferenceBundles/IOSDecryptHubPrefs.bundle/icon.png"*) ;;
        *) error "$VARIANT 缺少设置图标" ;;
    esac

    case "$PACKAGE_CONTENTS" in
        *"/PreferenceBundles/IOSDecryptHubPrefs.bundle/wechat-follow.png"*) ;;
        *) error "$VARIANT 缺少设置页公众号物料" ;;
    esac

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

    grep -q '<string>com.apple.UIKit</string>' \
        "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist" \
        || error "$VARIANT 的 MobileLoader 过滤器未覆盖 UIKit App"

    info "✅ $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"
}

mkdir -p "$BUILD_DIR"

case "$TARGET" in
    all)
        build_variant "rootless" "/var/jb" \
            "iphoneos-arm64" "arm64"
        build_variant "roothide" "" \
            "iphoneos-arm64e" "arm64 arm64e"
        ;;
    rootless)
        build_variant "rootless" "/var/jb" \
            "iphoneos-arm64" "arm64"
        ;;
    roothide)
        build_variant "roothide" "" \
            "iphoneos-arm64e" "arm64 arm64e"
        ;;
esac

info "全部完成! 产物在: $BUILD_DIR/"
ls -lh "$BUILD_DIR"/*.deb 2>/dev/null || true
