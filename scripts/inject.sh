#!/bin/bash
# 用法: ./scripts/inject.sh <input.ipa> <hook.dylib>

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IPA=$1
DYLIB=$2
WORK_DIR="work_$$"

if [ -z "$IPA" ] || [ -z "$DYLIB" ]; then
    echo "Usage: $0 <input.ipa> <hook.dylib>"
    exit 1
fi

echo "[*] 解包 IPA..."
mkdir -p "$WORK_DIR"
cp "$DYLIB" "$WORK_DIR/"
unzip -q "$IPA" -d "$WORK_DIR"

APP=$(find "$WORK_DIR/Payload" -maxdepth 1 -name "*.app" | head -1)
if [ -z "$APP" ]; then
    echo "❌ IPA 中未找到 Payload/*.app"
    exit 1
fi
python3 "$ROOT/tools/patch_info_plist.py" "$APP/Info.plist"
APP_EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP/Info.plist")
APP_BIN="$APP/$APP_EXECUTABLE"
DYLIB_NAME=$(basename "$DYLIB")

echo "[*] 复制 dylib 到 App Bundle..."
cp "$DYLIB" "$APP/"

echo "[*] 写入 LC_LOAD_DYLIB..."
# 使用 insert_dylib（Actions 中通过 Homebrew 安装）
insert_dylib --strip-codesig --inplace \
    "@executable_path/$DYLIB_NAME" "$APP_BIN"

echo "[*] 重新打包 IPA..."
OUTPUT="hooked_$(basename $IPA)"
cd "$WORK_DIR" && zip -qr "../$OUTPUT" Payload/ && cd ..

echo "[*] 清理临时目录..."
rm -rf "$WORK_DIR"

echo "✅ 完成: $OUTPUT"
