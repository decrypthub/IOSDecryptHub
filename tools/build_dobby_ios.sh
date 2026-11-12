#!/bin/bash
# 重新构建 vendor/dobby（iOS arm64 静态库 + 头文件）。
# 需要：macOS + Xcode + cmake + ninja + 网络。
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${DOBBY_WORK_DIR:-/tmp/dobby-ios}"
SRC="$WORK/Dobby"
BUILD="$WORK/build-ios"

rm -rf "$WORK"
mkdir -p "$WORK"
git clone --depth 1 https://github.com/jmpews/Dobby "$SRC"
( cd "$SRC" && git log -1 --oneline )

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_SYSTEM_PROCESSOR=arm64 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_DEBUG=OFF \
  -DDOBBY_BUILD_EXAMPLE=OFF \
  -DDOBBY_BUILD_TEST=OFF
cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu)"

mkdir -p "$REPO/vendor/dobby/lib" "$REPO/vendor/dobby/include"
cp "$BUILD/libdobby.a" "$REPO/vendor/dobby/lib/"
cp "$SRC/include/dobby.h" "$REPO/vendor/dobby/include/"
echo "✅ vendor/dobby updated: $(ls -lh "$REPO/vendor/dobby/lib/libdobby.a" | awk '{print $5}')"
