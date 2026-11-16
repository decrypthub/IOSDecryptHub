#!/bin/bash
# 构建真正的 iOS arm64 / arm64e 静态切片，再合并 universal 库。
# 需要：macOS + Xcode + cmake + ninja + 网络。
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${DOBBY_WORK_DIR:-/tmp/dobby-ios}"
mkdir -p "$WORK"
RUN=$(mktemp -d "$WORK/idh-build.XXXXXX")
SRC="$RUN/Dobby"
REV=5dfc8546954ce3b3198132ab13fddb89ee92cdd7
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/jmpews/Dobby
git -C "$SRC" fetch --depth 1 origin "$REV"
git -C "$SRC" checkout -q --detach FETCH_HEAD
git -C "$SRC" apply --check "$REPO/tools/patches/dobby-publish-original-before-patch.patch"
git -C "$SRC" apply "$REPO/tools/patches/dobby-publish-original-before-patch.patch"
git -C "$SRC" apply --check "$REPO/tools/patches/dobby-quiescent-code-patch.patch"
git -C "$SRC" apply "$REPO/tools/patches/dobby-quiescent-code-patch.patch"
mkdir -p "$REPO/vendor/dobby/lib" "$REPO/vendor/dobby/include"
for ARCH in arm64 arm64e; do
BUILD="$RUN/build-$ARCH"
cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_SYSTEM_PROCESSOR=arm64 \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_DEBUG=OFF \
  -DDOBBY_BUILD_EXAMPLE=OFF \
  -DDOBBY_BUILD_TEST=OFF
cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu)"
test "$(xcrun lipo -archs "$BUILD/libdobby.a")" = "$ARCH"
mkdir -p "$REPO/vendor/dobby/lib/$ARCH"
cp "$BUILD/libdobby.a" "$REPO/vendor/dobby/lib/$ARCH/"
done
xcrun lipo -create "$REPO/vendor/dobby/lib/arm64/libdobby.a" \
  "$REPO/vendor/dobby/lib/arm64e/libdobby.a" -output "$REPO/vendor/dobby/lib/libdobby.a"
xcrun lipo "$REPO/vendor/dobby/lib/libdobby.a" -verify_arch arm64 arm64e
cp "$SRC/include/dobby.h" "$REPO/vendor/dobby/include/"
printf '%s\n' "$REV" > "$REPO/vendor/dobby/lib/source-revision.txt"
echo "✅ vendor/dobby updated: $(ls -lh "$REPO/vendor/dobby/lib/libdobby.a" | awk '{print $5}')"
