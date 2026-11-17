#!/bin/bash
# 构建 iOS arm64 / arm64e（后者启用 QBDI_PTRAUTH），不重标记 arm64 产物。
# 需要：macOS + Xcode + cmake(3.28+) + ninja + 网络（会下载 LLVM 19.1.5 源码并交叉编译）。
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${QBDI_WORK_DIR:-/tmp/qbdi-ios}"
mkdir -p "$WORK"
RUN=$(mktemp -d "$WORK/idh-build.XXXXXX")
SRC="$RUN/QBDI"
REV=3318580550215a0c7a64e9c2476e02eb5fc55f14
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/quarkslab/QBDI
git -C "$SRC" fetch --depth 1 origin "$REV"
git -C "$SRC" checkout -q --detach FETCH_HEAD
git -C "$SRC" apply --check "$REPO/tools/patches/qbdi-ios-arm64e-asm.patch"
git -C "$SRC" apply "$REPO/tools/patches/qbdi-ios-arm64e-asm.patch"
git -C "$SRC" apply --check "$REPO/tools/patches/qbdi-controlled-native-boundary.patch"
git -C "$SRC" apply "$REPO/tools/patches/qbdi-controlled-native-boundary.patch"
mkdir -p "$REPO/vendor/qbdi/lib" "$REPO/vendor/qbdi/include/QBDI"
for ARCH in arm64 arm64e; do
BUILD="$RUN/build-$ARCH"
PAC=OFF
if [ "$ARCH" = arm64e ]; then PAC=ON; fi

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DQBDI_PLATFORM=ios \
  -DQBDI_ARCH=AARCH64 \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DQBDI_PTRAUTH="$PAC" \
  -DQBDI_THIRD_PARTY_DIRECTORY="$WORK/downloads" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$SRC/cmake/config/ios.toolchain.cmake" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DQBDI_TOOLS_FRIDAQBDI=OFF \
  -DQBDI_TOOLS_PYQBDI=OFF \
  -DQBDI_TOOLS_QBDIPRELOAD=OFF \
  -DQBDI_TOOLS_VALIDATOR=OFF \
  -DQBDI_EXAMPLES=OFF \
  -DQBDI_TEST=OFF \
  -DQBDI_CCACHE=OFF
cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu)"
test "$(xcrun lipo -archs "$BUILD/libQBDI.a")" = "$ARCH"
mkdir -p "$REPO/vendor/qbdi/lib/$ARCH"
cp "$BUILD/libQBDI.a" "$REPO/vendor/qbdi/lib/$ARCH/"
done
xcrun lipo -create "$REPO/vendor/qbdi/lib/arm64/libQBDI.a" \
  "$REPO/vendor/qbdi/lib/arm64e/libQBDI.a" -output "$REPO/vendor/qbdi/lib/libQBDI.a"
xcrun lipo "$REPO/vendor/qbdi/lib/libQBDI.a" -verify_arch arm64 arm64e
cp "$SRC"/include/QBDI/*.h "$REPO/vendor/qbdi/include/QBDI/"
# Config.h 按静态/动态库分别生成；本仓链接 libQBDI.a，使用静态配置。
python3 "$REPO/tools/qbdi_universal_config.py" \
  "$RUN/build-arm64/include-static/QBDI/Config.h" \
  "$RUN/build-arm64e/include-static/QBDI/Config.h" \
  "$REPO/vendor/qbdi/include/QBDI/Config.h"
cp "$BUILD"/include/QBDI/Version.h \
   "$BUILD"/include/QBDI/State.h "$BUILD"/include/QBDI/Options.h \
   "$REPO/vendor/qbdi/include/QBDI/"
printf '%s\n' "$REV" > "$REPO/vendor/qbdi/lib/source-revision.txt"
echo "✅ vendor/qbdi updated: $(ls -lh "$REPO/vendor/qbdi/lib/libQBDI.a" | awk '{print $5}')"
