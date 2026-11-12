#!/bin/bash
# 重新构建 vendor/qbdi（iOS arm64 静态库 + 头文件）。
# 需要：macOS + Xcode + cmake(3.28+) + ninja + 网络（会下载 LLVM 19.1.5 源码并交叉编译）。
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${QBDI_WORK_DIR:-/tmp/qbdi-ios}"
SRC="$WORK/QBDI"
BUILD="$WORK/build-ios"

rm -rf "$WORK"
mkdir -p "$WORK"
git clone --depth 1 https://github.com/quarkslab/QBDI "$SRC"
( cd "$SRC" && git log -1 --oneline )

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DQBDI_PLATFORM=ios \
  -DQBDI_ARCH=AARCH64 \
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

mkdir -p "$REPO/vendor/qbdi/lib" "$REPO/vendor/qbdi/include/QBDI"
cp "$BUILD/libQBDI.a" "$REPO/vendor/qbdi/lib/"
cp "$SRC"/include/QBDI/*.h "$REPO/vendor/qbdi/include/QBDI/"
cp "$BUILD"/include/QBDI/Config.h "$BUILD"/include/QBDI/Version.h \
   "$BUILD"/include/QBDI/State.h "$BUILD"/include/QBDI/Options.h \
   "$REPO/vendor/qbdi/include/QBDI/"
echo "✅ vendor/qbdi updated: $(ls -lh "$REPO/vendor/qbdi/lib/libQBDI.a" | awk '{print $5}')"
