#!/bin/bash
# Optional native host QBDI for the real CPU/control-flow tests. This output is
# separate from the iOS arm64/arm64e product library.
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${QBDI_MAC_WORK_DIR:-/tmp/qbdi-macos}"
mkdir -p "$WORK"
RUN=$(mktemp -d "$WORK/idh-build.XXXXXX")
SRC="$RUN/QBDI"
REV=3318580550215a0c7a64e9c2476e02eb5fc55f14
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/quarkslab/QBDI
git -C "$SRC" fetch --depth 1 origin "$REV"
git -C "$SRC" checkout -q --detach FETCH_HEAD
git -C "$SRC" apply --check "$REPO/tools/patches/qbdi-controlled-native-boundary.patch"
git -C "$SRC" apply "$REPO/tools/patches/qbdi-controlled-native-boundary.patch"
cmake -S "$SRC" -B "$RUN/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DQBDI_PLATFORM=macos -DQBDI_ARCH=AARCH64 -DQBDI_PTRAUTH=OFF \
    -DCMAKE_CROSSCOMPILING=FALSE \
    -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
    -DQBDI_THIRD_PARTY_DIRECTORY="$WORK/downloads" \
    -DQBDI_TOOLS_FRIDAQBDI=OFF -DQBDI_TOOLS_PYQBDI=OFF \
    -DQBDI_TOOLS_QBDIPRELOAD=OFF -DQBDI_TOOLS_VALIDATOR=OFF \
    -DQBDI_EXAMPLES=OFF -DQBDI_TEST=OFF -DQBDI_CCACHE=OFF
cmake --build "$RUN/build" -j"$(sysctl -n hw.ncpu)"
test "$(xcrun lipo -archs "$RUN/build/libQBDI.a")" = arm64
DEST="$REPO/vendor/qbdi/macos-arm64"
mkdir -p "$DEST/lib" "$DEST/include/QBDI"
cp "$RUN/build/libQBDI.a" "$DEST/lib/"
cp "$SRC"/include/QBDI/*.h "$DEST/include/QBDI/"
cp "$RUN/build/include/QBDI/State.h" "$RUN/build/include/QBDI/Options.h" \
    "$RUN/build/include/QBDI/Version.h" "$DEST/include/QBDI/"
cp "$RUN/build/include-static/QBDI/Config.h" "$DEST/include/QBDI/"
printf '%s\n' "$REV" > "$DEST/lib/source-revision.txt"
