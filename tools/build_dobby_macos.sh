#!/bin/bash
# Native Swift scheduler tests use a separate macOS library; never replace the
# arm64/arm64e iOS product libraries with a host-architecture build.
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${DOBBY_MAC_WORK_DIR:-/tmp/dobby-macos}"
mkdir -p "$WORK"
RUN=$(mktemp -d "$WORK/idh-build.XXXXXX")
SRC="$RUN/Dobby"
REV=5dfc8546954ce3b3198132ab13fddb89ee92cdd7
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/jmpews/Dobby
git -C "$SRC" fetch --depth 1 origin "$REV"
git -C "$SRC" checkout -q --detach FETCH_HEAD
for PATCH in dobby-publish-original-before-patch dobby-quiescent-code-patch dobby-context-entry; do
    git -C "$SRC" apply --check "$REPO/tools/patches/$PATCH.patch"
    git -C "$SRC" apply "$REPO/tools/patches/$PATCH.patch"
done
cmake -S "$SRC" -B "$RUN/build" -G Ninja \
    -DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_SYSTEM_PROCESSOR=arm64 -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DCMAKE_BUILD_TYPE=Release \
    -DDOBBY_DEBUG=OFF -DDOBBY_BUILD_EXAMPLE=OFF -DDOBBY_BUILD_TEST=OFF
cmake --build "$RUN/build" -j"$(sysctl -n hw.ncpu)"
test "$(xcrun lipo -archs "$RUN/build/libdobby.a")" = arm64
mkdir -p "$REPO/vendor/dobby/lib/macos-arm64" "$REPO/vendor/dobby/include"
cp "$RUN/build/libdobby.a" "$REPO/vendor/dobby/lib/macos-arm64/"
cp "$SRC/include/dobby.h" "$REPO/vendor/dobby/include/"
printf '%s\n' "$REV" > "$REPO/vendor/dobby/lib/macos-arm64/source-revision.txt"
