#!/bin/bash
# 兼容旧 deb 入口，转交 IOSDecryptHub 自己的完整构建。
# 不修改其它仓库版本，不跨仓复制引擎或产物。
set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "[x] 用法: $0 [all|rootless|roothide]" >&2
    exit 1
fi

case "${1:-all}" in
    all) MAKE_TARGET=deb ;;
    rootless) MAKE_TARGET=deb-rootless ;;
    roothide) MAKE_TARGET=deb-roothide ;;
    *) echo "[x] 未知目标: $1 (可选: all / rootless / roothide)" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec make -C "$REPO_ROOT" "$MAKE_TARGET"
