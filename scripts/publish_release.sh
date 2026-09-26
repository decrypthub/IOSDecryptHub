#!/usr/bin/env bash
# publish_release.sh — 本地一键发版（不依赖 CI；CI 发版走 .github/workflows/release.yml）
#
# 用法:
#   ./scripts/publish_release.sh            ← 版本号取 Makefile 的 VERSION
#   ./scripts/publish_release.sh 1.27.6     ← 指定版本号（必须与 Makefile 的 VERSION 一致）
#
# 做的事:
#   1. 校验版本号与 Makefile VERSION 一致
#   2. 编译三件产物：dist dylib（巨魔变体）+ rootless/roothide 两个 deb
#   3. 确保 tag v<version> 已推送到 origin
#   4. gh release create 建 Release 并上传三件资产
#
# 前置: gh 已登录（gh auth status）、make / dpkg-deb / ldid 可用。
#       推送 tag 会触发 release.yml，但它会检测到 Release 已存在并跳过，不会重复构建。
#
# Release 说明：优先用 .github/release-notes/<version>.md（手写），
# 没有则用上一个 tag 到当前的提交标题自动生成。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

command -v gh        >/dev/null 2>&1 || error "需要 gh（brew install gh 并 gh auth login）"
command -v dpkg-deb  >/dev/null 2>&1 || error "需要 dpkg-deb（brew install dpkg）"
command -v ldid      >/dev/null 2>&1 || error "需要 ldid（brew install ldid）"
gh auth status >/dev/null 2>&1       || error "gh 未登录，先跑 gh auth login"

# ---------- 版本号 ----------
MAKE_VERSION="$(grep -E '^VERSION[[:space:]]*:=' Makefile | head -1 | sed -E 's/^VERSION[[:space:]]*:=[[:space:]]*//')"
VERSION="${1:-$MAKE_VERSION}"
TAG="v${VERSION}"
[ "$VERSION" = "$MAKE_VERSION" ] || \
    error "版本号不一致：参数=$VERSION，Makefile VERSION=$MAKE_VERSION（先改 Makefile 再发版）"

info "发布 $TAG"

# ---------- 已有 Release 就拦下 ----------
if gh release view "$TAG" >/dev/null 2>&1; then
    error "Release $TAG 已存在。要重发请先在网页或 gh release delete $TAG 删掉它"
fi

# ---------- 编译 ----------
# 顺序不能反：dist 先抄走 trollstore 变体的 decrypt_helper.dylib，
# deb 阶段会反复覆盖同名文件。
info "编译 dist dylib（巨魔变体）…"
make VARIANT=trollstore dist

info "编译两个 deb（rootless + roothide）…"
make deb

DYLIB="decrypt_helper-${VERSION}.dylib"
DEB_ROOTLESS="build/deb/com.iosdecrypthub_${VERSION}_rootless.deb"
DEB_ROOTHIDE="build/deb/com.iosdecrypthub_${VERSION}_roothide.deb"
for f in "$DYLIB" "$DEB_ROOTLESS" "$DEB_ROOTHIDE"; do
    [ -f "$f" ] || error "产物缺失: $f"
done

# ---------- tag ----------
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    warn "tag $TAG 已存在，跳过创建"
else
    git tag -a "$TAG" -m "IOSDecryptHub $TAG"
    info "已创建 tag $TAG"
fi
info "推送 tag 到 origin …"
git push origin "$TAG"

# ---------- release notes ----------
HANDWRITTEN=".github/release-notes/${VERSION}.md"
if [ -f "$HANDWRITTEN" ]; then
    NOTES="$HANDWRITTEN"
else
    PREV="$(git tag --sort=-v:refname | grep -vx "$TAG" | head -1 || true)"
    NOTES="$(mktemp)"
    {
        echo "## IOSDecryptHub $TAG"
        echo
        if [ -n "$PREV" ]; then
            echo "自 $PREV 以来的改动："
            echo
            git log --no-merges --pretty='- %s' "$PREV..HEAD"
        else
            echo "首次发布。"
        fi
    } > "$NOTES"
    warn "没有 $HANDWRITTEN，用提交记录自动生成说明（建议下次手写）"
fi

# ---------- 创建 Release ----------
# tag 已经推上去了，所以不需要 --target。
info "创建 Release 并上传三件资产 …"
gh release create "$TAG" \
    --title "IOSDecryptHub $TAG" \
    --notes-file "$NOTES" \
    "$DYLIB" "$DEB_ROOTLESS" "$DEB_ROOTHIDE"

info "✅ 完成:"
gh release view "$TAG" --json url,assets --jq '.url, (.assets[] | "  \(.name)  \(.size) bytes")'
