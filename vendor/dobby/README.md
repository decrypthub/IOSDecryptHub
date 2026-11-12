# Dobby (vendored) — iOS/arm64 static build

用于越狱版 `hook_inline` 的内联 hook 后端。

| 项 | 值 |
|---|---|
| 上游 | https://github.com/jmpews/Dobby |
| 版本 | commit `5dfc854`（2026-11-13 拉取） |
| 构建 | `cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_PROCESSOR=arm64 -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release -DDOBBY_DEBUG=OFF -DDOBBY_BUILD_EXAMPLE=OFF -DDOBBY_BUILD_TEST=OFF` |
| 产物 | `lib/libdobby.a`（静态，arm64，iOS 14.0+）；`include/dobby.h` |
| 许可 | Apache-2.0（见上游 LICENSE） |

限制：只构建了 **arm64** 切片；含 arm64e 的 roothide 胖二进制不链接 Dobby，
`hook_inline` 会明确返回 unavailable（不静默降级）。

重新构建：`bash ../../tools/build_dobby_ios.sh`。
