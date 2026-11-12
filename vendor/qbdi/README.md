# QBDI (vendored) — iOS/AArch64 static build

用于越狱版 `trace_function` 的指令级 DBI 后端。

| 项 | 值 |
|---|---|
| 上游 | https://github.com/quarkslab/QBDI |
| 版本 | commit `3318580`（2026-08-21，LLVM 19.1.5） |
| 构建 | `cmake -DQBDI_PLATFORM=ios -DQBDI_ARCH=AARCH64 -DCMAKE_TOOLCHAIN_FILE=cmake/config/ios.toolchain.cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0`，Apple Silicon macOS + Xcode 26.3 构建 |
| 产物 | `lib/libQBDI.a`（静态，arm64，iOS 15.0+）；`include/QBDI/` 为源码头 + 构建生成的 `Config.h`/`Version.h`/`State.h`/`Options.h` |
| 许可 | Apache-2.0（见上游 LICENSE.txt） |

限制（沿用上游）：iOS 支持标注为 unstable、需要越狱；只构建了 **arm64** 切片，
因此含 arm64e 的 roothide 胖二进制不链接 QBDI，`trace_function` 会明确返回 unavailable。

重新构建：`bash ../../tools/build_qbdi_ios.sh`（需要 macOS + Xcode + cmake + ninja + 网络）。
