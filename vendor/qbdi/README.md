# QBDI (vendored) — iOS/AArch64 static build

用于越狱版 `trace_function` 的指令级 DBI 后端。

| 项 | 值 |
|---|---|
| 上游 | https://github.com/quarkslab/QBDI |
| 版本 | 固定 `3318580550215a0c7a64e9c2476e02eb5fc55f14`，QBDI `0.12.2-devel`，LLVM 19.1.5 |
| 构建 | `cmake -DQBDI_PLATFORM=ios -DQBDI_ARCH=AARCH64 -DCMAKE_TOOLCHAIN_FILE=cmake/config/ios.toolchain.cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0`，macOS + Xcode，分别交叉编译两个 ABI |
| 产物 | `lib/arm64/`、`lib/arm64e/` 独立库及 `lib/libQBDI.a` universal（iOS 15.0+）；源码及静态生成头 |
| 许可 | Apache-2.0（见上游 LICENSE.txt） |

1.28.35 起分别编译两种 ABI；arm64e 使用 `QBDI_PTRAUTH=ON`。两种静态 Config.h 仅允许
指针认证开关不同，合并后根据 `__arm64e__` 选择；其它差异令构建失败。
`tools/patches/qbdi-ios-arm64e-asm.patch` 修正上游 iOS 汇编硬编码 `-arch arm64`，让
CMake 使用实际请求的架构。补丁对固定上游执行 apply --check，不静默修改未知版本。

上游仍将 iOS 标为 unstable，要求越狱。Trace 是显式 replay，不还原完整线程现场、栈参数、
浮点/聚合参数、异常、信号或线程创建；时间预算仅在插桩回调协作检查，不能取消任意 native 调用。
优先对已验证的纯函数使用 `buffers` 复制输入，避免复用 App 临时指针。详见
`docs/ROOTHIDE_NATIVE_BACKENDS.md`。

重新构建：`bash ../../tools/build_qbdi_ios.sh`（需要 macOS + Xcode + cmake + ninja + 网络）。
