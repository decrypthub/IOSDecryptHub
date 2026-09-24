# vendor/dylib

本目录只放**打包用的引擎落地文件**，由 `make deb` / `make test-updater` 自动编译生成，
**不入版本库**（见 `.gitignore`）。引擎源码在本仓 `src/`。

| 路径 | 引擎变体 | 架构 |
|------|---------|------|
| `rootless/decrypt_helper.dylib` | `VARIANT=rootless` | arm64 |
| `roothide/decrypt_helper.dylib` | `VARIANT=roothide` | arm64 + arm64e |

`build_deb.sh` 从这两个路径取引擎打进 deb。缺文件时先在仓库根目录执行 `make deb`。
