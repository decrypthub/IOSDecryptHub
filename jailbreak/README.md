# 越狱整包兼容入口

本目录保留旧命令入口，统一转交本仓根目录的完整构建：`all` → `make deb`、`rootless` → `make deb-rootless`、`roothide` → `make deb-roothide`。

本仓 `make deb` 自动编译并打包 Manager、Loader、引擎与 updater。准备 Dobby/QBDI 依赖、完整构建和验证步骤见 [README](../README.md)。兼容脚本不会修改版本、从巨魔仓复制引擎或把产物同步到另一套源码。

产品与实施正本：[PRODUCT_ARCHITECTURE.md](../docs/PRODUCT_ARCHITECTURE.md)。
