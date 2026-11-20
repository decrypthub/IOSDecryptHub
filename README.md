# IOSDecryptHub · 越狱版

独立的 iOS 越狱运行时分析项目。面向 rootless / RootHide，以一个 deb 整包交付常驻守护程序、手机 Manager UI、注入 Loader 与 Agent 引擎，支持通过 APT 越狱源统一更新。

本仓是 **IOSDecryptHub 越狱版正式主仓**，承接原 IOSDecryptHubJB 的开发历史。巨魔版独立维护于 [IOSDecryptHubTrollStore](https://github.com/decrypthub/IOSDecryptHubTrollStore)，两个版本分别维护自己的 main、版本和发布。

本项目在 `decrypthub` 组织公开维护。2026-11-16 合并维护入口，保留本仓既有源码历史、Star、Issues、标签与历史 Release；原 JB 仓的 v1.27.6 完整包迁至本仓，既有官网域名、包 ID 与 APT 签名信任保持兼容。详见 [仓库整合说明](./docs/REPOSITORY_CONSOLIDATION_2026-11-16.md)。

## 当前版本与使用

[v1.28.52 完整包](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.28.52) 提供 Rootless 与 RootHide 两种架构。添加 [签名 APT 源](https://ios.decrypthub.com/) 并在 Sileo 或 Zebra 安装 IOSDecryptHub。Manager、Loader、daemon、Agent 与资源随整包更新。

在 Manager 为应用开启注入后，启动或手动重启应用。应用行的「会话」页可启用设备会话，查看应用退出后保留的摘要。配对后的 PC 可使用 [idh-cli 0.8.0](https://pypi.org/project/ios-decrypt-hub/0.8.0/) 查询记录。见[设备会话说明](./docs/DEVICE_SESSIONS.md)。

源码和问题反馈：[本仓 Issues](https://github.com/decrypthub/IOSDecryptHub/issues)。巨魔设备请使用 [巨魔版下载与说明](https://github.com/decrypthub/IOSDecryptHubTrollStore)。

## 构建与验证

在 Mac 上执行：

```bash
brew install dpkg ldid cmake ninja  # 已安装的工具可跳过
bash tools/build_dobby_ios.sh      # 准备真实 arm64 + arm64e Inline Hook 静态库
bash tools/build_qbdi_ios.sh       # arm64 + arm64e/PAC QBDI/LLVM，需网络且耗时较长
make test-updater  # 无需网络或手机的版本选择/旧更新请求边界回归
make test-hook-runtime test-unwind-runtime test-hook-ios-build # 实际汇编、ABI、栈展开
make test-flow-runtime # 异常/longjmp 状态与有界 GCD 自有 fixture
make deb           # 一次构建 rootless 和 RootHide 完整包
```

Dobby/QBDI 的静态库属于本机构建产物，不纳入 Git。源码签出后须先构建这两个依赖；CI 同样先准备依赖再执行原有更新策略和整包验证，不把缺库当作引擎编译回归。arm64e 支持范围与限制见各自 `vendor/` 说明。

无需单独编译或从巨魔项目复制 dylib。v1.27.6 已通过 Mac 回归和双环境整包编译、包内容与签名检查；尚未在手机上验收安装、升级或包管理器跳转。详见 [当前进度](./docs/PROGRESS.md)；此前正式基线的核验记录见 [基线核验报告](./docs/BASELINE_AUDIT_2026-10-26.md)。

## 设计与实施

- [产品架构、整包与实施顺序](./docs/PRODUCT_ARCHITECTURE.md)
- [手机 Manager 页面与交互](./docs/MANAGER_UI.md)
- [设备会话与只读 MCP](./docs/DEVICE_SESSIONS.md)
- [Hook / ABI / 事件 / Trace 技术设计](./docs/HOOK_AND_TRACE_DESIGN.md)
- [项目当前进度](./docs/PROGRESS.md)
- [开发边界](./AGENTS.md)

优先交付基础整包与逐应用注入闭环，再完成源升级、Inline、出口采集和 Trace。内部组件自动构建完成后，rootless / RootHide 各输出本环境匹配的一份完整 deb。

## 协议

[MIT](./LICENSE)，第三方组件声明见 [NOTICE](./NOTICE)。
