# IOSDecryptHub · 越狱版

独立的 iOS 越狱运行时分析项目。面向 rootless / RootHide，以一个 deb 整包交付常驻守护程序、手机 Manager UI、注入 Loader 与 Agent 引擎，支持通过 APT 越狱源统一更新。

本仓是 **IOSDecryptHub 越狱版正式主仓**，承接原 IOSDecryptHubJB 的开发历史。巨魔版独立维护于 [IOSDecryptHubTrollStore](https://github.com/decrypthub/IOSDecryptHubTrollStore)，两个版本分别维护自己的 main、版本和发布。

本项目在 `decrypthub` 组织公开维护。2026-11-16 合并维护入口，保留本仓既有源码历史、Star、Issues、标签与历史 Release；原 JB 仓的 v1.27.6 完整包迁至本仓，既有官网域名、包 ID 与 APT 签名信任保持兼容。详见 [仓库整合说明](./docs/REPOSITORY_CONSOLIDATION_2026-11-16.md)。

## 当前版本与使用

[v1.27.6 完整包](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.27.6) 基于组织正式 `a94a396` 的完整 v1 源码，包含 Manager、Loader、一次性管理 daemon、引擎与资源。添加源 **https://ios.decrypthub.com**，在 Sileo / Zebra 安装 IOSDecryptHub；rootless / RootHide 请使用对应架构的完整 deb。

打开 Manager → 开启目标应用的注入 → 启动或手动重启目标 → 通过原有 Web / MCP 查看分析。关闭注入影响后续加载；已加载的引擎要在目标退出后才离开进程。

v1.27.6 将版本检查切换到规范 APT 源，按安装包架构选择版本，更新与回退交给系统包管理器。Manager、Loader、daemon 与引擎统一升级；旧单引擎安装/回滚请求会被拒绝，遗留 staging 不再覆盖包内引擎。

**开发主线与正式包分开**：当前 main 为 1.28.37 开发代码，已在两台授权设备验证 Inline/PAC、QBDI 真实现场、同步 native 栈，以及非局部退出状态保护与有界 GCD 关联。验证范围见 [当前进度](./docs/PROGRESS.md)、[真实现场协议](./docs/LIVE_CONTEXT_TRACE.md) 与 [状态保护/GCD](./docs/FLOW_STATE_AND_GCD.md)。1.28.x 当前用于研发整包测试，尚未发布 Release/APT；上面的 v1.27.6 是已发布完整包。常驻分析服务、新 Manager 与 scope 架构继续按路线图推进。

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
- [Hook / ABI / 事件 / Trace 技术设计](./docs/HOOK_AND_TRACE_DESIGN.md)
- [项目当前进度](./docs/PROGRESS.md)
- [开发边界](./AGENTS.md)

优先交付基础整包与逐应用注入闭环，再完成源升级、Inline、出口采集和 Trace。内部组件自动构建完成后，rootless / RootHide 各输出本环境匹配的一份完整 deb。

## 协议

[MIT](./LICENSE)，第三方组件声明见 [NOTICE](./NOTICE)。
