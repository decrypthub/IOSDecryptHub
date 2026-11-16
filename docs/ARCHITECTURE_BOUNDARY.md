# IOSDecryptHub 越狱版架构边界

2026-10-25。完整架构与阶段验收以 [PRODUCT_ARCHITECTURE.md](./PRODUCT_ARCHITECTURE.md) 为准。

1. 本项目是独立越狱工程，不再与巨魔版共享同一工作分支、构建或版本。
2. 用户安装一个完整 deb；daemon、Manager、Loader、Agent 与资源由同一个构建任务装入包，内部 dylib 不单独分发/更新。
3. 手机 daemon 常驻并提供 scope、会话、存储、受限分析、Web / MCP；PC 可选。
4. 目标 Agent 轻量、采集有界、命中线程不做 I/O；Inline / Trace 在统一后端与 HookRegistry 中实现。
5. Manager 退出不影响 daemon，目标 App 不强制常驻。关闭 scope 的期望状态与进程驻留状态分别显示。
6. 配置唯一由 daemon 写入，Loader 读有版本快照；共享 schema 约束 UI / daemon / loader / agent。
7. APT 包管理器统一升级，版本/签名/架构/路径与迁移分别校验，不能在宿主内覆盖 dylib。
8. 旧 v1 共享核心/禁 inline/必需 PC Host/跨仓复制 dylib 的约束不适用于新架构，旧文件保留作历史与迁移参考。
9. 不将缺失组件、未验证设备或新目录名当作已经实现；当前状态以 [PROGRESS.md](./PROGRESS.md) 为准。
