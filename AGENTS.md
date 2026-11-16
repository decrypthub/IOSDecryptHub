# AGENTS.md — IOSDecryptHub 越狱主仓

Always respond in Chinese-simplified.

## 开始工作先读

1. `docs/PRODUCT_ARCHITECTURE.md`：唯一产品架构和阶段路线。
2. `docs/PROGRESS.md`：当前实现/验证状态。
3. 涉及 UI 读 `docs/MANAGER_UI.md`，涉及 Hook / Trace 读 `docs/HOOK_AND_TRACE_DESIGN.md`。
4. 按用户要求先读本机该项目 Claude memory 索引，再用代码和现场状态核对记忆。
5. 本仓 `https://github.com/decrypthub/IOSDecryptHub` 自 2026-11-16 承接原 IOSDecryptHubJB 越狱主线。既有 v1 源码和发布历史保留；历史文档中的 `legacy-public/main` 指本仓整合前的 `a94a396`，不再是另一个活动产品仓。见 `docs/REPOSITORY_CONSOLIDATION_2026-11-16.md`。
6. `docs/BASELINE_AUDIT_2026-10-26.md`：已校正的正式基线、完整组件、线上哈希与验证范围。不能仅凭 VERSION 一样就认为与正式代码一致。

## 产品定位

- 本仓库是 IOSDecryptHub，只维护越狱版；巨魔版位于独立 IOSDecryptHubTrollStore 仓库。越狱版以后统一在本仓 main 开发，不再创建或使用并列 IOSDecryptHubJB 工作目录；旧项目只保留在迁移备份区用于恢复，不作为开发或发布入口。
- 所有本产品仓库均在 decrypthub 组织公开维护；不另建个人私有工作仓作为版本真相。
- 使用自己的 main、版本和发布，不把巨魔仓的 jailbreak 分支作为开发入口。
- 对用户只交付整包 deb，包含 daemon + Manager + Loader + Agent + 必需资源。内部 dylib 由整包任务自动编译，不需要从另一个项目手工构建或复制。
- 手机常驻 daemon 是服务中心，PC 可选。Manager 能按应用开关注入，并区分已保存策略与实际加载状态。
- 系统包管理器通过唯一规范 APT 源统一更新整包；不在宿主内自行覆盖 dylib，不拆成互不匹配的组件版本。

## 架构边界

- Agent：目标进程内只做采集、Hook、有限运行时操作/Trace、有界 IPC；命中线程不写盘、不发网络、不做完整符号化。
- Loader：scope 快照判断与加载，启动路径不等待 daemon 同步 RPC。
- Daemon：独立常驻，负责 scope、会话、存储、有界分析、HTTP / MCP；一处业务实现服务 UI / REST / MCP。
- Manager：SwiftUI 原生管理界面，只发有限业务请求，不自行改 root 配置或执行任意 shell。
- 新 Agent 允许 Inline / 可执行内存 / 可选 DBI，通过统一注册表和后端接口管理，不受旧巨魔核心禁令限制。
- 旧 `src/`、`app-trollstore/`、跨仓打包脚本保留作迁移基线；不要将其存在当作新版功能已完成，也不要在巨魔项目整分支回合本项目。

## 真实状态与稳定性

- scope 原子持久化，读写带 revision；保存失败或并发冲突不能显示成功。
- 关闭注入禁止后续加载；在线引擎停采集与完全从进程卸载分别报告，不能假称 dylib 已消失。
- 用户开关不自动结束目标；停止/重启应用须来自明确的对应操作。
- 应用目录、PID、session generation 和版本现场核对，不用进程名或旧地址猜目标。
- Hook 安装、命中、过滤、预算、事件丢失分别计数。先预算后复制，错误有具体原因，不静默换后端。
- 不操作未被用户授权用于测试的手机，不把编译/模拟器通过当成真机通过。

## 开发和发布

- 每个实施切片具备确定性输入/输出与失败路径；改什么验证什么，不无故全量跑设备脚本。
- 维护 `docs/PROGRESS.md`，明确设计、已实现、已验证、未验证。
- rootless / RootHide 分别校验架构、路径、签名、依赖、加载、配置保留与升级行为。
- 正式包全部组件与 schema / 协议 manifest 同步版本；缺组件直接失败，不以裸 dylib 或空 UI 冒充整包。
- APT 发布先上传/校验 deb 再提交索引，维护脚本幂等；不自动重启用户目标 App。
- 提交格式 `type: 中文描述`。不提交构建产物、生成头、签名工具、私钥、凭据或捕获数据。
- 远程 Mac 连接参数只在本机 memory，不写仓库。

## 当前验证状态（2026-11-16）

同日 1.28.36 后续：补齐原 App 线程/栈/寄存器的 QBDI live-next-call、Dobby context 入口和公共桥 CFI，系统 libunwind 同步 native 栈在命中时只采 PC/SP、读取时符号化。两台真实快手 CRC/HMAC/白盒调用已通过，同步栈逐条报告完整/截断/错误；不能把正常返回约束、256 帧上限与模块内覆盖推广为任意异常/异步控制流支持。当前操作协议见 `docs/LIVE_CONTEXT_TRACE.md`，原有 post ABI 和 Inline 硬卸载限制继续生效。

同日 1.28.35 后续：RootHide 胖包已链接真实 arm64 / arm64e Inline 与 QBDI，双机 3 个独立进程代与快手真实原语采集/离线复算、复制输入的 SDK 指令回放通过。动态跳板仅保留直接 caller 与结构化同步关联，完整 unwind 不支持。最新验证与边界见 `docs/PROGRESS.md` 顶部；以下无后端说明为旧版快照。

同日 1.28.32 后续：两台已验证按 Darwin ABI 读取方法栈参数和命中时直接调用者；不支持透明转发的 ObjC post 请求在安装前拒绝。当前研发包与离线算法验证的具体范围继续以 `docs/PROGRESS.md` 顶部为准。

同日后续验证更新：1.28.31 研发包已按用户授权安装并核对两台测试手机，完成自定义 Mach-O 段识别、分支目标、方法参数证据和能力报告修复；验证范围与未完成的密码原语分析见 `docs/PROGRESS.md` 顶部。未发布到 Release / APT。下段 1.28.28 说明保留为迁仓时点快照。

main 为 1.28.28 开发代码，包含 Inline Hook、QBDI Trace 与后续运行时操作；实现范围、架构限制和真机证据按 docs/PROGRESS.md 核对，不把规划中的常驻分析服务或新 Manager 视为已完成。旧 IOSDecryptHubJB GitHub 仓已按用户明确授权删除，本机旧目录已从工作区根移入迁移备份区。

新签出源码先按 README 构建 Dobby/QBDI 依赖；CI 已补依赖准备并使用静态 Config.h。[CI 43802304063](https://github.com/decrypthub/IOSDecryptHub/actions/runs/43802304063) 已在 4e59e48 通过更新策略与 rootless / RootHide 完整包构建，产物仅用于验证。迁仓不发布 1.28.x 正式包、不更新 APT、不操作手机。

## v1.27.6 实现快照（历史）

已恢复组织正式 a94a396 的完整 v1。v1.27.6 按安装包架构检查 APT 源，安装与回退由包管理器负责；daemon 拒绝旧单引擎安装/回滚，updated.sh 不再应用旧 staging。Mac 本地回归和 make deb 双环境验证通过。当前管理 daemon 仍是一次性进程；常驻分析服务、新 Manager、scope IPC、Inline / Trace 未实现。未在手机验收安装、升级与包管理器跳转。
