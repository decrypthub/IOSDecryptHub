# IOSDecryptHubJB 当前进度

## 2026-10-25：独立工程与手机整包方案

用户决策：巨魔版定型，越狱版独立项目；一个 deb 包含常驻 daemon、手机 UI 和注入引擎，通过 APT 源统一更新；手机可按应用开关注入，UI 参考现有 Android Manager。

已完成：

- 从旧越狱 4858677 导入独立 IOSDecryptHubJB 项目，main 为唯一产品主线，保留引擎源码与提交历史。
- 核对 Android Manager / daemon / scope 代码，落定手机原生 UI 和真实生效状态语义。
- 将 PC 从必需分析中心改为可选客户端，手机 daemon 负责服务与数据。
- 产品、UI、Hook / Trace 设计与开发规则同步更新。
- 上一轮已实测 Mac SSH 和旧引擎 arm64 / arm64e 编译；当前没有新版完整包或设备验收。

尚未实现：

- J0：新版 daemon、Manager、Loader 接入、整包一键构建。
- J1：手机应用目录、scope IPC、开关/生效状态、目标启停。
- J2：本产品正式 APT 源、统一版本、升级与移除交易。
- J3–J5：Inline、出口采集、函数与指令 Trace。

接下来从 J0 开始：先做可安装完整最小包，再按 J1 验证应用 A 开启、B 不受影响、关闭/重启真实生效；不先以独立 dylib 交付新增能力。

## 2026-10-25：统一迁入组织公开维护，补齐旧公开源码发现

- 用户明确不要私有仓。当前仓从个人账号迁入 `decrypthub/IOSDecryptHubJB` 并设为 PUBLIC；巨魔版为 `decrypthub/IOSDecryptHubTrollStore`，官网为 `decrypthub/IOSDecryptHubPage`。
- 组织原有公开 `decrypthub/IOSDecryptHub` 已包含管理器、Loader、一次性 updater、整包脚本和发布链路，并有 v1.27.5 发布。它与本仓历史不同，不强推覆盖；本机加只读参考 `legacy-public/main`，核对提交 a94a396。
- 更正早期判断：“本机未发现并列 JB 仓”不能推断“旧越狱组件不存在”。后续从真实 v1 迁移常驻与整包更新，不从零重复造管理器/打包能力。
- 旧源声明为 `https://ios.decrypthub.com`，旧包 ID 为 `com.iosdecrypthub`；尚需核对线上签名/索引/已有安装和接管方式，本轮不改源、不发包、不操作手机。
- 本轮只迁移公开仓、更新链接与状态记录，不新增运行时功能。

## 2026-10-26：对齐组织正式源码，修正拆分基线

- 用户要求复核线上版本。确认正式 main 为 a94a396、正式 Release v1.27.5；官网三件下载与 Release digest / Git blob 完全一致，原源和包未被覆盖。
- 承认并修正此前基线选择错误：新 JB 从个人引擎仓开始，缺少正式管理器/Loader/updater/打包，且缺 RootHide 变体修复。
- 纳入正式仓历史并原样恢复 v1 组件与自包含 make deb，保留新设计和原测试资料；源码/打包关键路径与正式 Git blob 一致。
- Mac 实测 make deb 同时生成 rootless 和 RootHide 整包，包内检查通过；未装设备、未发布 Release、未更新线上源。
- 巨魔仓继承的 latest Release 是 v1.25.5，下载入口已改回正式 v1.27.5，避免旧产物被当作最新版本。
- 正式发布 workflow 仅保留为参考快照，不触发新发布。后续 J0/J1 是在完整 v1 上改造常驻服务和新版交互，不再从零拼装已存在的组件。
- 完整核验、SHA-256 与限制见 BASELINE_AUDIT_2026-10-26.md。上方早期“仅有引擎、无整包”的状态已被本节替代。

## 2026-10-26：v1.27.6 独立维护更新

- 发布独立完整包，沿用既有包 ID、APT 地址和签名信任，保留 v1.27.5 可用版本。
- 按 deb 架构查询规范 APT 源，rootless 与 RootHide 候选版本隔离；Manager 更新/回退入口交给包管理器。
- 删除 daemon 单引擎下载/替换/交换备份逻辑，拒绝旧 install / rollback 请求；启动脚本忽略遗留 staging，并修复转交请求时误删同路径请求的问题。
- Mac 上验证版本数字排序、架构隔离、格式错误、真实 daemon 拒绝旧请求与引擎不变；双环境完整构建和包内容/签名检查通过。
- 本轮不包含常驻分析 daemon、新 Manager、scope IPC、Inline Hook 或 Trace，尚未进行手机安装、升级、重启或跳转验收。

## 2026-11-13：J3 第一切片 — Inline Hook + QBDI 指令级 Trace（JB 版）

实现（只在越狱版；巨魔版不动）：

- `src/core/dh_thunk.m`：新增 `DH_HOOK_INLINE` 与 `dh_thunk_install_inline`。复用既有 thunk-bank（保存 x0-x8/q0-q7/lr，记录后尾调用原函数蹦床），后端为静态链接的 **Dobby**；支持 `module+symbol` 或绝对地址，地址先经 `vm_region_64` 校验可执行。
- `src/trace/qbdi_trace.m`：静态链接 **QBDI 19.1.5**（iOS/AArch64，iOS 15.0+），一次性 VM + `qbdi_call`，指令/时间双预算；预算在回调里 `QBDI_STOP`，不把截断伪报成 completed。
- MCP 新工具：`hook_inline`（install/软停由 `unhook` 承担）、`trace_function`；`list_hooks` 增 `kind=inline`；`trace_function` 进重活串行队列。
- 安全护栏：拒绝 inline-hook `malloc/calloc/realloc/free/objc_msgSend/objc_retain/...` —— 命中处理器本身会分配 Foundation 对象，hook 分配器会在原序言未完成时重入并打死宿主（实测 engine_shell 直接退出）。
- vendor：`vendor/dobby`（commit 5dfc854，arm64 静态）与 `vendor/qbdi`（commit 3318580，arm64 静态 + 头文件），构建脚本 `tools/build_dobby_ios.sh` / `tools/build_qbdi_ios.sh`。`Makefile` 只在 ARCHS 不含 arm64e 时链接这两个库；roothide 胖包可编译，但 `hook_inline/trace_function` 明确返回 unavailable。

真机验证（iPhone X / iPhone10,3 / iOS 15.6 / Dopamine rootless，rootless 1.28.0）：

- `trace_function` 对 `libsystem_kernel.dylib!getpid`：`ok=true`、`retval=0x1e1b`（= 进程 pid）、6 条指令、`stop_reason=completed`；`max_insns=32` 时按 instruction-limit 截断并标记 truncated。
- `hook_inline` 对 `write`：安装成功（`backend=dobby`），一次 `get_stats` 后 **hits=14**，宿主仍能正常响应；`unhook` 后 `enabled=false`、hits 保留、转发透明。
- `hook_inline` 对 `malloc`：明确拒绝并返回原因（`isError=true`），宿主存活。
- 引擎本体经一个 platform CLI 宿主 `dlopen` 验证（8088 正常起、MCP 工具可用）；QBDI/Dobby 各自也有独立 CLI probe 通过。

未完成/限制：

- **设备侧 Loader 注入状态**：本轮多次安装/重装 deb 并手动 respring 后，`IOSDecryptHubLoader` 不再注入第三方 App（旧引擎同样不注入，App 进程存活但 8088 不起），因此上述功能验证走的是「platform CLI dlopen 引擎」而非「Loader 注入 App」。需要设备重新激活越狱/正常 respring 后，用 App 再补一次端到端验收。
- vendor 只有 arm64 切片；arm64e（roothide）需另建 Dobby/QBDI，当前明确 unavailable。
- `trace_function` 是 **replay**：会在调用线程真实执行目标函数一次；只播种 x0-x7，栈/浮点参数不重建；有副作用。
- inline hook 仅入口观测 + 软停，未做安全硬卸载；不做返回值/参数改写。
- 尚未发布到 APT；1.28.0 仅本机构建并装到 iPhone X。

