# Hook、事件与 Trace 技术设计

2026-11-16 实施校注：现有 `src/` 研发线 1.28.35 已使用显式报告的 Dobby / QBDI 后端，在 rootless / RootHide 完成 Inline、PAC 与纯函数 replay 验证。当前实现和限制见 [PROGRESS.md](PROGRESS.md) 与 [ROOTHIDE_NATIVE_BACKENDS.md](ROOTHIDE_NATIVE_BACKENDS.md)；下文仍是新版架构设计，ElleKit 适配器及全部统一注册表规划不因此视为完成。

2026-10-25。状态：技术设计，尚未实现。产品与运行拓扑以 [PRODUCT_ARCHITECTURE.md](./PRODUCT_ARCHITECTURE.md) 为准：daemon 位于手机，PC 可选。

本文件保留上一轮的 Hook / ABI / 事件语义，不保留旧的双分支、跨仓 dylib 交付和必需 PC Host 约束。章节编号为技术条目的稳定引用。

## 5. Hook 管理与后端

### 5.1 统一 HookRegistry

所有内置加解密 Hook、动态导入 Hook、ObjC Hook、Inline Hook 均登记到同一注册表：

- 目标身份：`processGeneration + imageUUID + RVA`，ObjC 另含 Class / selector / instance-or-class。
- `hookId`、owner、mechanism、backend 及版本、original、安装前证据、启用状态、资源占用。
- 状态区分 `resolving / installed / installed-never-fired / active / disabled / failed / retired`。
- 计数至少包含 hits、filtered、sampledOut、budgetRejected、emitted、ringDropped、transportDropped。
- 多个本项目观察者复用同一次 patch；冲突返回现有 owner。检测到其它框架改写时报告现状，不能直接覆盖或恢复别人指令。

命中回调只做预算判断、有限寄存器/内存复制、入环和原函数转发。JSON、十六进制文本、完整符号化和网络发送在工作线程或 daemon 完成。

### 5.2 Inline Hook 的范围与选型

第一切片解决：静态链接 C 函数、模块内直接调用、没有导入槽位的自研算法函数。寻址支持模块 UUID + RVA，或当前会话的绝对地址；镜像/进程代际变化后旧地址失效。

**首选验证 ElleKit 适配器**：现有越狱路线已使用其加载生态，上游明确提供 arm64 / arm64e 的 C Hook。它仍须通过本项目的 original 转发、并发命中、代码页、PAC 和设备矩阵测试，不能以“库存在”当作已支持。[ElleKit 上游](https://github.com/tealbathingsuit/ellekit)

**Dobby 作为比较候选**：Android 已采用它，上游列出 iOS / ARM64 支持；这不足以证明本项目的 arm64e 与 RootHide 环境可用。只有主选不能满足验收时，单独验证并显式选择后端，禁止失败后静默换机制。[Dobby 上游](https://github.com/jmpews/Dobby)

注册表公开 `softDisable / hardUnhook / enterCapture / leaveCapture / stackArgs / floatArgs / structReturn` 等实测能力。默认软停记录，桥和 original 保留到安全退休。硬卸载仅在后端支持、无在途调用、当前 patch 归属仍一致时开放；不承诺靠保存几字节即可安全卸载所有后端。

### 5.3 参数、输出与 ABI

- 首先提供调用前通用寄存器快照和显式 `ptr_arg + length_arg + max_bytes` 内存窗口。
- 出口采集是独立能力：需要真正的 call-through 桥、嵌套调用上下文与返回现场保存；不能在尾跳原函数的入口桥后“补一段逻辑”冒充调用后。
- 支持整数、指针、浮点、栈参数、间接结构体返回等必须分别声明与验收；ObjC 消息桥不能当成任意 Swift ABI 桥。
- 地址必须现场安全读取；非法地址记录 unreadable，原始长度与实际捕获长度分别保存。
- C++ 异常、ObjC 异常、longjmp、非返回函数和特殊 Swift 调用约定先明确限制；不支持的出口方案拒绝安装或仅提供入口观察，并在结果中说明。
- 任意改参、改返回值、主动调用、内存写回可作为后续显式命令加入；与只读观察分开，默认不启用。

## 6. Trace 分层

| 层级 | 首要交付 | 明确边界 |
|---|---|---|
| 函数入口观测 | 目标函数命中、调用者、TID、参数快照 | backtrace 是命中时的栈，不是完整执行轨迹 |
| 函数调用 Trace | 指定目标集合的 enter / leave、parentSpan、耗时与输出 | 只覆盖已布置的函数，不宣称整个进程完整调用图 |
| 指令 Trace | 显式函数/模块范围、指令/时间/记录预算、分页结果 | 独立可选 DBI，不承诺所有设备和线程可用 |

指令后端候选 QBDI。上游明确将 iOS 标为不稳定且需越狱，并列出信号、线程创建和 C++ 异常限制，因此它不阻塞基础 Hook 交付。[QBDI 上游说明](https://raw.githubusercontent.com/QBDI/QBDI/dev-next/README.rst)

区分 `live-entry`（真实命中现场执行）和 `replay`（人工重新调用）。后者可能有副作用，不能证明原始请求走过同一路径。局部寄存器不足以重建完整现场时必须标记 `contextComplete=false`，不能声称等价重放。

Trace 状态包含 traceId、session、processGeneration、覆盖范围、过滤、预算、丢失、停止原因和完成度。停止需协作退出；daemon 的命令超时不代表目标线程已经被安全中止。Trace 活动期间禁止卸载相关 Hook / 模块。

Android 的 perf root_watch 不直接映射为 iOS 硬件观察点；后者涉及 Mach 调试权限、异常处理和越狱支持，另开研究切片，不混入首批承诺。

## 7. 统一事件与协议

### 7.1 事件信封

以下为拟定字段契约，不是现有 `DHLogEntry` 已支持的字段：

| 字段 | 含义 |
|---|---|
| schemaVersion / agentBuildId / protocolVersion | 结构、构建与通道版本 |
| sessionId / processGeneration / pid / tid | 事件来源；PID 重用不得混会话 |
| seq / monotonicNs / wallTimeMs | 进程内顺序、耗时基准、人类时间；跨设备单调时钟不能直接比较 |
| kind / mechanism / hookId | crypto / network / function / module / trace / diagnostic；fishhook / objc / inline / dbi |
| callId / parentCallId / phase | entry / leave 关联；parent 仅在已观察到的调用关系中建立 |
| imageUUID / rva / pc / lr | 运行地址与可持久化定位身份 |
| payload | 各类型结构化字段，不通过 detail 文本反解析协议 |
| blobs | 原始长度、实际长度、截断/不可读状态、内容引用 |
| observation | 抽样、额度、丢失与覆盖上下文 |

保留 v1→v2 适配器用于迁移既有 crypto / network 事件，不把 v2 新字段偷偷塞入 v1 文本。网络与加密按时间/线程/数据关联仅产生候选，daemon 通过明确的字节或算法核验提升为已验证结论。

### 7.2 传输与会话

- 使用带长度与类型的帧：`hello / capabilities / command / result / eventBatch / blobChunk / heartbeat / gap`。
- hello 包含协议版本、Agent 构建身份、bundle、PID、进程启动身份、每次进程启动的随机 generation、架构、实际 ops / limits / backends。
- 网络重连保留同一进程 generation；进程重启生成新 generation。旧命令、旧 Hook ID 和旧地址禁止跨 generation 使用。
- 命令含 commandId、sessionId、generation 和截止时间；超时、取消请求、实际完成分别记录。安装/卸载等变更以 commandId 做有界幂等，重连不盲目重放。
- 控制与事件具有独立额度，Trace 洪水不能饿死 stop / health。流量满时丢事件并发 gap，不能阻塞命中线程。
- 地址、寄存器、seq 等大整数在线协议中使用十六进制或十进制字符串，避免 JavaScript 的数值精度丢失。

### 7.3 初始资源预算

下列是首个验收切片的待测默认值，不代表当前性能承诺：

| 资源 | 初值 |
|---|---|
| 通用 Hook 数 | 每进程最多 128；槽位耗尽与退休槽位分别可见 |
| 单次通用内存窗口 | 最多 4 个，每个 256 B，总计不超过 1 KiB |
| 事件环 | 每进程 4 MiB 字节上限，同时限制记录数 |
| 堆栈 | 最多 32 帧，默认保存地址，daemon 符号化 |
| 事件批 | 最多 64 KiB；控制帧最多 256 KiB；blob 独立分片 |
| 函数 Trace | 显式目标与 TID/模块过滤；默认关闭 |
| 指令 Trace | 起始建议 10,000 指令、100 ms 协作时间预算、1 MiB 输出上限 |

持续 crypto 流还需每上下文字节数、上下文总数和过期回收；仅限制每条落盘大小不能控制命中线程的内存复制。所有预算在复制之前生效，完整率不能因丢记录而继续显示 100%。

## 8. 工具与控制面

拟定能力域：session / capabilities、module / symbol / memory、capture、hook、trace、event / artifact、analysis / guide。

每个工具只注册一次：名称、输入 schema、handler、所需能力、只读/变更属性、超时与资源上限同条登记，由它生成 MCP 和 REST 适配。设备能力取运行中 Agent / daemon 的实际回复，不用项目名或文档推断。

Hook 工具至少提供 install / status / disable，结果返回 resolvedTarget、mechanism、backend、actualPatch、originalAvailable、hitVerdict、limits、failureStage。零命中需要区分未安装、已安装未执行、被过滤与有命中但未保留。

Trace 提供 start / status / stop / read，数据分页并与 traceId / generation 绑定。daemon 负责保存、摘要、寄存器与内存变化查询，MCP 默认返回摘要和引用，按需读取原始字节。

分析指南直接可通过 MCP 查询，描述当前支持的观察路径、限制与下一步所需现场数据；不为了给建议而自动安装 Hook、触发目标函数或重新发送请求。

