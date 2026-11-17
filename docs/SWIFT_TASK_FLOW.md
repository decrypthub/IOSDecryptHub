# Swift Task 关联（1.28.48 研发包）

本模块记录实际 runtime 创建、入队、原生 job 范围、当前 Task 和结束证据。Task、closure、executor、优先级和 TaskLocal 值仍由原 Swift runtime 管理。Task 身份来自 `swift_task_getCurrent` 与实际创建生命周期，跨线程恢复继续使用该身份。

最终 Mac v38 的真实 native 后端、编译生成 Swift 夹具、原门禁和两类完整包均通过。两台整包各通过 81 个自有任务生命周期、四个错误 future 与 5 项 MCP；原 flow/timer/operation/unwind/ABI/live 回归通过。快手业务观察范围见文末及 PROGRESS.md。

## 开启和读取

默认关闭，单独使用 `configure_swift_capture`；GCD 的 `configure_async_capture` 不自动启用 Swift。

```json
{"process_generation":"<current-generation>","enabled":true,"max_tasks":128,"max_ms":30000}
```

首次开启会运行自有 Swift ABI/语言夹具。也可以先调用 `run_swift_selftest`；它拒绝替换已开启的 Swift 窗口。`get_swift_state` 返回准备、实际捕获和在途状态；`get_swift_tasks` 每页最多 16 条。配置变更和自检必须携带当前 generation。

| 资源 | 上限 |
|---|---:|
| 本代创建历史，不复用 | 512 |
| 单次窗口 / 时长 | 128 / 60 秒 |
| 创建现场的入队证据 / 提前完成证据 | 各 128 |
| 原始调度事件环 / 读取页 | 1024 / 64 |
| 校准的 runtime 最终回调 | 4 |

关闭、到期和预算后继续原调用；已登记的生命周期仍可记录结束。关闭且无已登记在途任务时走直接转发，不读取 Task 内存。适配补丁及测试资源句柄保留到进程重启。Agent 保持原 iOS 14 链接范围；独立 Swift 夹具只在明确调用自检时加载，需要 iOS 15 及以上。

## ABI 和生命周期证据

`swift_task_create`、`swift_task_create_common`、`swift_job_run` 与 global/main/delay/deadline 入队使用编译期 `swiftcall` 原型；最终回调使用 `swiftasynccall`、`swift_async_context`、`swift_context` 和必须尾调用的原转发。只读取公开的两指针创建结果及初始 AsyncContext；Task/Job、allocator 和 App TaskLocal 保持不透明。旧 runtime 没有 deadline 导出时，状态单独报告。

ABI 来源为 Swift 官方 [5.5 Concurrency.h](https://raw.githubusercontent.com/swiftlang/swift/swift-5.5-RELEASE/include/swift/Runtime/Concurrency.h)、[5.7 Concurrency.h](https://raw.githubusercontent.com/swiftlang/swift/swift-5.7-RELEASE/include/swift/Runtime/Concurrency.h) 和同版本 ABI/Task.h、Runtime/Config.h。地址来自当前 runtime 或自有初始 context 的真实最终函数指针；与原生 Hook 共用目标归属管理。

每次原创建调用有独立 ticket。实际入队中的 Job 指针须与该调用返回的 Task 精确相同，才建立初始入队证据。提前结束还须匹配该 ticket、Task、初始 context 与最终回调；不会仅因地址、线程或时间接近而补上完成。缺少初始入队、未知结束入口或证据容量不足时明确 unresolved，执行继续。

`createdBySwiftTaskId` 是实际创建者，`creationRelation` 区分已观测创建者、未登记的当前 runtime Task 和原生调用者；它不代表 Swift 结构化父子关系。detached Task 也可能在某个 Task 内创建。`createdByCallId/createdByAsyncTaskId` 单独保留实际同步/GCD 来源。

`runtime-completion-entry` 表示进入已校准的原结束函数；`completed` 还要求原 native job 范围正常返回。Swift Error 和 CancellationError 是 future 的正常错误结果，单独记录 `completionHadSwiftError`。原生 job 范围可能包含 actor 内联工作，不能将容器当成 Swift 父任务。

## 逐次事件和函数事件

`get_swift_events` 使用独立 `schedulerSeq`，支持 `after_seq` 和当前代 `swift_task_id` 过滤。创建、入队、job 入口/返回、实际当前 Task、结束、补记和确认分别记录；返回 oldest/latest/overwritten。序号属于这个原始事件环，不能传给通用 `get_event`。补记保留实际时间和后续 recordedNs，读取顺序不替代执行时间。

命中侧只写固定大小原始记录，读取侧生成 JSON 和解析镜像。executor 两个 word 保持不透明。deadline 的 word0/word1 是原 seconds/nanoseconds；完整原参数仍原样转发。读取依赖当前已加载镜像映射，裸地址仅在本代有效。

通用函数/网络事件增加可选 `swiftTaskId` 与创建来源；`query_events` 可按 `swift_task_id` 精确过滤。函数入口保存其 Task token，leave/abort 使用相同快照。当前 runtime Task 未登记时明确未解析；不会在函数返回时把新出现的 Task 身份倒填给入口。同步 parent/depth 与 GCD 身份按实际 runtime 域隔离，恢复嵌套 GCD 范围时保留它原来的域。

## 验证

`tools/build_dobby_macos.sh` 构建独立 macOS 测试依赖，随后 `make test-swift-runtime`。iOS 完整 deb 自动包含、验架构并签名 `IDHSwiftFixtures.dylib`；不手工替换手机组件。

自检以 7 类真实 Swift Task 覆盖 sleep/yield、MainActor、async-let、TaskLocal 继承/detached 隔离、原结果、实际跨线程身份、错误与取消。再验证窗口关闭后的 pending、两条预算下全部原工作继续，以及 65 个快速任务。81 个自有生命周期和四个错误 future 必须各自成立；原始事件至少具备三组完整创建/结束/确认。提前完成曾复现记录发布时间竞态，已保留负例。

`tests/swift_flow_mcp_test.py` 验证原生证据、分页、事件过滤、非法参数、generation 和自检不覆盖用户窗口。Swift 异步身份观测与 QBDI 的任意 Swift ABI 重放、异常/longjmp 透明执行是不同能力；后者继续单独实施。

最终双机快速任务分别实际恢复 7/11 个早于创建记录发布的结束，均须精确满足创建 ticket、初始入队、Task/context 和结束入口；不是用时间接近补边。Rootless 首次启动繁忙期 MainActor 在第 11.8 秒才执行，触发原 10 秒自检失败；原始失败与最终七任务均完成的事件已保留。没有延长门禁，待启动稳定后同包重跑通过。

同包快手窗口 Rootless 21 棵/315 对、RootHide 23 棵/345 对完整调用通过核心 15 参数、HTTP 与独立 HMAC/白盒/CRC；7/6 条同时具备精确 GCD 身份、原 callback native 栈与 HTTP。256/246 个 GCD 任务全完成，两窗栈关联不足增量为 0。Rootless 未见新 App Swift Task；RootHide 观察到 5 个实际 App Task 创建，初始入队及已校准结束入口有效，其中四个有独立 native job 入口/返回。读取时这五个 Task 尚无结束证据，保持 created，不把 job 返回标成 Task 完成；没有签名树携带这五个 TaskID，故不宣称 Swift→sig3 链通过。
