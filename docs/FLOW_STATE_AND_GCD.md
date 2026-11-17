# 1.28.42：非局部退出状态保护与有界 GCD 关联

本轮扩展现有 Agent 的调用状态与因果关系。真实 CPU 跟踪继续遵守 [LIVE_CONTEXT_TRACE.md](LIVE_CONTEXT_TRACE.md) 的正常返回约束；这里不增加 QBDI 内异常/longjmp 的透明执行支持。

## 非局部退出后的状态

普通 post 桥现在保留每线程最多 64 个保护记录，包含槽位、真实 caller SP、调用 token 及事件上下文。采集暂停或 Hook 软停时也登记内部保护 token，正常返回仍清理在途计数，但不伪造采集事件。

在同一线程下一次动态入口或事件/异步包装边界，系统 libunwind 获取完整同步栈，核对属于 IDH 的桥 PC 范围和真实栈位置。只有完整展开证实该桥已经不在链上，才退休相应记录、清理同步上下文、减少 inFlight，并为已有 entry 的调用生成 `phase:"aborted"`。它没有 returnValue，`get_call.status` 为 aborted，`retainedPair:false`，不补造 leave。

因此，函数内部抛出又捕获的异常仍保留活动父调用；不在全局 throw 入口清空所有调用。longjmp 不解析或修改不透明 jmp_buf，也不依靠普通 finally 保证清理。长期没有后续边界的记录可能继续保持 open，不能把它提前当作完成。

栈缺元数据、截断或错误时不根据“没看到桥”断言退出；即使 libunwind 正常停止，也必须证明展开已经越过已知保护帧的栈位置。相关父调用/异步关联暂时抑制，事件标明 contextComplete:false 与 parentValidation，计入 unverifiedBoundaries。下一次充分证据可恢复判断。超过 64 个保护记录会计 guardOverflows，相应未登记记录的退出保护不作保证；正常函数转发继续。

1.28.42 增加正向证据规则：即使更高层栈不完整，只要所有已登记 post 桥以及当前异步包装帧都实际出现，且准确 PC/SP 和 cookie 校验通过，仍保留已证实的活动上下文，并计 verifiedPartialBoundaries。这条路径不退休任何缺失帧；缺少任一锚仍抑制关联。它没有增加猜测性 FP 扫描或任意缺失元数据恢复。

线程结束使用 pthread-key 中独立保存的快照收尾。不能只在 key destructor 读取编译器 TLS：Darwin 的 TLV 清理顺序可能使此时读到空状态。快照保留原 call/parent/async token，使线程退出的 aborted 事件仍有原身份。这里保护的是采集状态，不修复 App 自身的非法异常/longjmp，也不改变其 catch、跳转结果或线程退出行为。

## GCD 提交与执行

默认关闭，显式调用 `configure_async_capture` 开启一个窗口：

```json
{"process_generation":"<current-generation>","enabled":true,"capture_roots":true,"max_tasks":128,"max_ms":30000}
```

覆盖当前及未来镜像中六种公开提交导入：`dispatch_async`、`dispatch_after`、`dispatch_group_async` 及其 `_f` 版本。fishhook 注册成功只说明注册完成，实际覆盖须看任务记录和命中，不能保证每个导入写入或所有调度路径。

- 已观测同步调用或异步任务中提交的工作继承来源。`capture_roots:true` 另允许 `.app/` 镜像直接提交的工作成为根；关闭时只传播已有观测上下文。
- 可选 queue_exclude 为最多 8 个非空、无 NUL、127 UTF8 字节以内的队列名子串，忽略大小写匹配；被排除的提交继续原样执行。IDH 自身提交不参与真实业务捕获，自有 fixture 使用明确的测试队列。避免日志/页面初始化任务先耗尽分析预算。
- `root_queue_include` 与 queue_exclude 使用同样的字符串约束和大小写规则；空列表不筛选。它只选择没有 async parent 的任务（包括有同步 call 来源的根），已选中任务的后代可以换队列；queue_exclude 仍对每一次提交优先生效。rootQueueMisses/queueExclusions 分别计数，不消耗任务记录。
- 普通 block 包装 App/IDH 镜像中的 invoke。另保留 `dispatch_block_create` 与 `dispatch_block_create_with_qos_class` 两个公开创建入口：仅为捕获窗口内创建、内层 invoke 可识别的 block 建立有界绑定；公开构造器仍生成原有外层 dispatch-block，提交时传递该外层对象，保留 flags、QoS、取消/等待语义，执行时由内层回调携带已观察的提交身份。只关联唯一观察到的首次提交；首次安装用公开构造器和队列分别校准 direct/async 回调，只有调用者位于已校准 async invoker 的 metadata 范围才承认执行。提交后直接调用同一 block 不会抢占排队任务身份。不会读取 libdispatch 私有 block 数据布局。
- 窗口前创建的特殊 block、未知/系统 invoke 仍原样转发并计 skippedSpecialOrUnknownBlocks。创建绑定最多每进程 1024 个、每窗口不超过本窗口任务预算，关闭或过期后不继续创建。重复提交或未经过提交入口的直接执行不能猜测执行边：若首次任务尚未开始，它变为 unresolved，executionThreadId/startedNs 仍为 0；block 最后释放且未观察到开始时同样记录 unresolved。正常原回调继续执行，不把缺失关联记成 App 异常、取消成功或正常完成。
- `_f` 版本保留原 context/function，由固定记录保存并恰好调用原 callback 一次。queue、group、deadline 原样传递。首次安装提前解析固定转发符号；不承诺保留第三方逐镜像 interposer 链。
- 安装时预留这八个导入的所有权，已有动态 Import Hook 时拒绝启用；安装后拒绝用动态 Import 再覆盖它们。软停仅停止新捕获，转发 patch 保留到目标重启。

每个任务分配当前代唯一 `asyncTaskId`，记录 `asyncParentTaskId`、`asyncSubmittedByCallId`、提交/执行 TID、queue、API 和时间。执行前安装任务上下文，正常返回或受支持的异常退出后恢复原上下文；保留任务也用真实包装帧的 unwind 范围、SP 与栈 cookie 核对有效性。GCD 可能复用线程，不能用 TID 或时间邻近推断父任务。

任意业务探针看不到包装帧时先抑制不确定关联，不据此完成任务的终结计数。任务终结以包装器的实际退出、线程退出或后续包装器入口的充分证据为准；terminalReason 说明来源。这避免图片解码等路径的提前展开终止被误记成 App 异常。正常返回仍能完成原任务；观测缺口与业务完成度分别报告。

函数、密码和网络事件增加上述异步字段。parentCallId 继续只表示同步调用关系，native 栈仍是该线程的真实栈；异步边单独呈现，不把提交者的栈拼进执行线程栈。网络响应合并继续保留请求原上下文。

固定上限：每进程保留 1024 个任务记录，每个窗口 1–256 个、1–60000ms，最多 64 个 pending/running、传播深度最多 8。任务槽位在本代不复用。每次提交最多保留 32 个原始栈帧，超限显式截断；读取线程补充直接提交 caller 的 UUID/RVA，命中线程不完整符号化。

超预算、窗口过期或关闭后继续转发原任务。关闭不取消已排队工作，它们仍可携带已有身份直到完成。pending 只表示尚未观测到完成，不能假定已执行、已取消或永远不会执行。捕获关闭后的包装任务中再提交的新工作不自动扩大捕获窗口。

## 查询和历史

- `get_flow_state`：预算、保留数、pending/running、abandonedCalls、unverifiedBoundaries、guardOverflows 和跳过/拒绝计数；windowStartedNs/windowDeadlineNs 和 windowStopReason 区分 capturing、task-budget、record-capacity、expired、disabled，关闭保留最近窗口诊断。threadGuardCount/threadAsyncTaskId 仅指处理命令的线程，不代表任意 App 线程。
- `get_flow_diagnostics`：最近 16 次不确定边界，offset 0–16、limit 1–4，默认 1；包括原因、真实末帧/锚 SP、候选任务与延迟符号化后的栈。candidateTaskId 不是已建立的因果边，association 明确为 suppressed。reasonCounts 区分 frame-budget、unwind-error、unwind-incomplete、stopped-before-guard、stopped-before-async-scope、wrapper-not-observed；栈 termination 另报告后端终止原因、stepResult、PC/SP/FP、procedure 和线程栈范围。各页是读取时的快照，活跃环被覆盖时检查 total/overwritten/记录 ID，不能假设跨页冻结。
- `get_async_tasks`：offset/limit 分页，最大 128；可传完整 task_id 查询本代某任务。无对应记录时 unknownTask:true。任务记录包含真实来源边、提交 caller 和 callback 的 UUID/RVA、有界原始提交栈；公开创建的特殊 block 另含 blockCreationCallerIdentity 与 dispatchBlockMetadataPreserved。unresolved 表示提交已观察但执行关联不可用，不能算 completed/aborted。
- `query_events.async_task_id`：精确查事件上下文；get_event/get_call 获取详情。submit/start/complete/aborted 任务事件与普通事件一样受存储预算和淘汰限制。
- 任务表在当前 Agent RAM；重启后旧 task_id 不用于新进程查询。journal 中已保留的事件仍携带采集时的进程代和异步 ID，不能将新代任务表当成旧表。完整历史因果图取决于实际保留的事件，不补缺失边。

配置和自检须传当前 process_generation；布尔值、分页、窗口和预算在修改状态前严格验证。运行中的 QBDI live 仍遵守正常返回契约，不能依赖本功能从执行引擎的异常/longjmp 中安全恢复。Swift Task、NSOperation、group notify、dispatch source、私有调度器及其它未布置入口不在本轮覆盖内。

## 验证入口

`make test-flow-runtime` 在独立临时日志目录运行真实汇编与运行时测试；既有 hook/unwind/iOS 编译、updater 和两种完整 deb 检查继续执行。Makefile 按文件扩展名选择 C/ObjC/ObjC++，避免全局 -ObjC 将 C++ fixture 错当 ObjC；验收断言没有放宽。

实机先恢复 all/other，再调用 `run_flow_selftest`。18 组自有 fixture 覆盖 ObjC/C++ 异常原样传播、longjmp 值、内部捕获不误退、暂停时的状态、缺失展开证据、局部栈已包含真实活动桥时保留父关联、线程退出、六类 GCD/嵌套跨线程任务、任务/时间预算、关闭后的待执行任务、特殊 block 取消/等待、根队列筛选及后代传播、两个公开 block 构造器、重复提交歧义和入队后直接调用不冒充异步执行。完成后重启目标清理临时 Hook 和转发 patch。

接口回归：`python tests/flow_mcp_test.py --endpoint http://<authorized-device>:8088 --aborted-call-id <retained-owned-fixture-call>`。旧 P0/native/live/ABI 拒绝回归继续使用各自自有 fixture，业务请求由正常 UI 产生。设备验证和实际覆盖以 [PROGRESS.md](PROGRESS.md) 为准。

在自检之后、捕获关闭时运行 `python tests/flow_diagnostics_mcp_test.py --endpoint http://<authorized-device>:8088`，验证有界分页、停止证据、正向局部栈计数和非法请求不修改状态/Hook。原始栈 V2 编解码、V1 兼容及截断处理由 `make test-unwind-runtime` 验证。

设计参考：[Apple GCD 队列](https://developer.apple.com/library/archive/documentation/General/Conceptual/ConcurrencyProgrammingGuide/OperationQueues/OperationQueues.html)、[Apple dispatch-block 实现](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/block.cpp)。

## 定向分析窗口

先记录真实队列、提交 caller 和 callback 身份，再选择根队列并排除已观察到的日志洪泛。不要用 `com.k` 等宽泛子串排除整个 App 的网络队列。先开启窗口再触发业务，按 windowStartedNs 与实际任务时间筛选样本；预算结束后发生的普通调用、窗口前已提交的工作及 RunLoop 同步回调分别报告。关联成功要求：完整保留祖先 TaskID 边、执行现场/同步 callId 配对，以及函数返回值与该任务或后代任务下 HTTP 字段的精确匹配；不得用 TID 或时间接近替代。
