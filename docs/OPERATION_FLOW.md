# NSOperation 调用关联（1.28.47 研发线）

通过原 `NSOperationQueue` 和原 operation 对象执行工作，保留依赖、取消、并发上限和等待行为。IDH 记录提交以及实际 `start`、`main` 或普通 block 回调，生命周期另读原对象的公开属性。原队列仍决定何时可以执行依赖中的工作；依赖不会被伪装成 `asyncParentTaskId`。

## 开启与读取

使用既有 `configure_async_capture`，例如：

```json
{"process_generation":"<current-generation>","enabled":true,"capture_roots":true,"max_tasks":128,"max_ms":30000,"root_api_include":["NSOperation","NSBlockOperation"]}
```

`root_queue_include` 可以筛选 `operation:` 开头的逻辑队列名，`root_callback_include` 可以筛选实际类与回调标签；筛选只作用于根，后代仍可换队列/API。原 256 任务/60 秒窗口、1024 任务、64 在途和深度 8 限制不变。默认关闭；关闭不取消原工作，已经提交的 one-shot 身份在实际执行时仍可使用。

新增 `get_operation_state` 返回准备状态、拒绝原因和有界 operation 历史。它刷新仍存活对象的公开生命周期属性，并依据已经 finished 或对象已释放的证据，将未观察到执行的 pending token 记为 unresolved。它不改变 App 的 operation 状态。`run_operation_selftest` 需要当前 generation，且拒绝覆盖已有活跃窗口或在途任务；使用独立队列，退出关闭测试窗口，适配器保留到目标重启。

## 覆盖和身份

五个固定 ABI Method 适配入口：

- `NSOperationQueue.addOperation:`、`addOperations:waitUntilFinished:`、`addOperationWithBlock:`。
- `NSBlockOperation.blockOperationWithBlock:`、`addExecutionBlock:`。

提交时按实际类登记具体 `start`/`main` Method。若类覆盖了 `start`，观察该覆盖，即使 `isAsynchronous/isConcurrent` 为 false；同步自定义 `start` 可以直接完成工作而完全不调用 `main`。只有继承 Foundation 基础 `start` 的情况选择 `main`，避免把 Foundation 队列可能绕过的公开 start 当成唯一执行入口。类型不符、归属冲突或容量不足时继续原调用并报告拒绝，不猜函数原型。

普通 App block 的每个执行体有独立 token，保留原捕获对象及原调用次数；多个 block 不共用一个正在运行的上下文。原 operation、依赖对象和顺序保持，`executionBlocks` 中被观测的普通 block 会显示转发包装器。未知或特殊 dispatch-block 保留原对象，不强行包装。

每个进程通过自有多 block operation 校准实际 Foundation invoker 的函数范围。只有该实际入口且 operation 正在执行时，才能领取对应的 pending block 身份；直接调用 `executionBlocks` 的 body 继续执行，但不会抢占队列任务，歧义 token 明确 unresolved。入队后、执行前添加 block 同样观测；若回调已经在绑定发布前执行，保留不足而不倒填 start。

所有 Method 与动态 Hook 共用归属检查，不能互相覆盖。共享元数据使用 IDH 自有锁，不获取 App 的 operation 监视锁；worker 列表按同一锁快照读取。最多 32 个具体执行 Method、64 个 operation 元数据记录、128 个 block 包装器；这些槽位本代不复用。历史元数据弱引用 App operation，且不因保存记录而延长原对象或原 block 的生命周期。达限、窗口前创建或未经过支持入口的工作不能承诺全部 block 子边，原工作继续。

## 回调结束与 operation 结束

`executionTaskId` 表示实际选择的执行回调，`executionMethod` 明确为 start 或 main；`workers` 是各 block 的独立任务。`startEntries/mainEntries` 统计实际适配 Method 入口，包含实际的 super 调用，不能直接当作逻辑 operation 数量。

回调的 `completed/normal-return` 仅表示回调正常返回。异步 operation 的 start 返回后可能继续工作，取消请求也不自动代表 finished。完成状态来自原 `isFinished/isExecuting/isCancelled/isAsynchronous`；读取时提供 `lifecycleSampleNs`、`lifecycleObservation`、`operationAlive` 和读取错误，明确当前属性与对象释放前的最后样本。不会根据时间或没有看到后续调用推断完成。Apple 对 [start](https://developer.apple.com/documentation/foundation/operation/start%28%29) 和 [异步 operation](https://developer.apple.com/documentation/foundation/operation/isasynchronous?language=objc) 的公开约定也区分这些状态。

正常回调使用已有真实 wrapper/CFA/cookie 的状态保护；嵌套 super 调用由 once-only token 防重，没有额外会被 longjmp 遗留的 operation TLS。普通调用的状态保护不等于 QBDI 内异常/longjmp 透明执行支持。

## 验证

独立 `make test-operation-runtime` 和 `run_operation_selftest` 覆盖原对象/依赖、多 block 并发身份、自定义同步 start、异步 start 与取消/finished 的区别、取消前未执行、窗口关闭后的 pending、入队后添加 block、直接调用 block 不抢任务、App 自有监视锁不增加等待、Unicode 队列名、BOOL waitUntilFinished 和预算后继续转发。`tests/operation_flow_mcp_test.py` 验证这些原生证据、generation、活跃窗口保护和 Method 归属。

专项必须隔离自有队列；App 的后台任务和活动命中计数会自然变化。原 flow MCP 夹具会验证自身固定的 unresolved 集合，因此完整流程先跑原回归，再跑新的 operation 专项，或使用独立进程代；不能混入其它夹具后下调原断言。

当前真机与实际快手验证结果以 `PROGRESS.md` 的最终记录为准。真实图片加载 operation 的工作链不能直接当作 sig3 请求链，后者仍需任务身份、真实原回调栈与精确 HTTP 数据分别证明。
