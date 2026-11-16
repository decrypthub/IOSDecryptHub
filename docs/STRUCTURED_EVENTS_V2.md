# 1.28.34：结构化事件、同步调用关联与 ABI 边界

`get_capabilities` 返回 `eventSchemaVersion:2` 和本次 Agent 的 `processGeneration`。地址、Hook 和调用 ID 都属于一个进程代；重新启动目标后必须重新握手、解析地址。历史事件保留采集时的代标识。

## 事件与关联

事件 JSON 的顶层增加 `schemaVersion`、`kind`、`phase`、`processGeneration`、`pid`、`agentBuild`、`monotonicNs`。函数事件还包含 `hookId`、`callId`、`parentCallId`、`depth`、`pairing`、`targetIdentity`；地址、64 位 token、单调时间和寄存器值用字符串表达，避免 JavaScript 数值精度损失。

- 同一次正常返回的调用，`entry` / `leave` 使用相同 `callId`。递归和并发线程不会依靠时间邻近配对。
- `parentCallId` 来自本线程正在执行的、已启用 post 的动态 Hook。默认密码/网络事件在采集时取得同一上下文；网络响应合并保留请求原来的上下文。
- 这是**已观测的同步调用关系**。entry-only Hook 不留存活动栈帧；异步任务、未 Hook 的调用和完整跨线程因果图不在覆盖范围。TLS 栈最多 64 层，溢出计入 `contextLostTotal`。
- `targetIdentity` 给出安装时的运行地址、镜像路径、UUID、运行时镜像基址与 `rva`。`rva` 相对该镜像基址，不能与 Mach-O vmaddr 混用。

`payload` 提供机器可读的证据：

| 字段 | 含义 |
|---|---|
| `rawRegisters` | 入口 x0–x8 或返回 x0/x1 的原始值 |
| `arguments` | 声明类型、参数下标、寄存器名或 Darwin 栈偏移、采集状态和数值 |
| `arguments[].object` | 显式启用描述且类型为对象时的快照；NSString/NSData 有界截断，其他对象只记录类和地址 |
| `returnValue` | 是否请求、是否存在合法返回值、声明类型与可用数值；void 不解释成对象 |
| `memory` | 阶段、来源寄存器、请求/实际长度、hex、截断和 captured/unreadable/empty/deferred 状态 |
| `caller` | 命中时直接调用者 LR 与原调用者 SP |
| `abi` | 签名来源、参数映射、栈转发范围及不支持的能力 |

`capture_after` 在入口只标 deferred、不读取输出区，leave 才按入口指针采集。长度寄存器为 0 表示空数据。`capture_multi` 是入口窗口，`capture_ret_multi` 仅允许返回 x0/x1；两者不能混作原始函数参数。

旧 `detail`、input/output 和栈字段仍可展示，但新客户端必须按 `phase` 与 `payload` 解析，不再匹配 detail 中的 `return` 或 `win_hex`。旧 journal 没有上下文时导出为 schema 1，不为其补造新进程身份。结构化 journal 负载最多 64KB，超限明确标记省略；恢复项带 `restoredFromJournal:true`。

## 查询

`query_events` 增加精确过滤器 `process_generation`、`call_id`、`parent_call_id`、`hook_id`、`phase`。摘要不含完整 payload，需要 `get_event`、`export_events` 或 `get_call` 获取详情。

```json
{"call_id":"<generation>:<decimal-token>","include_children":true,"limit":100,"max_blob_bytes":256,"max_output_bytes":524288}
```

将上述参数传给 `get_call`。响应给出保留的配对状态、entry/leave seq、子事件、`matched` 与 `resultTruncated`。默认 50 条、每个 hex 256B、事件编码预算 512KB；上限为 200 条、每个 hex 8192B、事件编码预算 2MB，外层响应元数据另计。对象文本另受采集时的 1024 字符上限约束。`open-or-leave-not-retained` 表示尚未返回或返回事件已被淘汰，不能仅凭它断定函数仍在执行。

## 安装与 ABI

以下工具必须传 `process_generation`，缺少或过期时在操作前拒绝：`hook_method`、`hook_inline`、`hook_import`、`unhook`、`trace_function`、`objc_call`、`run_hook_selftest`。

ObjC post 采集需要 `post_abi:"fixed-nonvariadic"`，由调用者确认方法不是变参。运行时类型编码不能自动识别 `...`。允许最多 32 个固定 GPR 标量/指针/对象参数，按 Darwin 自然大小和对齐转发至多 256B 栈参数。浮点、聚合和未知 ABI 拒绝 post，保留不猜测参数布局的入口观察。

C / Inline / Import 的 post 必须声明原型，例如 6 个参数、void 返回：

```json
{"abi":{"arguments":["pointer","pointer","pointer","u64","pointer","pointer"],"return":"void"},"capture_after":true,"capture_memory":{"ptr_arg":1,"max_bytes":32}}
```

支持 `pointer/object/u64/i64/u32/i32/u16/i16/u8/i8/bool`，返回另支持 `void`。这是**调用者提供的原型**，不是自动从机器码证明的 ABI。变参、浮点/向量、聚合返回、隐藏结构体返回和异常展开不支持 post；不得给未知函数虚报原型。

完整配置在发布 patch 前验证，发布后不可修改；更换方法配置应卸载后分配新槽位。方法硬卸载先核对当前 IMP 是否仍由该 Hook 持有，保留在途调用所需的原函数与元数据；不会覆盖后来安装的其他 IMP。没有线程静止机制时拒绝硬卸载 Inline。Import 仅支持软停。需要清除残留 patch 时重启目标 App。

Import 安装前解析可执行符号，缺失/数据符号不注册 fishhook；注册使用槽位永久保存的符号名与解析后的固定转发目标，对当前及未来镜像有效。它不保留每个镜像不同的 interposer 链，也不保证所有 GOT 写入均成功，须看诊断、hits 和真实 entry/leave。分配器及关键 ObjC runtime 符号被拒绝，以免事件处理器分配内存时递归。

## 验证入口

- Mac：`make test-hook-runtime`，实际汇编 thunk、15 参数、递归/并发、缓冲区、所有权、在途卸载、真实 C 导入命中及 journal 跨进程恢复。
- 两种整包：`make test-updater`、`make deb`。
- 真机：恢复 all/other 采集后显式调用 `run_hook_selftest`，它只操作 IDH 自有测试方法；`include_c_import:true` 另测试 getpid，完成后需重启目标以清除软停的导入 patch。`pass:false` 必须按 error 处理，不能把正常返回当作命中过 Hook。
- MCP：`python tests/hook_mcp_test.py --endpoint http://<authorized-device>:8088 --call-id <retained-nested-call>`。
- 复杂方法拒绝：`python tests/method_hook_guard_test.py --endpoint http://<authorized-device>:8088 --class-name IDHABIProbe --selector floating:`。

RootHide 当前整包仍不含 Inline/QBDI 后端。结构化 ObjC/Import 事件与调用关联不依赖这两个后端。
