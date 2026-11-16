# 1.28.36：QBDI 真实调用现场与同步 native 栈

这是现有 `src/` 研发线的实现协议。操作前检查 `get_capabilities` 的当前进程代、`trace_live`、`native_stack_unwind` 和实际后端；两种整包均须匹配设备。它不代表新 daemon / Manager 架构已经全部落地。

## 真实调用与回放

`trace_live_arm` 等待一个已安装且启用的 Inline 槽位的下一次真实命中。它不主动调用目标，不替换输入指针，也不复制输入后重新执行函数。命中线程只会执行该原调用一次。

IDH 专用 Dobby context 入口先保存 x16/x17，再转入 32B 槽位中的公共桥。公共桥在进入 C 处理器前保存 x0–x30、原始 SP/LR、q0–q31、NZCV、FPCR/FPSR；该路径的入口信息不受常规 veneer 对 IP 寄存器的使用影响。选中命中后，QBDI 的控制代码切到事先分配的、带 guard page 的 2MB 分析栈；guest 执行使用原 App 线程、TLS、SP、原栈及真实寄存器状态。退出时恢复真实结果，包括浮点和隐藏 x8 结构体输出。

`errno` 通过 QBDI 的 `setErrno/getErrno` 初始化和取回其独立 guest 状态，完成 VM 释放和事件处理后再交还给 App。只设置宿主 TLS 的 errno 不足以初始化 QBDI 的备份。

旧 `trace_function` 仍是显式 replay，其参数、输入复制和完成度规则保持独立；不能将它的结果称为原请求执行轨迹。普通动态 Hook 的 post ABI 仍限于已声明固定 GPR 参数；选中 live 路径保存完整 CPU 现场，不等于所有普通 Hook 已支持浮点、聚合或任意 Swift post。

## MCP 操作

1. 获取当前 `processGeneration`，重新解析本代镜像 UUID/RVA 和已验证函数入口。对已知会正常返回的函数安装 Inline；需要输出事件时按真实原型配置 capture，不能为未知函数虚报 ABI。
2. 恢复全局及 `other` 采集，向 `trace_live_arm` 传入当前槽位和正常返回声明：

```json
{"slot":12,"process_generation":"<current-generation>","normal_return":true,"max_insns":8192,"max_ms":10000}
```

3. 由正常 App 操作触发请求；使用 `trace_live_read` 轮询 `trace_id`。`armed/running` 只返回不可变元数据，完成后才能读取现场，避免与命中线程并发读取正在写的快照。
4. 按 `offset/limit` 分页。默认/最大页长受接口限制，最大 256 条；`nextOffset:null` 表示读完。每条指令保存 PREINST PC/SP、x0–x30、q0–q31、标志及反汇编；同时返回 entry/exit CPU、原栈最多 256B、threadId、callId、目标和原跳板地址。
5. 按相同 `callId` 查询 `get_call`，核对同一 TID、SP/LR、参数指针和真实 leave 输出；不按时间邻近猜测。`callCompleted` 还检查 VM 正常返回到原 LR、SP 保持原入口值。

可选 `thread_id` 是十进制/十六进制字符串；只选择该线程命中。arm/cancel/selftest 都检查当前 `process_generation`。只允许取消尚未命中的会话；正在执行的原调用不通过取消或 HTTP 超时中止。

每个进程最多保留 8 个会话，同时只有一个 armed/running；固定容量及控制栈均在 arm 阶段分配，完成后保留至进程退出，不复用仍可能被汇编恢复引用的快照。满额后重启授权目标并重新握手。预算为 1–8192 条记录、1–10000ms；时间预算在指令回调检查，不是函数执行超时。达到预算只停止记录、设置 `recordingTruncated/stopReason`，QBDI 继续原调用至正常返回，不能中断部分副作用后重放。

覆盖范围为目标模块和 original 跳板；模块外执行按 native transfer 计数，没有模块外逐指令记录。递归进入分析路径不再次启动 VM。异常、longjmp、线程创建、信号控制流、非返回函数或特殊 Swift 调用约定不在承诺范围，`normal_return:true` 是调用者对已确认目标的约束，不是自动证明。[QBDI C API](https://qbdi.readthedocs.io/en/stable/api_c.html) 与 [固定上游源码](https://github.com/QBDI/QBDI/tree/3318580550215a0c7a64e9c2476e02eb5fc55f14) 继续适用。

## 栈展开与符号化

动态入口从捕获的原 caller 寄存器、SP 和 LR−4 初始化系统 libunwind cursor，先加入语义上的被调入口，再展开同步 native caller。方法/导入/Inline 公共桥具有 CFI，包含 post 路径的栈参数区；arm64e 为展开单独保存按原 CFA 签名的返回地址，原始转发 LR 不与 CFI 返回槽混用。分析备用栈的桥明确终止其自己的 unwind，live 结果使用切栈前的 App caller 现场。

默认密码/网络 Hook 的栈也改为采集有界原始 PC/SP，不再在命中线程调用完整符号化。`payload.stack` 含 `frames/complete/truncated/error/scope`，最多 256 帧；缺失展开信息、循环帧和预算耗尽如实报告，不能把缺元数据当作正常根。`complete:true` 指 libunwind 正常走到该同步 native 链的根，不意味着恢复被优化掉的 inline/tail-call 或跨线程异步逻辑帧。

原始栈写入 journal；`get_event/get_call` 等读取路径才补充镜像路径、UUID、RVA 和最近符号。`dladdr-nearest` 不是可靠函数边界，尤其裁剪符号的 App 可能返回距离很远的符号。旧代/恢复事件保持原始 PC/SP，并标 `symbolication:"unavailable-for-old-generation"`，绝不套用新进程的 ASLR 或镜像列表。

系统 unwind API 在 Agent 初始化时从系统 libunwind 动态解析，握手只报告实际可用性。CFI 和栈检查用于观察正常调用；普通 post 的异常清理、TLS 关联恢复及异常安全卸载仍不支持。Inline 硬卸载继续拒绝，清除补丁需重启目标。

## 验证

- Mac：既有 `make test-hook-runtime`，新增 `make test-unwind-runtime` 检查嵌套 post 桥穿过原 driver 到根、原始栈文本恢复与截断状态；`make test-hook-ios-build` 编译真实 arm64/arm64e 汇编。更新策略和两种完整 `make deb` 检查继续执行。
- 实机：显式 `run_live_selftest`（当前进程代，恢复 all/other）测试 IDH 自有受控函数：15 参数 packed stack、真实栈展开、浮点/SIMD、隐藏 x8 聚合输出、入口 IP0/IP1、errno 入口/出口、4 条记录预算不中断调用、命中前取消。计数器验证恰好执行一次。此测试保留会话和软停槽位，完成后重启目标。
- 接口：`python tests/live_trace_mcp_test.py --endpoint http://<authorized-device>:8088 --trace-id <completed-owned-fixture-trace>`，检查能力、不可变分页、完整寄存器、错误参数/旧代拒绝且 Hook 配置不变；既有 native/P0/复杂 ABI 拒绝测试仍执行。
- 本轮两台快手 14.10.10 的真实 CRC/HMAC/白盒调用分别记录 2489/7603/5449 条完整指令，真实输出与独立离线复算一致。CRC 栈 rootless 85 帧、RootHide 129 帧，HMAC 76/76、白盒 77/77，均 complete、未截断、error 0。详细验证范围见 [当前进度](PROGRESS.md)。原始业务捕获只保存在本机验证目录。
