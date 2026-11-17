# RunLoop / NSTimer 的实测关联

`configure_async_capture` 沿用显式窗口、任务/注册/深度/挂起预算。默认关闭。`root_api_include` 可以选择 `NSTimer`、`CFRunLoopTimer` 或 `CFRunLoopPerformBlock`；只有根入口受该选择限制，后代仍可跨队列传播。模式名来自实际执行时的 `CFRunLoopCopyCurrentMode`，不把创建线程推测为执行线程。

`root_callback_include` 可按创建时直接观察到的 target 类/selector 标签筛选根注册，最多八个不区分大小写的子串（每项 127 UTF8 字节）。NSTimer target factory 标签为 `[Class selector:]`，block factory 为 `NSTimer.block`；registration/task 的 callbackLabel 提供该证据。此标签表示工厂实参，不承诺后来动态消息实际执行的 IMP。未知标签不会匹配，包括未观察到创建的旧 timer；后代不因新根筛选而丢失传播。该筛选适合先观察注册标签和创建 caller 的 UUID/RVA，再缩小下一窗口，避免高频无关定时器耗尽原有预算；不扩大预算或按时间猜父关系。

## 三类边

- `CFRunLoopPerformBlock` 是确实观察到提交与执行的单次任务，沿用 `observed-submit-to-execute`。
- 窗口内观察到 CF timer 创建或四种 NSTimer 工厂方法时建立独立 registration。每次实际回调建立不同 task，边为 `registered-handler-to-callback`，事件 phase 为 `delivery`，引用真实 registrationId。重复 timer 的注册与各次执行分开。
- 窗口前创建的 NSTimer 没有可恢复的注册历史。已校准的 Foundation 回调入口只能报告 `observed-callback-entry; registration-unobserved`，事件 phase 为 `callback-entry`；registrationId、asyncSubmittedByCallId 为空，asyncEnteredByCallId 仅记录本次入口的已观察同步上下文。不会生成 submit/delivery 事件或猜测历史父任务。

## 保持原行为

六个公开 CF 导入与其它调度导入统一预检所有权：Create、CreateWithHandler、Invalidate、AddTimer、RemoveTimer、PerformBlock。CF 原 timer 参数、context.info/retain/release、handler 参数、原 loop/mode、失效行为保持。CF context 的 retain/release 次数由框架决定，测试比较同一系统、相同行为的未采集基线，不硬编码系统实现次数。

NSTimer 的 scheduled/unscheduled、target/block 四种 class factory 使用固定真实原型转发 double、BOOL 与对象；不替换 target、selector、userInfo 或原 block，不解析私有 info 布局。内部 CF 创建去重。`[timer fire]` 是同步调用，不能假称经过 RunLoop 调度。未知 timer 子类不强转为已校准的 CF timer。

Foundation `__NSFireTimer` 每个进程重新 dlsym/映射校验；安装使用统一 typed Inline 所有权和已有 Dobby original 先发布机制。安装后通过自有 target 与 block timer 在实际 RunLoop 执行，验证公开 CF context 与真实入口 `(timer, info)` 以及原回调各执行一次。校准不匹配就不启用该入口/工厂交付关联，不将其它系统版本的 ABI 当作已验证。Mac 无 Inline 的测试明确跳过原生入口，仍验证公开 CF 路径。

## 读取与生命周期

`get_timer_state` 只读返回 processGeneration、校准计数/结果、native adapter 的 UUID/RVA/签名、工厂可用性及最多 64 个存活 binding。每进程 binding 创建上限 64、不复用；registration 总表沿用 128、不复用。失效或对象释放退休 registration；窗口关闭后不捏造后续 delivery。已安装物理补丁保留到进程重启，关闭捕获不代表卸载。

typed native/Method adapter 与动态 Hook 共用安装锁和目标互斥。冲突 Import/Inline/Method 请求拒绝，已补丁 native 目标不能作为 QBDI replay 入口。其它插件自行修改 ObjC runtime 不在 IDH 安装事务的保护范围。

验证入口：`make test-flow-runtime`、双机 `run_flow_selftest`，随后在同一新进程运行 `python tests/timer_flow_mcp_test.py --endpoint <明确授权设备>`。自有夹具通过不代表真实 App 每一种 timer 或所有异步请求都已覆盖。NSOperation、Swift Task、私有调度和 QBDI 非局部控制流是独立工作。

借用语义回归：将 `src/core/dh_flow_sources.m` 分别以 iOS arm64/arm64e、`-O2 -fobjc-arc -S -emit-llvm` 编译，再运行 `python3 tests/dispatch_borrowing_ir_test.py <两份 .ll>`。检查转发函数不额外 retain/release 借用的 source/queue/object 输入；被包装的 block 仍需在 setter 返回后由包装器强持有。原 source 生命周期夹具同时验证后者，不能通过把所有对象都改成 unsafe 来修复。
