# 私有 libdispatch callback 入口（1.28.49 研发包）

实际快手 source 回调的 native 栈包含未导出的 libdispatch callout；`dlsym` 无法解析名字。新增适配器从自有公开 source 的原 `_f` 回调返回地址定位函数，经系统 unwind 边界、当前镜像和完整识别的 A64 调用/返回序列验证，然后用同一 source 再次执行验证原 context、函数指针和次数。arm64e 校验 PACIBSP、BLRAAZ x1 与 RETAB；不靠最近符号、固定地址偏移或私有 dispatch 对象布局。

原型来自 Apple 官方 [libdispatch init.c](https://github.com/apple-oss-distributions/libdispatch/blob/libdispatch-1325.120.2/src/init.c) 的 `void(void*, dispatch_function_t)`。保留系统原 callout 包含的转发/异常处理。当前仅识别已观测到的两种 iOS 序列及现代 macOS 的紧凑 PAC 序列；未匹配时在补丁前报告 unsupported，不自动改用另一种 ABI。

`configure_dispatch_entry` 独立默认关闭，开启只准备转发适配器，不打开采集窗口。另用 `configure_async_capture` 配置原有 256/60 秒窗口，可用 `root_api_include:["libdispatch.client-callout"]` 定向。实际当前队列标签来自公开 API。关闭或窗口关闭后直接原样转发；已存在的已观测 async 身份优先，Agent 自身函数不作为 App 根。原 adapter 与 Inline/Trace 共用目标所有权，进程重启清除。

记录为 `observed-callback-entry; registration-unobserved`，registrationId 和 submittedBy 为空；它不证明 callback 是 source、notify 或异步提交，不会按线程或时间猜注册。公开 source 适配器已有真实注册时继续使用已有关系；新入口可观测窗口前已存在、没有观测到注册的 App 回调。函数、原 context、queue 和业务行为仍归原 libdispatch 管理，额外记录沿用有界原 Flow 表和既有非局部退出状态保护。

`get_dispatch_entry_state` 返回准备/开关、候选代码、原型校准及目标归属。`run_dispatch_entry_selftest` 拒绝覆盖当前 async 窗口，独立原生夹具检查 default-off、原 context/function、同一旧 source 的重复执行、不同 execution ID、缺失注册字段与关闭后的原工作。`make test-dispatch-entry-runtime` 使用独立 macOS 原生 Dobby；另有独立 C 负例拒绝跨函数前缀、错误 callsite/函数寄存器、改参指令和 PAC 返回不匹配。新 MCP 语义测试位于 `tests/dispatch_entry_mcp_test.py`。

最终 Mac v43 全门禁及两类完整包通过，两台各 4 组原生/5 项新 MCP，通过 typed 所有权冲突、非法/generation、独立开关与自检不覆盖窗口。还在全新进程先安装并关闭私有适配器，再通过 Swift 81 生命周期/4 错误 future/5 MCP、原 39 flow、timer/operation/unwind、native/PAC/ABI/live 与接口；没有依赖“未装补丁”的状态代替默认关闭回归。自有校准 context 由 source 的取消 block 保有到 disposal，超时返回时也不借用栈上 context。

实际快手专窗：Rootless 19、RootHide 18 个原 callback 入口与 private TaskID、精确 PC/线程/执行区间和完整 native 栈匹配。没有注册或提交历史，相关字段保持空；开窗前与关闭后原 callback 继续且没有新 TaskID。相同原 context 地址在前/中/后出现仅作为观测，不能据此推断 source 生命周期。两窗不足增量为 0；先期 v41 的 Rootless 3 次 App 日志路径 metadata 止步保留为负例，不套用新父边。

开启私有适配器与 Swift 观测的最终普通网络窗口：Rootless 22 棵/330 对、RootHide 24 棵/360 对完整签名调用，核心 15 参数、HTTP 和独立 HMAC/白盒/CRC 分别 22/66/22、24/72/24 一致；7/6 条精确 GCD/native/HTTP 链，256/246 任务完成，不足增量 0。窗口无新 App Swift Task，也没有私有入口→sig3 的推断。QBDI 异常/longjmp 透明执行继续独立实施。

此前同包 1.28.48 扩大的实际 source 页面窗口已独立通过：Rootless 2 个注册/6 回调，RootHide 3/7，均为 `tachikoma.timer_diagnostics` 队列上实际 App setter、原 callback PC、Task/registration ID、线程/时段与完整 native 栈精确匹配；每台有注册重复三次。17/16 个旧 callback 没有补造注册。该证据是注册/执行能力验证，不代表 source→sig3。

最终 v43 source 窗口重新验证：Rootless 2 注册/14 原 callback、RootHide 4/10，全部精确匹配；30/16 个窗口外旧 callback 不补造注册。Rootless 先期全类别加载窗口出现背压（含 23 条 other 丢弃），没有把任务表记录当作对应入口事件的替代。最终只开本窗口需要的 other 类并周期导出，丢弃为 0；关闭采集后恢复原捕获配置每一个字节。窗口关闭后的原回调仍继续，因此 observedInvocations 可大于 capturedInvocations，不能把两者强行等同。
