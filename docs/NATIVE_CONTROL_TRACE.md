# 原生控制流现场跟踪

1.28.50 新增独立、显式准备的 `live-native-control` 模式。普通 `trace_live_arm` 继续要求 `normal_return:true`，原有正常返回门禁和八个保留会话上限不变。当前实现与验收进度见 [PROGRESS.md](PROGRESS.md)。

## 范围与操作

目标是已经确认固定、非变参 GPR 原型的 App 原生函数。准备时只执行 IDH 自有夹具校准，不主动调用业务函数。开启全局／other 采集、关闭异步采集窗口后，使用当前 generation 和重新解析的函数地址调用：

1. `prepare_control_trace`：`process_generation`、`address`、`native_abi:"darwin-fixed-gpr"`、`abi:{arguments:[...],return:...}`；可带原有的 `capture_memory`、`capture_after`、`capture_multi`、`capture_ret_multi`、`describe_args`。返回独立 root slot。首次自有校准占一个会话。
2. 按需要开启原有 GCD／Swift／私有入口观察，再调用 `trace_control_arm`：`slot`、可选 `max_insns`（1..8192）、`max_ms`（1..10000）和原生线程过滤。
3. 让 App 自己产生实际调用，通过 `trace_live_read` 分页读取原始现场、指令和 `controlFlow`。`trace_live_cancel` 只取消尚未命中的会话，不终止正在发生的 App 调用。

root 的配置不可变。未 arm、软停或其它线程的调用原样转发；代码补丁与夹具资源保留到进程重启。系统运行时和 Agent 辅助函数不能作为这种模式的 root，它们保持原生执行。旧的普通 Inline root 不能在原址静默切换为新模式，须先重启、重新解析并准备。

`get_control_trace_state` 分开报告链接／准备／自有校准、当前活动状态、保留 root／恢复点、资源是否加载和共享会话预算。普通 Hook 的 ABI 限制继续适用；不能因为准备过此模式就把其它普通 post 声称为异常透明。

## 实际执行与恢复

QBDI 在离开目标镜像前退出 VM，保留真实寄存器、SP、LR 与 errno；原生 callee 在原线程和 App 栈上执行。没有用 `vm.call` 重放、替换指针或重新调用目标。新依赖的专用选项还覆盖没有 broker 返回点的原生返回，避免悄悄继续展开系统代码。普通 VM 不启用此选项。

恢复点只改写一个 A64 指令。优先使用新分配且专属的近距页；内核不允许在严格 B 范围内分配时，使用专属 `BRK #0x4944` 与进程内 Mach 接收线程恢复原线程现场。不占用未知代码空洞，不通过 `MAP_FIXED` 覆盖别人的映射。原始指令先于物理补丁发布给只读解码器，后续 VM 仍按原 PC 解码原指令。BL／BLR 和已识别的认证链接指令在关闭后的转发路径也保留真实 LR；未知链接形式和依赖 IP0 输入的特殊边界拒绝安装。原生 C 调用边界允许 IP0／IP1 scratch，这不是任意特殊寄存器 ABI 的逐位透明保证。

Mach 接收线程只处理原进程内、精确槽位／PC／原始指令归属和专属 BRK 匹配的现场；在原可写栈做与近距岛相同的 IP0/IP1 保存，通过公开 ARM thread-state 与 PAC setter 返回原线程的 context thunk，应用逻辑继续在原线程执行。SDK MIG 生成并校验消息，服务端与转发 stub 使用独立符号，生成文件不进入源码。没有安装或替换 App 的 SIGTRAP 处理器。已有 task breakpoint handler 的 DEFAULT／STATE／STATE_IDENTITY 与 32／64 位 code 协议按原 flavor 转发；已有 thread 级处理器、未知协议或超过 1024 线程时拒绝准备。仅接管 task 的 BREAKPOINT mask，原处理器、端口与补丁保留至进程重启；此期间要求其它调试器不改写异常端口，状态提供当前所有权，丢失所有权后拒绝新的 arm。不能把“没有近距页”误报为目标调用已经成功跟踪。

每个会话保存有界原生 continuation 栈。只有同一实际线程、会话、PC 和原 SP 匹配才恢复；旧恢复点或其它递归层经过同址不会猜配。旧 20 字节 Inline veneer 的入口保持 opaque，先交还原生 CPU 再进入 veneer，避免把它的临时 IP0/IP1 压栈误认成调用者 SP。未看到所需 continuation 会报告 coverage gap，不能用最终返回冒充完整覆盖。

## 异常与跳转证据

使用真实五参数 Itanium／ObjC personality 原型，原样转发参数、异常对象与 reason code。仅在 cleanup phase 的真实 `INSTALL_CONTEXT` 后，通过公开 `_Unwind_GetIP/GetCFA` 观察安装的 landing pad 与帧 SP；不猜 LSDA。目标模块内、root 以下的 landing pad 经实际命中恢复 VM；原生 helper 内的 cleanup／catch 保持原生；已越过 root 的安装清理该 root 的调用状态，不产生假的 leave 或返回值。

setjmp 家族在真正入口观察，以汇编恢复原 SP/LR 后继续原函数，不能使用会让系统保存 wrapper 帧的普通 C 返回包装。公开 setjmp 调用的实际返回 PC/SP 另行确认，内部同 env 的保存入口不能把公开 continuation 覆盖成 helper 的 LR。记录只关联实际 env 指针、调用 ticket、线程和不复用的会话；不读取私有 `jmp_buf` 字段。原 OS 完成 longjmp 的 0→1、寄存器及 signal mask 恢复，IDH 只在实际 continuation 命中后记录 `longjmp-resumed`。

关键事件区分 `native-handoff/native-return`、`public-landing-pad-install/landing-pad-resumed`、`setjmp-entry/public-setjmp-return/longjmp-entry/longjmp-resumed` 和 `nonlocal-exit`。原生交还与返回携带同一 `transferTicket`；跳转关联另带 `environment` 与 `environmentTicket`，分别报告请求值和实际恢复的 X0。安装、交还或跳转请求不是实际恢复，native helper 未展开也不等于其中没有执行。

范围外退出在原线程以 POD 脱离准确 root token 及其子 guard、恢复计数和同步上下文；日志／JSON 延后由读取侧生成，保留原线程和观测时间。异常退出没有 return value。未观测的 env 明确 unresolved；异步 signal 在正在执行的 VM／分析器内任意位置跳出不属于透明展开能力，已中断的 VM 不重入或销毁，不伪称捕获到了后续指令。Swift 特殊调用约定、跨线程 longjmp、无元数据任意展开及无限恢复点均没有由此获得支持。

## 自检与构建

`run_control_selftest` 使用整包内两个独立的自有原生资源：目标模块与 opaque callee 分离。要求新进程八个空闲会话，覆盖原对象／结果／线程／TLS／errno、C++ 析构、ObjC finally/rethrow、内外捕获、longjmp/siglongjmp、mask、0→1、env 复用、递归 root、相邻 native call、旧 Inline 互操作、结构化 entry/leave/abort、预算和取消。内部每种恢复之后必须实际记录到后续指令。另一个全新进程可显式传 `force_breakpoints:true`，要求真实 Mach 恢复计数大于零；不能只测试到近距路径便声称断点路径通过。结束后重启目标。

Mac 使用独立的 `tools/build_dobby_macos.sh` 与 `tools/build_qbdi_macos.sh`，再执行 `make test-control-runtime`。它分别验证近距／强制 Mach 的完整自检，以及“校准后关闭控制模式，再通过原 live 七项门禁”的独立进程；还运行六种原处理器转发、thread 处理器冲突拒绝及原未知 trap 负例，检查 GPR／SIMD／flags／TLS／mask 和 identity send-right 引用数。缺少原生 host 依赖时打印 skip 原因；新增 CI 的 ARM64 前提会先单独检查。iOS 依赖仍分别编译真正的 arm64／arm64e，整包构建、架构与签名检查包含两个资源，不能仅复制裸 Agent。

ABI 依据：[LLVM libunwind 公开接口](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.5/libunwind/include/unwind.h)、[pinned QBDI Engine](https://github.com/QBDI/QBDI/blob/3318580550215a0c7a64e9c2476e02eb5fc55f14/src/Engine/Engine.cpp)、[A64 指令编码](https://support.arm.com/documentation/ddi0602/2023-12/Index-by-Encoding)。依赖扩展只应用于记录的 pin，代码与测试在本仓维护。

Mach ABI 使用当前 Xcode SDK 的 `mach_exc.defs`／`exc.defs` 与公开 ARM thread-state API；上游实现依据见 [Apple XNU exception dispatch](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/exception.c) 和 [ARM exception codes](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/arm/exception.h)。
