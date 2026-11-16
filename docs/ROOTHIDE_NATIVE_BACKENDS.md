# 1.28.35：RootHide Inline / QBDI

RootHide 胖包现在链接真实 arm64 与 arm64e 静态依赖。`get_capabilities` 的后端与进程架构以运行中的 Agent 为准，不能仅凭包版本或工具名判断加载成功。具体真机结果见 [当前进度](PROGRESS.md)。

## 构建与 PAC

- Dobby 固定 `5dfc8546954ce3b3198132ab13fddb89ee92cdd7`，分别编译两个 ABI，再合并并检查切片。[上游 original 指针处理](https://github.com/jmpews/Dobby/blob/5dfc8546954ce3b3198132ab13fddb89ee92cdd7/source/InterceptRouting/InlineHookRouting.h) 会在 arm64e 签名 original。IDH 将其去除 PAC 后存入汇编分支表；thunk 的原始 br/blr 不消费带签名函数指针。符号解析得到的目标地址也先归一并验证可执行映射。
- Dobby 的仓内补丁将 original 以 release store 发布在激活入口补丁之前，消除并发线程先命中、original 尚未就绪的窗口。thunk 在处理事件前 acquire 读取 original，arm64e 当场去 PAC；因此发布期间也不会把签名指针交给裸 br/blr。若后端已发布 original 后失败，槽位和转发元数据保留，不回收给其他目标。该修复不等同于承诺任意第三方补丁的全局线程静止。
- Darwin 写补丁时，先解析依赖，再枚举并短暂停住其他线程；PC 落在待替换指令中、枚举/暂停/状态查询失败时，在写入前恢复已暂停线程并最多重试 4 次。权限切换、写入和缓存刷新期间不调用 Foundation、不分配、不记日志。跨页补丁和修改补丁器所在页拒绝；跳板写入失败必须上传为构建失败，不能返回尚无有效机器码的 original。该机制只覆盖线程枚举快照，不证明外部新线程、第三方补丁或任意异步回调都已静止，因此仍不开放 Inline 硬卸载。
- 动态跳板尚无完整 unwind 契约，命中时仅保存直接调用者 LR/SP，并明确报告 `callStackMode:"direct-caller-only"`；同步层级通过 callId/parentCallId 表示，不在跳板内调用完整栈展开或符号化。内部镜像身份采集绕过自身 dladdr 路径隐藏，保留实际镜像名和 UUID。
- QBDI 固定 `3318580550215a0c7a64e9c2476e02eb5fc55f14`。arm64e 开启 `QBDI_PTRAUTH`，选择上游的认证版执行/栈切换汇编和指针处理；arm64 关闭。参考 [上游配置](https://github.com/QBDI/QBDI/blob/3318580550215a0c7a64e9c2476e02eb5fc55f14/cmake/config/config-macOS-AARCH64e.sh)。
- 上游 iOS 的 ASM_FLAGS 原硬编码 arm64，与请求的 arm64e 构成双架构编译，导致 retab 的 pauth 指令报错。仓内小补丁移除此冲突，按 CMake 请求架构编译；不改二进制架构标签。
- `qbdi_universal_config.py` 验证两份静态 Config.h 只有指针认证开关不同，生成按编译架构选择的头。Makefile 在链接前检查库包含所有请求切片；缺失直接失败。
- 构建命令仍是两个依赖脚本后 `make deb`，rootless / RootHide 保持同版本完整组件。临时依赖构建目录保留在脚本打印的工作目录，便于排查；库属于构建产物，不提交。

## 真实自检

在授权目标恢复 all/other 采集，然后调用：

```json
{"process_generation":"<current generation>","include_native_backends":true}
```

工具为 `run_hook_selftest`。除既有结构化/ABI 测试外，`nativeBackends` 验证：

1. 纯计算函数在 QBDI 下完整执行并与普通 native 调用返回值一致；arm64e fixture 包含 PAC 序言、认证间接调用和返回。
2. 4 条指令预算停止时报告 instruction-limit，而不将部分执行当作有效结果。
3. Inline 转发 15 个固定 C 参数及 Darwin packed stack，观察同 callId 的入口/返回；软停后的原函数转发仍正确。
   安装期间另有并发线程持续执行同一 fixture，结果须与普通 native 参考一致。
4. 已保留 Inline 补丁的目标拒绝作为原函数 Trace 入口。

`pass` 与 `nativeBackends.pass` 都必须为 true。自检的 Inline 补丁软停后保留，完成须重启目标清除；不要靠硬恢复入口字节卸载。自检只运行 IDH 自有纯函数，不调用业务签名 facade。

## 复制输入的指令回放

`trace_function` 的 `args` 最多 8 个整数/指针，接受数字或十六进制字符串。新增可选 `buffers`：

```json
{
  "process_generation":"<current generation>",
  "addr":"<verified executable function address>",
  "args":[0,3],
  "buffers":[{"arg":0,"hex":"616263"}],
  "max_insns":4096,
  "max_ms":5000
}
```

这是将已知 `(pointer,length)` 原型的输入复制到本次调用拥有的可写缓冲区，然后回放一次函数。不是借用 App 原来的临时指针。调用者仍须核对原型、长度、读写范围和副作用；不能用它执行未知签名或把结果当作原请求的 live trace。

每个缓冲区至多 8192B、共至多 32768B、参数下标唯一且必须在 args 范围内。返回 `buffers[].afterHex`，在调用结束前复制输出，随后释放缓冲。零长度输入仍有独立存储，但报告长度为 0。错误的长度、hex、下标或预算在执行目标前拒绝。

响应增加 `executionMode:"replay"`、`contextComplete:false`、`pointerAuthentication`、`retval_valid`。必须同时检查 `call_ok`、`retval_valid`、`stop_reason` 和指令覆盖；预算停止或无覆盖不算取得函数返回值。时间预算是协作式，未插桩的阻塞调用不受硬超时保证。QBDI 上游的 iOS 稳定性、信号、异常与新线程限制仍适用。

如果目标已有 IDH Inline 补丁，即使已软停也拒绝 Trace。先重启目标，重新取得 processGeneration、镜像基址和原函数地址，再回放。它不检查任意第三方补丁或整张调用图，不能将入口检查当作完整执行安全证明。

可复用检查：`python tests/native_backend_mcp_test.py --endpoint http://<authorized-device>:8088`。它检查真实能力、错误输入拒绝和 getpid 解析指针回放，不安装 Hook；设备未显式指定时离线测试跳过。
