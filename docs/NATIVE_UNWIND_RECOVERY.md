# 原生栈的有界恢复（1.28.46 研发线）

系统展开信息不足时，IDH 可以显式登记一段经过独立验证的 A64 函数，恢复它实际保存的 caller 寄存器，再继续系统 libunwind。默认没有规则；不扫描 FP 链，不修改 App 指令、异常表或原 CPU 现场。这与 QBDI 内异常、longjmp 透明执行是不同能力，后者仍在后续清单中。

## 登记与使用

先读取 `get_capabilities.processGeneration` 和 `get_unwind_state`，再调用：

```json
{"process_generation":"<current-generation>","address":"0x<current-function-address>"}
```

工具名为 `register_unwind_recipe`。地址必须是本代可执行地址；Reader 使用独立的 `LC_FUNCTION_STARTS` 精确边界，不能使用 libunwind 自己给出的范围证明自己正确。函数最多 256 个指令槽、1024 字节，保存帧最多 512 字节。静态验证器沿所有可达 CFG 边追踪 SP、FP、原始 x19–x30 的保存槽和覆盖状态；汇合处必须完全一致。`instructionSlots` 是整个边界的槽数，`eligiblePoints` 才是实际可以恢复的位置数。

当前只接纳有限的整数 A64 指令和 canonical 无 PAC 帧。未知指令、SIMD、动态 SP、平台寄存器写入、未保存的非易失寄存器写入、保存槽覆盖、SP/FP 地址逃逸、内部子程序及无法证明的出口均拒绝。带保存/恢复桩的混淆函数也可能拒绝，不能将它解释为 App 的非法函数。

每个进程最多 32 条不可替换、不复用的登记。同范围同字节登记幂等，保留原启用状态；重叠或替换须重新启动目标。`set_unwind_recipe_enabled` 使用本代 `recipe_slot` 和布尔 `enabled` 显式开关。规则属于当前进程 RAM，重启后须按新 UUID、基址和 generation 重新核对登记。

## 命中时的验证和恢复

启用规则在其范围内优先于系统 metadata。实际恢复前重新读取全部函数字节，核对验证快照、当前指令状态、线程栈界限、精确 SP/FP 关系和所有保存槽。保存的 FP 必须对齐且在 caller 栈界内；保存 LR 必须本身无 PAC/tag、指向 RX，前一条是实际 BL/BLR。不会把 strip 后的任意数值当作有效 LR。

恢复仅作用于私有 unwind cursor：通过系统公开 context/init/register API，保存并恢复完整 GPR 及非易失 D8–D15，设置 caller IP 后重新核对 SP 与寄存器。不会解析、复制或修改系统 opaque cursor 布局，也不会把这些值写回正在运行的 App CPU。caller PC 使用已验证保存 LR 减 4，并保留明确的地址语义。

规则不能恢复当前指令或验证失败时，采集在该处停止，报告 `registered-recipe-refused-before-system-step` 及具体原因。它不会再次交给该处不可靠的系统 metadata，也不把拒绝当成业务异常或完整栈。未启用规则的函数继续使用原系统路径。

RootHide 的系统 unwinder 在处理故意缺失 RA 的 arm64e 测试 CFI 时会进行指针认证；直接使用“未定义 LR = 0”的夹具曾触发 trap。因此自有夹具使用与真实帧分离、正确认证的结束标记，真实函数仍按原 LR 返回；规则优先级也避免已登记函数先进入不可靠 CFI。不能把 Mac arm64 测试结果直接外推到 iOS arm64e。

## 结果和兼容性

原始栈 V3 记录每帧使用的 `unwindRecipeSlot`、终止拒绝原因；Reader 输出 `recoveredSteps`、`unwindSource`，恢复后的 caller 标明 `pcSemantics:"verified-saved-return-address-minus-4"` 和 `savedReturnAddress`。仍读取 V1/V2。旧进程代的日志不套用当前代 slot 身份。符号化和 JSON 在读取侧完成，命中侧只保存有界原始数据。

`complete` 保留系统后端终止的原有语义，不能单独证明已到线程根、越过已知包装帧或恢复任意缺口。调用关联仍需逐个真实桥 PC/SP/cookie 证据；其它栈缺口继续单独记录，不能因此伪造父边、返回或 aborted。

## 验证入口

- `make test-unwind-recipes`：portable CFG/保存状态正负例，以及自有真实汇编夹具。夹具的 caller DWARF CFA 依赖原 x19，必须完整恢复 x19/x20/FP 才能到原 root；关闭规则后重新止步，原 CPU 寄存器与返回结果保持。
- `run_unwind_selftest`：需要当前 generation，在目标内运行同一组原生测试；结束恢复原规则启用状态。
- `tests/unwind_recipe_mcp_test.py --endpoint <explicit-device> --fixture <private-result.json>`：验证真实恢复、V3 来源、幂等/开关、坏参数无状态变化及 STP/LDP writeback 信息。

本机两台授权手机均已通过 6 组原生夹具和 4 项 MCP 测试，原有 flow、Timer、ABI/PAC、live Trace 回归通过。真实 App 命中范围和最终同源整包状态以 `PROGRESS.md` 的最终记录为准，不能仅凭规则登记成功称作业务缺口已验证。
