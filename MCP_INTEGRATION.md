# Capstone + MCP 集成

在注入的 dylib 内提供一个 **MCP (Model Context Protocol) 服务器**，AI 客户端可通过 HTTP 调用 Capstone 反汇编与镜像分析能力。

## 1.28.34 结构化 Hook 协议

动态 Hook 和事件关联以 [结构化事件 v2](docs/STRUCTURED_EVENTS_V2.md) 为准。Hook/unhook/trace_function/objc_call/自检必须传当前 `process_generation`；函数阶段按 `phase`、调用按 `callId/parentCallId`、输入输出按 `payload` 解析。ObjC post 需要固定非变参声明，C post 需要显式 ABI。新 `get_call` 返回有界配对与同步子事件，`run_hook_selftest` 只测试 IDH 自有 fixture。下表的旧工具说明不能作为允许硬卸载 Inline 或安装后修改配置的依据。

## 传输与协议

- **传输**：MCP Streamable HTTP，端点 `POST /api/mcp`，复用现有 8088 HTTP 服务（不额外占端口）。
- **协议**：JSON-RPC 2.0，支持 `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`。
- **内容协商**：`Accept: text/event-stream` 时以单帧 SSE 返回，否则 `application/json`。
- **会话**：`initialize` 应答下发 `Mcp-Session-Id` 头，客户端后续请求回带。
- **协议版本**：支持 `2024-11-05` / `2025-03-26` / `2025-06-18`，`initialize` 回显客户端请求的版本（不支持则回 `2024-11-05`）。
- `GET /api/mcp` 不提供服务端主动推流，按规范返回 `405 Allow: POST`。

> ⚠️ 与本项目其它端点一致：MCP 服务**无认证**，仅供可信网络调试。

## 工具

| 工具 | 说明 | 必填参数 |
|------|------|---------|
| `disassemble` | 反汇编一段 hex 字节（容忍空格/`0x`前缀） | `bytes` |
| `analyze_function` | 安全读取进程内存 `address..+size` 并反汇编（`vm_read_overwrite` 防护，不可读地址返回 isError 而非崩溃） | `address`, `size` |
| `disassemble_function` | 反汇编包含 `address` 的函数；优先按 `LC_FUNCTION_STARTS` 自动归一入口和结束边界 | `address` |
| `resolve_symbol` | `dlsym` 解析导出符号；首选参数 `symbol`，兼容旧参数 `name` | `symbol` 或 `name` |
| `symbolicate` | 地址归属到镜像和包含函数，返回符号来源与置信度 | `address` |
| `list_imports` | 列举某镜像的导入（undefined）符号 —— fishhook 可 rebind 的候选 | `image_index` |
| `get_macho_info` | 列举 App bundle 内已加载镜像：load_address、cryptid、加密状态 | 无 |
| `list_loaded_images` | 完整 dyld 镜像地图：UUID、path、scope、slide、可执行范围和加密信息；不按 imports 过滤 | 可选 `query`/`include_system`/`offset`/`limit` |
| `find_xrefs` | 「谁调用了它」：扫某镜像 `__TEXT,__text` 里所有直接 `bl` 到目标符号/地址的调用点，经运行时已绑定的 GOT + dladdr 把 import stub 还原成真实符号 | `symbol` 或 `address` |
| `find_string_refs` | 「谁引用了这个字符串」：扫 `__text` 的 `ADRP+ADD`（直接）/ `ADRP+LDR`（间接指针槽）恢复的数据地址，落在字符串 section 则记引用点 | `string` 或 `address` |
| `find_selector_refs` | 「谁把这个 selector 用在了 objc 调用上」：扫 `__text` 的 objc_msgSend 调用点（经典 selref+`blr` 或现代 `__objc_stubs`），只报真实调用不报裸 selref 加载 | `selector` |
| `find_function_refs` | 内部调用图：本镜像 `__text` 内 `BL` 的 `from_func → to_func` 边，`direction` 取 callers/callees/both；import stub 与 objc_stub 天然排除 | `target` |
| `list_functions` | 函数清单（`LC_FUNCTION_STARTS`）：name（符号或 `sub_<addr>`）、start、vmaddr、size≈到下一入口；支持 `query` 子串过滤与 offset/limit 分页 | 无 |
| `objc_resolve_imp` | selector → 当前运行时 IMP；明确不宣称恢复第三方 swizzle 前实现 | `selector` + (`class` 或 `object`) |
| `find_objc_methods` | 查询 runtime 中类自身声明的方法：selector、type encoding、当前 IMP、class image 与 IMP image；支持过滤和分页 | 至少一个过滤条件 |
| `export_events` | 按稳定 seq 游标分页导出完整事件 JSON，包含密钥/IV/输入输出/结构化调用栈和进程元数据；blob 有界并标记截断 | 无 |
| `hook_import` | 对导入 C 符号装只读 hook（fishhook GOT 改写，不生成可执行内存）：记录 x0–x8 寄存器快照、调用栈；`describe_args:true` 尝试读 C 字符串参数；`capture_memory:{ptr_arg,len_arg,max_bytes}` 在命中瞬间把指针参数指向的内存拷贝到事件 `input`（hex/UTF-8），用于缓冲区随后被释放/复用的场景（如 CryptoSwift 的 key buffer）。仅对 `list_imports` 里出现的符号有效 | `symbol` |
| `hook_method` | 对 ObjC 方法装只读 hook（`method_setImplementation`，不使用 inline hook）：记录 self/SEL/参数寄存器与调用栈；`describe_args:true` 反引用对象参数；`capture_memory` 语义同上（x0=self, x1=_cmd, x2..=方法参数） | `class`, `selector` |
| `list_hooks` | 枚举本次会话已装的动态 hook：slot、kind、名称、命中次数、启用状态与 capture 配置 | 无 |
| `unhook` | 原子关闭动态 hook（thunk 继续透明转发，无 unbind 竞态） | `slot` |

可选参数：`disassemble`/`analyze_function` 的 `arch`（`arm64`/`arm`/`thumb`，默认 arm64）；`list_imports` 的 `query`（子串过滤）、`limit`；四个 xref 工具均支持 `image`（镜像名子串，默认主程序）、`max_results`（默认 256）、`scan_offset` 和 `scan_size`。

**大镜像分页与诊断**：`find_xrefs`、`find_string_refs`、`find_selector_refs`、`find_function_refs` 单次最多扫描 48MB `__text`。响应中的 `scan` 给出完整 `text_start/text_end`、本次 `scan_start/scan_end`、实际读取字节、不可读/部分可读页、`coverage_complete` 和 `incomplete_reasons`。若 `scan.has_more=true`，把 `scan.next_scan_offset` 原样传给下一次调用。字符串和 selector 扫描会额外读取前 4KB 作为状态预热，但不会返回本页起点之前的命中。

`find_xrefs` 仅 tier-1：只认直接 `bl`（不含 `blr`/`br` 间接调用、无 string/selector 引用、无 CFG）。三种 `kind`：`call_direct`（本镜像内部函数）/`call_import_stub`（经 `__stubs`/`__auth_stubs` 的导入 API）/`call_objc_stub`（经 `__objc_stubs` 的 `objc_msgSend$sel` 降级 stub）。lazy slot 尚未绑定时目标记为未知但仍保留调用点。`resolved_name` 反映**运行时真正到达的目标**——若该导入被 fishhook 改写，会如实显示 hook 符号。

**函数归属（tier-1.5）**：每条结果带 `from_func`（`main+0x50` 或 strip 后 `sub_<runtime>+0x50`）、`from_func_start`（函数起点运行时地址）、`from_func_offset`、`from_func_vmaddr`（起点 vmaddr，去 slide，跨 ASLR 稳定，宜作 ID）。归属优先用 `LC_FUNCTION_STARTS` 确定函数入口和近似结束位置，再接受恰好位于入口的 `dladdr` 符号；函数结束位置仍以下一入口近似，不是完整 CFG 边界恢复。

**地址与函数边界**：`symbolicate` 和 xref 的函数归属先用 `LC_FUNCTION_STARTS` 确定包含函数，只接受恰好落在该入口的 `dladdr` 符号。strip 镜像会返回 `symbol_source=lc_function_starts`、`has_symbol=false` 的 `sub_<runtime>`，而不会把数 MB 外的最近导出符号当作函数名。缺少函数元数据时才返回 `symbol_source=dladdr_nearest`、`confidence=low`。`disassemble_function` 接受函数中间地址，响应给出 `requested_address`、`resolved_start/end`、`requested_offset`、`boundary_source/confidence`；有 `LC_FUNCTION_STARTS` 时读到下一入口，不会在早退 `ret` 处误停。入口归属为高可信，结束位置仍是“下一入口”近似值，因此 `boundary_confidence=medium`。

**结构化反汇编与常量**：三个反汇编工具的每条指令除 `mnemonic/op_str` 外，还返回 `operands`（register/immediate/memory/floating_point）、显式 `registers_read/registers_written`、`groups`（jump/call/return）和直接分支 `target`。ARM64 的 `MOVZ/MOVN/MOVK` 会额外返回 `constant_build`，包含已拼接的 `value`、`known_mask`、位宽、链起点和指令数。该跟踪只在当前线性结果内工作，遇到控制流或寄存器覆盖即失效，不做 CFG/跨函数推演；`complete=false` 表示只知道部分 16 位片段，不应把未知位当成 0。

**事件 JSON 导出**：`export_events` 按 `seq` 升序返回完整事件。第一页记录 `cursor.snapshot_until_seq`，后续把它作为 `until_seq`，并把 `cursor.next_after_seq` 作为 `after_seq`，直到 `has_more=false`；固定上界可防止新事件插入造成翻页重复或漂移，但导出期间被内存保留策略淘汰的旧事件无法恢复。默认每页 25 条、每个 key/iv/input/output 最多编码 64KB，截断字段带 `<field>Truncated=true`；`include_dumps` 默认关闭，避免与 hex 重复膨胀。导出内容可能含密钥、明文、Token、路径和请求数据，必须按敏感材料存储和分享。

**`find_string_refs`（tier-2A）**：谁引用了某字符串。给 `string`（子串匹配）或 `address`（精确字符串地址），可选 `image`（默认主程序）、`max_results`。识别两种取址模式——`ADRP+ADD`（直接，`indirect:false`，目标在被扫镜像的 `__cstring`/`__objc_methname`/`__objc_classname`/`__objc_methtype`）与 `ADRP+LDR`→指针槽（间接，`indirect:true`，仅认 `__objc_selrefs`/`__got`/... 白名单槽；运行时 selref 已定到别处的 SEL，目标可能跨镜像，section 标 `(external)` 但字符串内容仍如实读出）。局部窗口回溯：按寄存器缓存最近 `ADRP` 页，寄存器被写即失效，不做跨基本块/跨函数数据流。每条结果带 `ref_site`、`string`、`string_addr`、`string_vmaddr`、`section`、`instruction`、`indirect`，以及与 find_xrefs 同款的 `from_func` 归属字段。

**`find_selector_refs`（tier-2B）**：谁把某 selector 用在了 objc 调用上——xref 站点是 `objc_msgSend` 的 **call_site**，不是裸 selref 加载。给 `selector`，可选 `match`（`exact`/`contains`/`prefix`，默认 exact）、`image`、`max_results`。两条路径：**A 经典** `adrp+ldr x1,[__objc_selrefs]` → `blr/bl objc_msgSend`（靠 x1 状态机 + 跟踪哪个寄存器持 msgSend 指针；`target_kind:objc_msgsend`，带 `selector_load_site`/`selector_slot`）；**B 现代** `bl <__objc_stubs 的 objc_msgSend$sel>`（`target_kind:objc_stub`，`selector_source:__objc_stubs`）。x1 被覆盖或只加载未调用不报，仅命中 `__objc_methname` 不报，不还原 receiver。每条结果带 `call_site`、`selector`、`target`、`target_kind`、`selector_source`、`instruction` 及 `from_func` 归属字段。因此 `find_string_refs("bytes")` 可有结果，但 `find_selector_refs("bytes")` 只在它真参与 objc 调用时才有。

**`find_function_refs`（tier-3A）**：本镜像内部的直接调用图。给 `target`（函数地址，通常取自别的工具输出的 `from_func_start`/`to_func_start`），`direction` 取 `callers`（谁调用它，默认）/`callees`（它调用谁）/`both`。只认 `BL imm` 落在本镜像 `__text` 内的目标——import stub（`__stubs`/`__auth_stubs`）与 `__objc_stubs` 在独立 section，天然排除。`BL` 目标可能落在函数中间（branch island/thunk/block invoke），故同时给 `target_addr` 与 `to_func_start`+`to_func_offset`，不假装是入口。每条边带 `relation`（caller/callee）、`call_site`、`from_func*`、`to_func*`、`instruction`。不做 `BLR`/`BR`/switch/CFG——建好 `from_func → to_func` 后再做 basic block / CFG 才自然。

**`list_functions`（tier-3B）**：把内部依赖的 `LC_FUNCTION_STARTS` 对外暴露成函数清单——其余 xref 工具的归属底座。可选 `image`（默认主程序）、`query`（名字子串）、`offset`/`limit`（分页，默认 limit 200）。每条含 `name`（dladdr 符号或 `sub_<runtime>`）、`start`（运行时入口）、`vmaddr`（去 slide，稳定 ID）、`size`（≈ 下一个入口 − 本入口，非精确边界）、`has_symbol`。strip 后仍列出（`LC_FUNCTION_STARTS` 不随 strip 丢失），名字退化为 `sub_<runtime>`。

**`objc_resolve_imp`**：把 selector 解析到**当前运行时 IMP**。静态反汇编到消息发送就是一条 `br x16`（objc_msgSend 间接跳转），注入进程可直接问 ObjC runtime 当前会执行哪个入口。给 `selector` + 二选一：`class` 或 `object`；对象地址仍使用安全 isa 读取。输出兼容字段 `imp` 以及语义更明确的 `current_imp`、`raw_imp`、`pointer_normalized`、声明类、image、symbol 和 type encoding。`imp_semantics=current_runtime_implementation`；若其他插件已先行 swizzle，这个地址就是插件入口，工具不会宣称恢复 swizzle 前实现，`original_imp_known` 固定诚实返回 false。

**`find_objc_methods`**：通过 Objective-C runtime 查询方法实体，至少传一个过滤条件：精确 `class`、模糊 `class_query`、`selector`、声明类 `image` 或当前实现 `imp_image`。`match` 控制 selector 的 exact/contains/prefix，`method_type` 控制 instance/class/both，`offset/limit` 分页。结果只列类自身当前声明的方法，不展开继承链；同时返回 `class_image` 与 `imp_image`。`imp_outside_class_image=true` 只表示当前实现落在另一镜像，可能来自 swizzle、category、共享实现或转发，不能单独当作 hook 定论。

工具执行错误走 MCP 的 `isError:true` content 信封（非 JSON-RPC 协议错误）；返回同时含 `structuredContent`（机器可读）与 `content[].text`（JSON 文本）。

## 逆向引导：标准加密 hook 全空时

如果 `sym` / `asym` / `digest` 分类没有事件，但网络层已经抓到密文，按这个顺序排查：

1. `get_capture_coverage` 确认 blind spot（静态链接 / 纯 Swift / 自研实现）；
2. `list_images` → `list_imports`，找静态加密库仍会调用的「指针 + 长度」导入：
   `mlock` / `memcpy` / `read` / `send` / `getrandom` / `memset`；
3. `hook_import` + `capture_memory` 在命中瞬间抓缓冲区；只存指针、事后 `read_memory` 通常已经太晚；
4. 候选 key 必须做「解密 + 回加密逐字节一致」闭环，并多次触发确认 key 生命周期；
5. 完整方法与实战案例见 `docs/analysis/逆向技巧-静态链接加密库.md`。

这条路径仍然只改 GOT/IMP 指针，不引入 inline hook / trampoline / 可执行内存。

## 调用示例

初始化握手：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"my-client","version":"1"}}}'
```

发现工具：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

反汇编字节：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"disassemble",
                 "arguments":{"bytes":"fd7bbfa9 fd030091 c0035fd6","arch":"arm64"}}}'
```
返回（节选）：
```json
{"jsonrpc":"2.0","id":3,"result":{
  "isError":false,
  "structuredContent":{"count":3,"instructions":[
    {"address":"0x0","mnemonic":"stp","op_str":"x29, x30, [sp, #-0x10]!","bytes":"fd7bbfa9","size":4},
    {"address":"0x4","mnemonic":"mov","op_str":"x29, sp","bytes":"fd030091","size":4},
    {"address":"0x8","mnemonic":"ret","op_str":"","bytes":"c0035fd6","size":4}]},
  "content":[{"type":"text","text":"{ ...上面的 JSON... }"}]}}
```

分析进程内某函数（先用 `get_macho_info` 拿 `load_address`，再喂给 `analyze_function`）：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"analyze_function",
                 "arguments":{"address":"0x1029ac000","size":64,"arch":"arm64"}}}'
```

## 实现

| 文件 | 职责 |
|------|------|
| `src/core/capstone/` | Capstone 5.0.1 源码（仅 ARM/AArch64） |
| `src/core/analysis.h/m` | Capstone 反汇编 + `vm_read_overwrite` 读内存 + macho 镜像枚举 |
| `src/server/mcp_server.h/m` | MCP 方法分发 + 工具执行 + content 信封 |
| `src/server/http_server.m` | `handle_mcp`：Streamable HTTP 传输（SSE 协商 / 通知 202 / 会话头 / 批量） |
| `Makefile` | `CAPSTONE_SRC` 源文件 + `CAPSTONE_DEF` 宏 |

### Capstone 编译宏（关键）

Capstone 以源码方式嵌入，**必须**定义以下宏（在 `Makefile` 的 `CAPSTONE_DEF`），否则运行时失败：

- `CAPSTONE_USE_SYS_DYN_MEM` —— 用系统 `malloc/free`，缺失则 `cs_open` 返回 `CS_ERR_MEMSETUP`
- `CAPSTONE_HAS_ARM` / `CAPSTONE_HAS_ARM64` —— 注册 ARM/AArch64 架构，缺失则 `cs_open` 返回 `CS_ERR_ARCH`

只编 ARM/AArch64 架构，产物 dylib 约 2MB。

## 边界

- **`get_macho_info` 作用域**：仅列 App bundle 内已加载镜像（不含系统库；`PlugIns/*.appex` 等独立进程也不在内）。在非 `.app` 宿主（如 mac 灰度测试的裸可执行）下会返回空列表——这是 `dh_dump_list_images` 的既有行为，非缺陷。
- **镜像工具不要混用**：`list_images` 是 `list_imports` 的索引来源，只列 imports 非空的 fishhook 候选；`list_loaded_images` 才是完整进程镜像地图；`get_macho_info` 仍只服务 App bundle 脱壳范围。
- **`analyze_function` 读的是本进程内存**：地址须是目标进程内已映射的地址；不可读时安全返回 `isError`。
- 无 `resources/prompts` 能力，`initialize` 只声明 `tools`。

## 快速验证（macOS 灰度）

```bash
make mac        # 编译 mac dylib
# 用任意宿主进程注入并保持存活, 然后 curl POST /api/mcp
```
`disassemble` / `list_imports` / `ping` / `initialize` 在 mac 下即可完整验证；`get_macho_info` / `analyze_function` 需真机 iOS App 环境才有实际镜像数据。
