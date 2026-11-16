---
name: ios-reverse
description: 用 IDH（IOSDecryptHub 越狱版）对 iOS 目标 App 做协议/算法逆向。当任务涉及抓某个函数的参数/返回值、定位签名或加密参数的生成点、判断某段代码到底有没有被执行、或者要复刻一个加密请求头时使用。包含判断顺序、证据卫生规则和踩坑清单。
---

# iOS 协议/算法逆向（IDH）

## 2026-11-16 真机补充

- 遇到方法 IMP 明明可读、但函数边界/xref 报找不到时，先核对完整镜像的 `executable_ranges` 与实际 section；代码和字符串不保证位于标准 `__TEXT`。1.28.31 已按权限/节名支持自定义段。
- `list_hooks.declared_args` 与 `argument_mapping` 是方法参数解释边界。原始寄存器中可读的对象可能只是调用者残留；x8 也不是第七个 ObjC 参数。只以真实声明和 ABI 能力确认的 arg 字段作输入证据。
- 浮点/聚合签名不按参数序号猜 x 寄存器；超过寄存器窗口的栈参数没有被观察到时，应明确写缺口。
- 已知单 GPR 方法的栈快照按 Darwin 自然大小/对齐解释，bool 可占相邻单字节；`caller_lr` 是命中时直接调用者，可补回溯栈的缺口。1.28.34 支持最多 32 个固定 GPR 参数的有界栈转发。ObjC post 必须声明 `post_abi:"fixed-nonvariadic"`；C post 必须给出 `abi.arguments/return`。复杂 ABI、变参和异常展开不支持 post，不能虚报原型。
- 同名/近似名的 SDK 方法必须逐轮用 hits 与实际返回→请求字节匹配确认，静态存在的旧入口可能是未使用分支。不要为了命中而调用签名 facade，把 oracle 输出当成内部算法已经还原。
- `symbolicate` 的函数起点置信度与 `disassemble_function` 的函数尾部置信度分开解释；LC_FUNCTION_STARTS 的下一入口是末尾近似，工具当前标 medium。
- 长函数按 `next_byte_offset` 续页，检查 `decode_start` 是否前进；仅改 address 会被函数归一重新拉回入口。收齐所有页才能声称覆盖完整函数，页间不要承诺 MOVK 常量传播。
- `capture_after` 的入口 input 应为空，输出在 `phase:"leave"` 记录中。1.28.34 按 `phase/callId/payload` 读取参数、内存窗口与返回值，不再正则解析 detail；旧 schema 1 才需要旧文本兼容。输入用独立入口窗口捕获，保留实际长度，固定窗口尾部的额外字节不是消息。
- 纯算法闭环要用独立来源的环境/时钟/计数做输入，再与 facade 和 HTTP 参数比较；从最终签名反解字段再编码只能验证封装，不能证明完整签名已复现。白盒表驱动复现也不等于已恢复原 AES 密钥。

## 1.28.34 结构化调用工作流

先握手取得 `processGeneration`，将其作为 `process_generation` 传给 Hook、unhook、trace_function、objc_call 和显式自检。重启后重新握手和解析地址；过期代的操作在修改前拒绝。

每次调用用 `callId` 配对 entry/leave，用 `parentCallId` 取同步父子关系；`get_call` 返回保留的子事件及缺失/截断状态。不要再按同线程时间相邻配对，递归和并发会误配。关系只覆盖正在执行的已启用 post 的 Hook，不宣称跨线程/异步完整调用图。

返回、参数、窗口都从 `payload` 读取，检查 status、实际长度、截断和 ABI 来源。`capture_after` 用入口指针在 leave 抓输出；返回寄存器窗口用 `capture_ret_multi`，仅 x0/x1，void 没有合法返回对象。旧 journal schema 1 无上下文时不补造身份。

配置在发布前整体校验且随后不可变。方法硬卸载必须仍持有 IMP；Inline/Import 用软停并在结束后重启目标清除 patch。不要按旧说明对运行中的 Inline 强行恢复入口字节。详细接口和验证命令见 [结构化事件 v2](../../docs/STRUCTURED_EVENTS_V2.md)。

## 0. 这个 Skill 要解决的问题

iOS App 的签名/加密参数（`X-Sign`、`jdgs`、`mtgsig` 这类）几乎都是：
某个 ObjC 类方法或 C 函数，吃进去若干字符串/字典，吐出一个十六进制或 base64 串。
难点不在「找到那个函数」（`list_images` + `find_objc_methods` + 交叉引用通常够），
而在于三件事：

1. **证明它真的被执行了**——静态存在的代码不等于运行时走到的代码
2. **拿到真实的输入输出**——不是猜的、不是从别的调用推断的
3. **别把假证据当结论**——缓冲区释放后回读是垃圾，读错寄存器是垃圾

下面按这个顺序讲。

## 1. 先建立目标模型（不要急着 hook）

```
get_stats                      # 选对进程（App 常有多个 :xxx 子进程）
get_capabilities                  # 取得 processGeneration、实际后端和 ABI 边界
get_macho_info                    # 拿 load_address = slide 基准，记下来
list_images                       # 主二进制叫什么、多大、cryptid 是否加密
```

**slide 每次进程重启都会变。** 所有「静态地址 + slide」的换算必须在同一进程代内完成。
用旧 slide 算出的地址不会报错，它会安安静静读到别的代码——这是本 Skill 里最贵的坑之一。

## 2. 定位候选函数

按可靠性从高到低：

1. **`find_objc_methods` / `objc_dump_ivars`** — 类名/方法名本身带语义（`sign`、`encrypt`、`token`）
2. **`list_imports` + `resolve_symbol` / `symbolicate`** — 目标用了 `CCCrypt`/`CC_SHA256` 就走系统加密库，好办
3. **字符串交叉引用** — `search_memory` / `find_string_refs` 找错误文案/URL/参数名，再找引用它的函数
4. **`search_memory` 搜明文**（iOS 上没有 dex，用 `search_memory` 搜明文）

找不到就说明它被混淆了：名字被抹掉、字符串加密、或者干脆是自研 VM。
这时不要硬啃反汇编，**直接进第 3 步做运行时观测**。

## 3. 证明「这段代码被执行了」

这是本 Skill 最重要的一节。

### 3.1 装 hook 后必须先看 hits

```
hook_inline { addr, label, process_generation }        # 或 hook_method / hook_import
# 触发一次目标操作
list_hooks                          # 看 hits 是不是 > 0
```

`hits == 0` 有四种可能，**必须逐条排除，不能假设**：

| 可能 | 怎么排除 |
|---|---|
| 地址算错了（slide 过期） | 重新 `get_macho_info` 核对 |
| 函数没被调用 | 换一个确定会走的分支触发 |
| hook 装失败但返回了成功 | `list_hooks` 看 `enabled` 与 `hits` |
| 装了但被别的 hook 抢了 | 同一符号重复装时 GOT 只指向最后一个槽位 |

### 3.1.1 别写轮询循环，用 wait_events

```json
wait_events { "category": "other", "operation": "<你给 hook 的 label>", "timeout_ms": 8000 }
```

服务端阻塞等待，命中就立刻返回，超时返回 `timeout:true` + 空列表（**这是正常结果，
不是错误**）。

**一定要带 `category`。** 不传等于扫全部 9 个桶再全排序，是整个 store 最贵的路径；
25Hz 轮询会和 hook 写事件抢同一把锁。`hook_inline` 的事件在 `other`。

两个游标别混用：

| 字段 | 含义 | 什么时候用 |
|---|---|---|
| `next_seq` | 已**返回**的最大 seq | 继续等同一过滤器（安全） |
| `scanned_seq` | 已**判断过**的最大 seq，含被过滤掉的 | 只跳过时间段、不在乎漏事件时 |

**换了 `operation`/`query` 就必须用 `next_seq`**。用 `scanned_seq` 会漏掉两个窗口
之间产生的、只有新过滤器才匹配的事件。

`timeout_ms` 上限是 12000，故意压在 `idh-cli` 的 15s 客户端超时之下——服务端等得比
客户端久的话，工具明明在工作却表现为失败，而且请求没被取消、连接还被占着。

采集被暂停（`set_pause`）时新事件不可能产生，它会立刻返回 `error` 而不是烧满超时。

### 3.1.2 卡住时先 agent_ping

```
agent_ping → { alive: true, elapsed_ms: 8, pid: 16500, app: "七鲜" }
```

HTTP 客户端看到的 `RemoteDisconnected` 或超时，分不清「目标崩了」还是「命令很慢」。
`agent_ping` 只回答「你还活着吗」，毫秒级返回。**先 ping 再排查**，能省掉一整轮
错误归因。

`elapsed_ms` 是**进程内耗时**，不含网络往返——别拿它和客户端 15s 超时对比。这个
工具本身也没有服务端超时（`get_stats` 是同步调用，无法安全放弃），真正的兜底是
客户端超时。

### 3.2 同轮对照

**任何「这段代码不执行」的结论，必须有一个同轮的正对照。**
例如：你说 `0x1004c2648` 的 SHA256 不在签名路径上，就要同时证明
「同一时刻另一个地址确实被命中了」。否则「0 hits」可能只是你的 hook 坏了。

### 3.3 别用「静态存在」代替「运行时执行」

反汇编里看到 `cmp #0x26` 就以为是 `opcode == 38` 的判断——实际上它可能是
不透明谓词或完整性校验。**只有运行时断点告诉你哪个分支真的走了。**

## 4. 抓真实数据

### 4.1 三种抓取位置，选错就等于没抓

| 场景 | 用什么 | 为什么 |
|---|---|---|
| 参数在寄存器里、指向的缓冲在**调用期间**有效 | `capture_memory` / `capture_multi` | 入口抓，内容还没被改 |
| 输出缓冲在**返回后**才写好 | `capture_after` + `capture_memory` | 入口抓到的是未初始化内存 |
| 结果是 `(status, buffer)` 且 buffer 返回后**立刻释放** | `capture_ret_multi` | 事后 `read_memory` 只能读到垃圾 |

**同一个函数往往需要多个窗口。** 一个 inline 目标只能装一个 hook，且槽位不回收，
所以 `capture_multi: "x0:64,x3:32,x5:128"` 一次抓全，别一个个试——每次换寄存器都要
重启目标进程。

### 4.2 读不到就是读不到

`capture` 失败会显式打印 `unreadable` / `null-pointer`。
**看到 unreadable 不要换个地址再试，先想清楚这个寄存器此刻到底指向什么。**
我浪费过一轮：`capture_after` 配 `ptr_arg:0`，而 `x0` 是返回值，
读到 `0x0` 一直失败——正确做法是用 `capture_ret_multi` 或换 `ptr_arg`。

### 4.3 ObjC 方法的寄存器约定


`x0 = self`，`x1 = _cmd`，`x2..x8` = 方法参数。
所以「第一个参数」是 `x2` 不是 `x0`。写 `ptr_arg:0` 抓的是对象头。

## 5. 证据卫生（决定结论可信度）

### 5.1 缓冲区有生命周期

命中瞬间拷贝，不要事后回读。实测 CryptoSwift 的 key 缓冲经 `mlock` 锁定又立刻
`munlock`，事后读只剩零。堆缓冲在 `free` 后会被复用，你读到的是别人的数据。

### 5.2 多调一次，看稳定性

- 同样输入调 5 次，输出**完全一致** → 纯函数
- 每次都不同 → 内部有计数器/时间/随机
- A/B 交替 → 有一个翻转的 1 bit 状态（thread-local 或调用计数）

这一步花 10 秒，能省掉后面几小时的错误建模。

### 5.3 长度是硬约束，先算再猜

加密算法对输出长度有强约束，用长度就能砍掉大半候选：

| 算法 | 输出长度 |
|---|---|
| MD5 | 16 |
| SHA1 | 20 |
| SHA256 | 32 |
| 带 padding 的分组密码（AES-CBC/ECB） | **16 的倍数** |
| XXTEA | **4 的倍数** |
| 流密码 / XOR / 自研 | 与明文等长，无对齐约束 |

**看到长度不是 16 的倍数，就别再试 AES 了**；不是 4 的倍数，别试 XXTEA。
这一条能省掉大量无用功。

### 5.4 排除法的判据本身要成立

我用过一条错判据：「AES 解密后没有可打印明文 → 不是 AES」。
但 **protobuf / 二进制结构的明文本来就不是可打印字符**，这条判据从一开始就不成立。
排除一个算法时，问自己：这个判据在「假设它确实是那个算法」时还会成立吗？

## 6. 常见结构：加密头字段

很多 App 的签名头是这种形状：

```json
{"b1":"<id>","b2":"<版本>","b3":"<版本>","b4":"<大块 base64>",
 "b5":"<64 hex>","b6":"<64 hex>","b7":"<毫秒时间戳>"}
```

经验规律（在七鲜上验证过）：

- `b1`/`b2`/`b3`/`b7` 往往是**明文字段**，直接从响应里读
- `b5`/`b6` 通常是某种哈希（32 字节 → 64 hex）
- `b4` 是「把前几个字段再序列化 + 加密」的那一块，**最难**，也最值得先搞清楚它的明文结构

**先找序列化器，再找加密。** 具体做法见 `cases/jdgs-7fresh.md`。

## 7. 工具改造

工具不够用就改。这个仓库的 `src/core/dh_thunk.m` 是 hook 核心，
`src/server/mcp_server.m` 是 MCP 工具层。加参数的最小步骤：

1. `dh_slot_t` 加字段（`src/core/dh_thunk.m` 的结构体）
2. 加 setter，做**纯校验函数**（校验必须在分配槽位之前，见 troubleshooting）
3. 在 handler 里用上，注意入口路径用 `gpr`、返回路径用 `regs`
4. MCP 层三个 Hook 工具都经 `install_configured` 整体校验；重复 import 不复写原配置
5. `dh_thunk_list` 回填 + `list_hooks` 输出，否则用户没法自查
6. 加进 schema

**改完必须回读目标行。** 批量编辑工具（尤其 PowerShell）会把多行压成一行、
吃掉函数签名，而编译器不一定第一时间报错。

## 8. 交付标准

一个逆向结论要能被别人复现，至少要有：

- 目标进程与版本（`get_stats` 的 pid + `get_macho_info` 的 image）
- 候选函数地址（静态偏移，注明是相对哪个 image）
- 「确实执行了」的证据（hits + 同轮对照）
- 输入输出的原始字节（不是描述）
- 稳定性（多调几次的结果）
- **明确写出哪些是验证过的、哪些是推断**

最后一条最重要。把推断写成结论，比慢一点交付的伤害大得多。
