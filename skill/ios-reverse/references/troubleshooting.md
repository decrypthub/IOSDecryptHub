# 排错手册

按现象查。每条都是实际撞过的。

## hook 装了但 hits = 0

**先查 slide。** `get_macho_info` 拿 `load_address`，重启后必须重取。

**再查是否重复装。** 同一符号装两次时，fishhook 只会把 GOT 指向最新槽位，
旧槽位从此永远 0 命中，而 `list_hooks` 里看起来是「已安装」。

```
list_hooks                    # 看有没有同名的两个槽位
```

1.28.15 起 core 会返回 `-(slot+10)` 精确带出已有槽位，MCP 层返回 `reused:true`。
但**复用分支不会重新装**，只是改配置。

**再查 `native_hook status` 的 verdict。** 有 `fired` / `installed-never-fired`
两种，后者说明装上了但目标没走到。

## `already inline-hooked at slot N`

同一地址只能有一个 inline hook，槽位不回收。换配置必须：

```
unhook {slot: N, hard: true}    # 恢复原始字节，槽位退休
hook_inline {addr: ..., ...}    # 重新装
```

**软 unhook（`hard:false`）不够**——蹦床会保留以避免在途线程 UAF，
同地址重装仍然被拒。所以「换个寄存器观察」的代价就是重启目标进程，
这就是 `capture_multi` 存在的原因。

## 引擎失联 / RemoteDisconnected

目标 App 崩了或 dylib 崩了。重新 `process_list` 看会话还在不在；
不在就重启 App：

```bash
killall <AppName>
uiopen -b <bundleId>
```

崩的原因常见于：

- 在函数序言内部下 inline hook（破坏跳转）
- 读已释放的对象（`objc_dump_ivars` 对着野指针）
- 把非对象指针当 `id` 传（见下）

## `{"$intptr":N}` 崩宿主

1.28.18 及以前：`objc_call` 里 `id argv[8]` 默认 `__strong`，
把栈上 `int` 的地址当 `id` 赋值会触发 `objc_storeStrong` → retain 读 isa → SIGSEGV，
**崩在赋值语句本身**，走不到方法调用。

1.28.19 起改成 `__unsafe_unretained`，真机验证通过。
如果还在崩，先确认版本：

```
get_stats        # 或 dpkg -s com.iosdecrypthub
```

## capture_after 一直 unreadable

三个原因：

1. `ptr_arg` 指向的是返回值位置（`x0` 在返回后已被覆盖）→ 用 `capture_ret_multi`
2. 缓冲地址来自栈上的第 9+ 个参数（`x8` 之后）→ 现在的实现只支持 `x0..x8`
3. 那块内存在返回前就释放了 → 只能在入口抓

`unreadable` 后面跟着的实际地址是最有价值的线索：
`@0x27` 这种小数值说明那个寄存器是**长度**不是指针。

## 装了 capture_multi 但 list_hooks 看不到

1.28.21 修过一次：`hook_import` 首次安装路径只声明了变量没调 setter，
回包照样显示已配置（假成功）。1.28.23 又修过一次：`dh_thunk_list` 回填时
没看 `ready` 标志。

如果现在还有这个现象，检查版本，然后：

```
list_hooks        # capture_multi 字段应该原样回显你设的规格
```

## capture_multi 报「语法非法」但看起来没问题

规格总长上限 95 字节（`char[96]`）。12 个窗口很容易超。

```
"x0:64,x1:64,x2:64,x3:64,x4:64,x5:64,x6:64,x7:64,x8:64"   # 71 字节，可以
再翻倍                                                      # 超了
```

超长会单独报「过长 N 字节, 上限 95」，不会和语法错误混在一起。

## 编译期 / 编辑期的坑

### PowerShell 双引号里的 `` `r`n `` 不展开

批量改代码时，双引号字符串里的 `` `r`n `` 在某些拼接上下文**不会**变成换行，
而是原样写入，把整段多行代码压成一行字面量。

**症状**：代码能编译但逻辑变成一句无效注释；或者报「unexpected '@' in program」。

**规则**：改完必须回读目标行（`ReadAllLines` 打印那几行），不要只看写入成功。

### `'\\0'` 是多字符常量

```c
s->buf[0] = '\\0';    // 错：两个反斜杠，值 0x5C30 截断成 '0'
s->buf[0] = '\0';     // 对
s->buf[0] = 0;        // 也可以
```

`-Wmultichar` 会警告，但**不一定当错误**。实测后果：把 `"x0:64"` 清成 `"00:64"`，
后者仍是合法规格，于是静默抓错寄存器。

### ARC 下把非对象指针伪装成 `id`

```c
id argv[8];                          // __strong，赋值会 retain
argv[i] = (__bridge id)&intSlot[i];  // 崩
__unsafe_unretained id argv[8];      // 对
```

### 校验必须在分配之前

如果「先分配槽位、再校验参数、失败就撤销」，就必须把目标上已改好的
跳转/IMP/GOT 全部回滚——漏一步就是内存安全事件：

- import：GOT 仍指向 thunk，而 `g_dh_thunk_orig[slot]` 被置 NULL → `br NULL` → SIGSEGV
- inline：补丁永久不可卸载
- method：会把当前 IMP(=thunk) 记成 orig → 无限递归

**正确做法**：抽一个纯校验函数（`dh_thunk_validate_capture_multi`），
在 `dh_thunk_install_*` **之前**调用。不需要撤销，就没有漏撤销。
