# 抓取位置怎么选

三个位置解决三类问题。选错的代价是「抓到垃圾还以为成功了」。

## 决策表

```
这个值在什么时候有效？
├─ 函数执行期间（输入参数、密钥、明文）
│    └─ capture_multi: "x0:64,x3:32,x5:128"
│
├─ 函数返回之后才写好（出参缓冲、摘要、密文）
│    ├─ 缓冲地址来自某个入参寄存器 → capture_after + capture_memory{ptr_arg:N}
│    └─ 缓冲地址是返回值（x0/x1） → capture_ret_multi: "x1:600"
│
└─ 不确定
     └─ 先 capture_multi 全部抓一遍，看哪个寄存器像指针
```

## capture_multi（入口，多窗口）

一次 hook 同时记录多个寄存器指向的内存。

```json
hook_inline {
  "addr": "0x1045a1234",
  "label": "core",
  "capture_multi": "x0:64,x3:32,x5:160"
}
```

输出进事件 detail：

```
win x3 @0x281066a28 = 32 bytes: 48454c4c4f006e67...
win x5 @0x2812c67f0 = 160 bytes: 0000000000000000...
```

要点：

- 寄存器 `x0..x8`，`:N` 是字节数，省略则用 `capture_max_bytes`
- 地址 < 4GB 的窗口会被跳过（不是 0 就是无效指针）
- 全部读失败会打印 `win [<spec>] unreadable`，**这本身就是信息**：说明这些寄存器此刻不是指针
- 一个 inline 目标只能装一个 hook，且槽位不回收——**一次抓全，别逐个试**

## capture_after（出参缓冲来自入参寄存器）

```json
hook_inline {
  "addr": "...",
  "capture_memory": {"ptr_arg": 2, "len_arg": 3, "max_bytes": 512},
  "capture_after": true
}
```

`capture_after` 让 handler 在**原函数返回后**才去读 `x{ptr_arg}` 指向的缓冲。
典型场景：`CCHmac(alg, key, keyLen, data, dataLen, out)` —— `out` 是第 6 个参数（`x7`）。

要点：

- 必须同时给 `capture_memory`，否则 `capture_after` 会直接报错（悬空语义）
- **`ptr_arg` 读的是「进入时」的寄存器**，不是返回后的。这点很关键：
  `x0` 在返回后已被返回值覆盖，用 `ptr_arg:0` 会读到返回值而不是出参指针
- 会自动启用 post 路径（多一层栈帧留到原函数返回）

## capture_ret_multi（出参缓冲是返回值）

```json
hook_inline {
  "addr": "...",
  "capture_ret_multi": "x1:600"
}
```

用于「返回 `(status, buffer)`」这种 ABI：`x0` 是状态码，`x1` 指向结果缓冲，
而那块内存在返回后**立刻被释放**——事后 `read_memory` 只能读到垃圾。

输出前缀是 `ret` 而不是 `win`：

```
ret x1 @0x281dde8b0 = 600 bytes: 91c34af6a1410000...
```

要点：

- 只作用于 post 路径（会强制打开 `capture_return`）
- 读的是**返回后**的寄存器快照，所以 `x0`/`x1` 都是返回值
- 同样受 `capture_max_bytes` 上限约束

## objc_call（主动调用，不装 hook）

把目标自己的入口当 oracle 用，做差分。

```json
objc_call {
  "class": "JDGB_unquilleted",
  "selector": "maHWP__unpliableness:errCode:",
  "class_method": true,
  "args": ["POST /api xxx=&functionId=yyy", {"$intptr": 0}]
}
```

- `args` 按顺序编组，字符串直接给，`null` → nil
- `{"$intptr": N}` → 分配一个 int32 初值 N，传它的**地址**，返回值在 `out_params.argN_int`
- `class_method: true` 表示调用 `+method`（类方法）
- 实例方法要传 `object`（地址），不是 `class`

**注意**：`{"$intptr":N}` 在 ARC 下曾经 100% 崩宿主（`id argv[]` 默认 `__strong`，
对栈地址 retain 会 SIGSEGV）。1.28.19 起已修。老版本不要用这个参数。

## 组合示例：一次调用拿全

```
hook_inline {
  "addr": "0x1045a1234",
  "label": "sign",
  "capture_multi": "x0:96,x3:64,x5:200",     // 入参、输入缓冲、配置对象
  "capture_ret_multi": "x1:600",              // 返回的缓冲
  "capture_return": true
}
```

一条事件里就能看到「进去什么、出来什么」，不用反复重启进程。
