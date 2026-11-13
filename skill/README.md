# IDH 逆向 Skill 索引

给接手 iOS 目标 App 协议/算法逆向的 Agent 用。这里记录的不是「工具怎么调」——那些
`analysis_guide` 会给——而是**判断顺序**和**踩过的坑**，目的是让你少走几小时的弯路。

## 先读哪个

| 你的处境 | 读这个 |
|---|---|
| 刚接手，不知道从哪下手 | `ios-reverse/SKILL.md`（主流程） |
| 要抓某个函数的参数/返回值，但不知道用哪个 hook | `ios-reverse/references/instrumentation.md` |
| 怀疑自己拿到的是假证据 | `ios-reverse/references/evidence.md` |
| 工具报错 / 装了没生效 | `ios-reverse/references/troubleshooting.md` |
| 要复现七鲜 jdgs 那种「加密头」 | `ios-reverse/cases/jdgs-7fresh.md`（进行中的真实案例） |

## 一句话原则

**先证明你在看的是真东西，再解释它。** 这个项目历史上最贵的错误全部来自「拿到了
看起来合理的数字，当成结论写下来」——包括我自己犯的（见 `evidence.md` 的误判清单）。

## 工具入口

- 设备侧：`POST http://<device>:8088/api/mcp`，JSON-RPC 2.0 `tools/call`
- 先 `analysis_guide(topic="start")`，再 `process_list` + `capabilities`
- 每次重启目标 App 后**必须重新取 slide**（`get_macho_info` 的 `load_address`），
  用旧 slide 算出来的地址会读到完全无关的代码——我因此误判过一次「二进制自解密改写代码段」

## 版本

对应 IDH 1.28.24+。`capture_multi` / `capture_ret_multi` / `objc_call` 的
`{"$intptr":N}` 都是这一轮加的能力，更老的包没有。
