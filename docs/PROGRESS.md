# IOSDecryptHubJB 当前进度

## 2026-10-25：独立工程与手机整包方案

用户决策：巨魔版定型，越狱版独立项目；一个 deb 包含常驻 daemon、手机 UI 和注入引擎，通过 APT 源统一更新；手机可按应用开关注入，UI 参考现有 Android Manager。

已完成：

- 从旧越狱 4858677 导入独立 IOSDecryptHubJB 项目，main 为唯一产品主线，保留引擎源码与提交历史。
- 核对 Android Manager / daemon / scope 代码，落定手机原生 UI 和真实生效状态语义。
- 将 PC 从必需分析中心改为可选客户端，手机 daemon 负责服务与数据。
- 产品、UI、Hook / Trace 设计与开发规则同步更新。
- 上一轮已实测 Mac SSH 和旧引擎 arm64 / arm64e 编译；当前没有新版完整包或设备验收。

尚未实现：

- J0：新版 daemon、Manager、Loader 接入、整包一键构建。
- J1：手机应用目录、scope IPC、开关/生效状态、目标启停。
- J2：本产品正式 APT 源、统一版本、升级与移除交易。
- J3–J5：Inline、出口采集、函数与指令 Trace。

接下来从 J0 开始：先做可安装完整最小包，再按 J1 验证应用 A 开启、B 不受影响、关闭/重启真实生效；不先以独立 dylib 交付新增能力。

## 2026-10-25：统一迁入组织公开维护，补齐旧公开源码发现

- 用户明确不要私有仓。当前仓从个人账号迁入 `decrypthub/IOSDecryptHubJB` 并设为 PUBLIC；巨魔版为 `decrypthub/IOSDecryptHubTrollStore`，官网为 `decrypthub/IOSDecryptHubPage`。
- 组织原有公开 `decrypthub/IOSDecryptHub` 已包含管理器、Loader、一次性 updater、整包脚本和发布链路，并有 v1.27.5 发布。它与本仓历史不同，不强推覆盖；本机加只读参考 `legacy-public/main`，核对提交 a94a396。
- 更正早期判断：“本机未发现并列 JB 仓”不能推断“旧越狱组件不存在”。后续从真实 v1 迁移常驻与整包更新，不从零重复造管理器/打包能力。
- 旧源声明为 `https://ios.decrypthub.com`，旧包 ID 为 `com.iosdecrypthub`；尚需核对线上签名/索引/已有安装和接管方式，本轮不改源、不发包、不操作手机。
- 本轮只迁移公开仓、更新链接与状态记录，不新增运行时功能。

## 2026-10-26：对齐组织正式源码，修正拆分基线

- 用户要求复核线上版本。确认正式 main 为 a94a396、正式 Release v1.27.5；官网三件下载与 Release digest / Git blob 完全一致，原源和包未被覆盖。
- 承认并修正此前基线选择错误：新 JB 从个人引擎仓开始，缺少正式管理器/Loader/updater/打包，且缺 RootHide 变体修复。
- 纳入正式仓历史并原样恢复 v1 组件与自包含 make deb，保留新设计和原测试资料；源码/打包关键路径与正式 Git blob 一致。
- Mac 实测 make deb 同时生成 rootless 和 RootHide 整包，包内检查通过；未装设备、未发布 Release、未更新线上源。
- 巨魔仓继承的 latest Release 是 v1.25.5，下载入口已改回正式 v1.27.5，避免旧产物被当作最新版本。
- 正式发布 workflow 仅保留为参考快照，不触发新发布。后续 J0/J1 是在完整 v1 上改造常驻服务和新版交互，不再从零拼装已存在的组件。
- 完整核验、SHA-256 与限制见 BASELINE_AUDIT_2026-10-26.md。上方早期“仅有引擎、无整包”的状态已被本节替代。

## 2026-10-26：v1.27.6 独立维护更新

- 发布独立完整包，沿用既有包 ID、APT 地址和签名信任，保留 v1.27.5 可用版本。
- 按 deb 架构查询规范 APT 源，rootless 与 RootHide 候选版本隔离；Manager 更新/回退入口交给包管理器。
- 删除 daemon 单引擎下载/替换/交换备份逻辑，拒绝旧 install / rollback 请求；启动脚本忽略遗留 staging，并修复转交请求时误删同路径请求的问题。
- Mac 上验证版本数字排序、架构隔离、格式错误、真实 daemon 拒绝旧请求与引擎不变；双环境完整构建和包内容/签名检查通过。
- 本轮不包含常驻分析 daemon、新 Manager、scope IPC、Inline Hook 或 Trace，尚未进行手机安装、升级、重启或跳转验收。

## 2026-11-13：J3 第一切片 — Inline Hook + QBDI 指令级 Trace（JB 版）

实现（只在越狱版；巨魔版不动）：

- `src/core/dh_thunk.m`：新增 `DH_HOOK_INLINE` 与 `dh_thunk_install_inline`。复用既有 thunk-bank（保存 x0-x8/q0-q7/lr，记录后尾调用原函数蹦床），后端为静态链接的 **Dobby**；支持 `module+symbol` 或绝对地址，地址先经 `vm_region_64` 校验可执行。
- `src/trace/qbdi_trace.m`：静态链接 **QBDI 0.12.2-devel（LLVM 19.1.5）**（iOS/AArch64，iOS 15.0+），一次性 VM + `qbdi_call`，指令/时间双预算；预算在回调里 `QBDI_STOP`，不把截断伪报成 completed。
- MCP 新工具：`hook_inline`（install/软停由 `unhook` 承担）、`trace_function`；`list_hooks` 增 `kind=inline`；`trace_function` 进重活串行队列。
- 安全护栏：拒绝 inline-hook `malloc/calloc/realloc/free/objc_msgSend/objc_retain/...` —— 命中处理器本身会分配 Foundation 对象，hook 分配器会在原序言未完成时重入并打死宿主（实测 engine_shell 直接退出）。
- vendor：`vendor/dobby`（commit 5dfc854，arm64 静态）与 `vendor/qbdi`（0.12.2-devel，arm64 静态 + 头文件），构建脚本 `tools/build_dobby_ios.sh` / `tools/build_qbdi_ios.sh`。`Makefile` 只在 ARCHS 不含 arm64e 时链接这两个库；roothide 胖包可编译，但 `hook_inline/trace_function` 明确返回 unavailable。

真机验证（iPhone X / iPhone10,3 / iOS 15.6 / Dopamine rootless，rootless 1.28.0）：

- `trace_function` 对 `libsystem_kernel.dylib!getpid`：`ok=true`、`retval=0x1e1b`（= 进程 pid）、6 条指令、`stop_reason=completed`；`max_insns=32` 时按 instruction-limit 截断并标记 truncated。
- `hook_inline` 对 `write`：安装成功（`backend=dobby`），一次 `get_stats` 后 **hits=14**，宿主仍能正常响应；`unhook` 后 `enabled=false`、hits 保留、转发透明。
- `hook_inline` 对 `malloc`：明确拒绝并返回原因（`isError=true`），宿主存活。
- 引擎本体经一个 platform CLI 宿主 `dlopen` 验证（8088 正常起、MCP 工具可用）；QBDI/Dobby 各自也有独立 CLI probe 通过。

未完成/限制：

- **设备侧 Loader 注入状态**：本轮多次安装/重装 deb 并手动 respring 后，`IOSDecryptHubLoader` 不再注入第三方 App（旧引擎同样不注入，App 进程存活但 8088 不起），因此上述功能验证走的是「platform CLI dlopen 引擎」而非「Loader 注入 App」。需要设备重新激活越狱/正常 respring 后，用 App 再补一次端到端验收。
- vendor 只有 arm64 切片；arm64e（roothide）需另建 Dobby/QBDI，当前明确 unavailable。
- `trace_function` 是 **replay**：会在调用线程真实执行目标函数一次；只播种 x0-x7，栈/浮点参数不重建；有副作用。
- inline hook 仅入口观测 + 软停，未做安全硬卸载；不做返回值/参数改写。
- 尚未发布到 APT；1.28.0 仅本机构建并装到 iPhone X。

## 2026-11-13：联想 App 真机 hook 实测 + QBDI 冷启动修正

设备/目标：iPhone X（iPhone10,3 / iOS 15.6 / Dopamine rootless）；联想 App 7.4.0（`com.lenovo.LenovoClub`，pid 8129）经 Loader 正常注入，MCP 8088 返回 bundleId=`com.lenovo.LenovoClub`、appName=`联想`。

- inline hook `libsystem_kernel.dylib!write`：安装成功（backend=dobby），App 正常响应；一次 `get_stats` 后 hits=32（更早一轮 716 次），App 持续存活。
- ObjC 方法 hook（swizzle）：`-[JPUSHService applicationDidBecomeActive]`、`-[JPUSHService applicationWillEnterForeground]` 各命中 1 次，App 存活；`-[LCAppDelegate checkUpdate]` 可安装但空闲窗口未命中。
- inline hook 联想自带 framework 代码（`SensorsAnalyticsSDK`、`SocketRocket`、`Reachability` 的方法）：安装成功、App 存活；空闲窗口内未命中，说明 patch 本身对 framework 是安全的。
- **inline hook 联想主二进制代码会触发 App 自身保护**：对 `LCAppDelegate.checkUpdate`、`LCAppDelegate.myAds`、`LenovoIDInlandSDK.leInlandLogout:`（当前进程实时解析的 IMP）装 inline hook 后 10–20 秒内 App 以 SIGILL 退出，即使目标方法从未被调用；崩溃线程停在 mach_msg_trap。对照：SevenFresh 主二进制同方式 inline hook 安装后 20 秒仍稳定，说明不是引擎/Dobby 的通用问题，而是联想主二进制的完整性/反篡改。
- QBDI trace 在真实 App 进程内可用，但**首次调用有 JIT 冷启动**：`max_ms=800` 时 `getpid` 只记录 1 条就 time-limit；同一进程随后 `max_ms=5000` 时 6 条 completed、retval=pid（8129）、65ms；`getuid` 4 条 completed、25ms。默认 `max_ms` 已由 1000 提高到 3000，并在 `time_limit && count<=3` 时返回「QBDI cold start，建议重试」的 warning。

结论：真实 App 内的 inline hook（系统函数、App 自带 framework）和 ObjC 方法 hook 已可用；联想主二进制 inline 被其自身完整性保护拦下，是否做反检测绕过属于产品决策，当前不静默假装成功。

## 2026-11-13：学习通 inline hook 对照

目标：学习通（`com.ssreader.ChaoXingStudy`，pid 9364，iPhone X / iOS 15.6 / rootless 1.28.1）。

- inline hook `libsystem_kernel.dylib!write`：安装成功，命中数逐步到 2432；`trace_function getpid` 默认预算 6 条 completed、`retval=0x2494`（=pid 9364）、7ms。
- **学习通主二进制 inline 可用**：对 `-[AppDelegate extDotInfoInAdInfo:]`（从未调用的方法）安装后 20 秒 App 仍存活、hits=0；再对 `-[AppDelegate nbs_applicationDidBecomeActive:]`、`-[AppDelegate nbs_applicationWillEnterForeground:]` 安装 inline hook，经 Settings/学习通前后台切换各命中 1 次，App 存活 2 分 30 秒。
- 对照结论：同一种 Dobby inline 在主二进制上，学习通稳定、联想 SIGILL；联想是自身完整性/反篡改，不是引擎或 Dobby 的通用缺陷。
- 测试后已 unhook 全部 slot（enabled=false，patch 保留），学习通进程未重启。

## 2026-11-13：Inline / Method 硬卸载与同目标重装（1.28.2）

- 槽位从 128 扩到 **256**；同一目标已有 active inline hook 时再次安装直接报错（不再叠一层 hook）。
- `unhook` 默认仍是软停；`hard:true` 才是硬卸载：
  - **inline**：安装前保存目标入口 32B 原始字节；DobbyHook 成功后再保存 patched 字节。硬停用 `DobbyCodePatch` 写回原始字节，**不调用 `DobbyDestroy`**——后者会释放 Dobby 原函数蹦床，而在途线程可能已经进入 thunk 并即将 `br` 到该蹦床，保留蹦床避免 use-after-free。槽位标记 retired。
  - **method**：把 IMP 恢复成安装前保存的原 IMP，槽位 retired。
  - **import (fishhook)**：不支持硬停，返回 -5，保持软停（没有安全的 GOT 反向恢复路径）。
- **同一目标重装不消耗新槽**：
  - inline 先读当前入口字节，必须与保存的原始字节一致，才用 `DobbyCodePatch` 重新写回 patched 字节并复用原槽位/原蹦床；字节被别人改过则拒绝，避免把别人的 patch 盖掉。
  - method 要求当前 IMP 仍等于原 IMP，才复用 retired 槽位；否则走新槽。
- 槽位仍不回收给**别的**目标（在途线程可能还持有旧 thunk 的地址），Dobby 蹦床按 hook 次数有界泄漏。准确语义是“同目标可反复装载/硬卸载”，不是“无限槽位回收”。
- 真机（学习通，rootless 1.28.2，pid 10746）：
  - `write` inline slot0 hits=98 → `hard:true` 返回 `restored=true, retired=true`，hits 冻结在 98；重装同目标复用 slot0，hits 升到 123；重复安装返回 `already inline-hooked at slot 0`。
  - `-[AppDelegate setupCXLaunchAd]` method slot0 → hard 返回 `restored=true, retired=true` → 重装复用 slot0；重复 method hook 返回 `already method-hooked`。
  - 全程 App 存活。





## 2026-11-13：capture_return（返回值记录）与七鲜 jdgs 实战

七鲜（`com.xstore.sevenFresh`，RN/Hermes）的请求头 `jdgs` 是每请求变化的 JSON，由 `JDGS_pentane` 生成。用本插件在真机上钉死了生成点，并在此过程中补上一个能力缺口。

### 新增能力：`capture_return`

`hook_import` / `hook_method` / `hook_inline` 新增 `capture_return: true`：

- 该槽位从「尾调用」改为 **post 路径**：先 `blr` 原函数，保存 x0/x1/q0-q3，调用 `dh_thunk_post_handler` 记录一条带 `ret=` 的事件，再把返回值原样交回调用者。
- 返回对象会反引用：`NSData` → 前 64 字节 hex、`NSString` → 文本（上限放宽到 4000 字符）、其它 → `description`。
- 代价明确：这一层栈帧要留到原函数返回（不再是尾调用），所以只对付费槽位启用，默认关闭。
- 汇编实现要点：post 分支必须用**局部标号**（`1:`），不能 `cbnz` 到外部符号（汇编器拒绝跨符号条件跳转）。

### 实测（iPhone X / iOS 15.6 / 1.28.4 / 七鲜 pid 12501）

```
-[JDGS_pentane signWithUrlString:contentType:method:bodyData:uppercaseBD:] return
  ret = { jdgs = "{\"b1\":\"486612aa-...\",\"b2\":\"3.0.55_1\",\"b3\":\"3.0\",
                  \"b4\":\"<716 base64 字符>\",\"b5\":\"<64 hex>\",\"b7\":\"<ms>\",\"b6\":\"<64 hex>\"}"; }

-[JDGS_pentane _doSha256:] return
  ret = NSString(64) 6668d13f...018efe
```

结论：`jdgs` 就是这个方法返回的 NSDictionary 里的 `jdgs` 键，不是拼在 header 层的。

### 顺带修掉的可用性缺陷

返回值/描述的截断上限原来是 200/300 字符，jdgs 有 700+ 字符会被切掉关键字段；已放宽到 4000（事件 detail 与 journal 的 8KB 上限仍生效）。

### 未解决（下一步）

b4（base64 解码后 537 字节，非 16 倍数）/ b5 / b6 的构造仍未还原：已排除 46 种单/双/三字段 SHA256 组合、以及用 CCCrypt 抓到的 16B key 做 HMAC。最可能依赖 `JDGS_pentane` 的 `svrtk`/`umidT`/`pwdTable`/`appkey` 等属性，需要 hook 这些 getter 的返回值继续追。
## 2026-11-13 夜间：objc_call oracle 与重复 hook 修复（1.28.9 → 1.28.15）

### 新增工具
| 工具 | 用途 |
|---|---|
| `objc_call` | 直接调用 ObjC 方法并把签名函数变成 oracle。参数按 NSString 编组，`{"$intptr":0}` 传 int32 出参地址（结果回读在 `out_params`）。`class_method:true` 走 +method |
| `objc_dump_ivars` | 沿完整父类链读 ivar（owner/name/type/offset/value/raw_u64），支持 `class`+`shared:true` |
| `objc_export_data` | 把 NSData/NSString ivar 写到 app `Documents/<name>.bin`，便于 scp 取大块数据 |

### capture_after
`capture_ptr_arg` 指向的出参缓冲只有在**函数返回后**才有效（CCHmac 摘要、CCCrypt 密文）。
新增 `capture_after` 标志自动切到 post 路径，在 handler 里读该缓冲并写进 `outputHex`/detail。

### 修掉的两个真 bug
1. **重复 hook_import 会让旧槽位永久 0 命中**：fishhook 按符号改 GOT，再装一次会把 GOT
   指向新槽位，旧槽位还留在 `list_hooks` 里看着像装好了。现在检测到已装就返回 -3，
   MCP 层改成**复用已有槽位**并在回复里带 `reused:true`。
2. **`g_dh_thunk_orig` 残留导致假成功**：dylib 在同进程被 reload 后，上一代的值还在，
   `rebind_symbols` 失败也会被当成成功。现在 rebind 前先清零。
3. `hook_method` 的 +method 解析：元类优先 → `class_getClassMethod` → 扫方法列表。

### 踩到的坑（重要）
**`hook_method` 的 class method 参数名是 `classMethod`（驼峰），`objc_call` 用的是
`class_method`（下划线）。** 传错不报错，只会被当成 instance 语义，返回
"class 'X' or its instance method 'Y' not found"——看起来像类方法不存在。
这个坑让整轮排查里所有下游 inline hook 都是 0 命中，误判成「函数没被调用」。