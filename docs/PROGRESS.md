# IOSDecryptHub 越狱版当前进度

## 2026-11-26：进程内工具端口默认只绑回环（1.28.52 之后，未发布）

- 注入进程自带的 HTTP 服务（越狱包 `8089..8108`）原本 bind `0.0.0.0`，还带 `Access-Control-Allow-Origin: *`，没有任何鉴权，等于把文件、符号、Dump 和事件接口开给同网段任何人。改动前实测：Windows 直连 `http://192.168.200.148:8089/` 返回 200 和完整面板 HTML。
- 现在越狱变体（`DH_DEVICE_SESSIONS`）跟随 `idhjd` 的口径：默认只绑 `127.0.0.1`，状态目录存在 `listen-remote` 标记才放开局域网。巨魔版没有守护进程、端口就是产品入口，保持监听局域网不变。
- `/api/stats` 和 MCP `get_stats` 增加 `port` / `listen`（`loopback` | `any`），让「工具连不上」先能区分是暴露面收紧还是服务没起来。
- 双机真机验收（本次研发包，arm64 / arm64e）：两台默认都报 `listen=loopback`，Windows 与 Mac 连 8089 均不可达；`idhjd` 的 `/api/apps/<bundle>/tools/files` 代理照常拿到真实目录。分别建标记后两台恢复 `listen=any`、局域网返回 200，删除标记并重启后回到 loopback。
- RootHide 路径口径：`/private/var/db/idhjd-v1` 在 App 与根 shell 里都解析到 `<jbroot>/rootfs/private/var/db/idhjd-v1`，标记建在这个视图里（即 `idhjd` 自己的 state 目录），根 shell 在真实 `/private/var/db` 下建同名目录不会生效。
- 门禁：`tests/verify_architecture.sh` 增加「跟随 idhjd 标记」「默认只绑回环」「统计接口报告监听范围」三条，并把它接入 CI（`build.yml` 新增 Verify architecture invariants 步骤）；同一轮修掉两条因为源码是 CRLF 而恒红的 `$` 锚定断言（`DH_HTTP_PORT_FIRST` / `IDH_SESSION_PORT`），现在本机 32/32 全绿。
- 只改进程内端口；`idhjd` 的 8088 原本就只绑回环，未改动。

## 2026-11-25：设备 / App 架构合入主线，进程工具双端真机验收通过

- 设备会话基座和按 App 产品功能已合入 main：`idhjd` 提供设备健康、已安装应用、真实图标、注入范围、App 重启、事件归档与分页；电脑 `idh` 面板改为按设备/App 组织，支持 USB、事件增量轮询、历史翻页和按 App 清理。
- 事件存储从单场会话淘汰改为 SQLite `app_events` / `app_stats` 连续归档。MCP / REST 以 `list_installed_apps`、`read_app_events`、`get/set_injection_scope`、`relaunch_app` 和 `clear_app_events` 为当前接口。
- 用户已确认当前采用 Frida 式传输信任：设备 HTTP 不再使用自定义 Bearer / pairing token，默认绑回环，局域网监听是显式标记行为。旧 `IDH_DEVICE_SESSION_TOKEN`、`IDH_DEVICE_SETTINGS_TOKEN` 和 `pair_process` 文档不再适用。
- 合并前完整包与 control-flow CI 已通过，最终 merge tree 与已验证 feature tree 完全相同；idh-cli 为 65 项本机测试通过。以上不等于 rootless / RootHide 真机验收。
- 本主线同时恢复进程内原工具服务：设备服务固定 `8088`，rootless / RootHide 的进程内文件、符号、Dump 和诊断服务从 `8089..8108` 选端口，避免会话模式开启后丢失原版能力。
- 进程工具代理（Agent 心跳上报进程内 HTTP 端口，`idhjd` 经 `/api/apps/<bundle>/tools/...` 代理原版文件、符号、Dump 接口，下载流转发；`get_process_identity` 设备端实现）已在 1.28.52 CI 验证包上完成双端真机验收：rootless 与 RootHide 的 `tools/files`、`tools/files/download`（二进制字节数精确一致）、`tools/symbols`、`tools/symbols/images`、`tools/dump`（POST）与 `tools/dump/status` 均经代理拿到真实进程数据；进程不在线时错误如实透传。
- 同日顺带修掉三个验收中暴露的问题并合入 main：① Dump 临时/产物目录改用 `NSTemporaryDirectory()` 并透传 NSError（PR #13，RootHide 上宿主 `Documents` 在 jbroot 下归 `root:mobile 755` 导致产物 zip 写失败；rootless 双端验证通过，bin zip 186,638 字节、RootHide 169,774 字节均含正确解密二进制）；② rootless 宿主主程序 dyld 真实路径含 `dopamine-` 段被默认 image 黑名单伪装成 `libSystem.B.dylib` 导致 `dump/images` 为空，dyld 伪装层放行主 bundle 内镜像（PR #14）；③ `relaunch` 谎报（PR #15）：`uiopen` fork 成功不再等同拉起，jb 应用在 `uiopen` 确认未拉起时兜底 `idh_spawn_mobile`（setuid 501 + execve 直启），fork 后仅 async-signal-safe 调用并关闭继承 fd。
- relaunch 双端真机验收：RootHide 0.7s 返回 `{"relaunched":true,"killed":["CryptoTestHost"]}`，新进程注入后 tools 正常；rootless 约 28s 返回 `relaunched:true`（`uiopen` 超时回收后直启兜底），新进程 pid/uid=501/lstart 全新，`dump`（ipa）完成并下载 188,930 字节 zip（186,496 字节解密二进制 + Info.plist）。
- 2026-11-21/22 的双机记录属于已被取代的 session/token 中间实现：当时验证过设备接管 `8088`、进程诊断转发、历史摘要读取和限额写入。这些事实只能作为设计证据保留，不能当作当前按 App 架构的验收结论。

## 2026-11-20：1.28.52 正式发布

- [GitHub Release](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.28.52) 指向源码 8c6de3c。Rootless、RootHide 原双机验收包与 SHA256SUMS 已公开并回下载核对。
- [官网与签名 APT 源](https://ios.decrypthub.com/) 已上线两种架构，公网索引、签名、下载文件及历史包与发布输入一致。保留原签名公钥与旧更新器的 v1.27.5 入口。
- 完整包与原生控制流 CI 均通过。[完整包 CI](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44673431471) [原生控制流 CI](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44673431450)

## 2026-11-19：1.28.52 摘要丢失修复与尾部确认（研发包）

- 在 RootHide 读取上一轮自有测试宿主会话的已保存摘要。序号 1–111 中缺失 65–69，前 64 条和后续 42 条在库，源队列丢失为 0。旧版用同一个 64 条上限限制单批和待确认队列，第一批等待发送或确认时丢掉了后续 5 条。现在每批最多 64 条，待确认队列最多 512 条，满批唤醒并在确认后继续发送。
- 首轮 192 次固定 SHA-256 突发复测另发现 RootHide 的会话 IPC 被网络 Hook 收入摘要，导致一轮 2,000 条记录中网络类达 1,723 条。Agent 通过已有的内部 fd 标记排除会话 IPC。修复后的 RootHide 直接退出及主动结束用例分别记录 6 和 7 条网络类摘要。
- Manager 主动结束时最多等待 3 秒。Agent 在日志队列设定边界，提交剩余摘要和最终序号。服务只有在核对保留条数与已知丢失合计并提交终批次后，才确认尾部。直接终止或者超时会标为尾部未确认。
- 最终 1.28.52 整包在两台真机分别用仓内 CryptoTestHost 跑了直接终止和 Manager 主动结束两组。Rootless 退出前后分别为 287→287 和 297→297，RootHide 为 278→278 和 284→284。四组都逐条匹配、序号连续，摘要和源队列丢失均为 0。待确认队列峰值 Rootless 为 101/105，RootHide 为 66/66。
- 直接终止两组标为尾部未确认。主动结束两组分别确认最终序号 297 和 284，退出后的记录与退出前相同。Manager、MCP 与 `idh-cli` 读数一致，直接终止两组另通过目标重启隔离、服务重启和重新配对复读。两份研发包与更新器回归通过，测试后关闭会话模式并保留记录。

## 2026-11-19：1.28.51 设备会话第一版（研发包）

- `idhjd` 由 launchd 管理。本机 Unix socket 依据内核返回的 PID、UID、审计身份和可执行路径识别对端。两种越狱环境均先用独立探针验证了 Manager 与自有宿主的往返和身份，随后用整包验证实际组件。Rootless 直接启动服务，RootHide 沿用 shell 包装入口及 bootstrap 内的 Manager 名单，Loader 和会话服务读取同一份名单。
- Manager 增加应用会话页，Agent 在日志工作队列输出独立编号的摘要。设备服务用 SQLite 一起提交摘要和游标，并通过本机 `8088` 提供配对后的只读 MCP。`idh-cli` 提供显式设备会话入口。
- 真机使用仓内 CryptoTestHost 与一次性 Manager 自动化入口触发实际界面操作。Rootless 退出前读取 117 条，退出后保留 139 条，117 条逐条匹配。RootHide 退出前后均为 106 条且逐条一致，摘要队列报告丢失 5 条。两台都报告目标已退出和尾部未确认，Manager、MCP、`idh-cli` 读到同一份保留记录。
- 两台均启动新目标进程验证进程代隔离，并重启 `idhjd` 验证旧凭证返回 401、Manager 重新配对后可分页读到与重启前相同的历史。两种 1.28.51 整包、更新器回归和 `idh-cli` 的 40 项测试通过。验收后恢复正式 Manager 二进制、关闭设备会话模式并保留测试记录。

使用方法和工具参数见 [设备会话第一版](DEVICE_SESSIONS.md)。

## 2026-11-18：1.28.50 正式发布

[v1.28.50 Release](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.28.50) 发布最终 v52 的 Rootless、RootHide 完整 deb 及 SHA256SUMS，标签指向已完成双机验收的 `7398355ccd32c01b1b0e9d46755e34ab72099b59`。原完整包 CI [44166230431](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44166230431) 与新增原生控制流 CI [44166230764](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44166230764) 均成功。本次使用已验收原包，没有重新构建。

完整发布说明见 [.github/release-notes/1.28.50.md](../.github/release-notes/1.28.50.md)。官网与签名 APT 源同步至 1.28.50，沿用原包 ID、公钥及历史包。巨魔版维持独立 1.27.6；旧单引擎 `releases/latest` 兼容入口保留，越狱版通过明确版本的 Release 或 APT 更新。以下“研发包／没有发布”的段落是发布前的验收快照。

## 2026-11-18：1.28.50 原生异常／跳转现场跟踪与最终集成（研发包）

- 新增显式准备的 `live-native-control`，保留原 `normal_return:true` 模式及共享八会话上限。离开模块前从 QBDI 交还真实 CPU／SP／LR，在原线程执行 native helper；通过真实返回点、公开 personality 安装的 landing pad 和实际观察的 setjmp continuation 恢复同一 VM。内部捕获后确实继续记录指令；外部退出以 POD 脱离准确 root／子 guard，再在读取侧生成原线程的 aborted 事件，没有伪造返回值。不读取私有 `jmp_buf` 或猜 LSDA。
- 单指令恢复点优先用专属近距岛。快手密集映射及不可分配的表观 ASLR 空隙已在真机复现，增加具体内核错误和专属 Mach BRK 后端；保留原 task handler 的六种行为／code 协议转发、thread handler 冲突拒绝、端口所有权与命中计数，不替换 App SIGTRAP 处理器。原始指令在物理 patch 前发布给 QBDI 解码器，关闭后的 BL／认证链接仍保持真实 LR；旧 20B Inline 入口先转为原生，避免把 veneer 临时 SP 当成 caller SP。
- Mac 最终 v52 完整包、全部原门禁通过。新增近距完整／准备后原 live、强制 Mach 完整／准备后原 live 四个独立进程，以及六种原处理器转发、thread 冲突、原未知 trap 共八项；验证 GPR／SIMD／flags／TLS／mask 和 identity send-right 引用。新原生 CI 独立于原完整包 workflow，使用真正 ARM64 host 依赖与 SDK MIG，不替换或放宽旧门禁。
- 两台最终整包各通过近距与强制 Mach 的八会话自检，以及七项非法 MCP 请求。验证原异常对象／结果／析构／finally、内外捕获、重抛、两类 jump、mask、0→1、env 复用、递归、相邻调用、旧 Inline 子调用、预算与取消；组合用例每次内部恢复后有十个实际 after PC。强制模式每台真实恢复 531 次，保留快手已有 task handler，RootHide 的 PAC 路径通过。另在已安装关闭 private 入口、已校准控制模式并准备真实签名 root 的状态下，通过 Swift 81 生命周期／4 error future／5 MCP、39 flow、7 timer、2 诊断、10 原生／4 MCP operation、6 原生／4 MCP unwind、native／PAC／ABI／live 7 与 private 4／5 MCP 原回归。
- 真实 `createSig3WithSig:path:` 每台六次原调用，90 对结构化调用、六个 HTTP 精确签名，独立 HMAC／白盒／CRC 为 6／18／6 全部一致；278 个不同实际主程序 PC 均现场解析到原镜像，无恢复缺口或事件丢失。每台五次完整记录 384 条指令，另一次只记录一条仍完成原请求。业务窗口不主动制造异常；异常语义由独立原生夹具验证，没有用重放或入口拒绝代替实现。
- 最终普通分析窗口：Rootless 27 棵／405 对，RootHide 25 棵／375 对完整签名树；15 参数、HTTP 和独立原语分别 27／81／27、25／75／25 一致。7／6 条精确 GCD→native→HTTP 链，256／246 任务完成，展开不足增量 0。没有新 App Swift Task 或 private→sig3 证据，不补造这些父边。Rootless 在本轮系统自动更新为快手 14.10.20(10097)，所有 Method 与实际地址重新解析；RootHide 为 14.10.10(10089)。
- 240 个源码／测试／工具／构建／新 CI 文件与 v52 构建归档 LF 归一后完全相同，另保留 SDK MIG 哈希。两种完整 deb 的安装 hash 与 Mac 原包相同；Rootless 的 Agent／Swift／两个控制资源每字节相同，RootHide 四文件各仅合法品牌字段和对应页 hash 的 40 字节变化，UUID 及其它字节相同。两台已新代重启、暂停，临时 Hook／窗口／任务／recipe／控制恢复点与 Mach server 均为 0，scope 保留。

操作与精确边界见 [NATIVE_CONTROL_TRACE.md](NATIVE_CONTROL_TRACE.md)：标准固定 GPR C／C++／ObjC，原生系统 helper 保持 opaque；任意异步 signal 在运行 VM 内跳出、特殊 Swift／SVE ABI、跨线程 longjmp 和不稳定异常端口没有因此获得支持。CI 终态以本提交的 Actions 记录为准；本轮没有发布 Release／APT。

1.28.49 最终复核：`2611e66` 原完整包 CI [44111775941](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44111775941) 成功；以下对应章节“继续核对”为当时快照。

## 2026-11-17：1.28.49 真实私有 dispatch callback 入口（研发包）

- 从实际快手 source 栈定位未导出的两指针 libdispatch callout；自有公开 source `_f` 回调的原返回地址、当前 unwind 函数边界、镜像、完整识别的 A64/PAC 调用/返回序列与再次真实执行校准。原型与 Apple 官方声明一致，原 context/function、原系统异常处理和执行次数保持；不读私有 source/continuation 字段，不用最近符号或固定偏移。
- 独立默认关闭的准备/开关/状态/自检。实际 App callback 使用原有有界 Flow 表、当前队列和真实函数指针，已有任务身份优先。仅记录 callback-entry，未见注册/入队的字段为空；关闭后仍原样执行。未开启或无窗口时直接转发，代码补丁保留到重启，所有权与 Inline/Trace 互斥。自有校准 context 由取消 block 保有，控制侧超时不遗留借用栈指针。
- Mac 最终 v43 的独立 C 负例、新 native 4 组、Swift 及所有原门禁、两类完整包通过。两台先在新代安装并关闭私有适配器，再通过 Swift 81 生命周期/4 错误 future/5 MCP 与原 39 flow、7 timer、2 诊断、10 原生/4 MCP operation、6 原生/4 MCP unwind、native/PAC/ABI/live7 与接口；再各通过新 private 4 原生/5 MCP，原门禁未放宽。
- 最终私有专窗 Rootless 19、RootHide 18 次实际原 callback，与 TaskID/PC/线程/区间及完整 native 栈精确匹配。窗口前和关闭后原 callback 继续，缺失注册/提交不补造；反复出现的 context 地址不当作 source 生命周期。两窗展开不足为 0。先期 v41 Rootless 3 次 App 日志路径 metadata 止步证据保留。
- 开启私有入口和 Swift 观测的普通网络窗口：Rootless 22 棵/330 对、RootHide 24 棵/360 对完整签名树，核心 15 参数、HTTP 与独立 HMAC/白盒/CRC 分别 22/66/22、24/72/24；7/6 条精确 GCD/native/HTTP，256/246 任务完成，两窗不足增量 0。窗口无新 App Swift Task，没有私有入口→sig3 外推。
- 最终 v43 source 页面另验证 Rootless 2 注册/14 次、RootHide 4 注册/10 次原 callback，全部 PC/Task/注册 ID/线程/区间和完整 native 栈一致；30/16 个旧 callback 没有补造注册。Rootless 先期窗口发生日志背压、缺少早期入口事件；最终按用途筛选 other 并周期导出，丢弃 0，原捕获配置逐字节恢复。没有扩大预算或用任务元数据代替丢失的原入口。

协议见 [PRIVATE_DISPATCH_ENTRY.md](PRIVATE_DISPATCH_ENTRY.md)。同源/安装字节/CI 复核继续；QBDI 异常/longjmp 透明执行和最终最高版本集成仍继续。没有发布 Release/APT。

## 2026-11-17：1.28.48 Swift Task 原生身份与生命周期（研发包）

- 独立默认关闭的 `configure_swift_capture` 与状态/任务/调度事件/自检五项工具。public Swift 5.5/5.7 runtime 的 typed swiftcall 创建、job、global/main/delay/deadline 入队与 swiftasync 最终回调保持原参数、executor、closure、TaskLocal 和实际任务对象；Rootless 缺少 deadline 导出时明确报告。最终回调必须尾调用原函数，runtime 镜像、真实函数指针和可执行映射逐项校准，不从弱 unwind 范围猜入口，不读取私有 Task/Job 布局。
- 每次原创建调用的 ticket 与实际初始 enqueue 指针证明生命周期；提前完成还须匹配 ticket/Task/初始 context/最终函数。512 历史不复用、128 单窗/60 秒、128 初始入队/128 提前完成证据及 1024 POD 事件环有界。创建记录发布前的真实结束竞态先红后绿；未知入口/未见入队/丢失明确 unresolved。runtime completion 进入与原 native job 返回确认分开，future 错误不是异常中止。
- 通用事件增加 TaskID/创建来源，成对调用保存入口的身份；同一物理线程上不同 runtime Task 的同步 parent/depth/GCD 身份隔离，恢复嵌套 GCD 范围保留原域。creator 关系不冒充 Swift structured parent，原生 job 容器不冒充 Task 父级。
- 最终 Mac v38 的新真实 Swift native 门禁和全部原门禁、arm64/arm64e 完整包通过。独立 Swift 资源随整包编译/架构验证/签名，仅显式自检加载；Agent 仍保持 iOS14 链接范围。两台各通过 81 自有生命周期、4 错误 future、MainActor/TaskLocal/async-let/sleep/yield/取消/关闭后 pending/预算与 65 快任务，5 项 MCP，以及原 39 flow、7 timer、2 诊断、10 原生/4 MCP operation、6 原生/4 MCP unwind、native/PAC/ABI/live7 与接口回归。真实提前结束补记 7/11 个。Rootless 启动繁忙期 MainActor 延至 11.8 秒触发原 10 秒失败，事件确认七任务最终正常结束；稳定启动后同包重跑通过，门禁未延长。
- 最终真实快手网络：Rootless 21 棵/315 对、RootHide 23 棵/345 对完整调用，核心 15 参数、sig3/HTTP 和独立 HMAC/白盒/CRC 分别 21/63/21、23/69/23 一致；7/6 条 GCD/native/HTTP 链，256/246 任务均完成，展开不足增量 0。Rootless 无新 App Swift Task；RootHide 实际捕获 5 次 App Task 创建和四个 job 入口/返回，初始 enqueue 身份有效、读取时任务未结束，不伪称 completed。没有观测到 Swift→sig3。

协议见 [SWIFT_TASK_FLOW.md](SWIFT_TASK_FLOW.md)。同源/安装字节与原 CI 核对继续；其它实际私有调度、source 实际路径、QBDI 异常/longjmp 透明执行及最终最高版本集成仍继续。没有发布 Release/APT。

1.28.48 最终复核：`2be1dba` 原完整包 CI [44101039455](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44101039455) 第2次成功；首次未分配到 hosted runner、无步骤执行。215 同源、双机 Agent/Swift 资源安装字节和清理全部通过，未改原 CI 门禁。

## 2026-11-17：1.28.47 NSOperation 实际执行与生命周期（研发包）

- 五个固定 ABI 公开 Method 适配器及每具体类的 start/main 入口共用原 Hook 归属检查；原 operation、依赖、取消、并发上限、BOOL wait 和队列负责执行。普通 block 每执行体独立 token，Foundation 实际 invoker 校准后才领取身份；直接调用 executionBlocks 不抢队列任务。64 元数据记录、32 执行 Method、128 block 包装器有界且不复用，达限继续原工作并明确 unresolved。
- 实测快手 `KSImageHodorTaskOperation` 覆盖 start，却报告非异步且不调用 main。已根据实际 Method 覆盖选择 start，独立同步自定义 start 夹具先红后绿。异步 start 返回与原 operation finished 分开，公开生命周期附采样时刻和对象存活状态；不把 callback completed 当作 operation 完成。
- 独立夹具还复现旧适配器获取 App operation 监视锁时的额外等待。最终改用 IDH 自有锁并统一 worker 快照读取，原对象锁不再被适配器获取。没有新增会在 longjmp 后遗留的 operation TLS。
- 最终 Mac v33 两类完整包、10 组 operation、原 flow/runtime/ABI/unwind/iOS/updater 门禁均通过；两台最终整包各通过 10 组新原生/4 项新 MCP、原 39 flow、7 项 timer、2 项诊断、6 原生/4 MCP unwind 和原 native/PAC/ABI/live 7 组与接口回归。原验收断言和 CI workflow 未放宽。
- 实际 operation 窗口：两台各 28 棵完整签名树、420 对调用、核心 15 参数、sig3/HTTP 与独立原语一致。Rootless 64 个 operation、RootHide 43 个；每台对 KSImageHodorTaskOperation、SDAsyncBlockOperation 各保留 8 个原函数 Inline 入口，准确 PC/原参数/TaskID/线程和实际回调区间一致；另分别 40/72 条子提交栈确含原 SD callback 的 operation→GCD 边。Rootless 222 任务完成、34 项容量拒绝均 unresolved 且无执行字段；RootHide 256 完成。223/330 次展开不足仍保留真实诊断，不重建缺帧。该窗口没有签名树携带 operation TaskID，不称作 operation→sig3 链通过。
- 换新代后的最终普通网络窗口：Rootless 31 棵/465 对，RootHide 23 棵/345 对，全部核心参数、HTTP 与独立 HMAC/白盒/CRC 分别 31/93/31、23/69/23 一致；4/6 条精确 GCD/native/HTTP 链。164/246 任务全部完成，两窗口展开不足增量均 0。根队列定向保持原 256 预算，没有据此声称所有请求都有完整异步图。

协议与边界见 [OPERATION_FLOW.md](OPERATION_FLOW.md)。本切片的同源、安装字节和 CI 继续核对；Swift Task、其它实际调度、source 实际注册与 QBDI 异常/longjmp 透明执行及最终集成仍继续。没有发布 Release/APT。

1.28.47 最终复核：`f4298a3` 原完整包 CI [44077317216](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44077317216) 成功；209 文件与 Mac v33 构建同源，Rootless 安装每字节一致，RootHide 仅合法品牌/对应页 hash 40 字节变化。两台已清临时 Hook/窗口/规则并暂停，scope 保留。

## 2026-11-17：1.28.46 原生缺失元数据的有界恢复（研发包）

- 新增显式登记的只读 A64 frame recipe：Reader 按独立 LC_FUNCTION_STARTS 边界验证最多 256 个指令槽、512 字节帧的 CFG、原始 x19–x30 保存状态和精确 SP/FP 关系；命中重查字节、栈界限、所有保存槽、无 PAC 的真实 LR 与 BL/BLR callsite。通过公开 unwind API 重建 caller cursor，包括非易失 D8–D15，不改 App CPU、代码或 CFI，不扫描 FP。32 条规则不替换、不复用，默认没有规则，开关与登记均检查本代 generation。
- 已启用规则优先于该函数的系统 metadata，验证失败报告具体原因并止步。原始栈 V3 保留逐帧规则来源、恢复次数及保存返回地址减 4 的地址语义，兼容 V1/V2；旧代日志不套当前 slot 身份。未知/PAC/动态栈/保存桩/不一致 CFG 等继续拒绝，不承诺任意缺口可恢复。
- 修复反汇编 STP/LDP 的 writeback 信息：读取 Capstone 架构 detail 中实际填充的字段，恢复 pre/post SP 写入报告。新增 portable 正负例、真实汇编缺口与依赖原 x19 的 caller DWARF 夹具，以及登记/开关/坏参数和 writeback 的 MCP 回归。
- 首个 arm64e 夹具将 undefined RA 直接设为 0，曾触发 RootHide 系统 unwinder 的指针认证 trap；保留崩溃与反汇编证据。改用独立、正确认证的结束标记后，最终 v21 两类完整包与原 Mac 门禁通过；双机 6 组原生夹具、4 项新 MCP、39 组 flow、Timer MCP 7 项、诊断 2 项及原 ABI/PAC/native/live 7 组和接口回归全部通过，scope 保留。独立 CLI 未能执行，不将其算作通过证据。
- 快手真实展示日志路径：第一条规则恢复后准确暴露 caller 的第二处 metadata 缺口；按真实 LC 边界另验证并登记第二条规则。最终 Rootless 82 个、RootHide 80 个样本均恢复两层，两个 caller SP 各增加实际帧长 32 字节，继续到原 CFRunLoopRunSpecific 与 UIApplicationMain，error 0 且无截断。关闭两条规则后，双机各 30 个样本重新止于第一处真实弱帧；不是只凭登记或计数称成功。
- 两条规则恢复后另做正常协议回归：Rootless 22 棵/330 对、RootHide 21 棵/315 对完整调用树，核心 15 参数、返回 sig3/HTTP 及独立 HMAC/白盒/CRC 分别 22/66/22 与 21/63/21 一致；实际异步/native/HTTP 链为 5/4 条，窗口展开不足增量均为 0。样本范围以真实窗口为准，没有声称所有请求都具备异步图。

协议与限制见 [NATIVE_UNWIND_RECOVERY.md](NATIVE_UNWIND_RECOVERY.md)。同源/CI 与本轮最终最高版本集成仍继续核对；NSOperation、Swift Task、其它实际私有调度、source 实际注册路径及 QBDI 异常/longjmp 透明执行仍在全部后续清单中。没有发布 Release/APT。

1.28.46 最终复核：提交 `1116671` 的原完整包 CI [44058900353](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44058900353) 成功；204 个源码/测试/工具与最终构建精确同源，Rootless 安装每字节相同，RootHide 仅合法品牌和对应页 hash 变化。两台已清除临时 Hook/窗口/规则并暂停采集，scope 保留。全部后续继续。

## 2026-11-17：1.28.45 RunLoop / NSTimer（研发包）

- 六个公开 CF 导入与既有 20 项调度导入统一管理所有权；CF context/retain/release、原 loop/mode、重复/移除/失效及 PerformBlock 原参数保持。四类 NSTimer 工厂固定原型保留 double、BOOL、target、selector、userInfo/block，不解析私有 info。统一 typed native/Method 后端与动态 Hook 互斥，原 Dobby 发布约束及已补丁 Trace 拒绝继续生效。
- 每代实际 RunLoop target/block timer 校准 Foundation `__NSFireTimer(timer, info)`，不匹配则不启用。新 callback-entry 边明确窗口前注册未观察到，registrationId/submittedBy 为空；新建 timer 的 registration 与每次 delivery 分开，手动 fire 不冒充调度。
- 新只读 get_timer_state 与 root_callback_include：直接观察工厂的 target 类/selector 标签筛选根，未知标签不匹配、后代继续传播；不扩大原 256 预算。Agent 内部提交继续排除，只在自有夹具线程显式允许测试来源，新增负例防止日志任务继承 App 上下文。
- 实测发现旧 source 转发强参数在系统 disposal 取消时额外 retain 触发 libdispatch 引用计数保护。已改借用 source/queue/object 参数，并单独保有真正包装的 handler。旧优化 IR 回归为红，新 arm64/arm64e 九种 wrapper 检查为绿；过程中 unsafe block capture 的生命周期问题由原 runtime 测试捕获，并以 owned handler 修复。保留失败证据，不将其归因于环境。
- 最终 v15：Mac 35 组（native/factory 明确 skip）、旧 runtime/ABI/unwind/iOS/updater 和两种完整包构建通过；双机 39 组 flow、新 timer MCP 7 项、诊断 2 项及原 native/PAC/ABI/live 7 组和接口回归通过，scope 保留。同源与 CI 继续核对；全部后续目标尚未结束。


- 实际 NSTimer 定向窗口：Rootless 26 棵/390 对、RootHide 27 棵/405 对完整树，所有核心 15 参数 ABI、返回 sig3/HTTP 与独立 HMAC、白盒、CRC 一致。每台另有 3 条同时具备实际 timer TaskID、原 Foundation callback 在 native 栈内与精确 HTTP 的链，真实创建实参为 `[KSRefreshControl timerToWaitDragingEndFired:]`。各窗口 256 任务全部正常完成；仍有预算/筛选外请求，2/3 次展开证据不足均保留诊断而不猜关联。
- 早期宽窗口曾被弹窗遮挡或重复 timer 耗尽预算，失败与不足证据单独保留。swipe 工具默认 20 个移动事件会在此 App 反复创建刷新轮询 timer，最终验证使用真实标签和短手势/单个移动事件；仍保持原任务预算。注册的 submittedNs 与本次 deliveryObservedNs/startedNs 含义不同，不能拿注册时间统计本次窗口耗尽时刻。

- 换新进程后的普通网络回归：Rootless 20 棵/300 对、RootHide 21 棵/315 对，全部核心参数、HTTP 与独立原语一致；每台另有 4 条真实 GCD/native/HTTP 任务链，窗口展开不足增量均为 0。两类窗口分开保存，不据此称所有请求均有完整图。

协议和边界见 [RUNLOOP_TIMERS.md](RUNLOOP_TIMERS.md)。没有发布 Release/APT。

## 2026-11-17：1.28.44 source 注册/delivery 与根 API 定向（研发包）

- 新有界注册层把来源注册与每次回调分开，提供 get_async_registrations、registrationId/asyncRegistrationId、deliveryObservedNs 和明确的 registered-handler-to-callback 边。128 个注册不复用、每页最多 8 条；source 生命周期创建绑定最多 64 个，原任务预算不扩大。新 root_api_include 选择根入口，后代保留传播。
- source 九项公开导入与原十一项一起检查/预留所有权。普通已识别 block、event/cancel/registration 的固定 `_f` 类型入口保留原 context；不替换 do_ctxt、不读私有 source 布局。重复事件独立任务、替换/NULL 移除/释放退休、取消请求与实际回调分开，队列变化保留原参数和两种时间位置。未知旧对象与特殊/未知 block 明确放行而不猜边。
- 新九组语义夹具使 flow 自检增至 30 组，Mac 与两台最终 v6 整包均通过。原 runtime/ABI/unwind/iOS、updater、两份完整 deb 构建通过；双机新注册分页/非法请求/Import 所有权、原 flow/diagnostics/native/PAC/live 与接口回归通过。原门禁未改，scope 保留。
- 实际 source 定向窗口：Rootless 29 棵、RootHide 32 棵完整签名树分别与 HTTP 和独立 HMAC/白盒/CRC 一致；该窗口没有捕获到支持范围内的新 source 注册或 delivery，不能称作 source 业务链通过。普通网络窗口另为 Rootless 18 棵 / 270 对与 RootHide 20 棵 / 300 对，各全部与 HTTP 和独立原语一致，其中 4/5 条有完整实际 GCD 任务链、原 callback native 栈和精确 HTTP。
- 未关联样本中实际观察到 Rootless 5 条、RootHide 6 条 __NSFireTimer 路径；两台都以当前代符号化、函数边界和反汇编核对 Foundation 的真实入口，dlsym 也匹配。RootHide 入口含 PACIBSP。这里只完成定位；RunLoop/NSTimer 适配与固定 ABI 校准继续实施，不据此伪造注册或父边。

当前只完成本切片，整体后续清单仍继续。协议及准确边界见 [CALLBACK_REGISTRATIONS.md](CALLBACK_REGISTRATIONS.md)，未发布 Release/APT。

## 2026-11-17：1.28.43 GCD group/block notify（后续调度适配之一）

- 在原六种提交和两个 block 构造器上补 `dispatch_group_notify`、`dispatch_group_notify_f`、`dispatch_block_notify`，十一项导入统一管理所有权。保留原 group/依赖 block、queue、context/function 和特殊 notification 的原外层对象；不会将登记通知当作依赖已结束或 callback 已执行。关闭窗口后，已登记的 pending 通知仍实际执行并保留原任务身份。
- 新三组真实运行时夹具验证 block/function 通知在依赖完成后各执行一次、原 `_f` context、被取消依赖仍触发通知、特殊 notification 的 QoS/等待与关闭窗口后的 pending 语义；Mac 与双机 21 组 flow 通过。既有 Mac ABI/unwind/iOS、更新策略和两种完整 deb 构建通过。1.28.43 整包已刷入两台且保留 scope，扩展的 Import 所有权 MCP 回归通过。
- 原完整包 CI [44021120704](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44021120704) 在 `47a7815` 成功，门禁保持不变。
- 快手最终网络窗口：Rootless 29 棵 / 435 对，RootHide 24 棵 / 360 对；核心 15 参数、返回 sig3/HTTP、独立 HMAC/白盒/CRC 分别为 29/87/29 和 24/72/24 一致。Rootless 5 条、RootHide 4 条同时具备真实任务链、原 callback 的 native 栈证据和精确 HTTP 匹配。Rootless 另实际观察到 1 个已正常完成的 group notify；RootHide 该实际窗口未观察到 notify，三类通知的双机语义证据来自自有夹具。
- 先期 RootHide 窗口有签名调用在窗口内找不到对应 HTTP，未将其当作完整链；收紧队列并回到首页后重新验证上述最终样本。先期另复现 176 次已知栈锚之前的元数据终止；最终定向窗口该计数增量为 0，两类窗口分别保留，不能据此称元数据缺口已修复。

dispatch source、RunLoop/NSTimer、NSOperation、Swift Task、私有调度以及 QBDI 异常/longjmp 透明执行继续待实现。当前是完整目标的一个切片，未发布 Release/APT。

## 2026-11-17：1.28.42 栈边界诊断与已证实关联的保留（研发包）

- native 栈增加精确终止原因、libunwind step 结果、最后 PC/SP/FP、procedure 范围与线程栈界限。原始记录升级为 V2，读取仍兼容 V1；缺行与畸形记录不报完整。`complete` 仍表示后端正常终止，不能单独证明到达线程根或越过某个已知包装帧。
- `get_flow_state` 按六类原因统计证据不足；新只读 `get_flow_diagnostics` 保留最近 16 条原始边界、每页最多 4 条，由读取线程符号化。`candidateTaskId` 仅用于诊断，不建立父边；命中线程只保存有界快照。活跃环形缓冲区可能在两页之间变化，读取者应检查 total/overwritten 和记录 ID。
- 局部栈已实际包含所有已登记 post 桥与当前异步包装帧的准确 PC/SP/cookie 时，保留已证实的关联；不会因更高层截断而丢掉该父关系。局部栈中没看到某帧仍不证明退出，不据此退休调用或任务。新增第 18 组真实活动桥夹具，旧缺口/异常/longjmp 状态保护回归继续通过。
- Mac 原运行时、unwind、iOS 编译、更新策略与两种完整 deb 构建通过；同一源码 1.28.42 整包已刷入两台授权设备且 scope 保留。两台各通过 18 组状态/GCD 自检、新诊断 MCP 的分页/非法参数/只读验证，以及既有 native/PAC/ABI 和 7 组 live 自检及 MCP 回归。
- 原完整包 CI [44019080374](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44019080374) 在 `23e1299` 成功，依赖/更新/整包验证步骤保持不变。
- 快手实际请求独立复核：Rootless 36 棵完整调用树、540 对调用，RootHide 25 棵、375 对调用；核心 15 参数 ABI、返回 sig3 与对应 HTTP 精确匹配，HMAC/白盒块/CRC 分别为 36/108/36 和 25/75/25 组一致。
- 该真实窗口 Rootless 另有 15 次 `stopped-before-async-scope`：libunwind 在 App RVA `0xda476b4` 正常停止，但还未到已知包装锚。已记录真实缺口并抑制关联，没有伪造业务 aborted，也没有盲目扫描 FP 补帧。RootHide 本窗口未复现同类缺口，不代表任意路径都可完整展开。

本版本完成诊断和有证据的局部恢复；任意缺失元数据路径的完整展开仍未解决。RunLoop/NSTimer、NSOperation、Swift Task、notify/source、私有调度适配和 QBDI 内异常/longjmp 透明执行仍未实现，不能用普通 post 的状态保护代替这些能力。未发布 Release/APT。

## 2026-11-17：1.28.41 系统库嵌套映射预检（全部后续项的第一切片）

- 修复 Import 与 QBDI 两处重复的 vm_region_recurse_64 遍历：内核会把 address 改为当前 region 起点，下一层必须恢复原目标地址；不能检查 shared-cache 起点的另一片区域。两入口共用有界叶映射查询，继续要求目标确实位于当前 EXECUTE 叶区，不以 max_protection 或整个镜像范围代替。
- 新只读 get_memory_mapping，提供每层原查询地址、实际 region、深度、当前/最大权限和内核错误；最多 16 次。非法输入、映射空洞、数据页、查询错误和过深嵌套保持拒绝。新增嵌套映射回归夹具通过，原运行时/ABI/unwind/iOS 编译、更新策略与两种完整 deb 构建通过。
- 同一 1.28.41 完整包已安装到两台授权手机并保留 scope。两台实际 walk 均见 shared-cache 外层只读 submap 与目标 RX 叶映射；RootHide 旧负例 dispatch_block_create Import 已安装并观察真实配对调用，dispatch_queue_get_label QBDI 正常完成并返回可读队列名。真实数据符号仍为不可执行，畸形地址仍拒绝。
- 原完整包 CI [44015331453](https://github.com/decrypthub/IOSDecryptHub/actions/runs/44015331453) 在提交 `47b8b44` 通过，依赖准备、更新策略与双环境整包门禁未改。
- 这只完成映射修复；用户本次要求的 native 展开改进、RunLoop/NSOperation/Swift Task/notify/source/私有调度、QBDI 异常/longjmp 透明执行仍继续实施，不以第一切片完成代替整体目标。


## 2026-11-17：1.28.40 RootHide sig3 调度入口与因果链（研发包）

- 先核对真实执行栈、App UUID/RVA、提交 stub/GOT 和运行时入口：普通网络分支经过已有 dispatch_async；额外延迟分支为公开 dispatch_block_create(0, block) → dispatch_after，队列是 com.kuaishou.statistics.serialQueue。旧宽泛排除条件会挡住目标队列；另一窗口的 256 条预算约 286ms 即被日志耗尽，签名在约 3.2s 后才执行。不能据“无 TaskID”断言缺少某种私有调度器。
- 新 root_queue_include 只筛选没有 async parent 的根，保留换队列后代；queue_exclude 继续对每次提交生效。新增窗口开始/截止、停止原因、筛选计数、callback UUID/RVA 和公开 block 创建 caller 身份，关闭后保留最近窗口诊断，预算没有扩大。
- 六个提交导入另加两个公开 block 构造器。捕获窗口内创建的 App block 在内层执行回调携带身份，提交仍传 libdispatch 原外层对象，保留 flags/QoS/取消/等待。校准 direct/async invoker 的真实 metadata 范围；执行前重用、入队后直接调用及释放但未观察到开始均不猜执行边，任务可标 unresolved，不能当 completed/aborted。创建绑定同样有每窗口/进程上限，不访问 libdispatch 私有布局。
- Mac 17 组状态/GCD 运行时测试、原汇编/ABI/unwind、iOS 编译、更新策略和两种完整包构建通过。1.28.40 整包已刷入两台授权设备，scope 保留；两台 17 组自检、扩展 MCP 参数/所有权/状态验证及原 Inline/PAC/ABI/live 回归通过。现有完整包 CI 门禁保持不变。
- 最终包首轮快手实测：RootHide 10 条普通网络链 + 1 条统计延迟链，Rootless 9 + 1。延迟链保留四级真实 TaskID：统计队列根 → 统计队列调度 → 特殊 block 的 dispatch_after → HTTP 队列签名/请求；完整同步调用树、原 callback 在实际 native 栈中、相同/后代 TaskID 与 HTTP sig3 精确匹配均核对，不按线程或时间猜父任务。
- RootHide 在第二个全新进程代重新安装临时探针并复测，统计延迟四级链再次精确匹配 HTTP；新 ASLR 下按本代 UUID/RVA 和 TaskID 取证，未复用旧绝对地址。该窗口另有 2 条 unresolved 和 1 条仍 pending，均未捏造执行或完成。
- 首轮 RootHide 46 棵同步树 / 690 个配对调用，Rootless 54 / 810；各树的核心 15 参数 ABI 与返回值/HTTP 一致，独立 HMAC、白盒块、CRC 验证分别为 46/138/46 与 54/162/54。两台另各完成真实 SDK CRC live 2489 指令、独立 zlib 一致；同步栈 RootHide 81、Rootless 89 帧，完整且 error 0。
- 统计窗口每台有 1 条提交未观察到执行，明确 unresolved；RootHide 普通窗口另有 230 次其他边界展开证据不足，按既有规则抑制不确定关联，未生成业务 aborted。已验证链逐条满足 contextComplete 和真实 callback 栈证据。RunLoop 定时器、未选中的根、窗口前/预算后调用继续单独报告，不称作所有请求的完整异步图。

未发布 Release/APT。当前协议和准确边界见 [状态保护/GCD](FLOW_STATE_AND_GCD.md)。

## 2026-11-16：1.28.37 非局部退出状态保护与有界 GCD（研发包）

- 普通 post 登记有界保护记录，正常返回之外，在后续边界用 owned bridge/CFA 栈证据清理退出的调用、同步父上下文和 inFlight；已有 entry 的调用标 aborted，不伪造 leave。线程结束由独立 pthread-key 快照收尾，避免依赖可能已被清理的编译器 TLS。
- 缺失/截断展开或尚未越过已知保护位置的提前停止只计 unverified 并抑制关联，不误退仍存活的帧。异步任务终结由实际包装器退出、线程退出或后续包装器入口的充分证据负责，任意业务探针看不到包装帧不直接标任务异常。
- 新 configure_async_capture/get_async_tasks/get_flow_state/run_flow_selftest。六类公开 GCD async/after/group 的 block 与 _f 导入按显式窗口观测 submit→execute；异步 ID 与同步 parent/native 栈分开。支持有界队列排除，跳过 IDH 自身提交；特殊 dispatch-block 和未知/系统 invoke 原样转发，校验取消/等待语义。导入所有权预留与动态 Hook 互斥。
- 默认关闭；每进程 1024 条、每窗口最多 256 条/60s、最多 64 pending/running、深度 8，提交栈 32 帧。关闭/超限继续转发，不取消已排队工作；pending 不冒充完成。队列标签有界且安全处理 UTF8 截断。
- Mac 新原生状态/GCD 测试 12 组通过，既有 hook/unwind/arm64+arm64e 编译、类型/Mach-O、更新策略、两份完整 deb 通过；Python 离线 8 项通过。C/ObjC/ObjC++ 按扩展名编译以支持 C++ fixture，既有验收断言与 workflow 未放宽。
- 最终研发整包在 rootless iPhone X / iOS 15.6 与 RootHide iPhone 11 / iOS 16.2 通过 12 组新自检与 3 项新 MCP 回归；另通过既有 Agent/native/PAC/P0/复杂 ABI 拒绝回归及 7 组 live 自检和其 MCP 回归。自有 fixture 实测 ObjC/C++ 异常原样传播、longjmp、内部捕获不误退、暂停、展开缺口、线程退出、跨线程嵌套与预算/窗口/关闭语义。
- 快手 14.10.10 最终整包实测：rootless 两个有界窗口保留 512 任务、346 次跨线程执行、187 个嵌套来源；RootHide 三个窗口 768/526/257，最终导出均实际正常返回。未充分验证的边界分别计 3/33，没有据此伪造任务异常；实际普通调用 aborted/guardOverflow 均 0。
- 两台各保留一组 15 棵完整签名调用树、225 对调用、15 次核心 15 参数正常入口/返回，15 个 facade 返回均匹配本轮 HTTP sig3；各 15 HMAC/45 白盒块/15 CRC 独立离线一致。最终整包 rootless 另有 3 棵树与 HTTP 在同一/后代真实任务 ID 下连接；RootHide 最终窗口未覆盖签名任务路径，不能把普通 GCD 任务验证外推成其全部 sig3 因果链。前一迭代 v10 在 RootHide 曾离线闭环 3 组，最终 v11 的差异仅为队列 UTF8 元数据处理，仍分别保留证据和覆盖结论。
- 最终整包的真实 SDK CRC live 再验：两台各 2489 条指令，结果与原 leave 和独立 zlib 相同，栈 rootless 130 / RootHide 129 帧均完整无错。历史 journal 保留旧代身份，任务表只属于本代 RAM。

整包保留原 scope；结束时重启授权目标清临时 Hook/转发并暂停采集。未发布 Release/APT。本轮不提供 QBDI 内异常/longjmp 透明执行，也未覆盖 Swift Task、NSOperation、group notify/source 或私有调度器；有界窗口的命中范围逐样本报告。协议、状态与入口见 [状态保护/GCD](FLOW_STATE_AND_GCD.md)。

## 2026-11-16：1.28.36 真实调用现场与完整同步 native 栈（研发包）

- 新增 `trace_live_arm/read/cancel`：选择已安装 Inline 的下一次真实调用，在原 App 线程、TLS、SP 和原栈上执行 QBDI，不人工重新调用、不替换输入指针。完整保存 x0–x30、q0–q31、NZCV/FPCR/FPSR、原始 SP/LR、errno 及出口现场；IDH 专用 Dobby context veneer 在使用 IP 寄存器前保存 x16/x17。
- QBDI 控制端使用预分配 guard 分析栈，guest 使用真实 App 栈；最多保留 8 会话，每次最多记录 8192 条。记录/时间预算耗尽只停止记录，继续原调用至正常返回；取消只适用于尚未命中。输出明确区分调用完成、记录截断与模块外 native transfer，不把 replay 当现场执行。
- 公共入口和 post 桥补 CFI，arm64e 的 unwind 返回槽按原 CFA 单独签名，避免与转发 LR 混用。动态 Hook 从原 caller 现场展开，默认密码/网络事件也改采原始 PC/SP。系统 libunwind 最多 256 帧，缺元数据、循环、截断和正常根分别报告；命中线程不完整符号化，读取时补 UUID/RVA/最近符号，旧代 journal 不套用新 ASLR。
- Mac 原有汇编/ABI/并发/journal、Darwin 类型与 Mach-O、更新策略及两种完整 deb 均通过；新增真实嵌套 post 栈展开测试通过，实际 arm64/arm64e 编译通过。原有完整包 CI 门禁保持不变，仍从固定源码构建依赖。
- 两台授权设备均安装同一 1.28.36 整包，通过既有 Agent/native/PAC/P0/复杂 ABI 拒绝测试；新增 live 7 组自检及 3 项 MCP 回归通过，覆盖恰好执行一次、15 参数 packed stack、SIMD、隐藏 x8 结构体输出、原 IP0/IP1、errno 入口/出口、4 条预算不中断、命中前取消。
- 快手 14.10.10 真实 UI 触发的 CRC/HMAC/白盒块，在两台各完整记录 2489/7603/5449 条指令；按同 callId/TID/SP/LR/真实参数指针核对原 entry/leave，输出与独立 zlib/SHA256/表驱动块运算一致。CRC 栈 rootless 85 帧、RootHide 129 帧，HMAC 76/76、白盒 77/77，全部 complete、未截断、error 0。
- 每台另采 15 棵完整同步调用树、225 个配对调用及 15 次核心 15 参数正常入口/返回；各 15 个 facade 返回逐字匹配本轮 HTTP `__NS_sig3`。两台各独立验证 15 HMAC、45 白盒块、15 CRC，一致。此处不是输出算法材料，原始捕获仅留本机验证目录。

研发整包已刷入两台，原 scope 保留；测试结束重启目标清除临时补丁并暂停采集。未发布 Release / APT。正常返回函数及模块内覆盖是约束；完整性指该同步 native 栈的实际展开结果，不恢复优化掉的 inline/tail-call 或异步逻辑帧，也不承诺异常/longjmp 控制流。普通 post ABI 与 Inline 硬卸载限制继续生效。操作、资源上限与测试入口见 [真实现场协议](LIVE_CONTEXT_TRACE.md)。

## 2026-11-16：1.28.35 RootHide Inline / QBDI（研发包）

- RootHide 完整包链接真正的 arm64 / arm64e Dobby 与 QBDI，移除胖包禁用后端的分支；链接前校验请求切片。Dobby/QBDI 固定源码提交、分架构编译，arm64e 开启 QBDI PAC；修正上游 iOS 汇编硬编码 arm64 和静态 Config.h 的架构选择。
- Inline original 在入口补丁激活前 release 发布，thunk acquire 读取并去 PAC；失败后已发布槽位保留。Darwin 写补丁增加有界线程暂停、PC 检查、恢复与写入前重试，拒绝跨页或补丁器自身页；代码生成必须传播写入失败。此机制覆盖枚举快照，不能保证外部新线程或第三方补丁全部静止，仍拒绝硬卸载。
- 跳板不具备完整 unwind 契约，动态命中仅记录直接 LR/SP，报告 direct-caller-only；同步层级使用 callId/parentCallId。内部镜像身份读取保留真实路径，避免自身隐藏策略污染 UUID/RVA 的说明。
- `trace_function` 新增有界 call-owned buffers，复制输入和参数区后回放、返回 afterHex；最多 8 个固定 GPR 参数。明确 replay/contextComplete:false、PAC、retval_valid，超预算结果不当作函数返回值；拒绝已保留 Inline 补丁的入口，软停后也须重启并重新解析。
- Mac 实际汇编/上下文/ABI/journal、纯 C 类型与 Mach-O、更新策略及两种完整包验证通过；Python 离线 8 项通过。原有完整包 CI 门禁保持不变，仍从固定源码构建两份依赖。
- 最终整包在 rootless iPhone X / iOS 15.6 与 RootHide iPhone 11 / iOS 16.2 的快手 14.10.10 分别通过 3 个独立进程代验证：既有 8 组 Agent 自检，加并发 Inline 安装、15 参数 packed stack、软停转发、QBDI 完整/4 指令预算和保留补丁拒绝；每轮 MCP 边界/关联/复杂 ABI 拒绝回归通过。RootHide 自有 fixture 真实覆盖 PACIBSP/PACIZA/BLRAAZ/RETAB。
- 真实 UI 产生的请求：两台各 15 棵完整同步调用树、225 个配对调用、15 次核心 15 参数正常入口/返回；各 15 个 facade 返回逐字匹配本轮 HTTP `__NS_sig3`。两台各独立离线验证 15 HMAC、45 白盒块、15 CRC，一致；按 schema v2 ID/phase/parent 配对，不按时间猜测。
- 清除 Inline 补丁并重新解析地址后，两台从真实 CRC 输入复制 48B 数据及参数区，各完整回放 2487 条 SDK 指令；返回值与已观察结果和独立 zlib CRC 一致，输入区未改变。RootHide 报 pointerAuthentication:true。该结果是受控纯函数 replay，不是原请求 live 指令跟踪或完整签名现场重建。

研发整包已刷入两台，原 scope 保留；最后重启快手清除所有临时补丁，两台 Hook 数 0、全局采集暂停。未发布 Release / APT。细节与协议边界见 [RootHide 后端](ROOTHIDE_NATIVE_BACKENDS.md)。以下旧版本的“RootHide 无后端”仅为当时状态。

## 2026-11-16：1.28.34 P0 结构化事件、调用关联与 ABI 安全（研发包）

- 增加 schema v2、进程代、Hook/调用 ID、entry/leave、同步父调用和单调时间。参数位置、对象、返回值、内存窗口及采集状态放入 `payload`，镜像 UUID/RVA 随 Hook 身份保存；不再依赖 detail 文本配对。
- 新 `get_call` 返回有界保留的调用树与配对/缺失/截断状态；`query_events` 支持上下文精确过滤。默认密码/网络事件采集同步父 ID，网络响应合并保留请求上下文。journal 保存原始代标识，旧记录保留 schema 1。
- 动态 Hook 配置安装前整体验证、发布后不可变；修改状态/执行目标的工具必须传当前 `process_generation`。方法 post 需要固定非变参声明，C post 需要显式固定 GPR ABI；最多 32 参数、256B Darwin 栈转发。void 不猜返回对象，复杂/变参/异常展开 post 拒绝。
- 方法硬卸载核对 IMP 所有权并保留在途状态，退休槽位不复用；Inline 无线程静止机制时拒绝硬卸载。Import 修复缺失符号失败后仍保留未来镜像注册的风险，永久保存注册名并固定解析后的转发目标；不承诺保留逐镜像 interposer 链，必须用真实命中验证覆盖。关键分配器/runtime Hook 拒绝。
- Mac 原生汇编测试通过：15 参数 packed stack、递归/并发、输出/零长度、实际 C 导入命中、配置拒绝、所有权与在途卸载、跨进程 journal/旧格式兼容；类型/段分析、更新策略、两种完整 deb 构建通过。离线 Python 6 项通过。
- 两台授权手机实际 Agent 自检通过上述 8 组能力；两台 MCP 错误参数/过期代/预算/配对测试及复杂 ABI 拒绝通过，拒绝操作未修改 Hook 配置。重启后各检查 5 条恢复事件，确认旧进程代保留。journal 为有界尾部恢复，早期自检调用已淘汰时如实返回 unknown，不承诺保留所有历史调用。
- 快手 14.10.10 正常 UI 操作：rootless / RootHide 各 15 棵完整同步调用树，分别 225 / 150 个配对调用；各 15 组核心 15 参数方法均有入口和正常 leave，两个 bool 的栈偏移为 0/+1、下一对象为 +8，void 返回不可用；30 组 facade 返回全部逐字匹配本轮真实 HTTP `__NS_sig3`。Rootless 原语额外离线验证 15 HMAC、45 白盒块、15 CRC，全部一致；使用 schema v2 ID/phase/payload 配对，没有按线程和时间猜测。
- RootHide 仍无 Inline/QBDI，未把 rootless 原语验证外推为其能力。关联范围是已启用 post 的同步 Hook，异步因果图、完整 native 图、浮点/聚合 post 和异常展开尚不支持。直接 CLI 自检未证实执行，真机通过结论来自实际注入 Agent 的受控自检和真实请求。

整包已安装两台，保留原 scope；未发布 Release / APT。详细协议和可复用验证入口见 [结构化事件 v2](STRUCTURED_EVENTS_V2.md)。

## 2026-11-16：1.28.33 长函数分页与采集阶段修正（研发包）

- 长函数原受每响应 1024 条指令限制，即使给出 65536B 仍截断；用 `next_address` 再请求又会归一到入口。新增 `byte_offset / next_byte_offset / decode_start`：分页起点与真实函数边界分开报告，常量传播限于当前页；无边界信息时拒绝偏移分页。
- `capture_after` 过去仍在入口读输出区，将未初始化内存当 input。现在入口只标 deferred，返回后才按入口指针读 output；长度参数为 0 时不再退回固定长度。安装响应补充实际 `capture_phase` 和阶段说明；Inline post 明确提示尚不转发栈参数。
- 两台已在 1.28.33 验证：6 项只读 MCP 测试，包括真实 45KB 函数跨过 1024 条限制继续分页、最后一页收敛；3 种不支持 post 的安装请求拒绝且 Hook 配置不变；各 10 组方法命中入口 input 为空、返回 output 为预定 8B。Mac 纯 C、updater 策略和两份完整 deb 构建通过。未发布 Release / APT。
- 常规 48 hex sig3 完成独立输入闭环：1.28.32 的 9 条与 1.28.33 的 13 条新样本，均从真实 `path + sig`、SDK 版本材料、独立环境字段、时钟与计数器进行离线计算，与 facade 返回一致；后 13 条均逐字匹配真实 HTTP 参数。离线脚本不连手机、不调用签名 oracle、不执行 App 原生代码。
- 具体计算路径为 HMAC-SHA256 → PKCS#7 → 16B 独立白盒查表块 → CRC32 → 环境/时间/计数封装与逐字节混淆。白盒查表复现不宣称恢复原 AES 密钥；当前材料来自快手 14.10.10。上游 `sig` 的一条 649B MD5 输入已逐字节复算，但未将其推广为任意 HTTP 请求规范化器；另见过的 64 hex 资源预热变体不在这 22 条验证范围中。
- RootHide 完成真实请求、ObjC 活动链和栈参数验证；内部原语与离线复算证据来自具备 Inline 后端的 rootless，不能据此声称 RootHide 已支持 Inline/QBDI。

## 2026-11-16：1.28.32 栈参数与直接调用者验证（研发包）

两台同一授权测试设备已安装整包并现场核对 1.28.32；保留原注入名单。尚未发布 Release / APT。

- 修正 thunk 报给处理器的原始 SP：304B 栈帧应加 `0x130`，旧值 `0xE0` 指向自己的快照。新增命中时 `caller_lr/caller_sp`，可直接定位被回溯栈漏掉的 SDK 调用点。
- 对已知单 GPR 类型方法，按 Darwin ARM64 的自然大小/对齐采集有界栈快照。两台均观察到 15 参数方法的后 9 参：两个 bool 在 SP+0/+1，下一对象在 +8；不把每个 bool 错当成 8B。
- 现有 post 路径不转发调用者栈参数。现在含栈参数或复杂输入 ABI 的 ObjC 方法若请求 `capture_return/capture_after/capture_ret_multi`，安装前明确拒绝；核心 setter 也拒绝启用。未知 C 签名不具有自动 ABI 安全保证，尤其不能对变参函数盲目开 post。
- Mac 24 个类型判定 + 10 个 Darwin 大小/对齐场景、10 个 Mach-O 场景、updater 策略与两份完整 deb 构建通过；两台各通过既有 5 项 MCP 回归及 3 种 post 拒绝/Hook 列表不变检查。首次 selector 测试误用了没有直接引用的 fixture，改用已确认存在的 `setOutput:`；没有放宽断言。
- 1.28.31 提交 `6ec2138` 的 [完整包 CI](https://github.com/decrypthub/IOSDecryptHub/actions/runs/43817252098) 已通过，含重新构建 Dobby/QBDI。

分析验证：rootless 对真实命中捕获的 HMAC-SHA256 输入/输出完成 7 组离线逐字节复算；提取有界查表数据后，21 个白盒块离线一致；7 组分块输出→CRC→24B 签名封装一致。该结果限于当前版本观察到的常规 48 hex 路径；64 hex 资源预热变体、上游请求规范化以及部分环境字段的独立取值验证仍在继续。白盒表驱动复现不等于恢复了原始 AES 密钥。原始数据、表和复算脚本只保存在本机任务目录，不提交公开仓。

## 2026-11-16：1.28.31 双设备协议分析验证（研发包）

按用户授权，在 rootless iPhone X / iOS 15.6 与 RootHide iPhone 11 / iOS 16.2 的快手 14.10.10 上测试；只重启该目标，保留原注入名单。两台运行中 Agent 均已核对为 1.28.31。未发布 Release / APT。

本轮修复：

- ARM64 `TBZ/TBNZ` 的结构化 `target` 原来取到位编号 0/13；现取最后一个立即数，保留寄存器间接跳转的未知目标语义。
- ObjC 方法查询先用 C 字符串过滤 selector，仅对返回页解析类名/符号。rootless 首次全局 selector 查询从实测 40.802s 降到 10.382s；这是一轮设备观察，不作为稳定延迟承诺。
- 能力握手列出实际动态 Hook 和编译后端：rootless 报 Dobby/QBDI，RootHide 当前切片明确 unavailable。
- ObjC Hook 按真实方法声明限定参数：原始 x2–x8 单列；仅声明中的 x2–x7 参数可标作 arg；仅对象类型可作对象描述。浮点/聚合/未知签名不猜参数位置，超出寄存器范围的参数明确未观测。安装时计算元数据，命中线程不查询方法类型。
- Mach-O 分析按段权限与节名识别自定义代码/字符串段，修复仅认标准段名导致的函数边界、selector/string xref 漏查。镜像图返回分离的 `executable_ranges`，地址归属不把段间 DATA/空洞视为代码。

验证：

- Mac `make test-updater` 与 rootless / RootHide 完整 `make deb` 通过；新增纯 C 测试：24 个参数类型、10 个自定义 Mach-O 节/权限/边界场景。
- 两台分别通过 5 项只读 MCP 测试，覆盖 12 类分支机器码、ObjC 查询分页/匹配、实际后端、真实自定义段方法起点与 selector 交叉引用。`symbolicate` 起点为 high；`disassemble_function` 按既有协议将下一入口近似出的函数尾部标 medium，不能混为一个置信度。
- 真机 66 / 45 条新格式方法入口记录检查，未再出现越过真实声明参数数的 arg 标签；15 参数的核心调用明确报告 9 个栈参数未观测。
- 现有离线 Python 用例 6 passed / 29 subtests；设备测试在未显式提供 endpoint 时跳过。

分析进度：两台均抓到 `__NS_sig3` 请求；常规接口观察到 48 hex，资源预热接口另有 64 hex。多条真实请求与签名返回值逐字匹配，活动链已验证到 `KSSignatureDataEncryptor` → `KWSecurity` → `DefaultMatrixImplementation` → `KWSecuritySignature.atlasSignPlus` → `KWOpenSecureSignatureComponent` → 核心 command `0x28b2`。SDK 中存在但零命中的旧分支不作为执行证据。原始请求、标识、密钥候选和捕获数据只保存在本机任务目录，不提交。

尚未完成：安全 SDK 内部各密码原语和纯算法的逐字节闭环；不能把捕获到 facade 返回值当作纯算法还原。QBDI 目前仍是显式 replay，不能用过期对象指针冒充正常请求的 live trace；RootHide 没有 QBDI 后端。本轮未对未知栈参数函数开启返回拦截。

## 2026-11-16：越狱主线归并原公开仓

- 用户决定由 `decrypthub/IOSDecryptHub` 继续研发越狱版，巨魔版保留独立 `IOSDecryptHubTrollStore`；旧 IOSDecryptHubJB 已在迁移核验后删除。用户明确接受旧安装版 Manager 历史版本列表失效，APT 整包更新继续使用原源。
- 原公开主线 `a94a396` 已包含在 JB 开发主线 `ef62acb` 历史中；按祖先关系推进，保留原提交、标签、Star 与 Issues，不重写历史。
- 原 JB 远端 v1.27.6 标签及两份完整 deb 迁至本仓；保留各自 SHA-256 和原发布源码提交。保留旧版 `latest` 指向，不把只有完整 deb 的迁移 Release 推给旧单引擎更新器。
- main 的 1.28.28 源码和此前本地开发提交一并保留；本次不发布 1.28.x 安装包、不更新 APT 索引、不操作手机。
- 官网、源码反馈入口与 Manager 历史版本 API 改指本仓；历史文档继续保留当时仓名，当前归属以本节与 [整合说明](./REPOSITORY_CONSOLIDATION_2026-11-16.md) 为准。
- 用户授权补齐 CI 依赖：先构建 Dobby/QBDI 静态库，再运行原有更新策略与完整包检查；修正 QBDI Config.h 应取 `include-static/QBDI/Config.h` 的旧脚本错误。
- [CI 43802304063](https://github.com/decrypthub/IOSDecryptHub/actions/runs/43802304063) 在 `4e59e48` 全部通过，实际生成并上传 1.28.28 rootless / RootHide 两份验证包。它们仅为 CI 测试产物，未发布 Release、未更新 APT、未安装手机，不代表本轮完成真机验收。

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

### 修掉的三个真 bug
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
## 2026-11-13 深夜：复审发现的 blocker（已修，真机验证）

`objc_call` 的 `{"$intptr":N}` 在 ARC 下 **100% 崩宿主**：`argv[]` 默认是 `__strong`，
把栈上 `int` 的地址当 `id` 赋值会触发 `objc_storeStrong` → retain 读 isa → SIGSEGV，
崩在赋值语句本身，根本走不到方法调用。改成 `__unsafe_unretained` 后真机验证通过
（传 `{"$intptr":0}` 正常返回 jdgs JSON，`out_params` 回读到 `arg1_int=0`）。
教训：把「不是对象的指针」伪装成 `id` 传参，在 ARC 下是崩溃而不是警告。

`capture_after` 原先从**返回后**的寄存器快照取 `ptr_arg`，而 x0 此时已被返回值覆盖：
`ptr_arg=0` 时读到 0 → 恒失效；函数返回指针时会把返回值当出参缓冲，抓到完全无关的
内存并当成证据上报（假数据比失败更难发现）。现在 trampoline 在 `blr` 之前把入口
`x0..x8` 另存到 `[sp,#0xE0]`，post handler 用它取 ptr/len。

顺带修的：
- `hook_import` 重复符号改由 core 返回 `-(slot+10)` 精确带出槽位（原来 MCP 层用
  `strncmp` 前缀匹配，查 `CCHmac` 会命中 `CCHmacInit` 的槽位，静默改错 hook）
- 删掉 `hook_method` 里对 Swift 类恒无效的第三级兜底（扫元类继承链 == 重实现
  `class_getInstanceMethod`，找不到任何新东西）
- `capture_after` 缺 `capture_memory` 时直接报错（原为悬空语义、静默无效），
  且 MCP 层把 `capture_memory` 提到 `capture_after` 之前设置
- `capture_multi` 语法非法时返回错误，不再静默降级
- `objc_call` 参数上限 8 → 6（switch 只实现到 6）
## 2026-11-13 深夜：第二轮复审（capture_multi）的 blocker

`hook_import` 的**首次安装**路径只声明了 `capMulti`，从没调用 `dh_thunk_set_capture_multi`，
但回包照样显示 `capture_multi` —— 用户以为配好了，slot 里其实还是空串，handler 永远不进
多窗口分支，一条 `win` 都产不出来。`hook_import` 是抓静态加密库 key 的主力路径，
这条**假成功**会让分析员基于「没有 win 输出」得出错误结论。

同轮修掉的：
- `%@` 传 `char[96]` 是未定义行为（`clang -Wformat` 会报），改 `%s`。触发条件是所有窗口
  都读失败，排查期很常见，原来会崩在宿主 App 的 hook 线程上。
- 三处 `capMulti = nil` 改为返回错误；复用分支补 `capture_multi` 回显。
- `dh_thunk_list` 回填 `capture_multi`，`list_hooks` 输出它 —— 否则用户没有任何事后
  自查手段，这也是上面假成功能漏过去的原因。
- 新增 `dh_thunk_abort_install`：参数校验失败时回收槽位。原来只 `disable`，槽位会以
  「名字是旧 label、配置是新参数」的混合状态留在表里。
- `capture_multi` 写入端加 shadow + 原子 `ready` 标志：它是普通 `char[96]` 不是 `_Atomic`，
  MCP 线程写、hook 线程读，无锁会读到写了一半的混合串并抓错寄存器。
- 多窗口 hex 改查表 + `stringWithCharacters` 一次成串：逐字节 `appendFormat` 在热函数上
  是几万次格式化调用，会把命中耗时拉到毫秒级、改变目标时序。

验收（iPhone X 真机）：非法规格 `x9:64` 明确报错且不留槽位；合法 `x3:32,x5:64` 回显一致、
`list_hooks` 可见；触发后事件里有完整 `win x3 = HELLO` 与 `win x5 = 配置对象`。
## 2026-11-13 深夜：第三轮复审（abort_install）的 blocker

`dh_thunk_abort_install` 回收槽位时只清了槽位表，**没撤销目标上的跳转/IMP/GOT**，
还把 `g_next_slot` 回退让索引立刻被复用：
- import：GOT 仍指向 `thunk[slot]`，而 `install_import` 会先把 `g_dh_thunk_orig[slot]`
  置 NULL，窗口内旧符号一被调用就是 `br NULL` → SIGSEGV
- inline：`used=0` 让 `dh_thunk_uninstall` 永远拒绝该槽，补丁永久不可卸载
- method：IMP 仍是 thunk，`used=0` 使复用检测失效，重新 hook 同 selector 会把
  当前 IMP(=thunk) 记成 orig → 无限递归

**打错一个参数就能触发进程级内存安全事件。**

改成「校验前置」：新增纯函数 `dh_thunk_validate_capture_multi`，在分配槽位**之前**
先校验，不过就根本不装。`abort_install` 整个删掉 —— 不需要撤销，就没有漏撤销。

同轮修：
- 复用分支失败时不再 `dh_thunk_disable`（原来会把原本正常的 hook 永久停掉，
  且没有任何一处把 `enabled` 置回 1，最终还 `return ok`）
- `capture_multi` 的 `ready` 改 seqlock 语义（1=可读, 2=写作中），读取端前后各读一次；
  删掉没有并发保护价值的 shadow 字段
- `'\\0'` 是两个反斜杠的多字符常量（值 0x5C30 截断成 `'0'`），会把 `"x0:64"` 清成
  `"00:64"`（仍是合法规格）；改成 `0`
- `install_method` 补齐 capture 配置初始化
- `dh_thunk_list` 回填 `capture_multi` 时先看 `ready`
- 超长（>=96B）与语法错分开报错

真机验收（1.28.23）：`"x9:64"` 在分配前被拒且不留槽位；20 段规格报「过长 119 字节,
上限 95」；`"x3:32,x5:64"` 回显一致且 `list_hooks` 可见；触发后事件有完整 `win x3`/`win x5`。

### 一个工具坑
用 PowerShell 批量改代码时，双引号字符串里的 `` `r`n `` 在某些拼接上下文不会展开，
会把整段多行代码压成**一行字面量**（本次因此让 `dh_thunk_list` 的回填逻辑变成一句
无效注释，`list_hooks` 显示空串）。改完必须回读目标行确认，别只看写入成功。
