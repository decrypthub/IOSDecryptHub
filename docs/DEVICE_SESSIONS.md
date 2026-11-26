# 设备会话与按 App 记录

本文描述当前越狱主线。2026-11-25 起，设备数据以 `idhjd` 为真源，记录按「设备 → App」连续归档；早期按单场会话淘汰、Bearer 配对凭证和 `read_session_events` 的实现已经被取代，不要再按旧文档恢复。

## 组件分工

- `idhjd`：手机常驻设备服务，固定使用 `8088`，负责设备健康、已安装应用、注入范围、App 事件存储、事件分页、按 App 清理、进程 MCP 转发和进程 HTTP 工具代理。
- Agent：注入目标进程后按进程代向 `idhjd` 登记；会话模式开启且 bundle 在注入范围内时才提交事件。
- Manager：查看设备状态和应用列表，管理注入范围，必要时重启目标 App 使新范围生效。
- 电脑 `idh`：通过 USB 或明确配置的地址连接同一台 `idhjd`；电脑面板只是客户端，不另采数据。
- 进程内原工具服务：rootless / RootHide 的 Agent 同时保留原来的文件、符号、Dump 和诊断 HTTP/MCP 服务。`8088` 让给设备服务，进程内服务从 `8089` 开始向 `8108` 扫端口；dev / 巨魔变体仍从 `8088` 开始。

## 连接信任边界

当前采用用户确认的 Frida 式传输信任：设备 HTTP 服务不再使用自定义 Bearer / pairing token。默认只绑 `127.0.0.1`；创建状态目录里的 `listen-remote` 标记后才监听局域网，等同显式接受同网段直连。打开局域网前应按 Frida server 的同一口径理解风险，电脑端优先使用 USB / usbmuxd 或受控转发。

进程内原工具服务（`8089..8108`）跟随同一份标记与同一默认值：越狱包默认也只绑回环，端口不再对同网段开放。它与 `idhjd` 是各自独立绑定，标记在启动时读一次，加删标记后重启目标 App（`idhjd` 则重启服务）才生效。巨魔版没有守护进程，端口就是产品入口，仍监听局域网，也没有下面的 `listen` 字段。

模板标记的命令（越狱版）：

```sh
# 放开：touch 标记后重启目标 App（idhjd 需重启服务）
touch /private/var/db/idhjd-v1/listen-remote
# 收回
rm -f /private/var/db/idhjd-v1/listen-remote
```

RootHide 上 `/private/var/db/idhjd-v1` 在根 shell 里是另一个视图：实测在真实 `/private/var/db` 下建标记不生效，要建在 `idhjd` 自己的 state 目录里（本机为 `/var/containers/Bundle/Application/.jbroot-*/rootfs/private/var/db/idhjd-v1/listen-remote`）。验收用的是无沙箱测试宿主，沙箱内的真实 App 是否读得到该路径尚未验证。

默认收紧后，PC 侧继续看进程内面板的三条路：设备本机浏览器开 `127.0.0.1:<端口>`；`ssh -L 8089:127.0.0.1:8089 root@<设备>` 转到本机；或建上面那个标记。`idhjd` 的 `/api/apps/<bundle>/tools/...` 只代理文件、符号、Dump，不代理面板 HTML 与 `/api/logs`。

`/api/stats` 与 MCP `get_stats` 带 `port` 与 `listen`（`loopback` / `any`）：`port=0` 才代表服务没起来，`listen` 只表示绑定策略。

`GET /health` 和面板外壳保持免鉴权。`Origin` 检查只是浏览器 CSRF 防护，不是认证。不要把「页面能打开」当作设备已授权，也不要把旧文档里的 `IDH_DEVICE_SESSION_TOKEN`、`IDH_DEVICE_SETTINGS_TOKEN` 或 `pair_process` 当成当前协议。

## HTTP / MCP 能力

设备服务的主要 HTTP 路由：

| 路由 | 用途 |
|---|---|
| `GET /health` | 设备服务与已登记进程概览 |
| `GET /api/apps` | 已安装应用、运行状态和注入范围摘要 |
| `GET /api/apps/<bundle>/events` | 按 App 读取事件，可用 `after` / `before` / `limit` 分页 |
| `GET /api/apps/<bundle>/icon` | 应用真实图标 PNG |
| `GET/POST /api/apps/<bundle>/tools/<工具路径>` | 经 `idhjd` 访问该 App 在线进程的原版文件、符号和 Dump HTTP 接口 |
| `GET /api/injection-scope` | 读取 loader 注入范围 |
| `POST /api/injection-scope` | 增加或移除 bundle；下次启动目标 App 生效 |
| `POST /api/apps/relaunch` | 结束并重新打开目标 App |
| `POST /api/apps/clear` | 真正删除该 App 在设备上的事件记录 |
| `POST /api/mcp` | 同一能力的 MCP 入口 |

MCP 工具包括 `list_installed_apps`、`read_app_events`、`clear_app_events`、`get_injection_scope`、`set_injection_scope`、`relaunch_app` 和 `get_process_identity`。`read_app_events` 不传游标时读最新一页；`after` 用于增量轮询，`before` 用于向历史翻页，`limit` 最大 500。电脑端对会改变设备状态的工具必须保留显式确认门。

进程工具代理的路径形状是 `/api/apps/<bundle>/tools/<工具路径>`；其中 `<工具路径>` 对应进程内 `/api/<工具路径>`。当前只放行原版文件、符号和 Dump：`files`、`files/preview`、`files/download`、`symbols`、`symbols/images`、`dump/images`、`dump/status`、`dump/download`、`dump/image`，以及 `POST dump`。代理按 bundle 选择唯一在线进程；多进程同包名时明确失败，不用第一个进程猜测。二进制下载经代理流式转发，不把 IPA 或文件整体读入 `idhjd` 内存。

## 事件存储

事件不再按一次性 session 淘汰。`idhjd` 在 SQLite 中按 `bundle_id` 写入 `app_events`，并维护 `app_stats` 汇总；同一 App 跨重启和跨进程代保持连续时间线。事件摘要可携带算法、操作、详情、输入输出长度和前缀字节；没有原始字节时不能补造。

按 App 清理是真实删除，不是「清空显示」。需要删除前应让用户确认范围。设备端存储配额按 App 裁剪最旧记录，裁剪丢失和读取分页是两件事。

## 注入范围与重启

Loader 的权威注入范围是 prefs plist；jb config 只是尽力写入的镜像。RootHide 用户域写不进 root 属主镜像时，只要权威 prefs 写入成功，就不能报 `config_write_failed`。bundle ID 必须合法，`com.apple.*` 拒绝写入。

修改注入范围不会自动结束运行中的目标 App。运行中的进程保持原状态；用户明确选择重启后，下一代进程才按新范围注入。

## 验收状态

进程工具代理（`/api/apps/<bundle>/tools/...`）与 App 重启已于 2026-11-25 完成 rootless / RootHide 双端真机验收：文件浏览/下载、符号、Dump（bin 与 ipa）经代理全链路通过，relaunch 双端如实上报（RootHide 走 `uiopen`，rootless 走 jb 直启兜底）。验收细节见 `PROGRESS.md` 2026-11-25 段。

按 App 连续归档、注入范围、USB 接入和电脑 Vue 面板本身的端到端双端验收仍待补；旧的 2026-11-21/22 双机证据属于已取代的 session/token 中间实现，只能说明当时设备接管、进程诊断转发、历史摘要读取和限额写入曾经走通过，不能当作当前架构的验收结论。
