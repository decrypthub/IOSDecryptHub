# IOSDecryptHub

**中文** | [English](README.en.md)

IOSDecryptHub 是一个注入到 iOS App 进程中的运行时分析 dylib，可捕获加解密、文件、网络、Keychain 与动态加载行为，并提供 Web 面板、脱壳与 MCP 分析能力。

**本仓是完整源码仓**：引擎 dylib、越狱加载器、管理器 App、updater daemon、打包脚本全部在这里，可自行编译与修改。

官网与效果演示：[ios.decrypthub.com](https://ios.decrypthub.com/)

## 能力

- 拦截系统加密 API，记录**算法 / Key / IV / 明文 / 密文 / 调用栈**（摘要、HMAC、对称、非对称、KDF、OpenSSL EVP）
- 文件、网络、Keychain、动态加载等行为观测
- 浏览器 Web 面板（实时事件流 + 详情），设备端悬浮窗显示统计与面板地址
- FairPlay 内存脱壳
- 内置 MCP 服务器（Streamable HTTP，复用 8088 端口），配合 [`idh`](https://github.com/decrypthub/idh-cli) 网关可直接给 AI 客户端调用

## 获取 dylib

从 [官网首页](https://ios.decrypthub.com/) 或 [GitHub Releases](https://github.com/decrypthub/IOSDecryptHub/releases) 下载，或自行编译：

```bash
make VARIANT=trollstore
```

产物在仓库根目录：`decrypt_helper.dylib`。

> **注意变体**：线上 Release 里的 dylib 资产是用 `VARIANT=trollstore` 编的。直接 `make`（不带参数）编出来的是 `dev` 变体，能力相同，只是自报的变体名不同。详见[编译变体](#编译变体)。

## 使用方法

三条注入路径共享**同一份核心引擎**，区别只在于谁负责把 dylib 放进目标 App 进程。

### 方式一：巨魔注入器（推荐）

适用于已通过 TrollStore 安装注入器的设备：

1. 在注入器中选择目标 App。
2. 添加 `decrypt_helper.dylib` 并执行注入。
3. 完全退出并重新启动目标 App。
4. 从悬浮窗或日志确认面板地址，在同一局域网的浏览器中打开 `http://<设备 IP>:8088`。

不同注入器界面略有差异，核心都是把 dylib 注入目标 App 后重启 App。

### 方式二：IPA 重打包

macOS 先安装 `insert_dylib`：

```bash
brew install insert_dylib
```

执行仓库内置脚本：

```bash
./scripts/inject.sh <input.ipa> decrypt_helper.dylib
```

脚本会生成 `hooked_<input>.ipa`。用 TrollStore、Sideloadly 或 AltStore 安装/重签后启动 App，再访问 `http://<设备 IP>:8088`。

### 方式三：越狱插件源

Sileo / Zebra 添加源：

```
https://ios.decrypthub.com
```

按环境安装（两种包对应不同设备架构，不能混装）：

- rootless（Dopamine、palera1n）：`com.iosdecrypthub` rootless 包
- roothide：`com.iosdecrypthub` roothide 包

装好后桌面上会多一个 **IOSDecryptHub** 图标：在这里开关要注入的 App、检查更新、看历史版本。打开目标 App 前先完全退出，再启动即可注入。默认不注入任何 App。依赖 ellekit。

<p align="center">
  <img src="./docs/screenshots/webui.png" alt="IOSDecryptHub Web 面板：加解密事件列表与输入明文 / HEX / HEXDUMP 详情" width="920">
</p>

### PC 端连接与 MCP 网关

在电脑上安装 `idh`，手动连接设备（设备 IP 从 App 面板或悬浮窗获取）：

```bash
pip install ios-decrypt-hub
idh connect <设备 IP>:8088
idh mcp
```

`idh mcp` 把设备上的 HTTP MCP 桥接为本机 stdio MCP，可作为 Codex、Claude 等客户端的固定 MCP 配置。`connect` 会把设备保存为持久连接，之后 `devices` / `watch` / `open` / `mcp` 直接使用；也可临时用 `--endpoint http://<设备 IP>:8088` 指定。

## 编译变体

一份源码编出四个变体，差别只有编译期的 `-DDH_VARIANT` 编号（见 `src/core/dh_capability.c`）。该编号目前只影响 MCP `get_capabilities` 握手自报的 `variant` 字段，**能力位不随变体改变**。

| 变体 | 命令 | 架构 | 用途 |
|------|------|------|------|
| `dev`（默认） | `make` | arm64 | 开发者手动注入 / `DYLD_INSERT_LIBRARIES` / 本地调试 |
| `trollstore` | `make VARIANT=trollstore` | arm64 | 巨魔注入器 —— **Release 里的 dylib 资产** |
| `rootless` | `make VARIANT=rootless` | arm64 | **rootless deb 包里的引擎** |
| `roothide` | `make VARIANT=roothide` | arm64 + arm64e | **roothide deb 包里的引擎**（胖切片） |

### 其他构建目标

```bash
make dist              # 产出带版本号的 decrypt_helper-<version>.dylib（发 Release 用）
make mac               # macOS 版 dylib，本机灰度测试
make sim               # iOS Simulator 版 dylib
make linux             # Linux/WSL 交叉编译（需设置 IOS_SDK 和 CROSS_CC）
```

## 从源码打越狱 deb

```bash
make deb              # 同时构建 rootless 与 roothide
make deb-rootless     # 仅普通 rootless（arm64）
make deb-roothide     # 仅 roothide（arm64 + arm64e）
```

产物在 `build/deb/`。必须安装与设备环境匹配的包；roothide 环境装普通 rootless 包会因 `arm64` / `arm64e` 不兼容而无法加载。

`make deb` 会自动先编译引擎并落到 `vendor/dylib/<variant>/`，再调用 `build_deb.sh` 打包。前提：macOS + Xcode（`xcrun`）+ `dpkg-deb` + `ldid`。

更新链路的仿真回归测试（macOS 本机即可，不需要真机，需要网络）：

```bash
make test-updater
```

## 仓库结构

```
src/
  core/        核心：fishhook、能力位、脱壳、符号重定向、日志存储
  hooks/       各 API 的 hook（crypto/ 加密算法，behavior/ 文件/网络/Keychain/dyld）
  server/      HTTP 服务与 MCP 服务器（Web 面板资源编译时嵌入）
  ui/          设备端悬浮窗
  loader.m     越狱注入加载器（读启用名单 → dlopen 引擎，不含 hook）
  dh_shared.h  加载器与引擎共享的定义
  core/capstone/  第三方反汇编引擎（BSD-3）
web/           Web 面板界面（编译时由 tools/gen_web.py 转成头文件嵌入 dylib）
tools/         gen_web.py（Web 资源转头文件）、patch_info_plist.py（IPA 重打包用）
app/           越狱版管理器 App（桌面图标：开关应用 / 检查更新 / 版本回滚）
daemon/        updater daemon（launchd 按需拉起，检查 / 下载 / 安装 / 回滚引擎）
repo/          Sileo 源公钥（装进设备 APT 信任链，否则源索引无法更新）
vendor/dylib/  打包用引擎落地目录（由 make deb / make test-updater 编译生成，不入版本库）
build_deb.sh   越狱 deb 打包脚本
```

## 包内组件（越狱 deb）

| 组件 | 作用 |
|------|------|
| 注入加载器 | 读启用名单，命中才 `dlopen` 引擎；不含任何 hook |
| 引擎 dylib | 运行时分析引擎，源码在本仓 `src/`，所有 hook 都在它的 constructor 里 |
| 管理器 App | 桌面图标：开关应用、看引擎版本与更新状态、一键更新 / 回滚 |
| updater daemon | 一次性进程（launchd 按需拉起），负责检查、下载、安装、回滚引擎 |

## 更新机制

管理器 App 里点「检查更新」→ 写入请求 → daemon 被 launchd 拉起执行：

1. 取最新版本号（先读 GitHub `releases/latest` 的 302，不吃 API 配额；失败才退回 API）
2. 下载引擎 → 校验体积与 Mach-O 架构（只认 arm64 家族），不合格直接丢弃
3. **先备份**当前引擎，替换失败立刻用备份恢复；没有备份成功就绝不替换
4. 原子落位后，结束已启用 App 的进程 —— 下次打开就是新引擎
5. 回滚是 swap 语义：滚回去，备份里留着刚滚下来的版本，还能再滚回来

不用卸装重装，也不用 respring。

## 注意事项

- Web 与 MCP 服务默认监听 `0.0.0.0:8088`，且**没有身份认证**，请仅在可信网络中使用。
- 注入、重签和脱壳能力受设备环境及目标 App 保护机制影响。
- 请勿将捕获到的 Key、口令、明文或其他敏感数据提交到公开 Issue。

遇到问题可在 [GitHub Issues](https://github.com/decrypthub/IOSDecryptHub/issues) 反馈。

## 关注

微信搜一搜 **DecryptHub**，点下面二维码也能加公众号。

<p align="center">
  <img src="./wechat-qr.png" alt="微信公众号 DecryptHub" width="168">
</p>

- Telegram：https://t.me/decrypthubteam
- X：https://x.com/decrypthub_

## 协议

[MIT](./LICENSE)

内嵌 [fishhook](https://github.com/facebook/fishhook) 与 [Capstone](https://www.capstone-engine.org/)（均为 BSD-3-Clause），版权声明见 [NOTICE](./NOTICE)。
