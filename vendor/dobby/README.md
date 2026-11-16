# Dobby — iOS arm64 / arm64e static builds

用于越狱版 `hook_inline` 的内联 hook 后端。

| 项 | 值 |
|---|---|
| 上游 | https://github.com/jmpews/Dobby |
| 版本 | commit `5dfc854`（2026-11-13 拉取） |
| 构建 | `cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_PROCESSOR=arm64 -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release -DDOBBY_DEBUG=OFF -DDOBBY_BUILD_EXAMPLE=OFF -DDOBBY_BUILD_TEST=OFF` |
| 产物 | `lib/arm64/`、`lib/arm64e/` 独立静态库及 `lib/libdobby.a` universal；`include/dobby.h` |
| 许可 | Apache-2.0（见上游 LICENSE） |

1.28.35 起，脚本固定上游 `5dfc8546954ce3b3198132ab13fddb89ee92cdd7`，分别以
`CMAKE_OSX_ARCHITECTURES=arm64/arm64e` 编译，再用 lipo 合并并校验。
arm64e Dobby 返回带 PAC 的 original；IDH 存入原始分支表前去除认证位，匹配 thunk 的 br/blr。
仓内补丁将 original 的 release 发布移至入口激活之前，thunk acquire 读取并在 arm64e 去 PAC，
覆盖安装期间并发命中的发布窗口；失败后已发布的槽位不复用。
不能通过重标记旧 arm64 文件替代真实 arm64e 构建。

Darwin 补丁通过有界线程暂停/PC 检查保护权限切换和指令写入，失败在恢复线程后返回；代码生成器必须传播写入失败。只覆盖枚举快照，不保证新线程或外部补丁的静止状态。Inline 硬卸载仍拒绝；软停后 patch 保留到目标重启。
设备验证范围见 `docs/PROGRESS.md` 与 `docs/ROOTHIDE_NATIVE_BACKENDS.md`。

1.28.36 增加独立 `DobbyHookWithContext` 扩展及 `dobby-context-entry.patch`：IDH 入口先将原始 x16/x17 压栈，再转入专用 thunk 的 +4 入口；方法/导入槽位自行执行同一次压栈。这个契约只适用于 IDH 公共桥，不能把新扩展指向普通 C replacement。普通 `DobbyHook` 保留上游调用语义。构建脚本每次应用并核验补丁；真实调用、CFI 和 PAC 验证见 `docs/LIVE_CONTEXT_TRACE.md`。

重新构建：`bash ../../tools/build_dobby_ios.sh`。
