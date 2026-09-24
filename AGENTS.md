# AGENTS.md — IOSDecryptHub

Always respond in Chinese-simplified

本仓含两部分：**引擎**（`src/`，源码在本仓，由 `make` 编译）与**越狱注入链路**（`src/loader.m` 加载器、`app/` 管理器 App、`daemon/` updater）。

ElleKit 把 `IOSDecryptHubLoader.dylib` 装进 UIKit App 后：读 `enabledBundles.plist` → 允许则 `dlopen` 引擎 `decrypt_helper.dylib`（由本仓 `src/` 编译后落在 `vendor/dylib/`）。

**加载器与 updater daemon 不得加入 hook、inline hook，也不得改成常驻型 daemon。** hook 全部在引擎里（`src/hooks/`），由引擎的 constructor 完成。

```bash
make deb
```

- ❌ 加载器 / daemon 里出现 `MSHookFunction` / `%hook`
- ❌ 常驻 daemon / `dh_server`
- ✅ updater daemon（一次性：launchd 按需拉起，跑完即退；只做更新检查/安装/回滚，不 hook、不常驻、不监听端口）
- ✅ 版本号：`Makefile` 的 `VERSION`
