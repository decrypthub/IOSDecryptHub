# IOSDecryptHub 仓库整合（2026-11-16）

用户决定将越狱版开发集中回已有关注度的原公开仓，巨魔版继续独立维护。

| 维护入口 | 负责范围 |
| --- | --- |
| [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub) | 越狱源码、完整 deb、问题反馈与后续研发 |
| [IOSDecryptHubTrollStore](https://github.com/decrypthub/IOSDecryptHubTrollStore) | 巨魔版源码、dylib 与发布 |
| [IOSDecryptHubPage](https://github.com/decrypthub/IOSDecryptHubPage) | 官网与已有 APT 分发 |

原 IOSDecryptHubJB 在代码、标签和 Release 迁移核验后删除；项目不再要求并列存在这个仓库。删除旧仓会使其 GitHub URL 失效，维护中的入口统一更新到上表，不承诺外部历史链接自动重定向。

## 历史与版本

- 原 IOSDecryptHub 的 `a94a3967381459ee1629cc3df450ca4529364f9f` 是 JB 开发主线 `ef62acba2cc7ed1364ff92dc10fc636974ac3f63` 的祖先。新主线保留两边历史，不强推、不覆盖既有标签。
- 原 JB 远端只有 main 和 v1.27.6 标签；迁移时没有 Star、Fork、Issue 或 PR。
- v1.27.6 标签仍对应 `8d256f2b0a00a340c65f283bebea1ec8a81b2518`，迁移两份既有 deb，不重新编译、不修改包内容。
- main 保留 1.28.28 开发代码。迁仓不等于发布新的安装包，功能验证范围和未完成项看 [PROGRESS.md](./PROGRESS.md)。

| v1.27.6 资产 | SHA-256 |
| --- | --- |
| `com.iosdecrypthub_1.27.6_rootless.deb` | `e5fe6b7de7cba56586409579bee4c414b4f6cc641177c65810da8304a665ed55` |
| `com.iosdecrypthub_1.27.6_roothide.deb` | `35bf9ac6a9a793630fb6f4c67e175b9757e466fc63e5c320444ca5f91a1fe907` |

## 兼容与后续发布

官网域名 `https://ios.decrypthub.com`、包 ID `com.iosdecrypthub`、APT 索引和原签名公钥保持兼容。本次只修改站点的项目入口，不更新设备或 APT 包。

旧单引擎更新器依赖原仓的 `releases/latest` 和 dylib 资产。迁入 v1.27.6 完整包时设置 `make_latest=false`，保留原先 v1.27.5 的 latest 指向；越狱安装使用对应版本 Release 或现有 APT 源。以后改变 latest 必须先核对旧更新器及资产兼容性。

新的源码中，Manager 版本列表 API、Web 面板反馈链接和 Issue 模板均使用本仓。已安装的历史二进制不会随源码迁移自动改写；若其版本历史列表仍访问旧 JB 地址，删除旧仓后该列表可能不可用，整包更新仍以原有 APT 源为准。

本机 Windows 无 iOS 原生构建工具链，仓库迁移中的静态检查与主机测试不等于新的 iOS 构建或真机验收；完整包发布仍执行原有架构、签名、依赖、安装与升级验证。
