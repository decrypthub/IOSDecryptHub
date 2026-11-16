# IOSDecryptHub 仓库整合（2026-11-16）

用户决定将越狱版开发集中回已有关注度的原公开仓，巨魔版继续独立维护。

| 维护入口 | 负责范围 |
| --- | --- |
| [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub) | 越狱源码、完整 deb、问题反馈与后续研发 |
| [IOSDecryptHubTrollStore](https://github.com/decrypthub/IOSDecryptHubTrollStore) | 巨魔版源码、dylib 与发布 |
| [IOSDecryptHubPage](https://github.com/decrypthub/IOSDecryptHubPage) | 官网与已有 APT 分发 |

原 IOSDecryptHubJB 已在代码、标签和 Release 迁移核验后，按用户明确授权删除；项目不再要求并列存在这个仓库。旧 GitHub URL 已失效，维护中的入口统一更新到上表，外部历史链接不会自动重定向。本机迁移前副本和完整 Git bundle 保留备份。

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

新的源码中，Manager 版本列表 API、Web 面板反馈链接和 Issue 模板均使用本仓。已安装的历史二进制不会随源码迁移自动改写；其版本历史列表仍访问旧 JB 地址时会失效。用户已确认接受这一影响，整包更新仍以原有 APT 源为准。

首次迁移的 CI 暴露了新签出源码缺少 Dobby/QBDI 静态库的依赖准备问题。经用户授权，CI 增加依赖构建并修正 QBDI 静态配置头文件路径；[CI 43802304063](https://github.com/decrypthub/IOSDecryptHub/actions/runs/43802304063) 在 `4e59e48` 完整通过，包括更新策略测试、rootless / RootHide 实际整包构建与测试产物上传。1.28.28 两份 CI 产物未作为正式 Release 或 APT 更新发布，本轮未在手机安装验收。完整包正式发布仍执行既有架构、签名、依赖、安装与升级验证。
