# IOSDecryptHub · Jailbreak edition

An independent jailbreak runtime-analysis project for rootless / RootHide iOS devices. The product is one complete deb containing a persistent daemon, a phone Manager app, an injection loader and the Agent, updated together through an APT repository.

The [TrollStore edition](https://github.com/decrypthub/IOSDecryptHubTrollStore) is a separate project. Each project maintains its own main branch, versions and releases.

This is the canonical jailbreak repository under the decrypthub organization. On 2026-11-16, development from IOSDecryptHubJB was consolidated here while retaining the original repository's history, stars, issues, tags and releases. See the [consolidation notes](./docs/REPOSITORY_CONSOLIDATION_2026-11-16.md).

The Manager enables or disables injection per app and shows both saved policy and the actual running state. The daemon continues without the Manager UI; the target app follows its ordinary lifecycle. The phone owns storage, bounded analysis, web and MCP services. A PC is optional.

The injected dylib remains an internal build artifact. Users do not download, compile, select or update it separately. Package managers such as Sileo / Zebra perform complete-package updates.

**Source and released packages have different versions.** Main contains 1.28.28 development code, including Inline Hook, QBDI Trace and runtime-operation work; see [Progress](./docs/PROGRESS.md) for validation and limitations. This repository consolidation does not publish a new 1.28.x package. The persistent analysis service, Manager redesign and scope architecture remain roadmap items.

The existing [v1.27.6 complete packages](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.27.6) have moved here with identical bytes. The website and APT source remain [ios.decrypthub.com](https://ios.decrypthub.com/), with the same package ID and signing trust. Older releases remain available. Submit jailbreak issues to [this repository](https://github.com/decrypthub/IOSDecryptHub/issues).

For a fresh macOS checkout, prepare the iOS analysis libraries before building complete packages (Xcode and network access are required):

```bash
brew install dpkg ldid cmake ninja
bash tools/build_dobby_ios.sh
bash tools/build_qbdi_ios.sh
make test-updater
make deb
```

The static libraries are generated locally and are not tracked in Git. QBDI also builds LLVM, so its first build can take a while. CI uses the same dependency preparation and retains the complete rootless/RootHide package checks. Architecture limitations are documented under `vendor/`.

Design documents:

- [Product architecture and delivery](./docs/PRODUCT_ARCHITECTURE.md)
- [Manager UI](./docs/MANAGER_UI.md)
- [Hook and Trace](./docs/HOOK_AND_TRACE_DESIGN.md)
- [Progress](./docs/PROGRESS.md)

[MIT license](./LICENSE); third-party notices: [NOTICE](./NOTICE).
