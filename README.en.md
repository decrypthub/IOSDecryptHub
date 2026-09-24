# IOSDecryptHub

[中文](README.md) | **English**

IOSDecryptHub is a runtime analysis dylib injected into an iOS app process. It captures crypto, file, network, Keychain and dynamic-loading behaviour, and adds a web panel, FairPlay unpacking and MCP analysis.

**This is the full source repository**: the engine dylib, the jailbreak loader, the manager app, the updater daemon and the packaging scripts all live here, and you can build and modify them yourself.

Website and demos: [ios.decrypthub.com](https://ios.decrypthub.com/)

## Capabilities

- Hooks system crypto APIs and records **algorithm / key / IV / plaintext / ciphertext / call stack** (digest, HMAC, symmetric, asymmetric, KDF, OpenSSL EVP)
- Observes file, network, Keychain and dynamic-loading behaviour
- Browser web panel (live event stream with detail view) plus an on-device floating window showing stats and the panel address
- FairPlay memory unpacking
- Built-in MCP server (Streamable HTTP, reusing port 8088); pair it with the [`idh`](https://github.com/decrypthub/idh-cli) gateway to drive it from AI clients

## Getting the dylib

Download from the [homepage](https://ios.decrypthub.com/) or [GitHub Releases](https://github.com/decrypthub/IOSDecryptHub/releases), or build it yourself:

```bash
make VARIANT=trollstore
```

The product lands in the repository root as `decrypt_helper.dylib`.

> **Mind the variant**: the dylib asset in our Releases is built with `VARIANT=trollstore`. A bare `make` produces the `dev` variant — same capabilities, different self-reported variant name. See [Build variants](#build-variants).

## Usage

All three injection paths share **one core engine**. The only difference is who puts the dylib into the target app process.

### Path 1: TrollStore injector (recommended)

For devices that already have TrollStore and a compatible injector installed:

1. Select the target app in the injector.
2. Add `decrypt_helper.dylib` and run the injection.
3. Fully quit and relaunch the target app.
4. Get the panel address from the floating window or the log, then open `http://<device-ip>:8088` in a browser on the same LAN.

Injector UIs differ slightly; the core step is always injecting the dylib and restarting the app.

### Path 2: IPA repack

Install `insert_dylib` on macOS first:

```bash
brew install insert_dylib
```

Then run the bundled script:

```bash
./scripts/inject.sh <input.ipa> decrypt_helper.dylib
```

It produces `hooked_<input>.ipa`. Install/re-sign it with TrollStore, Sideloadly or AltStore, launch the app, then open `http://<device-ip>:8088`.

### Path 3: Jailbreak package repository

Add the repo in Sileo / Zebra:

```
https://ios.decrypthub.com
```

Install the package matching your environment (the two packages target different architectures and must not be mixed):

- rootless (Dopamine, palera1n): the `com.iosdecrypthub` rootless package
- roothide: the `com.iosdecrypthub` roothide package

An **IOSDecryptHub** icon then appears on the home screen: toggle target apps, check for updates and pick a version there. Force-quit a target app before opening it. No app is injected by default. Depends on ellekit.

<p align="center">
  <img src="./docs/screenshots/webui.png" alt="IOSDecryptHub web panel: crypto event list with UTF-8 / HEX / HEXDUMP detail" width="920">
</p>

### PC side: idh gateway

Install `idh` on your computer and connect to the device manually (get the IP from the app panel or the floating window):

```bash
pip install ios-decrypt-hub
idh connect <device-ip>:8088
idh mcp
```

`idh mcp` bridges the on-device HTTP MCP to a local stdio MCP you can wire into Codex, Claude and other clients. `connect` saves the device as a persistent connection, so later `devices` / `watch` / `open` / `mcp` calls just work; you can also pass `--endpoint http://<device-ip>:8088` ad hoc.

## Build variants

One source tree produces four variants. They differ only in the compile-time `-DDH_VARIANT` number (see `src/core/dh_capability.c`). That number currently only affects the `variant` field the MCP `get_capabilities` handshake reports — **capability bits do not change between variants**.

| Variant | Command | Arch | Purpose |
|---------|---------|------|---------|
| `dev` (default) | `make` | arm64 | Manual injection / `DYLD_INSERT_LIBRARIES` / local debugging |
| `trollstore` | `make VARIANT=trollstore` | arm64 | TrollStore injector — **the dylib asset in our Releases** |
| `rootless` | `make VARIANT=rootless` | arm64 | **engine inside the rootless deb** |
| `roothide` | `make VARIANT=roothide` | arm64 + arm64e | **engine inside the roothide deb** (fat slice) |

### Other build targets

```bash
make dist              # versioned decrypt_helper-<version>.dylib (for releases)
make mac               # macOS dylib for local grey-box testing
make sim               # iOS Simulator dylib
make linux             # Linux/WSL cross-compile (set IOS_SDK and CROSS_CC)
```

## Building the jailbreak debs from source

```bash
make deb              # build both rootless and roothide
make deb-rootless     # rootless only (arm64)
make deb-roothide     # roothide only (arm64 + arm64e)
```

Products land in `build/deb/`. Install the package matching your environment; on roothide a plain rootless package fails to load because of the `arm64` / `arm64e` mismatch.

`make deb` compiles the engine first and stages it into `vendor/dylib/<variant>/`, then calls `build_deb.sh` to package. Requires macOS + Xcode (`xcrun`) + `dpkg-deb` + `ldid`.

Simulated regression test for the update path (runs on macOS, no device needed, needs network):

```bash
make test-updater
```

## Repository layout

```
src/
  core/        Core: fishhook, capability bits, unpacking, symbol redirection, log store
  hooks/       Per-API hooks (crypto/ algorithms, behavior/ file, network, Keychain, dyld)
  server/      HTTP server and MCP server (web panel assets are embedded at build time)
  ui/          On-device floating window
  loader.m     Jailbreak injection loader (reads the enabled list, dlopens the engine; no hooks)
  dh_shared.h  Definitions shared by the loader and the engine
  core/capstone/  Third-party disassembly engine (BSD-3)
web/           Web panel UI (converted to a header by tools/gen_web.py and embedded in the dylib)
tools/         gen_web.py (web assets to header), patch_info_plist.py (used by IPA repack)
app/           Jailbreak manager app (home-screen icon: toggle apps, check updates, roll back)
daemon/        Updater daemon (launched on demand by launchd; checks, downloads, installs, rolls back)
repo/          Sileo repo public key (installed into the device APT trust chain, or index updates fail)
vendor/dylib/  Staging directory for the engine used by packaging (built by make deb / make test-updater, not tracked)
build_deb.sh   Jailbreak deb packaging script
```

## What's inside (jailbreak deb)

| Component | Role |
|-----------|------|
| Injection loader | Reads the enabled list, `dlopen`s the engine only on a hit; contains no hooks |
| Engine dylib | The runtime analysis engine — source in `src/`; every hook lives in its constructor |
| Manager app | Home-screen icon: toggle apps, see engine version and update state, update / roll back |
| Updater daemon | One-shot process (launched on demand by launchd) that checks, downloads, installs and rolls back the engine |

## How updates work

Tap "Check for updates" in the manager app; it writes a request and launchd runs the daemon:

1. Resolve the latest version (reads the 302 of GitHub `releases/latest` first — no API quota; the API is only a fallback)
2. Download the engine, verify size and Mach-O architecture (arm64 family only); anything else is discarded
3. **Back up first** — a failed replace is restored from the backup, and no replace happens without a successful backup
4. After the atomic swap, running target apps are terminated, so the next launch uses the new engine
5. Rollback is a swap: it rolls back, keeps the version it just rolled off, and can roll again

No reinstall and no respring needed.

## Notes

- The web and MCP servers listen on `0.0.0.0:8088` with **no authentication** — use them only on trusted networks.
- Injection, re-signing and unpacking depend on the device environment and the target app's protections.
- Never post captured keys, passphrases, plaintext or other sensitive data in a public issue.

Open an issue at [GitHub Issues](https://github.com/decrypthub/IOSDecryptHub/issues).

## Follow

Search **DecryptHub** in WeChat, or scan the QR below.

<p align="center">
  <img src="./wechat-qr.png" alt="WeChat Official Account DecryptHub" width="168">
</p>

- Telegram: https://t.me/decrypthubteam
- X: https://x.com/decrypthub_

## License

[MIT](./LICENSE)

Bundles [fishhook](https://github.com/facebook/fishhook) and [Capstone](https://www.capstone-engine.org/) (both BSD-3-Clause); see [NOTICE](./NOTICE).
