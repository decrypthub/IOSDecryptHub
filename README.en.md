# IOSDecryptHub

[中文](README.md) | **English**

Add the repo in Sileo / Zebra:

```
https://ios.decrypthub.com
```

Install the deb for your jailbreak (rootless or roothide). Open **Settings → IOSDecryptHub**, enable the target app, force-quit it, then reopen. Open `http://<device-ip>:8088` in a browser to use the live web panel:

<p align="center">
  <img src="./docs/screenshots/webui.png" alt="IOSDecryptHub web panel: crypto event list with UTF-8 / HEX / HEXDUMP detail" width="920">
</p>

No app is injected by default. Depends on ellekit and preferenceloader.

Build debs (macOS + Xcode + dpkg + ldid):

```bash
make deb
```

## Follow

Search **DecryptHub** in WeChat, or scan the QR below.

<p align="center">
  <img src="./wechat-qr.png" alt="WeChat Official Account DecryptHub" width="168">
</p>

- Telegram: https://t.me/decrypthubteam
- X: https://x.com/decrypthub_
