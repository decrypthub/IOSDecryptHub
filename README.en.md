# IOSDecryptHub

Add the repo in Sileo / Zebra:

```
https://ios.decrypthub.com
```

Install the deb for your jailbreak (rootless or roothide). Open **Settings → IOSDecryptHub**, enable the target app, force-quit it, then reopen. Open `http://<device-ip>:8088` in a browser.

No app is injected by default. Depends on ellekit and preferenceloader.

Build debs (macOS + Xcode + dpkg + ldid):

```bash
make deb
```
