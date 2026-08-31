# IOSDecryptHub

Sileo / Zebra 添加源：

```
https://ios.decrypthub.com
```

按环境安装：

- rootless（Dopamine、palera1n）：rootless.deb
- roothide：roothide.deb

**设置 → IOSDecryptHub** 打开目标 App，完全退出后再启动。浏览器打开 `http://<设备IP>:8088`。

默认不注入任何 App。依赖 ellekit、preferenceloader。

从源码打 deb（macOS + Xcode + dpkg + ldid）：

```bash
make deb
```
