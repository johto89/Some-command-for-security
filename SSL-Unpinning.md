[Xposed Module: Just Trust Me](https://github.com/Fuzion24/JustTrustMe): Xposed Module to bypass SSL certificate pinning.

```
adb install ./JustTrustMe.apk
```

[Xposed Module: SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed) Android Xposed Module to bypass SSL certificate validation (Certificate Pinning).

```
adb install mobi.acpm.sslunpinning_latest.apk
```

Cydia Substrate Module: [Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller): Blackbox tool to bypass SSL certificate pinning for most applications running on a device.

```
adb install Android-SSL-TrustKiller.apk
```

Bypassing SSL Pinning with Frida

```
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f $PACKAGE
frida -U -f $PACKAGE -l universal-android-ssl-pinning-bypass-with-frida.js --no-pause
```
