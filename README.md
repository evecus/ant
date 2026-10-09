# Ant Proxy for Android

Companion APK for the [ant](https://github.com/aazz77/ant) proxy core.

**Architecture**: independent `ant` executable + process communication.

```
APK (Kotlin)
  └─ AntVpnService
       ├─ VpnService.Builder.establish()  →  TUN FD
       └─ ProcessBuilder(ant, -c config.yaml)
              env ANT_TUN_FD=<fd>
              ant adopts FD via tun external-FD mode
```

## Features

- Start / stop VPN (system VpnService)
- **Import config**: pick a local YAML file (mihomo-style); auto-injects TUN block if missing
- Live process log
- Bundled `ant` aarch64 binary (built in CI)

## Build (CI)

Push to `main` or run **Actions → Build Android APK → Run workflow**.

Artifacts:

- `ant-proxy-debug-apk` — installable APK
- `ant-android-aarch64` — the `ant` binary alone

CI steps: checkout ant core → `cargo ndk` → copy into `assets/ant` → `assembleDebug`.

## Local build

1. Build ant for Android:

```bash
# in ant source tree
cargo ndk --target aarch64-linux-android --platform 24 build --release --locked
cp target/aarch64-linux-android/release/ant \
   ant-android/app/src/main/assets/ant
```

2. Assemble APK:

```bash
cd ant-android
./gradlew :app:assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
```

## Config notes

TUN must match VpnService:

```yaml
tun:
  enable: true
  close-fd-on-drop: false
  address:
    - 172.19.0.1/30
  mtu: 1500
  auto-detect-interface: true
```

Do **not** set `file-descriptor` in YAML — the FD is passed via `ANT_TUN_FD` at runtime.

After **Import Config**, stop and start VPN to apply.

## Limitations (v0.1)

- No `VpnService.protect()` IPC yet (relies on `SO_BINDTODEVICE`)
- arm64-v8a only
- Minimal UI (start/stop, import, log)
