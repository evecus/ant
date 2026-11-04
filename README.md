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
- **零配置使用**：内置「绕过大陆」配置模板（master 分支 config.example.yaml 模式）与
  内置规则集 `geosite-cn.ars` / `geoip-cn.ars`（ruleset 分支）
- **导入节点链接**：粘贴 `vless://` 等分享链接（支持 vmess / ss / trojan /
  hysteria2 / tuic / anytls 等，多行 / base64 订阅均可），写入
  `proxy-providers`（type: file）即可使用
- 路由策略：国内域名 + 国内 IP **直连**，其余全部走 `PROXY` 组
- TUN 参数（stack / mtu / dns-hijack / log-level）由应用统一管理
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

配置完全由应用内置生成（`assets/config-template.yaml`），用户只需「导入节点」粘贴分享链接：

```yaml
route:
  - RULE-SET,geosite-cn,DIRECT
  - RULE-SET,geoip-cn,DIRECT,no-resolve
  - MATCH,PROXY
```

- 内置规则集释放到 `files/rules/`，节点链接写入 `files/providers/nodes.txt`
  （`proxy-providers.nodes`，type: file）
- 未导入节点时 `PROXY` 组回落为 DIRECT
- 导入或修改设置后，重启 VPN 生效（每次启动都会重新生成 config.yaml）

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

导入节点后，重启 VPN 生效。

## Limitations (v0.1)

- No `VpnService.protect()` IPC yet (relies on `SO_BINDTODEVICE`)
- arm64-v8a only
- Minimal UI (start/stop, import, log)
