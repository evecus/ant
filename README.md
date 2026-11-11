# ant

Minimal proxy tool (Linux / macOS / Windows) with **Hysteria2** / **VLESS** / **VMess** / **Trojan** / **Shadowsocks** / **SOCKS5** / **SOCKS4/4a** outbound, **YAML** config (mihomo-style), and binary **`.ars`** rule-sets.

Inspired by [clash-rs](https://github.com/Watfaq/clash-rs) (protocol code patterns for Hysteria2 / sniff / routing ideas).

## Features (v0.1)

- **Inbound**: `mixed-port` (HTTP CONNECT + SOCKS4/4a/5 TCP/UDP), `http-port` / `port` (HTTP only), `socks-port` (SOCKS4/4a/5 TCP/UDP), `tproxy-port` (Linux TProxy TCP+UDP), `redir-port`, TUN (system stack)
- **Outbound**: Hysteria2 / TUIC / **shadowquic** (JLS over QUIC, 0-RTT, UDP over datagram or stream) / **spectre** (JLS over QUIC + Brutal congestion control, UDP over datagram) / AnyTLS / **NaiveProxy** (HTTP/2 CONNECT, padding framing; UDP via sing UoT v2) / VLESS (ws / xhttp / REALITY / uTLS / ECH) / VMess (ws / xhttp / TLS / uTLS) / Trojan (ws / xhttp / TLS / uTLS) / **Shadowsocks** (AEAD + AEAD-2022, tcp / ws / xhttp, TLS / uTLS) / SOCKS5 (TCP + UDP ASSOCIATE, optional user/pass) / SOCKS4 + SOCKS4a (TCP CONNECT only) + direct / block；**WireGuard / SSH / Tailscale 为按需编译的 feature**（见 [Build](#build)）
- **Anti-loop**: every outbound socket (TCP + UDP, direct included) carries `SO_MARK` and binds the physical interface, so TUN auto-route never re-captures proxy traffic. System-wide `ip-auto-route` additionally supports loop prevention via **cgroup** (default), **gid** (`bypass-type: gid` + non-zero `primary-gid`, `setgid` runs in `early_prepare` before any sockets), or **mark**
- **DNS**: local UDP/TCP DNS. `rule-follow-route: true`（默认）复用 `route:` 规则——
  direct 域名用 `direct-nameserver`、节点域名用 `proxy-nameserver`、block 用 `rcode://success`；
  `false` 时用 `dns.rules` + `nameserver` 自定义 DNS 路由
- **Routing**: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR / SRC-IP-CIDR / RULE-SET; TLS/HTTP sniff first; required `MATCH` last
- **route-resolve**: optional (default false); resolve domain before IP rules; per-rule `no-resolve` skips
- **Rulesets**: binary `.ars` or plaintext (yaml/json/list/text) via `rule-providers` — plaintext loads directly
- **Proxy providers**: pull nodes from a subscription (`type: http`, auto refresh every `interval-time` hours or via the API/UI button) or a local file (`type: file`); payload may be YAML/JSON `proxies:`, a base64 blob, or share links (`hysteria2` / `tuic` / `anytls` / `vless` / `vmess` / `trojan` / `ss` / `socks5` / `spectre`)

## Build

```bash
# Linux / macOS / Windows, Rust 1.75+
cargo build --release
# macOS TUN needs root (or a Network Extension that hands over an fd)
```

### 按需编译的出站 feature

WireGuard / SSH / Tailscale 三个出站**默认不编译**，用到哪个开哪个（可组合）。
未开启 feature 时配置里出现该类型节点会在启动校验时 fail-fast，并提示需要
重新编译，不会静默变成不可用节点。

```bash
cargo build --release --features wireguard
cargo build --release --features ssh
cargo build --release --features tailscale
cargo build --release --features wireguard,ssh,tailscale
```

| feature | 出站类型 | 引入的可选依赖 | 说明 |
|---|---|---|---|
| `wireguard` | `type: wireguard` | `boringtun` | 用户态 WG 数据面 + 隧道内 smoltcp 栈（TUN 入站不再依赖用户态栈） |
| `ssh` | `type: ssh` | `russh`, `dirs`, `totp-rs` | `direct-tcpip` 转发；支持密码 / 公钥 / 键盘交互 TOTP 2FA；**不支持 UDP** |
| `tailscale` | `type: tailscale` / `ts` | `tailscale` (0.3) | userspace netstack 加入 tailnet；TCP + UDP；上游仅支持 Linux(x86_64/aarch64) / macOS(aarch64) |

> 依赖冲突处理：`tailscale` 的上游 `ts_tls_util → tokio-rustls` 默认 feature 会给
> rustls 同时启用 `aws-lc-rs` 与 `ring`，导致 `ClientConfig::builder()` 无法确定
> 进程级 CryptoProvider 而 panic。ant 自身的 TLS client 统一走
> `outbound::ring_client_builder()` 显式指定 ring，进程启动时也安装 ring 为默认
> provider（供第三方 crate 使用），所有 feature 组合的 270 个单元测试均通过。

配置字段见 `config.example.yaml` 中「按需编译的出站（feature）」一节；
share link 支持 `ssh://user:pass@host:22#name` 与
`tailscale://<base64 JSON>#name`（JSON key 与 YAML 字段同名）。

Tailscale 目标必须是 tailnet IP 或 subnet router 通告网段内的 IP：域名目标会用
bootstrap DNS 解析（TUN 模式下 dial 地址常是 fake-ip，不能直接进 netstack），
建议开启 sniffing 让域名以 `host_hint` 传入。

CI 的默认构建不带这三个 feature（保持最小二进制），需要它们的发布包请按上面
的命令自行开启。CI builds **linux aarch64**, **Windows**, and **macOS**
(aarch64 + x86_64 + universal) — see Actions artifacts / workflows
`arm64.yml`, `windows.yml`, `macos.yml`, `clippy-macos.yml`.

## Run

```bash
cp config.example.yaml config.yaml
# edit proxy server / password
./target/release/ant -c config.yaml
```

## Config sketch

See `config.example.yaml`.

Layout (mihomo-style):

- Flat top-level: `mixed-port`, `http-port`/`port`, `socks-port`, `tproxy-port`, `log-level`, `sniff`, … (`sniff: true` enables
  TLS SNI / HTTP Host / QUIC sniffing for domain routing, default off; DNS sniffing follows
  `dns.route-hijack` independently)
- `log-level`: `error` | `warn` | `info` | `debug` | `trace` | `off` — `off` disables logging
  completely (runtime output **and** the in-memory log buffer behind the API/UI). `RUST_LOG`
  overrides it when set. Logs never echo config secrets: node addresses, subscription URLs and
  rule/dns contents are not printed.
- `dns:` — `rule-follow-route` / `direct-nameserver` / `proxy-nameserver` / `rules` /
  `nameserver` / `mode` / `fakeip-range` / …
- `proxies:` — node list（节点名不得使用保留名 `direct` / `block` / `reject`，大小写不限）
- `proxy-providers:` — `type: file` (local `path`) or `type: http` (subscription `url` + cache `path`);
  `interval-time` = **hours, number only** (`0` = manual only); optional `header`, `filter`, `exclude-filter`
- `rule-providers:` — local files (`type: file`, `behavior: domain|ipcidr|classical`); `.ars` or plaintext
- `route:` — mihomo rule types + optional `,no-resolve`; final `MATCH` required

Outbound aliases: `DIRECT` → direct, `BLOCK` / `REJECT` → block.

```yaml
route:
  - RULE-SET,ads,REJECT
  - RULE-SET,cn-domain,DIRECT
  - MATCH,hy2-main
```

Sniff runs on every connection before ruleset matching (TLS SNI / HTTP Host).

### DNS 路由

```yaml
dns:
  port: 5353
  default-nameserver: "223.5.5.5:53"   # bootstrap，必须纯 IP
  # true（默认）：复用上面的 route: 规则匹配域名。
  # direct 出站 → direct-nameserver；节点出站 → proxy-nameserver；
  # block/reject 出站 → NOERROR 空应答（rcode://success）。
  # 此模式下 direct-nameserver / proxy-nameserver 必填。
  rule-follow-route: true
  direct-nameserver: "223.5.5.5:53"
  proxy-nameserver: "https://1.1.1.1/dns-query"
```

`rule-follow-route: false` 时自定义 DNS 路由：

```yaml
dns:
  port: 5353
  default-nameserver: "223.5.5.5:53"
  rule-follow-route: false
  # 关键字只能大写 RULE-SET / MATCH；第三列只能是 nameserver URL 或
  # rcode://success（不能写 direct / block / 节点名）。有 rules 时最后一条必须 MATCH。
  rules:
    - RULE-SET,cn-domain,udp://223.5.5.5:53
    - RULE-SET,ads,rcode://success
    - MATCH,tls://8.8.8.8:853
  # 未配置 rules 时，nameserver 作为默认上游（此时必填）。
  # nameserver: "udp://223.5.5.5:53"
```

## TProxy (optional)

```bash
# process needs CAP_NET_ADMIN
# set tproxy-port in config
# point iptables/nft TPROXY rules at that port for TCP and UDP
```

## TUN

TUN uses the kernel NAT system stack (`system_stack.rs` + `system_nat.rs`). `auto-route`, `strict-route` and `auto-redirect` are independent OS-integration options. Optional OS integration (mihomo-style):

```yaml
tun:
  enable: true
  address: ["198.18.0.1/30"]
  dns-hijack: ["any:53"]
  auto-route: true
  auto-detect-interface: true
  auto-redirect: false   # Linux only; REQUIRES auto-route (fails fast otherwise)
  strict-route: false
```

Set `mark:` (e.g. 255) together with auto-route so proxy outbound stays on the main table.

### External FD (Android VpnService / iOS)

Same pattern as sing-tun `FileDescriptor`: adopt an already-open TUN fd from the
VPN framework instead of creating one (no root required for the fd itself).

```yaml
tun:
  enable: true
  file-descriptor: 42          # or export ANT_TUN_FD=42
  close-fd-on-drop: true       # default; set false if JNI keeps ownership
  address: ["198.18.0.1/30"]   # must match VpnService.Builder addresses
  dns-hijack: ["any:53"]
  # auto-route / auto-redirect are ignored in this mode
```

When `file-descriptor` or `ANT_TUN_FD` is set, ant skips OS address configuration,
auto-route, and auto-redirect (the VPN framework owns those). The in-process
system stack still needs `address` for NAT / DNS hijack targets.

## Proxy groups

mihomo-compatible subset under `proxy-groups:`:

| type | behavior |
|------|----------|
| `select` | manual (API `/ui` or `PUT /proxies/{name}`) |
| `url-test` | lowest latency |
| `fallback` | first healthy in list order |
| `load-balance` | `round-robin` / `consistent-hashing` / `sticky-sessions` |
| `relay` | exit = last member |

Optional: `use: [provider]` pulls every node of a `proxy-providers` entry into the group;
`include-all-providers: true` pulls all of them; `filter` / `exclude-filter` /
`include-all-proxies` also apply. See `config.example.yaml`.

Nodes from providers are hot-swapped on refresh — group membership, the API group list and
the `GLOBAL` node list are all recomputed in place.

Subscription refresh:
- automatic every `interval-time` hours (`type: http` only);
- on demand: `PUT /providers/proxies/{name}`, or the 「拉取订阅」 button on the **信息** page;
- list/read state: `GET /providers/proxies` and `GET /providers/proxies/{name}`
  (mihomo clash-api shape, plus `interval-time` / `error`);
- `subscription-userinfo` response header is parsed into `subscriptionInfo`
  (upload / download / total / expire).

## Proxy providers — subscription compatibility

Subscription payloads are pre-processed like sub-store: Clash/mihomo YAML
(`proxies:` / `payload:`), SSD (`ssd://`), wrapped / url-safe / unpadded base64
blobs and plain share-link lists. Clash nodes are normalized **per node** (string
ports, string booleans, comma-list `alpn`, nested `ws-opts` / `xhttp-opts` /
`reality-opts`, protocol aliases, mihomo's default `tls: false`), and unsupported
nodes are skipped with a warning so one bad node cannot drop the whole subscription
or fail startup.

mihomo / sub-store field names are mapped onto ant's `ProxyConfig` keys, so a node
read from a YAML file and the same node written as a share link produce the same
config:

| mihomo / sub-store key | ant key |
|---|---|
| `auth` / `auth-str` (hysteria2 / tuic / anytls) | `password` |
| `congestion-controller` (tuic) | `congestion-control` |
| `tls-fingerprint` / `server-cert-fingerprint` | `fingerprint` |
| `servername` (vmess / vless) | `sni` |
| `public-key` (wireguard) | `peer-public-key` |
| `ip` / `ipv6` / `address`, `peers[0]` (wireguard) | `local-address`, `server` / `port` / `peer-public-key` |
| `host-key` / `host-key-algorithms` as a comma string (ssh) | string lists |
| `totp: <secret>` (ssh) | `totp-opt` mapping |
| `security` alongside `cipher` | dropped (avoids duplicate-field errors) |

v2rayN `vmess://<base64 JSON>` accepts `tls` as `true` / `1` / `"1"` / `"tls"`,
`alpn` as a comma string or array, `peer` as an SNI fallback, `verify_cert: false`
/ `allowInsecure`, JSON-string WS `host`, and `ps` / `remarks` / `remark` names.
VMessAEAD links map `encryption` → `cipher`. Share links also honour `wspath` /
`obfsParam`, `remarks` / `remark` names, `security=tls` (SS) and hysteria2 port-hop
ranges (`host:1000-2000,3000`). `disable_sni` on TUIC no longer disables cert
verification.

Share links are converted with the matrix below — everything maps onto
`ProxyConfig` fields that have a real outbound.

| scheme | transport (`?type=`) | TLS |
|---|---|---|
| `hysteria2` / `hy2` | — | always TLS; `sni`, `alpn`, `obfs`, `ports`/`mport`, `up`/`down`, `pinSHA256`, `insecure` |
| `tuic` | — | always TLS; `sni`, `alpn`, `congestion_control`, `pinSHA256` (v5 `uuid:password` only) |
| `anytls` | — | always TLS; uTLS `fp` (default `chrome`) |
| `vless` | `tcp` / `ws` / `xhttp` | `security=tls\|xtls\|reality\|none`; REALITY `pbk`+`sid`; `flow=*vision*`; uTLS `fp` (default `chrome`); `sni`, `alpn`, `pcs`/`pinSHA256`, `allowInsecure` |
| `vmess` | `tcp` / `ws` / `xhttp` | base64 JSON (`tls` bool/string, `sni`/`peer`, `alpn`, `allowInsecure`/`verify_cert`, `scy`, `pcs`, `fp`) **or** Xray AEAD link (`encryption` → `cipher`, `security`, `fp`, …) |
| `trojan` | `tcp` / `ws` / `xhttp` | always TLS; uTLS `fp` (default `chrome`), `pcs`/`pinSHA256` |
| `ss` | `tcp` / `ws` / `xhttp` | SIP002 + legacy + AEAD-2022; TLS when `sni`/`fp` or `security=tls` is given; `path`/`wspath`, `host`/`obfsParam` |
| `socks5` / `socks5h` / `socks` | — | — (optional user/pass) |
| `socks4` / `socks4a` | — | — (USERID only) |
| `naive` `shadowquic` `spectre` `wireguard` | — | ant-native formats (no cross-client standard); `wireguard://<base64 JSON>` uses the ant YAML key names |
| `ssh` | — | `ssh://user:pass@host:22?host-key=...&private-key=...&totp=...#name`（需 `ssh` feature） |
| `tailscale` / `ts` | — | `tailscale://<base64 JSON>#name`，JSON key 与 YAML 字段一致（需 `tailscale` feature） |

uTLS `fp`: `chrome` / `firefox` / `safari` / `edge` / `ios` / `android` / `360` / `qq` / `random`
(`none` disables). REALITY ignores `fp` — its handshake is self-implemented TLS 1.3.

Dashboard (`api:`) at `/ui`: **代理组** · **连接** · **信息**.

Connection list is controlled by top-level `api-connection-record` (default `true`):
always record live sessions; set to `false` for the old opt-in-while-UI-open behaviour.

## Limitations

- Windows: no tproxy/redir; TUN auto-route/dns-hijack supported; auto-redirect is Linux-only
- macOS: TUN via utun + `ifconfig`/`route` auto-route (sing-tun style); auto-redirect not available
- External TUN fd (`file-descriptor` / `ANT_TUN_FD`): Unix only; no Android VpnService shell yet (Rust side only)
- WireGuard / SSH / Tailscale 出站需对应 feature；SSH 出站不支持 UDP 转发；Tailscale 上游 crate 仅支持 Linux(x86_64/aarch64) / macOS(aarch64)，且为实验性实现（未做安全审计）
- DNS upstream schemes: udp / tcp / tls / https
- No hot reload (restart to apply config changes)
- Rules: only `RULE-SET` and `MATCH` (no DOMAIN-SUFFIX etc. yet)
- rule-providers: local `file` only
- proxy-providers share-link parsing: only the schemes/transports ant can actually dial — see the
  table below. `ssr`, hysteria v1, plain `http` proxy and `grpc` / `httpupgrade` transports have
  no outbound, so those links (and equivalent Clash nodes) are skipped with a warning instead of
  producing dead nodes. `subscription-userinfo` tolerates extra keys (`app_url`, `plan_name`) and
  malformed fragments; subscriptions are fetched with `User-Agent: clash.meta/v1.19.33` unless
  `header` overrides it

## License

MIT
