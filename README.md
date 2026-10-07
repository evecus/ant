# ant

Minimal proxy tool (Linux / macOS / Windows) with **Hysteria2** / **VLESS** / **VMess** / **Trojan** / **Shadowsocks** / **SOCKS5** / **SOCKS4/4a** outbound, **YAML** config (mihomo-style), and binary **`.ars`** rule-sets.

Inspired by [clash-rs](https://github.com/Watfaq/clash-rs) (protocol code patterns for Hysteria2 / sniff / routing ideas).

## Features (v0.1)

- **Inbound**: `mixed-port` (HTTP CONNECT + SOCKS4/4a/5 TCP/UDP), `http-port` / `port` (HTTP only), `socks-port` (SOCKS4/4a/5 TCP/UDP), `tproxy-port` (Linux TProxy TCP+UDP), `redir-port`, TUN (system stack)
- **Outbound**: Hysteria2 / TUIC / **shadowquic** (JLS over QUIC, 0-RTT, UDP over datagram or stream) / AnyTLS / **NaiveProxy** (HTTP/2 CONNECT, padding framing; UDP via sing UoT v2) / VLESS (ws / xhttp / REALITY / uTLS / ECH) / VMess (ws / xhttp / TLS / uTLS) / Trojan (ws / xhttp / TLS / uTLS) / **Shadowsocks** (AEAD + AEAD-2022, tcp / ws / xhttp, TLS / uTLS) / SOCKS5 (TCP + UDP ASSOCIATE, optional user/pass) / SOCKS4 + SOCKS4a (TCP CONNECT only) + direct / block
- **Anti-loop**: every outbound socket (TCP + UDP, direct included) carries `SO_MARK` and binds the physical interface, so TUN auto-route never re-captures proxy traffic
- **DNS**: local UDP/TCP DNS. `rule-follow-route: true`（默认）复用 `route:` 规则——
  direct 域名用 `direct-nameserver`、节点域名用 `proxy-nameserver`、block 用 `rcode://success`；
  `false` 时用 `dns.rules` + `nameserver` 自定义 DNS 路由
- **Routing**: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR / SRC-IP-CIDR / RULE-SET; TLS/HTTP sniff first; required `MATCH` last
- **route-resolve**: optional (default false); resolve domain before IP rules; per-rule `no-resolve` skips
- **Rulesets**: binary `.ars` or plaintext (yaml/json/list/text) via `rule-providers` — plaintext loads directly

## Build

Default binary is **minimal**: only **Hysteria2 + VLESS** (+ direct / groups /
DNS / rules). Extra outbounds and TUN are cargo features (compile-time).

```bash
# Minimal (Hy2 + VLESS) — smallest binary / lowest idle RSS
cargo build --release

# Everything (all protocols + TUN) — same as CI release artifacts
cargo build --release --features full

# Pick what you need
cargo build --release --features "tun,shadowsocks,vmess,trojan,socks"
```

| Feature | What it enables |
|---------|-----------------|
| `tuic` | TUIC outbound |
| `anytls` | AnyTLS outbound |
| `naive` | NaiveProxy outbound |
| `shadowquic` | shadowquic (JLS) outbound |
| `vmess` | VMess outbound |
| `shadowsocks` | Shadowsocks outbound |
| `socks` | SOCKS4/4a/5 outbound |
| `trojan` | Trojan outbound |
| `wireguard` | WireGuard outbound (boringtun + smoltcp) |
| `tun` | TUN virtual NIC + OS route/redirect |
| `full` | all of the above |

Using a disabled type in config fails fast at startup with a message to
recompile with the matching `--features …`.

macOS TUN needs root (or a Network Extension that hands over an fd).

CI builds **linux aarch64**, **Windows**, and **macOS** (aarch64 + x86_64 +
universal) with `--features full` — see Actions artifacts / workflows
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
- `dns:` — `rule-follow-route` / `direct-nameserver` / `proxy-nameserver` / `rules` /
  `nameserver` / `mode` / `fakeip-range` / …
- `proxies:` — node list（节点名不得使用保留名 `direct` / `block` / `reject`，大小写不限）
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

System stack only. Optional OS integration (mihomo-style):

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

Optional: `proxy-providers` (`type: file`), `use`, `filter` / `exclude-filter`,
`include-all-proxies` / `include-all-providers`. See `config.example.yaml`.

Dashboard (`api:`) at `/ui`: **代理组** · **连接** · **信息**.

Connection list is controlled by top-level `api-connection-record` (default `true`):
always record live sessions; set to `false` for the old opt-in-while-UI-open behaviour.

## Limitations

- Windows: no tproxy/redir; TUN auto-route/dns-hijack supported; auto-redirect is Linux-only
- macOS: TUN via utun + `ifconfig`/`route` auto-route (sing-tun style); auto-redirect not available
- External TUN fd (`file-descriptor` / `ANT_TUN_FD`): Unix only; no Android VpnService shell yet (Rust side only)
- DNS upstream schemes: udp / tcp / tls / https
- No hot reload (restart to apply config changes)
- Rules: only `RULE-SET` and `MATCH` (no DOMAIN-SUFFIX etc. yet)
- rule-providers: local `file` only

## License

MIT
