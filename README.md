# ant

Minimal Linux proxy tool with **Hysteria2** / **VLESS** outbound, **YAML** config (mihomo-style), and binary **`.ars`** rule-sets.

Inspired by [clash-rs](https://github.com/Watfaq/clash-rs) (protocol code patterns for Hysteria2 / sniff / routing ideas).

## Features (v0.1)

- **Inbound**: `mixed-port` (HTTP CONNECT + SOCKS5 TCP/UDP), `tproxy-port` (Linux TProxy TCP+UDP), `redir-port`, TUN (system stack)
- **Outbound**: Hysteria2 / VLESS (ws / xhttp / REALITY) + direct / block
- **DNS**: local UDP/TCP DNS; domain rules that route to direct use `direct-nameserver`, others use `proxy-nameserver`
- **Routing**: sequential `RULE-SET` match; TLS/HTTP sniff first; required `MATCH` last
- **Rulesets**: local binary `.ars` via `rule-providers` (convert from sing-box JSON)

## Build

```bash
# Linux, Rust 1.75+
cargo build --release
```

CI builds **linux aarch64** on every push to `main` (see Actions artifacts).

## Run

```bash
cp config.example.yaml config.yaml
# edit proxy server / password
./target/release/ant -c config.yaml
```

## Config sketch

See `config.example.yaml`.

Layout (mihomo-style):

- Flat top-level: `mixed-port`, `tproxy-port`, `log-level`, `sniff`, … (`sniff: true` enables
  TLS SNI / HTTP Host / QUIC sniffing for domain routing, default off; DNS sniffing follows
  `dns.route-hijack` independently)
- `dns:` — field names unchanged (`direct-nameserver`, `proxy-nameserver`, `mode`, `fakeip-range`, …)
- `proxies:` — node list
- `rule-providers:` — local `.ars` files (`type: file`, `behavior: domain|ip`)
- `rules:` — only `RULE-SET,<name>,<outbound>` and final `MATCH,<outbound>`

Outbound aliases: `DIRECT` → direct, `REJECT` → block.

```yaml
rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,cn-domain,DIRECT
  - MATCH,hy2-main
```

Sniff runs on every connection before ruleset matching (TLS SNI / HTTP Host).

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

## Limitations

- Windows: no tproxy/redir; TUN auto-route/dns-hijack supported; auto-redirect is Linux-only
- DNS upstream schemes: udp / tcp / tls / https
- No connection stats / hot reload
- Rules: only `RULE-SET` and `MATCH` (no DOMAIN-SUFFIX etc. yet)
- rule-providers: local `file` only

## License

MIT
