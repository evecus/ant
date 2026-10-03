# ant

Minimal Linux proxy tool with **Hysteria2** / **VLESS** outbound, **YAML** config (mihomo-style), and binary **`.ars`** rule-sets.

Inspired by [clash-rs](https://github.com/Watfaq/clash-rs) (protocol code patterns for Hysteria2 / sniff / routing ideas).

## Features (v0.1)

- **Inbound**: `mixed-port` (HTTP CONNECT + SOCKS5 TCP/UDP), `tproxy-port` (Linux TProxy TCP+UDP), `redir-port`
- **Outbound**: Hysteria2 / VLESS (ws / xhttp / REALITY) + DIRECT / BLOCK
- **DNS**: local UDP/TCP DNS; `rule-follow-route: true` (default) reuses the connection-routing
  `route:` rules — direct-routed domains use `direct-nameserver`, node-routed use `proxy-nameserver`;
  `rule-follow-route: false` selects upstreams with its own `dns.rules` list (+ default `nameserver`)
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
  `dns.route-hijack` independently. Against a fake-ip destination, an HTTP Host result always
  overrides the mapping; TLS/QUIC SNI results never do — the DNS-mapped domain wins.)
- `dns:` — field names unchanged (`direct-nameserver`, `proxy-nameserver`, `mode`, `fakeip-range`, …);
  `rule-follow-route: false` switches to self-contained DNS routing via `dns.rules`
  (`RULE-SET,<name>,<upstream|rcode://success>` / `MATCH,<upstream|rcode://success>`, uppercase keywords)
  — when `dns.rules` is set it must end with a `MATCH` and `nameserver` is optional (fallback); when unset,
  `nameserver` is required. `direct-nameserver` / `proxy-nameserver` are unused in this mode.
  `fakeip-filter` entries are `RULE-SET,<provider-name>`
- `proxies:` — node list
- `rule-providers:` — local `.ars` files (`type: file`, `behavior: domain|ip`)
- `route:` — only `RULE-SET,<name>,<outbound>` and final `MATCH,<outbound>` (`rules:` accepted as legacy alias).
  Outbounds: `DIRECT`/`direct`, `BLOCK`/`block`/`REJECT`/`reject`, or a proxies name

Outbound keywords accept both cases; they are **reserved** (a `proxies:` node may not be named
after any of them):

| Keyword | Meaning |
|---|---|
| `DIRECT` / `direct` | bypass (direct connection) |
| `BLOCK` / `block` / `REJECT` / `reject` | reject (DNS answers `rcode://success`) |

```yaml
route:
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

## Limitations

- Windows: `mixed-port` only (transparent inbounds are Linux/Android-specific and excluded at compile time)
- DNS upstream schemes: udp / tcp / tls / https
- No connection stats / hot reload
- Rules: only `RULE-SET` and `MATCH` (no DOMAIN-SUFFIX etc. yet)
- rule-providers: local `file` only

## License

MIT
