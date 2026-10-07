//! YAML configuration for ant (mihomo-style layout).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Flat top-level keys (mihomo-style): mixed-port, http-port, socks-port, log-level, …
    #[serde(flatten)]
    pub global: GlobalConfig,
    /// DNS 模块。整块省略 = 不启用（走系统 DNS）；块内 `enable: false` 同效。
    #[serde(default)]
    pub dns: DnsConfig,
    /// TUN virtual NIC (optional). System stack + optional OS route/DNS integration.
    #[serde(default)]
    pub tun: TunConfig,
    /// Proxy nodes: list under `proxies:`; each node has a unique `name`.
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    /// Proxy groups (mihomo-style): `select` / `url-test` / `fallback`.
    /// Group names are valid rule outbounds (like node names).
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,
    /// Proxy providers (mihomo-style map). Currently `type: file` only.
    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ProxyProviderConfig>,
    /// Local rule providers (mihomo-style map).
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,
    /// mihomo-style route strings: `RULE-SET,name,outbound` / `MATCH,outbound`.
    /// Outbound: `direct`/`DIRECT`, `block`/`BLOCK`, `reject`/`REJECT`, or a
    /// `proxies` node name (reserved names are rejected for node names).
    #[serde(default)]
    pub route: Vec<String>,
}

/// Flat `tun:` block. Creates a virtual NIC and runs the system stack.
/// Optional OS integration: dns-hijack / auto-route / auto-detect-interface /
/// auto-redirect (Linux) / strict-route — see field docs.
// Fields are consumed by src/tun/ which is compiled only with --features tun.
// Without that feature the struct still exists for YAML deserialization + validate.
#[cfg_attr(not(feature = "tun"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct TunConfig {
    /// Master switch. Default false.
    #[serde(default)]
    pub enable: bool,
    /// Interface name. Empty → OS assigns (Linux `tunN`; Windows defaults to `ant-tun`).
    #[serde(default)]
    pub device: Option<String>,
    /// External TUN file descriptor (sing-tun `FileDescriptor` equivalent).
    ///
    /// When set (or when env `ANT_TUN_FD` is a positive integer), the process
    /// adopts an already-open TUN fd instead of creating one. Typical sources:
    /// Android `VpnService.Builder.establish()` / iOS PacketTunnelProvider.
    ///
    /// In this mode the OS (VpnService) already owns addresses and routing, so
    /// `auto-route` / `auto-redirect` / OS address configuration are skipped.
    /// Unix only; ignored on Windows.
    #[serde(default, rename = "file-descriptor")]
    pub file_descriptor: Option<i32>,
    /// Whether to close `file-descriptor` when the TUN device is dropped.
    /// Default true (take ownership). Set false if the caller retains ownership
    /// (e.g. JNI side will close the ParcelFileDescriptor).
    /// Consumed only on Unix (external-FD path in `tun::device`).
    #[cfg_attr(not(unix), allow(dead_code))]
    #[serde(default = "default_true", rename = "close-fd-on-drop")]
    pub close_fd_on_drop: bool,
    /// Address prefixes, e.g. `["198.18.0.1/30"]`.
    /// System stack needs server=addr, client=addr+1 inside the prefix — avoid `/32`.
    /// Still required for the in-process system stack even when using an external FD
    /// (values must match what VpnService configured).
    #[serde(default)]
    pub address: Vec<String>,
    /// MTU. Default 1500.
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,
    /// DNS destinations to intercept inside the TUN stack, e.g. `any:53`, `0.0.0.0:53`.
    /// Matched UDP/TCP port-53 queries are answered by the local DNS module.
    #[serde(default, rename = "dns-hijack")]
    pub dns_hijack: Vec<String>,
    /// Install routes so traffic enters the TUN device (Linux `ip` / Windows `netsh`).
    #[serde(default, rename = "auto-route")]
    pub auto_route: bool,
    /// Bind outbound sockets to the current default physical interface so proxy
    /// traffic does not re-enter TUN (loop prevention). Linux: SO_BINDTODEVICE;
    /// Windows: best-effort (mark/route still required for full isolation).
    #[serde(default, rename = "auto-detect-interface")]
    pub auto_detect_interface: bool,
    /// Linux only: mihomo/sing-tun style auto-redirect (internal listener + nft/iptables).
    /// Uses the classic topology (requires `auto-route`); TCP is handled by the
    /// redirect listener, UDP/ICMP enter the TUN device. Does **not** require
    /// `redir-port`. Ignored on non-Linux.
    #[serde(default, rename = "auto-redirect")]
    pub auto_redirect: bool,
    /// Stronger anti-leak routing on top of auto-route (Linux). May break LAN reachability.
    #[serde(default, rename = "strict-route")]
    pub strict_route: bool,
    /// Custom prefixes routed into TUN when auto-route is on. Empty → split default
    /// (`0.0.0.0/1`+`128.0.0.0/1` and IPv6 equivalents).
    #[serde(default, rename = "route-address")]
    pub route_address: Vec<String>,
    /// Prefixes excluded from auto-route (not installed / explicitly deleted).
    #[serde(default, rename = "route-exclude-address")]
    pub route_exclude_address: Vec<String>,
    /// iproute2 table index for policy routing (Linux). Default 1982.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    #[serde(default = "default_tun_table", rename = "iproute2-table-index")]
    pub iproute2_table_index: i32,
    /// iproute2 rule priority (Linux). Default 9000.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    #[serde(default = "default_tun_rule", rename = "iproute2-rule-index")]
    pub iproute2_rule_index: i32,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            device: None,
            file_descriptor: None,
            close_fd_on_drop: true,
            address: Vec::new(),
            mtu: default_tun_mtu(),
            dns_hijack: Vec::new(),
            auto_route: false,
            auto_detect_interface: false,
            auto_redirect: false,
            strict_route: false,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            iproute2_table_index: default_tun_table(),
            iproute2_rule_index: default_tun_rule(),
        }
    }
}

#[cfg_attr(not(feature = "tun"), allow(dead_code))]
impl TunConfig {
    /// Resolve external TUN fd: config `file-descriptor` wins, else env `ANT_TUN_FD`.
    /// Returns `None` when neither is a positive integer (create device ourselves).
    pub fn resolved_file_descriptor(&self) -> Option<i32> {
        if let Some(fd) = self.file_descriptor {
            if fd > 0 {
                return Some(fd);
            }
        }
        std::env::var("ANT_TUN_FD")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .filter(|&fd| fd > 0)
    }

    /// True when we adopt an external TUN fd (Android VpnService / iOS / parent).
    pub fn is_external_fd(&self) -> bool {
        self.resolved_file_descriptor().is_some()
    }
}

fn default_tun_table() -> i32 {
    1982
}

fn default_tun_rule() -> i32 {
    9000
}

fn default_tun_mtu() -> u32 {
    1500
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_log_level", rename = "log-level")]
    pub log_level: String,
    /// None = 入站未启用；显式 `0` 会被校验拒绝（想关闭就省略字段）。
    #[serde(default, rename = "tproxy-port")]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub tproxy_port: Option<u16>,
    #[serde(default, rename = "mixed-port")]
    pub mixed_port: Option<u16>,
    /// Dedicated HTTP inbound (CONNECT + absolute-URI). None = disabled.
    /// Explicit `0` is rejected at validate (omit the field to disable).
    /// Alias `port` matches mihomo / clash flat config.
    #[serde(default, rename = "http-port", alias = "port")]
    pub http_port: Option<u16>,
    /// Dedicated SOCKS4/4a/5 inbound (TCP + SOCKS5 UDP ASSOCIATE). None = disabled.
    /// Explicit `0` is rejected at validate (omit the field to disable).
    #[serde(default, rename = "socks-port", alias = "socks5-port")]
    pub socks_port: Option<u16>,
    /// None = 入站未启用；显式 `0` 会被校验拒绝（想关闭就省略字段）。
    #[serde(default, rename = "redir-port")]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub redir_port: Option<u16>,
    /// SO_MARK for outbound sockets (anti-loop with TUN auto-route).
    /// If 0 and TUN auto-route/redirect/detect-interface is on, a default (255) is applied at runtime.
    #[serde(default, rename = "mark")]
    pub mark: u32,
    /// Inbound / DNS listen address family control.
    /// - `true` (default / unset): dual-stack — IPv4 + IPv6 traffic, rulesets load both
    ///   IPv4 and IPv6 CIDRs, DNS AAAA controlled independently by `dns.ipv6`.
    /// - `false`: IPv4 only — inbound and DNS listen on IPv4 only, DNS ignores
    ///   `dns.ipv6` (A records only), FakeIP allocates only IPv4, IP rulesets
    ///   load only IPv4 CIDRs.
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// Listen address for all inbounds and the DNS module.
    /// Only `0.0.0.0` (LAN-accessible) or `127.0.0.1` (loopback-only) are accepted.
    /// Whether IPv6 sockets are also opened is controlled solely by top-level `ipv6`.
    #[serde(default = "default_bind", rename = "bind-address")]
    pub bind_address: String,
    #[serde(default, rename = "api")]
    pub api: String,
    /// API 面板（/ui 及全部 JSON 接口）访问密码。非空时必须先登录：
    /// 浏览器输入密码 → 服务端下发凭证 Cookie → 后续请求自动携带。
    /// 类似 mihomo clash-api 的 secret，但只需密码、无需地址/端口。
    #[serde(default, rename = "api-secret")]
    pub api_secret: String,
    /// 是否常驻记录活跃连接（供 API 面板「连接」页显示）。
    /// - `true`（默认 / 不写）：始终记录当前正在进行的连接；连接结束后自动移除，不会显示死连接。
    /// - `false`：仅在面板打开期间记录（打开 `/ui` 或轮询 `/connections` 后短时生效，关闭后清空）。
    #[serde(default = "default_true", rename = "api-connection-record")]
    pub api_connection_record: bool,
    /// Protocol sniffing (TLS SNI / HTTP Host / QUIC SNI) for domain-based routing.
    /// Off by default. DNS-query sniffing is independent: it follows `dns.route-hijack`.
    #[serde(default)]
    pub sniff: bool,
    /// When true, domain destinations are resolved before matching IP rules /
    /// IP rule-providers. Default false. Per-rule `no-resolve` skips this line.
    #[serde(default, rename = "route-resolve")]
    pub route_resolve: bool,
    /// Global persistent cache (redb). Default false.
    /// When true: DNS, Fake-IP, select-group choices, and path-less rule-providers
    /// are stored in redb (`cache-file`).
    #[serde(default)]
    pub cache: bool,
    /// Path to the redb file when `cache: true`. Default `cache.db`.
    #[serde(default = "default_cache_file", rename = "cache-file")]
    pub cache_file: PathBuf,
}

fn default_bind() -> String {
    "0.0.0.0".into()
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// 总开关。`dns:` 块存在时默认 true；`dns:` 块整体省略时 Default（false，
    /// 即完全不启用 DNS 模块——所有内部解析走系统 resolver）。
    /// port 是否配置不影响启用状态：省略 port = 不监听（仅 route-hijack /
    /// TUN dns-hijack 路径应答）；`port: 0` 校验直接拒绝。
    #[serde(default = "default_true")]
    pub enable: bool,
    /// None = 不监听 DNS 端口（仅经路由劫持应答）；显式 `0` 校验拒绝。
    #[serde(default, rename = "port", alias = "dns-port")]
    pub port: Option<u16>,
    /// rule-follow-route=true 时必填：路由出站为 direct 的域名用此上游解析。
    #[serde(default, rename = "direct-nameserver", alias = "direct-dns")]
    pub direct_nameserver: Option<String>,
    /// rule-follow-route=true 时必填：路由出站为任意节点的域名用此上游解析。
    #[serde(default, rename = "proxy-nameserver", alias = "proxy-dns")]
    pub proxy_nameserver: Option<String>,
    /// Bootstrap 上游（必须纯 IP），用于解析其他 nameserver 与节点 server 域名。
    /// enable=true 时必填。
    #[serde(default, rename = "default-nameserver")]
    pub default_nameserver: Option<String>,
    /// true（默认）：DNS 复用顶层 `route:` 规则匹配域名——出站 direct 用
    /// direct-nameserver、节点用 proxy-nameserver、block/reject 回 rcode://success。
    /// false：用 `dns.rules` 自定义 DNS 路由（见下）。
    #[serde(default = "default_true", rename = "rule-follow-route")]
    pub rule_follow_route: bool,
    /// rule-follow-route=false 时的 DNS 路由表：`RULE-SET,<name>,<upstream>` /
    /// `MATCH,<upstream>`。upstream 只能是 nameserver URL 或 `rcode://success`；
    /// 配置了 rules 时最后一条必须是 MATCH。
    #[serde(default)]
    pub rules: Vec<String>,
    /// rule-follow-route=false 且未配置 dns.rules 时的默认上游（必填）。
    #[serde(default)]
    pub nameserver: Option<String>,
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    #[serde(default, rename = "fakeip-range")]
    pub fakeip_range: Option<String>,
    #[serde(default, rename = "fakeip6-range")]
    pub fakeip6_range: Option<String>,
    /// Domain rulesets deciding fake-ip usage, interpreted by `fakeip-filter-mode`:
    /// blacklist (default) — matched domains stay real-IP, everything else gets fake-ip;
    /// whitelist — only matched domains get fake-ip.
    #[serde(default, rename = "fakeip-filter")]
    pub fakeip_filter: Vec<String>,
    #[serde(default, rename = "fakeip-filter-mode")]
    pub fakeip_filter_mode: String,
    #[serde(default, rename = "route-hijack", alias = "hijack-dns")]
    pub route_hijack: bool,
    #[serde(default = "default_true")]
    pub ipv6: bool,
    #[serde(default = "default_cache_size", rename = "cache-size")]
    pub cache_size: usize,
}

impl Default for DnsConfig {
    /// `dns:` 块整体省略 → 不启用 DNS 模块（全部字段为安全默认值）。
    fn default() -> Self {
        Self {
            enable: false,
            port: None,
            direct_nameserver: None,
            proxy_nameserver: None,
            default_nameserver: None,
            rule_follow_route: true,
            rules: Vec::new(),
            nameserver: None,
            mode: default_dns_mode(),
            fakeip_range: None,
            fakeip6_range: None,
            fakeip_filter: Vec::new(),
            fakeip_filter_mode: String::new(),
            route_hijack: false,
            ipv6: true,
            cache_size: default_cache_size(),
        }
    }
}

impl DnsConfig {
    /// DNS UDP/TCP 监听端口；省略 = 0 = 不监听（仅经路由劫持应答）。
    pub fn listen_port(&self) -> u16 {
        self.port.unwrap_or(0)
    }
}

fn default_dns_mode() -> String {
    "redir-host".into()
}

fn default_cache_size() -> usize {
    4096
}

/// One entry under `proxy-groups:` (mihomo-compatible subset).
///
/// ```yaml
/// proxy-groups:
///   - name: PROXY
///     type: select          # select | url-test | fallback
///     proxies:
///       - hy2-hk
///       - hy2-jp
///       - DIRECT
///   - name: AUTO
///     type: url-test
///     proxies: [hy2-hk, hy2-jp]
///     url: http://www.gstatic.com/generate_204
///     interval: 300        # seconds between probes
/// ```
///
/// Rules reference the group `name` the same way as a proxy node name.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyGroupConfig {
    pub name: String,
    /// `select` | `url-test` | `fallback` | `load-balance` | `relay`
    #[serde(rename = "type")]
    pub ty: String,
    /// Member names: proxy node names, other group names, or `DIRECT` / `REJECT`.
    #[serde(default)]
    pub proxies: Vec<String>,
    /// Provider names under `proxy-providers:` whose nodes are included.
    #[serde(default)]
    pub r#use: Vec<String>,
    /// Include every node from `proxies:` (mihomo `include-all-proxies`).
    #[serde(default, rename = "include-all-proxies")]
    pub include_all_proxies: bool,
    /// Include every provider (mihomo `include-all-providers`).
    #[serde(default, rename = "include-all-providers")]
    pub include_all_providers: bool,
    /// Regex filter on member names (mihomo ``filter``; `` ` `` separates alternatives).
    #[serde(default)]
    pub filter: Option<String>,
    /// Regex exclude on member names (mihomo ``exclude-filter``).
    #[serde(default, rename = "exclude-filter")]
    pub exclude_filter: Option<String>,
    /// Health-check URL for `url-test` / `fallback` / `load-balance` (default generate_204).
    #[serde(default)]
    pub url: Option<String>,
    /// Probe interval in seconds (default 300).
    #[serde(default)]
    pub interval: Option<u64>,
    /// Initial selected member for `select` (default: first in `proxies`).
    #[serde(default)]
    pub selected: Option<String>,
    /// Tolerance in ms for url-test (default 50).
    #[serde(default)]
    pub tolerance: Option<u32>,
    /// `load-balance` strategy: `round-robin` (default) | `consistent-hashing` | `sticky-sessions`.
    #[serde(default)]
    pub strategy: Option<String>,
}

/// One entry under `proxy-providers:` (mihomo-compatible subset).
///
/// ```yaml
/// proxy-providers:
///   sub:
///     type: file
///     path: ./providers/sub.yaml   # contains a `proxies:` list
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProviderConfig {
    #[serde(rename = "type")]
    pub ty: String,
    /// Local path for `type: file`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Health-check URL (optional; reserved for future HTTP provider refresh).
    #[serde(default)]
    #[allow(dead_code)]
    pub url: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub interval: Option<u64>,
}

/// Shared proxy node config. `type` selects protocol; other fields are type-specific.
///
/// Configured under `proxies:` — multiple nodes, each identified by `name`.
/// Route rules reference nodes by name: `RULE-SET,cn,my-hk` or `MATCH,my-hk`.
/// Reserved (case-insensitive): `direct`, `block`, `reject` (+ internal
/// `final` / `proxy`) — node names must not use any of them.
///
/// ## hysteria2
/// `password`, optional `sni` / `alpn` / `skip-cert-verify` / `fingerprint` / `udp-mtu`
///
/// ## tuic
/// `uuid`, `password`, optional `sni` / `alpn` (default `h3`) / `skip-cert-verify` /
/// `fingerprint` / `congestion-control` = `cubic`(default)|`bbr`|`new_reno` /
/// `heartbeat` (e.g. `"10s"`, default 10s)
///
/// ## anytls
/// `password`, optional `sni` / `alpn` / `skip-cert-verify` / `fingerprint` /
/// `client-fingerprint` (uTLS browser hello). UDP rides sing UoT v2.
///
/// ## vless
/// `uuid` (or `password` as uuid), `network` = `tcp`|`ws`|`xhttp`, `tls` = bool,
/// optional `sni`, `skip-cert-verify`, `ws-path`, `ws-host`,
/// `reality-public-key` / `reality-short-id`, `xhttp-path` / `xhttp-host` / `xhttp-mode`
///
/// ## vmess
/// `uuid` (or `password` as uuid), `cipher` = `auto`(default)|`aes-128-gcm`|
/// `chacha20-poly1305`|`none`|`zero` (`auto` + tls → `zero`), `alter-id` = 0,
/// `network` = `tcp`|`ws`|`xhttp`, `tls` = bool, optional `sni`, `skip-cert-verify`,
/// `client-fingerprint` (uTLS), `ws-path` / `ws-host`,
/// `xhttp-path` / `xhttp-host` / `xhttp-mode`
///
/// ## shadowsocks (`ss`)
/// `password` (+ `cipher` / `method` 指定加密方式), `network` = `tcp`|`ws`|`xhttp`,
/// 可选 `sni` / `skip-cert-verify` / `client-fingerprint` (uTLS) /
/// `ws-path` / `ws-host` / `xhttp-*`。
/// 注意两点：
/// * **TLS 默认关闭**。`tls` 字段的全局默认值是 true，但 SS 只在显式给出 `sni`
///   （或 `servername`）、或配置了 `client-fingerprint` 时才启用 TLS —— 没有 SNI
///   的 TLS 握手没有意义。想彻底关闭写 `tls: false`。
/// * **UDP 只在 `network: tcp` 下可用**。SS 的 UDP 是原生 UDP 中继，ws / xhttp
///   承载的是 TCP 流，没有 UDP-over-TCP 约定，`dial_udp` 会直接报错。
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProxyConfig {
    /// Node name referenced by rules (`MATCH` / `RULE-SET` outbound).
    #[serde(default)]
    pub name: String,

    #[serde(rename = "type")]
    pub ty: String,
    pub server: String,
    pub port: u16,

    #[serde(default)]
    pub password: Option<String>,

    /// SOCKS5 username (RFC 1929). With `password`; omit both for no-auth.
    /// For `socks4` / `socks4a` it is sent as the USERID field (no password).
    #[serde(default)]
    pub username: Option<String>,

    /// SOCKS protocol version for `type: socks`: `"5"` (default), `"4a"` or `"4"`.
    /// Ignored for the explicit `socks5` / `socks4a` / `socks4` types (a
    /// conflicting value is rejected).
    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub uuid: Option<String>,

    /// VLESS flow，目前仅支持 `xtls-rprx-vision`（XTLS Vision，TCP/REALITY 专用）。
    #[serde(default)]
    pub flow: Option<String>,

    /// VMess 内层加密方式 / Shadowsocks 加密方法（mihomo 字段名 `cipher`，
    /// 别名 `security`；sing-box 的 `method` 也可识别）：
    /// * vmess：`auto`(默认) | `aes-128-gcm` | `chacha20-poly1305` | `none` | `zero`
    ///   （`auto` + tls 时降级为 `zero`，外层 TLS 已加密，内层冗余；仅 AEAD，
    ///   不支持 `aes-128-cfb`）
    /// * shadowsocks：`aes-128-gcm` | `aes-256-gcm` | `chacha20-ietf-poly1305` |
    ///   `2022-blake3-aes-128-gcm` | `2022-blake3-aes-256-gcm` |
    ///   `2022-blake3-chacha20-poly1305` | `none`
    #[serde(default, rename = "cipher", alias = "security", alias = "method")]
    pub cipher: Option<String>,
    /// VMess `alterId`。仅支持 AEAD 模式（0），非 0 在校验阶段 fail-fast。
    #[serde(default, rename = "alter-id", alias = "alterId")]
    pub alter_id: Option<u32>,

    /// Transport: `tcp` (default), `ws`, or `xhttp` (VLESS).
    #[serde(default = "default_network")]
    pub network: String,

    #[serde(default = "default_true")]
    pub tls: bool,

    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default, rename = "servername")]
    pub servername: Option<String>,

    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default, rename = "skip-cert-verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// vless uTLS 浏览器指纹（clash `client-fingerprint` 字段）。
    /// 设置后 VLESS 的 TLS 握手发送浏览器形状的 ClientHello。
    #[serde(default, rename = "client-fingerprint")]
    pub client_fingerprint: Option<String>,

    #[serde(default, rename = "ws-path")]
    pub ws_path: Option<String>,
    #[serde(default, rename = "ws-host")]
    pub ws_host: Option<String>,
    #[serde(default, rename = "ws-headers")]
    pub ws_headers: Option<std::collections::HashMap<String, String>>,

    /// Server x25519 public key (base64 / base64url). Non-empty enables REALITY.
    #[serde(default, rename = "reality-public-key", alias = "public-key")]
    pub reality_public_key: Option<String>,
    /// REALITY shortId (hex, 0..16 chars).
    #[serde(default, rename = "reality-short-id", alias = "short-id")]
    pub reality_short_id: Option<String>,

    /// VLESS ECH（Encrypted Client Hello，RFC 9849/9460）。启用后 rustls 客户端
    /// 用 HPKE 把真实 SNI（inner）加密进 outer ClientHello 的 ECH 扩展，outer
    /// SNI 取 ECH 配置中的 public_name，防止链路观察者看到真实域名。
    /// 仅作用于 rustls TLS 路径：与 REALITY / client-fingerprint (uTLS) 互斥
    /// （构建期 fail-fast）。
    #[serde(default, rename = "ech")]
    pub ech: bool,
    /// ECH 配置（PEM `ECH CONFIGS` 块）。设置后不再走 DNS HTTPS RR。
    #[serde(default, rename = "ech-config")]
    pub ech_config: Option<String>,
    /// ECH 配置文件路径（PEM `ECH CONFIGS` 块）。
    #[serde(default, rename = "ech-config-path")]
    pub ech_config_path: Option<std::path::PathBuf>,
    /// DNS HTTPS RR 获取 ECH 配置时使用的查询域名（默认 sni）。
    #[serde(default, rename = "ech-query-server-name")]
    pub ech_query_server_name: Option<String>,

    /// XHTTP path (default `/`).
    #[serde(default, rename = "xhttp-path", alias = "path")]
    pub xhttp_path: Option<String>,
    /// XHTTP Host header (default: SNI / server).
    #[serde(default, rename = "xhttp-host")]
    pub xhttp_host: Option<String>,
    /// `auto` | `stream-one` | `packet-up` | `stream-up` (currently stream-one over HTTP/1.1).
    #[serde(default, rename = "xhttp-mode")]
    pub xhttp_mode: Option<String>,
    /// Extra XHTTP request headers.
    #[serde(default, rename = "xhttp-headers")]
    pub xhttp_headers: Option<std::collections::HashMap<String, String>>,

    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, rename = "obfs-password")]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub up: Option<String>,
    #[serde(default)]
    pub down: Option<String>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    #[serde(default, rename = "disable-mtu-discovery")]
    pub disable_mtu_discovery: bool,
    #[serde(default, rename = "udp-mtu")]
    pub udp_mtu: Option<u32>,

    /// TUIC 拥塞控制：`cubic`（默认）/ `bbr` / `new_reno`（quinn 无独立实现，
    /// 降级为 cubic）。未知值 fail-fast 拒绝启动。
    #[serde(default, rename = "congestion-control")]
    pub congestion_control: Option<String>,
    /// TUIC 应用层心跳间隔（QUIC datagram Heartbeat 帧），如 `"10s"`；默认 10s。
    /// shadowquic 复用为 QUIC 层 keep-alive 间隔（`"off"` / `"0"` 关闭）。
    #[serde(default)]
    pub heartbeat: Option<String>,

    // ── shadowquic 专用 ────────────────────────────────────────────────────
    /// shadowquic：UDP 走 QUIC stream 而不是 datagram。
    /// `false`（默认）用 datagram（类似 TUIC），`true` 用 uni stream。
    /// 代理 HTTP/3 时建议保持 `false`：over-stream 的重传会与 shadowquic 内部
    /// 拥塞控制冲突，并破坏 HTTP/3 的 MTU 探测。
    #[serde(default, rename = "over-stream")]
    pub over_stream: bool,
    /// shadowquic：0-RTT 握手（默认 true）。
    #[serde(default = "default_true")]
    pub zero_rtt: bool,
    /// shadowquic：QUIC 初始 MTU（默认 1300，必须 >= min-mtu 且 >= 1200）。
    #[serde(default, rename = "initial-mtu")]
    pub initial_mtu: Option<u16>,
    /// shadowquic：QUIC 最小 MTU（默认 1290，必须 >= 1200）。
    #[serde(default, rename = "min-mtu")]
    pub min_mtu: Option<u16>,

    // ── wireguard 专用 ─────────────────────────────────────────────────────
    /// WireGuard 本机私钥（base64，32 字节）。fail-fast 必填。
    #[serde(default, rename = "private-key", alias = "private_key")]
    pub private_key: Option<String>,
    /// WireGuard 对端公钥（base64，32 字节）。fail-fast 必填。
    #[serde(default, rename = "peer-public-key", alias = "peer_public_key")]
    pub peer_public_key: Option<String>,
    /// WireGuard 预共享密钥（可选，base64，32 字节）。
    #[serde(default, rename = "pre-shared-key", alias = "pre_shared_key")]
    pub pre_shared_key: Option<String>,
    /// 本机隧道内地址（含前缀），如 `["10.7.0.2/32", "fd42::2/128"]`。
    /// 至少一个；缺 v4 且目标是 v4 时 dial 报错（fail-fast）。
    #[serde(default, rename = "local-address", alias = "local_address")]
    pub local_address: Vec<String>,
    /// WireGuard 隧道 MTU（默认 1420 = 1500 - 80 WG 开销；不含内核接口 60~80 字节余量）。
    #[serde(default, rename = "mtu")]
    pub wg_mtu: Option<u32>,
    /// 持久保活间隔（秒）。默认 25（wireguard-go `PersistentKeepaliveInterval`），
    /// 0 = 关闭。
    #[serde(default, rename = "persistent-keepalive")]
    pub persistent_keepalive: Option<u16>,
}

/// SOCKS upstream protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V5,
    V4a,
    V4,
}

fn default_network() -> String {
    "tcp".into()
}
fn default_cache_file() -> PathBuf {
    PathBuf::from("cache.db")
}

fn default_true() -> bool {
    true
}

impl ProxyConfig {
    /// Resolve the SOCKS version from `type` (+ `version` for plain `socks`).
    /// Errors for non-socks types or a `version` that conflicts with `type`.
    pub fn socks_version(&self) -> Result<SocksVersion> {
        fn parse(v: &str) -> Result<SocksVersion> {
            match v.trim().to_ascii_lowercase().as_str() {
                "5" | "" => Ok(SocksVersion::V5),
                "4a" => Ok(SocksVersion::V4a),
                "4" => Ok(SocksVersion::V4),
                other => bail!("unsupported socks version `{other}`, expected 5 / 4a / 4"),
            }
        }
        let by_type = match self.ty.to_ascii_lowercase().as_str() {
            "socks5" => Some(SocksVersion::V5),
            "socks4a" => Some(SocksVersion::V4a),
            "socks4" => Some(SocksVersion::V4),
            "socks" => None,
            other => bail!("`{other}` is not a socks type"),
        };
        let by_field = self.version.as_deref().map(parse).transpose()?;
        match (by_type, by_field) {
            (Some(t), Some(f)) if t != f => bail!(
                "type `{}` conflicts with version `{}`",
                self.ty,
                self.version.as_deref().unwrap_or("")
            ),
            (Some(t), _) => Ok(t),
            (None, Some(f)) => Ok(f),
            (None, None) => Ok(SocksVersion::V5),
        }
    }

    pub fn effective_sni(&self) -> String {
        self.sni
            .clone()
            .or_else(|| self.servername.clone())
            .or_else(|| self.ws_host.clone())
            .unwrap_or_else(|| self.server.clone())
    }

    pub fn vless_uuid(&self) -> Result<String> {
        self.uuid
            .clone()
            .or_else(|| self.password.clone())
            .context("vless requires `uuid` (or `password` as uuid)")
    }
}

/// One entry under `rule-providers:`.
///
/// Storage priority for downloaded / loaded payloads:
/// 1. Explicit `path` (highest) — absolute, relative, or `file:/abs/path`
/// 2. Else if top-level `cache: true` — store/load from redb
/// 3. Else — default file `rules/<name>.ars` under the run directory (`-d/--dir` or cwd)
#[derive(Debug, Clone, Deserialize)]
pub struct RuleProviderConfig {
    /// `file` | `http`
    #[serde(default = "default_provider_type", rename = "type")]
    pub ty: String,
    /// `domain` / `ip` / `ipcidr` / `classical`.
    #[serde(default = "default_behavior")]
    pub behavior: String,
    /// Optional format hint: `text` | `yaml` | `json` | `ars` (auto by extension / content).
    #[serde(default)]
    pub format: Option<String>,
    /// Local path or `file:/abs/path`. Optional — see storage priority above.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Remote URL when `type: http`.
    #[serde(default)]
    pub url: Option<String>,
    /// Auto-update interval for remote rule-providers, in **hours** (number only).
    /// `0` or omitted = download once at startup, no periodic refresh.
    #[serde(default, rename = "update-interval")]
    pub update_interval: u64,
}

fn default_provider_type() -> String {
    "file".into()
}

fn default_behavior() -> String {
    "domain".into()
}

/// Where a rule-provider payload is read/written.
#[derive(Debug, Clone)]
pub enum RulesetStorage {
    /// Filesystem path (explicit or default `rules/<name>.ars`).
    File(PathBuf),
    /// redb table key = provider name.
    Db,
}

/// Normalized ruleset descriptor used by the router (derived from rule-providers).
#[derive(Debug, Clone)]
pub struct RulesetConfig {
    pub name: String,
    /// `domain` / `ip` / `classical`.
    pub ty: String,
    pub format: Option<String>,
    /// `file` or `http`.
    pub provider_type: String,
    pub url: Option<String>,
    /// Hours between remote refreshes; 0 = no auto-update.
    pub update_interval: u64,
    pub storage: RulesetStorage,
}

/// Kind of a single route / DNS rule (mihomo-compatible).
#[derive(Debug, Clone)]
pub enum RuleKind {
    RuleSet(String),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    IpCidr(String),
    SrcIpCidr(String),
    Match,
}

/// Parsed mihomo-style rule line.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub kind: RuleKind,
    /// Normalized outbound: `direct` / `block` / node name.
    pub outbound: String,
    /// Skip domain→IP resolve for this rule (`no-resolve` flag).
    pub no_resolve: bool,
}

impl ParsedRule {
    pub fn is_match(&self) -> bool {
        matches!(self.kind, RuleKind::Match)
    }
    pub fn ruleset_name(&self) -> Option<&str> {
        match &self.kind {
            RuleKind::RuleSet(n) => Some(n.as_str()),
            _ => None,
        }
    }
}

/// Outbound names that cannot be used as proxy node names. Case-insensitive:
/// `direct`/`DIRECT`, `block`/`BLOCK`, `reject`/`REJECT` (+ internal `final`,
/// `proxy`) are all reserved.
pub const RESERVED_OUTBOUND_NAMES: &[&str] = &["direct", "block", "final", "proxy", "reject"];

/// Normalize reserved outbound aliases (`DIRECT`→`direct`, `REJECT`→`block`).
pub fn normalize_outbound_name(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "direct" => "direct".into(),
        "reject" | "block" => "block".into(),
        _ => s.to_string(),
    }
}

fn is_no_resolve_flag(s: &str) -> bool {
    s.eq_ignore_ascii_case("no-resolve")
}

/// Parse a single mihomo-style rule string.
///
/// Supported: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX,
/// IP-CIDR, IP-CIDR6, SRC-IP-CIDR, RULE-SET, MATCH.
/// Trailing `no-resolve` skips domain→IP resolution when `route-resolve: true`.
pub fn parse_rule_line(line: &str) -> Result<ParsedRule> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty rule line");
    }
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        bail!("empty rule line");
    }
    let kind = parts[0].to_ascii_uppercase();
    // Collect no-resolve from any trailing field after the required ones.
    let no_resolve = parts.iter().skip(1).any(|p| is_no_resolve_flag(p));
    // Filter no-resolve out of payload/outbound slots for indexing.
    let core: Vec<&str> = parts.iter().copied().filter(|p| !is_no_resolve_flag(p)).collect();
    match kind.as_str() {
        "RULE-SET" => {
            if core.len() < 3 {
                bail!("RULE-SET needs name and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::RuleSet(core[1].to_string()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "MATCH" => {
            if core.len() < 2 {
                bail!("MATCH needs outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::Match,
                outbound: normalize_outbound_name(core[1]),
                no_resolve: false,
            })
        }
        "DOMAIN" => {
            if core.len() < 3 {
                bail!("DOMAIN needs domain and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::Domain(core[1].to_ascii_lowercase()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "DOMAIN-SUFFIX" => {
            if core.len() < 3 {
                bail!("DOMAIN-SUFFIX needs suffix and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::DomainSuffix(core[1].trim_start_matches('.').to_ascii_lowercase()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "DOMAIN-KEYWORD" => {
            if core.len() < 3 {
                bail!("DOMAIN-KEYWORD needs keyword and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::DomainKeyword(core[1].to_ascii_lowercase()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "DOMAIN-REGEX" => {
            if core.len() < 3 {
                bail!("DOMAIN-REGEX needs regex and outbound, got: {line}");
            }
            regex::Regex::new(core[1])
                .with_context(|| format!("invalid DOMAIN-REGEX: {}", core[1]))?;
            Ok(ParsedRule {
                kind: RuleKind::DomainRegex(core[1].to_string()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "IP-CIDR" | "IP-CIDR6" => {
            if core.len() < 3 {
                bail!("{kind} needs cidr and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::IpCidr(core[1].to_string()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            if core.len() < 3 {
                bail!("{kind} needs cidr and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::SrcIpCidr(core[1].to_string()),
                outbound: normalize_outbound_name(core[2]),
                no_resolve,
            })
        }
        other => bail!(
            "unsupported rule type `{other}`: {line}\n\
             supported: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, \
             IP-CIDR, IP-CIDR6, SRC-IP-CIDR, RULE-SET, MATCH"
        ),
    }
}


/// Strip optional `file:` / `file://` prefix from a path string.
fn strip_file_scheme(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("file://") {
        return rest;
    }
    if let Some(rest) = s.strip_prefix("file:") {
        return rest;
    }
    s
}

/// Resolve where a rule-provider is stored.
///
/// Priority:
/// 1. Explicit `path` (highest)
/// 2. `cache: true` → redb
/// 3. Default file `rules/<name>.ars` under `base_dir`
pub fn resolve_ruleset_storage(
    name: &str,
    rp: &RuleProviderConfig,
    base_dir: &std::path::Path,
    global_cache: bool,
) -> RulesetStorage {
    if let Some(ref path) = rp.path {
        let raw = path.to_string_lossy();
        let stripped = strip_file_scheme(&raw);
        let p = PathBuf::from(stripped);
        let abs = if p.is_absolute() {
            p
        } else {
            base_dir.join(p)
        };
        return RulesetStorage::File(abs);
    }
    if global_cache {
        return RulesetStorage::Db;
    }
    RulesetStorage::File(base_dir.join("rules").join(format!("{name}.ars")))
}

fn normalize_behavior(behavior: &str) -> Result<String> {
    match behavior.to_ascii_lowercase().as_str() {
        "domain" => Ok("domain".into()),
        "ip" | "ipcidr" | "ip-cidr" => Ok("ip".into()),
        "classical" => Ok("classical".into()),
        other => bail!(
            "rule-provider behavior must be domain, ip/ipcidr, or classical, got `{other}`"
        ),
    }
}

/// Parsed `dns.rules` line (used when `rule-follow-route: false`).
#[derive(Debug, Clone)]
pub struct ParsedDnsRule {
    pub kind: RuleKind,
    /// Raw upstream value: a nameserver URL or `rcode://success`.
    pub upstream: String,
}

impl ParsedDnsRule {
    pub fn is_match(&self) -> bool {
        matches!(self.kind, RuleKind::Match)
    }
    pub fn ruleset_name(&self) -> Option<&str> {
        match &self.kind {
            RuleKind::RuleSet(n) => Some(n.as_str()),
            _ => None,
        }
    }
}

/// Parse a `dns.rules` line. Same rule types as route; last field is upstream
/// (nameserver URL or `rcode://success`), never an outbound name.
pub fn parse_dns_rule_line(line: &str) -> Result<ParsedDnsRule> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty dns rule line");
    }
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        bail!("empty dns rule line");
    }
    let kind = parts[0].to_ascii_uppercase();
    // 与文档一致：关键字只能大写（RULE-SET / MATCH / DOMAIN...），
    // 小写直接拒绝而不是静默归一化。
    if parts[0] != kind {
        bail!(
            "dns rules keyword must be uppercase, got `{}` (expected `{kind}`)",
            parts[0]
        );
    }
    match kind.as_str() {
        "RULE-SET" => {
            if parts.len() < 3 {
                bail!("dns rules `RULE-SET` needs <name>,<upstream>, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::RuleSet(parts[1].to_string()),
                upstream: parts[2].to_string(),
            })
        }
        "MATCH" => {
            if parts.len() < 2 {
                bail!("dns rules `MATCH` needs <upstream>, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::Match,
                upstream: parts[1].to_string(),
            })
        }
        "DOMAIN" => {
            if parts.len() < 3 {
                bail!("dns rules DOMAIN needs domain and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::Domain(parts[1].to_ascii_lowercase()),
                upstream: parts[2].to_string(),
            })
        }
        "DOMAIN-SUFFIX" => {
            if parts.len() < 3 {
                bail!("dns rules DOMAIN-SUFFIX needs suffix and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::DomainSuffix(parts[1].trim_start_matches('.').to_ascii_lowercase()),
                upstream: parts[2].to_string(),
            })
        }
        "DOMAIN-KEYWORD" => {
            if parts.len() < 3 {
                bail!("dns rules DOMAIN-KEYWORD needs keyword and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::DomainKeyword(parts[1].to_ascii_lowercase()),
                upstream: parts[2].to_string(),
            })
        }
        "DOMAIN-REGEX" => {
            if parts.len() < 3 {
                bail!("dns rules DOMAIN-REGEX needs regex and upstream, got: {line}");
            }
            regex::Regex::new(parts[1])
                .with_context(|| format!("invalid DOMAIN-REGEX: {}", parts[1]))?;
            Ok(ParsedDnsRule {
                kind: RuleKind::DomainRegex(parts[1].to_string()),
                upstream: parts[2].to_string(),
            })
        }
        "IP-CIDR" | "IP-CIDR6" => {
            if parts.len() < 3 {
                bail!("dns rules {kind} needs cidr and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::IpCidr(parts[1].to_string()),
                upstream: parts[2].to_string(),
            })
        }
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            if parts.len() < 3 {
                bail!("dns rules {kind} needs cidr and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::SrcIpCidr(parts[1].to_string()),
                upstream: parts[2].to_string(),
            })
        }
        other => bail!(
            "dns rules: unsupported type `{other}` (got: {line})\n\
             supported: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, \
             IP-CIDR, SRC-IP-CIDR, RULE-SET, MATCH"
        ),
    }
}

/// Ensure a cargo feature was enabled at compile time. Used by config
/// validation so misconfigured binaries fail fast with a clear message.
fn require_feature(what: &str, feature: &str) -> Result<()> {
    let enabled = match feature {
        "tuic" => cfg!(feature = "tuic"),
        "anytls" => cfg!(feature = "anytls"),
        "naive" => cfg!(feature = "naive"),
        "shadowquic" => cfg!(feature = "shadowquic"),
        "vmess" => cfg!(feature = "vmess"),
        "shadowsocks" => cfg!(feature = "shadowsocks"),
        "socks" => cfg!(feature = "socks"),
        "trojan" => cfg!(feature = "trojan"),
        "wireguard" => cfg!(feature = "wireguard"),
        "tun" => cfg!(feature = "tun"),
        "api" => cfg!(feature = "api"),
        "cache" => cfg!(feature = "cache"),
        _ => false,
    };
    if enabled {
        Ok(())
    } else {
        bail!(
            "`{what}` is not included in this build; \
             recompile with `--features {feature}` (or `--features full`)"
        )
    }
}

/// Validate a `dns.rules` upstream value: `rcode://success` or a parseable
/// nameserver URL (udp/tcp/tls/https). Outbound names — reserved words and
/// `proxies` node names — are rejected (fail-fast).
pub fn validate_dns_upstream(upstream: &str, node_names: &[String]) -> Result<()> {
    let lower = upstream.trim().to_ascii_lowercase();
    if lower == "rcode://success" {
        return Ok(());
    }
    if RESERVED_OUTBOUND_NAMES.contains(&lower.as_str())
        || node_names.iter().any(|n| n.to_ascii_lowercase() == lower)
    {
        bail!(
            "dns rules upstream must be a nameserver url or rcode://success, \
             not an outbound name (got `{upstream}`)"
        );
    }
    crate::dns::parse_nameserver(upstream)
        .with_context(|| format!("dns rules upstream `{upstream}`"))
        .map(|_| ())
}

fn known_has(known: &[String], name: &str) -> bool {
    known.iter().any(|k| k.eq_ignore_ascii_case(name))
}

impl Config {
    /// All routable outbound names: reserved + node names + group names.
    pub fn outbound_names(&self) -> Vec<String> {
        RESERVED_OUTBOUND_NAMES
            .iter()
            .filter(|n| **n != "final" && **n != "proxy" && **n != "reject")
            .map(|s| s.to_string())
            .chain(self.proxies.iter().map(|p| p.name.clone()))
            .chain(self.proxy_groups.iter().map(|g| g.name.clone()))
            .collect()
    }

    /// Rulesets derived from `rule-providers` for the router.
    ///
    /// `base_dir`: `-d/--dir` or cwd — used for relative / default paths.
    pub fn ruleset_list(&self, base_dir: Option<&std::path::Path>) -> Result<Vec<RulesetConfig>> {
        let base = base_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let mut out = Vec::with_capacity(self.rule_providers.len());
        for (name, rp) in &self.rule_providers {
            let pty = rp.ty.to_ascii_lowercase();
            if pty != "file" && pty != "http" {
                bail!(
                    "rule-provider `{name}`: type must be `file` or `http` (got `{}`)",
                    rp.ty
                );
            }
            if pty == "http" && rp.url.as_ref().map(|u| u.trim().is_empty()).unwrap_or(true) {
                bail!("rule-provider `{name}`: type http requires `url`");
            }
            let storage = resolve_ruleset_storage(name, rp, &base, self.global.cache);
            out.push(RulesetConfig {
                name: name.clone(),
                ty: normalize_behavior(&rp.behavior)?,
                format: rp.format.clone(),
                provider_type: pty,
                url: rp.url.clone(),
                update_interval: rp.update_interval,
                storage,
            });
        }
        Ok(out)
    }

    /// Absolute path for the shared redb cache database.
    pub fn cache_db_path(&self, base_dir: Option<&std::path::Path>) -> PathBuf {
        let p = &self.global.cache_file;
        if p.is_absolute() {
            p.clone()
        } else if let Some(base) = base_dir {
            base.join(p)
        } else {
            p.clone()
        }
    }

    /// Parse and validate all `route:` lines.
    pub fn parsed_rules(&self) -> Result<Vec<ParsedRule>> {
        self.route
            .iter()
            .map(|line| parse_rule_line(line))
            .collect()
    }

    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {path}"))?;
        let mut cfg: Config = serde_yaml::from_str(&raw).context("parse YAML config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve rule-provider paths against a base directory (`-d/--dir` mode):
    /// relative paths (`cn.ars`, `./rules/cn.ars`, `rules/cn.ars`, deeper
    /// nesting alike) are joined onto `base_dir`; absolute paths are untouched.
    pub fn resolve_ruleset_paths(&mut self, base_dir: &std::path::Path) {
        for rp in self.rule_providers.values_mut() {
            if let Some(ref path) = rp.path {
                let raw = path.to_string_lossy();
                let stripped = strip_file_scheme(&raw);
                let p = PathBuf::from(stripped);
                if p.is_relative() {
                    rp.path = Some(base_dir.join(p));
                } else {
                    rp.path = Some(p);
                }
            }
        }
    }

    fn validate(&mut self) -> Result<()> {
        if self.proxies.is_empty() {
            bail!("at least one proxy node under `proxies:` is required");
        }
        for (i, p) in self.proxies.iter().enumerate() {
            let label = if p.name.is_empty() {
                format!("proxies[{i}]")
            } else {
                p.name.clone()
            };
            if p.name.is_empty() {
                bail!("proxies[{i}] requires a non-empty `name`");
            }
            if RESERVED_OUTBOUND_NAMES.contains(&p.name.to_ascii_lowercase().as_str()) {
                bail!("proxy node name `{}` is reserved", p.name);
            }
            match p.ty.to_lowercase().as_str() {
                "hysteria2" => {
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("hysteria2 node `{label}` requires password");
                    }
                }
                // `tuic` / `anytls` 之前漏了这两个分支，节点会被 `other` 分支当成
                // 不支持的类型拒掉（尽管 OutboundManager 已经能构造它们）。
                "tuic" => {
                    require_feature("tuic", "tuic")?;
                    if p.uuid.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("tuic node `{label}` requires uuid");
                    }
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("tuic node `{label}` requires password");
                    }
                }
                "anytls" => {
                    require_feature("anytls", "anytls")?;
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("anytls node `{label}` requires password");
                    }
                }
                "shadowquic" => {
                    require_feature("shadowquic", "shadowquic")?;
                    // JLS 认证：username(user iv) + password(JLS pwd) 同时参与
                    // QUIC/TLS 层握手，缺任何一个服务端都无法识别。
                    if p.username.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("shadowquic node `{label}` requires username");
                    }
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("shadowquic node `{label}` requires password");
                    }
                    // SNI 必须等于服务端 jls-upstream 的域名；不能退化成 IP。
                    let sni = p
                        .sni
                        .as_deref()
                        .or(p.servername.as_deref())
                        .unwrap_or("");
                    if sni.is_empty() {
                        bail!("shadowquic node `{label}` requires sni (must match the server's jls-upstream domain)");
                    }
                    if let Some(m) = p.min_mtu {
                        if m < 1200 {
                            bail!("shadowquic node `{label}`: min-mtu must be >= 1200");
                        }
                    }
                    if let Some(m) = p.initial_mtu {
                        if m < p.min_mtu.unwrap_or(1290) {
                            bail!("shadowquic node `{label}`: initial-mtu must be >= min-mtu");
                        }
                    }
                }
                "naive" => {
                    require_feature("naive", "naive")?;
                    // NaiveProxy 必然是 TLS + HTTP/2 CONNECT，且必须有 Basic 认证。
                    if !p.tls {
                        bail!("naive node `{label}`: `tls: false` is invalid (naive is always TLS)");
                    }
                    if p.username.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("naive node `{label}` requires username");
                    }
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("naive node `{label}` requires password");
                    }
                }
                "vless" => {
                    let _ = p.vless_uuid().with_context(|| format!("node `{label}`"))?;
                    let net = p.network.to_lowercase();
                    if net != "tcp" && net != "ws" && net != "xhttp" {
                        bail!(
                            "vless node `{label}` network must be \"tcp\", \"ws\" or \"xhttp\", got {}",
                            p.network
                        );
                    }
                    if let Some(pk) = &p.reality_public_key {
                        if pk.is_empty() {
                            bail!("reality-public-key must not be empty when set");
                        }
                    }
                    if p.ech {
                        if p.reality_public_key.is_some() {
                            bail!(
                                "vless node `{label}`: ech cannot be combined with \
                                 reality-public-key (REALITY is self-implemented TLS 1.3, \
                                 not the rustls ECH path)"
                            );
                        }
                        if !p.tls {
                            bail!("vless node `{label}`: ech requires tls");
                        }
                        if p.client_fingerprint.is_some() {
                            bail!(
                                "vless node `{label}`: ech cannot be combined with \
                                 client-fingerprint (uTLS patches the ClientHello, rustls \
                                 ECH constructs its own)"
                            );
                        }
                    }
                }
                "vmess" => {
                    require_feature("vmess", "vmess")?;
                    if p.uuid
                        .as_ref()
                        .or(p.password.as_ref())
                        .map(|s| s.is_empty())
                        .unwrap_or(true)
                    {
                        bail!("vmess node `{label}` requires uuid (or password as uuid)");
                    }
                    let net = p.network.to_lowercase();
                    if net != "tcp" && net != "ws" && net != "xhttp" {
                        bail!(
                            "vmess node `{label}` network must be \"tcp\", \"ws\" or \"xhttp\", got {}",
                            p.network
                        );
                    }
                    // 只实现 AEAD（alterId = 0）；旧 MD5 认证头不支持。
                    if let Some(alter) = p.alter_id {
                        if alter != 0 {
                            bail!(
                                "vmess node `{label}`: alterId={alter} is not supported \
                                 (only AEAD / alterId=0)"
                            );
                        }
                    }
                }
                "trojan" => {
                    require_feature("trojan", "trojan")?;
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("trojan node `{label}` requires password");
                    }
                    let net = p.network.to_lowercase();
                    if net != "tcp" && net != "ws" && net != "xhttp" {
                        bail!(
                            "trojan node `{label}` network must be \"tcp\", \"ws\" or \"xhttp\", got {}",
                            p.network
                        );
                    }
                }
                "shadowsocks" | "ss" => {
                    require_feature("shadowsocks", "shadowsocks")?;
                    if p.password.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        bail!("shadowsocks node `{label}` requires password");
                    }
                    let method = p
                        .cipher
                        .as_deref()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .with_context(|| {
                            format!("shadowsocks node `{label}` requires `cipher` (or `method`)")
                        })?;
                    #[cfg(feature = "shadowsocks")]
                    crate::outbound::validate_ss_method(method)
                        .with_context(|| format!("shadowsocks node `{label}`"))?;
                    #[cfg(not(feature = "shadowsocks"))]
                    let _ = method;
                    let net = p.network.to_lowercase();
                    if net != "tcp" && net != "ws" && net != "xhttp" {
                        bail!(
                            "shadowsocks node `{label}` network must be \"tcp\", \"ws\" or \"xhttp\", got {}",
                            p.network
                        );
                    }
                    if p.client_fingerprint.is_some() && !p.tls {
                        bail!("shadowsocks node `{label}`: client-fingerprint requires tls");
                    }
                }
                "socks5" | "socks" | "socks4" | "socks4a" => {
                    require_feature("socks", "socks")?;
                    if p.server.is_empty() {
                        bail!("socks node `{label}` requires server");
                    }
                    let ver = p.socks_version().with_context(|| format!("node `{label}`"))?;
                    let u = p.username.as_deref().unwrap_or("");
                    let pw = p.password.as_deref().unwrap_or("");
                    if u.len() > 255 || pw.len() > 255 {
                        bail!("socks node `{label}`: username/password must be <= 255 bytes");
                    }
                    if ver != SocksVersion::V5 {
                        if u.as_bytes().contains(&0) {
                            bail!("socks4 node `{label}`: username (USERID) must not contain NUL");
                        }
                        if !pw.is_empty() {
                            tracing::warn!(
                                "socks4 node `{label}`: SOCKS4 has no password auth, `password` is ignored"
                            );
                        }
                    }
                }
                "wireguard" => {
                    require_feature("wireguard", "wireguard")?;
                    use base64::Engine;
                    if p.server.is_empty() {
                        bail!("wireguard node `{label}` requires server");
                    }
                    if p.port == 0 {
                        bail!("wireguard node `{label}` requires a non-zero port");
                    }
                    let key_ok = |s: Option<&str>| {
                        s.and_then(|s| {
                            base64::engine::general_purpose::STANDARD
                                .decode(s.trim())
                                .ok()
                                .filter(|b| b.len() == 32)
                        })
                        .is_some()
                    };
                    if !key_ok(p.private_key.as_deref()) {
                        bail!(
                            "wireguard node `{label}` requires `private-key` \
                             (base64, exactly 32 bytes)"
                        );
                    }
                    if !key_ok(p.peer_public_key.as_deref()) {
                        bail!(
                            "wireguard node `{label}` requires `peer-public-key` \
                             (base64, exactly 32 bytes)"
                        );
                    }
                    if p.pre_shared_key.is_some() && !key_ok(p.pre_shared_key.as_deref()) {
                        bail!(
                            "wireguard node `{label}`: `pre-shared-key` must be \
                             base64 of exactly 32 bytes"
                        );
                    }
                    if p.local_address.is_empty() {
                        bail!(
                            "wireguard node `{label}` requires `local-address` \
                             (e.g. [\"10.7.0.2/32\"])"
                        );
                    }
                    for cidr in &p.local_address {
                        if cidr.parse::<ipnet::IpNet>().is_err() {
                            bail!(
                                "wireguard node `{label}`: invalid local-address `{cidr}` \
                                 (expected CIDR like 10.7.0.2/32)"
                            );
                        }
                    }
                    if let Some(mtu) = p.wg_mtu {
                        // 最小合法 IP 包 576(RFC 791) 对应 WG MTU 576；上限受 WG
                        // 数据包 65535 限制（IP 包 + 32 字节封装头）
                        if !(576..=65000).contains(&mtu) {
                            bail!(
                                "wireguard node `{label}`: mtu {mtu} out of range [576, 65000]"
                            );
                        }
                    }
                }
                other => bail!("proxy node `{label}`: unsupported type={other}; use hysteria2, tuic, anytls, naive, vless, vmess, trojan, shadowsocks, socks5, socks4, socks4a or wireguard"),
            }
        }
        let names: Vec<&str> = self.proxies.iter().map(|p| p.name.as_str()).collect();
        if names.len() != names.iter().collect::<std::collections::HashSet<_>>().len() {
            bail!("duplicate proxy node name in proxies");
        }

        // --- proxy-groups ---
        let mut group_names = std::collections::HashSet::new();
        for (i, g) in self.proxy_groups.iter().enumerate() {
            if g.name.trim().is_empty() {
                bail!("proxy-groups[{i}] requires a non-empty `name`");
            }
            // Only direct/block/reject are reserved for groups. Names like
            // `PROXY` / `proxy` are allowed (mihomo-compatible); `final`/`proxy`
            // remain reserved only for leaf `proxies:` node names.
            if ["direct", "block", "reject"]
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&g.name))
            {
                bail!(
                    "proxy-groups[{i}]: name `{}` is reserved (direct/block/reject)",
                    g.name
                );
            }
            if names.iter().any(|n| n.eq_ignore_ascii_case(&g.name)) {
                bail!(
                    "proxy-groups[{i}]: name `{}` collides with a proxies node",
                    g.name
                );
            }
            if !group_names.insert(g.name.to_ascii_lowercase()) {
                bail!("duplicate proxy-group name `{}`", g.name);
            }
            let ty = g.ty.to_ascii_lowercase();
            if !matches!(
                ty.as_str(),
                "select"
                    | "url-test"
                    | "urltest"
                    | "fallback"
                    | "load-balance"
                    | "loadbalance"
                    | "relay"
            ) {
                bail!(
                    "proxy-groups[{i}] (`{}`): unsupported type `{}`                      (supported: select, url-test, fallback, load-balance, relay)",
                    g.name,
                    g.ty
                );
            }
            if g.proxies.is_empty()
                && g.r#use.is_empty()
                && !g.include_all_proxies
                && !g.include_all_providers
            {
                bail!(
                    "proxy-groups[{i}] (`{}`): need `proxies`, `use`, or include-all-*",
                    g.name
                );
            }
            for u in &g.r#use {
                if !self.proxy_providers.contains_key(u) {
                    bail!(
                        "proxy-groups[{i}] (`{}`): unknown proxy-provider `{u}`",
                        g.name
                    );
                }
            }
            if let Some(st) = &g.strategy {
                let s = st.to_ascii_lowercase();
                if !matches!(
                    s.as_str(),
                    "round-robin" | "roundrobin" | "consistent-hashing" | "consistenthashing" | "sticky-sessions" | "stickysessions"
                ) {
                    bail!(
                        "proxy-groups[{i}] (`{}`): unsupported strategy `{st}`",
                        g.name
                    );
                }
            }
        }
        // proxy-providers
        for (name, pp) in &self.proxy_providers {
            let ty = pp.ty.to_ascii_lowercase();
            if ty != "file" {
                bail!("proxy-providers.`{name}`: only type `file` is supported (got `{ty}`)");
            }
            if pp.path.as_ref().map(|p| p.as_os_str().is_empty()).unwrap_or(true) {
                bail!("proxy-providers.`{name}`: `path` is required for type file");
            }
        }
        // Member references: node / group / DIRECT / REJECT. Groups may
        // reference each other; cycles are rejected after building the graph.
        let all_group: std::collections::HashSet<String> = self
            .proxy_groups
            .iter()
            .map(|g| g.name.to_ascii_lowercase())
            .collect();
        let all_node: std::collections::HashSet<String> = self
            .proxies
            .iter()
            .map(|p| p.name.to_ascii_lowercase())
            .collect();
        for (i, g) in self.proxy_groups.iter().enumerate() {
            for m in &g.proxies {
                let key = m.to_ascii_lowercase();
                if key == "direct" || key == "reject" || key == "block" {
                    continue;
                }
                if all_node.contains(&key) || all_group.contains(&key) {
                    continue;
                }
                // May come from a proxy-provider loaded at runtime.
                if !self.proxy_providers.is_empty() || g.include_all_providers {
                    continue;
                }
                bail!(
                    "proxy-groups[{i}] (`{}`): unknown member `{m}`                      (must be a proxies name, another group, DIRECT, or REJECT)",
                    g.name
                );
            }
            if let Some(sel) = &g.selected {
                let key = sel.to_ascii_lowercase();
                let ok = g.proxies.iter().any(|m| m.eq_ignore_ascii_case(sel))
                    || key == "direct"
                    || key == "reject"
                    || key == "block";
                if !ok {
                    bail!(
                        "proxy-groups[{i}] (`{}`): selected `{sel}` is not in proxies list",
                        g.name
                    );
                }
            }
        }
        // Simple cycle detection among groups.
        {
            use std::collections::HashMap;
            let mut edges: HashMap<String, Vec<String>> = HashMap::new();
            for g in &self.proxy_groups {
                let from = g.name.to_ascii_lowercase();
                let deps: Vec<String> = g
                    .proxies
                    .iter()
                    .map(|m| m.to_ascii_lowercase())
                    .filter(|m| all_group.contains(m))
                    .collect();
                edges.insert(from, deps);
            }
            fn has_cycle(
                node: &str,
                edges: &HashMap<String, Vec<String>>,
                stack: &mut std::collections::HashSet<String>,
                seen: &mut std::collections::HashSet<String>,
            ) -> bool {
                if !stack.insert(node.to_string()) {
                    return true;
                }
                if seen.insert(node.to_string()) {
                    if let Some(deps) = edges.get(node) {
                        for d in deps {
                            if has_cycle(d, edges, stack, seen) {
                                return true;
                            }
                        }
                    }
                }
                stack.remove(node);
                false
            }
            let mut seen = std::collections::HashSet::new();
            let mut stack = std::collections::HashSet::new();
            for g in edges.keys() {
                if has_cycle(g, &edges, &mut stack, &mut seen) {
                    bail!("proxy-groups: cycle detected involving `{g}`");
                }
            }
        }

        let known = self.outbound_names();

        // TUN / API / cache require matching cargo features.
        if self.tun.enable {
            require_feature("tun", "tun")?;
        }
        if !self.global.api.trim().is_empty() {
            require_feature("api", "api")?;
        }
        if self.global.cache {
            require_feature("cache", "cache")?;
        }

        // 端口 fail-fast：显式 0 一律拒绝；想关闭某个入站就省略字段。
        if self.global.mixed_port == Some(0) {
            bail!("mixed-port cannot be 0; omit the field to disable the inbound");
        }
        if self.global.http_port == Some(0) {
            bail!("http-port cannot be 0; omit the field to disable the inbound");
        }
        if self.global.socks_port == Some(0) {
            bail!("socks-port cannot be 0; omit the field to disable the inbound");
        }
        if self.global.tproxy_port == Some(0) {
            bail!("tproxy-port cannot be 0; omit the field to disable the inbound");
        }
        if self.global.redir_port == Some(0) {
            bail!("redir-port cannot be 0; omit the field to disable the inbound");
        }
        if self.dns.port == Some(0) {
            bail!("dns.port cannot be 0; omit `port` (hijack-only mode) or the whole dns block");
        }
        // bind-address: only 0.0.0.0 (LAN) or 127.0.0.1 (loopback).
        // Dual-stack vs IPv4-only is controlled solely by top-level `ipv6`.
        {
            let b = self.global.bind_address.trim();
            if b == "localhost" {
                self.global.bind_address = "127.0.0.1".into();
            } else if b != "0.0.0.0" && b != "127.0.0.1" {
                bail!(
                    "bind-address must be \"0.0.0.0\" or \"127.0.0.1\" (got `{b}`); \
                     use top-level `ipv6: true/false` to control IPv6 listening"
                );
            } else {
                self.global.bind_address = b.to_string();
            }
        }
        // DNS 模块关闭时，任何依赖 DNS 模块应答的劫持路径都必须为空（fail-fast）。
        if !self.dns.enable {
            if self.dns.route_hijack {
                bail!("dns.route-hijack requires dns.enable=true (DNS module is disabled)");
            }
            if !self.tun.dns_hijack.is_empty() {
                bail!("tun.dns-hijack requires dns.enable=true (DNS module is disabled)");
            }
        }
        self.global.api_secret = self.global.api_secret.trim().to_string();

        if self.dns.enable {
            let mode = self.dns.mode.to_ascii_lowercase();
            if mode != "redir-host" && mode != "fakeip" {
                bail!("dns.mode must be redir-host or fakeip");
            }
            self.dns.mode = mode;
            // Effective DNS IPv6: top-level ipv6=false forces A-only regardless of dns.ipv6.
            let effective_dns_ipv6 = self.global.ipv6 && self.dns.ipv6;
            if self.dns.mode == "fakeip" {
                if self.dns.fakeip_range.as_ref().map(|s| s.is_empty()).unwrap_or(true)
                    && self.dns.fakeip6_range.as_ref().map(|s| s.is_empty()).unwrap_or(true)
                {
                    bail!("fakeip mode requires fakeip-range and/or fakeip6-range");
                }
                if let Some(r) = &self.dns.fakeip_range {
                    r.parse::<ipnet::IpNet>().map_err(|e| anyhow::anyhow!("fakeip-range: {e}"))?;
                }
                if let Some(r) = &self.dns.fakeip6_range {
                    r.parse::<ipnet::IpNet>().map_err(|e| anyhow::anyhow!("fakeip6-range: {e}"))?;
                }
                if !effective_dns_ipv6
                    && self.dns.fakeip_range.as_ref().map(|s| s.is_empty()).unwrap_or(true)
                {
                    bail!("ipv6=false requires fakeip-range");
                }
                let fmode = self.dns.fakeip_filter_mode.to_ascii_lowercase();
                if fmode != "blacklist" && fmode != "whitelist" {
                    bail!("dns.fakeip-filter-mode must be blacklist or whitelist");
                }
                self.dns.fakeip_filter_mode = fmode;
                if self.dns.fakeip_filter_mode == "whitelist" && self.dns.fakeip_filter.is_empty() {
                    bail!("fakeip-filter-mode=whitelist requires non-empty fakeip-filter");
                }
            }
            let bootstrap = self
                .dns
                .default_nameserver
                .as_deref()
                .context("dns.enable=true requires dns.default-nameserver")?;
            crate::dns::parse_nameserver(bootstrap).context("invalid default-nameserver")?;
            // default-nameserver 是 bootstrap 本身，不能依赖任何解析：必须是纯 IP。
            {
                let raw = bootstrap.trim();
                let host_part = raw.rsplit("://").next().unwrap_or(raw);
                let host_part = host_part.split('/').next().unwrap_or(host_part);
                let host = if let Some(end) = host_part.find(']') {
                    &host_part[1..end]
                } else {
                    host_part.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_part)
                };
                if host.parse::<std::net::IpAddr>().is_err() {
                    bail!("default-nameserver must be a pure IP address (got {host})");
                }
            }
        }

        // rule-providers: .ars binary or plaintext (yaml/json/list/text)
        let rulesets = self.ruleset_list(None)?;
        let ruleset_names: std::collections::HashSet<&str> =
            rulesets.iter().map(|r| r.name.as_str()).collect();

        // route（原 rules:，出站可为 direct/block/reject 别名或节点名）
        if self.route.is_empty() {
            bail!("route must not be empty; need a final MATCH rule");
        }
        let parsed = self.parsed_rules()?;
        let last = parsed.last().unwrap();
        if !last.is_match() {
            bail!("last route rule must be MATCH,<outbound>");
        }
        for (i, r) in parsed.iter().enumerate() {
            if i + 1 == parsed.len() {
                continue;
            }
            if r.is_match() {
                bail!("MATCH is only allowed as the last route rule (found at route[{i}])");
            }
            if let Some(name) = r.ruleset_name() {
                if !ruleset_names.contains(name) {
                    bail!("route[{i}]: unknown rule-provider `{name}`");
                }
            }
            if !known_has(&known, &r.outbound) {
                bail!(
                    "route[{i}]: unknown outbound `{}`; use direct/DIRECT, block/BLOCK, \
                     reject/REJECT, a proxies name, or a proxy-groups name",
                    r.outbound
                );
            }
        }
        if !known_has(&known, &last.outbound) {
            bail!(
                "MATCH: unknown outbound `{}`; use direct/DIRECT, block/BLOCK, \
                 reject/REJECT, a proxies name, or a proxy-groups name",
                last.outbound
            );
        }

        // DNS 出站选择策略校验（rule-follow-route / dns.rules / nameserver）
        if self.dns.enable && self.dns.rule_follow_route {
            if !self.dns.rules.is_empty() {
                bail!("dns.rules is only used with rule-follow-route=false");
            }
            if self.dns.nameserver.is_some() {
                bail!("dns.nameserver is only used with rule-follow-route=false");
            }
            let direct = self
                .dns
                .direct_nameserver
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if direct.is_empty() {
                bail!("rule-follow-route=true requires dns.direct-nameserver");
            }
            let proxy = self
                .dns
                .proxy_nameserver
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if proxy.is_empty() {
                bail!("rule-follow-route=true requires dns.proxy-nameserver");
            }
            crate::dns::parse_nameserver(&direct).context("invalid direct-nameserver")?;
            crate::dns::parse_nameserver(&proxy).context("invalid proxy-nameserver")?;
        } else if self.dns.enable {
            if self.dns.direct_nameserver.is_some() || self.dns.proxy_nameserver.is_some() {
                bail!(
                    "direct-nameserver/proxy-nameserver are only used with \
                     rule-follow-route=true; use dns.rules + nameserver instead"
                );
            }
            let node_names: Vec<String> = self.proxies.iter().map(|p| p.name.clone()).collect();
            for (i, line) in self.dns.rules.iter().enumerate() {
                let r = parse_dns_rule_line(line).with_context(|| format!("dns.rules[{i}]"))?;
                if r.is_match() && i + 1 != self.dns.rules.len() {
                    bail!("dns.rules[{i}]: MATCH is only allowed as the last dns rule");
                }
                if let Some(name) = r.ruleset_name() {
                    let rs = rulesets
                        .iter()
                        .find(|rs| rs.name == name)
                        .ok_or_else(|| {
                            anyhow::anyhow!("dns.rules[{i}] references unknown rule-provider {name}")
                        })?;
                    if rs.ty != "domain" && rs.ty != "classical" {
                        bail!("dns.rules[{i}] `{name}` must be a domain or classical rule-provider");
                    }
                }
                validate_dns_upstream(&r.upstream, &node_names)
                    .with_context(|| format!("dns.rules[{i}]"))?;
            }
            if self.dns.rules.is_empty() {
                let ns = self.dns.nameserver.as_deref().unwrap_or_default().trim();
                if ns.is_empty() {
                    bail!("rule-follow-route=false without dns.rules requires dns.nameserver");
                }
                crate::dns::parse_nameserver(ns).context("invalid dns.nameserver")?;
            }
        }

        if self.dns.enable && self.dns.mode == "fakeip" {
            let check = |names: &[String], field: &str| -> Result<()> {
                for name in names {
                    let rs = rulesets
                        .iter()
                        .find(|r| &r.name == name)
                        .ok_or_else(|| anyhow::anyhow!("{field} references unknown rule-provider {name}"))?;
                    if rs.ty != "domain" && rs.ty != "classical" {
                        bail!("{field} `{name}` must be a domain or classical rule-provider");
                    }
                }
                Ok(())
            };
            check(&self.dns.fakeip_filter, "fakeip-filter")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
mixed-port: 7898
dns:
  port: 5353
  direct-nameserver: "223.5.5.5:53"
  proxy-nameserver: "https://1.1.1.1/dns-query"
  default-nameserver: "223.5.5.5:53"
"#;

    fn two_nodes() -> String {
        r#"
proxies:
  - name: hy2-main
    type: hysteria2
    server: 1.2.3.4
    port: 443
    password: pw
  - name: vless-xhttp
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    network: xhttp
    tls: true
"#
        .into()
    }

    fn rules_and_routes(final_ob: &str) -> String {
        format!(
            r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: /tmp/cn.ars
route:
  - RULE-SET,cn,vless-xhttp
  - MATCH,{final_ob}
"#
        )
    }

    fn parse(yaml_text: &str) -> Result<Config> {
        let mut cfg: Config = serde_yaml::from_str(yaml_text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn resolve_ruleset_paths_joins_relative_only() {
        let yaml = format!(
            "{BASE}{}{}",
            two_nodes(),
            r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: cn.ars
  ads:
    type: file
    behavior: domain
    path: ./rules/ads.ars
  abs:
    type: file
    behavior: domain
    path: /var/lib/ant/abs.ars
route:
  - RULE-SET,cn,vless-xhttp
  - MATCH,hy2-main
"#
        );
        let mut cfg = parse(&yaml).unwrap();
        let base = std::path::Path::new("/opt/ant");
        cfg.resolve_ruleset_paths(base);
        let list = cfg.ruleset_list(Some(base)).unwrap();
        let path_of = |n: &str| -> std::path::PathBuf {
            match &list.iter().find(|r| r.name == n).unwrap().storage {
                RulesetStorage::File(p) => p.clone(),
                RulesetStorage::Db => panic!("expected file storage"),
            }
        };
        assert_eq!(path_of("cn"), base.join("cn.ars"));
        assert_eq!(path_of("ads"), base.join("rules").join("ads.ars"));
        assert_eq!(path_of("abs"), std::path::PathBuf::from("/var/lib/ant/abs.ars"));
    }

    #[test]
    fn multi_node_and_named_routing_ok() {
        let cfg = parse(&format!("{BASE}{}{}", two_nodes(), rules_and_routes("hy2-main"))).unwrap();
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.proxies[0].name, "hy2-main");
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ruleset_name(), Some("cn"));
        assert_eq!(parsed[0].outbound, "vless-xhttp");
        assert!(parsed[1].is_match());
        assert_eq!(parsed[1].outbound, "hy2-main");
    }

    #[test]
    fn match_accepts_direct_alias() {
        let cfg = parse(&format!("{BASE}{}{}", two_nodes(), rules_and_routes("DIRECT"))).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed.last().unwrap().outbound, "direct");
    }

    #[test]
    fn match_accepts_reject_as_block() {
        let yaml = format!(
            "{BASE}{}{}",
            two_nodes(),
            r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: /tmp/cn.ars
route:
  - RULE-SET,cn,REJECT
  - MATCH,hy2-main
"#
        );
        let cfg = parse(&yaml).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed[0].outbound, "block");
    }

    #[test]
    fn route_accepts_block_alias() {
        let yaml = format!(
            "{BASE}{}{}",
            two_nodes(),
            r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: /tmp/cn.ars
route:
  - RULE-SET,cn,block
  - MATCH,DIRECT
"#
        );
        let cfg = parse(&yaml).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed[0].outbound, "block");
        assert_eq!(parsed[1].outbound, "direct");
    }

    #[test]
    fn reserved_node_name_block_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: BLOCK\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,direct\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn old_rules_key_rejected() {
        // 顶层字段已更名为 route:，旧 rules: 直接 fail-fast。
        let yaml = format!(
            "{BASE}{}{}",
            two_nodes(),
            r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: /tmp/cn.ars
rules:
  - MATCH,direct
"#
        );
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn missing_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,direct\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("requires a non-empty `name`"), "{err}");
    }

    #[test]
    fn duplicate_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,direct\n"
        );
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn reserved_node_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: direct\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,direct\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn reserved_node_name_reject_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: REJECT\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,direct\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn unknown_route_outbound_rejected() {
        let yaml = format!("{BASE}{}{}", two_nodes(), rules_and_routes("no-such-node"));
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("unknown outbound"), "{err}");
    }

    #[test]
    fn last_rule_must_be_match() {
        let yaml = format!(
            "{BASE}{}\nrule-providers:\n  cn:\n    type: file\n    behavior: domain\n    path: /tmp/cn.ars\nroute:\n  - RULE-SET,cn,direct\n",
            two_nodes()
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("MATCH"), "{err}");
    }

    /// 在 BASE 的 dns: 块中（default-nameserver 行之后）追加额外字段。
    fn base_dns_extra(extra: &str) -> String {
        BASE.replacen(
            "  default-nameserver: \"223.5.5.5:53\"",
            &format!("  default-nameserver: \"223.5.5.5:53\"\n{extra}"),
            1,
        )
    }

    #[test]
    fn follow_route_requires_direct_and_proxy_nameserver() {
        let yaml = format!(
            "mixed-port: 7898\ndns:\n  port: 5353\n  default-nameserver: \"223.5.5.5:53\"\n{}{}",
            two_nodes(),
            rules_and_routes("direct")
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("direct-nameserver"), "{err}");
    }

    #[test]
    fn follow_route_rejects_dns_rules() {
        let yaml = format!(
            "{}{}{}",
            base_dns_extra("  rules:\n    - MATCH,udp://223.5.5.5:53\n"),
            two_nodes(),
            rules_and_routes("direct")
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("dns.rules is only used with rule-follow-route=false"),
            "{err}"
        );
    }

    #[test]
    fn follow_route_rejects_nameserver() {
        let yaml = format!(
            "{}{}{}",
            base_dns_extra("  nameserver: \"udp://223.5.5.5:53\"\n"),
            two_nodes(),
            rules_and_routes("direct")
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("dns.nameserver is only used with rule-follow-route=false"),
            "{err}"
        );
    }

    #[test]
    fn custom_rules_reject_direct_nameserver() {
        let yaml = format!(
            "{}{}{}",
            custom_dns_base("  nameserver: \"udp://223.5.5.5:53\"\n  direct-nameserver: \"223.5.5.5:53\"\n"),
            two_nodes(),
            rules_and_routes("direct")
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("rule-follow-route=true"), "{err}");
    }

    /// false 模式基础配置：dns 块显式构造，不含 direct/proxy-nameserver。
    fn custom_dns_base(extra: &str) -> String {
        format!(
            "mixed-port: 7898\ndns:\n  port: 5353\n  default-nameserver: \"223.5.5.5:53\"\n  rule-follow-route: false\n{extra}"
        )
    }

    fn dns_rules_config(dns_extra: &str) -> String {
        format!(
            "{}{}{}",
            custom_dns_base(dns_extra),
            two_nodes(),
            rules_and_routes("direct")
        )
    }

    #[test]
    fn custom_dns_rules_ok() {
        let yaml = dns_rules_config(
            r#"  rules:
    - RULE-SET,cn,udp://223.5.5.5:53
    - MATCH,rcode://success
"#,
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.dns.rules.len(), 2);
        let r0 = parse_dns_rule_line(&cfg.dns.rules[0]).unwrap();
        assert_eq!(r0.ruleset_name(), Some("cn"));
        assert_eq!(r0.upstream, "udp://223.5.5.5:53");
    }

    #[test]
    fn custom_dns_rules_match_must_be_last() {
        let yaml = dns_rules_config(
            r#"  rules:
    - MATCH,udp://223.5.5.5:53
    - RULE-SET,cn,udp://223.5.5.5:53
"#,
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("MATCH is only allowed as the last"), "{err}");
    }

    #[test]
    fn custom_dns_rules_lowercase_rejected() {
        let yaml = dns_rules_config(
            r#"  rules:
    - match,udp://223.5.5.5:53
"#,
        );
        let err = format!("{:#}", parse(&yaml).unwrap_err());
        assert!(err.contains("uppercase"), "{err:#}");
    }

    #[test]
    fn custom_dns_rules_outbound_names_rejected() {
        for upstream in ["direct", "REJECT", "block", "hy2-main", "vless-xhttp"] {
            let yaml = dns_rules_config(&format!(
                "  rules:\n    - MATCH,{upstream}\n"
            ));
            let err = format!("{:#}", parse(&yaml).unwrap_err());
            assert!(
                err.contains("nameserver url or rcode://success"),
                "upstream `{upstream}`: {err}"
            );
        }
    }

    #[test]
    fn custom_dns_rules_unknown_ruleset_rejected() {
        let yaml = dns_rules_config(
            r#"  rules:
    - RULE-SET,nope,udp://223.5.5.5:53
    - MATCH,udp://223.5.5.5:53
"#,
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("unknown rule-provider"), "{err}");
    }

    #[test]
    fn custom_dns_without_rules_requires_nameserver() {
        let yaml = dns_rules_config("");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("dns.nameserver"), "{err}");
    }

    #[test]
    fn custom_dns_nameserver_default_ok() {
        let yaml = dns_rules_config("  nameserver: \"udp://223.5.5.5:53\"\n");
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.dns.nameserver.as_deref(), Some("udp://223.5.5.5:53"));
        assert!(cfg.dns.direct_nameserver.is_none());
    }

    #[test]
    fn custom_dns_nameserver_rejects_outbound_name() {
        let yaml = dns_rules_config("  nameserver: \"hy2-main\"\n");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("invalid dns.nameserver"), "{err}");
    }

    // ── dns enable / port 语义 ──────────────────────────────────

    fn minimal_config(body: &str) -> String {
        format!("{body}{}{}", two_nodes(), rules_and_routes("direct"))
    }

    #[test]
    fn dns_block_absent_means_disabled() {
        let cfg = parse(&minimal_config("mixed-port: 7898\n")).unwrap();
        assert!(!cfg.dns.enable);
        assert_eq!(cfg.dns.listen_port(), 0);
        assert!(cfg.dns.default_nameserver.is_none());
    }

    #[test]
    fn dns_enable_false_skips_nameserver_requirements() {
        let yaml = minimal_config(
            "mixed-port: 7898\ndns:\n  enable: false\n  route-hijack: false\n",
        );
        let cfg = parse(&yaml).unwrap();
        assert!(!cfg.dns.enable);
    }

    #[test]
    fn dns_block_present_defaults_enabled() {
        let yaml = minimal_config(
            "dns:\n  port: 5353\n  default-nameserver: \"223.5.5.5:53\"\n  rule-follow-route: false\n  nameserver: \"udp://223.5.5.5:53\"\n",
        );
        let cfg = parse(&yaml).unwrap();
        assert!(cfg.dns.enable);
        assert_eq!(cfg.dns.listen_port(), 5353);
    }

    #[test]
    fn dns_enabled_without_port_is_hijack_only() {
        let yaml = minimal_config(
            "dns:\n  default-nameserver: \"223.5.5.5:53\"\n  rule-follow-route: false\n  nameserver: \"udp://223.5.5.5:53\"\n",
        );
        let cfg = parse(&yaml).unwrap();
        assert!(cfg.dns.enable);
        assert_eq!(cfg.dns.listen_port(), 0);
    }

    #[test]
    fn dns_enabled_requires_default_nameserver() {
        let yaml = minimal_config(
            "dns:\n  port: 5353\n  rule-follow-route: false\n  nameserver: \"udp://223.5.5.5:53\"\n",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("default-nameserver"), "{err}");
    }

    #[test]
    fn dns_route_hijack_rejected_when_disabled() {
        let yaml = minimal_config(
            "dns:\n  enable: false\n  route-hijack: true\n",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("route-hijack requires dns.enable=true"), "{err}");
    }

    #[test]
    fn explicit_zero_ports_rejected() {
        for line in [
            "mixed-port: 0\n",
            "tproxy-port: 0\n",
            "redir-port: 0\n",
        ] {
            let yaml = minimal_config(&format!("{line}dns:\n  enable: false\n"));
            let err = parse(&yaml).unwrap_err().to_string();
            assert!(err.contains("cannot be 0"), "{line}: {err}");
        }
        let yaml = minimal_config("dns:\n  enable: true\n  port: 0\n  default-nameserver: \"223.5.5.5:53\"\n  rule-follow-route: false\n  nameserver: \"udp://223.5.5.5:53\"\n");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("dns.port cannot be 0"), "{err}");
    }

    #[test]
    fn parse_rule_line_ok() {
        let r = parse_rule_line("RULE-SET, ads , REJECT").unwrap();
        assert_eq!(r.ruleset_name(), Some("ads"));
        assert_eq!(r.outbound, "block");
        assert!(!r.is_match());
        assert!(!r.no_resolve);
        let m = parse_rule_line("MATCH,hy2-main").unwrap();
        assert!(m.is_match());
        let nr = parse_rule_line("RULE-SET,cn-ip,DIRECT,no-resolve").unwrap();
        assert!(nr.no_resolve);
        assert_eq!(m.outbound, "hy2-main");
    }

    #[test]
    fn parse_dns_rule_line_ok() {
        let r = parse_dns_rule_line("RULE-SET, ads , udp://1.1.1.1:53").unwrap();
        assert_eq!(r.ruleset_name(), Some("ads"));
        assert_eq!(r.upstream, "udp://1.1.1.1:53");
        let m = parse_dns_rule_line("MATCH,rcode://success").unwrap();
        assert!(m.is_match());
        assert_eq!(m.upstream, "rcode://success");
        // type keywords are case-insensitive
    }

    #[test]
    fn validate_dns_upstream_accepts_nameserver_and_rcode() {
        let nodes = vec!["hy2-main".to_string()];
        validate_dns_upstream("udp://1.1.1.1:53", &nodes).unwrap();
        validate_dns_upstream("https://1.1.1.1/dns-query", &nodes).unwrap();
        validate_dns_upstream("rcode://success", &nodes).unwrap();
        for bad in ["direct", "BLOCK", "reject", "hy2-main", "rcode://nxdomain"] {
            assert!(validate_dns_upstream(bad, &nodes).is_err(), "{bad}");
        }
    }
}
