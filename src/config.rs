//! YAML configuration for ant (mihomo-style layout).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Flat top-level keys (mihomo-style): mixed-port, log-level, …
    #[serde(flatten)]
    pub global: GlobalConfig,
    pub dns: DnsConfig,
    /// Proxy nodes: list under `proxies:`; each node has a unique `name`.
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    /// Local rule providers (mihomo-style map).
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,
    /// mihomo-style rule strings under `route:` (alias `rules:` for compat).
    #[serde(default, rename = "route", alias = "rules")]
    pub route: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_log_level", rename = "log-level")]
    pub log_level: String,
    #[serde(default, rename = "tproxy-port")]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub tproxy_port: u16,
    #[serde(default, rename = "mixed-port")]
    pub mixed_port: u16,
    /// Dedicated HTTP inbound (`http-port` / alias `port`). 0 = disabled.
    #[serde(default, rename = "http-port", alias = "port")]
    pub http_port: u16,
    /// Dedicated SOCKS inbound (`socks-port` / alias `socks5-port`). 0 = disabled.
    #[serde(default, rename = "socks-port", alias = "socks5-port")]
    pub socks_port: u16,
    #[serde(default, rename = "redir-port")]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub redir_port: u16,
    #[serde(default, rename = "mark")]
    pub mark: u32,
    /// Inbound / DNS listen address family control.
    /// - `true` (default): dual-stack — IPv4 + IPv6; rulesets keep IPv6 CIDRs;
    ///   DNS AAAA still gated by `dns.ipv6`.
    /// - `false`: IPv4 only — listen IPv4 only; DNS ignores `dns.ipv6` (A only);
    ///   FakeIP only IPv4; IP rulesets drop IPv6 CIDRs.
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// Listen address for all inbounds and the DNS module.
    /// Only `0.0.0.0` (LAN) or `127.0.0.1` (loopback). IPv6 sockets are
    /// controlled solely by top-level `ipv6`.
    #[serde(default = "default_bind", rename = "bind-address")]
    pub bind_address: String,
    /// Protocol sniffing (TLS SNI / HTTP Host / QUIC SNI) for domain-based routing.
    /// Off by default. DNS-query sniffing is independent: it follows `dns.route-hijack`.
    #[serde(default)]
    pub sniff: bool,
    /// When true, resolve domain hosts before matching IP-CIDR / IP rule-providers.
    /// Default false. Per-rule opt-out: append `,no-resolve`.
    #[serde(default, rename = "route-resolve")]
    pub route_resolve: bool,
}

fn default_bind() -> String {
    "0.0.0.0".into()
}

fn default_log_level() -> String {
    "info".into()
}

fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(rename = "port", alias = "dns-port")]
    pub port: u16,
    /// Used when `rule-follow-route: true` (default): domains routed to direct.
    #[serde(default, rename = "direct-nameserver", alias = "direct-dns")]
    pub direct_nameserver: Option<String>,
    /// Used when `rule-follow-route: true`: domains routed to a proxy node.
    #[serde(default, rename = "proxy-nameserver", alias = "proxy-dns")]
    pub proxy_nameserver: Option<String>,
    #[serde(rename = "default-nameserver")]
    pub default_nameserver: String,
    /// true (default): reuse top-level `route:` for DNS — direct → direct-nameserver,
    /// node → proxy-nameserver, block → rcode://success.
    /// false: use `dns.rules` + `nameserver` instead.
    #[serde(default = "default_true_bool", rename = "rule-follow-route")]
    pub rule_follow_route: bool,
    /// Custom DNS rules when `rule-follow-route: false`.
    /// Format: `TYPE,payload,upstream` where upstream is a nameserver URL or `rcode://success`.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Default upstream when `rule-follow-route: false` and `rules` is empty.
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
    #[serde(skip)]
    pub resolved_direct: Option<crate::dns::DnsUpstream>,
    #[serde(skip)]
    pub resolved_proxy: Option<crate::dns::DnsUpstream>,
}

fn default_dns_mode() -> String {
    "redir-host".into()
}

fn default_cache_size() -> usize {
    4096
}

/// Shared proxy node config. `type` selects protocol; other fields are type-specific.
///
/// Configured under `proxies:` — multiple nodes, each identified by `name`.
/// Route rules reference nodes by name: `RULE-SET,cn,my-hk` or `MATCH,my-hk`.
/// Reserved: `direct` / `DIRECT`, `block` / `REJECT`.
///
/// ## hysteria2
/// `password`, optional `sni` / `alpn` / `skip-cert-verify` / `fingerprint` / `udp-mtu`
///
/// ## vless
/// `uuid` (or `password` as uuid), `network` = `tcp`|`ws`|`xhttp`, `tls` = bool,
/// optional `sni`, `skip-cert-verify`, `ws-path`, `ws-host`,
/// `reality-public-key` / `reality-short-id`, `xhttp-path` / `xhttp-host` / `xhttp-mode`
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

    #[serde(default)]
    pub uuid: Option<String>,

    /// VLESS flow，目前仅支持 `xtls-rprx-vision`（XTLS Vision，TCP/REALITY 专用）。
    #[serde(default)]
    pub flow: Option<String>,

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
}

fn default_network() -> String {
    "tcp".into()
}
fn default_true() -> bool {
    true
}

impl ProxyConfig {
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

/// One entry under `rule-providers:` (local file only for now).
#[derive(Debug, Clone, Deserialize)]
pub struct RuleProviderConfig {
    /// Provider type; only `file` is supported.
    #[serde(default = "default_provider_type", rename = "type")]
    pub ty: String,
    /// `domain` or `ip` / `ipcidr`.
    pub behavior: String,
    pub path: PathBuf,
}

fn default_provider_type() -> String {
    "file".into()
}

/// Normalized ruleset descriptor used by the router (derived from rule-providers).
#[derive(Debug, Clone)]
pub struct RulesetConfig {
    pub name: String,
    /// `domain` or `ip`.
    pub ty: String,
    pub path: PathBuf,
}

/// Kind of a single route rule (mihomo-compatible).
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
    /// Skip domain→IP resolve for this rule when `route-resolve: true`.
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

/// Outbound names that cannot be used as proxy node names.
pub const RESERVED_OUTBOUND_NAMES: &[&str] = &["direct", "block", "final", "proxy", "reject"];

/// Normalize reserved outbound aliases.
/// - `direct` / `DIRECT` → `direct`
/// - `block` / `BLOCK` / `reject` / `REJECT` → `block` (same effect: drop connection / DNS rcode://success)
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
    let no_resolve = parts.iter().skip(1).any(|p| is_no_resolve_flag(p));
    let parts: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|p| !is_no_resolve_flag(p))
        .collect();
    match kind.as_str() {
        "RULE-SET" => {
            if parts.len() < 3 {
                bail!("RULE-SET needs name and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::RuleSet(parts[1].to_string()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "MATCH" => {
            if parts.len() < 2 {
                bail!("MATCH needs outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::Match,
                outbound: normalize_outbound_name(parts[1]),
                no_resolve: false,
            })
        }
        "DOMAIN" => {
            if parts.len() < 3 {
                bail!("DOMAIN needs domain and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::Domain(parts[1].to_ascii_lowercase()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "DOMAIN-SUFFIX" => {
            if parts.len() < 3 {
                bail!("DOMAIN-SUFFIX needs suffix and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::DomainSuffix(
                    parts[1].trim_start_matches('.').to_ascii_lowercase(),
                ),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "DOMAIN-KEYWORD" => {
            if parts.len() < 3 {
                bail!("DOMAIN-KEYWORD needs keyword and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::DomainKeyword(parts[1].to_ascii_lowercase()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "DOMAIN-REGEX" => {
            if parts.len() < 3 {
                bail!("DOMAIN-REGEX needs regex and outbound, got: {line}");
            }
            regex::Regex::new(parts[1])
                .with_context(|| format!("invalid DOMAIN-REGEX: {}", parts[1]))?;
            Ok(ParsedRule {
                kind: RuleKind::DomainRegex(parts[1].to_string()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "IP-CIDR" | "IP-CIDR6" => {
            if parts.len() < 3 {
                bail!("{kind} needs cidr and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::IpCidr(parts[1].to_string()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            if parts.len() < 3 {
                bail!("{kind} needs cidr and outbound, got: {line}");
            }
            Ok(ParsedRule {
                kind: RuleKind::SrcIpCidr(parts[1].to_string()),
                outbound: normalize_outbound_name(parts[2]),
                no_resolve,
            })
        }
        other => bail!(
            "unsupported rule type `{other}`; supported: DOMAIN, DOMAIN-SUFFIX,              DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, SRC-IP-CIDR, RULE-SET, MATCH: {line}"
        ),
    }
}

/// Parsed `dns.rules` line (when `rule-follow-route: false`).
#[derive(Debug, Clone)]
pub struct ParsedDnsRule {
    pub kind: RuleKind,
    /// Nameserver URL or `rcode://success`.
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

/// Parse a `dns.rules` line. Same types as route; last field is upstream
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
    match kind.as_str() {
        "RULE-SET" => {
            if parts.len() < 3 {
                bail!("dns rules RULE-SET needs name and upstream, got: {line}");
            }
            Ok(ParsedDnsRule {
                kind: RuleKind::RuleSet(parts[1].to_string()),
                upstream: parts[2].to_string(),
            })
        }
        "MATCH" => {
            if parts.len() < 2 {
                bail!("dns rules MATCH needs upstream, got: {line}");
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
                kind: RuleKind::DomainSuffix(
                    parts[1].trim_start_matches('.').to_ascii_lowercase(),
                ),
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
                .with_context(|| format!("invalid dns DOMAIN-REGEX: {}", parts[1]))?;
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
            "dns rules: unsupported type `{other}` (got: {line});              supported: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX,              IP-CIDR, SRC-IP-CIDR, RULE-SET, MATCH"
        ),
    }
}

/// Validate dns.rules upstream: `rcode://success` or parseable nameserver URL.
pub fn validate_dns_upstream(upstream: &str, node_names: &[String]) -> Result<()> {
    let lower = upstream.trim().to_ascii_lowercase();
    if lower == "rcode://success" {
        return Ok(());
    }
    if RESERVED_OUTBOUND_NAMES.contains(&lower.as_str())
        || node_names.iter().any(|n| n.to_ascii_lowercase() == lower)
    {
        bail!(
            "dns rules upstream must be a nameserver url or rcode://success,              not an outbound name (got `{upstream}`)"
        );
    }
    crate::dns::parse_nameserver(upstream)
        .with_context(|| format!("dns rules upstream `{upstream}`"))
        .map(|_| ())
}

fn normalize_behavior(behavior: &str) -> Result<String> {
    match behavior.to_ascii_lowercase().as_str() {
        "domain" => Ok("domain".into()),
        "ip" | "ipcidr" | "ip-cidr" => Ok("ip".into()),
        other => bail!("rule-provider behavior must be domain or ip/ipcidr, got `{other}`"),
    }
}

impl Config {
    /// All routable outbound names: reserved + node names.
    pub fn outbound_names(&self) -> Vec<String> {
        RESERVED_OUTBOUND_NAMES
            .iter()
            .filter(|n| **n != "final" && **n != "proxy" && **n != "reject")
            .map(|s| s.to_string())
            .chain(self.proxies.iter().map(|p| p.name.clone()))
            .collect()
    }

    /// Rulesets derived from `rule-providers` for the router.
    pub fn ruleset_list(&self) -> Result<Vec<RulesetConfig>> {
        let mut out = Vec::with_capacity(self.rule_providers.len());
        for (name, rp) in &self.rule_providers {
            if !rp.ty.eq_ignore_ascii_case("file") {
                bail!(
                    "rule-provider `{name}`: type must be `file` (got `{}`)",
                    rp.ty
                );
            }
            out.push(RulesetConfig {
                name: name.clone(),
                ty: normalize_behavior(&rp.behavior)?,
                path: rp.path.clone(),
            });
        }
        Ok(out)
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
                other => bail!("proxy node `{label}`: unsupported type={other}; use hysteria2 or vless"),
            }
        }
        let names: Vec<&str> = self.proxies.iter().map(|p| p.name.as_str()).collect();
        if names.len() != names.iter().collect::<std::collections::HashSet<_>>().len() {
            bail!("duplicate proxy node name in proxies");
        }
        let known = self.outbound_names();

        let mode = self.dns.mode.to_ascii_lowercase();
        if mode != "redir-host" && mode != "fakeip" {
            bail!("dns.mode must be redir-host or fakeip");
        }
        self.dns.mode = mode;
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
            let effective_dns_ipv6 = self.global.ipv6 && self.dns.ipv6;
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
        crate::dns::parse_nameserver(&self.dns.default_nameserver).context("invalid default-nameserver")?;

        // bind-address: only 0.0.0.0 (LAN) or 127.0.0.1 (loopback).
        // Dual-stack vs IPv4-only is controlled solely by top-level `ipv6`.
        {
            let b = self.global.bind_address.trim();
            if b == "localhost" {
                self.global.bind_address = "127.0.0.1".into();
            } else if b != "0.0.0.0" && b != "127.0.0.1" {
                bail!(
                    "bind-address must be \"0.0.0.0\" or \"127.0.0.1\" (got `{b}`);                      use top-level `ipv6: true/false` to control IPv6 listening"
                );
            } else {
                self.global.bind_address = b.to_string();
            }
        }

        // DNS routing strategy
        let node_names: Vec<String> = self.proxies.iter().map(|p| p.name.clone()).collect();
        if self.dns.rule_follow_route {
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
                .filter(|s| !s.is_empty())
                .context("rule-follow-route=true requires dns.direct-nameserver")?;
            let proxy = self
                .dns
                .proxy_nameserver
                .as_deref()
                .filter(|s| !s.is_empty())
                .context("rule-follow-route=true requires dns.proxy-nameserver")?;
            crate::dns::parse_nameserver(direct).context("invalid direct-nameserver")?;
            crate::dns::parse_nameserver(proxy).context("invalid proxy-nameserver")?;
        } else {
            if self.dns.direct_nameserver.as_ref().is_some_and(|s| !s.is_empty())
                || self.dns.proxy_nameserver.as_ref().is_some_and(|s| !s.is_empty())
            {
                bail!(
                    "direct-nameserver/proxy-nameserver are only used with rule-follow-route=true"
                );
            }
            if self.dns.rules.is_empty() {
                let ns = self
                    .dns
                    .nameserver
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .context(
                        "rule-follow-route=false without dns.rules requires dns.nameserver",
                    )?;
                crate::dns::parse_nameserver(ns).context("invalid dns.nameserver")?;
            } else {
                let ruleset_names: std::collections::HashSet<&str> =
                    self.rule_providers.keys().map(|s| s.as_str()).collect();
                let parsed_dns: Vec<ParsedDnsRule> = self
                    .dns
                    .rules
                    .iter()
                    .enumerate()
                    .map(|(i, line)| {
                        parse_dns_rule_line(line).with_context(|| format!("dns.rules[{i}]"))
                    })
                    .collect::<Result<_>>()?;
                let last = parsed_dns.last().unwrap();
                if !last.is_match() {
                    bail!("last dns.rules entry must be MATCH,<upstream>");
                }
                for (i, r) in parsed_dns.iter().enumerate() {
                    if i + 1 != parsed_dns.len() && r.is_match() {
                        bail!("MATCH is only allowed as the last dns.rules entry (at [{i}])");
                    }
                    if let Some(name) = r.ruleset_name() {
                        if !ruleset_names.contains(name) {
                            bail!("dns.rules[{i}]: unknown rule-provider `{name}`");
                        }
                    }
                    validate_dns_upstream(&r.upstream, &node_names)
                        .with_context(|| format!("dns.rules[{i}]"))?;
                }
            }
        }

        // rule-providers
        let rulesets = self.ruleset_list()?;
        for rs in &rulesets {
            let ext = rs
                .path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if !ext.eq_ignore_ascii_case("ars") {
                bail!(
                    "rule-provider `{}` path must end with .ars (got {:?}); convert with: ant ruleset-convert -i in.json -o out.ars",
                    rs.name,
                    rs.path
                );
            }
        }
        let ruleset_names: std::collections::HashSet<&str> =
            rulesets.iter().map(|r| r.name.as_str()).collect();

        // route
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
                bail!("MATCH is only allowed as the last rule (found at route[{i}])");
            }
            if let Some(name) = r.ruleset_name() {
                if !ruleset_names.contains(name) {
                    bail!("route[{i}]: unknown rule-provider `{name}`");
                }
            }
            if !known.contains(&r.outbound) {
                bail!(
                    "route[{i}]: unknown outbound `{}`; use direct/DIRECT, block/REJECT, or a proxies name",
                    r.outbound
                );
            }
        }
        if !known.contains(&last.outbound) {
            bail!(
                "MATCH: unknown outbound `{}`; use direct/DIRECT, block/REJECT, or a proxies name",
                last.outbound
            );
        }

        if self.dns.mode == "fakeip" {
            let check = |names: &[String], field: &str| -> Result<()> {
                for name in names {
                    let rs = rulesets
                        .iter()
                        .find(|r| &r.name == name)
                        .ok_or_else(|| anyhow::anyhow!("{field} references unknown rule-provider {name}"))?;
                    if rs.ty != "domain" {
                        bail!("{field} `{name}` must be a domain rule-provider");
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
        for alias in ["REJECT", "reject", "BLOCK", "block"] {
            let yaml = format!(
                "{BASE}{}{}",
                two_nodes(),
                format!(
                    r#"
rule-providers:
  cn:
    type: file
    behavior: domain
    path: /tmp/cn.ars
route:
  - RULE-SET,cn,{alias}
  - MATCH,hy2-main
"#
                )
            );
            let cfg = parse(&yaml).unwrap();
            let parsed = cfg.parsed_rules().unwrap();
            assert_eq!(parsed[0].outbound, "block", "alias={alias}");
        }
        assert_eq!(normalize_outbound_name("REJECT"), "block");
        assert_eq!(normalize_outbound_name("reject"), "block");
        assert_eq!(normalize_outbound_name("BLOCK"), "block");
        assert_eq!(normalize_outbound_name("block"), "block");
    }

    #[test]
    fn missing_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nrules:\n  - MATCH,direct\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("requires a non-empty `name`"), "{err}");
    }

    #[test]
    fn duplicate_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nrules:\n  - MATCH,direct\n"
        );
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn reserved_node_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: direct\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nrules:\n  - MATCH,direct\n"
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
            "{BASE}{}\nrule-providers:\n  cn:\n    type: file\n    behavior: domain\n    path: /tmp/cn.ars\nrules:\n  - RULE-SET,cn,direct\n",
            two_nodes()
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("MATCH"), "{err}");
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
        assert_eq!(m.outbound, "hy2-main");
        let ip = parse_rule_line("IP-CIDR,1.1.1.1/32,DIRECT,no-resolve").unwrap();
        assert!(ip.no_resolve);
        assert_eq!(ip.outbound, "direct");
        matches!(ip.kind, RuleKind::IpCidr(_));
    }
}
