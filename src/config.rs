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
    /// mihomo-style rule strings: `RULE-SET,name,outbound` / `MATCH,outbound`.
    /// YAML key: `route:` (`rules:` accepted as a legacy alias).
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
    #[serde(default, rename = "redir-port")]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub redir_port: u16,
    #[serde(default, rename = "mark")]
    pub mark: u32,
    #[serde(default = "default_bind", rename = "bind-address")]
    pub bind_address: String,
    #[serde(default, rename = "api")]
    pub api: String,
    /// Protocol sniffing (TLS SNI / HTTP Host / QUIC SNI) for domain-based routing.
    /// Off by default. DNS-query sniffing is independent: it follows `dns.route-hijack`.
    #[serde(default)]
    pub sniff: bool,
}

fn default_bind() -> String {
    "::".into()
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(rename = "port", alias = "dns-port")]
    pub port: u16,
    /// true (default): upstream selection reuses the connection-routing `rules`
    /// (domain match): direct-routed → `direct-nameserver`, any proxy node →
    /// `proxy-nameserver`. Both fields are required.
    #[serde(default = "default_true", rename = "rule-follow-route")]
    pub rule_follow_route: bool,
    #[serde(default, rename = "direct-nameserver", alias = "direct-dns")]
    pub direct_nameserver: String,
    #[serde(default, rename = "proxy-nameserver", alias = "proxy-dns")]
    pub proxy_nameserver: String,
    /// Default upstream for `rule-follow-route: false`. Required when
    /// `dns.rules` is empty; optional (but still used as fallback) when
    /// `dns.rules` is configured — in that case `dns.rules` must end with `match`.
    #[serde(default, rename = "nameserver")]
    pub nameserver: String,
    /// DNS-specific routing rules (`rule-follow-route: false`):
    /// DNS-specific routing rules (`rule-follow-route: false`):
    /// `RULE-SET,<provider-name>,<target>` / `MATCH,<target>` (keywords uppercase).
    /// Target is an upstream URL (udp/tcp/tls/https) or `rcode://success`.
    #[serde(default, rename = "rules")]
    pub rules: Vec<String>,
    #[serde(rename = "default-nameserver")]
    pub default_nameserver: String,
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    #[serde(default, rename = "fakeip-range")]
    pub fakeip_range: Option<String>,
    #[serde(default, rename = "fakeip6-range")]
    pub fakeip6_range: Option<String>,
    /// Domain rulesets deciding fake-ip usage, interpreted by `fakeip-filter-mode`:
    /// blacklist (default) — matched domains stay real-IP, everything else gets fake-ip;
    /// whitelist — only matched domains get fake-ip.
    /// Each entry: `RULE-SET,<provider-name>`.
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
    /// `dns.rules` entries with upstreams resolved via `default-nameserver`
    /// (only for `rule-follow-route: false`).
    #[serde(skip)]
    pub resolved_rules: Option<Vec<crate::dns::DnsResolvedRoute>>,
    #[serde(skip)]
    pub resolved_nameserver: Option<crate::dns::DnsUpstream>,
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
/// Reserved node names (outbound keywords): `direct` / `DIRECT`,
/// `block` / `BLOCK`, `reject` / `REJECT`.
///
/// ## hysteria2
/// `password`, optional `sni` / `alpn` / `skip-cert-verify` / `fingerprint` / `udp-mtu`
///
/// ## vless
/// `uuid` (or `password` as uuid), `network` = `tcp`|`ws`|`xhttp`, `tls` = bool,
/// optional `sni`, `skip-cert-verify`, `client-fingerprint` (uTLS: chrome /
/// firefox / safari / edge / ios / android / 360 / qq / random),
/// `ws-path`, `ws-host`, `reality-public-key` / `reality-short-id`,
/// `xhttp-path` / `xhttp-host` / `xhttp-mode` (`auto`|`packet-up`|`stream-up`|`stream-one`)
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
    /// hysteria2: 证书 SHA256 指纹（pinning）；vless: uTLS 浏览器指纹
    /// (`client-fingerprint`)，支持 chrome/firefox/safari/edge/ios/android/
    /// 360/qq/random（见 outbound::utls 的 `UtlsFingerprint::parse`）。
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

    /// XHTTP path (default `/`).
    #[serde(default, rename = "xhttp-path", alias = "path")]
    pub xhttp_path: Option<String>,
    /// XHTTP Host header (default: SNI / server).
    #[serde(default, rename = "xhttp-host")]
    pub xhttp_host: Option<String>,
    /// `auto` | `stream-one` | `packet-up` | `stream-up`。
    /// `auto`：对齐 Xray dialer.go —— 默认 `packet-up`；REALITY 下默认 `stream-one`。
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

/// Parsed mihomo-style rule line.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    /// Ruleset name for `RULE-SET`; `None` for `MATCH`.
    pub ruleset: Option<String>,
    /// Normalized outbound: `direct` / `block` / node name.
    pub outbound: String,
    pub is_match: bool,
}

/// Reserved node names: every accepted spelling of a built-in outbound.
/// These are **reserved**: a `proxies:` node may not use any of them as its
/// `name`, otherwise the route target would be ambiguous.
pub const RESERVED_NODE_NAMES: &[&str] =
    &["DIRECT", "direct", "BLOCK", "block", "REJECT", "reject"];

/// Parse a single mihomo-style rule string.
/// Supported: `RULE-SET,<name>,<outbound>` and `MATCH,<outbound>`.
/// The outbound is kept verbatim; `DIRECT`/`direct` and
/// `BLOCK`/`block`/`REJECT`/`reject` are the built-in outbounds, everything
/// else is a proxy node name.
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
    match kind.as_str() {
        "RULE-SET" => {
            if parts.len() < 3 {
                bail!("RULE-SET needs name and outbound, got: {line}");
            }
            Ok(ParsedRule {
                ruleset: Some(parts[1].to_string()),
                outbound: parts[2].to_string(),
                is_match: false,
            })
        }
        "MATCH" => {
            if parts.len() < 2 {
                bail!("MATCH needs outbound, got: {line}");
            }
            Ok(ParsedRule {
                ruleset: None,
                outbound: parts[1].to_string(),
                is_match: true,
            })
        }
        other => bail!(
            "unsupported rule type `{other}` (only RULE-SET and MATCH are supported): {line}"
        ),
    }
}

/// Parse one `dns.rules` line (`rule-follow-route: false`).
/// Supported: `RULE-SET,<name>,<target>` and `MATCH,<target>` (keywords uppercase).
/// Target: an upstream URL (udp/tcp/tls/https) or `rcode://success`.
pub fn parse_dns_rule_line(line: &str) -> Result<crate::dns::DnsRouteEntry> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty dns.rules line");
    }
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let kind = parts.first().copied().unwrap_or("");
    match kind {
        "RULE-SET" => {
            if parts.len() != 3 {
                bail!("dns.rules RULE-SET needs exactly <name>,<upstream>, got: {line}");
            }
            if parts[1].is_empty() {
                bail!("dns.rules RULE-SET name must not be empty: {line}");
            }
            Ok(crate::dns::DnsRouteEntry {
                ruleset: Some(parts[1].to_string()),
                spec: parts[2].to_string(),
            })
        }
        "MATCH" => {
            if parts.len() != 2 {
                bail!("dns.rules MATCH needs exactly <upstream>, got: {line}");
            }
            Ok(crate::dns::DnsRouteEntry {
                ruleset: None,
                spec: parts[1].to_string(),
            })
        }
        other => bail!(
            "unsupported dns.rules type `{other}` (only RULE-SET and MATCH, uppercase, are supported): {line}"
        ),
    }
}

/// Parse one `fakeip-filter` entry: `RULE-SET,<provider-name>` (uppercase keyword).
pub fn parse_fakeip_filter_entry(line: &str) -> Result<String> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty fakeip-filter entry");
    }
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    match parts.first().copied().unwrap_or("") {
        "RULE-SET" => {
            if parts.len() != 2 {
                bail!("fakeip-filter RULE-SET needs exactly <name>, got: {line}");
            }
            Ok(parts[1].to_string())
        }
        other => bail!(
            "unsupported fakeip-filter type `{other}` (only RULE-SET, uppercase, is supported): {line}"
        ),
    }
}

fn normalize_behavior(behavior: &str) -> Result<String> {
    match behavior.to_ascii_lowercase().as_str() {
        "domain" => Ok("domain".into()),
        "ip" | "ipcidr" | "ip-cidr" => Ok("ip".into()),
        other => bail!("rule-provider behavior must be domain or ip/ipcidr, got `{other}`"),
    }
}

impl Config {
    /// All routable outbound names: built-in aliases + node names.
    pub fn outbound_names(&self) -> Vec<String> {
        RESERVED_NODE_NAMES
            .iter()
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
            if RESERVED_NODE_NAMES.contains(&p.name.as_str()) {
                bail!(
                    "proxies[{i}]: node name `{}` is reserved (outbound keywords: {})",
                    p.name,
                    RESERVED_NODE_NAMES.join(", ")
                );
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
            if !self.dns.ipv6
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
        if self.dns.rule_follow_route {
            if self.dns.direct_nameserver.trim().is_empty() {
                bail!("rule-follow-route=true requires dns.direct-nameserver");
            }
            if self.dns.proxy_nameserver.trim().is_empty() {
                bail!("rule-follow-route=true requires dns.proxy-nameserver");
            }
            crate::dns::parse_nameserver(&self.dns.direct_nameserver)
                .context("invalid direct-nameserver")?;
            crate::dns::parse_nameserver(&self.dns.proxy_nameserver)
                .context("invalid proxy-nameserver")?;
        } else {
            if !self.dns.direct_nameserver.trim().is_empty()
                || !self.dns.proxy_nameserver.trim().is_empty()
            {
                eprintln!(
                    "warning: rule-follow-route=false ignores dns.direct-nameserver / dns.proxy-nameserver"
                );
            }
            // No `dns.rules` → `nameserver` is the only upstream, so it is required.
            // With `dns.rules` → a trailing `match` is required instead, and
            // `nameserver` becomes optional (used only as a fallback).
            if self.dns.rules.is_empty() && self.dns.nameserver.trim().is_empty() {
                bail!(
                    "rule-follow-route=false without dns.rules requires dns.nameserver (default upstream)"
                );
            }
            if !self.dns.nameserver.trim().is_empty() {
                crate::dns::parse_nameserver(&self.dns.nameserver)
                    .context("invalid dns.nameserver")?;
            }
        }
        crate::dns::parse_nameserver(&self.dns.default_nameserver)
            .context("invalid default-nameserver")?;

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
        if !last.is_match {
            bail!("last route rule must be MATCH,<outbound>");
        }
        for (i, r) in parsed.iter().enumerate() {
            if i + 1 == parsed.len() {
                continue;
            }
            if r.is_match {
                bail!("MATCH is only allowed as the last rule (found at route[{i}])");
            }
            let name = r.ruleset.as_deref().unwrap();
            if !ruleset_names.contains(name) {
                bail!("route[{i}]: unknown rule-provider `{name}`");
            }
            if !known.contains(&r.outbound) {
                bail!(
                    "route[{i}]: unknown outbound `{}`; use DIRECT/direct, BLOCK/block/REJECT/reject, or a proxies name",
                    r.outbound
                );
            }
        }
        if !known.contains(&last.outbound) {
            bail!(
                "MATCH: unknown outbound `{}`; use DIRECT/direct, BLOCK/block/REJECT/reject, or a proxies name",
                last.outbound
            );
        }

        // dns.rules (only used when rule-follow-route=false)
        if !self.dns.rule_follow_route {
            let mut last_is_match = false;
            for (i, line) in self.dns.rules.iter().enumerate() {
                let e = parse_dns_rule_line(line).with_context(|| format!("dns.rules[{i}]"))?;
                if let Some(name) = &e.ruleset {
                    let rs = rulesets.iter().find(|r| &r.name == name).ok_or_else(|| {
                        anyhow::anyhow!("dns.rules[{i}]: unknown rule-provider `{name}`")
                    })?;
                    if rs.ty != "domain" {
                        bail!("dns.rules[{i}]: rule-provider `{name}` must be a domain ruleset");
                    }
                }
                if !crate::dns::is_block_rcode(&e.spec) {
                    crate::dns::parse_nameserver(&e.spec).with_context(|| {
                        format!(
                            "dns.rules[{i}]: invalid target `{}` (use an upstream URL, or rcode://success)",
                            e.spec
                        )
                    })?;
                }
                last_is_match = e.ruleset.is_none();
            }
            // A configured `dns.rules` must end with `MATCH,<target>` so every
            // query has an upstream (mirrors the trailing-MATCH rule of `route:`).
            if !self.dns.rules.is_empty() && !last_is_match {
                bail!("dns.rules must end with a MATCH,<target> rule (got: {})", {
                    self.dns.rules.last().map(String::as_str).unwrap_or("")
                });
            }
        }

        if self.dns.mode == "fakeip" {
            for (i, line) in self.dns.fakeip_filter.iter().enumerate() {
                let name = parse_fakeip_filter_entry(line)
                    .with_context(|| format!("fakeip-filter[{i}]"))?;
                let rs = rulesets.iter().find(|r| r.name == name).ok_or_else(|| {
                    anyhow::anyhow!("fakeip-filter[{i}] references unknown rule-provider {name}")
                })?;
                if rs.ty != "domain" {
                    bail!("fakeip-filter[{i}] `{name}` must be a domain rule-provider");
                }
            }
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
        assert_eq!(parsed[0].ruleset.as_deref(), Some("cn"));
        assert_eq!(parsed[0].outbound, "vless-xhttp");
        assert!(parsed[1].is_match);
        assert_eq!(parsed[1].outbound, "hy2-main");
    }

    #[test]
    fn match_accepts_direct_uppercase() {
        let cfg = parse(&format!("{BASE}{}{}", two_nodes(), rules_and_routes("DIRECT"))).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed.last().unwrap().outbound, "DIRECT");
    }

    #[test]
    fn match_accepts_block_uppercase() {
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
  - RULE-SET,cn,BLOCK
  - MATCH,hy2-main
"#
        );
        let cfg = parse(&yaml).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed[0].outbound, "BLOCK");
    }

    #[test]
    fn lowercase_direct_accepted_as_builtin() {
        // `direct` / `block` / `reject` are accepted aliases for the built-ins
        let yaml = format!("{BASE}{}\nroute:\n  - MATCH,direct\n", two_nodes());
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.parsed_rules().unwrap()[0].outbound, "direct");
    }

    #[test]
    fn node_named_direct_is_rejected() {
        // outbound keywords are reserved → a node may not be named after them
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: direct\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,DIRECT\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("is reserved"), "{err}");
    }

    #[test]
    fn all_reserved_node_names_rejected() {
        for name in ["DIRECT", "direct", "BLOCK", "block", "REJECT", "reject"] {
            let yaml = format!(
                "{BASE}\nproxies:\n  - name: {name}\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,DIRECT\n"
            );
            let err = parse(&yaml).unwrap_err().to_string();
            assert!(err.contains("is reserved"), "`{name}` should be rejected: {err}");
        }
    }

    #[test]
    fn outbound_aliases_all_resolve() {
        for out in ["DIRECT", "direct"] {
            let yaml = format!("{BASE}{}\nroute:\n  - MATCH,{out}\n", two_nodes());
            let cfg = parse(&yaml).unwrap();
            assert_eq!(
                cfg.parsed_rules().unwrap()[0].outbound,
                out,
                "`{out}` should be a valid route target"
            );
        }
        for out in ["BLOCK", "block", "REJECT", "reject"] {
            let yaml = format!("{BASE}{}\nroute:\n  - MATCH,{out}\n", two_nodes());
            let cfg = parse(&yaml).unwrap();
            assert_eq!(cfg.parsed_rules().unwrap()[0].outbound, out);
        }
    }

    #[test]
    fn missing_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,DIRECT\n"
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("requires a non-empty `name`"), "{err}");
    }

    #[test]
    fn duplicate_name_rejected() {
        let yaml = format!(
            "{BASE}\nproxies:\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\n  - name: a\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,DIRECT\n"
        );
        assert!(parse(&yaml).is_err());
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

    #[test]
    fn legacy_rules_key_still_accepted_as_route() {
        let yaml = format!(
            "{BASE}{}\nrule-providers:\n  cn:\n    type: file\n    behavior: domain\n    path: /tmp/cn.ars\nrules:\n  - RULE-SET,cn,block\n  - MATCH,reject\n",
            two_nodes()
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.route.len(), 2);
        assert!(cfg.route[0].contains("block"));
        assert!(cfg.route[1].contains("reject"));
    }

    #[test]
    fn parse_rule_line_ok() {
        let r = parse_rule_line("RULE-SET, ads , BLOCK").unwrap();
        assert_eq!(r.ruleset.as_deref(), Some("ads"));
        assert_eq!(r.outbound, "BLOCK");
        assert!(!r.is_match);
        let m = parse_rule_line("MATCH,hy2-main").unwrap();
        assert!(m.is_match);
        assert_eq!(m.outbound, "hy2-main");
        // all six outbound keywords are accepted variants (validated later)
        for out in ["DIRECT", "direct", "BLOCK", "block", "REJECT", "reject"] {
            assert_eq!(parse_rule_line(&format!("MATCH,{out}")).unwrap().outbound, out);
        }
    }

    const DNS_RULE_BASE: &str = "\
mixed-port: 7898
dns:
  port: 5353
  rule-follow-route: false
  default-nameserver: \"223.5.5.5:53\"";

    /// Build a rule-mode config: `dns_lines` are extra lines inside the `dns:` block.
    fn dns_rule_yaml(dns_lines: &str, nameserver: &str) -> String {
        let ns_line = if nameserver.is_empty() {
            String::new()
        } else {
            format!("\n  nameserver: \"{nameserver}\"")
        };
        format!(
            "{DNS_RULE_BASE}{ns_line}{dns_lines}\nrule-providers:\n  cn:\n    type: file\n    behavior: domain\n    path: /tmp/cn.ars\nproxies:\n  - name: hy2-main\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pw\nroute:\n  - MATCH,hy2-main\n"
        )
    }

    #[test]
    fn dns_rule_mode_ok_without_direct_proxy_nameserver() {
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,cn,udp://223.5.5.5:53\n    - MATCH,rcode://success\n",
            "https://223.5.5.5/dns-query",
        );
        let cfg = parse(&yaml).unwrap();
        assert!(!cfg.dns.rule_follow_route);
        assert_eq!(cfg.dns.rules.len(), 2);
        assert!(cfg.dns.direct_nameserver.is_empty());
        assert!(cfg.dns.proxy_nameserver.is_empty());
        let e0 = parse_dns_rule_line(&cfg.dns.rules[0]).unwrap();
        assert_eq!(e0.ruleset.as_deref(), Some("cn"));
        assert_eq!(e0.spec, "udp://223.5.5.5:53");
        let e1 = parse_dns_rule_line(&cfg.dns.rules[1]).unwrap();
        assert!(e1.ruleset.is_none());
        assert!(crate::dns::is_block_rcode(&e1.spec));
    }

    #[test]
    fn dns_rule_mode_no_rules_requires_nameserver() {
        let yaml = dns_rule_yaml("", "");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("without dns.rules requires dns.nameserver"), "{err}");
    }

    #[test]
    fn dns_rule_mode_rules_without_nameserver_ok_when_match_present() {
        // rules present + trailing match → nameserver optional
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,cn,udp://223.5.5.5:53\n    - MATCH,udp://8.8.8.8:53\n",
            "",
        );
        let cfg = parse(&yaml).unwrap();
        assert!(cfg.dns.nameserver.is_empty());
        assert_eq!(cfg.dns.rules.len(), 2);
    }

    #[test]
    fn dns_rule_mode_rules_must_end_with_match() {
        // rules present but no trailing match → rejected
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,cn,udp://223.5.5.5:53\n",
            "",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("must end with a MATCH"), "{err}");
    }

    #[test]
    fn dns_rule_mode_match_not_last_rejected() {
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - MATCH,udp://8.8.8.8:53\n    - RULE-SET,cn,udp://223.5.5.5:53\n",
            "",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("must end with a MATCH"), "{err}");
    }

    #[test]
    fn dns_rule_unknown_provider_rejected() {
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,nope,udp://223.5.5.5:53\n    - MATCH,rcode://success\n",
            "https://223.5.5.5/dns-query",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("unknown rule-provider `nope`"), "{err}");
    }

    #[test]
    fn dns_rule_ip_behavior_provider_rejected() {
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,cn-ip,udp://223.5.5.5:53\n    - MATCH,rcode://success\n",
            "https://223.5.5.5/dns-query",
        );
        // Swap the domain provider for an ip-behavior one referenced by dns.rules.
        let yaml = yaml.replace(
            "rule-providers:\n  cn:\n    type: file\n    behavior: domain\n    path: /tmp/cn.ars",
            "rule-providers:\n  cn-ip:\n    type: file\n    behavior: ip\n    path: /tmp/cn-ip.ars",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("must be a domain ruleset"), "{err}");
    }

    #[test]
    fn dns_rule_invalid_upstream_rejected() {
        let yaml = dns_rule_yaml(
            "\n  rules:\n    - RULE-SET,cn,foo://bad\n    - MATCH,rcode://success\n",
            "https://223.5.5.5/dns-query",
        );
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("invalid target"), "{err}");
    }

    #[test]
    fn follow_route_requires_direct_and_proxy_nameserver() {
        let yaml = "\
mixed-port: 7898
dns:
  port: 5353
  rule-follow-route: true
  proxy-nameserver: \"https://1.1.1.1/dns-query\"
  default-nameserver: \"223.5.5.5:53\"
proxies:
  - name: hy2-main
    type: hysteria2
    server: 1.2.3.4
    port: 443
    password: pw
route:
  - MATCH,hy2-main
";
        let err = parse(yaml).unwrap_err().to_string();
        assert!(err.contains("requires dns.direct-nameserver"), "{err}");
    }

    #[test]
    fn parse_dns_rule_line_variants() {
        let r = parse_dns_rule_line("RULE-SET, ads , rcode://success").unwrap();
        assert_eq!(r.ruleset.as_deref(), Some("ads"));
        assert_eq!(r.spec, "rcode://success");
        let m = parse_dns_rule_line("MATCH,https://1.1.1.1/dns-query").unwrap();
        assert!(m.ruleset.is_none());
        assert_eq!(m.spec, "https://1.1.1.1/dns-query");
        assert!(parse_dns_rule_line("domain,ads,direct").is_err());
        assert!(parse_dns_rule_line("RULE-SET,only-name").is_err());
        assert!(parse_dns_rule_line("").is_err());
        assert!(crate::dns::is_block_rcode("rcode://success"));
        assert!(!crate::dns::is_block_rcode("udp://223.5.5.5:53"));
        // `block`/`REJECT` are no longer valid dns.rules targets
        assert!(!crate::dns::is_block_rcode("block"));
        assert!(!crate::dns::is_block_rcode("REJECT"));
        assert!(!crate::dns::is_block_rcode("RCODE://success"));
    }

    #[test]
    fn dns_rule_keyword_is_case_sensitive() {
        // lowercase keywords are rejected (must match the upstream `route:` style)
        assert!(parse_dns_rule_line("ruleset,cn,udp://223.5.5.5:53").is_err());
        assert!(parse_dns_rule_line("match,rcode://success").is_err());
        assert!(parse_dns_rule_line("Rule-Set,cn,udp://223.5.5.5:53").is_err());
    }

    #[test]
    fn parse_fakeip_filter_entry_variants() {
        assert_eq!(parse_fakeip_filter_entry("RULE-SET,cn-domain").unwrap(), "cn-domain");
        assert_eq!(parse_fakeip_filter_entry("RULE-SET, google-domain ").unwrap(), "google-domain");
        assert!(parse_fakeip_filter_entry("cn-domain").is_err());
        assert!(parse_fakeip_filter_entry("rule-set,cn").is_err());
        assert!(parse_fakeip_filter_entry("RULE-SET,a,b").is_err());
        assert!(parse_fakeip_filter_entry("").is_err());
    }

    #[test]
    fn fakeip_filter_accepts_rule_set_prefix() {
        let yaml = "\
mixed-port: 7898
dns:
  port: 5353
  mode: fakeip
  fakeip-range: \"198.18.0.0/15\"
  fakeip-filter:
    - RULE-SET,cn-domain
  fakeip-filter-mode: blacklist
  default-nameserver: \"223.5.5.5:53\"
  direct-nameserver: \"223.5.5.5:53\"
  proxy-nameserver: \"udp://8.8.8.8:53\"
rule-providers:
  cn-domain:
    type: file
    behavior: domain
    path: /tmp/cn-domain.ars
proxies:
  - name: hy2-main
    type: hysteria2
    server: 1.2.3.4
    port: 443
    password: pw
route:
  - MATCH,hy2-main
";
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.dns.fakeip_filter, vec!["RULE-SET,cn-domain".to_string()]);
    }

    #[test]
    fn fakeip_filter_non_domain_provider_rejected() {
        let yaml = "\
mixed-port: 7898
dns:
  port: 5353
  mode: fakeip
  fakeip-range: \"198.18.0.0/15\"
  fakeip-filter:
    - RULE-SET,cn-ip
  fakeip-filter-mode: blacklist
  default-nameserver: \"223.5.5.5:53\"
  direct-nameserver: \"223.5.5.5:53\"
  proxy-nameserver: \"udp://8.8.8.8:53\"
rule-providers:
  cn-ip:
    type: file
    behavior: ip
    path: /tmp/cn-ip.ars
proxies:
  - name: hy2-main
    type: hysteria2
    server: 1.2.3.4
    port: 443
    password: pw
route:
  - MATCH,hy2-main
";
        let err = parse(yaml).unwrap_err().to_string();
        assert!(err.contains("must be a domain rule-provider"), "{err}");
    }
}
