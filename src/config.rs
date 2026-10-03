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
    #[serde(default)]
    pub rules: Vec<String>,
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
    #[serde(rename = "direct-nameserver", alias = "direct-dns")]
    pub direct_nameserver: String,
    #[serde(rename = "proxy-nameserver", alias = "proxy-dns")]
    pub proxy_nameserver: String,
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

/// Parsed mihomo-style rule line.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    /// Ruleset name for `RULE-SET`; `None` for `MATCH`.
    pub ruleset: Option<String>,
    /// Normalized outbound: `direct` / `block` / node name.
    pub outbound: String,
    pub is_match: bool,
}

/// Outbound names that cannot be used as proxy node names.
pub const RESERVED_OUTBOUND_NAMES: &[&str] = &["direct", "block", "final", "proxy", "reject"];

/// Normalize reserved outbound aliases (`DIRECT`→`direct`, `REJECT`→`block`).
pub fn normalize_outbound_name(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "direct" => "direct".into(),
        "reject" | "block" => "block".into(),
        _ => s.to_string(),
    }
}

/// Parse a single mihomo-style rule string.
/// Supported: `RULE-SET,<name>,<outbound>` and `MATCH,<outbound>`.
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
                outbound: normalize_outbound_name(parts[2]),
                is_match: false,
            })
        }
        "MATCH" => {
            if parts.len() < 2 {
                bail!("MATCH needs outbound, got: {line}");
            }
            Ok(ParsedRule {
                ruleset: None,
                outbound: normalize_outbound_name(parts[1]),
                is_match: true,
            })
        }
        other => bail!(
            "unsupported rule type `{other}` (only RULE-SET and MATCH are supported): {line}"
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

    /// Parse and validate all `rules:` lines.
    pub fn parsed_rules(&self) -> Result<Vec<ParsedRule>> {
        self.rules
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
        crate::dns::parse_nameserver(&self.dns.direct_nameserver).context("invalid direct-nameserver")?;
        crate::dns::parse_nameserver(&self.dns.proxy_nameserver).context("invalid proxy-nameserver")?;
        crate::dns::parse_nameserver(&self.dns.default_nameserver).context("invalid default-nameserver")?;

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

        // rules
        if self.rules.is_empty() {
            bail!("rules must not be empty; need a final MATCH rule");
        }
        let parsed = self.parsed_rules()?;
        let last = parsed.last().unwrap();
        if !last.is_match {
            bail!("last rule must be MATCH,<outbound>");
        }
        for (i, r) in parsed.iter().enumerate() {
            if i + 1 == parsed.len() {
                continue;
            }
            if r.is_match {
                bail!("MATCH is only allowed as the last rule (found at rules[{i}])");
            }
            let name = r.ruleset.as_deref().unwrap();
            if !ruleset_names.contains(name) {
                bail!("rules[{i}]: unknown rule-provider `{name}`");
            }
            if !known.contains(&r.outbound) {
                bail!(
                    "rules[{i}]: unknown outbound `{}`; use direct/DIRECT, block/REJECT, or a proxies name",
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
rules:
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
rules:
  - RULE-SET,cn,REJECT
  - MATCH,hy2-main
"#
        );
        let cfg = parse(&yaml).unwrap();
        let parsed = cfg.parsed_rules().unwrap();
        assert_eq!(parsed[0].outbound, "block");
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
        assert_eq!(r.ruleset.as_deref(), Some("ads"));
        assert_eq!(r.outbound, "block");
        assert!(!r.is_match);
        let m = parse_rule_line("MATCH,hy2-main").unwrap();
        assert!(m.is_match);
        assert_eq!(m.outbound, "hy2-main");
    }
}
