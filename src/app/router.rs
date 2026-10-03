//! Routing: sniff first, then sequential RULE-SET match, MATCH last.

use crate::config::Config;
use crate::dns::cache::DnsCache;
use crate::dns::fakeip::FakeIpPool;
use crate::dns::{
    DnsResolvedRoute, DnsRouteTarget, DnsUpstream, DnsUpstreamPick, parse_nameserver,
};
use crate::ruleset::{self, RuleSet};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Direct,
    /// A named proxy node; resolved to its dialer by OutboundManager.
    Node(String),
    /// Reject connection; DNS answers with NOERROR empty (rcode://success).
    Block,
}

impl Outbound {
    /// Parse a `route:` outbound value. The built-in outbounds accept the
    /// aliases `DIRECT` / `direct` and `BLOCK` / `block` / `REJECT` / `reject`
    /// (they are reserved, see `config::RESERVED_NODE_NAMES`, so no node can
    /// shadow them). Anything else is a proxy node name (validated by config).
    pub fn from_str(s: &str) -> Self {
        match s {
            "DIRECT" | "direct" => Outbound::Direct,
            "BLOCK" | "block" | "REJECT" | "reject" => Outbound::Block,
            other => Outbound::Node(other.to_string()),
        }
    }

    /// Display label: `DIRECT` / `BLOCK` / the node name.
    pub fn label(&self) -> String {
        match self {
            Outbound::Direct => "DIRECT".into(),
            Outbound::Block => "BLOCK".into(),
            Outbound::Node(name) => name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub outbound: Outbound,
    /// Ruleset name, or `"MATCH"`.
    pub rule: String,
}

pub struct Router {
    rulesets: HashMap<String, RuleSet>,
    routes: Vec<RouteEntry>,
    final_outbound: Outbound,
    fakeip: bool,
    fakeip_pool: Option<FakeIpPool>,
    fakeip_filter: Vec<String>,
    fakeip_whitelist: bool,
    /// Protocol sniffing (TLS/HTTP/QUIC) enabled via top-level `sniff: true`.
    sniff: bool,
    // Read by the DNS-hijack path in tproxy/redir inbounds (linux/android only).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    hijack_dns: bool,
    // DNS upstream selection (`rule-follow-route`).
    // true mode: connection-routing rules pick direct/proxy-nameserver.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    direct_dns: Option<DnsUpstream>,
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    proxy_dns: Option<DnsUpstream>,
    // false mode: dns.rules entries + optional default `nameserver`.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    dns_rule: Option<Vec<DnsResolvedRoute>>,
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    dns_default: Option<DnsUpstream>,
    ipv6: bool,
    dns_cache: Option<Arc<DnsCache>>,
}

struct RouteEntry {
    ruleset: String,
    outbound: Outbound,
}

impl Router {
    pub fn from_config(cfg: &Config) -> Result<Arc<Self>> {
        let ruleset_list = cfg.ruleset_list()?;
        let mut rulesets = HashMap::new();
        for rs in &ruleset_list {
            let loaded = ruleset::load_ars(&rs.name, &rs.path)?;
            tracing::info!(
                "loaded ruleset {} ({}) from {:?}",
                rs.name,
                rs.ty,
                rs.path
            );
            rulesets.insert(rs.name.clone(), loaded);
        }

        let parsed = cfg.parsed_rules()?;
        let mut routes = Vec::new();
        let mut final_outbound = Outbound::Node("__unset__".into());
        for (i, r) in parsed.iter().enumerate() {
            if r.is_match {
                final_outbound = Outbound::from_str(&r.outbound);
                continue;
            }
            let name = r.ruleset.as_ref().unwrap();
            if !rulesets.contains_key(name) {
                anyhow::bail!("route[{}] references unknown rule-provider {}", i, name);
            }
            routes.push(RouteEntry {
                ruleset: name.clone(),
                outbound: Outbound::from_str(&r.outbound),
            });
        }

        let ipv6 = cfg.dns.ipv6;
        let fakeip = cfg.dns.mode == "fakeip";
        let fakeip_pool = if fakeip {
            let v6_range = if ipv6 {
                cfg.dns.fakeip6_range.as_deref()
            } else {
                None
            };
            Some(FakeIpPool::new(cfg.dns.fakeip_range.as_deref(), v6_range)?)
        } else {
            None
        };
        if fakeip {
            tracing::info!(
                "fake-ip enabled v4={:?} v6={:?} ipv6={} mode={} filter={:?}",
                cfg.dns.fakeip_range,
                if ipv6 {
                    cfg.dns.fakeip6_range.clone()
                } else {
                    None
                },
                ipv6,
                cfg.dns.fakeip_filter_mode,
                cfg.dns.fakeip_filter
            );
        }

        let dns_cache = if cfg.dns.cache_size > 0 {
            tracing::info!("dns cache size={}", cfg.dns.cache_size);
            Some(Arc::new(DnsCache::new(cfg.dns.cache_size)))
        } else {
            None
        };

        // DNS upstream selection per `rule-follow-route`.
        let (direct_dns, proxy_dns, dns_rule, dns_default) = if cfg.dns.rule_follow_route {
            let direct = match cfg.dns.resolved_direct.clone() {
                Some(u) => u,
                None => parse_nameserver(&cfg.dns.direct_nameserver)?,
            };
            let proxy = match cfg.dns.resolved_proxy.clone() {
                Some(u) => u,
                None => parse_nameserver(&cfg.dns.proxy_nameserver)?,
            };
            (Some(direct), Some(proxy), None, None)
        } else {
            let default = match cfg.dns.resolved_nameserver.clone() {
                Some(u) => Some(u),
                None if cfg.dns.nameserver.trim().is_empty() => None,
                None => Some(parse_nameserver(&cfg.dns.nameserver)?),
            };
            let rule = cfg.dns.resolved_rules.clone().unwrap_or_default();
            tracing::info!(
                "dns rule-follow-route=false: {} dns.rules, default nameserver={}",
                rule.len(),
                default
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "none (match rule)".into())
            );
            (None, None, Some(rule), default)
        };

        Ok(Arc::new(Router {
            rulesets,
            routes,
            final_outbound,
            fakeip,
            fakeip_pool,
            fakeip_filter: cfg.dns.fakeip_filter.clone(),
            fakeip_whitelist: cfg.dns.fakeip_filter_mode == "whitelist",
            sniff: cfg.global.sniff,
            hijack_dns: cfg.dns.route_hijack,
            direct_dns,
            proxy_dns,
            dns_rule,
            dns_default,
            ipv6,
            dns_cache,
        }))
    }

    // Used by the DNS server and the tproxy/redir DNS-hijack path (linux/android only).
    /// Pick the DNS upstream for one query.
    /// - `rule-follow-route: true`: connection-routing rules decide —
    ///   DIRECT → `direct-nameserver`, any node → `proxy-nameserver`, block → empty answer.
    /// - `rule-follow-route: false`: `dns.rules` entries (`ruleset,<name>,<target>` /
    ///   `match,<target>`); `match` always terminates the list. If no `match` is
    ///   present (i.e. the list is empty), fall back to `nameserver`.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub fn dns_upstream_for(&self, domain: &str) -> DnsUpstreamPick<'_> {
        if let Some(rules) = &self.dns_rule {
            for entry in rules {
                let hit = match &entry.ruleset {
                    None => true, // `match` fallback
                    Some(name) => self
                        .rulesets
                        .get(name)
                        .is_some_and(|rs| rs.match_domain(domain)),
                };
                if hit {
                    return match &entry.target {
                        DnsRouteTarget::Block => DnsUpstreamPick::Block,
                        DnsRouteTarget::Upstream(u) => DnsUpstreamPick::Upstream {
                            label: entry.ruleset.clone().unwrap_or_else(|| "match".into()),
                            upstream: u,
                        },
                    };
                }
            }
            if let Some(def) = &self.dns_default {
                return DnsUpstreamPick::Upstream {
                    label: "nameserver".into(),
                    upstream: def,
                };
            }
            // Unreachable: validate() requires `nameserver` in rule mode.
            return DnsUpstreamPick::Block;
        }
        let direct = self
            .direct_dns
            .as_ref()
            .expect("direct-nameserver present in rule-follow-route mode");
        let proxy = self
            .proxy_dns
            .as_ref()
            .expect("proxy-nameserver present in rule-follow-route mode");
        match self.dns_outbound_for_domain(domain) {
            Outbound::Block => DnsUpstreamPick::Block,
            Outbound::Direct => DnsUpstreamPick::Upstream {
                label: "DIRECT".into(),
                upstream: direct,
            },
            Outbound::Node(name) => DnsUpstreamPick::Upstream {
                label: name,
                upstream: proxy,
            },
        }
    }

    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub fn hijack_dns(&self) -> bool {
        self.hijack_dns
    }

    pub fn sniff(&self) -> bool {
        self.sniff
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    pub fn dns_cache(&self) -> Option<&DnsCache> {
        self.dns_cache.as_deref()
    }

    pub fn fakeip_enabled(&self) -> bool {
        self.fakeip
    }

    /// Blacklist mode (default): matched domains stay real-IP, everything
    /// else gets fake-ip. Whitelist mode: only matched domains get fake-ip.
    /// `fakeip_filter` holds `RULE-SET,<provider-name>` entries.
    pub fn use_fakeip(&self, domain: &str) -> bool {
        if !self.fakeip || domain.is_empty() {
            return false;
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let hit = self.fakeip_filter.iter().any(|entry| {
            crate::config::parse_fakeip_filter_entry(entry)
                .ok()
                .is_some_and(|name| {
                    self.rulesets
                        .get(&name)
                        .is_some_and(|rs| rs.match_domain(&d))
                })
        });
        if self.fakeip_whitelist {
            hit
        } else {
            !hit
        }
    }

    pub fn allocate_fakeip(&self, domain: &str, v6: bool) -> Option<std::net::IpAddr> {
        if v6 && !self.ipv6 {
            return None;
        }
        self.fakeip_pool.as_ref()?.allocate(domain, v6)
    }

    pub fn has_fakeip_v4(&self) -> bool {
        self.fakeip_pool.as_ref().map(|p| p.has_v4()).unwrap_or(false)
    }

    pub fn has_fakeip_v6(&self) -> bool {
        self.ipv6
            && self
                .fakeip_pool
                .as_ref()
                .map(|p| p.has_v6())
                .unwrap_or(false)
    }

    /// Map a destination fake-ip back to the domain that was answered.
    pub fn domain_for_fakeip(&self, ip: std::net::IpAddr) -> Option<String> {
        let pool = self.fakeip_pool.as_ref()?;
        if !pool.contains(ip) {
            return None;
        }
        pool.domain_of(ip)
    }

    /// Match by domain (preferred after sniff) and/or destination IP.
    pub fn match_outbound(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Outbound {
        self.match_route(domain, ip).outbound
    }

    pub fn match_route(&self, domain: Option<&str>, ip: Option<IpAddr>) -> RouteMatch {
        // Fake-ip addresses must not hit ip rulesets; route by the mapped domain.
        let ip = ip.filter(|addr| self.domain_for_fakeip(*addr).is_none());
        for entry in &self.routes {
            if let Some(rs) = self.rulesets.get(&entry.ruleset) {
                let hit = match (domain, ip) {
                    (Some(d), _) if rs.match_domain(d) => true,
                    (_, Some(addr)) if rs.match_ip(addr) => true,
                    _ => false,
                };
                if hit {
                    tracing::debug!(
                        "route hit ruleset={} -> {}",
                        entry.ruleset,
                        entry.outbound.label()
                    );
                    return RouteMatch {
                        outbound: entry.outbound.clone(),
                        rule: entry.ruleset.clone(),
                    };
                }
            }
        }
        tracing::debug!("route MATCH -> {}", self.final_outbound.label());
        RouteMatch {
            outbound: self.final_outbound.clone(),
            rule: "MATCH".into(),
        }
    }

    /// For DNS: decide which upstream (or block) for a domain query.
    pub fn dns_outbound_for_domain(&self, domain: &str) -> Outbound {
        for entry in &self.routes {
            if let Some(rs) = self.rulesets.get(&entry.ruleset) {
                if rs.match_domain(domain) {
                    return entry.outbound.clone();
                }
            }
        }
        self.final_outbound.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::parse_nameserver;
    use std::net::IpAddr;

    fn domain_ruleset(name: &str, yaml: &str) -> RuleSet {
        let compiled = crate::ruleset::compile_mihomo_ruleset(
            yaml,
            Some(crate::ruleset::ProviderBehavior::Classical),
        )
        .unwrap();
        let mut buf = Vec::new();
        crate::ruleset::write_ars(&compiled, &mut buf).unwrap();
        RuleSet::from_bytes(name, &buf).unwrap()
    }

    fn router_with_filter(whitelist: bool) -> Router {
        let cn = domain_ruleset(
            "cn",
            "payload:
  - DOMAIN-SUFFIX,cn
",
        );
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        Router {
            rulesets,
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: true,
            fakeip_pool: Some(FakeIpPool::new(Some("198.18.0.0/15"), None).unwrap()),
            fakeip_filter: vec!["RULE-SET,cn".to_string()],
            fakeip_whitelist: whitelist,
            sniff: false,
            hijack_dns: false,
            direct_dns: Some(parse_nameserver("223.5.5.5:53").unwrap()),
            proxy_dns: Some(parse_nameserver("8.8.8.8:53").unwrap()),
            dns_rule: None,
            dns_default: None,
            ipv6: true,
            dns_cache: None,
        }
    }

    fn upstream_label(pick: DnsUpstreamPick<'_>) -> String {
        match pick {
            DnsUpstreamPick::Block => "block".into(),
            DnsUpstreamPick::Upstream { label, .. } => label,
        }
    }

    fn rule_router(rules: Vec<DnsResolvedRoute>, default: Option<DnsUpstream>) -> Router {
        let cn = domain_ruleset(
            "cn",
            "payload:
  - DOMAIN-SUFFIX,cn
",
        );
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        Router {
            rulesets,
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: false,
            fakeip_pool: None,
            fakeip_filter: vec![],
            fakeip_whitelist: false,
            sniff: false,
            hijack_dns: false,
            direct_dns: None,
            proxy_dns: None,
            dns_rule: Some(rules),
            dns_default: default,
            ipv6: true,
            dns_cache: None,
        }
    }

    #[test]
    fn dns_rule_mode_picks_configured_upstream() {
        let cn_up = parse_nameserver("223.5.5.5:53").unwrap();
        let r = rule_router(
            vec![
                DnsResolvedRoute {
                    ruleset: Some("cn".into()),
                    target: DnsRouteTarget::Upstream(cn_up),
                },
                DnsResolvedRoute {
                    ruleset: None,
                    target: DnsRouteTarget::Upstream(parse_nameserver("1.1.1.1:53").unwrap()),
                },
            ],
            None,
        );
        // ruleset hit → its upstream; miss → `match` fallback.
        assert_eq!(upstream_label(r.dns_upstream_for("www.baidu.cn")), "cn");
        assert_eq!(upstream_label(r.dns_upstream_for("google.com")), "match");
    }

    #[test]
    fn dns_rule_mode_miss_falls_to_nameserver_default() {
        let cn_up = parse_nameserver("223.5.5.5:53").unwrap();
        let def = parse_nameserver("9.9.9.9:53").unwrap();
        let r = rule_router(
            vec![DnsResolvedRoute {
                ruleset: Some("cn".into()),
                target: DnsRouteTarget::Upstream(cn_up),
            }],
            Some(def),
        );
        assert_eq!(upstream_label(r.dns_upstream_for("www.baidu.cn")), "cn");
        assert_eq!(
            upstream_label(r.dns_upstream_for("google.com")),
            "nameserver"
        );
    }

    #[test]
    fn dns_rule_mode_block_target_answers_empty() {
        let r = rule_router(
            vec![DnsResolvedRoute {
                ruleset: Some("cn".into()),
                target: DnsRouteTarget::Block,
            }],
            Some(parse_nameserver("9.9.9.9:53").unwrap()),
        );
        assert!(matches!(
            r.dns_upstream_for("www.baidu.cn"),
            DnsUpstreamPick::Block
        ));
    }

    #[test]
    fn dns_follow_route_maps_outbound_to_nameserver() {
        let r = router_with_filter(false);
        // No `routes`: everything falls to final_outbound = node "main" → proxy-nameserver.
        assert_eq!(upstream_label(r.dns_upstream_for("google.com")), "main");
    }

    #[test]
    fn fakeip_blacklist_matched_stays_real_ip() {
        let r = router_with_filter(false);
        assert!(r.use_fakeip("google.com"));
        assert!(!r.use_fakeip("www.baidu.cn"));
        // trailing dot tolerated: still matches the filter ruleset
        assert!(!r.use_fakeip("www.baidu.cn."));
        assert!(!r.use_fakeip(""));
    }

    #[test]
    fn fakeip_whitelist_only_matched_gets_fake_ip() {
        let r = router_with_filter(true);
        assert!(!r.use_fakeip("google.com"));
        assert!(r.use_fakeip("www.baidu.cn"));
    }

    #[test]
    fn outbound_node_label_roundtrip() {
        // Built-in aliases (all reserved, so no node can shadow them).
        assert_eq!(Outbound::from_str("DIRECT"), Outbound::Direct);
        assert_eq!(Outbound::from_str("direct"), Outbound::Direct);
        assert_eq!(Outbound::from_str("BLOCK"), Outbound::Block);
        assert_eq!(Outbound::from_str("block"), Outbound::Block);
        assert_eq!(Outbound::from_str("REJECT"), Outbound::Block);
        assert_eq!(Outbound::from_str("reject"), Outbound::Block);
        // anything else is a node name
        assert_eq!(
            Outbound::from_str("hy2-main"),
            Outbound::Node("hy2-main".into())
        );
        assert_eq!(Outbound::Node("hy2-main".into()).label(), "hy2-main");
        assert_eq!(Outbound::Direct.label(), "DIRECT");
        assert_eq!(Outbound::Block.label(), "BLOCK");
        assert!(Outbound::Node("x".into()) != Outbound::Node("y".into()));
        let _ = IpAddr::from([127, 0, 0, 1]); // silence unused import if cfg changes
    }
}
