//! Routing: sniff first, then sequential RULE-SET match, MATCH last.

use crate::config::Config;
use crate::dns::cache::DnsCache;
use crate::dns::fakeip::FakeIpPool;
use crate::dns::{parse_nameserver, DnsUpstream};
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
    /// Parse a route outbound value: `direct`/`DIRECT` and `block`/`REJECT`
    /// are reserved; anything else is a proxy node name (validated by config).
    pub fn from_str(s: &str) -> Self {
        match crate::config::normalize_outbound_name(s).as_str() {
            "direct" => Outbound::Direct,
            "block" => Outbound::Block,
            other => Outbound::Node(other.to_string()),
        }
    }

    /// Display label: `direct` / `block` / the node name.
    pub fn label(&self) -> String {
        match self {
            Outbound::Direct => "direct".into(),
            Outbound::Block => "block".into(),
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
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    direct_dns: DnsUpstream,
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    proxy_dns: DnsUpstream,
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
                anyhow::bail!("rules[{}] references unknown rule-provider {}", i, name);
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
            direct_dns: cfg.dns.resolved_direct.clone().unwrap_or(parse_nameserver(&cfg.dns.direct_nameserver)?),
            proxy_dns: cfg.dns.resolved_proxy.clone().unwrap_or(parse_nameserver(&cfg.dns.proxy_nameserver)?),
            ipv6,
            dns_cache,
        }))
    }

    // Used by tproxy/redir DNS hijack (linux/android only).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub fn dns_upstreams(&self) -> (&DnsUpstream, &DnsUpstream) {
        (&self.direct_dns, &self.proxy_dns)
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
    pub fn use_fakeip(&self, domain: &str) -> bool {
        if !self.fakeip || domain.is_empty() {
            return false;
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let hit = self
            .fakeip_filter
            .iter()
            .any(|name| self.rulesets.get(name).is_some_and(|rs| rs.match_domain(&d)));
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
            fakeip_filter: vec!["cn".to_string()],
            fakeip_whitelist: whitelist,
            sniff: false,
            hijack_dns: false,
            direct_dns: parse_nameserver("223.5.5.5:53").unwrap(),
            proxy_dns: parse_nameserver("223.5.5.5:53").unwrap(),
            ipv6: true,
            dns_cache: None,
        }
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
        assert_eq!(Outbound::from_str("direct"), Outbound::Direct);
        assert_eq!(Outbound::from_str("DIRECT"), Outbound::Direct);
        assert_eq!(Outbound::from_str("block"), Outbound::Block);
        assert_eq!(Outbound::from_str("REJECT"), Outbound::Block);
        assert_eq!(
            Outbound::from_str("hy2-main"),
            Outbound::Node("hy2-main".into())
        );
        assert_eq!(Outbound::Node("hy2-main".into()).label(), "hy2-main");
        assert!(Outbound::Node("x".into()) != Outbound::Node("y".into()));
        let _ = IpAddr::from([127, 0, 0, 1]); // silence unused import if cfg changes
    }
}
