//! Routing: sniff first, then sequential RULE-SET match, MATCH last.

use crate::config::Config;
use crate::dns::cache::DnsCache;
use crate::dns::fakeip::FakeIpPool;
use crate::dns::{parse_nameserver, DnsUpstream};
use crate::ruleset::{self, RuleSet};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

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

/// DNS 上游决策：`Upstream` 正常转发；`Block` 回 NOERROR 空应答（rcode://success）。
#[derive(Debug, Clone)]
pub enum DnsAction {
    Upstream(DnsUpstream),
    Block,
}

/// DNS 上游选择策略（`dns.rule-follow-route`）。
enum DnsRoute {
    /// true（默认）：域名复用顶层 `route:` 匹配——direct → direct-nameserver、
    /// 节点 → proxy-nameserver、block/reject → rcode://success。
    FollowRoute {
        direct: DnsAction,
        proxy: DnsAction,
    },
    /// false：`dns.rules` 自定义表（Match kind = MATCH 兜底）。
    Rules(Vec<(crate::config::RuleKind, DnsAction)>),
}

pub struct Router {
    rulesets: RwLock<HashMap<String, RuleSet>>,
    routes: Vec<RouteEntry>,
    final_outbound: Outbound,
    fakeip: bool,
    fakeip_pool: Option<FakeIpPool>,
    fakeip_filter: Vec<String>,
    fakeip_whitelist: bool,
    /// Protocol sniffing (TLS/HTTP/QUIC) enabled via top-level `sniff: true`.
    sniff: bool,
    /// Top-level `route-resolve`.
    route_resolve: bool,
    // Read by the DNS-hijack path in tproxy/redir inbounds (linux/android only).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    hijack_dns: bool,
    dns_route: DnsRoute,
    /// Effective DNS IPv6 (global.ipv6 && dns.ipv6 && dns.enable).
    ipv6: bool,
    /// Top-level `ipv6` flag (controls ruleset IP loading and listen dual-stack).
    global_ipv6: bool,
    dns_cache: Option<Arc<DnsCache>>,
}

struct RouteEntry {
    kind: crate::config::RuleKind,
    outbound: Outbound,
    label: String,
    no_resolve: bool,
}

impl Router {
    pub async fn from_config(
        cfg: &Config,
        base_dir: Option<&std::path::Path>,
        cache: Option<Arc<crate::cache::AppCache>>,
    ) -> Result<Arc<Self>> {
        let ruleset_list = cfg.ruleset_list(base_dir)?;
        let mut rulesets = ruleset::load_all_providers(&ruleset_list, cache.as_deref()).await?;
        // Top-level ipv6=false → drop all IPv6 CIDRs from every ruleset so
        // IP matching is IPv4-only.
        let global_ipv6 = cfg.global.ipv6;
        if !global_ipv6 {
            for (name, rs) in rulesets.iter_mut() {
                rs.drop_ipv6();
                tracing::info!("ruleset `{name}`: IPv6 CIDRs dropped (ipv6=false)");
            }
        }
        for name in rulesets.keys() {
            tracing::info!("ruleset `{name}` ready");
        }

        let parsed = cfg.parsed_rules()?;
        let mut routes = Vec::new();
        let mut final_outbound = Outbound::Node("__unset__".into());
        for (i, r) in parsed.iter().enumerate() {
            if r.is_match() {
                final_outbound = Outbound::from_str(&r.outbound);
                continue;
            }
            if let Some(name) = r.ruleset_name() {
                if !rulesets.contains_key(name) {
                    anyhow::bail!("rules[{}] references unknown rule-provider {}", i, name);
                }
            }
            routes.push(RouteEntry {
                kind: r.kind.clone(),
                outbound: Outbound::from_str(&r.outbound),
                label: rule_label(&r.kind),
                no_resolve: r.no_resolve,
            });
        }

        // DNS 模块总开关：无 `dns:` 块或 enable=false → 完全不启用
        // （无监听、无劫持、无 fakeip/缓存；内部解析走系统 resolver）。
        let dns_enabled = cfg.dns.enable;
        // Effective DNS IPv6 requires both top-level ipv6 and dns.ipv6.
        let ipv6 = dns_enabled && global_ipv6 && cfg.dns.ipv6;
        let fakeip = dns_enabled && cfg.dns.mode == "fakeip";
        // Persist DNS/FakeIP only when top-level `cache: true` and redb is open.
        let persist_store: Option<Arc<crate::cache::AppCache>> =
            if cfg.global.cache { cache.clone() } else { None };

        let fakeip_pool = if fakeip {
            let v6_range = if ipv6 {
                cfg.dns.fakeip6_range.as_deref()
            } else {
                None
            };
            let pool = FakeIpPool::new(cfg.dns.fakeip_range.as_deref(), v6_range)?
                .with_store(persist_store.clone());
            Some(pool)
        } else {
            None
        };
        if fakeip {
            tracing::info!(
                "fake-ip enabled v4={:?} v6={:?} ipv6={} mode={} filter={:?} persistent={}",
                cfg.dns.fakeip_range,
                if ipv6 {
                    cfg.dns.fakeip6_range.clone()
                } else {
                    None
                },
                ipv6,
                cfg.dns.fakeip_filter_mode,
                cfg.dns.fakeip_filter,
                persist_store.is_some()
            );
        }

        let dns_cache = if dns_enabled && cfg.dns.cache_size > 0 {
            tracing::info!(
                "dns cache size={} persistent={}",
                cfg.dns.cache_size,
                persist_store.is_some()
            );
            Some(Arc::new(DnsCache::with_store(
                cfg.dns.cache_size,
                persist_store.clone(),
            )))
        } else {
            None
        };

        let dns_route = if !dns_enabled {
            // 模块关闭：不出上游；answer_query 在此状态下不可能被调用
            // （监听未启动、劫持路径已被 hijack_dns=false 关闭）。
            DnsRoute::Rules(Vec::new())
        } else if cfg.dns.rule_follow_route {
            let direct = parse_nameserver(
                cfg.dns
                    .direct_nameserver
                    .as_deref()
                    .context("rule-follow-route=true requires dns.direct-nameserver")?,
            )?;
            let proxy = parse_nameserver(
                cfg.dns
                    .proxy_nameserver
                    .as_deref()
                    .context("rule-follow-route=true requires dns.proxy-nameserver")?,
            )?;
            tracing::info!("dns rule-follow-route=true direct={direct} proxy={proxy}");
            DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(direct),
                proxy: DnsAction::Upstream(proxy),
            }
        } else {
            let mut entries: Vec<(crate::config::RuleKind, DnsAction)> = Vec::new();
            if cfg.dns.rules.is_empty() {
                // 无 dns.rules：nameserver 即默认上游（配置校验已强制存在）。
                let ns = cfg
                    .dns
                    .nameserver
                    .as_deref()
                    .context("rule-follow-route=false without dns.rules requires dns.nameserver")?;
                let up = parse_nameserver(ns)?;
                tracing::info!("dns rule-follow-route=false rules=0 nameserver={up}");
                entries.push((crate::config::RuleKind::Match, DnsAction::Upstream(up)));
            } else {
                for (i, line) in cfg.dns.rules.iter().enumerate() {
                    let r = crate::config::parse_dns_rule_line(line)
                        .with_context(|| format!("dns.rules[{i}]"))?;
                    let action = if r.upstream.eq_ignore_ascii_case("rcode://success") {
                        DnsAction::Block
                    } else {
                        DnsAction::Upstream(parse_nameserver(&r.upstream)?)
                    };
                    tracing::info!("dns rule {} -> {}", line.trim(), match &action {
                        DnsAction::Upstream(u) => u.to_string(),
                        DnsAction::Block => "rcode://success".into(),
                    });
                    entries.push((r.kind, action));
                }
            }
            DnsRoute::Rules(entries)
        };

        Ok(Arc::new(Router {
            rulesets: RwLock::new(rulesets),
            routes,
            final_outbound,
            fakeip,
            fakeip_pool,
            fakeip_filter: cfg.dns.fakeip_filter.clone(),
            fakeip_whitelist: cfg.dns.fakeip_filter_mode == "whitelist",
            sniff: cfg.global.sniff,
            route_resolve: cfg.global.route_resolve,
            hijack_dns: dns_enabled && cfg.dns.route_hijack,
            dns_route,
            ipv6,
            global_ipv6,
            dns_cache,
        }))
    }

    /// DNS 上游决策：`None` → block（NOERROR 空应答，rcode://success）。
    pub fn dns_action_for_domain(&self, domain: &str) -> Option<&DnsAction> {
        match &self.dns_route {
            DnsRoute::FollowRoute { direct, proxy } => {
                match self.dns_outbound_for_domain(domain) {
                    Outbound::Direct => Some(direct),
                    Outbound::Node(_) => Some(proxy),
                    Outbound::Block => None,
                }
            }
            DnsRoute::Rules(entries) => entries
                .iter()
                .find(|(kind, _)| self.match_kind(kind, Some(domain), None, None, &[], true))
                .map(|(_, action)| action),
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
    pub fn use_fakeip(&self, domain: &str) -> bool {
        if !self.fakeip || domain.is_empty() {
            return false;
        }
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let guard = self.rulesets.read().ok();
        let hit = self.fakeip_filter.iter().any(|name| {
            guard
                .as_ref()
                .and_then(|g| g.get(name.as_str()))
                .is_some_and(|rs| rs.match_domain(&d))
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

    /// Replace a loaded ruleset (used by remote auto-update).
    /// When top-level `ipv6=false`, IPv6 CIDRs are stripped before insertion.
    pub fn replace_ruleset(&self, name: &str, mut rs: RuleSet) {
        if !self.global_ipv6 {
            rs.drop_ipv6();
        }
        if let Ok(mut g) = self.rulesets.write() {
            g.insert(name.to_string(), rs);
            tracing::info!(name, "ruleset hot-reloaded");
        }
    }

    /// Snapshot of loaded rulesets for the API info panel: (name, rule_count).
    pub fn ruleset_stats(&self) -> Vec<(String, usize)> {
        let guard = match self.rulesets.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<(String, usize)> = guard
            .iter()
            .map(|(n, rs)| (n.clone(), rs.rule_count))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Background loop: re-download `type: http` providers with `update-interval` > 0.
    /// Interval unit is **hours**.
    pub fn spawn_ruleset_updater(
        self: &Arc<Self>,
        list: Vec<crate::config::RulesetConfig>,
        cache: Option<Arc<crate::cache::AppCache>>,
    ) {
        for rs in list {
            if !rs.provider_type.eq_ignore_ascii_case("http") {
                continue;
            }
            if rs.update_interval == 0 {
                continue;
            }
            if rs.url.as_ref().map(|u| u.trim().is_empty()).unwrap_or(true) {
                continue;
            }
            let hours = rs.update_interval;
            let router = Arc::clone(self);
            let cache = cache.clone();
            let cfg = rs;
            tokio::spawn(async move {
                let period = std::time::Duration::from_secs(hours.saturating_mul(3600));
                tracing::info!(
                    name = %cfg.name,
                    hours,
                    "ruleset auto-update scheduled"
                );
                loop {
                    tokio::time::sleep(period).await;
                    match crate::ruleset::refresh_remote(&cfg, cache.as_deref()).await {
                        Ok(loaded) => router.replace_ruleset(&cfg.name, loaded),
                        Err(e) => tracing::warn!(
                            name = %cfg.name,
                            error = %e,
                            "ruleset auto-update failed"
                        ),
                    }
                }
            });
        }
    }

    pub fn route_resolve(&self) -> bool {
        self.route_resolve
    }

    /// Match by domain (preferred after sniff) and/or destination IP.
    pub fn match_outbound(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Outbound {
        self.match_route(domain, ip, &[]).outbound
    }

    /// `resolved_ips`: addresses from resolving `domain` when `route-resolve: true`.
    /// Used for IP rules that do not carry `no-resolve`.
    pub fn match_route(
        &self,
        domain: Option<&str>,
        ip: Option<IpAddr>,
        resolved_ips: &[IpAddr],
    ) -> RouteMatch {
        self.match_route_ex(domain, ip, None, resolved_ips)
    }

    pub fn match_route_ex(
        &self,
        domain: Option<&str>,
        dst_ip: Option<IpAddr>,
        src_ip: Option<IpAddr>,
        resolved_ips: &[IpAddr],
    ) -> RouteMatch {
        // Fake-ip addresses must not hit ip rulesets; route by the mapped domain.
        let dst_ip = dst_ip.filter(|addr| self.domain_for_fakeip(*addr).is_none());
        for entry in &self.routes {
            if self.match_kind(
                &entry.kind,
                domain,
                dst_ip,
                src_ip,
                resolved_ips,
                entry.no_resolve,
            ) {
                tracing::debug!(
                    "route hit {} -> {}{}",
                    entry.label,
                    entry.outbound.label(),
                    if entry.no_resolve { " (no-resolve)" } else { "" }
                );
                return RouteMatch {
                    outbound: entry.outbound.clone(),
                    rule: entry.label.clone(),
                };
            }
        }
        tracing::debug!("route MATCH -> {}", self.final_outbound.label());
        RouteMatch {
            outbound: self.final_outbound.clone(),
            rule: "MATCH".into(),
        }
    }

    fn match_kind(
        &self,
        kind: &crate::config::RuleKind,
        domain: Option<&str>,
        dst_ip: Option<IpAddr>,
        src_ip: Option<IpAddr>,
        resolved_ips: &[IpAddr],
        no_resolve: bool,
    ) -> bool {
        use crate::config::RuleKind;
        match kind {
            RuleKind::Match => true,
            RuleKind::RuleSet(name) => {
                let guard = match self.rulesets.read() {
                    Ok(g) => g,
                    Err(_) => return false,
                };
                let Some(rs) = guard.get(name) else {
                    return false;
                };
                if let Some(d) = domain {
                    if rs.match_domain(d) {
                        return true;
                    }
                }
                if let Some(addr) = dst_ip {
                    if rs.match_ip(addr) {
                        return true;
                    }
                }
                // route-resolve: also try resolved IPs unless no-resolve
                if self.route_resolve && !no_resolve {
                    for addr in resolved_ips {
                        if rs.match_ip(*addr) {
                            return true;
                        }
                    }
                }
                false
            }
            RuleKind::Domain(d) => domain
                .map(|x| {
                    let x = x.trim_end_matches('.').to_ascii_lowercase();
                    x == *d
                })
                .unwrap_or(false),
            RuleKind::DomainSuffix(suf) => domain
                .map(|x| {
                    let x = x.trim_end_matches('.').to_ascii_lowercase();
                    x == *suf || x.ends_with(&format!(".{suf}"))
                })
                .unwrap_or(false),
            RuleKind::DomainKeyword(kw) => domain
                .map(|x| {
                    let x = x.trim_end_matches('.').to_ascii_lowercase();
                    x.contains(kw.as_str())
                })
                .unwrap_or(false),
            RuleKind::DomainRegex(re) => domain
                .map(|x| {
                    let x = x.trim_end_matches('.').to_ascii_lowercase();
                    regex::Regex::new(re)
                        .map(|r| r.is_match(&x))
                        .unwrap_or(false)
                })
                .unwrap_or(false),
            RuleKind::IpCidr(cidr) => {
                if let Some(addr) = dst_ip {
                    if ip_in_cidr(addr, cidr) {
                        return true;
                    }
                }
                if self.route_resolve && !no_resolve {
                    for addr in resolved_ips {
                        if ip_in_cidr(*addr, cidr) {
                            return true;
                        }
                    }
                }
                false
            }
            RuleKind::SrcIpCidr(cidr) => {
                src_ip.map(|addr| ip_in_cidr(addr, cidr)).unwrap_or(false)
            }
        }
    }

    /// For DNS (rule-follow-route=true): decide which upstream (or block) for a
    /// domain query by reusing the top-level `route:` match.
    fn dns_outbound_for_domain(&self, domain: &str) -> Outbound {
        for entry in &self.routes {
            if self.match_kind(&entry.kind, Some(domain), None, None, &[], true) {
                return entry.outbound.clone();
            }
        }
        self.final_outbound.clone()
    }
}

fn rule_label(kind: &crate::config::RuleKind) -> String {
    use crate::config::RuleKind;
    match kind {
        RuleKind::Match => "MATCH".into(),
        RuleKind::RuleSet(n) => n.clone(),
        RuleKind::Domain(d) => format!("DOMAIN,{d}"),
        RuleKind::DomainSuffix(s) => format!("DOMAIN-SUFFIX,{s}"),
        RuleKind::DomainKeyword(k) => format!("DOMAIN-KEYWORD,{k}"),
        RuleKind::DomainRegex(r) => format!("DOMAIN-REGEX,{r}"),
        RuleKind::IpCidr(c) => format!("IP-CIDR,{c}"),
        RuleKind::SrcIpCidr(c) => format!("SRC-IP-CIDR,{c}"),
    }
}

fn ip_in_cidr(addr: IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if let Ok(ip) = cidr.parse::<IpAddr>() {
        return ip == addr;
    }
    let (ip_s, prefix_s) = match cidr.split_once('/') {
        Some(p) => p,
        None => return false,
    };
    let prefix: u8 = match prefix_s.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    match (addr, ip_s.parse::<IpAddr>()) {
        (IpAddr::V4(a), Ok(IpAddr::V4(base))) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
            (u32::from(a) & mask) == (u32::from(base) & mask)
        }
        (IpAddr::V6(a), Ok(IpAddr::V6(base))) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(base) & mask)
        }
        _ => false,
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
            rulesets: RwLock::new(rulesets),
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: true,
            fakeip_pool: Some(FakeIpPool::new(Some("198.18.0.0/15"), None).unwrap()),
            fakeip_filter: vec!["cn".to_string()],
            fakeip_whitelist: whitelist,
            sniff: false,
            route_resolve: false,
            hijack_dns: false,
            dns_route: DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                proxy: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
            },
            ipv6: true,
            global_ipv6: true,
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

    #[test]
    fn dns_action_rules_mode() {
        let cn = domain_ruleset("cn", "payload:\n  - DOMAIN-SUFFIX,cn\n");
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        let r = Router {
            rulesets: RwLock::new(rulesets),
            routes: vec![],
            final_outbound: Outbound::Node("main".into()),
            fakeip: false,
            fakeip_pool: None,
            fakeip_filter: vec![],
            fakeip_whitelist: false,
            sniff: false,
            route_resolve: false,
            hijack_dns: false,
            dns_route: DnsRoute::Rules(vec![
                (
                    crate::config::RuleKind::RuleSet("cn".into()),
                    DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                ),
                (crate::config::RuleKind::Match, DnsAction::Block),
            ]),
            ipv6: true,
            global_ipv6: true,
            dns_cache: None,
        };
        match r.dns_action_for_domain("www.baidu.cn") {
            Some(DnsAction::Upstream(u)) => assert_eq!(u.to_string(), "udp://223.5.5.5:53"),
            other => panic!("expected upstream, got {other:?}"),
        }
        // 未命中 → MATCH 兜底 → rcode://success
        assert!(matches!(
            r.dns_action_for_domain("google.com"),
            Some(DnsAction::Block)
        ));
    }

    #[test]
    fn dns_action_follow_route_block_and_node() {
        let cn = domain_ruleset("cn", "payload:\n  - DOMAIN-SUFFIX,cn\n");
        let mut rulesets = HashMap::new();
        rulesets.insert("cn".to_string(), cn);
        let r = Router {
            rulesets: RwLock::new(rulesets),
            routes: vec![
                RouteEntry {
                    kind: crate::config::RuleKind::RuleSet("cn".into()),
                    outbound: Outbound::Block,
                    label: "cn".into(),
                    no_resolve: false,
                },
            ],
            final_outbound: Outbound::Node("main".into()),
            fakeip: false,
            fakeip_pool: None,
            fakeip_filter: vec![],
            fakeip_whitelist: false,
            sniff: false,
            route_resolve: false,
            hijack_dns: false,
            dns_route: DnsRoute::FollowRoute {
                direct: DnsAction::Upstream(parse_nameserver("223.5.5.5:53").unwrap()),
                proxy: DnsAction::Upstream(parse_nameserver("8.8.8.8:53").unwrap()),
            },
            ipv6: true,
            global_ipv6: true,
            dns_cache: None,
        };
        // route 出站 block → None（rcode://success）
        assert!(r.dns_action_for_domain("www.baidu.cn").is_none());
        // route 出站节点 → proxy-nameserver
        match r.dns_action_for_domain("google.com") {
            Some(DnsAction::Upstream(u)) => assert_eq!(u.to_string(), "udp://8.8.8.8:53"),
            other => panic!("expected proxy upstream, got {other:?}"),
        }
    }
}
