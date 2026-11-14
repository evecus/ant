//! Turn a destination (possibly a fake-ip) into a dial address + host hint.

use crate::app::router::{Outbound, Router};
use std::net::{IpAddr, SocketAddr};

pub struct DialTarget {
    pub outbound: Outbound,
    pub addr: SocketAddr,
    pub host: Option<String>,
    /// Ruleset name or `"final"`.
    pub rule: String,
}

/// Sniffed domain wins; otherwise recover the domain from a fake-ip.
///
/// When `route-resolve: true`, a domain host is resolved up-front so IP
/// rule-providers / IP-CIDR rules can match against the resolved addresses
/// (unless a rule carries `no-resolve`). Direct connections to a fake-ip are
/// always resolved to a real address so `DirectOutbound` does not dial the
/// fake range.
///
/// All resolution here goes through the configured direct upstream
/// (`direct-nameserver` / matching `dns.rules`), **not** the OS resolver: with
/// TUN + dns-hijack the OS resolver is captured by our own DNS module, which
/// in fake-ip mode would just hand back another fake-ip.
pub async fn decide(router: &Router, dest: SocketAddr, sniffed: Option<String>) -> DialTarget {
    let mapped = router.domain_for_fakeip(dest.ip());
    let host = sniffed.or(mapped.clone());

    let resolved_ips: Vec<IpAddr> = if router.route_resolve() {
        if let Some(ref h) = host {
            if h.parse::<IpAddr>().is_err() {
                resolve_all(router, h).await
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    if !resolved_ips.is_empty() {
        tracing::debug!(
            host = host.as_deref().unwrap_or(""),
            ips = ?resolved_ips,
            "route-resolve: resolved domain for IP rule matching"
        );
    }

    let m = router.match_route(host.as_deref(), Some(dest.ip()), &resolved_ips);
    let mut addr = dest;
    if m.outbound == Outbound::Direct && mapped.is_some() {
        if let Some(ref h) = host {
            // Reuse the route-resolve result when we already have it.
            let ips = if resolved_ips.is_empty() {
                resolve_all(router, h).await
            } else {
                resolved_ips.clone()
            };
            let pick = ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| ips.first())
                .copied();
            match pick {
                Some(ip) => addr = SocketAddr::new(ip, dest.port()),
                None => tracing::warn!(
                    host = h.as_str(),
                    "direct: cannot resolve real address for fake-ip destination"
                ),
            }
        }
    }
    DialTarget {
        outbound: m.outbound,
        addr,
        host,
        rule: m.rule,
    }
}

/// Resolve `host` to real addresses: direct upstream first, OS resolver as a
/// fallback (with fake-ip answers discarded).
async fn resolve_all(router: &Router, host: &str) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    if let Some(up) = router.dns_direct_upstream(host) {
        match crate::dns::resolve_a_via(up, host).await {
            Ok(ips) => return ips,
            Err(e) => tracing::debug!(host, error = %format!("{e:#}"), "direct resolve via {up} failed"),
        }
    }
    match tokio::net::lookup_host((host, 0)).await {
        Ok(iter) => {
            let mut ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).filter(|ip| !router.is_fakeip(*ip)).collect();
            ips.sort_unstable();
            ips.dedup();
            ips
        }
        Err(e) => {
            tracing::debug!(host, error = %e, "route-resolve: DNS lookup failed");
            Vec::new()
        }
    }
}
