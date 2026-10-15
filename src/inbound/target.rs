//! Turn a destination (possibly a fake-ip) into a dial address + host hint.

use crate::app::router::{Outbound, Router};
use anyhow::{Context, Result};
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
pub async fn decide(router: &Router, dest: SocketAddr, sniffed: Option<String>) -> DialTarget {
    let mapped = router.domain_for_fakeip(dest.ip());
    let host = sniffed.or(mapped.clone());

    let resolved_ips: Vec<IpAddr> = if router.route_resolve() {
        if let Some(ref h) = host {
            if h.parse::<IpAddr>().is_err() {
                resolve_all(h).await
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
            if let Ok(real) = lookup_host(h, dest.port()).await {
                addr = real;
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

async fn resolve_all(host: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host((host, 0)).await {
        Ok(iter) => {
            let mut ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
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

async fn lookup_host(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?;
    addrs.next().context("no address")
}
