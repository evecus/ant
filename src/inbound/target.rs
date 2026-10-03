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
/// Direct connections to a fake-ip are resolved to a real address first so
/// `DirectOutbound` does not dial the fake range.
pub async fn decide(router: &Router, dest: SocketAddr, sniffed: Option<String>) -> DialTarget {
    let mapped = router.domain_for_fakeip(dest.ip());
    let host = sniffed.or(mapped.clone());
    let m = router.match_route(host.as_deref(), Some(dest.ip()));
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

async fn lookup_host(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?;
    addrs.next().context("no address")
}
