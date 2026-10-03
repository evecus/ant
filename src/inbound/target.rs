//! Turn a destination (possibly a fake-ip) into a dial address + host hint.

use crate::app::router::{Outbound, Router};
use crate::app::sniffer::SniffResult;
use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};

pub struct DialTarget {
    pub outbound: Outbound,
    pub addr: SocketAddr,
    pub host: Option<String>,
    /// Ruleset name or `"final"`.
    pub rule: String,
}

/// Merge the sniffed/protocol domain with any fake-ip mapping:
/// - HTTP Host (and protocol-provided domains) always override the mapping
///   (override-destination: true);
/// - TLS/QUIC SNI never override it (override-destination: false) — the domain
///   the client actually resolved through our DNS wins;
/// - no domain at all → fall back to the fake-ip mapping.
///
/// Direct connections to a fake-ip are resolved to a real address first so
/// `DirectOutbound` does not dial the fake range.
pub async fn decide(router: &Router, dest: SocketAddr, sniffed: SniffResult) -> DialTarget {
    let mapped = router.domain_for_fakeip(dest.ip());
    let host = match &mapped {
        // Fake-ip mapping exists: only HTTP Host (or a protocol-provided domain)
        // overrides it; TLS/QUIC SNI never do.
        Some(m) => match sniffed.domain {
            Some(d) if sniffed.source.overrides_fakeip() => Some(d),
            _ => Some(m.clone()),
        },
        // No mapping: use whatever domain we have.
        None => sniffed.domain,
    };
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
