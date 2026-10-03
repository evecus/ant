//! Local DNS server: UDP + TCP listen, dual-stack.
//! Upstream: udp / tcp / tls / https (clash-rs URL style).
//! block → rcode://success (NOERROR empty answer).

mod upstream;
pub mod fakeip;
pub mod cache;

pub use upstream::{apply_bootstrap, parse_nameserver, DnsUpstream};

use crate::app::router::Router;
use crate::config::Config;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// One raw `dns.rules` line (`rule-follow-route: false`).
#[derive(Debug, Clone)]
pub struct DnsRouteEntry {
    /// Ruleset name (`RULE-SET,<name>,<target>`); `None` for `MATCH,<target>`.
    pub ruleset: Option<String>,
    /// Raw target: an upstream URL (udp/tcp/tls/https) or `rcode://success`.
    pub spec: String,
}

/// Upstream target of a `dns.rules` entry, resolved at bootstrap time.
#[derive(Debug, Clone)]
pub enum DnsRouteTarget {
    Upstream(DnsUpstream),
    /// `rcode://success` → NOERROR empty answer.
    Block,
}

impl std::fmt::Display for DnsRouteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(u) => write!(f, "{u}"),
            Self::Block => write!(f, "rcode://success (NOERROR empty)"),
        }
    }
}

/// A `dns.rules` entry with its upstream resolved via `default-nameserver`.
#[derive(Debug, Clone)]
pub struct DnsResolvedRoute {
    pub ruleset: Option<String>,
    pub target: DnsRouteTarget,
}

/// Upstream picked for one DNS query.
pub enum DnsUpstreamPick<'a> {
    Block,
    Upstream {
        /// Rule label for logs: `direct`, the node name, ruleset name, or `match`.
        label: String,
        upstream: &'a DnsUpstream,
    },
}

/// Is this `dns.rules` target the reserved block rcode? Case-sensitive:
/// only the literal `rcode://success` (NOERROR empty answer) is accepted.
pub fn is_block_rcode(spec: &str) -> bool {
    spec.trim() == "rcode://success"
}

pub async fn run_dns_server(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = cfg.dns.port;
    if cfg.dns.rule_follow_route {
        tracing::info!(
            "dns rule-follow-route=true ipv6={} direct-nameserver={} proxy-nameserver={}",
            cfg.dns.ipv6,
            cfg.dns.direct_nameserver,
            cfg.dns.proxy_nameserver
        );
    } else {
        tracing::info!(
            "dns rule-follow-route=false ipv6={} nameserver={} rules={}",
            cfg.dns.ipv6,
            cfg.dns.nameserver,
            cfg.dns.rules.len()
        );
    }

    let mut handles = Vec::new();

    for bind in crate::app::sockopt::listen_addrs(&cfg.global.bind_address, port) {
        match crate::app::sockopt::bind_udp_listener(bind) {
            Ok((sock, bind)) => {
                tracing::info!("DNS listening on UDP {bind}");
                let sock = Arc::new(sock);
                let router = router.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dns_udp(sock, router).await {
                        tracing::error!("dns udp: {e:#}");
                    }
                }));
            }
            Err(e) => tracing::warn!("dns udp bind {bind}: {e}"),
        }
    }

    for bind in crate::app::sockopt::listen_addrs(&cfg.global.bind_address, port) {
        match crate::app::sockopt::bind_tcp_listener(bind) {
            Ok((listener, bind)) => {
                tracing::info!("DNS listening on TCP {bind}");
                let router = router.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dns_tcp(listener, router).await {
                        tracing::error!("dns tcp: {e:#}");
                    }
                }));
            }
            Err(e) => tracing::warn!("dns tcp bind {bind}: {e}"),
        }
    }

    if handles.is_empty() {
        anyhow::bail!("dns: no UDP/TCP bind succeeded");
    }
    futures::future::join_all(handles).await;
    Ok(())
}

async fn run_dns_udp(sock: Arc<UdpSocket>, router: Arc<Router>) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let sock2 = sock.clone();
        let router2 = router.clone();
        tokio::spawn(async move {
            match answer_query(&query, &router2).await {
                Ok(resp) => {
                    let _ = sock2.send_to(&resp, peer).await;
                }
                Err(e) => tracing::debug!("dns udp query: {e:#}"),
            }
        });
    }
}

async fn run_dns_tcp(listener: TcpListener, router: Arc<Router>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dns_tcp(stream, peer, router).await {
                tracing::debug!("dns tcp {peer}: {e:#}");
            }
        });
    }
}

async fn handle_dns_tcp(mut stream: TcpStream, _peer: SocketAddr, router: Arc<Router>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            anyhow::bail!("bad dns tcp length {len}");
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let resp = answer_query(&query, &router).await?;
        let rlen = (resp.len() as u16).to_be_bytes();
        stream.write_all(&rlen).await?;
        stream.write_all(&resp).await?;
    }
}

pub async fn answer_query(query: &[u8], router: &Router) -> Result<Vec<u8>> {
    let domain = extract_qname(query).unwrap_or_default();
    let qtype = query_type(query).unwrap_or(1);

    // ipv6 disabled: never answer or forward AAAA
    if qtype == 28 && !router.ipv6_enabled() {
        tracing::debug!("dns {domain} AAAA dropped (ipv6=false)");
        return Ok(make_noerror_empty(query));
    }

    // Cache lookup (real + fakeip answers)
    if !domain.is_empty() {
        if let Some(cache) = router.dns_cache() {
            if let Some(mut hit) = cache.get(&domain, qtype) {
                cache::apply_query_id(&mut hit, query);
                tracing::debug!("dns cache hit {domain} type={qtype}");
                return Ok(hit);
            }
        }
    }

    if router.fakeip_enabled() && !domain.is_empty() && router.use_fakeip(&domain) {
        if qtype == 1 {
            if router.has_fakeip_v4() {
                if let Some(ip) = router.allocate_fakeip(&domain, false) {
                    tracing::debug!("dns fakeip {domain} A -> {ip}");
                    let resp = build_fakeip_answer(query, ip);
                    cache_put(router, &domain, qtype, &resp, Duration::from_secs(60));
                    return Ok(resp);
                }
            }
            return Ok(make_noerror_empty(query));
        }
        if qtype == 28 {
            if router.has_fakeip_v6() {
                if let Some(ip) = router.allocate_fakeip(&domain, true) {
                    tracing::debug!("dns fakeip {domain} AAAA -> {ip}");
                    let resp = build_fakeip_answer(query, ip);
                    cache_put(router, &domain, qtype, &resp, Duration::from_secs(60));
                    return Ok(resp);
                }
            }
            return Ok(make_noerror_empty(query));
        }
    }
    // Empty qname (unparseable query) matches no ruleset: rule-follow-route falls
    // to `final`, dns-rule mode falls to `match` / `nameserver`.
    let (label, upstream) = match router.dns_upstream_for(&domain) {
        DnsUpstreamPick::Block => {
            tracing::debug!("dns {domain} -> rcode://success (NOERROR empty)");
            return Ok(make_noerror_empty(query));
        }
        DnsUpstreamPick::Upstream { label, upstream } => (label, upstream),
    };
    tracing::debug!("dns {domain} -> {label} ({upstream})");
    let resp = upstream::exchange(upstream, query).await?;
    if !domain.is_empty() && resp.len() >= 12 {
        // Cache NOERROR / NXDOMAIN
        let rcode = resp[3] & 0x0F;
        if rcode == 0 || rcode == 3 {
            let secs = cache::response_ttl_secs(&resp, 300);
            cache_put(router, &domain, qtype, &resp, Duration::from_secs(secs as u64));
        }
    }
    Ok(resp)
}

fn cache_put(router: &Router, domain: &str, qtype: u16, resp: &[u8], ttl: Duration) {
    if let Some(cache) = router.dns_cache() {
        cache.put(domain, qtype, resp.to_vec(), ttl);
    }
}

fn make_noerror_empty(query: &[u8]) -> Vec<u8> {
    build_rcode_response(query, 0)
}

fn question_section_end(msg: &[u8], offset: usize) -> Option<usize> {
    let mut i = offset;
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if i + 1 > msg.len() {
                return None;
            }
            i += 1;
            break;
        }
        i += len;
        if i > msg.len() {
            return None;
        }
    }
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}

fn build_rcode_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let qdcount: u16 = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };
    let question_end = if qdcount >= 1 {
        question_section_end(query, 12)
    } else {
        None
    };
    let id = if query.len() >= 2 {
        [query[0], query[1]]
    } else {
        [0, 0]
    };
    let flag2: u8 = 0x85;
    let flag3: u8 = 0x80 | (rcode & 0x0F);

    if let Some(end) = question_end {
        let mut resp = Vec::with_capacity(end);
        resp.extend_from_slice(&id);
        resp.push(flag2);
        resp.push(flag3);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..end]);
        resp
    } else {
        let mut resp = Vec::with_capacity(12);
        resp.extend_from_slice(&id);
        resp.push(flag2);
        resp.push(flag3);
        resp.extend_from_slice(&[0u8; 8]);
        resp
    }
}

fn extract_qname(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    while i < msg.len() {
        let len = msg[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            break;
        }
        i += 1;
        if i + len > msg.len() {
            return None;
        }
        let label = std::str::from_utf8(&msg[i..i + len]).ok()?;
        labels.push(label.to_lowercase());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn query_type(msg: &[u8]) -> Option<u16> {
    let end = question_section_end(msg, 12)?;
    if end < 4 {
        return None;
    }
    Some(u16::from_be_bytes([msg[end - 4], msg[end - 3]]))
}

fn build_fakeip_answer(query: &[u8], ip: std::net::IpAddr) -> Vec<u8> {
    let question_end = question_section_end(query, 12).unwrap_or(12);
    let mut resp = Vec::with_capacity(question_end + 28);
    resp.extend_from_slice(&query[..2]);
    resp.push(0x81); // QR RD
    resp.push(0x80); // RA
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    if question_end > 12 {
        resp.extend_from_slice(&query[12..question_end]);
    }
    resp.extend_from_slice(&[0xC0, 0x0C]);
    match ip {
        std::net::IpAddr::V4(v4) => {
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            resp.extend_from_slice(&28u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&v6.octets());
        }
    }
    resp
}
