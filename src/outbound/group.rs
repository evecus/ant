//! Proxy groups (mihomo-compatible): select / url-test / fallback /
//! load-balance / relay, plus `filter` / `use` provider membership.

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyGroupConfig;
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

pub type DialerMap = Arc<RwLock<HashMap<String, Arc<dyn OutboundDialer>>>>;

/// Provider name → node names loaded from that provider.
pub type ProviderIndex = HashMap<String, Vec<String>>;

#[derive(Clone)]
pub struct SelectHandle {
    name: String,
    members: Arc<RwLock<Vec<String>>>,
    selected: Arc<RwLock<String>>,
    cache: Option<Arc<crate::cache::AppCache>>,
}

impl SelectHandle {
    pub fn group_name(&self) -> &str {
        &self.name
    }
    pub fn members(&self) -> Vec<String> {
        self.members.read().map(|g| g.clone()).unwrap_or_default()
    }
    pub fn now(&self) -> String {
        self.selected.read().map(|g| g.clone()).unwrap_or_default()
    }
    pub fn set(&self, member: &str) -> Result<()> {
        let members = self.members.read().unwrap();
        let ok = members.iter().any(|m| m.eq_ignore_ascii_case(member));
        if !ok {
            bail!("member `{member}` not in group `{}`", self.name);
        }
        let canon = members
            .iter()
            .find(|m| m.eq_ignore_ascii_case(member))
            .cloned()
            .unwrap();
        drop(members);
        *self.selected.write().unwrap() = canon.clone();
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.put(&self.name, &canon) {
                warn!(group = %self.name, error = %e, "failed to persist select choice");
            }
        }
        info!(group = %self.name, selected = %canon, "proxy-group select");
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub now: String,
    pub all: Vec<String>,
}

pub fn resolve_members(
    cfg: &ProxyGroupConfig,
    all_proxy_names: &[String],
    providers: &ProviderIndex,
) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    let push = |name: &str, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        let key = name.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(name.to_string());
        }
    };

    for m in &cfg.proxies {
        push(m, &mut out, &mut seen);
    }
    if cfg.include_all_proxies {
        for n in all_proxy_names {
            push(n, &mut out, &mut seen);
        }
    }
    let provider_names: Vec<String> = if cfg.include_all_providers {
        providers.keys().cloned().collect()
    } else {
        cfg.r#use.clone()
    };
    for pn in provider_names {
        if let Some(nodes) = providers.get(&pn) {
            for n in nodes {
                push(n, &mut out, &mut seen);
            }
        } else if !cfg.include_all_providers {
            warn!(provider = %pn, group = %cfg.name, "proxy-provider not loaded");
        }
    }

    out = apply_filter(out, cfg.filter.as_deref(), cfg.exclude_filter.as_deref())?;
    if out.is_empty() {
        bail!(
            "proxy-group `{}`: no members after proxies/use/filter",
            cfg.name
        );
    }
    Ok(out)
}

fn apply_filter(
    members: Vec<String>,
    filter: Option<&str>,
    exclude: Option<&str>,
) -> Result<Vec<String>> {
    let include_regs = compile_alts(filter)?;
    let exclude_regs = compile_alts(exclude)?;
    Ok(members
        .into_iter()
        .filter(|name| {
            if !include_regs.is_empty() && !include_regs.iter().any(|r| r.is_match(name)) {
                return false;
            }
            if exclude_regs.iter().any(|r| r.is_match(name)) {
                return false;
            }
            true
        })
        .collect())
}

fn compile_alts(pat: Option<&str>) -> Result<Vec<regex::Regex>> {
    let Some(pat) = pat.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in pat.split('`') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(
            regex::Regex::new(part)
                .map_err(|e| anyhow::anyhow!("invalid group filter regex `{part}`: {e}"))?,
        );
    }
    Ok(out)
}

fn lookup(map: &DialerMap, name: &str) -> Result<Arc<dyn OutboundDialer>> {
    let g = map.read().unwrap();
    if let Some(d) = g.get(name) {
        return Ok(d.clone());
    }
    let lower = name.to_ascii_lowercase();
    for (k, v) in g.iter() {
        if k.to_ascii_lowercase() == lower {
            return Ok(v.clone());
        }
    }
    bail!("proxy-group member `{name}` not found")
}

struct SelectGroup {
    handle: SelectHandle,
    map: DialerMap,
}

#[async_trait]
impl OutboundDialer for SelectGroup {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let name = self.handle.now();
        lookup(&self.map, &name)?.dial_tcp(addr, host_hint).await
    }
    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let name = self.handle.now();
        lookup(&self.map, &name)?.dial_udp(local_hint).await
    }
}

struct UrlTestGroup {
    name: String,
    members: Vec<String>,
    map: DialerMap,
    best: AtomicUsize,
    url: String,
    tolerance_ms: u32,
}

#[async_trait]
impl OutboundDialer for UrlTestGroup {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let idx = self.best.load(Ordering::Relaxed).min(self.members.len().saturating_sub(1));
        lookup(&self.map, &self.members[idx])?
            .dial_tcp(addr, host_hint)
            .await
    }
    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let idx = self.best.load(Ordering::Relaxed).min(self.members.len().saturating_sub(1));
        lookup(&self.map, &self.members[idx])?
            .dial_udp(local_hint)
            .await
    }
}

struct FallbackGroup {
    name: String,
    members: Vec<String>,
    map: DialerMap,
    alive: AtomicUsize,
}

#[async_trait]
impl OutboundDialer for FallbackGroup {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let n = self.members.len();
        let start = self.alive.load(Ordering::Relaxed).min(n.saturating_sub(1));
        let mut last_err = None;
        for i in 0..n {
            let idx = (start + i) % n;
            let Ok(dialer) = lookup(&self.map, &self.members[idx]) else { continue };
            match dialer.dial_tcp(addr, host_hint).await {
                Ok(s) => {
                    self.alive.store(idx, Ordering::Relaxed);
                    return Ok(s);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("fallback `{}`: all failed", self.name)))
    }
    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let n = self.members.len();
        let start = self.alive.load(Ordering::Relaxed).min(n.saturating_sub(1));
        let mut last_err = None;
        for i in 0..n {
            let idx = (start + i) % n;
            let Ok(dialer) = lookup(&self.map, &self.members[idx]) else { continue };
            match dialer.dial_udp(local_hint).await {
                Ok(s) => {
                    self.alive.store(idx, Ordering::Relaxed);
                    return Ok(s);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("fallback `{}`: all failed", self.name)))
    }
}

#[derive(Clone, Copy)]
enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
    StickySessions,
}

struct LoadBalanceGroup {
    members: Vec<String>,
    map: DialerMap,
    strategy: LbStrategy,
    rr: AtomicUsize,
}

impl LoadBalanceGroup {
    fn pick(&self, host_hint: Option<&str>, addr: SocketAddr) -> &str {
        let n = self.members.len();
        if n == 0 {
            return "";
        }
        match self.strategy {
            LbStrategy::RoundRobin => {
                let i = self.rr.fetch_add(1, Ordering::Relaxed) % n;
                &self.members[i]
            }
            LbStrategy::ConsistentHashing | LbStrategy::StickySessions => {
                let key = host_hint
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| addr.ip().to_string());
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                key.hash(&mut hasher);
                let i = (hasher.finish() as usize) % n;
                &self.members[i]
            }
        }
    }
}

#[async_trait]
impl OutboundDialer for LoadBalanceGroup {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let name = self.pick(host_hint, addr);
        lookup(&self.map, name)?.dial_tcp(addr, host_hint).await
    }
    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let n = self.members.len().max(1);
        let i = match self.strategy {
            LbStrategy::RoundRobin => self.rr.fetch_add(1, Ordering::Relaxed) % n,
            _ => {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                local_hint.hash(&mut hasher);
                (hasher.finish() as usize) % n
            }
        };
        lookup(&self.map, &self.members[i])?
            .dial_udp(local_hint)
            .await
    }
}

/// name → (server host, port) for relay chain warm-up.
pub type RelayAddrMap = Arc<HashMap<String, (String, u16)>>;

struct RelayGroup {
    name: String,
    members: Vec<String>,
    map: DialerMap,
    addrs: RelayAddrMap,
}

#[async_trait]
impl OutboundDialer for RelayGroup {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        if self.members.is_empty() {
            bail!("relay `{}`: empty", self.name);
        }
        // Exit = last member. Intermediate hops best-effort dial the exit
        // server through the previous hop (dialer-proxy warm-up). Full
        // multi-protocol nesting needs per-outbound injected transports.
        let exit = self.members.last().unwrap();
        let exit_dialer = lookup(&self.map, exit)?;
        if self.members.len() > 1 {
            if let Some(prev) = self.members.iter().rev().nth(1) {
                if let Some((host, port)) = self.addrs.get(exit).or_else(|| {
                    self.addrs
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(exit))
                        .map(|(_, v)| v)
                }) {
                    if let Ok(exit_addr) = resolve_host(host, *port).await {
                        if let Ok(prev_d) = lookup(&self.map, prev) {
                            let _ = prev_d.dial_tcp(exit_addr, Some(host)).await;
                        }
                    }
                }
            }
        }
        exit_dialer.dial_tcp(addr, host_hint).await
    }

    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let exit = self
            .members
            .last()
            .ok_or_else(|| anyhow::anyhow!("relay `{}`: empty", self.name))?;
        lookup(&self.map, exit)?.dial_udp(local_hint).await
    }
}

async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("resolve {host}"))
}

pub fn build_groups(
    cfgs: &[ProxyGroupConfig],
    map: DialerMap,
    all_proxy_names: &[String],
    providers: &ProviderIndex,
    addrs: RelayAddrMap,
    select_cache: Option<Arc<crate::cache::AppCache>>,
) -> Result<(Vec<SelectHandle>, Vec<GroupStatus>)> {
    let mut selects = Vec::new();
    let mut statuses = Vec::new();

    for cfg in cfgs {
        let ty = cfg.ty.to_ascii_lowercase();
        let members = resolve_members(cfg, all_proxy_names, providers)?;
        match ty.as_str() {
            "select" => {
                let initial = select_cache
                    .as_ref()
                    .and_then(|c| c.get(&cfg.name))
                    .filter(|s| members.iter().any(|m| m.eq_ignore_ascii_case(s)))
                    .or_else(|| {
                        cfg.selected
                            .clone()
                            .filter(|s| members.iter().any(|m| m.eq_ignore_ascii_case(s)))
                    })
                    .unwrap_or_else(|| members[0].clone());
                let initial = members
                    .iter()
                    .find(|m| m.eq_ignore_ascii_case(&initial))
                    .cloned()
                    .unwrap_or(initial);
                let handle = SelectHandle {
                    name: cfg.name.clone(),
                    members: Arc::new(RwLock::new(members.clone())),
                    selected: Arc::new(RwLock::new(initial.clone())),
                    cache: select_cache.clone(),
                };
                let group = Arc::new(SelectGroup {
                    handle: handle.clone(),
                    map: map.clone(),
                });
                map.write()
                    .unwrap()
                    .insert(cfg.name.clone(), group as Arc<dyn OutboundDialer>);
                statuses.push(GroupStatus {
                    name: cfg.name.clone(),
                    ty: "select".into(),
                    now: initial,
                    all: members,
                });
                selects.push(handle);
                info!(group = %cfg.name, "proxy-group select ready");
            }
            "url-test" | "urltest" => {
                let url = cfg
                    .url
                    .clone()
                    .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
                let interval = Duration::from_secs(cfg.interval.unwrap_or(300).max(10));
                let group = Arc::new(UrlTestGroup {
                    name: cfg.name.clone(),
                    members: members.clone(),
                    map: map.clone(),
                    best: AtomicUsize::new(0),
                    url: url.clone(),
                    tolerance_ms: cfg.tolerance.unwrap_or(50),
                });
                map.write()
                    .unwrap()
                    .insert(cfg.name.clone(), group.clone() as Arc<dyn OutboundDialer>);
                statuses.push(GroupStatus {
                    name: cfg.name.clone(),
                    ty: "url-test".into(),
                    now: members[0].clone(),
                    all: members,
                });
                let g = group.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    loop {
                        run_url_test(&g).await;
                        tokio::time::sleep(interval).await;
                    }
                });
                info!(group = %cfg.name, url = %url, "proxy-group url-test ready");
            }
            "fallback" => {
                let url = cfg
                    .url
                    .clone()
                    .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
                let interval = Duration::from_secs(cfg.interval.unwrap_or(300).max(10));
                let group = Arc::new(FallbackGroup {
                    name: cfg.name.clone(),
                    members: members.clone(),
                    map: map.clone(),
                    alive: AtomicUsize::new(0),
                });
                map.write()
                    .unwrap()
                    .insert(cfg.name.clone(), group.clone() as Arc<dyn OutboundDialer>);
                statuses.push(GroupStatus {
                    name: cfg.name.clone(),
                    ty: "fallback".into(),
                    now: members[0].clone(),
                    all: members,
                });
                let g = group.clone();
                let url_c = url;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    loop {
                        run_fallback_probe(&g, &url_c).await;
                        tokio::time::sleep(interval).await;
                    }
                });
                info!(group = %cfg.name, "proxy-group fallback ready");
            }
            "load-balance" | "loadbalance" => {
                let strategy = match cfg
                    .strategy
                    .as_deref()
                    .unwrap_or("round-robin")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "consistent-hashing" | "consistenthashing" => LbStrategy::ConsistentHashing,
                    "sticky-sessions" | "stickysessions" => LbStrategy::StickySessions,
                    _ => LbStrategy::RoundRobin,
                };
                let group = Arc::new(LoadBalanceGroup {
                    members: members.clone(),
                    map: map.clone(),
                    strategy,
                    rr: AtomicUsize::new(0),
                });
                map.write()
                    .unwrap()
                    .insert(cfg.name.clone(), group as Arc<dyn OutboundDialer>);
                statuses.push(GroupStatus {
                    name: cfg.name.clone(),
                    ty: "load-balance".into(),
                    now: members[0].clone(),
                    all: members,
                });
                info!(group = %cfg.name, "proxy-group load-balance ready");
            }
            "relay" => {
                let group = Arc::new(RelayGroup {
                    name: cfg.name.clone(),
                    members: members.clone(),
                    map: map.clone(),
                    addrs: addrs.clone(),
                });
                map.write()
                    .unwrap()
                    .insert(cfg.name.clone(), group as Arc<dyn OutboundDialer>);
                statuses.push(GroupStatus {
                    name: cfg.name.clone(),
                    ty: "relay".into(),
                    now: members.last().cloned().unwrap_or_default(),
                    all: members,
                });
                info!(group = %cfg.name, "proxy-group relay ready (exit = last member)");
            }
            other => bail!("unsupported proxy-group type `{other}`"),
        }
    }
    Ok((selects, statuses))
}

async fn run_url_test(g: &UrlTestGroup) {
    let mut best_idx = 0usize;
    let mut best_ms = u64::MAX;
    for (i, name) in g.members.iter().enumerate() {
        let Ok(dialer) = lookup(&g.map, name) else { continue };
        match probe(dialer.as_ref(), &g.url).await {
            Some(d) => {
                let ms = d.as_millis() as u64;
                debug!(group = %g.name, member = %name, delay_ms = ms, "url-test probe ok");
                if best_ms == u64::MAX || ms + (g.tolerance_ms as u64) < best_ms {
                    best_ms = ms;
                    best_idx = i;
                }
            }
            None => debug!(group = %g.name, member = %name, "url-test probe failed"),
        }
    }
    if best_ms != u64::MAX {
        let prev = g.best.swap(best_idx, Ordering::Relaxed);
        if prev != best_idx {
            info!(
                group = %g.name,
                selected = %g.members[best_idx],
                delay_ms = best_ms,
                "url-test switched"
            );
        }
    }
}

async fn run_fallback_probe(g: &FallbackGroup, url: &str) {
    for (i, name) in g.members.iter().enumerate() {
        let Ok(dialer) = lookup(&g.map, name) else { continue };
        if probe(dialer.as_ref(), url).await.is_some() {
            let prev = g.alive.swap(i, Ordering::Relaxed);
            if prev != i {
                info!(group = %g.name, selected = %name, "fallback switched");
            }
            return;
        }
    }
    warn!(group = %g.name, "fallback: no healthy member");
}

fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        ("http", url)
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".into()),
    };
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.parse().ok()?)
    } else {
        let port = if scheme == "https" { 443 } else { 80 };
        (hostport.to_string(), port)
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

pub async fn delay_ms(dialer: &dyn OutboundDialer, url: &str) -> Option<u32> {
    probe(dialer, url).await.map(|d| d.as_millis() as u32)
}

async fn probe(dialer: &dyn OutboundDialer, url: &str) -> Option<Duration> {
    let (host, port, path) = parse_http_url(url)?;
    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .ok()?
        .next()?;
    let start = Instant::now();
    if port == 443 || url.contains("https://") {
        let _stream = dialer.dial_tcp(addr, Some(&host)).await.ok()?;
        return Some(start.elapsed());
    }
    let mut stream = dialer.dial_tcp(addr, Some(&host)).await.ok()?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ant\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 {
        return None;
    }
    if buf.starts_with(b"HTTP/") {
        Some(start.elapsed())
    } else {
        None
    }
}
