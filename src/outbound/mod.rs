mod anytls;
mod direct;
mod group;
mod ech;
mod hpke;
mod hysteria2;
mod tuic;
mod vless;
mod reality;
mod socks;
mod trojan;
mod utls;
mod vision;
mod ws;
mod xhttp;
mod xhttp_h2;

pub use anytls::AnyTlsOutbound;
pub use direct::DirectOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use socks::SocksOutbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vless::VlessOutbound;

use crate::config::{DnsConfig, ProxyConfig, ProxyGroupConfig};
use crate::dns::{parse_nameserver, DnsUpstream};
use crate::app::router::Outbound;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub type BoxedStream = Box<dyn AsyncStream + Send + Unpin>;

pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncStream for T {}

#[async_trait]
pub trait UdpSession: Send + Sync {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()>;
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)>;
}

#[async_trait]
pub trait OutboundDialer: Send + Sync {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream>;
    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>>;
}

/// Always fails — used when a group member is REJECT/BLOCK.
struct BlockOutbound;

#[async_trait]
impl OutboundDialer for BlockOutbound {
    async fn dial_tcp(&self, _addr: SocketAddr, _host_hint: Option<&str>) -> Result<BoxedStream> {
        bail!("blocked by proxy-group member REJECT")
    }
    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        bail!("blocked by proxy-group member REJECT")
    }
}

pub struct OutboundManager {
    direct: Arc<DirectOutbound>,
    /// Proxy nodes + proxy-groups by name.
    nodes: HashMap<String, Arc<dyn OutboundDialer>>,
    /// Handles for `select` groups (API switching).
    selects: Vec<group::SelectHandle>,
    /// All group snapshots (select/url-test/fallback/…).
    group_list: std::sync::RwLock<Vec<group::GroupStatus>>,
    /// Leaf proxy node names (not groups).
    node_names: Vec<String>,
}

impl OutboundManager {
    pub async fn new(
        proxies: &[ProxyConfig],
        groups: &[ProxyGroupConfig],
        providers: &std::collections::HashMap<String, crate::config::ProxyProviderConfig>,
        dns: Option<&DnsConfig>,
        select_cache: Option<std::sync::Arc<crate::cache::AppCache>>,
    ) -> Result<Arc<Self>> {
        // ECH 的 DNS HTTPS RR 查询 upstream 优先级：
        // proxy-nameserver（通常为加密上游）→ dns.nameserver（自定义默认上游）
        // → default-nameserver（bootstrap）。
        // 这里只做 parse（无网络 IO）；域名上游的解析在 exchange 时惰性完成。
        let ech_dns: Vec<DnsUpstream> = match dns {
            Some(d) => [
                d.proxy_nameserver
                    .as_deref()
                    .and_then(|s| parse_nameserver(s).ok()),
                d.nameserver
                    .as_deref()
                    .and_then(|s| parse_nameserver(s).ok()),
                d.default_nameserver
                    .as_deref()
                    .and_then(|s| parse_nameserver(s).ok()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            None => Vec::new(),
        };
        let mut nodes: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        for cfg in proxies {
            let dialer: Arc<dyn OutboundDialer> = match cfg.ty.to_lowercase().as_str() {
                "hysteria2" => Arc::new(Hysteria2Outbound::new(cfg).await?),
                "tuic" => Arc::new(TuicOutbound::new(cfg).await?),
                "anytls" => Arc::new(AnyTlsOutbound::new(cfg)?),
                "vless" => Arc::new(VlessOutbound::new_with_ech_dns(cfg, &ech_dns).await?),
                "socks5" | "socks" | "socks4" | "socks4a" => Arc::new(SocksOutbound::new(cfg)?),
                "trojan" => Arc::new(TrojanOutbound::new(cfg)?),
                other => bail!("unsupported proxy type: {other}"),
            };
            tracing::info!(
                "proxy node `{}` ({}) = {}:{} ready",
                cfg.name,
                cfg.ty,
                cfg.server,
                cfg.port
            );
            nodes.insert(cfg.name.clone(), dialer);
        }

        let direct = Arc::new(DirectOutbound);
        // Shared map used by groups to resolve members (including other groups).
        let map: group::DialerMap = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let mut addr_map: HashMap<String, (String, u16)> = HashMap::new();
        for cfg in proxies {
            addr_map.insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
        }
        {
            let mut g = map.write().unwrap();
            for (k, v) in &nodes {
                g.insert(k.clone(), v.clone());
            }
            g.insert(
                "DIRECT".into(),
                direct.clone() as Arc<dyn OutboundDialer>,
            );
            g.insert(
                "direct".into(),
                direct.clone() as Arc<dyn OutboundDialer>,
            );
            let block: Arc<dyn OutboundDialer> = Arc::new(BlockOutbound);
            g.insert("REJECT".into(), block.clone());
            g.insert("reject".into(), block.clone());
            g.insert("BLOCK".into(), block.clone());
            g.insert("block".into(), block);
        }

        // Load file proxy-providers and merge their nodes into `nodes` + map.
        let mut provider_index: group::ProviderIndex = HashMap::new();
        for (pname, pcfg) in providers {
            let path = pcfg
                .path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("proxy-provider `{pname}` missing path"))?;
            let loaded = load_provider_file(path)?;
            let mut names = Vec::new();
            for cfg in &loaded {
                let dialer: Arc<dyn OutboundDialer> = match cfg.ty.to_lowercase().as_str() {
                    "hysteria2" => Arc::new(Hysteria2Outbound::new(cfg).await?),
                    "tuic" => Arc::new(TuicOutbound::new(cfg).await?),
                    "anytls" => Arc::new(AnyTlsOutbound::new(cfg)?),
                    "vless" => Arc::new(VlessOutbound::new_with_ech_dns(cfg, &ech_dns).await?),
                    "socks5" | "socks" | "socks4" | "socks4a" => Arc::new(SocksOutbound::new(cfg)?),
                    "trojan" => Arc::new(TrojanOutbound::new(cfg)?),
                    other => bail!("provider `{pname}`: unsupported proxy type: {other}"),
                };
                tracing::info!(
                    "provider `{pname}` node `{}` ({}) ready",
                    cfg.name,
                    cfg.ty
                );
                addr_map.insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
                names.push(cfg.name.clone());
                nodes.insert(cfg.name.clone(), dialer.clone());
                map.write().unwrap().insert(cfg.name.clone(), dialer);
            }
            provider_index.insert(pname.clone(), names);
        }

        let all_proxy_names: Vec<String> = nodes.keys().cloned().collect();
        let addrs: group::RelayAddrMap = Arc::new(addr_map);
        let (selects, statuses) = group::build_groups(
            groups,
            map.clone(),
            &all_proxy_names,
            &provider_index,
            addrs,
            select_cache,
        )?;
        // Fold group dialers into nodes so select(Outbound::Node(group)) works.
        {
            let g = map.read().unwrap();
            for (k, v) in g.iter() {
                if k.eq_ignore_ascii_case("direct") {
                    continue;
                }
                nodes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

        // Leaf names only (exclude groups we just inserted).
        let group_names: std::collections::HashSet<String> =
            statuses.iter().map(|s| s.name.to_ascii_lowercase()).collect();
        let node_names: Vec<String> = all_proxy_names
            .into_iter()
            .filter(|n| !group_names.contains(&n.to_ascii_lowercase()))
            .collect();

        Ok(Arc::new(Self {
            direct,
            nodes,
            selects,
            group_list: std::sync::RwLock::new(statuses),
            node_names,
        }))
    }

    /// Snapshot of every proxy-group for GET /proxies.
    /// Appends a synthetic `GLOBAL` group (all proxy nodes + DIRECT) for the
    /// dashboard so nodes outside any proxy-group can still be listed / latency-tested.
    pub fn group_status(&self) -> Vec<group::GroupStatus> {
        let mut list = self.group_list.read().unwrap().clone();
        // Refresh `now` for select groups from live handles.
        for h in &self.selects {
            if let Some(s) = list.iter_mut().find(|s| s.name.eq_ignore_ascii_case(h.group_name())) {
                s.now = h.now();
                s.all = h.members();
            }
        }
        // Synthetic GLOBAL: every configured node + DIRECT (not selectable for routing).
        let mut all = self.node_names.clone();
        if !all.iter().any(|n| n.eq_ignore_ascii_case("DIRECT")) {
            all.push("DIRECT".to_string());
        }
        list.push(group::GroupStatus {
            name: "GLOBAL".to_string(),
            ty: "global".to_string(),
            now: String::new(),
            all,
        });
        list
    }

    pub fn node_names(&self) -> &[String] {
        &self.node_names
    }

    /// Switch a `select` group to `member`.
    pub fn set_group(&self, group: &str, member: &str) -> Result<()> {
        for h in &self.selects {
            if h.group_name().eq_ignore_ascii_case(group) {
                h.set(member)?;
                // Reflect in snapshot.
                if let Ok(mut list) = self.group_list.write() {
                    if let Some(s) = list.iter_mut().find(|s| s.name.eq_ignore_ascii_case(group)) {
                        s.now = h.now();
                    }
                }
                return Ok(());
            }
        }
        bail!("select group `{group}` not found (only type: select can be switched)");
    }

    /// Health-check delay in ms for a node or group member name.
    pub async fn delay(&self, name: &str, url: &str) -> Option<u32> {
        let dialer = self.select(Outbound::from_str(name))?;
        group::delay_ms(dialer.as_ref(), url).await
    }

    /// Returns `None` for `Outbound::Block` (caller should drop the connection)
    /// and for unknown node names (config validation should prevent this).
    pub fn select(&self, ob: Outbound) -> Option<Arc<dyn OutboundDialer>> {
        match ob {
            Outbound::Direct => Some(self.direct.clone() as Arc<dyn OutboundDialer>),
            Outbound::Node(name) => {
                if let Some(d) = self.nodes.get(&name) {
                    return Some(d.clone());
                }
                let lower = name.to_ascii_lowercase();
                self.nodes
                    .iter()
                    .find(|(k, _)| k.to_ascii_lowercase() == lower)
                    .map(|(_, v)| v.clone())
            }
            Outbound::Block => None,
        }
    }
}


pub async fn relay(mut a: BoxedStream, mut b: BoxedStream) -> Result<()> {
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(e.into()),
    }
}


/// Load a mihomo-style provider file: either a bare `proxies:` list document or
/// a map with a `proxies` key.
fn load_provider_file(path: &std::path::Path) -> Result<Vec<ProxyConfig>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read proxy-provider {}", path.display()))?;
    // Try `{ proxies: [...] }` first, then a bare list.
    #[derive(serde::Deserialize)]
    struct Wrapper {
        proxies: Vec<ProxyConfig>,
    }
    if let Ok(w) = serde_yaml::from_str::<Wrapper>(&text) {
        return Ok(w.proxies);
    }
    let list: Vec<ProxyConfig> = serde_yaml::from_str(&text)
        .with_context(|| format!("parse proxy-provider {}", path.display()))?;
    Ok(list)
}
