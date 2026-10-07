mod anytls;
mod direct;
mod group;
mod ech;
mod hpke;
mod hysteria2;
mod naive;
mod shadowquic;
mod tuic;
mod vless;
mod vmess;
mod reality;
mod shadowsocks;
mod socks;
mod trojan;
mod utls;
mod vision;
mod wg_stack;
mod wireguard;
mod ws;
mod xhttp;
mod xhttp_h2;

pub use anytls::AnyTlsOutbound;
pub use direct::DirectOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use naive::NaiveOutbound;
pub use shadowsocks::{validate_method as validate_ss_method, ShadowsocksOutbound};
pub use shadowquic::ShadowquicOutbound;
pub use socks::SocksOutbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vless::VlessOutbound;
pub use vmess::VmessOutbound;
pub use wireguard::WireGuardOutbound;

use crate::app::router::Outbound;
use crate::config::{DnsConfig, ProxyConfig, ProxyGroupConfig};
use crate::dns::{parse_nameserver, DnsUpstream};
use crate::proxy_provider::ProxyProviderStore;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
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
    /// Every dialable name: static nodes, provider nodes, groups, DIRECT, REJECT.
    /// Shared with the group dialers, so a provider refresh is visible to them
    /// without rebuilding the manager.
    dialers: group::DialerMap,
    /// Handles for `select` groups (API switching).
    selects: Vec<group::SelectHandle>,
    /// All group snapshots (select/url-test/fallback/…).
    group_list: RwLock<Vec<group::GroupStatus>>,
    /// Group configs, index-aligned with `group_members`.
    group_cfgs: Vec<ProxyGroupConfig>,
    /// Live member lists shared with the group dialers.
    group_members: Vec<group::Members>,
    /// Leaf node names from `proxies:` (never from a provider).
    static_nodes: Vec<String>,
    /// Leaf node names including provider nodes (API `GLOBAL` group).
    node_names: RwLock<Vec<String>>,
    /// name → (server, port), shared with relay groups.
    addrs: group::RelayAddrMap,
    /// Provider node name → provider name (ownership bookkeeping for refresh).
    provider_owner: RwLock<HashMap<String, String>>,
    /// Fingerprint (`{:?}`) of the config each provider node was built from —
    /// a refresh only rebuilds dialers whose config actually changed.
    provider_cfg: RwLock<HashMap<String, String>>,
    providers: Option<Arc<ProxyProviderStore>>,
    /// DNS upstreams for VLESS ECH (HTTPS RR lookup).
    ech_dns: Vec<DnsUpstream>,
}

impl OutboundManager {
    pub async fn new(
        proxies: &[ProxyConfig],
        groups: &[ProxyGroupConfig],
        providers: Option<Arc<ProxyProviderStore>>,
        dns: Option<&DnsConfig>,
        select_cache: Option<Arc<crate::cache::AppCache>>,
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

        let mut map: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        let mut addr_map: HashMap<String, (String, u16)> = HashMap::new();
        let mut static_nodes: Vec<String> = Vec::new();
        for cfg in proxies {
            let dialer = build_dialer(cfg, &ech_dns)
                .await
                .with_context(|| format!("proxy node `{}`", cfg.name))?;
            tracing::info!(
                "proxy node `{}` ({}) = {}:{} ready",
                cfg.name,
                cfg.ty,
                cfg.server,
                cfg.port
            );
            addr_map.insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
            static_nodes.push(cfg.name.clone());
            map.insert(cfg.name.clone(), dialer);
        }

        let direct = Arc::new(DirectOutbound);
        let dialers: group::DialerMap = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut g = dialers.write().unwrap();
            for (k, v) in &map {
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
        let addrs: group::RelayAddrMap = Arc::new(RwLock::new(addr_map));

        // Proxy-provider nodes (already downloaded / parsed by the store).
        let mut provider_owner: HashMap<String, String> = HashMap::new();
        let mut provider_cfg: HashMap<String, String> = HashMap::new();
        let mut provider_index: group::ProviderIndex = HashMap::new();
        let mut provider_nodes: Vec<String> = Vec::new();
        if let Some(store) = &providers {
            provider_index = store.index();
            for (pname, cfg) in store.nodes() {
                if cfg.name.is_empty() {
                    continue;
                }
                if map.contains_key(&cfg.name) {
                    tracing::warn!(
                        provider = %pname,
                        node = %cfg.name,
                        "provider node name collides with an existing node; skipped"
                    );
                    continue;
                }
                if provider_owner.contains_key(&cfg.name) {
                    tracing::warn!(
                        provider = %pname,
                        node = %cfg.name,
                        "duplicate provider node name; skipped"
                    );
                    continue;
                }
                let dialer = build_dialer(&cfg, &ech_dns)
                    .await
                    .with_context(|| format!("proxy-provider `{pname}` node `{}`", cfg.name))?;
                tracing::info!(
                    "provider `{pname}` node `{}` ({}) ready",
                    cfg.name,
                    cfg.ty
                );
                dialers.write().unwrap().insert(cfg.name.clone(), dialer);
                addrs
                    .write()
                    .unwrap()
                    .insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
                provider_owner.insert(cfg.name.clone(), pname.clone());
                provider_cfg.insert(cfg.name.clone(), fingerprint(&cfg));
                provider_nodes.push(cfg.name.clone());
            }
        }

        // Membership resolution order: `proxies:` nodes first, then provider
        // nodes (stable, so group output does not shuffle between reloads).
        let mut all_proxy_names: Vec<String> = static_nodes.clone();
        all_proxy_names.extend(provider_nodes.iter().cloned());

        let (selects, statuses, member_refs) = group::build_groups(
            groups,
            dialers.clone(),
            &all_proxy_names,
            &provider_index,
            addrs.clone(),
            select_cache,
        )?;

        // Leaf names only (exclude group names).
        let group_names: HashSet<String> =
            statuses.iter().map(|s| s.name.to_ascii_lowercase()).collect();
        let node_names: Vec<String> = all_proxy_names
            .into_iter()
            .filter(|n| !group_names.contains(&n.to_ascii_lowercase()))
            .collect();

        Ok(Arc::new(Self {
            direct,
            dialers,
            selects,
            group_list: RwLock::new(statuses),
            group_cfgs: groups.to_vec(),
            group_members: member_refs,
            static_nodes,
            node_names: RwLock::new(node_names),
            addrs,
            provider_owner: RwLock::new(provider_owner),
            provider_cfg: RwLock::new(provider_cfg),
            providers,
            ech_dns,
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
        let mut all = self.node_names();
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

    pub fn node_names(&self) -> Vec<String> {
        self.node_names.read().map(|g| g.clone()).unwrap_or_default()
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

    /// Re-download / re-read a proxy-provider and merge its nodes into the
    /// live outbound table. Returns the new node count.
    pub async fn update_provider(&self, name: &str) -> Result<usize> {
        let Some(store) = &self.providers else {
            bail!("no proxy-providers configured");
        };
        let n = store.update(name).await?;
        self.sync_providers()
            .await
            .with_context(|| format!("apply proxy-provider `{name}` update"))?;
        Ok(n)
    }

    /// Rebuild provider nodes + group membership from the current store state.
    ///
    /// Dialers whose node config is unchanged are kept as-is (some outbounds
    /// spawn background tasks on construction); only genuinely changed nodes
    /// are rebuilt, and nodes that disappeared are dropped.
    pub async fn sync_providers(&self) -> Result<()> {
        let Some(store) = &self.providers else {
            return Ok(());
        };
        let entries = store.nodes();
        let mut target: Vec<(String, ProxyConfig)> = Vec::new();
        {
            let mut seen: HashSet<String> = HashSet::new();
            for (pname, cfg) in entries {
                if cfg.name.is_empty() {
                    continue;
                }
                if seen.insert(cfg.name.to_ascii_lowercase()) {
                    target.push((pname, cfg));
                } else {
                    tracing::warn!(
                        node = %cfg.name,
                        provider = %pname,
                        "duplicate provider node name; skipped"
                    );
                }
            }
        }

        // 1) Drop nodes a provider no longer exposes.
        let wanted: HashSet<String> = target
            .iter()
            .map(|(_, c)| c.name.to_ascii_lowercase())
            .collect();
        let stale: Vec<String> = {
            let owner = self.provider_owner.read().unwrap();
            owner
                .keys()
                .filter(|n| !wanted.contains(&n.to_ascii_lowercase()))
                .cloned()
                .collect()
        };
        {
            let mut owner = self.provider_owner.write().unwrap();
            let mut cfg_fp = self.provider_cfg.write().unwrap();
            let mut dialers = self.dialers.write().unwrap();
            let mut addrs = self.addrs.write().unwrap();
            for n in &stale {
                owner.remove(n);
                cfg_fp.remove(n);
                dialers.remove(n);
                addrs.remove(n);
                tracing::debug!(node = %n, "provider node removed");
            }
        }

        // 2) (Re)build provider nodes.
        let mut added = 0usize;
        let mut rebuilt = 0usize;
        for (pname, cfg) in &target {
            let fp = fingerprint(cfg);
            let existing_fp = self.provider_cfg.read().unwrap().get(&cfg.name).cloned();
            let owned_by_other = self
                .provider_owner
                .read()
                .unwrap()
                .get(&cfg.name)
                .cloned()
                .filter(|o| o != pname);
            let is_static = self.static_nodes.iter().any(|n| n.eq_ignore_ascii_case(&cfg.name));
            if is_static || owned_by_other.is_some() {
                // A node from `proxies:` (or another provider) owns this name.
                continue;
            }
            if existing_fp.as_deref() == Some(fp.as_str()) {
                // Unchanged: keep the existing dialer, refresh its address.
                self.addrs
                    .write()
                    .unwrap()
                    .insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
                continue;
            }
            let dialer = build_dialer(cfg, &self.ech_dns)
                .await
                .with_context(|| format!("proxy-provider `{pname}` node `{}`", cfg.name))?;
            self.dialers.write().unwrap().insert(cfg.name.clone(), dialer);
            self.provider_owner
                .write()
                .unwrap()
                .insert(cfg.name.clone(), pname.clone());
            self.provider_cfg.write().unwrap().insert(cfg.name.clone(), fp);
            self.addrs
                .write()
                .unwrap()
                .insert(cfg.name.clone(), (cfg.server.clone(), cfg.port));
            if existing_fp.is_some() {
                rebuilt += 1;
            } else {
                added += 1;
            }
        }

        // 3) Recompute group membership for every group.
        let index = store.index();
        let mut all_names = self.static_nodes.clone();
        all_names.extend(target.iter().map(|(_, c)| c.name.clone()));
        for (i, cfg) in self.group_cfgs.iter().enumerate() {
            let members = match group::resolve_members(cfg, &all_names, &index) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        group = %cfg.name,
                        error = %e,
                        "group membership unchanged after provider refresh"
                    );
                    continue;
                }
            };
            if let Some(r) = self.group_members.get(i) {
                *r.write().unwrap() = members.clone();
            }
            if let Ok(mut list) = self.group_list.write() {
                if let Some(s) = list.get_mut(i) {
                    s.all = members.clone();
                    if !members.iter().any(|m| m.eq_ignore_ascii_case(&s.now)) {
                        s.now = members.first().cloned().unwrap_or_default();
                    }
                }
            }
        }
        // select 组的当前选择在节点消失后可能失效 —— 回落到第一个成员。
        for h in &self.selects {
            h.prune_selected();
        }

        // 4) Refresh the leaf-name list exposed by the API.
        let group_names: HashSet<String> = self
            .group_list
            .read()
            .map(|g| g.iter().map(|s| s.name.to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let leaves: Vec<String> = all_names
            .into_iter()
            .filter(|n| !group_names.contains(&n.to_ascii_lowercase()))
            .collect();
        *self.node_names.write().unwrap() = leaves;

        tracing::info!(
            added,
            rebuilt,
            removed = stale.len(),
            "proxy-provider nodes synced"
        );
        Ok(())
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
                let g = self.dialers.read().unwrap();
                if let Some(d) = g.get(&name) {
                    return Some(d.clone());
                }
                let lower = name.to_ascii_lowercase();
                g.iter()
                    .find(|(k, _)| k.to_ascii_lowercase() == lower)
                    .map(|(_, v)| v.clone())
            }
            Outbound::Block => None,
        }
    }
}

/// Build one outbound dialer from a node config (static `proxies:` entry or a
/// proxy-provider node).
async fn build_dialer(cfg: &ProxyConfig, ech_dns: &[DnsUpstream]) -> Result<Arc<dyn OutboundDialer>> {
    let dialer: Arc<dyn OutboundDialer> = match cfg.ty.to_lowercase().as_str() {
        "hysteria2" => Arc::new(Hysteria2Outbound::new(cfg).await?),
        "tuic" => Arc::new(TuicOutbound::new(cfg).await?),
        "shadowquic" => Arc::new(ShadowquicOutbound::new(cfg).await?),
        "anytls" => Arc::new(AnyTlsOutbound::new(cfg)?),
        "naive" => Arc::new(NaiveOutbound::new(cfg)?),
        "vless" => Arc::new(VlessOutbound::new_with_ech_dns(cfg, ech_dns).await?),
        "vmess" => Arc::new(VmessOutbound::new(cfg)?),
        "socks5" | "socks" | "socks4" | "socks4a" => Arc::new(SocksOutbound::new(cfg)?),
        "trojan" => Arc::new(TrojanOutbound::new(cfg)?),
        "shadowsocks" | "ss" => Arc::new(ShadowsocksOutbound::new(cfg)?),
        "wireguard" => Arc::new(WireGuardOutbound::new(cfg).await?),
        other => bail!("unsupported proxy type: {other}"),
    };
    Ok(dialer)
}

/// Cheap change-detection key for a node config (`ProxyConfig` derives Debug).
fn fingerprint(c: &ProxyConfig) -> String {
    format!("{c:?}")
}

pub async fn relay(mut a: BoxedStream, mut b: BoxedStream) -> Result<()> {
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(e.into()),
    }
}
