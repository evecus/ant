mod direct;
mod ech;
mod hpke;
mod hysteria2;
mod vless;
mod reality;
mod utls;
mod vision;
mod xhttp;
mod xhttp_h2;

pub use direct::DirectOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use vless::VlessOutbound;

use crate::config::{DnsConfig, ProxyConfig};
use crate::dns::{parse_nameserver, DnsUpstream};
use crate::app::router::Outbound;
use anyhow::{bail, Result};
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

pub struct OutboundManager {
    direct: Arc<DirectOutbound>,
    /// [[proxy]] nodes by name, built once at startup.
    nodes: HashMap<String, Arc<dyn OutboundDialer>>,
}

impl OutboundManager {
    pub async fn new(proxies: &[ProxyConfig], dns: Option<&DnsConfig>) -> Result<Arc<Self>> {
        // ECH 的 DNS HTTPS RR 查询 upstream 优先级：
        // proxy-nameserver（通常为加密上游）→ nameserver（rule 模式回退）
        // → default-nameserver（bootstrap）。
        let ech_dns: Vec<DnsUpstream> = match dns {
            Some(d) => [
                d.resolved_proxy.clone(),
                d.resolved_nameserver.clone(),
                parse_nameserver(&d.default_nameserver).ok(),
            ]
            .into_iter()
            .flatten()
            .collect(),
            None => Vec::new(),
        };
        let mut nodes = HashMap::new();
        for cfg in proxies {
            let dialer: Arc<dyn OutboundDialer> = match cfg.ty.to_lowercase().as_str() {
                "hysteria2" => Arc::new(Hysteria2Outbound::new(cfg).await?),
                "vless" => {
                    Arc::new(VlessOutbound::new_with_ech_dns(cfg, &ech_dns).await?)
                }
                other => bail!("unsupported proxy type: {other}"),
            };
            tracing::info!("proxy node `{}` ({}) = {}:{} ready", cfg.name, cfg.ty, cfg.server, cfg.port);
            nodes.insert(cfg.name.clone(), dialer);
        }
        Ok(Arc::new(Self {
            direct: Arc::new(DirectOutbound),
            nodes,
        }))
    }

    /// Returns `None` for `Outbound::Block` (caller should drop the connection)
    /// and for unknown node names (config validation should prevent this).
    pub fn select(&self, ob: Outbound) -> Option<Arc<dyn OutboundDialer>> {
        match ob {
            Outbound::Direct => Some(self.direct.clone() as Arc<dyn OutboundDialer>),
            Outbound::Node(name) => self.nodes.get(&name).cloned(),
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
