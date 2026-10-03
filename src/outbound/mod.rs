mod direct;
mod hysteria2;
mod vless;
mod reality;
mod xhttp;

pub use direct::DirectOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use vless::VlessOutbound;

use crate::config::ProxyConfig;
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
    pub async fn new(proxies: &[ProxyConfig]) -> Result<Arc<Self>> {
        let mut nodes = HashMap::new();
        for cfg in proxies {
            let dialer: Arc<dyn OutboundDialer> = match cfg.ty.to_lowercase().as_str() {
                "hysteria2" => Arc::new(Hysteria2Outbound::new(cfg).await?),
                "vless" => Arc::new(VlessOutbound::new(cfg).await?),
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
