use super::{BoxedStream, OutboundDialer, UdpSession};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct DirectOutbound;

#[async_trait]
impl OutboundDialer for DirectOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, _host_hint: Option<&str>) -> Result<BoxedStream> {
        let s = crate::app::sockopt::connect_tcp(addr).await.context("direct tcp connect")?;
        s.set_nodelay(true)?;
        Ok(Box::new(s))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let sock = crate::app::sockopt::bind_udp("0.0.0.0:0".parse().unwrap()).await.context("direct udp bind")?;
        Ok(Box::new(DirectUdpSession {
            sock: Arc::new(sock),
        }))
    }
}

struct DirectUdpSession {
    sock: Arc<UdpSocket>,
}

#[async_trait]
impl UdpSession for DirectUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, _dst_host: Option<&str>) -> Result<()> {
        self.sock.send_to(data, dst).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        let (n, src) = self.sock.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, src))
    }
}
