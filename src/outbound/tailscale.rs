//! Tailscale 出站（feature `tailscale`）。
//!
//! 参考 reflex `src/outbound/tailscale.rs`，按 ant 的 `OutboundDialer` /
//! `UdpSession` 接口重写：用 `tailscale-rs` 的 userspace netstack 加入 tailnet，
//! TCP 走 `Device::tcp_connect`，UDP 走 `Device::udp_bind`。
//!
//! 与 clash-rs / reflex 一致，不暴露 exit-node 选择：目标应是 tailnet 节点 IP
//! 或 subnet router 通告网段内的 IP。域名目标会用 bootstrap DNS 解析成 IP
//! （Tailscale netstack 只接受 IP，且 TUN 模式下 dial 地址常是 fake-ip）。

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use rand::Rng;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

/// 状态文件名（与 reflex / clash-rs 一致）。
const STATE_FILE_NAME: &str = "tailscale_state.json";
const DEFAULT_CLIENT_NAME: &str = "ant";

pub struct TailscaleOutbound {
    tag: String,
    state_dir: Option<String>,
    ephemeral: bool,
    control_url: Option<String>,
    auth_key: Option<String>,
    hostname: Option<String>,
    client_name: String,
    /// 懒加载：首次 dial 时才连接控制面，之后复用（Device 内部有后台 actor）。
    device: tokio::sync::Mutex<Option<Arc<tailscale::Device>>>,
}

impl TailscaleOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let tag = cfg.name.clone();
        if let Some(u) = cfg.ts_control_url.as_deref() {
            let u = u.trim();
            if !(u.starts_with("https://") || u.starts_with("http://")) || u.len() < 10 {
                bail!("tailscale: control-url must be an http(s) URL");
            }
        }
        tracing::info!(
            "proxy node `{tag}` (tailscale) ready (state_dir={:?}, ephemeral={})",
            cfg.ts_state_dir,
            cfg.ts_ephemeral
        );
        Ok(Self {
            tag,
            state_dir: cfg.ts_state_dir.clone().filter(|s| !s.trim().is_empty()),
            ephemeral: cfg.ts_ephemeral,
            control_url: cfg.ts_control_url.clone(),
            auth_key: cfg.ts_auth_key.clone().filter(|s| !s.trim().is_empty()),
            hostname: cfg.ts_hostname.clone(),
            client_name: cfg
                .ts_client_name
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_CLIENT_NAME.to_string()),
            device: tokio::sync::Mutex::new(None),
        })
    }

    /// 懒加载 Device：ephemeral 用空身份；`state-dir` 时从状态文件加载持久
    /// 身份（加载失败不阻塞启动，回落到新身份并重新认证）。
    async fn get_device(&self) -> Result<Arc<tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        // 上游 crate 要求显式确认实验性软件身份（与 reflex / clash-rs 一致）。
        std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");

        let key_state = if self.ephemeral {
            Default::default()
        } else if let Some(dir) = &self.state_dir {
            let state_file = PathBuf::from(dir).join(STATE_FILE_NAME);
            match tailscale::config::load_key_file(
                state_file.clone(),
                tailscale::config::BadFormatBehavior::Overwrite,
            )
            .await
            {
                Ok(ks) => ks,
                Err(e) => {
                    warn!(
                        tag = %self.tag,
                        path = %state_file.display(),
                        err = %e,
                        "tailscale: load key state failed, falling back to fresh identity"
                    );
                    Default::default()
                }
            }
        } else {
            Default::default()
        };

        let mut ts_config = tailscale::Config {
            key_state,
            ..Default::default()
        };
        ts_config.client_name = Some(self.client_name.clone());
        ts_config.requested_hostname = self.hostname.clone();
        if let Some(url) = &self.control_url {
            ts_config.control_server_url = url
                .parse()
                .map_err(|e| anyhow!("tailscale: invalid control-url: {e}"))?;
        }

        debug!(tag = %self.tag, "tailscale: initializing device");
        let device = tailscale::Device::new(&ts_config, self.auth_key.clone())
            .await
            .map_err(|e| anyhow!("tailscale: failed to initialize device: {e}"))?;
        let device = Arc::new(device);
        *guard = Some(Arc::clone(&device));
        Ok(device)
    }

    /// 按目标 IP 协议族选一个本机 tailnet 地址作为 UDP 源地址。
    async fn local_ip(&self, device: &tailscale::Device, dst: IpAddr) -> Result<IpAddr> {
        match dst {
            IpAddr::V4(_) => Ok(IpAddr::V4(
                device
                    .ipv4_addr()
                    .await
                    .map_err(|e| anyhow!("tailscale: get ipv4_addr failed: {e}"))?,
            )),
            IpAddr::V6(_) => Ok(IpAddr::V6(
                device
                    .ipv6_addr()
                    .await
                    .map_err(|e| anyhow!("tailscale: get ipv6_addr failed: {e}"))?,
            )),
        }
    }
}

/// 把 dial 目标解析成真实 IP。
///
/// - 有 `host_hint` 域名 → bootstrap DNS 解析（不能用 `addr.ip()`：TUN 模式下
///   它通常是 fake-ip，Tailscale netstack 无法路由）
/// - 无域名提示 → 直接用 `addr.ip()`
async fn resolve_target_ip(host_hint: Option<&str>, addr: SocketAddr) -> Result<IpAddr> {
    if let Some(h) = host_hint.filter(|s| !s.is_empty()) {
        if let Ok(ip) = h.parse::<IpAddr>() {
            return Ok(ip);
        }
        let resolved = crate::dns::resolve_host_via_bootstrap(h, addr.port())
            .await
            .with_context(|| format!("tailscale: resolve '{h}'"))?;
        return Ok(resolved.ip());
    }
    Ok(addr.ip())
}

#[async_trait]
impl OutboundDialer for TailscaleOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let ip = resolve_target_ip(host_hint, addr).await?;
        let target = SocketAddr::new(ip, addr.port());
        let device = self.get_device().await?;
        debug!(tag = %self.tag, target = %target, "tailscale: tcp connect");
        let stream = device
            .tcp_connect(target)
            .await
            .map_err(|e| anyhow!("tailscale: tcp_connect to {target} failed: {e}"))?;
        Ok(Box::new(TailscaleTcpStream::new(stream, device)))
    }

    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let device = self.get_device().await?;
        // 默认按 IPv4 绑定；local_hint 是 IPv6 时用 tailnet IPv6 地址。
        let family = local_hint
            .map(|a| a.ip())
            .filter(|ip| ip.is_ipv6())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let local_ip = self.local_ip(&device, family).await?;
        let local_port: u16 = rand::thread_rng().gen_range(49152u16..=u16::MAX);
        let bind = SocketAddr::new(local_ip, local_port);
        debug!(tag = %self.tag, local = %bind, "tailscale: udp bind");
        let sock = device
            .udp_bind(bind)
            .await
            .map_err(|e| anyhow!("tailscale: udp_bind on {bind} failed: {e}"))?;
        Ok(Box::new(TailscaleUdpSession {
            sock,
            tag: self.tag.clone(),
            // 持有 Device，避免 socket 还在使用时 Device 被释放。
            _device: device,
        }))
    }
}

// ── TCP stream 包装 ─────────────────────────────────────────────────────────

pub struct TailscaleTcpStream {
    inner: tailscale::netstack::TcpStream,
    _device: Arc<tailscale::Device>,
}

impl TailscaleTcpStream {
    fn new(inner: tailscale::netstack::TcpStream, device: Arc<tailscale::Device>) -> Self {
        Self {
            inner,
            _device: device,
        }
    }
}

impl AsyncRead for TailscaleTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TailscaleTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── UDP session ─────────────────────────────────────────────────────────────

/// `netstack::UdpSocket` 的 send_to / recv_from 都是 `&self`，本身 Send+Sync，
/// 因此 ant 的 UDP relay（并发 send_to + recv_from）不需要额外的锁。
struct TailscaleUdpSession {
    sock: tailscale::netstack::UdpSocket,
    tag: String,
    _device: Arc<tailscale::Device>,
}

#[async_trait]
impl UdpSession for TailscaleUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let ip = resolve_target_ip(dst_host, dst).await?;
        let target = SocketAddr::new(ip, dst.port());
        self.sock
            .send_to(target, data)
            .await
            .map_err(|e| anyhow!("tailscale `{}`: udp send to {target} failed: {e}", self.tag))
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        let (src, n) = self
            .sock
            .recv_from(&mut buf)
            .await
            .map_err(|e| anyhow!("tailscale `{}`: udp recv failed: {e}", self.tag))?;
        buf.truncate(n);
        Ok((buf, src))
    }
}
