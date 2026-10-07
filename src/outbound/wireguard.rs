//! WireGuard 出站。
//!
//! 分层（对齐 sing-box wireguard endpoint + 用户态协议栈方案）：
//!
//! ```text
//! 应用 dial_tcp/dial_udp
//!   └─ wg_stack（smoltcp 用户态栈，把会话封装成 IP 包）
//!        └─ 本模块 wire task（boringtun Tunn 封装成 WG 数据包）
//!             └─ endpoint UDP socket（app::sockopt::bind_udp 创建）
//! ```
//!
//! **防回环**：endpoint socket 一律通过 `app::sockopt::bind_udp` 创建，与其他
//! 出站协议/直连完全同源——Linux/Android 设 SO_MARK（fwmark），Unix 绑定物理
//! 网卡（SO_BINDTODEVICE / IP_BOUND_IF），Windows 设 IP_UNICAST_IF。TUN
//! auto-route / auto-detect-interface 开启时 WG 自身的加密流量不会重新进入
//! TUN（否则造成路由回环）。握手、数据、keepalive 全部走这一个 socket。
//!
//! WG 数据面用 boringtun（Cloudflare）的 `noise::Tunn`：握手发起/响应、
//! cookie reply、会话轮换、持久保活与重传定时器都在库内完成，本模块只负责
//! IO 三件事——`encapsulate`（栈 IP 包 → WG 包 → endpoint）、
//! `decapsulate`（endpoint 包 → WG 包 → 栈 IP 包）、`update_timers`（250ms tick）。

use super::anytls::resolve_server;
use super::wg_stack::{pick_default_ip, pick_local_ip, WgStack};
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::wire::{IpCidr, IpAddress};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// 默认隧道 MTU：1500 - IPv4 头 20 - UDP 头 8 - WG 数据包头 16 - Poly1305 tag 16
/// - 最低外层余量……对齐 wireguard-go 默认 1420。
const DEFAULT_WG_MTU: u32 = 1420;
/// 默认持久保活（秒）：wireguard-go `defaultPersistentKeepaliveInterval`。
const DEFAULT_KEEPALIVE: u16 = 25;
/// endpoint UDP datagram / 加解密缓冲上限（WG 单包最大 65535）。
const WIRE_BUF: usize = 65535;
/// boringtun 定时器 tick（对齐 boringtun device 的 250ms）。
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Tunn 实例序号（单 peer，固定 1；boringtun 内部左移 8 位作 sender index 基址）。
const TUNN_INDEX: u32 = 1;

// ── 密钥 ─────────────────────────────────────────────────────────────────────

fn decode_key(field: &str, s: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .with_context(|| format!("wireguard: {field} base64 decode failed"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("wireguard: {field} must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

// ── 出站 ─────────────────────────────────────────────────────────────────────

pub struct WireGuardOutbound {
    tag: String,
    /// 隧道内 smoltcp 栈句柄（dial 入口）。
    stack: super::wg_stack::StackHandle,
    local_v4: Option<IpAddr>,
    local_v6: Option<IpAddr>,
}

impl WireGuardOutbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        let tag = cfg.name.clone();
        let private = decode_key(
            "private-key",
            cfg.private_key.as_deref().context("wireguard: private-key missing")?,
        )?;
        let peer_public = decode_key(
            "peer-public-key",
            cfg.peer_public_key
                .as_deref()
                .context("wireguard: peer-public-key missing")?,
        )?;
        let psk = match cfg.pre_shared_key.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(decode_key("pre-shared-key", s)?),
            _ => None,
        };

        // 本机隧道地址 → smoltcp CIDR + 源地址族记录。
        let mut cidrs: Vec<IpCidr> = Vec::new();
        let mut local_v4 = None;
        let mut local_v6 = None;
        for s in &cfg.local_address {
            let net: ipnet::IpNet = s.trim().parse().with_context(|| format!("wireguard: local-address `{s}`"))?;
            cidrs.push(IpCidr::new(IpAddress::from(net.addr()), net.prefix_len()));
            match net.addr() {
                IpAddr::V4(ip) => local_v4.get_or_insert(IpAddr::V4(ip)),
                IpAddr::V6(ip) => local_v6.get_or_insert(IpAddr::V6(ip)),
            };
        }

        let mtu = cfg.wg_mtu.unwrap_or(DEFAULT_WG_MTU);
        let keepalive = cfg.persistent_keepalive.unwrap_or(DEFAULT_KEEPALIVE);

        // endpoint 解析：IP 直用；域名走 default-nameserver bootstrap → 系统解析
        // （对齐其他出站，DNS 不会环回进 ant 自身）。
        let endpoint = resolve_server(&cfg.server, cfg.port)
            .await
            .context("wireguard: resolve endpoint")?;

        // endpoint socket：统一走 sockopt::bind_udp（SO_MARK / 物理网卡绑定防回环），
        // 然后 connect 到 endpoint——所有 WG 包（握手/数据/keepalive）都走它。
        let bind: SocketAddr = if endpoint.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let udp = crate::app::sockopt::bind_udp(bind)
            .await
            .context("wireguard: bind endpoint udp socket")?;
        udp.connect(endpoint)
            .await
            .context("wireguard: connect endpoint")?;

        // 隧道内协议栈。default route 网关取值只用于路由查表（Medium::Ip 无 ARP），
        // 惯例取本机地址 +1（wireguard-go 客户端配置的 peer 隧道地址位置）。
        let v4_gw = local_v4.map(|ip| match ip {
            IpAddr::V4(v) => Ipv4Addr::from(u32::from(v).wrapping_add(1)),
            _ => unreachable!(),
        });
        let v6_gw = local_v6.map(|ip| match ip {
            IpAddr::V6(v) => Ipv6Addr::from(u128::from(v).wrapping_add(1)),
            _ => unreachable!(),
        });
        let (stack, tx_rx, rx_tx) = WgStack::new(mtu, &cidrs, v4_gw, v6_gw);

        let tunn = Tunn::new(
            boringtun::x25519::StaticSecret::from(private),
            boringtun::x25519::PublicKey::from(peer_public),
            psk,
            (keepalive != 0).then_some(keepalive),
            TUNN_INDEX,
            None,
        );
        tokio::spawn(wire_task(tunn, udp, endpoint, tx_rx, rx_tx, stack.clone()));

        tracing::info!(
            "proxy node `{tag}` (wireguard) = {}:{} ready (mtu={mtu}, keepalive={keepalive}s)",
            cfg.server,
            cfg.port
        );
        Ok(Self {
            tag,
            stack,
            local_v4,
            local_v6,
        })
    }
}

// ── wire task：WG 数据面 IO ──────────────────────────────────────────────────

async fn wire_task(
    mut tunn: Tunn,
    udp: tokio::net::UdpSocket,
    endpoint: SocketAddr,
    mut tx_rx: mpsc::Receiver<Vec<u8>>,
    rx_tx: mpsc::UnboundedSender<Vec<u8>>,
    stack: super::wg_stack::StackHandle,
) {
    let mut rx_buf = vec![0u8; WIRE_BUF];
    let mut enc_buf = vec![0u8; WIRE_BUF + 64];
    let mut tick = tokio::time::interval(TIMER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            r = udp.recv(&mut rx_buf) => match r {
                Ok(n) if n > 0 => {
                    if let Err(e) = on_endpoint_packet(
                        &mut tunn,
                        &udp,
                        endpoint,
                        &rx_buf[..n],
                        &mut enc_buf,
                        &rx_tx,
                        &stack,
                    )
                    .await
                    {
                        tracing::debug!("wireguard: endpoint packet io: {e:#}");
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("wireguard: endpoint recv: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            pkt = tx_rx.recv() => {
                let Some(pkt) = pkt else {
                    // 栈已关闭（出站生命周期结束）。
                    break;
                };
                if let Err(e) = encapsulate_send(&mut tunn, &udp, &pkt, &mut enc_buf).await {
                    tracing::debug!("wireguard: encapsulate: {e:#}");
                }
            }
            _ = tick.tick() => {
                // 保活 / 重传 / 会话轮换全部由 boringtun 定时器驱动。
                match tunn.update_timers(&mut enc_buf) {
                    TunnResult::Done => {}
                    TunnResult::WriteToNetwork(p) => {
                        if let Err(e) = udp.send(p).await {
                            tracing::warn!("wireguard: timer send: {e}");
                        }
                    }
                    TunnResult::Err(e) => {
                        tracing::debug!("wireguard: timer: {e:?}");
                    }
                    _ => {}
                }
            }
        }
    }
}

/// 处理 endpoint 来的一个 WG 包，冲完 decapsulate 队列（对齐 boringtun device
/// 的 flush 模式：`WriteToNetwork` / 握手完成后继续 `decapsulate(None, &[])`）。
async fn on_endpoint_packet(
    tunn: &mut Tunn,
    udp: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    datagram: &[u8],
    enc_buf: &mut [u8],
    rx_tx: &mpsc::UnboundedSender<Vec<u8>>,
    stack: &super::wg_stack::StackHandle,
) -> Result<()> {
    let mut result = tunn.decapsulate(Some(endpoint.ip()), datagram, enc_buf);
    loop {
        match result {
            TunnResult::Done => break,
            TunnResult::Err(e) => {
                tracing::debug!("wireguard: decapsulate: {e:?}");
                break;
            }
            TunnResult::WriteToNetwork(p) => {
                // 握手响应 / cookie reply / 重传包：回发 endpoint。
                udp.send(p).await?;
                result = tunn.decapsulate(None, &[], enc_buf);
            }
            TunnResult::WriteToTunnelV4(p, _src) | TunnResult::WriteToTunnelV6(p, _src) => {
                // 隧道内明文 IP 包 → 注入 smoltcp 栈。
                if rx_tx.send(p.to_vec()).is_err() {
                    bail!("wg stack closed");
                }
                stack.nudge();
                result = tunn.decapsulate(None, &[], enc_buf);
            }
        }
    }
    Ok(())
}

/// 栈 IP 包 → WG 包 → endpoint。
async fn encapsulate_send(
    tunn: &mut Tunn,
    udp: &tokio::net::UdpSocket,
    pkt: &[u8],
    enc_buf: &mut [u8],
) -> Result<()> {
    match tunn.encapsulate(pkt, enc_buf) {
        TunnResult::Done => Ok(()),
        TunnResult::WriteToNetwork(p) => {
            udp.send(p).await?;
            Ok(())
        }
        TunnResult::Err(e) => bail!("wg encapsulate: {e:?}"),
        // encapsulate 不会产生隧道方向的结果
        _ => Ok(()),
    }
}

// ── OutboundDialer ───────────────────────────────────────────────────────────

#[async_trait]
impl OutboundDialer for WireGuardOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, _host_hint: Option<&str>) -> Result<BoxedStream> {
        let local_ip = pick_local_ip(self.local_v4, self.local_v6, addr.ip())?;
        let stream = self
            .stack
            .connect_tcp(SocketAddr::new(local_ip, 0), addr)
            .await?;
        tracing::debug!(
            tag = %self.tag,
            "wireguard tcp dial {addr} via {local_ip} established"
        );
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let local_ip = pick_default_ip(self.local_v4, self.local_v6)?;
        let session = self.stack.bind_udp(SocketAddr::new(local_ip, 0)).await?;
        Ok(Box::new(session))
    }
}
