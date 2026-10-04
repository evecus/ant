//! ICMP Echo Request forwarder with route decision.
//!
//! - `Outbound::Block` → drop
//! - `Outbound::Direct` → raw ICMP/ICMPv6 socket to upstream, reply to TUN
//! - `Outbound::Node` → cannot tunnel ICMP through typical proxies; drop with log
//!
//! Unix only (raw sockets). On non-unix builds the module is empty stub.

#![cfg(unix)]

use crate::app::router::{Outbound, Router};
use crate::outbound::OutboundManager;
use crate::tun::native_tun::NativeTunWriter;
use crate::tun::packet::{internet_checksum, recompute_ipv4_checksum};
use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

const ICMP_FLOW_TIMEOUT: Duration = Duration::from_secs(30);
const ICMP_SEND_QUEUE: usize = 64;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    icmp_id: u16,
}

struct FlowEntry {
    tx: mpsc::Sender<Bytes>,
    last_seen: Instant,
}

pub struct IcmpForwarder {
    flows: Arc<Mutex<HashMap<FlowKey, FlowEntry>>>,
    writer: Arc<Mutex<NativeTunWriter>>,
    router: Arc<Router>,
    #[allow(dead_code)]
    outbound_mgr: Arc<OutboundManager>,
}

impl IcmpForwarder {
    pub fn new(
        writer: Arc<Mutex<NativeTunWriter>>,
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            flows: Arc::new(Mutex::new(HashMap::new())),
            writer,
            router,
            outbound_mgr,
        });
        let gc = this.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let now = Instant::now();
                gc.flows
                    .lock()
                    .await
                    .retain(|_, e| now.duration_since(e.last_seen) < ICMP_FLOW_TIMEOUT);
            }
        });
        this
    }

    /// Returns true if the packet was handled as ICMP echo.
    pub async fn handle_packet(&self, raw: &[u8]) -> bool {
        if raw.is_empty() {
            return false;
        }
        match raw[0] >> 4 {
            4 => self.handle_v4(raw).await,
            6 => self.handle_v6(raw).await,
            _ => false,
        }
    }

    async fn handle_v4(&self, raw: &[u8]) -> bool {
        if raw.len() < 28 {
            return false;
        }
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if ihl < 20 || raw.len() < ihl + 8 {
            return false;
        }
        if raw[9] != IPPROTO_ICMP || raw[ihl] != ICMPV4_ECHO_REQUEST {
            return false;
        }
        let src = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
        let dst = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
        let icmp_id = u16::from_be_bytes([raw[ihl + 4], raw[ihl + 5]]);

        match self.router.match_route(None, Some(IpAddr::V4(dst))).outbound {
            Outbound::Block => {
                debug!(%dst, "tun: icmp v4 blocked");
                return true;
            }
            Outbound::Node(ref name) => {
                debug!(%dst, node = %name, "tun: icmp v4 via proxy not supported, drop");
                return true;
            }
            Outbound::Direct => {}
        }

        let payload = Bytes::copy_from_slice(&raw[ihl..]);
        self.forward(
            FlowKey {
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                icmp_id,
            },
            payload,
            raw,
            false,
        )
        .await
    }

    async fn handle_v6(&self, raw: &[u8]) -> bool {
        if raw.len() < 48 {
            return false;
        }
        if raw[6] != IPPROTO_ICMPV6 || raw[40] != ICMPV6_ECHO_REQUEST {
            return false;
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
        let icmp_id = u16::from_be_bytes([raw[44], raw[45]]);

        match self.router.match_route(None, Some(IpAddr::V6(dst))).outbound {
            Outbound::Block => {
                debug!(%dst, "tun: icmp v6 blocked");
                return true;
            }
            Outbound::Node(ref name) => {
                debug!(%dst, node = %name, "tun: icmp v6 via proxy not supported, drop");
                return true;
            }
            Outbound::Direct => {}
        }

        let payload = Bytes::copy_from_slice(&raw[40..]);
        self.forward(
            FlowKey {
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                icmp_id,
            },
            payload,
            raw,
            true,
        )
        .await
    }

    async fn forward(&self, key: FlowKey, payload: Bytes, template: &[u8], is_v6: bool) -> bool {
        {
            let mut flows = self.flows.lock().await;
            if let Some(e) = flows.get_mut(&key) {
                e.last_seen = Instant::now();
                let _ = e.tx.try_send(payload);
                return true;
            }
            let (tx, rx) = mpsc::channel::<Bytes>(ICMP_SEND_QUEUE);
            let _ = tx.try_send(payload);
            flows.insert(
                key,
                FlowEntry {
                    tx,
                    last_seen: Instant::now(),
                },
            );
            drop(flows);

            let writer = self.writer.clone();
            let flows = self.flows.clone();
            let tmpl = template.to_vec();
            tokio::spawn(async move {
                if let Err(e) = run_icmp_flow(key, rx, tmpl, is_v6, writer).await {
                    debug!(err = %e, "tun: icmp flow ended");
                }
                flows.lock().await.remove(&key);
            });
        }
        true
    }
}

async fn run_icmp_flow(
    key: FlowKey,
    mut rx: mpsc::Receiver<Bytes>,
    template: Vec<u8>,
    is_v6: bool,
    writer: Arc<Mutex<NativeTunWriter>>,
) -> std::io::Result<()> {
    let sock = if is_v6 {
        // IPPROTO_ICMPV6 = 58
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(58)))?
    } else {
        // IPPROTO_ICMP = 1
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(1)))?
    };
    sock.set_nonblocking(true)?;
    let async_fd = AsyncFd::new(sock)?;

    loop {
        tokio::select! {
            pkt = rx.recv() => {
                let Some(payload) = pkt else { break; };
                let dst = match key.dst {
                    IpAddr::V4(a) => SockAddr::from(SocketAddr::from((a, 0))),
                    IpAddr::V6(a) => SockAddr::from(SocketAddr::from((a, 0))),
                };
                let mut guard = async_fd.writable().await?;
                match guard.try_io(|inner| inner.get_ref().send_to(&payload, &dst)) {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => {}
                }
            }
            ready = async_fd.readable() => {
                let mut guard = ready?;
                let mut buf = vec![0u8; 65535];
                let result = guard.try_io(|inner| {
                    use std::os::fd::AsRawFd;
                    let fd = inner.get_ref().as_raw_fd();
                    let n = unsafe {
                        libc::recv(
                            fd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });
                match result {
                    Ok(Ok(n)) if n > 0 => {
                        buf.truncate(n);
                        // Linux IPv4 raw recv includes IP header; ICMPv6 is payload only.
                        if let Some(pkt) = build_reply_to_tun(&template, key, &buf, is_v6) {
                            let mut w = writer.lock().await;
                            let _ = w.write_packet(&pkt).await;
                            let _ = w.flush_gro().await;
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => {}
                }
            }
        }
    }
    Ok(())
}

fn build_reply_to_tun(
    template: &[u8],
    key: FlowKey,
    recv: &[u8],
    is_v6: bool,
) -> Option<Vec<u8>> {
    if is_v6 {
        // recv is ICMPv6 message
        if recv.is_empty() || recv[0] != ICMPV6_ECHO_REPLY {
            return None;
        }
        if template.len() < 48 {
            return None;
        }
        let mut pkt = template.to_vec();
        // swap src/dst
        if let (IpAddr::V6(src), IpAddr::V6(dst)) = (key.src, key.dst) {
            pkt[8..24].copy_from_slice(&dst.octets()); // reply src = original dst
            pkt[24..40].copy_from_slice(&src.octets());
        }
        let icmp_len = recv.len() as u16;
        pkt[4..6].copy_from_slice(&icmp_len.to_be_bytes());
        pkt[6] = IPPROTO_ICMPV6;
        pkt.truncate(40);
        pkt.extend_from_slice(recv);
        // recompute icmpv6 checksum
        if pkt.len() >= 44 {
            pkt[42] = 0;
            pkt[43] = 0;
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            let mut sum: u32 = 0;
            for c in src_ip.octets().chunks(2).chain(dst_ip.octets().chunks(2)) {
                sum += u16::from_be_bytes([c[0], c[1]]) as u32;
            }
            let len = pkt.len() - 40;
            sum += (len as u32) >> 16;
            sum += (len as u32) & 0xffff;
            sum += IPPROTO_ICMPV6 as u32;
            let mut i = 40;
            while i + 1 < pkt.len() {
                sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
                i += 2;
            }
            if i < pkt.len() {
                sum += (pkt[i] as u32) << 8;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let c = !(sum as u16);
            pkt[42] = (c >> 8) as u8;
            pkt[43] = (c & 0xff) as u8;
        }
        Some(pkt)
    } else {
        // Linux: recv includes IPv4 header
        let icmp_off = if recv.len() >= 20 && recv[0] >> 4 == 4 {
            let ihl = ((recv[0] & 0x0f) as usize) * 4;
            if recv.len() < ihl + 8 {
                return None;
            }
            if recv[ihl] != ICMPV4_ECHO_REPLY {
                return None;
            }
            ihl
        } else if !recv.is_empty() && recv[0] == ICMPV4_ECHO_REPLY {
            0
        } else {
            return None;
        };
        let icmp = &recv[icmp_off..];
        if template.len() < 28 {
            return None;
        }
        let ihl = ((template[0] & 0x0f) as usize) * 4;
        let mut pkt = template[..ihl].to_vec();
        if let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src, key.dst) {
            pkt[12..16].copy_from_slice(&dst.octets());
            pkt[16..20].copy_from_slice(&src.octets());
        }
        pkt.extend_from_slice(icmp);
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        // fix icmp checksum if needed
        if pkt.len() >= ihl + 4 {
            pkt[ihl + 2] = 0;
            pkt[ihl + 3] = 0;
            let c = internet_checksum(&pkt[ihl..]);
            pkt[ihl + 2] = (c >> 8) as u8;
            pkt[ihl + 3] = (c & 0xff) as u8;
        }
        recompute_ipv4_checksum(&mut pkt);
        Some(pkt)
    }
}
