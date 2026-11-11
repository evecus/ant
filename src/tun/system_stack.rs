//! System stack: TCP NAT + UDP sessions + accept/dial relay.
//! Packet path: defrag, ICMP echo, MSS clamp, RST on NAT exhaustion,
//! UDP template replies. Device I/O via NativeTun (vnet_hdr + GSO split).

use super::ip_defrag::IpDefragmenter;
use super::system_nat::TcpNat;
use super::gso::GroDisablementFlags;
use super::native_tun::{NativeTun, NativeTunWriter};
use super::packet::{
    broadcast_addr_v4, build_tcp_rst_v4, build_tcp_rst_v6, build_udp_reply_with_template,
    clamp_tcp_mss, compute_effective_mss, is_global_unicast_v4, is_global_unicast_v6,
    nat_update_ip_checksum_v4, nat_update_tcp_checksum_v4, nat_update_tcp_checksum_v6,
    verify_checksums_v4,
};
#[cfg(not(unix))]
use super::packet::{build_icmp_echo_reply_v4, build_icmp_echo_reply_v6};
use crate::app::router::{Outbound, Router};
use crate::app::stats;
use crate::config::TunConfig;
use crate::dns;
use crate::inbound::target;
use crate::outbound::{relay, OutboundManager};
use super::packet::build_udp_reply;
use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, trace, warn};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const UDP_IDLE: Duration = Duration::from_secs(300);
const TCP_NAT_TIMEOUT: Duration = Duration::from_secs(300);

type UdpPacket = (Bytes, SocketAddr);

/// Diagnostic: render TCP flag byte, e.g. "SYN|ACK".
fn tcp_flags_str(f: u8) -> String {
    let mut v = Vec::new();
    for (bit, name) in [
        (0x02u8, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
    ] {
        if f & bit != 0 {
            v.push(name);
        }
    }
    if v.is_empty() {
        "-".into()
    } else {
        v.join("|")
    }
}

struct UdpEntry {
    packet_tx: mpsc::Sender<UdpPacket>,
    last_seen: Instant,
}

pub struct StackAddrs {
    pub inet4_server: Option<Ipv4Addr>,
    pub inet4_client: Option<Ipv4Addr>,
    pub inet6_server: Option<Ipv6Addr>,
    pub inet6_client: Option<Ipv6Addr>,
    pub prefixes_v4: Vec<(Ipv4Addr, u8)>,
}

#[derive(Clone)]
struct StackRuntime {
    writer: Arc<Mutex<NativeTunWriter>>,
    tcp_nat: Arc<TcpNat>,
    /// std Mutex: critical sections never await (try_send is sync) and this
    /// map is hit on every UDP packet.
    udp_sessions: Arc<std::sync::Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    tcp_port_v4: u16,
    tcp_port_v6: u16,
    inet4_server: Option<Ipv4Addr>,
    inet4_client: Option<Ipv4Addr>,
    inet6_server: Option<Ipv6Addr>,
    inet6_client: Option<Ipv6Addr>,
    inet4_broadcast: Option<Ipv4Addr>,
    tcp_mss: Option<u16>,
    #[cfg(unix)]
    icmp: Option<Arc<super::icmp_forwarder::IcmpForwarder>>,
    /// Parsed dns-hijack rules; empty = disabled.
    dns_hijack: Arc<Vec<DnsHijackRule>>,
}

/// One `dns-hijack` entry: optional IP filter + port (usually 53).
#[derive(Clone, Debug)]
pub struct DnsHijackRule {
    /// None / unspecified = match any address on this port.
    pub addr: Option<std::net::IpAddr>,
    pub port: u16,
}

impl DnsHijackRule {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix("udp://").or_else(|| s.strip_prefix("tcp://")).unwrap_or(s);
        let (host, port_s) = if let Some((h, p)) = s.rsplit_once(':') {
            (h, p)
        } else {
            (s, "53")
        };
        let port: u16 = port_s.parse().ok()?;
        let host = host.trim_matches(|c| c == '[' || c == ']');
        let addr = if host.eq_ignore_ascii_case("any")
            || host == "0.0.0.0"
            || host == "::"
            || host.is_empty()
        {
            None
        } else {
            Some(host.parse().ok()?)
        };
        Some(Self { addr, port })
    }

    pub fn matches(&self, dst: SocketAddr) -> bool {
        if dst.port() != self.port {
            return false;
        }
        match self.addr {
            None => true,
            Some(a) => a == dst.ip(),
        }
    }
}

pub fn parse_dns_hijack(list: &[String]) -> Vec<DnsHijackRule> {
    list.iter().filter_map(|s| DnsHijackRule::parse(s)).collect()
}

pub struct TunStackParams {
    pub dev: tun::AsyncDevice,
    pub if_name: String,
    pub cfg: TunConfig,
    pub addrs: StackAddrs,
    pub router: Arc<Router>,
    pub outbounds: Arc<OutboundManager>,
    pub vnet_hdr: bool,
    pub gro_flags: GroDisablementFlags,
    pub dns_hijack: Vec<DnsHijackRule>,
}

pub async fn run_system_stack(p: TunStackParams) -> Result<()> {
    let TunStackParams {
        dev,
        if_name,
        cfg,
        addrs,
        router,
        outbounds,
        vnet_hdr,
        gro_flags,
        dns_hijack,
    } = p;
    let dns_hijack = Arc::new(dns_hijack);
    let tcp_nat = Arc::new(TcpNat::new());
    // macOS: use AsyncRead path (tun crate strips 4-byte PI). Batch recvmsg_x
    // needs exclusive fd ownership and is available via NativeTun::new_macos
    // when the device is constructed from a raw fd (external FD / future path).
    let native = NativeTun::new(dev, vnet_hdr, gro_flags);
    let (reader, writer) = native.split();

    let tcp_listener_v4 = match addrs.inet4_server {
        Some(addr) => bind_with_retry(SocketAddr::V4(SocketAddrV4::new(addr, 0))).await,
        None => None,
    };
    let tcp_listener_v6 = match addrs.inet6_server {
        Some(addr) => bind_with_retry(SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0))).await,
        None => None,
    };

    let tcp_port_v4 = tcp_listener_v4
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);
    let tcp_port_v6 = tcp_listener_v6
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);

    if tcp_port_v4 != 0 {
        info!(interface = %if_name, port = tcp_port_v4, "tun: TCP v4 listener ready");
    }
    if tcp_port_v6 != 0 {
        info!(interface = %if_name, port = tcp_port_v6, "tun: TCP v6 listener ready");
    }

    for listener in [tcp_listener_v4, tcp_listener_v6].into_iter().flatten() {
        let nat = tcp_nat.clone();
        let r = router.clone();
        let o = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(listener, nat, r, o).await;
        });
    }

    let udp_sessions: Arc<std::sync::Mutex<HashMap<SocketAddr, UdpEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    #[cfg(unix)]
    let icmp = super::icmp_forwarder::IcmpForwarder::new(
        writer.clone(),
        router.clone(),
        outbounds.clone(),
    );


    {
        let nat = tcp_nat.clone();
        let sessions = udp_sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                nat.gc(TCP_NAT_TIMEOUT);
                let mut map = sessions.lock().unwrap();
                let now = Instant::now();
                map.retain(|_, e| now.duration_since(e.last_seen) < UDP_IDLE);
            }
        });
    }


    // 事件驱动 flush：write_packet 首包 notify → 2ms 批窗口 → flush_gro。
    // 空闲时零唤醒（旧实现的 2ms 忙轮询在空闲时也有 500 wake/s，是 CPU 占用
    // 来源之一）。
    {
        let notify = writer.lock().await.flush_notify();
        let w = writer.clone();
        tokio::spawn(async move {
            loop {
                notify.notified().await;
                tokio::time::sleep(Duration::from_millis(2)).await;
                let mut g = w.lock().await;
                if let Err(e) = g.flush_gro().await {
                    warn!(err = %e, "tun: flush_gro/write to device failed");
                }
            }
        });
    }

    let inet4_broadcast = addrs
        .prefixes_v4
        .first()
        .map(|(net, pl)| broadcast_addr_v4(*net, *pl));
    let tcp_mss = compute_effective_mss(None, cfg.mtu);

    if !dns_hijack.is_empty() {
        info!(
            rules = dns_hijack.len(),
            "tun: dns-hijack enabled inside system stack"
        );
    }

    let rt = StackRuntime {
        writer: writer.clone(),
        tcp_nat,
        udp_sessions,
        router,
        outbounds,
        tcp_port_v4,
        tcp_port_v6,
        inet4_server: addrs.inet4_server,
        inet4_client: addrs.inet4_client,
        inet6_server: addrs.inet6_server,
        inet6_client: addrs.inet6_client,
        inet4_broadcast,
        tcp_mss,
        #[cfg(unix)]
        icmp: Some(icmp),
        dns_hijack,
    };

    let mut defrag = IpDefragmenter::new();
    let mut reader = reader.lock().await;
    // Diagnostic counters: packets read from the TUN device, by kind.
    let mut stat_last = Instant::now();
    let mut stat_tcp4 = 0u64;
    let mut stat_udp4 = 0u64;
    let mut stat_icmp4 = 0u64;
    let mut stat_other4 = 0u64;
    let mut stat_v6 = 0u64;
    let mut stat_prev_total = 0u64;
    info!("tun: packet loop started, waiting for packets from device");
    // NOTE: holding reader lock for the whole loop is fine (single reader task).

    loop {
        let pkt = match reader.read_packet().await {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                warn!("tun: device EOF");
                break;
            }
            Err(e) => {
                warn!(err = %e, "tun: read error");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if pkt.len() < 20 {
            reader.recycle(pkt);
            continue;
        }
        if tracing::enabled!(tracing::Level::DEBUG) {
            match pkt[0] >> 4 {
                4 => match pkt[9] {
                    IPPROTO_TCP => stat_tcp4 += 1,
                    IPPROTO_UDP => stat_udp4 += 1,
                    IPPROTO_ICMP => stat_icmp4 += 1,
                    _ => stat_other4 += 1,
                },
                6 => stat_v6 += 1,
                _ => {}
            }
            if stat_last.elapsed() >= Duration::from_secs(5) {
                let total = stat_tcp4 + stat_udp4 + stat_icmp4 + stat_other4 + stat_v6;
                if total != stat_prev_total {
                    info!(
                        tcp4 = stat_tcp4,
                        udp4 = stat_udp4,
                        icmp4 = stat_icmp4,
                        other4 = stat_other4,
                        v6 = stat_v6,
                        "tun: device rx packet counters (cumulative)"
                    );
                    stat_prev_total = total;
                }
                stat_last = Instant::now();
            }
        }
        // 分片重组返回的 Vec 与原始读缓冲都通过 recycle 归还缓冲池，
        // 稳态下读路径零分配（对齐 sing-tun batchLoop 的固定缓冲复用）。
        let (version, mut full) = match pkt[0] >> 4 {
            4 => {
                let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
                let is_frag = (flags_frag & 0x1fff) != 0 || (flags_frag & 0x2000) != 0;
                let full = if is_frag {
                    let assembled = defrag.feed(&pkt, Instant::now());
                    reader.recycle(pkt);
                    assembled
                } else {
                    Some(pkt)
                };
                (4u8, full)
            }
            6 if pkt.len() >= 40 => {
                let full = if super::ip_defrag::ipv6_is_fragment(&pkt) {
                    let assembled = defrag.feed_ipv6(&pkt, Instant::now());
                    reader.recycle(pkt);
                    assembled
                } else {
                    Some(pkt)
                };
                (6u8, full)
            }
            _ => {
                reader.recycle(pkt);
                (0u8, None)
            }
        };
        if let Some(f) = full.as_mut() {
            if version == 4 {
                process_ipv4(f, &rt).await;
            } else {
                process_ipv6(f, &rt).await;
            }
        }
        if let Some(f) = full {
            reader.recycle(f);
        }
    }
    Ok(())
}

async fn bind_with_retry(addr: SocketAddr) -> Option<TcpListener> {
    // 10 x 300ms: tolerate residual address-validity transience after netsh
    // address assignment (dadtransmits=0 is set in device.rs, this is belt
    // and braces).
    for attempt in 0..10u32 {
        match TcpListener::bind(addr).await {
            Ok(l) => return Some(l),
            Err(e) if attempt < 9 => {
                warn!(err = %e, attempt, addr = %addr, "tun: TCP bind failed, retrying");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => {
                warn!(err = %e, addr = %addr, "tun: failed to bind TCP listener");
                return None;
            }
        }
    }
    None
}

async fn accept_loop(
    listener: TcpListener,
    nat: Arc<TcpNat>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err = %e, "tun: accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let peer = crate::app::sockopt::canonical(peer);
        let nat_port = peer.port();
        let Some((orig_src, orig_dst)) = nat.lookup_back(nat_port) else {
            warn!(nat_port, peer = %peer, "tun: accept: unknown NAT port, drop");
            continue;
        };
        debug!(peer = %peer, src = %orig_src, dst = %orig_dst, "tun: accept ok");
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(stream, peer, orig_dst, router, outbounds).await {
                debug!(err = %e, peer = %peer, dest = %orig_dst, "tun: tcp session ended");
            }
        });
    }
}

async fn handle_tcp(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    dest: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    // sing-tun stack_system.go acceptLoop: SetLinger(0) on the inbound conn so
    // closing emits RST instead of TIME_WAIT — without it Windows accumulates
    // TIME_WAIT endpoints (kernel memory + ephemeral port pressure) under
    // connection churn. relay() only shuts down write halves, nothing closes
    // the stream mid-relay, so behaviour during the relay is unchanged.
    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
    debug!(peer = %peer, dest = %dest, "tun: handle_tcp start");
    // TCP DNS is rare; if dest is :53, answer via local DNS when route-hijack-style
    // behaviour is desired — caller may still use udp dns-hijack primarily.
    let decided = target::decide(&router, dest, None).await;
    if decided.outbound == Outbound::Block {
        debug!(dest = %dest, "tun: tcp blocked");
        return Ok(());
    }
    let conn = stats::global().register(stats::ConnectionInfo {
        peer,
        dest: decided.addr,
        dest_host: decided.host.clone(),
        network: "tcp",
        inbound: "tun",
        rule: decided.rule.clone(),
        outbound: decided.outbound.label(),
    });
    let dialer = outbounds.select(decided.outbound).context("no dialer")?;
    let remote = dialer
        .dial_tcp(decided.addr, decided.host.as_deref())
        .await
        .with_context(|| format!("dial {}", decided.addr))?;
    let local: crate::outbound::BoxedStream = Box::new(stream);
    conn.while_alive(relay(local, remote)).await?;
    Ok(())
}

async fn process_ipv4(raw: &mut [u8], rt: &StackRuntime) {
    if raw.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if ihl < 20 || raw.len() < ihl {
        return;
    }
    let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
    if Some(dst_ip) == rt.inet4_broadcast {
        return;
    }
    match raw[9] {
        IPPROTO_TCP if rt.tcp_port_v4 != 0 => {
            handle_tcp_v4(raw, rt).await;
        }
        IPPROTO_TCP => {
            warn!("tun: rx tcp4 but v4 TCP listener is not running (tcp_port_v4=0), dropped");
        }
        IPPROTO_UDP => {
            handle_udp(raw, &raw[ihl..], true, rt).await;
        }
        IPPROTO_ICMP => {
            #[cfg(unix)]
            {
                let handled = if let Some(ref icmp) = rt.icmp {
                    icmp.handle_packet(raw).await
                } else {
                    false
                };
                if !handled {
                    // forwarder only handles echo request; other ICMP ignored
                }
            }
            #[cfg(not(unix))]
            if let Some(reply) = build_icmp_echo_reply_v4(raw) {
                tun_write(&rt.writer, &reply).await;
            }
        }
        _ => {}
    }
}

async fn process_ipv6(raw: &mut [u8], rt: &StackRuntime) {
    if raw.len() < 40 {
        return;
    }
    // Skip extension headers to find L4 (simplified walk)
    let (next, l4_off) = ipv6_l4_offset(raw);
    if l4_off >= raw.len() {
        return;
    }
    match next {
        IPPROTO_TCP if rt.tcp_port_v6 != 0 => {
            handle_tcp_v6(raw, rt).await;
        }
        IPPROTO_UDP => {
            handle_udp(raw, &raw[l4_off..], false, rt).await;
        }
        IPPROTO_ICMPV6 => {
            #[cfg(unix)]
            {
                let _handled = if let Some(ref icmp) = rt.icmp {
                    icmp.handle_packet(raw).await
                } else {
                    false
                };
            }
            #[cfg(not(unix))]
            if let Some(reply) = build_icmp_echo_reply_v6(raw) {
                tun_write(&rt.writer, &reply).await;
            }
        }
        _ => {}
    }
}

/// Walk IPv6 extension headers; return (next_header, offset of L4).
fn ipv6_l4_offset(raw: &[u8]) -> (u8, usize) {
    let mut next = raw[6];
    let mut off = 40usize;
    // hopopt=0, routing=43, dstopts=60, fragment=44 (should be reassembled already)
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if off + 2 > raw.len() {
                    return (next, off);
                }
                let hdr_len = (raw[off + 1] as usize + 1) * 8;
                next = raw[off];
                off += hdr_len;
            }
            44 => {
                // fragment left after failed reassembly — stop
                return (next, off);
            }
            _ => return (next, off),
        }
    }
    (next, off)
}

async fn handle_tcp_v4(raw: &mut [u8], rt: &StackRuntime) {
    let (server_addr, client_addr) = match (rt.inet4_server, rt.inet4_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if raw.len() < ihl + 20 {
        return;
    }
    // 先读出全部需要的字段（可变改写前），避免借用冲突 + 逐包 debug 分配
    let src_ip = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
    let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
    let src_port = u16::from_be_bytes([raw[ihl], raw[ihl + 1]]);
    let dst_port = u16::from_be_bytes([raw[ihl + 2], raw[ihl + 3]]);
    let flags = raw[ihl + 13];
    let seq = u32::from_be_bytes([raw[ihl + 4], raw[ihl + 5], raw[ihl + 6], raw[ihl + 7]]);
    let tcp_port = rt.tcp_port_v4;

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = rt.tcp_nat.lookup_back(dst_port) {
            trace!(
                nat_port = dst_port,
                orig_src = %orig_src,
                orig_dst = %orig_dst,
                flags = %tcp_flags_str(flags),
                "tun: tcp4 reverse (listener -> app)"
            );
            let (ns, nsp) = match orig_dst {
                SocketAddr::V4(a) => (*a.ip(), a.port()),
                _ => return,
            };
            let (nd, ndp) = match orig_src {
                SocketAddr::V4(a) => (*a.ip(), a.port()),
                _ => return,
            };
            // 就地改写（省去逐包 to_vec 分配 + 拷贝）+ 增量校验和更新
            //（RFC 1624，O(1)，省去每包全量 payload 重扫——Linux CPU 热点）
            raw[12..16].copy_from_slice(&ns.octets());
            raw[16..20].copy_from_slice(&nd.octets());
            raw[ihl..ihl + 2].copy_from_slice(&nsp.to_be_bytes());
            raw[ihl + 2..ihl + 4].copy_from_slice(&ndp.to_be_bytes());
            nat_update_tcp_checksum_v4(
                raw, ihl, src_ip.octets(), dst_ip.octets(), src_port, dst_port,
            );
            nat_update_ip_checksum_v4(raw, src_ip.octets(), dst_ip.octets());
            if let Some(mss) = rt.tcp_mss {
                clamp_tcp_mss(raw, ihl, mss);
            }
            tun_write(&rt.writer, raw).await;
        } else {
            warn!(dst_port, "tun: tcp4 reverse packet but NAT entry not found");
        }
        return;
    }

    if !is_global_unicast_v4(dst_ip) {
        return;
    }

    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
    let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
    let Some(nat_port) = rt.tcp_nat.lookup_or_insert(src, dst) else {
        warn!("tun: TCP NAT port space exhausted");
        let rst = build_tcp_rst_v4(dst_ip, src_ip, dst_port, src_port, seq);
        tun_write(&rt.writer, &rst).await;
        return;
    };

    trace!(
        src = %src,
        dst = %dst,
        nat_port,
        to = %format!("{server_addr}:{tcp_port}"),
        "tun: tcp4 forward (app -> listener), writing NAT-ed packet to device"
    );
    raw[12..16].copy_from_slice(&client_addr.octets());
    raw[16..20].copy_from_slice(&server_addr.octets());
    raw[ihl..ihl + 2].copy_from_slice(&nat_port.to_be_bytes());
    raw[ihl + 2..ihl + 4].copy_from_slice(&tcp_port.to_be_bytes());
    nat_update_tcp_checksum_v4(
        raw, ihl, src_ip.octets(), dst_ip.octets(), src_port, dst_port,
    );
    nat_update_ip_checksum_v4(raw, src_ip.octets(), dst_ip.octets());
    if let Some(mss) = rt.tcp_mss {
        clamp_tcp_mss(raw, ihl, mss);
    }
    {
        // Diagnostic: dump the first few NAT-ed SYNs and self-verify checksums.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DUMPED: AtomicUsize = AtomicUsize::new(0);
        if flags & 0x02 != 0 && DUMPED.fetch_add(1, Ordering::Relaxed) < 6 {
            let (ip_ok, tcp_ok) = verify_checksums_v4(raw, ihl);
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            info!(ip_csum_ok = ip_ok, tcp_csum_ok = tcp_ok, len = raw.len(), hex = %hex, "tun: DIAG NAT-ed SYN");
        }
    }
    tun_write(&rt.writer, raw).await;
}

async fn handle_tcp_v6(raw: &mut [u8], rt: &StackRuntime) {
    let (server_addr, client_addr) = match (rt.inet6_server, rt.inet6_client) {
        (Some(s), Some(c)) => (s, c),
        _ => return,
    };
    let tcp_off = ipv6_l4_offset(raw).1;
    if raw.len() < tcp_off + 20 {
        return;
    }
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
    let src_port = u16::from_be_bytes([raw[tcp_off], raw[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([raw[tcp_off + 2], raw[tcp_off + 3]]);
    let seq = u32::from_be_bytes([
        raw[tcp_off + 4],
        raw[tcp_off + 5],
        raw[tcp_off + 6],
        raw[tcp_off + 7],
    ]);
    let tcp_port = rt.tcp_port_v6;

    if src_ip == server_addr && src_port == tcp_port {
        if let Some((orig_src, orig_dst)) = rt.tcp_nat.lookup_back(dst_port) {
            let (ns, nsp) = match orig_dst {
                SocketAddr::V6(a) => (*a.ip(), a.port()),
                _ => return,
            };
            let (nd, ndp) = match orig_src {
                SocketAddr::V6(a) => (*a.ip(), a.port()),
                _ => return,
            };
            raw[8..24].copy_from_slice(&ns.octets());
            raw[24..40].copy_from_slice(&nd.octets());
            raw[tcp_off..tcp_off + 2].copy_from_slice(&nsp.to_be_bytes());
            raw[tcp_off + 2..tcp_off + 4].copy_from_slice(&ndp.to_be_bytes());
            nat_update_tcp_checksum_v6(
                raw, tcp_off, src_ip.octets(), dst_ip.octets(), src_port, dst_port,
            );
            if let Some(mss) = rt.tcp_mss {
                clamp_tcp_mss(raw, tcp_off, mss);
            }
            tun_write(&rt.writer, raw).await;
        }
        return;
    }

    if !is_global_unicast_v6(dst_ip) {
        return;
    }

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
    let Some(nat_port) = rt.tcp_nat.lookup_or_insert(src, dst) else {
        warn!("tun: TCP NAT port space exhausted (v6)");
        let rst = build_tcp_rst_v6(dst_ip, src_ip, dst_port, src_port, seq);
        tun_write(&rt.writer, &rst).await;
        return;
    };

    raw[8..24].copy_from_slice(&client_addr.octets());
    raw[24..40].copy_from_slice(&server_addr.octets());
    raw[tcp_off..tcp_off + 2].copy_from_slice(&nat_port.to_be_bytes());
    raw[tcp_off + 2..tcp_off + 4].copy_from_slice(&tcp_port.to_be_bytes());
    nat_update_tcp_checksum_v6(
        raw, tcp_off, src_ip.octets(), dst_ip.octets(), src_port, dst_port,
    );
    if let Some(mss) = rt.tcp_mss {
        clamp_tcp_mss(raw, tcp_off, mss);
    }
    tun_write(&rt.writer, raw).await;
}

async fn handle_udp(raw: &[u8], udp_payload: &[u8], is_v4: bool, rt: &StackRuntime) {
    if udp_payload.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
    let dst_port = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
    let (src, dst) = if is_v4 {
        if raw.len() < 20 {
            return;
        }
        let src_ip = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
        let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
        if !is_global_unicast_v4(dst_ip) {
            return;
        }
        (
            SocketAddr::V4(SocketAddrV4::new(src_ip, src_port)),
            SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
        )
    } else {
        if raw.len() < 40 {
            return;
        }
        let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap());
        let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap());
        if !is_global_unicast_v6(dst_ip) {
            return;
        }
        (
            SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0)),
        )
    };

    // 快路径：已有 UDP 会话直接投递，避免为每个包分配 template + data 拷贝
    //（DNS/QUIC 等高频小包路径的关键省分配点）。
    {
        let mut map = rt.udp_sessions.lock().unwrap();
        if let Some(e) = map.get_mut(&src) {
            e.last_seen = Instant::now();
            let data = Bytes::copy_from_slice(&udp_payload[8..]);
            let _ = e.packet_tx.try_send((data, dst));
            return;
        }
    }

    // DNS hijack: answer inside the stack and write reply to TUN.
    // 上游选择由 Router 决策（rule-follow-route / dns.rules），无需单独传 upstream。
    if !rt.dns_hijack.is_empty() && rt.dns_hijack.iter().any(|r| r.matches(dst)) {
        let query = udp_payload[8..].to_vec();
        let router = rt.router.clone();
        let writer = rt.writer.clone();
        let reply_src = dst;
        let reply_dst = src;
        tokio::spawn(async move {
            match dns::answer_query(&query, &router).await {
                Ok(resp) => {
                    if let Some(pkt) = build_udp_reply(reply_src, reply_dst, &resp) {
                        tun_write(&writer, &pkt).await;
                    }
                }
                Err(e) => debug!(err = %e, "tun: dns-hijack answer failed"),
            }
        });
        return;
    }

    // Template = IP header + UDP header (no payload)
    let ihl = if is_v4 {
        ((raw[0] & 0x0f) as usize) * 4
    } else {
        40
    };
    let template = if raw.len() >= ihl + 8 {
        raw[..ihl + 8].to_vec()
    } else {
        Vec::new()
    };
    let data = Bytes::copy_from_slice(&udp_payload[8..]);
    feed_udp(src, dst, data, template, rt).await;
}

async fn feed_udp(
    src: SocketAddr,
    dst: SocketAddr,
    data: Bytes,
    template: Vec<u8>,
    rt: &StackRuntime,
) {
    let rx = {
        let mut map = rt.udp_sessions.lock().unwrap();
        if let Some(e) = map.get_mut(&src) {
            // Session appeared between the fast path and here — just feed it.
            e.last_seen = Instant::now();
            let _ = e.packet_tx.try_send((data, dst));
            return;
        }
        let (tx, rx) = mpsc::channel::<UdpPacket>(64);
        let _ = tx.try_send((data, dst));
        map.insert(
            src,
            UdpEntry {
                packet_tx: tx,
                last_seen: Instant::now(),
            },
        );
        rx
    };

    let writer = rt.writer.clone();
    let sessions = rt.udp_sessions.clone();
    let router = rt.router.clone();
    let outbounds = rt.outbounds.clone();
    tokio::spawn(async move {
        run_udp_session(src, rx, template, writer, sessions, router, outbounds).await;
    });
}

async fn run_udp_session(
    client: SocketAddr,
    mut rx: mpsc::Receiver<UdpPacket>,
    template: Vec<u8>,
    writer: Arc<Mutex<NativeTunWriter>>,
    sessions: Arc<std::sync::Mutex<HashMap<SocketAddr, UdpEntry>>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) {
    let Some((first_payload, first_dst)) = rx.recv().await else {
        sessions.lock().unwrap().remove(&client);
        return;
    };

    let decided = target::decide(&router, first_dst, None).await;
    if decided.outbound == Outbound::Block {
        sessions.lock().unwrap().remove(&client);
        return;
    }
    let Some(dialer) = outbounds.select(decided.outbound) else {
        sessions.lock().unwrap().remove(&client);
        return;
    };
    let sess = match dialer.dial_udp(Some(client)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!(err = %e, "tun: udp dial failed");
            sessions.lock().unwrap().remove(&client);
            return;
        }
    };

    let sess_r = sess.clone();
    let writer_r = writer.clone();
    let tmpl = template.clone();
    let recv_task = tokio::spawn(async move {
        while let Ok((payload, from)) = sess_r.recv_from().await {
            if let Some(pkt) =
                build_udp_reply_with_template(&tmpl, from, client, &payload)
            {
                tun_write(&writer_r, &pkt).await;
            }
        }
    });

    if let Err(e) = sess
        .send_to(&first_payload, first_dst, decided.host.as_deref())
        .await
    {
        debug!(err = %e, "tun: udp send failed");
        recv_task.abort();
        sessions.lock().unwrap().remove(&client);
        return;
    }

    while let Ok(Some((payload, dest))) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {
        if let Some(e) = sessions.lock().unwrap().get_mut(&client) {
            e.last_seen = Instant::now();
        }
        if let Err(e) = sess.send_to(&payload, dest, None).await {
            debug!(err = %e, "tun: udp send failed");
            break;
        }
    }

    recv_task.abort();
    sessions.lock().unwrap().remove(&client);
}

async fn tun_write(writer: &Arc<Mutex<NativeTunWriter>>, pkt: &[u8]) {
    let mut w = writer.lock().await;
    if let Err(e) = w.write_packet(pkt).await {
        warn!(err = %e, "tun: write failed");
    }
}
