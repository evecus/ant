//! Linux TProxy TCP + UDP inbound (IPv4 + IPv6).
//! CPU-sensitive path: recvmsg/sendto run inline after readable (no spawn_blocking per packet).

use crate::outbound::OutboundManager;
use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use super::target;
use anyhow::{Context, Result};
use etherparse::PacketBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

const UDP_IDLE: Duration = Duration::from_secs(60);

pub async fn run_tproxy(
    port: u16,
    bind_address: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let mut handles = Vec::new();
    let addrs = crate::app::sockopt::listen_addrs(&bind_address, port);

    for bind in addrs.clone() {
        let r = router.clone();
        let o = outbounds.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tproxy_tcp(bind, r, o).await {
                tracing::error!("tproxy tcp {}: {e:#}", bind);
            }
        }));
    }

    for bind in addrs {
        let r = router.clone();
        let o = outbounds.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tproxy_udp(bind, r, o).await {
                tracing::error!("tproxy udp {}: {e:#}", bind);
            }
        }));
    }

    tracing::info!("tproxy TCP+UDP listening (bind-address={bind_address}, port={port})");
    futures::future::join_all(handles).await;
    Ok(())
}

async fn run_tproxy_tcp(
    bind: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let (listener, bind) = match bind_tproxy_tcp(bind) {
        Ok(l) => (l, bind),
        Err(e) => match crate::app::sockopt::v4_fallback(&bind) {
            Some(v4) => {
                tracing::warn!("tproxy tcp bind {bind}: {e}; falling back to {v4}");
                (bind_tproxy_tcp(v4)?, v4)
            }
            None => return Err(e),
        },
    };
    tracing::info!("tproxy TCP listening on {}", bind);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
            Err(e) => {
                tracing::warn!("tproxy accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tproxy_tcp(stream, peer, router, outbounds).await {
                tracing::debug!("tproxy tcp {peer}: {e:#}");
            }
        });
    }
}

fn bind_tproxy_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        let dual = crate::app::sockopt::is_dual_stack(&addr);
        // `::` = one dual-stack socket serving both IPv4 and IPv6.
        socket.set_only_v6(!dual)?;
        set_ip_transparent_v6(socket.as_raw_fd())?;
        if dual {
            set_ip_transparent_v4(socket.as_raw_fd())?;
        }
    } else {
        set_ip_transparent_v4(socket.as_raw_fd())?;
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: StdTcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

async fn handle_tproxy_tcp(
    stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let dest = stream
        .local_addr()
        .ok()
        .map(crate::app::sockopt::canonical)
        .filter(|a| a.port() != 0)
        .or_else(|| {
            if peer.is_ipv4() {
                original_dst_tcp_v4(stream.as_raw_fd())
            } else {
                original_dst_tcp_v6(stream.as_raw_fd())
            }
        })
        .unwrap_or(peer);
    tracing::debug!("tproxy tcp {} -> {}", peer, dest);

    let mut domain = None;
    let mut peek_buf = vec![0u8; 2048];
    // Peek is only needed for protocol sniffing (`sniff`) or DNS-stream detection
    // (`dns.route-hijack`, port 53 is hijacked unconditionally below).
    let want_peek = router.sniff() || (router.hijack_dns() && dest.port() != 53);
    if want_peek {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), stream.peek(&mut peek_buf)).await
        {
            let sniffed = sniffer::sniff_tcp_ex(&peek_buf[..n], router.sniff(), router.hijack_dns());
            domain = sniffed.domain;
            if router.hijack_dns() && (dest.port() == 53 || sniffed.dns) {
                tracing::debug!("tproxy tcp hijack dns {peer} -> {dest}");
                return hijack_dns_tcp(stream, router).await;
            }
        }
    }
    if router.hijack_dns() && dest.port() == 53 {
        tracing::debug!("tproxy tcp hijack dns {peer} -> {dest}");
        return hijack_dns_tcp(stream, router).await;
    }

    let target = target::decide(&router, dest, domain).await;
    if target.outbound == Outbound::Block {
        tracing::debug!("tproxy tcp block {} ({:?})", dest, target.host);
        return Ok(());
    }
    let _conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
        peer,
        dest: target.addr,
        dest_host: target.host.clone(),
        network: "tcp",
        inbound: "tproxy",
        rule: target.rule.clone(),
        outbound: target.outbound.label(),
    });
    let dialer = outbounds.select(target.outbound).context("no dialer")?;
    let remote = dialer
        .dial_tcp(target.addr, target.host.as_deref())
        .await
        .with_context(|| format!("dial tcp {}", target.addr))?;
    let local: crate::outbound::BoxedStream = Box::new(stream);
    crate::outbound::relay(local, remote).await?;
    Ok(())
}

type UdpNatKey = (SocketAddr, SocketAddr);

async fn run_tproxy_udp(
    bind: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let (sock, bind) = match bind_tproxy_udp(bind) {
        Ok(s) => (s, bind),
        Err(e) => match crate::app::sockopt::v4_fallback(&bind) {
            Some(v4) => {
                tracing::warn!("tproxy udp bind {bind}: {e}; falling back to {v4}");
                (bind_tproxy_udp(v4)?, v4)
            }
            None => return Err(e),
        },
    };
    let sock = Arc::new(sock);
    tracing::info!("tproxy UDP listening on {}", bind);

    let raw = Arc::new(RawSockets::new(bind).context("create raw socket (need CAP_NET_RAW)")?);

    let nat: Arc<Mutex<HashMap<UdpNatKey, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut buf = vec![0u8; 65535];

    loop {
        let (n, peer, dest) = match recv_tproxy_udp(&sock, &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("tproxy udp recv: {e:#}");
                // Avoid busy-loop when the kernel keeps returning errors.
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let data = buf[..n].to_vec();

        if dest.ip().is_multicast()
            || matches!(dest.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            continue;
        }

        let key = (peer, dest);
        let mut map = nat.lock().await;
        if let Some(tx) = map.get(&key) {
            // Full or disconnected: drop packet / fall through to recreate only if dead.
            match tx.try_send(data) {
                Ok(()) => continue,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Session alive but slow — drop rather than thrash tasks.
                    continue;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(d)) => {
                    map.remove(&key);
                    // recreate below with this packet
                    let data = d;
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                    let _ = tx.try_send(data);
                    map.insert(key, tx);
                    drop(map);
                    let router = router.clone();
                    let outbounds = outbounds.clone();
                    let raw = raw.clone();
                    let nat = nat.clone();
                    tokio::spawn(async move {
                        if let Err(e) = udp_session_worker(raw, peer, dest, rx, router, outbounds).await {
                            tracing::debug!("tproxy udp session {peer} -> {dest}: {e:#}");
                        }
                        nat.lock().await.remove(&(peer, dest));
                    });
                    continue;
                }
            }
        }

        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        let _ = tx.try_send(data);
        map.insert(key, tx);
        drop(map);

        let router = router.clone();
        let outbounds = outbounds.clone();
        let raw = raw.clone();
        let nat = nat.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_session_worker(raw, peer, dest, rx, router, outbounds).await {
                tracing::debug!("tproxy udp session {peer} -> {dest}: {e:#}");
            }
            nat.lock().await.remove(&(peer, dest));
        });
    }
}

async fn udp_session_worker(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let first = match rx.recv().await {
        Some(d) => d,
        None => return Ok(()),
    };
    let sniffed = sniffer::sniff_udp_ex(&first, router.sniff(), router.hijack_dns());
    if router.hijack_dns() && (dest.port() == 53 || sniffed.dns) {
        tracing::debug!("tproxy udp hijack dns {peer} -> {dest}");
        return hijack_dns_udp(raw, peer, dest, first, rx, router).await;
    }
    let sniff_quic_hit = sniffed.quic;
    let sniffed = sniffed.domain;
    let target = target::decide(&router, dest, sniffed).await;
    if let Some(ref d) = target.host {
        tracing::debug!("tproxy udp sniff {} -> domain={d} via {:?}", dest, target.outbound);
    }
    if target.outbound == Outbound::Block {
        tracing::debug!("tproxy udp block {} ({:?})", dest, target.host);
        while let Ok(Some(_)) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {}
        return Ok(());
    }
    // 入站类型统一为 tproxy（不区分 tcp/udp）；流量类型单独记录：
    // 首包被识别为 QUIC Initial → quic，否则 udp。
    let network = if sniff_quic_hit { "quic" } else { "udp" };
    let _conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
        peer,
        dest: target.addr,
        dest_host: target.host.clone(),
        network,
        inbound: "tproxy",
        rule: target.rule.clone(),
        outbound: target.outbound.label(),
    });
    let dialer = outbounds.select(target.outbound).context("no dialer")?;
    let sess = dialer
        .dial_udp(Some(peer))
        .await
        .with_context(|| format!("dial udp {}", target.addr))?;

    if let Err(e) = sess.send_to(&first, target.addr, target.host.as_deref()).await {
        tracing::debug!("tproxy udp send first: {e}");
        return Ok(());
    }

    // Idle deadline only advances on real traffic; avoids perpetual sessions when
    // a broken outbound keeps waking recv_from with errors (we break on Err).
    let mut deadline = tokio::time::Instant::now() + UDP_IDLE;
    loop {
        tokio::select! {
            pkt = rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = sess.send_to(&data, target.addr, target.host.as_deref()).await {
                            tracing::debug!("tproxy udp send: {e}");
                            break;
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    None => break,
                }
            }
            resp = sess.recv_from() => {
                match resp {
                    Ok((data, src)) => {
                        let reply_src = if src.is_ipv4() == peer.is_ipv4() { src } else { dest };
                        if let Err(e) = sendto_with_src(&raw, &data, peer, reply_src) {
                            tracing::debug!("tproxy udp reply: {e}");
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    Err(e) => {
                        tracing::debug!("tproxy udp recv remote: {e}");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }
    Ok(())
}

fn bind_tproxy_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true);
    if addr.is_ipv6() {
        let dual = crate::app::sockopt::is_dual_stack(&addr);
        socket.set_only_v6(!dual)?;
        set_ip_transparent_v6(socket.as_raw_fd())?;
        set_recv_origdst_v6(socket.as_raw_fd())?;
        if dual {
            // IPv4 packets arriving on the dual-stack socket carry their
            // original destination via the IPv4 cmsg.
            set_ip_transparent_v4(socket.as_raw_fd())?;
            set_recv_origdst_v4(socket.as_raw_fd())?;
        }
    } else {
        set_ip_transparent_v4(socket.as_raw_fd())?;
        set_recv_origdst_v4(socket.as_raw_fd())?;
    }
    socket.bind(&addr.into())?;
    let std_sock: StdUdpSocket = socket.into();
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn recv_tproxy_udp(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    // Must use try_io so a WouldBlock clears the readiness interest; otherwise
    // readable().await returns immediately forever and spins one core.
    use tokio::io::Interest;
    loop {
        let ready = sock.ready(Interest::READABLE).await?;
        if !ready.is_readable() {
            continue;
        }
        match sock.try_io(Interest::READABLE, || recvmsg_origdst(sock.as_raw_fd(), buf)) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn recvmsg_origdst(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 256];
        let mut src_storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_storage as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of_val(&src_storage) as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let peer = sockaddr_to_socket_addr(&src_storage, msg.msg_namelen)
            .map(crate::app::sockopt::canonical)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad peer addr"))?;

        let mut dest = peer;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let sa = *data;
                dest = SocketAddr::new(
                    std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).into(),
                    u16::from_be(sa.sin_port),
                );
                break;
            }
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == 74 {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let sa = *data;
                dest = SocketAddr::new(
                    std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr).into(),
                    u16::from_be(sa.sin6_port),
                );
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Ok((n as usize, peer, dest))
    }
}

fn sockaddr_to_socket_addr(ss: &libc::sockaddr_storage, len: u32) -> Option<SocketAddr> {
    unsafe {
        match ss.ss_family as i32 {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::new(
                    std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).into(),
                    u16::from_be(sa.sin_port),
                ))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in6);
                Some(SocketAddr::new(
                    std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr).into(),
                    u16::from_be(sa.sin6_port),
                ))
            }
            _ => None,
        }
    }
}

fn new_raw_socket(v6: bool) -> io::Result<Socket> {
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(libc::IPPROTO_RAW)))?;
    socket.set_nonblocking(true)?;
    if v6 {
        unsafe {
            let opt: libc::c_int = 1;
            let _ = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                36,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            );
        }
    }
    Ok(socket)
}

/// Raw sockets used to spoof the reply source address. A dual-stack listener
/// needs one per address family.
struct RawSockets {
    v4: Option<Socket>,
    v6: Option<Socket>,
}

impl RawSockets {
    fn new(bind: SocketAddr) -> io::Result<Self> {
        if bind.is_ipv4() {
            return Ok(Self { v4: Some(new_raw_socket(false)?), v6: None });
        }
        if crate::app::sockopt::is_dual_stack(&bind) {
            let v6 = new_raw_socket(true)?;
            let v4 = match new_raw_socket(false) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("tproxy udp: ipv4 raw socket: {e}");
                    None
                }
            };
            return Ok(Self { v4, v6: Some(v6) });
        }
        Ok(Self { v4: None, v6: Some(new_raw_socket(true)?) })
    }
}

fn sendto_with_src(raw: &RawSockets, buf: &[u8], dst: SocketAddr, src: SocketAddr) -> Result<()> {
    let socket = match dst {
        SocketAddr::V4(_) => raw.v4.as_ref(),
        SocketAddr::V6(_) => raw.v6.as_ref(),
    }
    .context("no raw socket for this address family")?;
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            let builder = PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64)
                .udp(s.port(), d.port());
            let mut packet = Vec::with_capacity(builder.size(buf.len()));
            builder
                .write(&mut packet, buf)
                .map_err(|e| anyhow::anyhow!("build udp v4 packet: {e}"))?;
            sendto_raw(socket, &packet, dst)
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            let builder = PacketBuilder::ipv6(s.ip().octets(), d.ip().octets(), 64)
                .udp(s.port(), d.port());
            let mut packet = Vec::with_capacity(builder.size(buf.len()));
            builder
                .write(&mut packet, buf)
                .map_err(|e| anyhow::anyhow!("build udp v6 packet: {e}"))?;
            sendto_raw(socket, &packet, dst)
        }
        _ => anyhow::bail!("tproxy udp reply family mismatch src={src} dst={dst}"),
    }
}

fn sendto_raw(socket: &Socket, packet: &[u8], dst: SocketAddr) -> Result<()> {
    let dst_sa = socket2::SockAddr::from(dst);
    let fd = socket.as_raw_fd();
    let ret = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            dst_sa.as_ptr(),
            dst_sa.len(),
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(err.into());
        }
    }
    Ok(())
}

fn set_recv_origdst_v4(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!(
                "IP_RECVORIGDSTADDR failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn set_recv_origdst_v6(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            74,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!(
                "IPV6_RECVORIGDSTADDR failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn set_ip_transparent_v4(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!(
                "IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn set_ip_transparent_v6(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!(
                "IPV6_TRANSPARENT failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn original_dst_tcp_v4(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::new(ip.into(), port))
    }
}

fn original_dst_tcp_v6(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
        let port = u16::from_be(addr.sin6_port);
        Some(SocketAddr::new(ip.into(), port))
    }
}

async fn hijack_dns_tcp(mut stream: TcpStream, router: Arc<Router>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            anyhow::bail!("bad dns tcp length {len}");
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let resp = crate::dns::answer_query(&query, &router).await?;
        stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
}

async fn hijack_dns_udp(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr,
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
) -> Result<()> {
    let mut queries = vec![first];
    while let Ok(Some(q)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
        queries.push(q);
    }
    for query in queries {
        match crate::dns::answer_query(&query, &router).await {
            Ok(resp) => {
                if let Err(e) = sendto_with_src(&raw, &resp, peer, dest) {
                    tracing::debug!("hijack dns reply: {e}");
                }
            }
            Err(e) => tracing::debug!("hijack dns query: {e}"),
        }
    }
    Ok(())
}
