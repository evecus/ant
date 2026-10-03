//! Socket mark (SO_MARK) and listen-address selection.

use anyhow::{Context, Result};
use socket2::{Domain, Socket, Type};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcp, UdpSocket as StdUdp};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

static MARK: AtomicU32 = AtomicU32::new(0);

pub fn set_fwmark(mark: u32) {
    MARK.store(mark, Ordering::Relaxed);
    if mark != 0 {
        tracing::info!("fwmark={mark}");
    }
}

// Only read by the SO_MARK path in apply_mark (linux/android).
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code)
)]
pub fn fwmark() -> u32 {
    MARK.load(Ordering::Relaxed)
}

fn apply_mark(sock: &Socket) {
    // SO_MARK works on Linux and Android (bionic); socket2::set_mark supports
    // both. On other platforms this is a no-op.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mark = fwmark();
        if mark != 0 {
            if let Err(e) = sock.set_mark(mark) {
                tracing::warn!("SO_MARK {mark}: {e}");
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = sock;
}

/// `::` (or empty) is a single dual-stack IPv6 socket (IPV6_V6ONLY=0) that
/// accepts both IPv4 and IPv6, so it is bound exactly once; binding `0.0.0.0`
/// as well would make the `[::]` bind fail with EADDRINUSE.
/// `0.0.0.0` v4 external, `127.0.0.1` localhost v4+v6.
pub fn listen_addrs(bind: &str, port: u16) -> Vec<SocketAddr> {
    let dual = || vec![SocketAddr::from(([0u16; 8], port))];
    match bind.trim() {
        "" | "::" | "[::]" => dual(),
        "0.0.0.0" => vec![SocketAddr::from(([0, 0, 0, 0], port))],
        "127.0.0.1" | "localhost" => vec![
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
        ],
        other => {
            if let Ok(ip) = other.parse() {
                vec![SocketAddr::new(ip, port)]
            } else {
                tracing::warn!("unknown bind-address {other}, using dual-stack");
                dual()
            }
        }
    }
}

/// True for `[::]:port`, i.e. the dual-stack wildcard.
pub fn is_dual_stack(addr: &SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(a) if a.ip().is_unspecified())
}

/// `0.0.0.0:port` fallback for a dual-stack address (used when the host has
/// IPv6 disabled and `[::]` cannot be bound).
pub fn v4_fallback(addr: &SocketAddr) -> Option<SocketAddr> {
    if is_dual_stack(addr) {
        Some(SocketAddr::from(([0, 0, 0, 0], addr.port())))
    } else {
        None
    }
}

/// Map an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, as seen on a dual-stack
/// socket) back to a plain IPv4 address.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(a) = addr {
        if let Some(v4) = a.ip().to_ipv4_mapped() {
            return SocketAddr::new(v4.into(), a.port());
        }
    }
    addr
}

fn new_listen_socket(addr: SocketAddr, ty: Type) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, ty, None)?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        // Explicit, so behaviour does not depend on net.ipv6.bindv6only.
        sock.set_only_v6(!is_dual_stack(&addr))?;
    }
    sock.set_nonblocking(true)?;
    Ok(sock)
}

fn bind_tcp_once(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = new_listen_socket(addr, Type::STREAM)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    let std: StdTcpListener = sock.into();
    TcpListener::from_std(std)
}

fn bind_udp_once(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = new_listen_socket(addr, Type::DGRAM)?;
    sock.bind(&addr.into())?;
    let std: StdUdp = sock.into();
    UdpSocket::from_std(std)
}

/// Bind a TCP listener. `[::]` is dual-stack; if IPv6 is unavailable it falls
/// back to `0.0.0.0`. Returns the address actually bound.
pub fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<(TcpListener, SocketAddr)> {
    match bind_tcp_once(addr) {
        Ok(l) => Ok((l, addr)),
        Err(e) => match v4_fallback(&addr) {
            Some(v4) => {
                tracing::warn!("tcp bind {addr}: {e}; falling back to {v4}");
                bind_tcp_once(v4).map(|l| (l, v4))
            }
            None => Err(e),
        },
    }
}

/// UDP counterpart of [`bind_tcp_listener`].
pub fn bind_udp_listener(addr: SocketAddr) -> std::io::Result<(UdpSocket, SocketAddr)> {
    match bind_udp_once(addr) {
        Ok(l) => Ok((l, addr)),
        Err(e) => match v4_fallback(&addr) {
            Some(v4) => {
                tracing::warn!("udp bind {addr}: {e}; falling back to {v4}");
                bind_udp_once(v4).map(|l| (l, v4))
            }
            None => Err(e),
        },
    }
}

pub async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, None).context("tcp socket")?;
    apply_mark(&sock);
    sock.set_nonblocking(true)?;
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        // Non-blocking connect on Unix reports EINPROGRESS.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).context("tcp connect"),
    }
    let std: StdTcp = sock.into();
    let stream = TcpStream::from_std(std)?;
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e).context("tcp connect");
    }
    Ok(stream)
}

pub async fn bind_udp(bind: SocketAddr) -> Result<UdpSocket> {
    let domain = if bind.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, None).context("udp socket")?;
    apply_mark(&sock);
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into()).context("udp bind")?;
    let std: StdUdp = sock.into();
    Ok(UdpSocket::from_std(std)?)
}
