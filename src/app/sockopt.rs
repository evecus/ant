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

fn apply_bind_iface(sock: &Socket) {
    // Force outbound onto the physical default interface so packets do not
    // re-enter TUN when auto-route / auto-detect-interface is on.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Some(name) = crate::tun::bind_interface() {
            // socket2 0.5: bind_device takes Option<&[u8]>
            if let Err(e) = sock.bind_device(Some(name.as_bytes())) {
                tracing::warn!("SO_BINDTODEVICE {name}: {e}");
            }
        }
    }
    // macOS: IP_BOUND_IF / IPV6_BOUND_IF (no SO_BINDTODEVICE).
    // mihomo / sing-box use the same approach for loop prevention.
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        if let Some(name) = crate::tun::bind_interface() {
            let Ok(cname) = CString::new(name.as_str()) else {
                return;
            };
            let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if idx == 0 {
                tracing::warn!("tun: if_nametoindex({name}) failed");
                return;
            }
            let idx = idx as u32;
            // netinet/in.h: IP_BOUND_IF=25, IPV6_BOUND_IF=125
            const IP_BOUND_IF: libc::c_int = 25;
            const IPV6_BOUND_IF: libc::c_int = 125;
            let fd = sock.as_raw_fd();
            let len = std::mem::size_of_val(&idx) as libc::socklen_t;
            let rc4 = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_BOUND_IF,
                    &idx as *const _ as *const libc::c_void,
                    len,
                )
            };
            let rc6 = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IPV6_BOUND_IF,
                    &idx as *const _ as *const libc::c_void,
                    len,
                )
            };
            // One of the two will fail for a single-family socket; only warn if both fail.
            if rc4 != 0 && rc6 != 0 {
                tracing::warn!(
                    name = %name,
                    idx,
                    err = %std::io::Error::last_os_error(),
                    "tun: IP_BOUND_IF / IPV6_BOUND_IF failed"
                );
            }
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    )))]
    let _ = sock;
}

/// Windows: `IP_UNICAST_IF` / `IPV6_UNICAST_IF` — mihomo `bind_windows.go`
/// alignment. v4 index is set in network byte order (mihomo `bind4`), v6 in
/// host byte order (`bind6`). This is the Windows loop-prevention for
/// auto-detect-interface (no SO_BINDTODEVICE / SO_MARK there).
#[cfg(target_os = "windows")]
fn apply_unicast_if(sock: &Socket, is_v4: bool) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF,
    };

    let Some(idx) = crate::tun::iface::bind_interface_index() else {
        return;
    };
    let s = sock.as_raw_socket() as usize;
    let rc = if is_v4 {
        // network byte order (mihomo bind4: BigEndian.PutUint32)
        let v = idx.to_be_bytes();
        unsafe {
            setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, v.as_ptr(), v.len() as i32)
        }
    } else {
        // host byte order (mihomo bind6: plain SetsockoptInt)
        let v = idx.to_ne_bytes();
        unsafe {
            setsockopt(
                s,
                IPPROTO_IPV6,
                IPV6_UNICAST_IF,
                v.as_ptr(),
                v.len() as i32,
            )
        }
    };
    if rc != 0 {
        tracing::warn!(
            "tun: IP_UNICAST_IF bind if-index {idx} failed (err={})",
            std::io::Error::last_os_error()
        );
    }
}

/// Resolve listen addresses from `bind-address` + top-level `ipv6`.
///
/// `bind` is restricted to `0.0.0.0` / `127.0.0.1` (validated in config).
/// - `ipv6 = true`: dual-stack via a single `[::]` socket (IPV6_V6ONLY=0) for
///   LAN binds, or `127.0.0.1` + `::1` for loopback.
/// - `ipv6 = false`: IPv4 only.
pub fn listen_addrs(bind: &str, port: u16, ipv6: bool) -> Vec<SocketAddr> {
    let dual = || vec![SocketAddr::from(([0u16; 8], port))];
    match bind.trim() {
        "0.0.0.0" | "" => {
            if ipv6 {
                dual()
            } else {
                vec![SocketAddr::from(([0, 0, 0, 0], port))]
            }
        }
        "127.0.0.1" | "localhost" => {
            if ipv6 {
                vec![
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
                ]
            } else {
                vec![SocketAddr::from(([127, 0, 0, 1], port))]
            }
        }
        // Legacy values kept for best-effort compatibility.
        "::" | "[::]" => {
            if ipv6 {
                dual()
            } else {
                vec![SocketAddr::from(([0, 0, 0, 0], port))]
            }
        }
        other => {
            if let Ok(ip) = other.parse::<std::net::IpAddr>() {
                if !ipv6 && ip.is_ipv6() {
                    tracing::warn!(
                        "bind-address {other} is IPv6 but top-level ipv6=false; falling back to 0.0.0.0"
                    );
                    vec![SocketAddr::from(([0, 0, 0, 0], port))]
                } else {
                    vec![SocketAddr::new(ip, port)]
                }
            } else {
                tracing::warn!("unknown bind-address {other}, using dual-stack={ipv6}");
                if ipv6 {
                    dual()
                } else {
                    vec![SocketAddr::from(([0, 0, 0, 0], port))]
                }
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
    apply_bind_iface(&sock);
    #[cfg(target_os = "windows")]
    // mihomo bindControl skips non-global-unicast destinations (loopback,
    // unspecified, multicast) so local traffic stays local.
    if !addr.ip().is_loopback() && !addr.ip().is_unspecified() {
        apply_unicast_if(&sock, addr.is_ipv4());
    }
    sock.set_nonblocking(true)?;
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        // Non-blocking connect is expected to report "in progress": EINPROGRESS
        // on Unix, WSAEWOULDBLOCK on Windows. Completion is awaited via
        // stream.writable() + take_error() below; treating WSAEWOULDBLOCK as a
        // real error made every outbound dial fail instantly on Windows.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        #[cfg(windows)]
        Err(e) if e.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK) => {}
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
    apply_bind_iface(&sock);
    #[cfg(target_os = "windows")]
    // mihomo bindIfaceToListenConfig: relay/listen UDP sockets are bound to
    // the interface unconditionally (destination may be any).
    apply_unicast_if(&sock, bind.is_ipv4());
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into()).context("udp bind")?;
    let std: StdUdp = sock.into();
    Ok(UdpSocket::from_std(std)?)
}
