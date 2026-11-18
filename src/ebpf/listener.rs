//! Transparent TCP/UDP listeners created inside `antns` and published into
//! the LISTEN_SOCKETS sockmap that the sk_lookup program assigns packets to.
//!
//! [方案二] UDP 按地址族各起一组并行监听 socket，槽位常量由
//! ant-ebpf-common 统一定义；sk_lookup 按五元组哈希把一条流固定到其中
//! 一个 socket，用户态给每个 socket 配一条独立 recvmsg 线程和 flow 表。

use super::ns::with_antns;
use anyhow::{Context, Result};
use ant_ebpf_common::{KEY_TCP4, KEY_TCP6, KEY_UDP4_BASE, KEY_UDP6_BASE, UDP_LISTENER_MAX};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

pub const IP_TRANSPARENT: i32 = 19;
pub const IPV6_TRANSPARENT: i32 = 75;
pub const IP_RECVORIGDSTADDR: i32 = 20;
pub const IPV6_RECVORIGDSTADDR: i32 = 74;

pub struct Listeners {
    pub tcp4: tokio::net::TcpListener,
    /// 阻塞 socket：每个由一条独立的 recvmsg 线程消费（见 relay）。
    pub udp4: Vec<std::net::UdpSocket>,
    /// v6 TCP 监听。`create(..., has_v6 = true, ...)` 会把它发布到 sockmap
    /// 的 KEY_TCP6，sk_lookup 把所有 AF_INET6/TCP 连接都交给它 —— 因此
    /// 必须有人 accept（见 relay::run_tcp），否则 IPv6 TCP 代理连接会全部
    /// 挂在半连接队列里直到超时。
    pub tcp6: Option<tokio::net::TcpListener>,
    /// [方案二] v6 并行监听组。旧版创建了却没人 recv，数据报会在队列里
    /// 堆积到溢出；现在一并交给 relay 消费。
    pub udp6: Vec<std::net::UdpSocket>,
}

/// Create transparent listeners inside `antns` and register their fds in the
/// sockmap. Returns the tokio handles for the control plane.
///
/// `workers` 是每族并行 UDP socket 数，1..=UDP_LISTENER_MAX；它同时写进
/// PARAM.udp_workers 作为 sk_lookup 哈希的模数，两者必须一致。
pub fn create(
    dp: &mut super::datapath::Datapath,
    has_v6: bool,
    workers: usize,
) -> Result<Listeners> {
    let workers = workers.clamp(1, UDP_LISTENER_MAX as usize);
    let (tcp4_fd, udp4_fds) =
        with_antns(|| Ok((tcp_listen4()?, udp_listen_group(false, workers)?)))?;
    let (tcp6_fd, udp6_fds) = if has_v6 {
        with_antns(|| Ok((Some(tcp_listen6()?), udp_listen_group(true, workers)?)))?
    } else {
        (None, Vec::new())
    };

    // TCP fds go to tokio and must be non-blocking. UDP fds stay blocking:
    // they are read by dedicated threads (recvmsg with RECVORIGDSTADDR has
    // no tokio equivalent).
    for fd in std::iter::once(tcp4_fd).chain(tcp6_fd.iter().map(|f| f.as_raw_fd())) {
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    }

    dp.publish_listener(KEY_TCP4, tcp4_fd)?;
    for (i, fd) in udp4_fds.iter().enumerate() {
        dp.publish_listener(KEY_UDP4_BASE + i as u32, *fd)?;
    }
    if let Some(fd) = tcp6_fd.as_ref().map(|f| f.as_raw_fd()) {
        dp.publish_listener(KEY_TCP6, fd)?;
    }
    for (i, fd) in udp6_fds.iter().enumerate() {
        dp.publish_listener(KEY_UDP6_BASE + i as u32, *fd)?;
    }

    let tcp4 = tokio::net::TcpListener::from_std(from_raw_tcp(tcp4_fd))?;
    let udp4 = udp4_fds.into_iter().map(from_raw_udp).collect();
    let tcp6 = match tcp6_fd {
        Some(fd) => Some(tokio::net::TcpListener::from_std(from_raw_tcp(fd))?),
        None => None,
    };
    let udp6 = udp6_fds.into_iter().map(from_raw_udp).collect();
    Ok(Listeners {
        tcp4,
        udp4,
        tcp6,
        udp6,
    })
}

fn set_transparent(fd: std::os::fd::RawFd, v6: bool) -> Result<()> {
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, IP_TRANSPARENT)
    };
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        anyhow::bail!("IP_TRANSPARENT: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn tcp_listen4() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, false)?;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind tcp4: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 256) } != 0 {
        anyhow::bail!("listen: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn tcp_listen6() -> Result<std::os::fd::RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!("socket6: {}", std::io::Error::last_os_error());
    }
    set_transparent(fd, true)?;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1i32 as *const _ as *const libc::c_void,
            4,
        )
    };
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    if rc != 0 {
        anyhow::bail!("bind tcp6: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 256) } != 0 {
        anyhow::bail!("listen6: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// [方案二] 建一组并行透明 UDP 监听 socket。
///
/// SO_REUSEPORT 让同组 socket 共享绑定；绑定端口写 0 也不影响投递，因为
/// sk_lookup 用 bpf_sk_assign 显式指派 socket，绕开了按端口的查找。每个
/// socket 都带 IP_TRANSPARENT + RECVORIGDSTADDR，数据报由 relay 各自的
/// recvmsg 线程读出原目的地址。
fn udp_listen_group(v6: bool, workers: usize) -> Result<Vec<std::os::fd::RawFd>> {
    let mut out = Vec::with_capacity(workers);
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let (dst_level, dst_opt) = if v6 {
        (libc::IPPROTO_IPV6, IPV6_RECVORIGDSTADDR)
    } else {
        (libc::IPPROTO_IP, IP_RECVORIGDSTADDR)
    };
    for _ in 0..workers {
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            anyhow::bail!("udp socket: {}", std::io::Error::last_os_error());
        }
        if let Err(e) = set_transparent(fd, v6) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                4,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                4,
            );
            libc::setsockopt(fd, dst_level, dst_opt, &one as *const _ as *const libc::c_void, 4);
        }
        if v6 {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &one as *const _ as *const libc::c_void,
                    4,
                );
            }
        }
        // sockaddr 声明在函数作用域，bind 的指针不会指向即将销毁的局部变量。
        let addr4 = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let addr6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_scope_id: 0,
        };
        let (ptr, len) = if v6 {
            (
                &addr6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        } else {
            (
                &addr4 as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if unsafe { libc::bind(fd, ptr, len) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            anyhow::bail!("bind udp group: {err}");
        }
        out.push(fd);
    }
    Ok(out)
}

fn from_raw_tcp(fd: std::os::fd::RawFd) -> std::net::TcpListener {
    unsafe { std::net::TcpListener::from_raw_fd(fd) }
}

fn from_raw_udp(fd: std::os::fd::RawFd) -> std::net::UdpSocket {
    unsafe { std::net::UdpSocket::from_raw_fd(fd) }
}

use std::os::fd::FromRawFd;

/// Address of the original destination for an accepted transparent TCP conn.
pub fn orig_dst_tcp(conn: &tokio::net::TcpStream) -> Result<SocketAddr> {
    conn.local_addr().context("getsockname orig dst")
}

/// Create a UDP socket inside `antns` bound to an original destination, so
/// datagrams sent from it look like replies from the original target.
pub fn create_reply_socket(orig: SocketAddr) -> Result<tokio::net::UdpSocket> {
    let fd = with_antns(|| {
        // The sockaddr must outlive the bind() call: declare the storage
        // here, not inside the match arms (a pointer to an arm-local would
        // dangle and bind() then fails with EAFNOSUPPORT at random).
        let sin: libc::sockaddr_in;
        let sin6: libc::sockaddr_in6;
        let (family, ptr, len) = match orig {
            SocketAddr::V4(a) => {
                sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: a.port().to_be(),
                    // s_addr is a memory-layout field: octets() is already
                    // network order.
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(a.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                (
                    libc::AF_INET,
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            }
            SocketAddr::V6(a) => {
                sin6 = sockaddr6_from(&a);
                (
                    libc::AF_INET6,
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32,
                )
            }
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            anyhow::bail!("reply socket: {}", std::io::Error::last_os_error());
        }
        set_transparent(fd, family == libc::AF_INET6)?;
        // Two concurrent flows may target the same orig dst; this socket is
        // send-only, so reuse is safe and prevents EADDRINUSE.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &1i32 as *const _ as *const libc::c_void,
                4,
            )
        };
        if unsafe { libc::bind(fd, ptr, len) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            anyhow::bail!("bind reply socket: {err}");
        }
        Ok(fd)
    })?;
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    Ok(tokio::net::UdpSocket::from_std(from_raw_udp(fd))?)
}

fn sockaddr6_from(a: &std::net::SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: a.port().to_be(),
        sin6_flowinfo: a.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: a.ip().octets(),
        },
        sin6_scope_id: a.scope_id(),
    }
}
