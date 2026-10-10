//! macOS utun device configuration — faithful port of sing-tun `tun_darwin.go`
//! address / MTU / buffer setup (without auto-route).
//!
//! ## utun packet format
//! Kernel always prefixes each frame with a 4-byte family header:
//!   `[0, 0, 0, AF_INET]` or `[0, 0, 0, AF_INET6]` (big-endian u32).
//! The `tun` crate (packet_information=true, default on macOS) strips this on
//! read and prepends it on write, so upper layers see pure IP — same contract
//! as Linux without IFF_NO_PI and Windows/WinTun.
//!
//! ## Address configuration
//! Uses `SIOCAIFADDR` / `SIOCAIFADDR_IN6` ioctls (not shell `ifconfig`), matching
//! sing-tun `create()`. IPv4 is point-to-point style (addr == dst); IPv6 sets
//! NODAD | SECURED and infinite lifetimes.

#![allow(non_camel_case_types)]

use anyhow::{Context, Result};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use tracing::info;

const IFNAMSIZ: usize = 16;

/// netinet6/in6_var.h
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080691a; // 2155899162
const IN6_IFF_NODAD: u32 = 0x0020;
const IN6_IFF_SECURED: u32 = 0x0400;
const ND6_INFINITE_LIFETIME: u32 = 0xffff_ffff;

/// sing-tun receive-buffer targets for utun control socket.
const UTUN_RCVBUF_TARGET: i32 = 8 << 20;
const UTUN_RCVBUF_MINIMUM: i32 = 1 << 20;
const UTUN_RCVBUF_DEFAULT: i32 = 512 << 10;

#[repr(C)]
struct ifaliasreq {
    ifra_name: [libc::c_char; IFNAMSIZ],
    ifra_addr: libc::sockaddr_in,
    ifra_broadaddr: libc::sockaddr_in, // dst on point-to-point
    ifra_mask: libc::sockaddr_in,
}

#[repr(C)]
struct in6_addrlifetime {
    ia6t_expire: f64,
    ia6t_preferred: f64,
    ia6t_vltime: u32,
    ia6t_pltime: u32,
}

#[repr(C)]
struct in6_aliasreq {
    ifra_name: [libc::c_char; IFNAMSIZ],
    ifra_addr: libc::sockaddr_in6,
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: u32,
    ifra_lifetime: in6_addrlifetime,
}

fn copy_ifname(dst: &mut [libc::c_char; IFNAMSIZ], name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1);
    for i in 0..n {
        dst[i] = bytes[i] as libc::c_char;
    }
    dst[n..].fill(0);
}

fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(addr).to_be(),
    };
    sa
}

fn sockaddr_in6(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_addr = libc::in6_addr {
        s6_addr: addr.octets(),
    };
    sa
}

fn prefix_mask_v4(pl: u8) -> Ipv4Addr {
    let pl = pl.min(32);
    let mask = if pl == 0 {
        0u32
    } else {
        !((1u32 << (32 - pl)) - 1)
    };
    Ipv4Addr::from(mask)
}

fn prefix_mask_v6(pl: u8) -> Ipv6Addr {
    let pl = pl.min(128) as u32;
    let mut bytes = [0u8; 16];
    let full = (pl / 8) as usize;
    let rem = pl % 8;
    bytes[..full].fill(0xff);
    if full < 16 && rem > 0 {
        bytes[full] = !(0xffu8 >> rem);
    }
    Ipv6Addr::from(bytes)
}

fn with_dgram_socket(domain: i32, f: impl FnOnce(RawFd) -> io::Result<()>) -> io::Result<()> {
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = f(fd);
    unsafe {
        libc::close(fd);
    }
    result
}

fn fill_ifreq_name(ifr: &mut libc::ifreq, name: &str) {
    // ifreq.ifr_name is [c_char; IFNAMSIZ] on Darwin.
    let name_ptr = ifr.ifr_name.as_mut_ptr() as *mut libc::c_char;
    let slice = unsafe { std::slice::from_raw_parts_mut(name_ptr, IFNAMSIZ) };
    for b in slice.iter_mut() {
        *b = 0;
    }
    let bytes = name.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1);
    for i in 0..n {
        slice[i] = bytes[i] as libc::c_char;
    }
}

/// Set interface MTU via `SIOCSIFMTU` (sing-tun `IoctlSetIfreqMTU`).
pub fn set_mtu(if_name: &str, mtu: u32) -> Result<()> {
    with_dgram_socket(libc::AF_INET, |fd| {
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        fill_ifreq_name(&mut ifr, if_name);
        ifr.ifr_ifru.ifru_mtu = mtu as i32;
        let rc = unsafe { libc::ioctl(fd, libc::SIOCSIFMTU, &ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
    .with_context(|| format!("SIOCSIFMTU {if_name} mtu={mtu}"))
}

/// Bring interface up (`SIOCSIFFLAGS` | IFF_UP | IFF_RUNNING).
pub fn set_up(if_name: &str) -> Result<()> {
    with_dgram_socket(libc::AF_INET, |fd| {
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        fill_ifreq_name(&mut ifr, if_name);
        let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = unsafe { ifr.ifr_ifru.ifru_flags } as i16;
        let new_flags = flags | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
        ifr.ifr_ifru.ifru_flags = new_flags as _;
        let rc = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
    .with_context(|| format!("SIOCSIFFLAGS up {if_name}"))
}

/// Add IPv4 address via `SIOCAIFADDR` (point-to-point: addr == dst).
/// Matches sing-tun: both Addr and Dstaddr set to the TUN server address.
pub fn add_addr_v4(if_name: &str, addr: Ipv4Addr, prefix: u8) -> Result<()> {
    let mask = prefix_mask_v4(prefix);
    with_dgram_socket(libc::AF_INET, |fd| {
        let mut req: ifaliasreq = unsafe { mem::zeroed() };
        copy_ifname(&mut req.ifra_name, if_name);
        req.ifra_addr = sockaddr_in(addr);
        // sing-tun uses the same address for Dstaddr on non-/32
        req.ifra_broadaddr = sockaddr_in(addr);
        req.ifra_mask = sockaddr_in(mask);
        let rc = unsafe { libc::ioctl(fd, libc::SIOCAIFADDR as _, &req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
    .with_context(|| format!("SIOCAIFADDR {if_name} {addr}/{prefix}"))
}

/// Add IPv6 address via `SIOCAIFADDR_IN6` with NODAD|SECURED + infinite lifetime.
pub fn add_addr_v6(if_name: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
    let mask = prefix_mask_v6(prefix);
    with_dgram_socket(libc::AF_INET6, |fd| {
        let mut req: in6_aliasreq = unsafe { mem::zeroed() };
        copy_ifname(&mut req.ifra_name, if_name);
        req.ifra_addr = sockaddr_in6(addr);
        req.ifra_prefixmask = sockaddr_in6(mask);
        req.ifra_flags = IN6_IFF_NODAD | IN6_IFF_SECURED;
        req.ifra_lifetime = in6_addrlifetime {
            ia6t_expire: 0.0,
            ia6t_preferred: 0.0,
            ia6t_vltime: ND6_INFINITE_LIFETIME,
            ia6t_pltime: ND6_INFINITE_LIFETIME,
        };
        // /128: set dst to addr+1 (sing-tun)
        if prefix == 128 {
            let next = Ipv6Addr::from(u128::from(addr).wrapping_add(1));
            req.ifra_dstaddr = sockaddr_in6(next);
        }
        let rc = unsafe { libc::ioctl(fd, SIOCAIFADDR_IN6 as _, &req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
    .with_context(|| format!("SIOCAIFADDR_IN6 {if_name} {addr}/{prefix}"))
}

/// Tune SO_RCVBUF on the utun fd (sing-tun `configure()`).
/// utun drops outbound with ENOBUFS once the queued byte budget is exhausted;
/// a larger receive buffer keeps the control socket from starving.
pub fn tune_recv_buffer(tun_fd: RawFd, mtu: u32) -> i32 {
    let _ = mtu;
    let mut applied = UTUN_RCVBUF_DEFAULT;
    let mut size = UTUN_RCVBUF_TARGET;
    while size >= UTUN_RCVBUF_MINIMUM {
        let rc = unsafe {
            libc::setsockopt(
                tun_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        if rc == 0 {
            applied = size;
            break;
        }
        size /= 2;
    }
    // Also bump SO_SNDBUF symmetrically (best-effort).
    let snd = applied;
    let _ = unsafe {
        libc::setsockopt(
            tun_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &snd as *const _ as *const libc::c_void,
            mem::size_of_val(&snd) as libc::socklen_t,
        )
    };
    applied
}

/// Full post-create configuration: MTU, addresses, up, log.
pub fn configure_interface(
    if_name: &str,
    mtu: u32,
    v4: &[(Ipv4Addr, u8)],
    v6: &[(Ipv6Addr, u8)],
) -> Result<()> {
    set_mtu(if_name, mtu)?;
    for &(ip, pl) in v4 {
        add_addr_v4(if_name, ip, pl)?;
    }
    for &(ip, pl) in v6 {
        add_addr_v6(if_name, ip, pl)?;
    }
    set_up(if_name)?;
    info!(
        interface = %if_name,
        mtu,
        v4 = v4.len(),
        v6 = v6.len(),
        "tun: addresses configured via ioctl (SIOCAIFADDR / SIOCAIFADDR_IN6)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// AF_ROUTE auto-route (sing-tun `addRoute` via golang.org/x/net/route)
// ---------------------------------------------------------------------------

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_VERSION: u8 = 5;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_STATIC: i32 = 0x800;
const RTF_BLACKHOLE: i32 = 0x1000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;

#[repr(C)]
struct RtMetrics {
    locks: u32,
    mtu: u32,
    hopcount: u32,
    expire: i32,
    recvpipe: u32,
    sendpipe: u32,
    ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    pksent: u32,
    filler: [u32; 4],
}

#[repr(C)]
struct RtMsghdr {
    msglen: u16,
    version: u8,
    type_: u8,
    index: u16,
    flags: i32,
    addrs: i32,
    pid: i32,
    seq: i32,
    errno: i32,
    use_: i32,
    inits: u32,
    rmx: RtMetrics,
}

fn roundup(n: usize) -> usize {
    // Darwin ROUNDUP for sockaddrs in routing messages
    const ALIGN: usize = 4;
    if n == 0 {
        ALIGN
    } else {
        (n + ALIGN - 1) & !(ALIGN - 1)
    }
}

fn append_sa_v4(buf: &mut Vec<u8>, addr: Ipv4Addr) {
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(addr).to_be(),
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &sa as *const _ as *const u8,
            mem::size_of::<libc::sockaddr_in>(),
        )
    };
    buf.extend_from_slice(bytes);
    let pad = roundup(bytes.len()) - bytes.len();
    buf.extend(std::iter::repeat_n(0u8, pad));
}

fn append_sa_v6(buf: &mut Vec<u8>, addr: Ipv6Addr) {
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_addr = libc::in6_addr {
        s6_addr: addr.octets(),
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &sa as *const _ as *const u8,
            mem::size_of::<libc::sockaddr_in6>(),
        )
    };
    buf.extend_from_slice(bytes);
    let pad = roundup(bytes.len()) - bytes.len();
    buf.extend(std::iter::repeat_n(0u8, pad));
}

fn write_rtmsg(msg: &[u8]) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = unsafe { libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
    let err = io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }
    if n < 0 {
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Add a unicast route via gateway (sing-tun `addRoute`, RTF_UP|STATIC|GATEWAY).
pub fn af_route_add(dest: &str, gateway: &str, v6: bool) -> Result<()> {
    let (dip, pl) = parse_cidr(dest)?;
    let gip: std::net::IpAddr = gateway
        .parse()
        .with_context(|| format!("parse gateway {gateway}"))?;
    let mut body = Vec::with_capacity(256);
    match (&dip, gip) {
        (IpV::V4(d), std::net::IpAddr::V4(g)) if !v6 => {
            append_sa_v4(&mut body, *d);
            append_sa_v4(&mut body, g);
            append_sa_v4(&mut body, prefix_mask_v4(pl));
        }
        (IpV::V6(d), std::net::IpAddr::V6(g)) if v6 => {
            append_sa_v6(&mut body, *d);
            append_sa_v6(&mut body, g);
            append_sa_v6(&mut body, prefix_mask_v6(pl));
        }
        _ => anyhow::bail!("address family mismatch for {dest} via {gateway}"),
    }
    let hdr_len = mem::size_of::<RtMsghdr>();
    let mut hdr: RtMsghdr = unsafe { mem::zeroed() };
    hdr.msglen = (hdr_len + body.len()) as u16;
    hdr.version = RTM_VERSION;
    hdr.type_ = RTM_ADD;
    hdr.flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
    hdr.addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    hdr.seq = 1;
    let mut msg = Vec::with_capacity(hdr.msglen as usize);
    let hdr_bytes =
        unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, hdr_len) };
    msg.extend_from_slice(hdr_bytes);
    msg.extend_from_slice(&body);
    write_rtmsg(&msg).with_context(|| format!("AF_ROUTE RTM_ADD {dest} via {gateway}"))
}

/// Add a blackhole default (strict-route missing family).
pub fn af_route_blackhole(v6: bool) -> Result<()> {
    let mut body = Vec::with_capacity(128);
    if v6 {
        append_sa_v6(&mut body, Ipv6Addr::UNSPECIFIED);
        append_sa_v6(&mut body, Ipv6Addr::UNSPECIFIED);
        append_sa_v6(&mut body, prefix_mask_v6(0));
    } else {
        append_sa_v4(&mut body, Ipv4Addr::UNSPECIFIED);
        append_sa_v4(&mut body, Ipv4Addr::UNSPECIFIED);
        append_sa_v4(&mut body, prefix_mask_v4(0));
    }
    let hdr_len = mem::size_of::<RtMsghdr>();
    let mut hdr: RtMsghdr = unsafe { mem::zeroed() };
    hdr.msglen = (hdr_len + body.len()) as u16;
    hdr.version = RTM_VERSION;
    hdr.type_ = RTM_ADD;
    hdr.flags = RTF_UP | RTF_STATIC | RTF_BLACKHOLE;
    hdr.addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    hdr.seq = 1;
    let mut msg = Vec::with_capacity(hdr.msglen as usize);
    let hdr_bytes =
        unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, hdr_len) };
    msg.extend_from_slice(hdr_bytes);
    msg.extend_from_slice(&body);
    write_rtmsg(&msg).context("AF_ROUTE RTM_ADD blackhole")
}

/// Delete a route previously added (RTM_DELETE).
pub fn af_route_del(dest: &str, v6: bool) -> Result<()> {
    let (dip, pl) = parse_cidr(dest)?;
    let mut body = Vec::with_capacity(128);
    match dip {
        IpV::V4(d) if !v6 => {
            append_sa_v4(&mut body, d);
            append_sa_v4(&mut body, prefix_mask_v4(pl));
        }
        IpV::V6(d) if v6 => {
            append_sa_v6(&mut body, d);
            append_sa_v6(&mut body, prefix_mask_v6(pl));
        }
        _ => anyhow::bail!("address family mismatch for delete {dest}"),
    }
    let hdr_len = mem::size_of::<RtMsghdr>();
    let mut hdr: RtMsghdr = unsafe { mem::zeroed() };
    hdr.msglen = (hdr_len + body.len()) as u16;
    hdr.version = RTM_VERSION;
    hdr.type_ = RTM_DELETE;
    hdr.flags = RTF_UP | RTF_STATIC;
    hdr.addrs = RTA_DST | RTA_NETMASK;
    hdr.seq = 1;
    let mut msg = Vec::with_capacity(hdr.msglen as usize);
    let hdr_bytes =
        unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, hdr_len) };
    msg.extend_from_slice(hdr_bytes);
    msg.extend_from_slice(&body);
    match write_rtmsg(&msg) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("AF_ROUTE RTM_DELETE {dest}")),
    }
}

enum IpV {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

fn parse_cidr(s: &str) -> Result<(IpV, u8)> {
    let (ip_s, pl_s) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR required: {s}"))?;
    let pl: u8 = pl_s.parse().context("prefix")?;
    if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
        Ok((IpV::V4(ip), pl.min(32)))
    } else if let Ok(ip) = ip_s.parse::<Ipv6Addr>() {
        Ok((IpV::V6(ip), pl.min(128)))
    } else {
        anyhow::bail!("bad address in {s}")
    }
}
