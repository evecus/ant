//! Inbounds for proxy clients:
//! - **mixed**: auto-detect HTTP CONNECT + SOCKS4/4a/5 (TCP + UDP ASSOCIATE)
//! - **http**: HTTP CONNECT / absolute-URI only (like clash-rs `proxy/http/inbound`)
//! - **socks**: SOCKS4 / SOCKS4a / SOCKS5 only (like clash-rs `proxy/socks/inbound`)
//!
//! Listen addresses follow `bind-address` + top-level `ipv6`
//! (`0.0.0.0` / `127.0.0.1`; dual-stack when `ipv6: true`).

use crate::outbound::{relay, OutboundManager, UdpSession};
use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use super::target;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Protocol mode for a TCP client handler.
#[derive(Clone, Copy)]
enum Mode {
    /// Peek first byte: 0x05 → SOCKS5, 0x04 → SOCKS4, else HTTP.
    Mixed,
    /// Force HTTP CONNECT / absolute-form proxy requests only.
    Http,
    /// Force SOCKS4 / SOCKS4a / SOCKS5 only.
    Socks,
}

pub async fn run_mixed(
    port: u16,
    bind_address: String,
    ipv6: bool,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    run_listener(
        "mixed",
        "mixed (HTTP+SOCKS4/4a/5, TCP/UDP)",
        port,
        bind_address,
        ipv6,
        router,
        outbounds,
        Mode::Mixed,
    )
    .await
}

/// Dedicated HTTP inbound (HTTP CONNECT + absolute-URI GET/POST/…).
/// Mirrors clash-rs `HttpInbound`: TCP only, no SOCKS framing.
pub async fn run_http(
    port: u16,
    bind_address: String,
    ipv6: bool,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    run_listener(
        "http",
        "http (CONNECT + absolute-URI)",
        port,
        bind_address,
        ipv6,
        router,
        outbounds,
        Mode::Http,
    )
    .await
}

/// Dedicated SOCKS inbound (SOCKS4 / SOCKS4a / SOCKS5 TCP + SOCKS5 UDP ASSOCIATE).
/// Mirrors clash-rs `SocksInbound`.
pub async fn run_socks(
    port: u16,
    bind_address: String,
    ipv6: bool,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    run_listener(
        "socks",
        "socks (SOCKS4/4a/5, TCP/UDP)",
        port,
        bind_address,
        ipv6,
        router,
        outbounds,
        Mode::Socks,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_listener(
    name: &'static str,
    log_label: &'static str,
    port: u16,
    bind_address: String,
    ipv6: bool,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    mode: Mode,
) -> Result<()> {
    let mut handles = Vec::new();
    for bind in crate::app::sockopt::listen_addrs(&bind_address, port, ipv6) {
        match crate::app::sockopt::bind_tcp_listener(bind) {
            Ok((listener, bind)) => {
                tracing::info!("{log_label} listening on {bind}");
                let router = router.clone();
                let outbounds = outbounds.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
                            Err(e) => {
                                tracing::warn!("{name} accept: {e}");
                                continue;
                            }
                        };
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_client(mode, stream, peer, router, outbounds).await
                            {
                                tracing::debug!("{name} client {peer}: {e}");
                            }
                        });
                    }
                }));
            }
            Err(e) => tracing::warn!("{name} bind {bind}: {e}"),
        }
    }
    if handles.is_empty() {
        anyhow::bail!("{name}: no bind succeeded");
    }
    futures::future::join_all(handles).await;
    Ok(())
}

async fn handle_client(
    mode: Mode,
    stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    // Connection-tracker `inbound` label reflects the *listener*, not the wire
    // protocol: mixed-port → "mixed"; http-port → "http"; socks-port → "socks5"/"socks4".
    match mode {
        Mode::Http => handle_http(stream, peer, router, outbounds, "http").await,
        Mode::Socks => {
            let mut peek = [0u8; 1];
            let n = stream.peek(&mut peek).await?;
            if n == 0 {
                return Ok(());
            }
            if peek[0] == 0x05 {
                handle_socks5(stream, peer, router, outbounds, "socks5").await
            } else if peek[0] == 0x04 {
                handle_socks4(stream, peer, router, outbounds, "socks4").await
            } else {
                bail!("socks inbound: expected SOCKS4/5, got 0x{:02x}", peek[0]);
            }
        }
        Mode::Mixed => {
            let mut peek = [0u8; 1];
            let n = stream.peek(&mut peek).await?;
            if n == 0 {
                return Ok(());
            }
            // Always tag as "mixed" so the connections page shows the listener name.
            if peek[0] == 0x05 {
                handle_socks5(stream, peer, router, outbounds, "mixed").await
            } else if peek[0] == 0x04 {
                handle_socks4(stream, peer, router, outbounds, "mixed").await
            } else {
                handle_http(stream, peer, router, outbounds, "mixed").await
            }
        }
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    inbound: &'static str,
) -> Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        bail!("not socks5");
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("bad socks ver");
    }
    let cmd = hdr[1];
    let atyp = hdr[3];
    let (host, port, dest_ip) = read_socks_addr(&mut stream, atyp).await?;

    match cmd {
        0x01 => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            serve_connect(stream, peer, router, outbounds, host, port, dest_ip, inbound).await
        }
        0x03 => {
            let bind = if peer.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let udp = Arc::new(UdpSocket::bind(bind).await?);
            let relay_addr = udp.local_addr()?;
            let port_be = relay_addr.port().to_be_bytes();
            let resp = [
                0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, port_be[0], port_be[1],
            ];
            stream.write_all(&resp).await?;
            tracing::debug!("socks5 UDP ASSOCIATE for {} relay={}", peer, relay_addr);

            let router = router.clone();
            let outbounds = outbounds.clone();
            let udp2 = udp.clone();
            let udp_task =
                tokio::spawn(async move { socks5_udp_relay(udp2, router, outbounds).await });
            let mut sink = [0u8; 16];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            udp_task.abort();
            Ok(())
        }
        _ => {
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("socks5 cmd {} not supported", cmd);
        }
    }
}

/// Shared tail of a SOCKS CONNECT (v4 / v4a / v5) once the success reply has
/// been sent: sniff, route, dial and relay.
#[allow(clippy::too_many_arguments)]
async fn serve_connect(
    stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    host: String,
    port: u16,
    dest_ip: Option<IpAddr>,
    label: &'static str,
) -> Result<()> {
    let mut domain = if dest_ip.is_none() {
        Some(host.clone())
    } else {
        None
    };
    if domain.is_none() && router.sniff() {
        let mut tmp = vec![0u8; 2048];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            stream.peek(&mut tmp),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
        if n > 0 {
            if let Some(d) = sniffer::sniff_tcp_ex(&tmp[..n], true, false).domain {
                domain = Some(d);
            }
        }
    }

    let dest_addr = resolve_or_ip(&host, port, dest_ip).await?;
    let decided = target::decide(&router, dest_addr, domain).await;
    tracing::debug!("{label} TCP {} → {:?} via {:?}", host, decided.host, decided.outbound);

    if decided.outbound == Outbound::Block {
        tracing::debug!("{label} TCP block {}", host);
        return Ok(());
    }

    let conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
        peer,
        dest: decided.addr,
        dest_host: decided.host.clone(),
        network: "tcp",
        inbound: label,
        rule: decided.rule.clone(),
        outbound: decided.outbound.label(),
    });
    let dialer = outbounds.select(decided.outbound).context("no dialer")?;
    let remote = dialer
        .dial_tcp(decided.addr, decided.host.as_deref())
        .await
        .context("dial")?;
    let local: crate::outbound::BoxedStream = Box::new(stream);
    conn.while_alive(relay(local, remote)).await?;
    Ok(())
}

// ── SOCKS4 / SOCKS4a ─────────────────────────────────────────────────────────

const S4_VER: u8 = 0x04;
const S4_CMD_CONNECT: u8 = 0x01;
const S4_GRANTED: u8 = 0x5A;
const S4_REJECTED: u8 = 0x5B;
/// Upper bound for the NUL-terminated USERID / hostname fields.
const S4_MAX_FIELD: usize = 255;

#[derive(Debug, PartialEq, Eq)]
struct Socks4Req {
    cmd: u8,
    port: u16,
    ip: Ipv4Addr,
    /// SOCKS4a hostname (DSTIP = 0.0.0.x, x != 0).
    domain: Option<String>,
}

/// Read a NUL-terminated field byte by byte (the stream is unbuffered and the
/// client payload follows immediately, so we must not over-read).
async fn read_cstr<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = r.read_u8().await?;
        if b == 0 {
            return Ok(out);
        }
        if out.len() >= S4_MAX_FIELD {
            bail!("socks4: field too long");
        }
        out.push(b);
    }
}

/// `VN CD DSTPORT(2) DSTIP(4) USERID 0 [HOSTNAME 0]`. USERID is read and
/// discarded (ant does no SOCKS4 identd / user auth).
async fn read_socks4_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Socks4Req> {
    let mut hdr = [0u8; 8];
    r.read_exact(&mut hdr).await?;
    if hdr[0] != S4_VER {
        bail!("not socks4");
    }
    let port = u16::from_be_bytes([hdr[2], hdr[3]]);
    let ip = Ipv4Addr::new(hdr[4], hdr[5], hdr[6], hdr[7]);
    let _userid = read_cstr(r).await?;
    let o = ip.octets();
    let domain = if o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] != 0 {
        let d = read_cstr(r).await?;
        if d.is_empty() {
            bail!("socks4a: empty hostname");
        }
        Some(String::from_utf8(d).context("socks4a: hostname is not utf-8")?)
    } else {
        None
    };
    Ok(Socks4Req {
        cmd: hdr[1],
        port,
        ip,
        domain,
    })
}

async fn handle_socks4(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    inbound: &'static str,
) -> Result<()> {
    let req = read_socks4_request(&mut stream).await?;
    if req.cmd != S4_CMD_CONNECT {
        // BIND (0x02) and anything else is unsupported.
        stream.write_all(&[0, S4_REJECTED, 0, 0, 0, 0, 0, 0]).await?;
        bail!("socks4 cmd {} not supported", req.cmd);
    }
    // Same as the SOCKS5 path: grant first, routing / dial happens after.
    stream.write_all(&[0, S4_GRANTED, 0, 0, 0, 0, 0, 0]).await?;
    let (host, dest_ip) = match req.domain {
        Some(d) => (d, None),
        None => (req.ip.to_string(), Some(IpAddr::V4(req.ip))),
    };
    serve_connect(stream, peer, router, outbounds, host, req.port, dest_ip, inbound).await
}

async fn socks5_udp_relay(
    udp: Arc<UdpSocket>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let sessions: Arc<Mutex<HashMap<SocketAddr, Arc<dyn UdpSession>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client) = udp.recv_from(&mut buf).await?;
        if n < 4 || buf[2] != 0 {
            continue;
        }
        let atyp = buf[3];
        let (dst_host, dst_port, dst_ip, hdr_len) = match atyp {
            0x01 if n >= 10 => {
                let ip = IpAddr::from([buf[4], buf[5], buf[6], buf[7]]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                (ip.to_string(), port, Some(ip), 10usize)
            }
            0x03 if n >= 7 => {
                let len = buf[4] as usize;
                if n < 5 + len + 2 {
                    continue;
                }
                let host = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
                (host, port, None, 5 + len + 2)
            }
            0x04 if n >= 22 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[4..20]);
                let ip = IpAddr::from(a);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                (ip.to_string(), port, Some(ip), 22usize)
            }
            _ => continue,
        };
        let payload = buf[hdr_len..n].to_vec();
        let dest = match resolve_or_ip(&dst_host, dst_port, dst_ip).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        let domain_owned: Option<String> = if dst_ip.is_none() {
            Some(dst_host.clone())
        } else if router.sniff() {
            sniffer::sniff_udp_ex(&payload, true, false).domain
        } else {
            None
        };
        let decided = target::decide(&router, dest, domain_owned).await;
        if decided.outbound == Outbound::Block {
            continue;
        }
        let dest = decided.addr;
        let domain = decided.host.as_deref();
        let ob = decided.outbound;

        let sess = {
            let mut map = sessions.lock().await;
            if let Some(s) = map.get(&client) {
                s.clone()
            } else {
                let Some(dialer) = outbounds.select(ob) else {
                    continue;
                };
                let s = match dialer.dial_udp(Some(client)).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("socks5 udp dial: {e}");
                        continue;
                    }
                };
                let s: Arc<dyn UdpSession> = Arc::from(s);
                map.insert(client, s.clone());
                let udp2 = udp.clone();
                let s2 = s.clone();
                let client2 = client;
                let sessions2 = sessions.clone();
                tokio::spawn(async move {
                    while let Ok(Ok((data, src))) = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        s2.recv_from(),
                    )
                    .await
                    {
                        if send_socks5_udp_reply(&udp2, client2, src, &data)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    sessions2.lock().await.remove(&client2);
                });
                s
            }
        };
        let _ = sess.send_to(&payload, dest, domain).await;
    }
}

async fn send_socks5_udp_reply(
    udp: &UdpSocket,
    client: SocketAddr,
    src: SocketAddr,
    data: &[u8],
) -> Result<()> {
    let mut pkt = Vec::with_capacity(10 + data.len());
    pkt.extend_from_slice(&[0, 0, 0]);
    match src {
        SocketAddr::V4(v4) => {
            pkt.push(0x01);
            pkt.extend_from_slice(&v4.ip().octets());
            pkt.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            pkt.push(0x04);
            pkt.extend_from_slice(&v6.ip().octets());
            pkt.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    pkt.extend_from_slice(data);
    udp.send_to(&pkt, client).await?;
    Ok(())
}

async fn read_socks_addr(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<(String, u16, Option<IpAddr>)> {
    match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let ip = IpAddr::from(ip);
            Ok((ip.to_string(), port, Some(ip)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            Ok((String::from_utf8(name)?, port, None))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let ip = IpAddr::from(ip);
            Ok((ip.to_string(), port, Some(ip)))
        }
        _ => bail!("bad atyp"),
    }
}

async fn handle_http(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    inbound: &'static str,
) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("http header too large");
        }
    }

    let header = String::from_utf8_lossy(&buf);
    let first_line = header.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target)?;

        let mut domain = Some(host.clone());
        let dest_addr = resolve_or_ip(&host, port, None).await?;
        let mut peek_buf = vec![0u8; 2048];
        let ob = router.match_outbound(domain.as_deref(), Some(dest_addr.ip()));
        if ob == Outbound::Block {
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        if router.sniff() {
            if let Ok(Ok(n)) = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                stream.peek(&mut peek_buf),
            )
            .await
            {
                if let Some(d) = sniffer::sniff_tcp_ex(&peek_buf[..n], true, false).domain {
                    domain = Some(d);
                }
            }
        }
        let decided = target::decide(&router, dest_addr, domain).await;
        if decided.outbound == Outbound::Block {
            return Ok(());
        }

        tracing::debug!("{inbound} CONNECT {} → {:?} via {:?}", target, decided.host, decided.outbound);
        let conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
            peer,
            dest: decided.addr,
            dest_host: decided.host.clone(),
            network: "tcp",
            inbound,
            rule: decided.rule.clone(),
            outbound: decided.outbound.label(),
        });
        let dialer = outbounds.select(decided.outbound).context("no dialer")?;
        let remote = dialer
            .dial_tcp(decided.addr, decided.host.as_deref())
            .await
            .context("dial")?;
        let local: crate::outbound::BoxedStream = Box::new(stream);
        conn.while_alive(relay(local, remote)).await?;
        Ok(())
    } else {
        let url = target.to_string();
        let host = header
            .lines()
            .find_map(|l| {
                l.strip_prefix("Host:")
                    .or_else(|| l.strip_prefix("host:"))
                    .map(|s| s.trim().to_string())
            })
            .or_else(|| {
                url.strip_prefix("http://")
                    .and_then(|r| r.split('/').next())
                    .map(|s| s.to_string())
            })
            .context("no host")?;
        let (h, port) = if let Some((a, b)) = host.rsplit_once(':') {
            (a.to_string(), b.parse().unwrap_or(80))
        } else {
            (host.clone(), 80)
        };

        let dest_addr = resolve_or_ip(&h, port, None).await?;
        let decided = target::decide(&router, dest_addr, Some(h.clone())).await;
        if decided.outbound == Outbound::Block {
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
        let conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
            peer,
            dest: decided.addr,
            dest_host: decided.host.clone(),
            network: "tcp",
            inbound,
            rule: decided.rule.clone(),
            outbound: decided.outbound.label(),
        });
        let dialer = outbounds.select(decided.outbound).context("no dialer")?;
        let mut remote = dialer.dial_tcp(decided.addr, decided.host.as_deref()).await?;

        let path = if let Some(rest) = url.strip_prefix("http://") {
            rest.find('/')
                .map(|i| &rest[i..])
                .unwrap_or("/")
                .to_string()
        } else {
            url
        };
        let mut new_req = format!("{} {} HTTP/1.1\r\n", method, path);
        for line in header.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if line.to_lowercase().starts_with("proxy-connection") {
                continue;
            }
            new_req.push_str(line);
            new_req.push_str("\r\n");
        }
        new_req.push_str("\r\n");
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body = &buf[pos + 4..];
            remote.write_all(new_req.as_bytes()).await?;
            if !body.is_empty() {
                remote.write_all(body).await?;
            }
        } else {
            remote.write_all(new_req.as_bytes()).await?;
        }

        let local: crate::outbound::BoxedStream = Box::new(stream);
        conn.while_alive(relay(local, remote)).await?;
        Ok(())
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        Ok((
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse()?,
        ))
    } else {
        Ok((s.to_string(), 443))
    }
}

async fn resolve_or_ip(host: &str, port: u16, known_ip: Option<IpAddr>) -> Result<SocketAddr> {
    if let Some(ip) = known_ip {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("resolve failed for {}", host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks4_request_ip() {
        let mut b: &[u8] = &[4, 1, 0x01, 0xBB, 1, 2, 3, 4, b'u', 0, b'X'];
        let r = read_socks4_request(&mut b).await.unwrap();
        assert_eq!(
            r,
            Socks4Req {
                cmd: 1,
                port: 443,
                ip: Ipv4Addr::new(1, 2, 3, 4),
                domain: None
            }
        );
        // payload byte after the request must not be consumed
        assert_eq!(b, b"X");
    }

    #[tokio::test]
    async fn socks4a_request_domain() {
        let mut b: &[u8] = &[4, 1, 0, 80, 0, 0, 0, 1, 0, b'a', b'.', b'b', 0, b'X'];
        let r = read_socks4_request(&mut b).await.unwrap();
        assert_eq!(r.domain.as_deref(), Some("a.b"));
        assert_eq!(r.port, 80);
        assert_eq!(b, b"X");
    }

    #[tokio::test]
    async fn socks4_request_invalid() {
        // wrong version
        let mut b: &[u8] = &[5, 1, 0, 80, 1, 2, 3, 4, 0];
        assert!(read_socks4_request(&mut b).await.is_err());
        // 0.0.0.0 is NOT the 4a marker → plain IP, no hostname read
        let mut b: &[u8] = &[4, 1, 0, 80, 0, 0, 0, 0, 0];
        assert_eq!(read_socks4_request(&mut b).await.unwrap().domain, None);
        // 4a with empty hostname
        let mut b: &[u8] = &[4, 1, 0, 80, 0, 0, 0, 1, 0, 0];
        assert!(read_socks4_request(&mut b).await.is_err());
        // unterminated / oversized USERID
        let mut v = vec![4, 1, 0, 80, 1, 2, 3, 4];
        v.resize(v.len() + 300, b'a');
        let mut b: &[u8] = &v;
        assert!(read_socks4_request(&mut b).await.is_err());
        // truncated
        let mut b: &[u8] = &[4, 1, 0, 80, 1, 2, 3, 4, b'u'];
        assert!(read_socks4_request(&mut b).await.is_err());
    }
}
