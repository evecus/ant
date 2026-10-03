//! Mixed inbound: HTTP CONNECT + SOCKS5 (TCP CONNECT + UDP ASSOCIATE).
//! Listens dual-stack: 0.0.0.0 and [::].

use crate::outbound::{relay, OutboundManager, UdpSession};
use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use super::target;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub async fn run_mixed(
    port: u16,
    bind_address: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let mut handles = Vec::new();
    for bind in crate::app::sockopt::listen_addrs(&bind_address, port) {
        match crate::app::sockopt::bind_tcp_listener(bind) {
            Ok((listener, bind)) => {
                tracing::info!("mixed (HTTP+SOCKS5 TCP/UDP) listening on {}", bind);
                let router = router.clone();
                let outbounds = outbounds.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
                            Err(e) => {
                                tracing::warn!("mixed accept: {e}");
                                continue;
                            }
                        };
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, peer, router, outbounds).await {
                                tracing::debug!("mixed client {}: {}", peer, e);
                            }
                        });
                    }
                }));
            }
            Err(e) => tracing::warn!("mixed bind {}: {e}", bind),
        }
    }
    if handles.is_empty() {
        anyhow::bail!("mixed: no bind succeeded");
    }
    futures::future::join_all(handles).await;
    Ok(())
}

async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut peek = [0u8; 1];
    let n = stream.peek(&mut peek).await?;
    if n == 0 {
        return Ok(());
    }
    if peek[0] == 0x05 {
        handle_socks5(stream, peer, router, outbounds).await
    } else {
        handle_http(stream, peer, router, outbounds).await
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
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

            let mut sniffed = sniffer::SniffResult::default();
            if dest_ip.is_none() {
                // Protocol-provided hostname is authoritative.
                sniffed.domain = Some(host.clone());
            } else if router.sniff() {
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
                    sniffed = sniffer::sniff_tcp_ex(&tmp[..n], true, false);
                }
            }

            let dest_addr = resolve_or_ip(&host, port, dest_ip).await?;
            let decided = target::decide(&router, dest_addr, sniffed).await;
            tracing::debug!("socks5 TCP {} → {:?} via {:?}", host, decided.host, decided.outbound);

            if decided.outbound == Outbound::Block {
                tracing::debug!("socks5 TCP block {}", host);
                return Ok(());
            }

            let _conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
                peer,
                dest: decided.addr,
                dest_host: decided.host.clone(),
                inbound: "socks5",
                rule: decided.rule.clone(),
                outbound: decided.outbound.label(),
            });
            let dialer = outbounds.select(decided.outbound).context("no dialer")?;
            let remote = dialer
                .dial_tcp(decided.addr, decided.host.as_deref())
                .await
                .context("dial")?;
            let local: crate::outbound::BoxedStream = Box::new(stream);
            relay(local, remote).await?;
            Ok(())
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
        let sniffed = if dst_ip.is_none() {
            sniffer::SniffResult { domain: Some(dst_host.clone()), ..Default::default() }
        } else if router.sniff() {
            sniffer::sniff_udp_ex(&payload, true, false)
        } else {
            sniffer::SniffResult::default()
        };
        let decided = target::decide(&router, dest, sniffed).await;
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

        // CONNECT hostname is authoritative (source: none → overrides fake-ip);
        // sniffing may refine it to the actual HTTP Host / TLS SNI.
        let mut sniffed =
            sniffer::SniffResult { domain: Some(host.clone()), ..Default::default() };
        let dest_addr = resolve_or_ip(&host, port, None).await?;
        let mut peek_buf = vec![0u8; 2048];
        let ob = router.match_outbound(sniffed.domain.as_deref(), Some(dest_addr.ip()));
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
                let s = sniffer::sniff_tcp_ex(&peek_buf[..n], true, false);
                if s.domain.is_some() {
                    sniffed = s;
                }
            }
        }
        let decided = target::decide(&router, dest_addr, sniffed).await;
        if decided.outbound == Outbound::Block {
            return Ok(());
        }

        tracing::debug!("http CONNECT {} → {:?} via {:?}", target, decided.host, decided.outbound);
        let _conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
            peer,
            dest: decided.addr,
            dest_host: decided.host.clone(),
            inbound: "http",
            rule: decided.rule.clone(),
            outbound: decided.outbound.label(),
        });
        let dialer = outbounds.select(decided.outbound).context("no dialer")?;
        let remote = dialer
            .dial_tcp(decided.addr, decided.host.as_deref())
            .await
            .context("dial")?;
        let local: crate::outbound::BoxedStream = Box::new(stream);
        relay(local, remote).await?;
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
        let decided = target::decide(
            &router,
            dest_addr,
            sniffer::SniffResult { domain: Some(h.clone()), ..Default::default() },
        )
        .await;
        if decided.outbound == Outbound::Block {
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
        let _conn = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
            peer,
            dest: decided.addr,
            dest_host: decided.host.clone(),
            inbound: "http",
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
        relay(local, remote).await?;
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
