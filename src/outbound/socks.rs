use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::{ProxyConfig, SocksVersion};
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const AUTH_VER: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

// SOCKS4 / 4a
const V4_VER: u8 = 0x04;
const V4_CMD_CONNECT: u8 = 0x01;
const V4_REP_GRANTED: u8 = 0x5A;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SocksOutbound {
    server: String,
    port: u16,
    version: SocksVersion,
    /// SOCKS5 `(username, password)`; `None` → only NO_AUTH is offered.
    auth: Option<(String, String)>,
    /// SOCKS4 / 4a USERID (empty when no username is configured).
    userid: String,
}

impl SocksOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let version = cfg.socks_version()?;
        let username = cfg.username.as_deref().filter(|u| !u.is_empty());
        let (auth, userid) = match (version, username) {
            (SocksVersion::V5, Some(u)) => {
                let p = cfg.password.clone().unwrap_or_default();
                ensure!(
                    u.len() <= 255 && p.len() <= 255,
                    "socks5 node `{}`: username/password longer than 255 bytes",
                    cfg.name
                );
                (Some((u.to_string(), p)), String::new())
            }
            (SocksVersion::V5, None) => (None, String::new()),
            (_, u) => {
                let u = u.unwrap_or("");
                ensure!(
                    !u.as_bytes().contains(&0),
                    "socks4 node `{}`: username must not contain NUL",
                    cfg.name
                );
                (None, u.to_string())
            }
        };
        Ok(Self {
            server: cfg.server.clone(),
            port: cfg.port,
            version,
            auth,
            userid,
        })
    }

    async fn resolve_server(&self) -> Result<SocketAddr> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, self.port));
        }
        // 与 vless 一致：优先 bootstrap DNS，避免系统 DNS 指回 ant 自身的回环。
        crate::dns::resolve_host_via_bootstrap(&self.server, self.port).await
    }

    /// Connect to the upstream server over a marked / interface-bound socket.
    async fn connect_proxy(&self) -> Result<(TcpStream, SocketAddr)> {
        let proxy = self.resolve_server().await?;
        let s = crate::app::sockopt::connect_tcp(proxy)
            .await
            .with_context(|| format!("socks connect {proxy}"))?;
        let _ = s.set_nodelay(true);
        Ok((s, proxy))
    }

    /// SOCKS5: connect, then finish the method negotiation + optional
    /// username/password sub-negotiation.
    async fn connect_and_auth(&self) -> Result<(TcpStream, SocketAddr)> {
        let (mut s, proxy) = self.connect_proxy().await?;

        if self.auth.is_some() {
            s.write_all(&[VER, 2, METHOD_NO_AUTH, METHOD_USER_PASS]).await?;
        } else {
            s.write_all(&[VER, 1, METHOD_NO_AUTH]).await?;
        }
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        ensure!(resp[0] == VER, "socks5: bad server version 0x{:02x}", resp[0]);
        match resp[1] {
            METHOD_NO_AUTH => {}
            METHOD_USER_PASS => {
                let Some((u, p)) = &self.auth else {
                    bail!("socks5: server demands username/password but none configured");
                };
                let mut buf = Vec::with_capacity(3 + u.len() + p.len());
                buf.push(AUTH_VER);
                buf.push(u.len() as u8);
                buf.extend_from_slice(u.as_bytes());
                buf.push(p.len() as u8);
                buf.extend_from_slice(p.as_bytes());
                s.write_all(&buf).await?;
                let mut ar = [0u8; 2];
                s.read_exact(&mut ar).await?;
                ensure!(ar[1] == 0x00, "socks5: authentication failed");
            }
            METHOD_NONE_ACCEPTABLE => bail!("socks5: no acceptable auth method"),
            m => bail!("socks5: unsupported auth method 0x{m:02x}"),
        }
        Ok((s, proxy))
    }

    /// Send a request and return the BND address of the reply.
    async fn request(s: &mut TcpStream, cmd: u8, dst: &Dst<'_>) -> Result<Bnd> {
        let mut req = Vec::with_capacity(22);
        req.extend_from_slice(&[VER, cmd, 0x00]);
        dst.encode(&mut req)?;
        s.write_all(&req).await?;

        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await?;
        ensure!(hdr[0] == VER, "socks5: bad reply version 0x{:02x}", hdr[0]);
        ensure!(hdr[1] == 0x00, "socks5: server refused, REP=0x{:02x}", hdr[1]);
        match hdr[3] {
            ATYP_V4 => {
                let mut b = [0u8; 6];
                s.read_exact(&mut b).await?;
                Ok(Bnd::Addr(SocketAddr::new(
                    Ipv4Addr::new(b[0], b[1], b[2], b[3]).into(),
                    u16::from_be_bytes([b[4], b[5]]),
                )))
            }
            ATYP_V6 => {
                let mut b = [0u8; 18];
                s.read_exact(&mut b).await?;
                let ip: [u8; 16] = b[..16].try_into().unwrap();
                Ok(Bnd::Addr(SocketAddr::new(
                    Ipv6Addr::from(ip).into(),
                    u16::from_be_bytes([b[16], b[17]]),
                )))
            }
            ATYP_DOMAIN => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                let mut b = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut b).await?;
                let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
                Ok(Bnd::Domain(port))
            }
            a => bail!("socks5: unknown BND.ATYP 0x{a:02x}"),
        }
    }
}

enum Dst<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

enum Bnd {
    Addr(SocketAddr),
    /// Domain BND (rare); only the port is usable.
    Domain(u16),
}

impl Dst<'_> {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Dst::Ip(a) => {
                match a.ip() {
                    IpAddr::V4(ip) => {
                        out.push(ATYP_V4);
                        out.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        out.push(ATYP_V6);
                        out.extend_from_slice(&ip.octets());
                    }
                }
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Dst::Domain(h, p) => {
                ensure!(!h.is_empty() && h.len() <= 255, "socks5: bad domain length");
                out.push(ATYP_DOMAIN);
                out.push(h.len() as u8);
                out.extend_from_slice(h.as_bytes());
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
        Ok(())
    }
}

fn pick_dst<'a>(addr: SocketAddr, host_hint: Option<&'a str>) -> Dst<'a> {
    match host_hint {
        Some(h) if !h.is_empty() && h.parse::<IpAddr>().is_err() => Dst::Domain(h, addr.port()),
        _ => Dst::Ip(addr),
    }
}

#[async_trait]
impl OutboundDialer for SocksOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let fut = async {
            if self.version == SocksVersion::V5 {
                let dst = pick_dst(addr, host_hint);
                let (mut s, _) = self.connect_and_auth().await?;
                Self::request(&mut s, CMD_CONNECT, &dst).await?;
                Ok::<_, anyhow::Error>(s)
            } else {
                // Resolve before dialing so a DNS failure doesn't leave a
                // half-open connection to the proxy.
                let dst = pick_dst4(self.version, addr, host_hint).await?;
                let (mut s, _) = self.connect_proxy().await?;
                socks4_handshake(&mut s, &dst, &self.userid).await?;
                Ok(s)
            }
        };
        let s = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
            .await
            .context("socks handshake timeout")??;
        Ok(Box::new(s))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        ensure!(
            self.version == SocksVersion::V5,
            "socks4/4a does not support UDP"
        );
        let fut = async {
            let (mut ctrl, proxy) = self.connect_and_auth().await?;
            // DST = 0.0.0.0:0 (we don't know our source port in advance).
            let any = Dst::Ip(SocketAddr::from(([0, 0, 0, 0], 0)));
            let bnd = Self::request(&mut ctrl, CMD_UDP_ASSOCIATE, &any).await?;
            // RFC 1928 §6: unspecified / missing BND.ADDR → use the server IP
            // the control connection went to.
            let relay = match bnd {
                Bnd::Addr(a) if !a.ip().is_unspecified() => a,
                Bnd::Addr(a) => SocketAddr::new(proxy.ip(), a.port()),
                Bnd::Domain(p) => SocketAddr::new(proxy.ip(), p),
            };
            let local: SocketAddr = if relay.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            // Marked / interface-bound like every other dialer socket.
            let udp = crate::app::sockopt::bind_udp(local)
                .await
                .context("socks5 udp bind")?;
            Ok::<_, anyhow::Error>((ctrl, udp, relay))
        };
        let (ctrl, udp, relay) = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
            .await
            .context("socks5 udp associate timeout")??;
        Ok(Box::new(SocksUdpSession {
            udp,
            relay,
            _ctrl: Mutex::new(ctrl),
        }))
    }
}

struct SocksUdpSession {
    udp: UdpSocket,
    relay: SocketAddr,
    /// RFC 1928: the UDP association lives only as long as this TCP
    /// connection; many servers drop the relay as soon as it closes.
    _ctrl: Mutex<TcpStream>,
}

#[async_trait]
impl UdpSession for SocksUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let mut pkt = Vec::with_capacity(data.len() + 22);
        pkt.extend_from_slice(&[0, 0, 0]); // RSV(2) FRAG(1)
        pick_dst(dst, dst_host).encode(&mut pkt)?;
        pkt.extend_from_slice(data);
        self.udp.send_to(&pkt, self.relay).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = self.udp.recv_from(&mut buf).await?;
            // Only accept datagrams from the relay (compare IPs; some servers
            // reply from a different port).
            if from.ip() != self.relay.ip() {
                continue;
            }
            if let Some((src, off)) = parse_udp_header(&buf[..n]) {
                return Ok((buf[off..n].to_vec(), src));
            }
        }
    }
}

/// Parse `RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT`; returns `(source, payload
/// offset)`. Fragmented datagrams (FRAG != 0) are dropped. A domain source is
/// reported as `0.0.0.0:port`.
fn parse_udp_header(b: &[u8]) -> Option<(SocketAddr, usize)> {
    if b.len() < 4 || b[2] != 0 {
        return None;
    }
    match b[3] {
        ATYP_V4 if b.len() >= 10 => {
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Some((SocketAddr::new(ip.into(), u16::from_be_bytes([b[8], b[9]])), 10))
        }
        ATYP_V6 if b.len() >= 22 => {
            let ip: [u8; 16] = b[4..20].try_into().ok()?;
            Some((
                SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from_be_bytes([b[20], b[21]])),
                22,
            ))
        }
        ATYP_DOMAIN if b.len() >= 5 => {
            let l = b[4] as usize;
            let end = 5 + l + 2;
            if b.len() < end {
                return None;
            }
            let port = u16::from_be_bytes([b[end - 2], b[end - 1]]);
            let ip = std::str::from_utf8(&b[5..5 + l])
                .ok()
                .and_then(|h| h.parse::<IpAddr>().ok())
                .unwrap_or(Ipv4Addr::UNSPECIFIED.into());
            Some((SocketAddr::new(ip, port), end))
        }
        _ => None,
    }
}

/// SOCKS4 / 4a request destination.
#[derive(Debug, PartialEq, Eq)]
enum Dst4 {
    Ip(SocketAddrV4),
    /// SOCKS4a only: hostname resolved by the server.
    Domain(String, u16),
}

/// Pick the SOCKS4 destination.
///
/// * `socks4a`: a domain hint is forwarded as-is; otherwise `addr` must be IPv4.
/// * `socks4`: a domain hint is resolved locally (it may be backed by a
///   fake-ip `addr`); otherwise `addr` must be IPv4.
async fn pick_dst4(
    version: SocksVersion,
    addr: SocketAddr,
    host_hint: Option<&str>,
) -> Result<Dst4> {
    let domain = host_hint.filter(|h| !h.is_empty() && h.parse::<IpAddr>().is_err());
    match (domain, version) {
        (Some(h), SocksVersion::V4a) => Ok(Dst4::Domain(h.to_string(), addr.port())),
        (Some(h), _) => Ok(Dst4::Ip(resolve_v4(h, addr.port()).await?)),
        (None, _) => match addr.ip() {
            IpAddr::V4(ip) => Ok(Dst4::Ip(SocketAddrV4::new(ip, addr.port()))),
            IpAddr::V6(ip) => bail!("socks4: IPv6 target {ip} not supported"),
        },
    }
}

/// Local IPv4 resolution for plain SOCKS4 (bootstrap DNS first, then system).
async fn resolve_v4(host: &str, port: u16) -> Result<SocketAddrV4> {
    if let Ok(SocketAddr::V4(a)) = crate::dns::resolve_host_via_bootstrap(host, port).await {
        return Ok(a);
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("socks4: resolve {host}"))?;
    for a in addrs {
        if let SocketAddr::V4(a) = a {
            return Ok(a);
        }
    }
    bail!("socks4: {host} has no IPv4 address (SOCKS4 cannot carry IPv6)")
}

/// `VN=4 CD=1 DSTPORT(2) DSTIP(4) USERID 0 [HOSTNAME 0]`.
fn encode_socks4_request(dst: &Dst4, userid: &str) -> Result<Vec<u8>> {
    ensure!(!userid.as_bytes().contains(&0), "socks4: USERID contains NUL");
    let mut req = Vec::with_capacity(16 + userid.len());
    req.extend_from_slice(&[V4_VER, V4_CMD_CONNECT]);
    match dst {
        Dst4::Ip(a) => {
            req.extend_from_slice(&a.port().to_be_bytes());
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(userid.as_bytes());
            req.push(0);
        }
        Dst4::Domain(h, port) => {
            ensure!(
                !h.is_empty() && h.len() <= 255 && !h.as_bytes().contains(&0),
                "socks4a: bad domain"
            );
            req.extend_from_slice(&port.to_be_bytes());
            // SOCKS4a marker: 0.0.0.x with x != 0.
            req.extend_from_slice(&[0, 0, 0, 1]);
            req.extend_from_slice(userid.as_bytes());
            req.push(0);
            req.extend_from_slice(h.as_bytes());
            req.push(0);
        }
    }
    Ok(req)
}

/// Check the 8-byte reply `VN(0) CD DSTPORT(2) DSTIP(4)`.
fn check_socks4_reply(resp: &[u8; 8]) -> Result<()> {
    // The spec says VN is 0; a few non-conforming servers echo 4.
    ensure!(
        resp[0] == 0x00 || resp[0] == V4_VER,
        "socks4: bad reply version 0x{:02x}",
        resp[0]
    );
    match resp[1] {
        V4_REP_GRANTED => Ok(()),
        0x5B => bail!("socks4: request rejected or failed (CD=0x5b)"),
        0x5C => bail!("socks4: server cannot reach client identd (CD=0x5c)"),
        0x5D => bail!("socks4: identd reported a different user-id (CD=0x5d)"),
        c => bail!("socks4: server refused, CD=0x{c:02x}"),
    }
}

async fn socks4_handshake<S>(s: &mut S, dst: &Dst4, userid: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    s.write_all(&encode_socks4_request(dst, userid)?).await?;
    let mut resp = [0u8; 8];
    s.read_exact(&mut resp).await?;
    check_socks4_reply(&resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_v4() {
        let mut b = vec![0, 0, 0, ATYP_V4, 1, 2, 3, 4, 0x00, 0x50];
        b.extend_from_slice(b"hello");
        let (src, off) = parse_udp_header(&b).unwrap();
        assert_eq!(src, "1.2.3.4:80".parse().unwrap());
        assert_eq!(&b[off..], b"hello");
    }

    #[test]
    fn udp_header_domain_and_frag() {
        let d = b"example.com";
        let mut b = vec![0, 0, 0, ATYP_DOMAIN, d.len() as u8];
        b.extend_from_slice(d);
        b.extend_from_slice(&[0x01, 0xBB]);
        b.extend_from_slice(b"world");
        let (src, off) = parse_udp_header(&b).unwrap();
        assert_eq!(src.port(), 443);
        assert_eq!(&b[off..], b"world");
        b[2] = 1; // fragmented → dropped
        assert!(parse_udp_header(&b).is_none());
    }

    #[test]
    fn encode_dst() {
        let mut v = Vec::new();
        Dst::Domain("a.b", 443).encode(&mut v).unwrap();
        assert_eq!(v, [ATYP_DOMAIN, 3, b'a', b'.', b'b', 0x01, 0xBB]);
        let mut v = Vec::new();
        Dst::Ip("1.2.3.4:80".parse().unwrap()).encode(&mut v).unwrap();
        assert_eq!(v, [ATYP_V4, 1, 2, 3, 4, 0, 80]);
    }

    #[test]
    fn socks4_request_ip() {
        let dst = Dst4::Ip("1.2.3.4:80".parse().unwrap());
        assert_eq!(
            encode_socks4_request(&dst, "").unwrap(),
            [4, 1, 0, 80, 1, 2, 3, 4, 0]
        );
        assert_eq!(
            encode_socks4_request(&dst, "bob").unwrap(),
            [4, 1, 0, 80, 1, 2, 3, 4, b'b', b'o', b'b', 0]
        );
    }

    #[test]
    fn socks4a_request_domain() {
        let dst = Dst4::Domain("a.b".into(), 443);
        assert_eq!(
            encode_socks4_request(&dst, "").unwrap(),
            [4, 1, 0x01, 0xBB, 0, 0, 0, 1, 0, b'a', b'.', b'b', 0]
        );
        assert!(encode_socks4_request(&Dst4::Domain(String::new(), 1), "").is_err());
        assert!(encode_socks4_request(&dst, "a\0b").is_err());
    }

    #[test]
    fn socks4_reply_codes() {
        let ok = [0, 0x5A, 0, 0, 0, 0, 0, 0];
        assert!(check_socks4_reply(&ok).is_ok());
        let mut lenient = ok;
        lenient[0] = 4;
        assert!(check_socks4_reply(&lenient).is_ok());
        for cd in [0x5B, 0x5C, 0x5D, 0x00] {
            let r = [0, cd, 0, 0, 0, 0, 0, 0];
            assert!(check_socks4_reply(&r).is_err(), "cd={cd:#x}");
        }
        assert!(check_socks4_reply(&[5, 0x5A, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn socks4_pick_dst() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        // 4a forwards the domain; fake-ip addr is irrelevant.
        assert_eq!(
            pick_dst4(SocksVersion::V4a, addr, Some("example.com")).await.unwrap(),
            Dst4::Domain("example.com".into(), 443)
        );
        // IP hint / no hint → plain IPv4.
        for hint in [None, Some(""), Some("10.0.0.1")] {
            assert_eq!(
                pick_dst4(SocksVersion::V4, addr, hint).await.unwrap(),
                Dst4::Ip("10.0.0.1:443".parse().unwrap())
            );
        }
        // IPv6 can't be expressed in SOCKS4/4a.
        let v6: SocketAddr = "[::1]:80".parse().unwrap();
        assert!(pick_dst4(SocksVersion::V4a, v6, None).await.is_err());
        assert!(pick_dst4(SocksVersion::V4, v6, None).await.is_err());
    }

    #[tokio::test]
    async fn socks4_handshake_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let dst = Dst4::Domain("x.io".into(), 80);
        let expect = encode_socks4_request(&dst, "u").unwrap();
        let srv = tokio::spawn({
            let n = expect.len();
            async move {
                let mut got = vec![0u8; n];
                server.read_exact(&mut got).await.unwrap();
                server.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
                got
            }
        });
        socks4_handshake(&mut client, &dst, "u").await.unwrap();
        assert_eq!(srv.await.unwrap(), expect);
    }

    #[tokio::test]
    async fn socks4_handshake_refused() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut b = [0u8; 9];
            server.read_exact(&mut b).await.unwrap();
            server.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let dst = Dst4::Ip("1.2.3.4:80".parse().unwrap());
        let e = socks4_handshake(&mut client, &dst, "").await.unwrap_err();
        assert!(e.to_string().contains("0x5b"));
    }
}
