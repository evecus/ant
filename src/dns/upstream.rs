//! DNS upstream: udp / tcp / tls (DoT) / https (DoH).
//! Clash-rs style URL: no scheme → UDP; udp:// tcp:// tls:// https://

use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum DnsUpstream {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Dot {
        host: String,
        port: u16,
        /// 已知地址（纯 IP 配置时直接给出；域名配置时为 None，exchange 时惰性解析）。
        addr: Option<SocketAddr>,
        sni: String,
    },
    Doh {
        host: String,
        port: u16,
        path: String,
        sni: String,
        addr: Option<SocketAddr>,
    },
}

impl std::fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(a) => write!(f, "udp://{a}"),
            Self::Tcp(a) => write!(f, "tcp://{a}"),
            Self::Dot { host, port, addr, sni } => match addr {
                Some(a) => write!(f, "tls://{a} (sni={sni})"),
                None => write!(f, "tls://{host}:{port} (sni={sni})"),
            },
            Self::Doh {
                host,
                port,
                path,
                sni,
                ..
            } => write!(f, "https://{host}:{port}{path} (sni={sni})"),
        }
    }
}

/// Parse nameserver string (clash-rs compatible).
/// - `1.1.1.1` / `1.1.1.1:53` → UDP
/// - `udp://1.1.1.1:53` → UDP
/// - `tcp://1.1.1.1:53` → TCP
/// - `tls://1.1.1.1:853` / `tls://cloudflare-dns.com` → DoT
/// - `https://1.1.1.1/dns-query` → DoH
pub fn parse_nameserver(s: &str) -> Result<DnsUpstream> {
    let raw = s.trim();
    if raw.is_empty() {
        bail!("empty dns nameserver");
    }

    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("udp://{raw}")
    };

    let (scheme, rest) = with_scheme
        .split_once("://")
        .context("invalid dns nameserver URL")?;
    let scheme = scheme.to_ascii_lowercase();

    match scheme.as_str() {
        "udp" => {
            let addr = parse_host_port(rest, 53)?;
            Ok(DnsUpstream::Udp(addr))
        }
        "tcp" => {
            let addr = parse_host_port(rest, 53)?;
            Ok(DnsUpstream::Tcp(addr))
        }
        "tls" => {
            let (host, port) = split_host_port(rest, 853)?;
            let sni = host.trim_matches(|c| c == '[' || c == ']').to_string();
            // 域名不在此处解析：留给 exchange 时经 default-nameserver 惰性解析。
            let addr = sni.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, port));
            Ok(DnsUpstream::Dot { host: sni.clone(), port, addr, sni })
        }
        "https" => {
            let (authority, path) = match rest.split_once('/') {
                Some((a, p)) => (a, format!("/{p}")),
                None => (rest, "/dns-query".to_string()),
            };
            let (host, port) = split_host_port(authority, 443)?;
            let sni = host.trim_matches(|c| c == '[' || c == ']').to_string();
            let addr = if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
                Some(SocketAddr::new(ip, port))
            } else {
                None
            };
            Ok(DnsUpstream::Doh {
                host: sni.clone(),
                port,
                path,
                sni,
                addr,
            })
        }
        other => bail!("unsupported dns scheme: {other} (use udp/tcp/tls/https)"),
    }
}

fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if s.starts_with('[') {
        let end = s
            .find(']')
            .context("invalid IPv6 bracket in dns address")?;
        let host = s[1..end].to_string();
        let rest = &s[end + 1..];
        if let Some(p) = rest.strip_prefix(':') {
            let port: u16 = p.parse().context("invalid dns port")?;
            Ok((host, port))
        } else {
            Ok((host, default_port))
        }
    } else if let Some((h, p)) = s.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p.parse().context("invalid dns port")?;
            Ok((h.to_string(), port))
        } else {
            Ok((s.to_string(), default_port))
        }
    } else {
        Ok((s.to_string(), default_port))
    }
}

fn parse_host_port(s: &str, default_port: u16) -> Result<SocketAddr> {
    let (host, port) = split_host_port(s, default_port)?;
    resolve_host_port(&host, port)
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .with_context(|| format!("resolve dns host {host}"))?
        .collect();
    addrs
        .into_iter()
        .next()
        .with_context(|| format!("no address for dns host {host}"))
}

pub async fn exchange(upstream: &DnsUpstream, query: &[u8]) -> Result<Vec<u8>> {
    match upstream {
        DnsUpstream::Udp(addr) => exchange_udp(*addr, query).await,
        DnsUpstream::Tcp(addr) => exchange_tcp(*addr, query).await,
        DnsUpstream::Dot { host, port, addr, sni } => {
            let a = match addr {
                Some(a) => *a,
                None => resolve_upstream_addr(host, *port).await?,
            };
            match exchange_dot(a, sni, query).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    // 地址可能已变：清缓存，下次查询重新解析。
                    invalidate_upstream_addr(host, *port);
                    Err(e)
                }
            }
        }
        DnsUpstream::Doh {
            host,
            port,
            path,
            sni,
            addr,
        } => {
            let a = match addr {
                Some(a) => *a,
                None => resolve_upstream_addr(host, *port).await?,
            };
            match exchange_doh(host, *port, path, sni, Some(a), query).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    invalidate_upstream_addr(host, *port);
                    Err(e)
                }
            }
        }
    }
}

// ── 惰性地址解析（对齐 mihomo：启动零网络 IO，用到处才解析，失败不致命）──────

/// bootstrap 上游（`default-nameserver`），main 启动时 set（纯内存，不联网）。
static BOOTSTRAP: OnceLock<DnsUpstream> = OnceLock::new();

pub fn set_bootstrap(up: DnsUpstream) {
    let _ = BOOTSTRAP.set(up);
}

/// DoT/DoH 域名 → 地址的解析缓存。交换失败时由 `exchange` 清除以触发重解。
static RESOLVED_CACHE: Lazy<Mutex<HashMap<String, SocketAddr>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

async fn resolve_upstream_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let key = format!("{host}:{port}");
    if let Some(a) = RESOLVED_CACHE.lock().unwrap().get(&key) {
        return Ok(*a);
    }
    let addr = resolve_host_via_bootstrap(host, port)
        .await
        .with_context(|| format!("resolve dns upstream host {host}"))?;
    RESOLVED_CACHE
        .lock()
        .unwrap()
        .insert(key, addr);
    Ok(addr)
}

fn invalidate_upstream_addr(host: &str, port: u16) {
    RESOLVED_CACHE
        .lock()
        .unwrap()
        .remove(&format!("{host}:{port}"));
}

/// 解析任意主机名：IP 直过 → default-nameserver（bootstrap）优先 → 系统解析回落。
///
/// 供 outbound 节点 `server` 域名拨号时使用。bootstrap 优先可避免系统 DNS
/// 指回 ant 自身时的解析回环；bootstrap 失败仅影响当次解析，由调用方决定
/// 是否降级，绝不杀进程。
pub async fn resolve_host_via_bootstrap(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(boot) = BOOTSTRAP.get() {
        match lookup_via(boot, host, port).await {
            Ok(a) => return Ok(a),
            Err(e) => {
                // Per-query; the queried name is user traffic — debug only.
                tracing::debug!(
                    "resolve {host} via default-nameserver failed: {e:#}; falling back to system resolver"
                );
            }
        }
    }
    let mut it = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host} via system resolver"))?;
    it.next()
        .with_context(|| format!("no address for {host}"))
}

async fn exchange_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = crate::app::sockopt::bind_udp(bind).await?;
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, sock.recv(&mut buf))
        .await
        .context("dns udp timeout")??;
    Ok(buf[..n].to_vec())
}

async fn exchange_tcp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(TIMEOUT, crate::app::sockopt::connect_tcp(addr))
        .await
        .context("dns tcp connect timeout")??;
    write_tcp_msg(&mut stream, query).await?;
    read_tcp_msg(&mut stream).await
}

async fn exchange_dot(addr: SocketAddr, sni: &str, query: &[u8]) -> Result<Vec<u8>> {
    let stream = tokio::time::timeout(TIMEOUT, crate::app::sockopt::connect_tcp(addr))
        .await
        .context("dns dot connect timeout")??;
    let connector = tls_connector_dot();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("invalid sni for DoT: {sni}"))?;
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, stream))
        .await
        .context("dns dot tls timeout")??;
    write_tcp_msg(&mut tls, query).await?;
    read_tcp_msg(&mut tls).await
}

async fn exchange_doh(
    host: &str,
    port: u16,
    path: &str,
    sni: &str,
    known: Option<SocketAddr>,
    query: &[u8],
) -> Result<Vec<u8>> {
    let addr = if let Some(a) = known {
        a
    } else {
        let mut it = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolve DoH host {host}"))?;
        it.next()
            .with_context(|| format!("no address for DoH host {host}"))?
    };
    let stream = tokio::time::timeout(TIMEOUT, crate::app::sockopt::connect_tcp(addr))
        .await
        .context("dns doh connect timeout")??;
    let connector = tls_connector_doh();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("invalid sni for DoH: {sni}"))?;
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, stream))
        .await
        .context("dns doh tls timeout")??;

    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        query.len()
    );
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(query).await?;
    tls.flush().await?;

    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(TIMEOUT, async {
        let mut tmp = [0u8; 2048];
        loop {
            let n = tls.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 64 * 1024 {
                bail!("DoH response too large");
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("dns doh read timeout")??;

    parse_http_body(&buf)
}

fn parse_http_body(resp: &[u8]) -> Result<Vec<u8>> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("DoH: no HTTP header end")?;
    let headers = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let status_line = headers.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        bail!("DoH HTTP status not 200: {status_line}");
    }
    Ok(resp[header_end + 4..].to_vec())
}

async fn write_tcp_msg<S: AsyncWriteExt + Unpin>(stream: &mut S, query: &[u8]) -> Result<()> {
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_tcp_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .context("dns tcp read len timeout")??;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 65535 {
        bail!("bad dns tcp message length {len}");
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .context("dns tcp read body timeout")??;
    Ok(buf)
}

fn tls_connector_dot() -> TlsConnector {
    static CONNECTOR: once_cell::sync::Lazy<TlsConnector> =
        once_cell::sync::Lazy::new(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            TlsConnector::from(Arc::new(cfg))
        });
    CONNECTOR.clone()
}

fn tls_connector_doh() -> TlsConnector {
    static CONNECTOR: once_cell::sync::Lazy<TlsConnector> =
        once_cell::sync::Lazy::new(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            TlsConnector::from(Arc::new(cfg))
        });
    CONNECTOR.clone()
}

/// Resolve `host` to an address using the bootstrap nameserver (A query).
/// IP literals are returned as-is.
async fn lookup_via(bootstrap: &DnsUpstream, host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let query = build_a_query(host);
    // bootstrap 只可能是 Udp/Tcp（config validate 强制纯 IP）。这里直接走
    // 非惰性交换路径，避免 exchange → resolve → lookup_via 的 async 递归。
    let resp = match bootstrap {
        DnsUpstream::Udp(a) => exchange_udp(*a, &query).await,
        DnsUpstream::Tcp(a) => exchange_tcp(*a, &query).await,
        _ => bail!("default-nameserver must be a pure-IP udp/tcp upstream"),
    }
    .context("default-nameserver lookup")?;
    let ip = first_a(&resp).with_context(|| format!("no A record for {host} via default-nameserver"))?;
    Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

fn build_a_query(host: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in host.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn first_a(msg: &[u8]) -> Option<std::net::Ipv4Addr> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        i = skip_name(msg, i)?;
        i += 4;
    }
    for _ in 0..an {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            return None;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        let rdata = i + 10;
        if typ == 1 && rdlen == 4 && rdata + 4 <= msg.len() {
            return Some(std::net::Ipv4Addr::new(msg[rdata], msg[rdata+1], msg[rdata+2], msg[rdata+3]));
        }
        i = rdata + rdlen;
    }
    None
}

fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return (i + 2 <= msg.len()).then_some(i + 2);
        }
        i += 1 + len;
    }
}

