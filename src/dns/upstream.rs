//! DNS upstream: udp / tcp / tls (DoT) / https (DoH).
//! Clash-rs style URL: no scheme → UDP; udp:// tcp:// tls:// https://
//!
//! 实现要点（对齐 reflex / sing-box 的做法）：
//! - UDP：每次查询独立随机源端口；校验响应 ID + Question（丢弃伪造/迟到包）；
//!   超时重发一次；TC 位置位时改走 TCP（TCP 也失败则退回截断响应）。
//! - TCP / DoT：2 字节长度前缀帧，一次 write 发出；校验响应。
//! - DoT：有限并发的 TLS 连接池（复用连接，空闲过期，复用失败自动换新连接重试）。
//! - DoH：优先 HTTP/2（ALPN）并复用连接多路复用，服务端不支持 h2 时回落 HTTP/1.1；
//!   RFC 8484 要求 DNS ID 置 0；HTTP/1.1 路径正确处理状态行 / Content-Length / chunked。
//! - 上游域名（含 outbound 节点 server 域名）经 default-nameserver 惰性解析：
//!   带 TTL 缓存、并发合并（singleflight）、短暂负缓存、A→AAAA、系统解析回落。
//! - 整次交换有总超时；传输失败会清掉对应连接池与已解析地址。

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2 as h2c;
use hyper_util::rt::{TokioExecutor, TokioIo};
use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// 一次 `exchange` 的总预算（含地址解析、建连、握手、收发）。
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP 单次发送后的等待时间；超时后重发一次。
const UDP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_ATTEMPTS: usize = 2;
const UDP_MIN_BUF: usize = 4096;
/// 复用连接上的单次交换超时：连接可能已被对端静默关闭（半开），
/// 尽早放弃并换新连接，而不是把整个预算耗在死连接上。
const REUSE_TIMEOUT: Duration = Duration::from_secs(2);
/// bootstrap 每一步（A / AAAA 各一次）与系统解析回落的超时。
const BOOTSTRAP_STEP_TIMEOUT: Duration = Duration::from_millis(2500);
const SYSTEM_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
/// DoT 连接池容量 = 同时在用连接数上限（对齐 sing-box tls.go `MaxInflight: 8`）。
const POOL_CAPACITY: usize = 8;
/// 空闲连接保留时间；超过则丢弃（对端通常 10~30s 内会关闭空闲连接）。
const POOL_IDLE_TTL: Duration = Duration::from_secs(15);
const MAX_DOH_BODY: usize = 64 * 1024;
/// 已解析上游地址的缓存 TTL 夹取范围。
const RESOLVE_MIN_TTL: u32 = 30;
const RESOLVE_MAX_TTL: u32 = 600;
/// 解析失败的负缓存时间：避免排队的并发调用各自再等一轮超时。
const RESOLVE_NEG_TTL: Duration = Duration::from_secs(3);

// ───────────────────────────── 类型与解析 ─────────────────────────────

/// 上游地址：IP 字面量直接可用；域名则在 exchange 时惰性解析。
#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
    ip: Option<IpAddr>,
}

impl Target {
    fn parse(s: &str, default_port: u16) -> Result<Self> {
        let (host, port) = split_host_port(s, default_port)?;
        let ip = host.parse::<IpAddr>().ok();
        Ok(Self { host, port, ip })
    }

    fn display(&self) -> String {
        match self.ip {
            Some(ip) => SocketAddr::new(ip, self.port).to_string(),
            None => fmt_host_port(&self.host, self.port),
        }
    }
}

enum Kind {
    Udp(Target),
    Tcp(Target),
    Dot {
        target: Target,
        sni: String,
        pool: Arc<DotPool>,
    },
    Doh {
        target: Target,
        sni: String,
        /// `Host` / `:authority`：IPv6 加方括号，默认端口 443 省略。
        authority: String,
        path: String,
        pool: Arc<DohPool>,
    },
}

/// 一个已解析的 DNS 上游。`Clone` 很便宜（共享内部连接池）。
#[derive(Clone)]
pub struct DnsUpstream {
    kind: Arc<Kind>,
}

impl std::fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.kind {
            Kind::Udp(t) => write!(f, "udp://{}", t.display()),
            Kind::Tcp(t) => write!(f, "tcp://{}", t.display()),
            Kind::Dot { target, sni, .. } => write!(f, "tls://{} (sni={sni})", target.display()),
            Kind::Doh {
                target, sni, path, ..
            } => write!(
                f,
                "https://{}{path} (sni={sni})",
                fmt_host_port(&target.host, target.port)
            ),
        }
    }
}

impl std::fmt::Debug for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DnsUpstream({self})")
    }
}

impl DnsUpstream {
    fn target(&self) -> &Target {
        match &*self.kind {
            Kind::Udp(t) | Kind::Tcp(t) => t,
            Kind::Dot { target, .. } | Kind::Doh { target, .. } => target,
        }
    }

    /// 地址是否为 IP 字面量（无需任何域名解析即可使用）。
    /// default-nameserver（bootstrap）必须满足此条件。
    pub fn is_literal_ip(&self) -> bool {
        self.target().ip.is_some()
    }

    /// 传输失败后的善后：丢弃可能已失效的连接，并让域名上游下次重新解析。
    fn on_failure(&self) {
        match &*self.kind {
            Kind::Dot { pool, .. } => pool.clear(),
            Kind::Doh { pool, .. } => pool.clear(),
            _ => {}
        }
        let t = self.target();
        if t.ip.is_none() {
            invalidate_resolved(&t.host);
        }
    }

    /// 在已知 IP 上执行一次交换（不做地址解析，故 bootstrap 路径不会递归）。
    async fn run(&self, query: &[u8], ip: IpAddr) -> Result<Vec<u8>> {
        let addr = SocketAddr::new(ip, self.target().port);
        match &*self.kind {
            Kind::Udp(_) => udp_exchange(addr, query).await,
            Kind::Tcp(_) => tcp_exchange(addr, query).await,
            Kind::Dot { sni, pool, .. } => dot_exchange(pool, addr, sni, query).await,
            Kind::Doh {
                sni,
                authority,
                path,
                pool,
                ..
            } => doh_exchange(pool, addr, sni, authority, path, query).await,
        }
    }
}

/// Parse nameserver string (clash-rs compatible).
/// - `1.1.1.1` / `1.1.1.1:53` / `[2606:4700::1111]:53` / `2606:4700::1111` → UDP
/// - `udp://1.1.1.1:53` → UDP
/// - `tcp://1.1.1.1:53` → TCP
/// - `tls://1.1.1.1:853` / `tls://cloudflare-dns.com` → DoT
/// - `https://1.1.1.1/dns-query` → DoH
///
/// 纯解析，无任何网络 IO；域名主机在 `exchange` 时经 default-nameserver 惰性解析。
pub fn parse_nameserver(s: &str) -> Result<DnsUpstream> {
    let raw = s.trim();
    if raw.is_empty() {
        bail!("empty dns nameserver");
    }

    let (scheme, rest) = match raw.split_once("://") {
        Some((sc, rest)) => (sc.to_ascii_lowercase(), rest),
        None => ("udp".to_string(), raw),
    };

    let kind = match scheme.as_str() {
        "udp" => Kind::Udp(Target::parse(rest, 53)?),
        "tcp" => Kind::Tcp(Target::parse(rest, 53)?),
        "tls" => {
            let target = Target::parse(rest, 853)?;
            let sni = target.host.clone();
            let pool = dot_pool(&format!("{}|{sni}", fmt_host_port(&target.host, target.port)));
            Kind::Dot { target, sni, pool }
        }
        "https" => {
            let (authority, path) = match rest.split_once('/') {
                Some((a, p)) => (a, format!("/{p}")),
                None => (rest, "/dns-query".to_string()),
            };
            let target = Target::parse(authority, 443)?;
            let sni = target.host.clone();
            let authority = build_authority(&target.host, target.port);
            let pool = doh_pool(&format!(
                "{}|{sni}|{path}",
                fmt_host_port(&target.host, target.port)
            ));
            Kind::Doh {
                target,
                sni,
                authority,
                path,
                pool,
            }
        }
        other => bail!("unsupported dns scheme: {other} (use udp/tcp/tls/https)"),
    };
    Ok(DnsUpstream {
        kind: Arc::new(kind),
    })
}

/// `host[:port]` / `[v6][:port]` / 裸 IPv4 / 裸 IPv6 → (host, port)。
fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty dns address");
    }
    // 裸 IP（含不带方括号的 IPv6）：整体就是主机，用默认端口。
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip.to_string(), default_port));
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').context("invalid IPv6 bracket in dns address")?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if tail.is_empty() => default_port,
            None => bail!("invalid dns address: {s}"),
        };
        (host.to_string(), port)
    } else {
        match s.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => {
                bail!("ambiguous dns address {s}: wrap IPv6 in [] when giving a port")
            }
            Some((h, p)) => (h.to_string(), parse_port(p)?),
            None => (s.to_string(), default_port),
        }
    };
    ensure!(!host.is_empty(), "empty host in dns address: {s}");
    ensure!(
        !host.chars().any(|c| c.is_whitespace() || c == '/'),
        "invalid host in dns address: {s}"
    );
    Ok((host, port))
}

fn parse_port(p: &str) -> Result<u16> {
    let port: u16 = p.parse().with_context(|| format!("invalid dns port `{p}`"))?;
    ensure!(port != 0, "invalid dns port 0");
    Ok(port)
}

fn fmt_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// HTTP authority：IPv6 加方括号；默认端口 443 省略。
fn build_authority(host: &str, port: u16) -> String {
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        h
    } else {
        format!("{h}:{port}")
    }
}

// ───────────────────────────── 对外入口 ─────────────────────────────

/// 向上游发送一条 DNS 查询（wire 格式）并返回已校验的响应。
pub async fn exchange(upstream: &DnsUpstream, query: &[u8]) -> Result<Vec<u8>> {
    ensure!(query.len() >= 12, "dns query too short");
    let fut = async {
        let ip = match upstream.target().ip {
            Some(ip) => ip,
            // 解析失败不触发 on_failure：负缓存要留给后续排队的调用。
            None => resolve_name(&upstream.target().host).await?,
        };
        match upstream.run(query, ip).await {
            Ok(r) => Ok(r),
            Err(e) => {
                upstream.on_failure();
                Err(e)
            }
        }
    };
    match timeout(TOTAL_TIMEOUT, fut).await {
        Ok(r) => r.with_context(|| format!("dns upstream {upstream}")),
        Err(_) => {
            upstream.on_failure();
            Err(anyhow!("dns upstream {upstream}: timeout after {TOTAL_TIMEOUT:?}"))
        }
    }
}

// ───────────────────────── 惰性地址解析（bootstrap）─────────────────────────
// 对齐 mihomo：启动零网络 IO，用到处才解析，失败不致命。

/// bootstrap 上游（`default-nameserver`），main 启动时 set（纯内存，不联网）。
static BOOTSTRAP: OnceLock<DnsUpstream> = OnceLock::new();

pub fn set_bootstrap(up: DnsUpstream) {
    let _ = BOOTSTRAP.set(up);
}

enum Resolved {
    Ok { ip: IpAddr, expires: Instant },
    Fail { msg: String, expires: Instant },
}

static RESOLVED: Lazy<Mutex<HashMap<String, Resolved>>> = Lazy::new(|| Mutex::new(HashMap::new()));
/// 每个主机名一把异步锁，合并并发解析（锁数量受限于不同主机名个数，极少）。
static INFLIGHT: Lazy<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn norm_host(host: &str) -> String {
    host.trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn invalidate_resolved(host: &str) {
    lock(&RESOLVED).remove(&norm_host(host));
}

fn resolved_get(key: &str) -> Option<Result<IpAddr>> {
    let mut g = lock(&RESOLVED);
    match g.get(key) {
        Some(Resolved::Ok { ip, expires }) if *expires > Instant::now() => Some(Ok(*ip)),
        Some(Resolved::Fail { msg, expires }) if *expires > Instant::now() => {
            Some(Err(anyhow!("{msg}")))
        }
        Some(_) => {
            g.remove(key);
            None
        }
        None => None,
    }
}

/// 解析主机名 → IP（带 TTL 缓存 + 并发合并 + 负缓存）。
async fn resolve_name(host: &str) -> Result<IpAddr> {
    let key = norm_host(host);
    if let Ok(ip) = key.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(r) = resolved_get(&key) {
        return r;
    }
    let gate = lock(&INFLIGHT)
        .entry(key.clone())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = gate.lock().await;
    // 等锁期间可能已有人解析完成。
    if let Some(r) = resolved_get(&key) {
        return r;
    }
    match resolve_uncached(&key).await {
        Ok((ip, ttl)) => {
            let ttl = ttl.clamp(RESOLVE_MIN_TTL, RESOLVE_MAX_TTL);
            lock(&RESOLVED).insert(
                key,
                Resolved::Ok {
                    ip,
                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                },
            );
            Ok(ip)
        }
        Err(e) => {
            lock(&RESOLVED).insert(
                key,
                Resolved::Fail {
                    msg: format!("{e:#}"),
                    expires: Instant::now() + RESOLVE_NEG_TTL,
                },
            );
            Err(e)
        }
    }
}

/// bootstrap 优先（避免系统 DNS 指回 ant 自身造成回环），失败回落系统解析。
async fn resolve_uncached(host: &str) -> Result<(IpAddr, u32)> {
    if let Some(boot) = BOOTSTRAP.get() {
        match lookup_via(boot, host).await {
            Ok(r) => return Ok(r),
            Err(e) => tracing::warn!(
                "resolve {host} via default-nameserver failed: {e:#}; falling back to system resolver"
            ),
        }
    }
    let addrs: Vec<SocketAddr> = timeout(SYSTEM_RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 0)))
        .await
        .map_err(|_| anyhow!("resolve {host} via system resolver: timeout"))?
        .with_context(|| format!("resolve {host} via system resolver"))?
        .collect();
    // 与 bootstrap 一致：优先 IPv4。
    let pick = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .with_context(|| format!("no address for {host}"))?;
    Ok((pick.ip(), 60))
}

/// 经 bootstrap 查询 A，无 A 记录再查 AAAA。返回 (ip, ttl)。
async fn lookup_via(boot: &DnsUpstream, host: &str) -> Result<(IpAddr, u32)> {
    let ip = boot
        .target()
        .ip
        .context("default-nameserver must be a pure-IP upstream")?;
    for qtype in [QTYPE_A, QTYPE_AAAA] {
        let q = build_query(host, qtype)?;
        let resp = timeout(BOOTSTRAP_STEP_TIMEOUT, boot.run(&q, ip))
            .await
            .map_err(|_| anyhow!("default-nameserver lookup {host}: timeout"))?
            .context("default-nameserver lookup")?;
        let rcode = resp[3] & 0x0F;
        ensure!(rcode == 0, "default-nameserver rcode {rcode} for {host}");
        if let Some(r) = first_ip(&resp, qtype) {
            return Ok(r);
        }
    }
    bail!("no A/AAAA record for {host} via default-nameserver")
}

/// 解析任意主机名：IP 直过 → default-nameserver（bootstrap）优先 → 系统解析回落。
///
/// 供 outbound 节点 `server` 域名拨号时使用。结果带 TTL 缓存并合并并发请求，
/// 失败仅影响当次解析，由调用方决定是否降级，绝不杀进程。
pub async fn resolve_host_via_bootstrap(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let ip = resolve_name(host).await?;
    Ok(SocketAddr::new(ip, port))
}

// ───────────────────────────── UDP / TCP ─────────────────────────────

async fn udp_exchange(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = crate::app::sockopt::bind_udp(bind).await?;
    sock.connect(addr).await?;
    // 缓冲区跟随查询里声明的 EDNS UDP size，避免把大响应截断。
    let cap = edns_udp_size(query).unwrap_or(0).clamp(UDP_MIN_BUF, 65535);
    let mut buf = vec![0u8; cap];

    for attempt in 0..UDP_ATTEMPTS {
        sock.send(query).await?;
        let wait = async {
            loop {
                let n = sock.recv(&mut buf).await?;
                match validate_response(query, &buf[..n]) {
                    Ok(()) => return Ok::<usize, anyhow::Error>(n),
                    // 连接的 UDP 已过滤了源地址；ID / Question 对不上的是伪造或迟到包。
                    Err(e) => tracing::debug!("dns udp {addr}: drop response: {e}"),
                }
            }
        };
        match timeout(UDP_ATTEMPT_TIMEOUT, wait).await {
            Ok(r) => {
                let n = r?;
                let resp = buf[..n].to_vec();
                if resp[2] & 0x02 != 0 {
                    tracing::debug!("dns udp {addr}: TC bit set, retrying over TCP");
                    return match tcp_exchange(addr, query).await {
                        Ok(full) => Ok(full),
                        Err(e) => {
                            // 退回截断响应：客户端可自行改用 TCP 重试。
                            tracing::debug!("dns udp {addr}: TCP retry failed ({e:#}), using truncated reply");
                            Ok(resp)
                        }
                    };
                }
                return Ok(resp);
            }
            Err(_) => tracing::debug!("dns udp {addr}: attempt {} timeout", attempt + 1),
        }
    }
    bail!("dns udp {addr}: timeout")
}

async fn tcp_exchange(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut s = crate::app::sockopt::connect_tcp(addr)
        .await
        .with_context(|| format!("dns tcp connect {addr}"))?;
    let _ = s.set_nodelay(true);
    framed_exchange(&mut s, query).await
}

/// 2 字节长度前缀帧（TCP / DoT 共用）：长度+报文合并为一次 write，读完整帧后校验。
async fn framed_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    query: &[u8],
) -> Result<Vec<u8>> {
    ensure!(query.len() <= 65535, "dns query too large");
    let mut out = Vec::with_capacity(2 + query.len());
    out.extend_from_slice(&(query.len() as u16).to_be_bytes());
    out.extend_from_slice(query);
    s.write_all(&out).await?;
    s.flush().await?;

    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    ensure!(len >= 12, "dns tcp response too short: {len}");
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    validate_response(query, &buf)?;
    Ok(buf)
}

// ───────────────────────────── TLS ─────────────────────────────

fn make_client_config(alpn: &[&[u8]], extra_roots: &[rustls::pki_types::CertificateDer<'static>]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in extra_roots {
        let _ = roots.add(c.clone());
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

#[derive(Clone, Copy)]
enum TlsProfile {
    Dot,
    Doh,
}

/// 进程内共享的 TLS 配置（共享即共享会话恢复缓存，重连更快）。
#[cfg(not(test))]
fn tls_connector(p: TlsProfile) -> TlsConnector {
    static DOT: Lazy<Arc<ClientConfig>> = Lazy::new(|| make_client_config(&[], &[]));
    static DOH: Lazy<Arc<ClientConfig>> =
        Lazy::new(|| make_client_config(&[b"h2", b"http/1.1"], &[]));
    TlsConnector::from(match p {
        TlsProfile::Dot => DOT.clone(),
        TlsProfile::Doh => DOH.clone(),
    })
}

/// 测试：额外信任测试用自签证书。
#[cfg(test)]
pub(crate) static TEST_ROOTS: Lazy<Mutex<Vec<rustls::pki_types::CertificateDer<'static>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

#[cfg(test)]
fn tls_connector(p: TlsProfile) -> TlsConnector {
    let extra = lock(&TEST_ROOTS).clone();
    TlsConnector::from(match p {
        TlsProfile::Dot => make_client_config(&[], &extra),
        TlsProfile::Doh => make_client_config(&[b"h2", b"http/1.1"], &extra),
    })
}

async fn dial_tls(
    addr: SocketAddr,
    sni: &str,
    profile: TlsProfile,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = crate::app::sockopt::connect_tcp(addr)
        .await
        .with_context(|| format!("tcp connect {addr}"))?;
    let _ = tcp.set_nodelay(true);
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow!("invalid sni: {sni}"))?;
    tls_connector(profile)
        .connect(name, tcp)
        .await
        .with_context(|| format!("tls handshake with {sni} ({addr})"))
}

// ───────────────────────────── DoT 连接池 ─────────────────────────────

type DotStream = tokio_rustls::client::TlsStream<TcpStream>;

/// 有限并发的 DoT 连接池。
///
/// DNS-over-TCP 帧不能在一条连接上并发复用（一发一收），但可以维护多条连接：
/// 空闲队列 + 信号量限流（对齐 sing-box `ConnPool`，`MaxInflight: 8`）。
/// 取出的连接由调用方独占；被外层超时取消时连接随 future 一并 drop 而关闭，
/// 因此不会有状态不明的连接留在池里。
pub struct DotPool {
    idle: Mutex<VecDeque<(DotStream, Instant)>>,
    permits: Semaphore,
}

impl DotPool {
    fn new() -> Self {
        Self {
            idle: Mutex::new(VecDeque::new()),
            permits: Semaphore::new(POOL_CAPACITY),
        }
    }

    /// 取最近归还（LIFO）且未过期的空闲连接。
    fn take(&self) -> Option<DotStream> {
        let mut g = lock(&self.idle);
        while let Some((c, since)) = g.pop_back() {
            if since.elapsed() < POOL_IDLE_TTL {
                return Some(c);
            }
        }
        None
    }

    fn put(&self, c: DotStream) {
        let mut g = lock(&self.idle);
        g.retain(|(_, since)| since.elapsed() < POOL_IDLE_TTL);
        g.push_back((c, Instant::now()));
        while g.len() > POOL_CAPACITY {
            g.pop_front();
        }
    }

    fn clear(&self) {
        lock(&self.idle).clear();
    }
}

static DOT_POOLS: Lazy<Mutex<HashMap<String, Arc<DotPool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 同一上游（无论 parse 了多少次）共享同一个池。
fn dot_pool(key: &str) -> Arc<DotPool> {
    lock(&DOT_POOLS)
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(DotPool::new()))
        .clone()
}

async fn dot_exchange(pool: &DotPool, addr: SocketAddr, sni: &str, query: &[u8]) -> Result<Vec<u8>> {
    let _permit = pool
        .permits
        .acquire()
        .await
        .map_err(|_| anyhow!("dot pool closed"))?;
    // 每轮要么消耗一条空闲连接（有限），要么新建连接并直接返回结果。
    loop {
        let (mut tls, reused) = match pool.take() {
            Some(c) => (c, true),
            None => (dial_tls(addr, sni, TlsProfile::Dot).await?, false),
        };
        let r = if reused {
            match timeout(REUSE_TIMEOUT, framed_exchange(&mut tls, query)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow!("reused dot connection timeout")),
            }
        } else {
            framed_exchange(&mut tls, query).await
        };
        match r {
            Ok(resp) => {
                pool.put(tls);
                return Ok(resp);
            }
            // 复用连接可能已被对端关闭：丢弃它，换下一条/新连接。
            Err(e) if reused => {
                tracing::debug!("dot {addr}: pooled connection failed ({e:#}), retrying");
            }
            Err(e) => return Err(e),
        }
    }
}

// ───────────────────────────── DoH ─────────────────────────────

type H2Sender = h2c::SendRequest<Full<Bytes>>;

struct H2Conn {
    id: u64,
    tx: H2Sender,
}

/// DoH 的 h2 连接槽。`SendRequest` 可 clone，多个查询并发多路复用同一连接。
pub struct DohPool {
    slot: Mutex<Option<H2Conn>>,
    next_id: AtomicU64,
}

impl DohPool {
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }

    fn current(&self) -> Option<(u64, H2Sender)> {
        lock(&self.slot)
            .as_ref()
            .filter(|c| !c.tx.is_closed())
            .map(|c| (c.id, c.tx.clone()))
    }

    /// 槽空时占位；已有可用连接则保持不动（并发冷启动时多拨的连接只服务当次查询）。
    fn publish(&self, tx: &H2Sender) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut g = lock(&self.slot);
        let occupied = g.as_ref().map(|c| !c.tx.is_closed()).unwrap_or(false);
        if !occupied {
            *g = Some(H2Conn { id, tx: tx.clone() });
        }
        id
    }

    /// 仅当槽里仍是这条连接时才清掉（避免误伤已被替换的新连接）。
    fn invalidate(&self, id: u64) {
        let mut g = lock(&self.slot);
        if g.as_ref().map(|c| c.id) == Some(id) {
            *g = None;
        }
    }

    fn clear(&self) {
        *lock(&self.slot) = None;
    }
}

/// future 被取消 / 请求失败时，把对应 h2 连接移出池（卡死的连接不能继续被复用）。
struct InvalidateOnDrop<'a> {
    pool: &'a DohPool,
    id: u64,
    armed: bool,
}

impl Drop for InvalidateOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.pool.invalidate(self.id);
        }
    }
}

static DOH_POOLS: Lazy<Mutex<HashMap<String, Arc<DohPool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn doh_pool(key: &str) -> Arc<DohPool> {
    lock(&DOH_POOLS)
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(DohPool::new()))
        .clone()
}

/// RFC 8484：DoH 请求的 DNS ID 应为 0（利于 HTTP 缓存）；返回 (改写后的报文, 原 ID)。
fn zero_id(msg: &[u8]) -> (Vec<u8>, [u8; 2]) {
    let mut v = msg.to_vec();
    let id = [v[0], v[1]];
    v[0] = 0;
    v[1] = 0;
    (v, id)
}

async fn doh_exchange(
    pool: &DohPool,
    addr: SocketAddr,
    sni: &str,
    authority: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>> {
    let (wire, orig_id) = zero_id(query);
    let uri = format!("https://{authority}{path}");

    let finish = |mut resp: Vec<u8>| -> Result<Vec<u8>> {
        ensure!(resp.len() >= 12, "doh response too short");
        resp[0..2].copy_from_slice(&orig_id);
        validate_response(query, &resp)?;
        Ok(resp)
    };

    // 1) 复用已有 h2 连接。
    if let Some((id, tx)) = pool.current() {
        let mut guard = InvalidateOnDrop {
            pool,
            id,
            armed: true,
        };
        match timeout(REUSE_TIMEOUT, doh_h2_request(&tx, &uri, &wire)).await {
            Ok(Ok(resp)) => {
                guard.armed = false;
                return finish(resp);
            }
            Ok(Err(e)) => tracing::debug!("doh {addr}: pooled h2 connection failed ({e:#}), redialing"),
            Err(_) => tracing::debug!("doh {addr}: pooled h2 connection timeout, redialing"),
        }
        // guard 在此 drop → 失效连接移出池。
    }

    // 2) 新建连接。
    let tls = dial_tls(addr, sni, TlsProfile::Doh).await?;
    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    if !is_h2 {
        // 服务端只讲 HTTP/1.1：一次性连接，不入池。
        let resp = doh_h1_request(tls, authority, path, &wire).await?;
        return finish(resp);
    }
    let (tx, conn) = h2c::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .context("doh h2 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("doh h2 connection closed: {e}");
        }
    });
    let id = pool.publish(&tx);
    let mut guard = InvalidateOnDrop {
        pool,
        id,
        armed: true,
    };
    let resp = doh_h2_request(&tx, &uri, &wire).await?;
    guard.armed = false;
    finish(resp)
}

async fn doh_h2_request(tx: &H2Sender, uri: &str, wire: &[u8]) -> Result<Vec<u8>> {
    let mut tx = tx.clone();
    tx.ready().await.context("h2 connection not ready")?;
    let req = http::Request::post(uri)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(wire)))
        .context("build doh request")?;
    let resp = tx.send_request(req).await.context("doh h2 request")?;
    let (parts, body) = resp.into_parts();
    ensure!(
        parts.status == http::StatusCode::OK,
        "doh server returned {}",
        parts.status
    );
    let body = Limited::new(body, MAX_DOH_BODY)
        .collect()
        .await
        .map_err(|e| anyhow!("doh body: {e}"))?
        .to_bytes();
    ensure!(!body.is_empty(), "doh response body is empty");
    Ok(body.to_vec())
}

/// HTTP/1.1 回落：`Connection: close`，读到 EOF 后解析。
async fn doh_h1_request<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    authority: &str,
    path: &str,
    wire: &[u8],
) -> Result<Vec<u8>> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        wire.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(wire);
    s.write_all(&out).await?;
    s.flush().await?;

    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    loop {
        match s.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                ensure!(buf.len() <= MAX_DOH_BODY + 8192, "doh response too large");
            }
            // 对端未发 close_notify 就关闭：数据已读完，交给解析器判断是否完整。
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => break,
            Err(e) => return Err(e.into()),
        }
    }
    parse_http1_response(&buf)
}

/// 解析 HTTP/1.x 响应：严格状态码、Transfer-Encoding: chunked 优先于 Content-Length。
fn parse_http1_response(resp: &[u8]) -> Result<Vec<u8>> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("doh: no HTTP header end")?;
    let head = std::str::from_utf8(&resp[..header_end]).context("doh: headers not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut it = status_line.split_whitespace();
    let version = it.next().unwrap_or("");
    let code: u16 = it
        .next()
        .and_then(|c| c.parse().ok())
        .filter(|_| version.starts_with("HTTP/1."))
        .with_context(|| format!("doh: malformed status line: {status_line}"))?;
    ensure!(code == 200, "doh server returned {status_line}");

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    let body = &resp[header_end + 4..];
    let out = if chunked {
        dechunk(body)?
    } else if let Some(n) = content_length {
        ensure!(body.len() >= n, "doh: truncated body ({} < {n})", body.len());
        body[..n].to_vec()
    } else {
        body.to_vec()
    };
    ensure!(!out.is_empty(), "doh response body is empty");
    ensure!(out.len() <= MAX_DOH_BODY, "doh response too large");
    Ok(out)
}

/// RFC 7230 §4.1 chunked 解码（忽略 chunk 扩展与 trailer）。
fn dechunk(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("chunked: missing size line")?;
        let line = std::str::from_utf8(&input[..line_end]).context("chunked: size not UTF-8")?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| anyhow!("chunked: bad size `{size_str}`"))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        ensure!(input.len() >= size + 2, "chunked: truncated chunk");
        out.extend_from_slice(&input[..size]);
        ensure!(&input[size..size + 2] == b"\r\n", "chunked: missing chunk CRLF");
        input = &input[size + 2..];
        ensure!(out.len() <= MAX_DOH_BODY, "chunked: body too large");
    }
}

// ───────────────────────────── DNS 报文辅助 ─────────────────────────────

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// 跳过一个（可能压缩的）域名，返回其后的偏移。全程带边界检查。
fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return (i + 2 <= msg.len()).then_some(i + 2);
        }
        if len & 0xC0 != 0 {
            return None; // 保留的标签类型
        }
        i += 1 + len;
        if i > msg.len() {
            return None;
        }
    }
}

fn be16(msg: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]))
}

/// 单 Question 报文的 Question 段原始字节（QNAME+QTYPE+QCLASS）。
fn question_bytes(msg: &[u8]) -> Option<&[u8]> {
    if msg.len() < 12 || be16(msg, 4)? != 1 {
        return None;
    }
    let end = skip_name(msg, 12)? + 4;
    msg.get(12..end)
}

/// 校验响应与查询匹配：ID 一致、QR 置位、Question 一致（域名大小写不敏感）。
fn validate_response(query: &[u8], resp: &[u8]) -> Result<()> {
    ensure!(resp.len() >= 12, "response too short ({} bytes)", resp.len());
    ensure!(resp[0..2] == query[0..2], "id mismatch");
    ensure!(resp[2] & 0x80 != 0, "not a response (QR=0)");
    match (question_bytes(query), question_bytes(resp)) {
        (Some(q), Some(r)) => ensure!(q.eq_ignore_ascii_case(r), "question mismatch"),
        // 某些服务器的 FORMERR 等错误响应不带 Question：仅在 rcode≠0 时放行。
        (Some(_), None) => ensure!(
            be16(resp, 4) == Some(0) && resp[3] & 0x0F != 0,
            "response question missing or malformed"
        ),
        (None, _) => {}
    }
    Ok(())
}

/// 查询 Additional 段里 OPT 记录声明的 EDNS UDP payload size。
fn edns_udp_size(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let (qd, an, ns, ar) = (
        be16(msg, 4)? as usize,
        be16(msg, 6)? as usize,
        be16(msg, 8)? as usize,
        be16(msg, 10)? as usize,
    );
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(msg, i)? + 4;
    }
    for _ in 0..(an + ns) {
        let n = skip_name(msg, i)?;
        i = n + 10 + be16(msg, n + 8)? as usize;
    }
    for _ in 0..ar {
        let n = skip_name(msg, i)?;
        if be16(msg, n)? == 41 {
            return Some(be16(msg, n + 2)? as usize);
        }
        i = n + 10 + be16(msg, n + 8)? as usize;
    }
    None
}

/// 构造 `host` 的 A / AAAA 查询（随机 ID，RD=1）。
fn build_query(host: &str, qtype: u16) -> Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    ensure!(!host.is_empty() && host.len() <= 253, "invalid dns name: {host}");
    let mut q = Vec::with_capacity(18 + host.len());
    q.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid dns label in {host}"
        );
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Ok(q)
}

/// 取响应 Answer 段中第一条 `qtype`（A/AAAA）记录，返回 (ip, ttl)。CNAME 链被自然跳过。
fn first_ip(msg: &[u8], qtype: u16) -> Option<(IpAddr, u32)> {
    let (qd, an) = (be16(msg, 4)? as usize, be16(msg, 6)? as usize);
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(msg, i)? + 4;
    }
    for _ in 0..an {
        let n = skip_name(msg, i)?;
        let typ = be16(msg, n)?;
        let ttl = u32::from_be_bytes(msg.get(n + 4..n + 8)?.try_into().ok()?);
        let rdlen = be16(msg, n + 8)? as usize;
        let rd = msg.get(n + 10..n + 10 + rdlen)?;
        if typ == qtype {
            match (qtype, rd.len()) {
                (QTYPE_A, 4) => {
                    return Some((IpAddr::from(<[u8; 4]>::try_from(rd).ok()?), ttl));
                }
                (QTYPE_AAAA, 16) => {
                    return Some((IpAddr::from(<[u8; 16]>::try_from(rd).ok()?), ttl));
                }
                _ => {}
            }
        }
        i = n + 10 + rdlen;
    }
    None
}