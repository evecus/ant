//! shadowquic 出站（JLS over QUIC）
//!
//! 协议参考 shadowquic 0.4.1：`msgs/squic.rs`（SQReq / SQUdpControlHeader /
//! SQPacketDatagramHeader）+ `squic/{mod,outbound}.rs`（TCP 走 bi stream、UDP
//! 走 datagram 或 uni stream）+ `shadowquic/quinn_wrapper/wrapper.rs`（JLS
//! QUIC client config）。
//!
//! 与 tuic / hysteria2 一样，QUIC endpoint 的 UDP socket 走
//! `sockopt::bind_udp`（SO_MARK + SO_BINDTODEVICE），避免出站流量回到 TUN
//! 形成回环。

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use quinn_jls::{
    ClientConfig, Connection, Endpoint, MtuDiscoveryConfig, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

// ── 协议常量 ─────────────────────────────────────────────────────────────────

/// `SQReq` 判别字（u8），shadowquic msgs/squic.rs
const SQ_CONNECT: u8 = 0x01;
const SQ_ASSOCIATE_OVER_DATAGRAM: u8 = 0x03;
const SQ_ASSOCIATE_OVER_STREAM: u8 = 0x04;

/// SOCKS5 地址类型（shadowquic msgs/socks5.rs）
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// QUIC 传输窗口与超时（与 tuic 出站保持一致）
const QUIC_STREAM_WINDOW: u64 = 8 * 1024 * 1024;
const QUIC_CONN_WINDOW: u64 = 15 * 1024 * 1024;
const IDLE_TIMEOUT_MS: u32 = 30_000;
const KEEP_ALIVE_SECS: u64 = 10;
const MAX_DATAGRAM_WINDOW: usize = 2 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(3);

/// UDP 会话的接收队列深度（满了丢弃，避免拖慢连接级 datagram 读循环）
const UDP_QUEUE: usize = 64;

// ── 目标地址编解码 ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Target {
    Domain(String, u16),
    Socket(SocketAddr),
}

impl Target {
    fn new(dst: SocketAddr, host: Option<&str>) -> Self {
        match host {
            Some(h) if !h.is_empty() => Target::Domain(
                h.to_string(),
                if dst.port() != 0 { dst.port() } else { 443 },
            ),
            _ => Target::Socket(dst),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Target::Domain(host, port) => {
                buf.put_u8(ATYP_DOMAIN);
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
                buf.put_u16(*port);
            }
            Target::Socket(addr) => match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(ATYP_V4);
                    buf.put_slice(&ip.octets());
                    buf.put_u16(addr.port());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(ATYP_V6);
                    buf.put_slice(&ip.octets());
                    buf.put_u16(addr.port());
                }
            },
        }
    }

    /// 异步解码（UDP 控制流）。
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let mut atyp = [0u8; 1];
        r.read_exact(&mut atyp).await?;
        match atyp[0] {
            ATYP_V4 => {
                let mut b = [0u8; 6];
                r.read_exact(&mut b).await?;
                let ip = IpAddr::from(<[u8; 4]>::try_from(&b[0..4]).unwrap());
                Ok(Target::Socket(SocketAddr::new(
                    ip,
                    u16::from_be_bytes([b[4], b[5]]),
                )))
            }
            ATYP_V6 => {
                let mut b = [0u8; 18];
                r.read_exact(&mut b).await?;
                let ip = IpAddr::from(<[u8; 16]>::try_from(&b[0..16]).unwrap());
                Ok(Target::Socket(SocketAddr::new(
                    ip,
                    u16::from_be_bytes([b[16], b[17]]),
                )))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                r.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                r.read_exact(&mut name).await?;
                let host = String::from_utf8(name)
                    .map_err(|_| io::Error::other("shadowquic: addr is not utf-8"))?;
                let mut port = [0u8; 2];
                r.read_exact(&mut port).await?;
                Ok(Target::Domain(host, u16::from_be_bytes(port)))
            }
            other => Err(io::Error::other(format!(
                "shadowquic: unknown addr type {other:#x}"
            ))),
        }
    }

    /// 转成 `SocketAddr`（域名退化为 `0.0.0.0:port`，与 tuic 一致）。
    fn socket_addr(&self) -> SocketAddr {
        match self {
            Target::Socket(a) => *a,
            // 服务端回传的源地址一定是 IP；这里只为满足 `recv_from` 的返回类型。
            Target::Domain(_, port) => SocketAddr::from(([0, 0, 0, 0], *port)),
        }
    }
}

/// `SQReq`：判别字 + 目标地址。
fn encode_req(cmd: u8, target: &Target) -> BytesMut {
    let mut buf = BytesMut::with_capacity(1 + 1 + 1 + 255 + 2);
    buf.put_u8(cmd);
    target.encode(&mut buf);
    buf
}

// ── 连接 ─────────────────────────────────────────────────────────────────────

/// 一条到 shadowquic 服务端的 QUIC 连接。
///
/// 上行（客户端→服务端）与下行（服务端→客户端）的 UDP id 空间是**独立**的
/// （shadowquic `SQConn.send_id_store` / `recv_id_store` 各有一个计数器）：
/// * 上行 id 由本端分配，经控制流 `SQUdpControlHeader` 告知服务端；
/// * 下行 id 由服务端分配，经同一条控制流回传，登记进 `id_src` 才能把
///   datagram 还原成 `(payload, src)`。
struct SqConn {
    quic: Connection,
    over_stream: bool,
    /// 上行 id 计数器（连接级，所有会话共享）
    next_id: AtomicU16,
    /// 下行 id → 服务端登记的源地址
    id_src: StdMutex<HashMap<u16, Target>>,
    /// 下行 id → UDP 会话的投递通道
    routes: StdMutex<HashMap<u16, mpsc::Sender<(Bytes, SocketAddr)>>>,
}

impl SqConn {
    fn new(quic: Connection, over_stream: bool) -> Arc<Self> {
        let conn = Arc::new(Self {
            quic,
            over_stream,
            next_id: AtomicU16::new(0),
            id_src: StdMutex::new(HashMap::new()),
            routes: StdMutex::new(HashMap::new()),
        });

        // ── QUIC datagram 读循环（over_stream 关闭时使用）───────────────────
        {
            let c = conn.clone();
            tokio::spawn(async move {
                while let Ok(data) = c.quic.read_datagram().await {
                    if data.len() < 2 {
                        continue;
                    }
                    let id = u16::from_be_bytes([data[0], data[1]]);
                    c.deliver(id, data.slice(2..));
                }
                tracing::debug!("shadowquic datagram loop end");
            });
        }

        // ── uni stream 读循环（over_stream 开启时承载 UDP 报文）──────────────
        // 服务端为每个源地址开一条 uni stream：开头是 `SQPacketDatagramHeader`
        // (id)，之后每包 `[len u16][payload]`。
        {
            let c = conn.clone();
            tokio::spawn(async move {
                while let Ok(mut stream) = c.quic.accept_uni().await {
                    let cc = c.clone();
                    tokio::spawn(async move {
                        let mut id_buf = [0u8; 2];
                        if stream.read_exact(&mut id_buf).await.is_err() {
                            return;
                        }
                        let id = u16::from_be_bytes(id_buf);
                        loop {
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                return;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut buf = BytesMut::with_capacity(len);
                            buf.resize(len, 0);
                            if stream.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                            cc.deliver(id, buf.freeze());
                        }
                    });
                }
                tracing::debug!("shadowquic uni-stream loop end");
            });
        }

        conn
    }

    /// 同步派发（不在 datagram 读循环里 `.await`，慢会话不会拖住整条连接）。
    fn deliver(&self, id: u16, payload: Bytes) {
        let src = self
            .id_src
            .lock()
            .unwrap()
            .get(&id)
            .map(|t| t.socket_addr())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let routes = self.routes.lock().unwrap();
        if let Some(tx) = routes.get(&id) {
            let _ = tx.try_send((payload, src));
        }
    }

    /// 登记下行 id（由会话的控制流任务调用）。
    fn register_down(&self, id: u16, src: Target, tx: mpsc::Sender<(Bytes, SocketAddr)>) {
        self.id_src.lock().unwrap().insert(id, src);
        self.routes.lock().unwrap().insert(id, tx);
    }

    fn unregister_down(&self, id: u16) {
        self.id_src.lock().unwrap().remove(&id);
        self.routes.lock().unwrap().remove(&id);
    }
}

// ── 出站 ─────────────────────────────────────────────────────────────────────

struct SqOption {
    server: String,
    port: u16,
    /// JLS 用户名（user_iv）
    username: String,
    /// JLS 密码（user_pwd）
    password: String,
    /// TLS SNI，必须与服务端 jls-upstream 的域名一致
    sni: String,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    congestion_control: String,
    over_stream: bool,
    zero_rtt: bool,
    initial_mtu: u16,
    min_mtu: u16,
    mtu_discovery: bool,
    keep_alive: Option<Duration>,
}

pub struct ShadowquicOutbound {
    opts: SqOption,
    endpoint: Endpoint,
    state: Mutex<ConnState>,
}

struct ConnState {
    conn: Option<Arc<SqConn>>,
    last_fail: Option<(Instant, String)>,
}

/// 解析 `heartbeat`（QUIC 层 keep_alive_interval）：`"10s"` / `"1500ms"` /
/// `"10"`（秒）；`"0"` / `"off"` 关闭。默认 10s，防止 idle timeout 拆连接。
fn parse_keep_alive(raw: &Option<String>) -> Result<Option<Duration>> {
    let Some(s) = raw else {
        return Ok(Some(Duration::from_secs(KEEP_ALIVE_SECS)));
    };
    let t = s.trim().to_lowercase();
    if t == "0" || t == "off" || t == "false" || t == "0s" {
        return Ok(None);
    }
    let (num, mul) = if let Some(n) = t.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('s') {
        (n, 1000)
    } else {
        (t.as_str(), 1000)
    };
    let ms: u64 = num.parse().map_err(|_| {
        anyhow!("shadowquic: invalid heartbeat {s:?} (expected e.g. \"10s\" or \"500ms\")")
    })?;
    anyhow::ensure!(ms * mul > 0, "shadowquic: heartbeat must be > 0");
    Ok(Some(Duration::from_millis(ms * mul)))
}

/// 校验 `congestion-control`（默认 bbr，与 shadowquic 一致），未知值 fail-fast。
fn validate_congestion_control(raw: &Option<String>) -> Result<String> {
    let s = raw.clone().unwrap_or_default().to_ascii_lowercase();
    match s.as_str() {
        "" | "bbr" => Ok("bbr".into()),
        "cubic" => Ok("cubic".into()),
        "new_reno" | "newreno" | "reno" => Ok("new_reno".into()),
        other => bail!("shadowquic: unknown congestion-control {other:?} (bbr | cubic | new_reno)"),
    }
}

impl ShadowquicOutbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        // JLS 的 SNI 必须是伪装域名（服务端 jls-upstream 的域名），退化成 IP
        // 会让服务端无法识别，因此要求显式配置 sni / servername。
        let sni = cfg
            .sni
            .clone()
            .or_else(|| cfg.servername.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "shadowquic: `sni` is required (must match the server's jls-upstream domain)"
                )
            })?;
        let username = cfg
            .username
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("shadowquic: `username` is required (JLS user iv)"))?;
        let password = cfg
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("shadowquic: `password` is required (JLS password)"))?;

        let opts = SqOption {
            server: cfg.server.clone(),
            port: cfg.port,
            username,
            password,
            sni,
            alpn: cfg.alpn.clone().unwrap_or_else(|| vec!["h3".into()]),
            skip_cert_verify: cfg.skip_cert_verify,
            fingerprint: cfg.fingerprint.clone(),
            congestion_control: validate_congestion_control(&cfg.congestion_control)?,
            over_stream: cfg.over_stream,
            zero_rtt: cfg.zero_rtt,
            initial_mtu: cfg.initial_mtu.unwrap_or(1300),
            min_mtu: cfg.min_mtu.unwrap_or(1290),
            mtu_discovery: !cfg.disable_mtu_discovery,
            keep_alive: parse_keep_alive(&cfg.heartbeat)?,
        };
        anyhow::ensure!(
            opts.min_mtu >= 1200 && opts.initial_mtu >= opts.min_mtu,
            "shadowquic: invalid mtu (initial-mtu {} must be >= min-mtu {} >= 1200)",
            opts.initial_mtu,
            opts.min_mtu
        );

        let client_config = build_quic_config(&opts)?;

        // ── 出站 socket 走 sockopt：SO_MARK + 绑定物理网卡（防回环）─────────
        // 与 tuic / hysteria2 完全相同的路径；shadowquic 的 QUIC endpoint 复用
        // 这一个 UDP socket 承载全部 TCP/UDP 流量。
        let udp = match crate::app::sockopt::bind_udp("[::]:0".parse().unwrap()).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(
                    "shadowquic: dual-stack udp bind failed ({e}); falling back to 0.0.0.0:0"
                );
                crate::app::sockopt::bind_udp("0.0.0.0:0".parse().unwrap()).await?
            }
        };
        let endpoint = Endpoint::new(
            quinn_jls::EndpointConfig::default(),
            None,
            udp.into_std()?,
            Arc::new(quinn_jls::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            opts,
            endpoint,
            state: Mutex::new(ConnState {
                conn: None,
                last_fail: None,
            }),
        })
    }

    async fn ensure_conn(&self) -> Result<Arc<SqConn>> {
        let mut guard = self.state.lock().await;
        if let Some(ref c) = guard.conn {
            if c.quic.close_reason().is_none() {
                return Ok(c.clone());
            }
            guard.conn = None;
        }

        if let Some((when, ref msg)) = &guard.last_fail {
            let elapsed = when.elapsed();
            if elapsed < RECONNECT_COOLDOWN {
                bail!(
                    "shadowquic unavailable (retry in {}ms): {}",
                    (RECONNECT_COOLDOWN - elapsed).as_millis(),
                    msg
                );
            }
        }

        match self.connect_once().await {
            Ok(conn) => {
                guard.conn = Some(conn.clone());
                guard.last_fail = None;
                Ok(conn)
            }
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!("shadowquic connect failed: {msg}");
                guard.last_fail = Some((Instant::now(), msg.clone()));
                Err(anyhow!(msg))
            }
        }
    }

    async fn connect_once(&self) -> Result<Arc<SqConn>> {
        let server_addr = resolve_server(&self.opts.server, self.opts.port).await?;
        tracing::debug!(
            "shadowquic connecting to {} (sni={}, alpn={:?}, cc={}, over-stream={})",
            server_addr,
            self.opts.sni,
            self.opts.alpn,
            self.opts.congestion_control,
            self.opts.over_stream
        );

        let connecting = self
            .endpoint
            .connect(server_addr, &self.opts.sni)
            .context("quic connect start")?;

        // 0-RTT：握手完成前即可发数据（shadowquic 默认开启）。JLS 校验结果在
        // 后台确认；无法 0-RTT 时退回普通 1-RTT 握手。
        let quic = if self.opts.zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, accepted)) => {
                    let c = conn.clone();
                    tokio::spawn(async move {
                        let ok = accepted.await;
                        tracing::debug!("shadowquic 0-rtt accepted: {ok}");
                        if c.is_jls() == Some(false) {
                            tracing::error!("shadowquic: JLS hijacked or wrong password/username");
                            c.close(0u8.into(), b"");
                        }
                    });
                    conn
                }
                Err(e) => e.await.context("quic handshake")?,
            }
        } else {
            tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
                .await
                .map_err(|_| {
                    anyhow!("quic handshake timeout ({}s)", HANDSHAKE_TIMEOUT.as_secs())
                })?
                .context("quic handshake")?
        };

        if quic.is_jls() == Some(false) {
            quic.close(0u8.into(), b"");
            bail!("shadowquic: JLS authentication failed (wrong password/username?)");
        }

        Ok(SqConn::new(quic, self.opts.over_stream))
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 域名：先走 bootstrap（default-nameserver），避免 DNS 回环把拨号卡死。
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ── TCP：bi stream + SQConnect ───────────────────────────────────────────────

pub struct SqTcpStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for SqTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for SqTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

// ── UDP：控制流 + datagram / uni stream ──────────────────────────────────────

/// 一个 UDP 关联（一次 `SQAssociat*` 请求 = 一条 bi stream 控制流）。
///
/// 上下行 id 空间独立，因此本会话分配的**上行** id 只记录在 `dst_ids` 里；
/// 服务端分配的**下行** id 通过控制流回传后登记到连接级 `SqConn`，并在会话
/// 结束时从 `down_ids` 回收。
struct SqUdpSession {
    conn: Arc<SqConn>,
    /// 控制流（bi stream 的发送半边）：新目的地址注册时写 `SQUdpControlHeader`
    ctrl: Mutex<SendStream>,
    /// 本会话的 目的地址 → 上行 id
    dst_ids: Mutex<HashMap<Target, u16>>,
    /// over_stream 模式：上行 id → uni stream
    uni: Mutex<HashMap<u16, SendStream>>,
    /// 服务端分配的下行 id（与控制流任务共享，会话结束时回收）
    down_ids: Arc<StdMutex<Vec<u16>>>,
    rx: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
}

impl SqUdpSession {
    /// 返回目的地址对应的上行 id；新地址时先写控制头再返回（顺序不可颠倒，
    /// 否则对端会收到无人认领的 datagram 并泄漏 id）。
    async fn id_for(&self, target: &Target) -> Result<u16> {
        let mut dst_ids = self.dst_ids.lock().await;
        if let Some(id) = dst_ids.get(target) {
            return Ok(*id);
        }
        let id = self.conn.next_id.fetch_add(1, Ordering::Relaxed);
        // `SQUdpControlHeader { dst, id }` — dst 在前，id 在后。
        let mut hdr = BytesMut::with_capacity(64);
        target.encode(&mut hdr);
        hdr.put_u16(id);
        self.ctrl
            .lock()
            .await
            .write_all(&hdr)
            .await
            .map_err(io::Error::other)
            .context("shadowquic udp control header")?;

        if self.conn.over_stream {
            let mut uni_stream = self
                .conn
                .quic
                .open_uni()
                .await
                .context("shadowquic open uni stream")?;
            // uni stream 开头先写 `SQPacketDatagramHeader { id }`
            uni_stream
                .write_all(&id.to_be_bytes())
                .await
                .map_err(io::Error::other)
                .context("shadowquic udp stream header")?;
            self.uni.lock().await.insert(id, uni_stream);
        }

        dst_ids.insert(target.clone(), id);
        Ok(id)
    }
}

#[async_trait]
impl UdpSession for SqUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let target = Target::new(dst, dst_host);
        let id = self.id_for(&target).await?;

        if self.conn.over_stream {
            // `[len u16][payload]`
            anyhow::ensure!(
                data.len() <= u16::MAX as usize,
                "shadowquic udp: packet too large ({})",
                data.len()
            );
            let mut buf = BytesMut::with_capacity(2 + data.len());
            buf.put_u16(data.len() as u16);
            buf.put_slice(data);
            let mut uni = self.uni.lock().await;
            let stream = uni
                .get_mut(&id)
                .ok_or_else(|| anyhow!("shadowquic udp: uni stream missing for id {id}"))?;
            stream
                .write_all(&buf)
                .await
                .map_err(io::Error::other)
                .context("shadowquic udp over stream")?;
            return Ok(());
        }

        // datagram：`SQPacketDatagramHeader { id }` + payload
        let Some(max) = self.conn.quic.max_datagram_size() else {
            bail!("shadowquic: server does not support QUIC datagrams");
        };
        anyhow::ensure!(
            2 + data.len() <= max,
            "shadowquic udp: packet too large ({} > {})",
            data.len(),
            max.saturating_sub(2)
        );
        let mut buf = BytesMut::with_capacity(2 + data.len());
        buf.put_u16(id);
        buf.put_slice(data);
        self.conn
            .quic
            .send_datagram(buf.freeze())
            .map_err(|e| anyhow!("shadowquic send datagram: {e}"))
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let (data, src) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("shadowquic udp session closed"))?;
        Ok((data.to_vec(), src))
    }
}

impl Drop for SqUdpSession {
    fn drop(&mut self) {
        // 回收服务端为本会话分配的下行 id（上行 id 只在本会话内，无需清理）。
        let ids: Vec<u16> = std::mem::take(&mut *self.down_ids.lock().unwrap());
        if ids.is_empty() {
            return;
        }
        for id in ids {
            self.conn.unregister_down(id);
        }
    }
}

// ── OutboundDialer ───────────────────────────────────────────────────────────

#[async_trait]
impl OutboundDialer for ShadowquicOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let conn = self.ensure_conn().await?;
        let (mut send, recv) = conn
            .quic
            .open_bi()
            .await
            .context("shadowquic open bi stream")?;
        // `SQReq::SQConnect(dst)`，之后就是裸数据双向流（服务端无响应头）。
        let req = encode_req(SQ_CONNECT, &Target::new(addr, host_hint));
        send.write_all(&req)
            .await
            .map_err(io::Error::other)
            .context("shadowquic send connect")?;
        Ok(Box::new(SqTcpStream { send, recv }))
    }

    async fn dial_udp(&self, local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let conn = self.ensure_conn().await?;
        let cmd = if conn.over_stream {
            SQ_ASSOCIATE_OVER_STREAM
        } else {
            SQ_ASSOCIATE_OVER_DATAGRAM
        };
        // 关联请求的 bind-addr：socks5 语义下为 0.0.0.0:0（服务端不据此限制）。
        let bind =
            Target::Socket(local_hint.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))));
        let (mut send, mut recv) = conn
            .quic
            .open_bi()
            .await
            .context("shadowquic open udp bi stream")?;
        let req = encode_req(cmd, &bind);
        send.write_all(&req)
            .await
            .map_err(io::Error::other)
            .context("shadowquic send associate")?;

        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        let down_ids = Arc::new(StdMutex::new(Vec::new()));
        let session = SqUdpSession {
            conn: conn.clone(),
            ctrl: Mutex::new(send),
            dst_ids: Mutex::new(HashMap::new()),
            uni: Mutex::new(HashMap::new()),
            down_ids: down_ids.clone(),
            rx: Mutex::new(rx),
        };
        let tracked = down_ids.clone();

        // ── 控制流接收 ─────────────────────────────────────────────────────
        // 服务端回的 `SQUdpControlHeader { dst, id }` 把下行 id 绑定到源地址，
        // 下行 datagram 才能还原成 `(payload, src)`。
        tokio::spawn(async move {
            loop {
                let dst = match Target::decode_async(&mut recv).await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!("shadowquic udp control stream end: {e}");
                        return;
                    }
                };
                let mut id_buf = [0u8; 2];
                if recv.read_exact(&mut id_buf).await.is_err() {
                    return;
                }
                let id = u16::from_be_bytes(id_buf);
                conn.register_down(id, dst, tx.clone());
                tracked.lock().unwrap().push(id);
            }
        });

        Ok(Box::new(session))
    }
}

// ── QUIC / JLS 配置 ──────────────────────────────────────────────────────────

/// rustls-jls 的证书校验器（与 hysteria2 的 `SkipServerVerification` 同语义，
/// 但 trait 来自 rustls-jls，不能复用）。
#[derive(Debug)]
struct JlsCertVerifier {
    skip: bool,
    fingerprint: Option<String>,
}

impl quinn_jls::rustls::client::danger::ServerCertVerifier for JlsCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &quinn_jls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[quinn_jls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &quinn_jls::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: quinn_jls::rustls::pki_types::UnixTime,
    ) -> Result<quinn_jls::rustls::client::danger::ServerCertVerified, quinn_jls::rustls::Error> {
        if let Some(ref fp) = self.fingerprint {
            let hash = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
            let hex_fp = hex::encode(hash.as_ref());
            if hex_fp.eq_ignore_ascii_case(fp) {
                return Ok(quinn_jls::rustls::client::danger::ServerCertVerified::assertion());
            }
            return Err(quinn_jls::rustls::Error::General(
                "certificate fingerprint mismatch".into(),
            ));
        }
        let _ = self.skip;
        Ok(quinn_jls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &quinn_jls::rustls::pki_types::CertificateDer<'_>,
        _dss: &quinn_jls::rustls::DigitallySignedStruct,
    ) -> Result<quinn_jls::rustls::client::danger::HandshakeSignatureValid, quinn_jls::rustls::Error>
    {
        Ok(quinn_jls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &quinn_jls::rustls::pki_types::CertificateDer<'_>,
        _dss: &quinn_jls::rustls::DigitallySignedStruct,
    ) -> Result<quinn_jls::rustls::client::danger::HandshakeSignatureValid, quinn_jls::rustls::Error>
    {
        Ok(quinn_jls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn_jls::rustls::SignatureScheme> {
        quinn_jls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造 QUIC client config：TLS(JLS) + 传输 + 拥塞控制。
fn build_quic_config(opts: &SqOption) -> Result<ClientConfig> {
    use quinn_jls::rustls::ClientConfig as RustlsClientConfig;

    let mut crypto = if opts.skip_cert_verify || opts.fingerprint.is_some() {
        RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(JlsCertVerifier {
                skip: opts.skip_cert_verify,
                fingerprint: opts.fingerprint.clone(),
            }))
            .with_no_client_auth()
    } else {
        // JLS 伪装的是真实站点，证书可被公开根校验（shadowquic 默认行为）。
        let root_store = quinn_jls::rustls::RootCertStore {
            roots: webpki_roots_jls::TLS_SERVER_ROOTS.to_vec(),
        };
        RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    crypto.alpn_protocols = opts.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    crypto.enable_early_data = opts.zero_rtt;
    // JLS：user_pwd = password，user_iv = username（shadowquic gen_client_cfg）
    crypto.jls_config = quinn_jls::rustls::jls::JlsClientConfig::new(&opts.password, &opts.username);

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(500u32.into());
    transport.max_concurrent_uni_streams(500u32.into());
    transport.stream_receive_window(VarInt::from_u64(QUIC_STREAM_WINDOW).unwrap());
    transport.receive_window(VarInt::from_u64(QUIC_CONN_WINDOW).unwrap());
    transport.send_window(QUIC_CONN_WINDOW);
    transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_WINDOW));
    transport.max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
    transport.keep_alive_interval(opts.keep_alive);
    transport.initial_mtu(opts.initial_mtu);
    transport.min_mtu(opts.min_mtu);
    transport.mtu_discovery_config(if opts.mtu_discovery {
        let mut d = MtuDiscoveryConfig::default();
        d.black_hole_cooldown(Duration::from_secs(120));
        d.interval(Duration::from_secs(90));
        Some(d)
    } else {
        None
    });

    let cc: Arc<dyn quinn_jls::congestion::ControllerFactory + Send + Sync> =
        match opts.congestion_control.as_str() {
            "bbr" => Arc::new(quinn_jls::congestion::BbrConfig::default()),
            "new_reno" => Arc::new(quinn_jls::congestion::NewRenoConfig::default()),
            _ => Arc::new(quinn_jls::congestion::CubicConfig::default()),
        };
    transport.congestion_controller_factory(cc);

    let mut client_config = ClientConfig::new(Arc::new(
        quinn_jls::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("build shadowquic quic client config")?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_addr_layout_v4() {
        let t = Target::Socket("1.2.3.4:53".parse().unwrap());
        let mut b = BytesMut::new();
        t.encode(&mut b);
        assert_eq!(b[0], ATYP_V4);
        assert_eq!(&b[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 53);
        assert_eq!(b.len(), 7);
    }

    #[test]
    fn socks_addr_layout_v6() {
        let t = Target::Socket("[2001:db8::1]:443".parse().unwrap());
        let mut b = BytesMut::new();
        t.encode(&mut b);
        assert_eq!(b[0], ATYP_V6);
        assert_eq!(b.len(), 19); // 1 + 16 + 2
        assert_eq!(u16::from_be_bytes([b[17], b[18]]), 443);
    }

    #[test]
    fn socks_addr_layout_domain() {
        let t = Target::Domain("example.com".into(), 443);
        let mut b = BytesMut::new();
        t.encode(&mut b);
        assert_eq!(b[0], ATYP_DOMAIN);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([b[13], b[14]]), 443);
        assert_eq!(b.len(), 15);
    }

    #[test]
    fn connect_req_layout() {
        let b = encode_req(SQ_CONNECT, &Target::Domain("example.com".into(), 443));
        assert_eq!(b[0], SQ_CONNECT);
        assert_eq!(b[1], ATYP_DOMAIN);
        assert_eq!(b[2], 11);
        assert_eq!(&b[3..14], b"example.com");
        assert_eq!(u16::from_be_bytes([b[14], b[15]]), 443);
    }

    #[tokio::test]
    async fn decode_async_roundtrip() {
        for t in [
            Target::Socket("1.2.3.4:53".parse().unwrap()),
            Target::Socket("[2001:db8::1]:443".parse().unwrap()),
            Target::Domain("example.com".into(), 443),
        ] {
            let mut b = BytesMut::new();
            t.encode(&mut b);
            let mut cur = std::io::Cursor::new(b.to_vec());
            let got = Target::decode_async(&mut cur).await.unwrap();
            assert_eq!(got, t);
        }
    }

    #[test]
    fn keep_alive_parse() {
        assert_eq!(
            parse_keep_alive(&None).unwrap(),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_keep_alive(&Some("10s".into())).unwrap(),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_keep_alive(&Some("500ms".into())).unwrap(),
            Some(Duration::from_millis(500))
        );
        assert_eq!(parse_keep_alive(&Some("off".into())).unwrap(), None);
        assert!(parse_keep_alive(&Some("abc".into())).is_err());
    }

    #[test]
    fn congestion_control_validate() {
        assert_eq!(validate_congestion_control(&None).unwrap(), "bbr");
        assert_eq!(
            validate_congestion_control(&Some("CUBIC".into())).unwrap(),
            "cubic"
        );
        assert!(validate_congestion_control(&Some("vegas".into())).is_err());
    }
}
