//! spectre 出站（QUIC + JLS 伪装 + Brutal 拥塞控制）。
//!
//! 协议参考 spectre-master：`PROTOCOL.md` + `src/protocol`（线格式 / Brutal /
//! UDP 分片）+ `src/client/mod.rs`（`proxy_via_spectre*` 出站路径）。
//! 线格式与拥塞控制分别在本目录 `spectre_wire.rs` / `spectre_brutal.rs`。
//!
//! 与 ant 其他 QUIC 出站（tuic / hysteria2 / shadowquic）一致：
//! QUIC endpoint 的 UDP socket 走 `app::sockopt::bind_udp`（SO_MARK +
//! 绑定物理网卡），出站流量不会回到 TUN 形成回环。
//!
//! ## 握手流程
//!
//! 1. QUIC 连接（TLS ClientHello/ServerHello 内嵌 JLS 认证材料，ALPN `h3`，
//!    SNI = 伪装域名）。JLS 失败时 quinn-jls 会把流量转发给伪装目标，
//!    `is_jls()` 返回 `Some(false)`/`None` —— 此时必须放弃，凭据不会明文外泄。
//! 2. 首条 bi stream 发 `AUTH`（用户名 / 密码 / rx_bps / tx_bps + padding），
//!    服务端回 `AuthResponse`。
//! 3. 之后每条 TCP 请求开一条 bi stream：`TCP_CONNECT`（地址 + padding）→
//!    状态响应 → 纯双向字节流。
//! 4. UDP 走 QUIC datagram：`[session_id][packet_id][frag][frag_count][addr]
//!    [payload]`，大包分片、接收侧重组，按 session_id 路由到会话。
//! 5. Brutal：客户端发送端按 `up`（tx_bps）发包，服务端发送端按 AUTH 里声明
//!    的 `down`（rx_bps）发包；0 = 交回 BBR。

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use crate::outbound::spectre_brutal::{parse_rate, tune_transport, BrutalHandle};
use crate::outbound::spectre_wire::{
    fragment_udp, jittered_interval, random_padding, Address, AuthRequest, AuthResponse,
    FragmentReassembler, PaddingFrame, TcpConnectRequest, TcpConnectResponse, WireError,
    AUTH_PADDING, DEFAULT_MAX_DATAGRAM_PAYLOAD, TCP_REQUEST_PADDING,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use quinn_jls::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt,
};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// 与 tuic / hysteria2 一致。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 连接失败后的重连冷却（避免每次拨号都触发一次完整握手）。
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(3);
/// padding keepalive 基础间隔（参考实现 `spawn_padding_keepalive`：20s +
/// 50% 抖动 → 实际 20~30s）。
const KEEPALIVE_BASE: Duration = Duration::from_secs(20);
const KEEPALIVE_JITTER: f64 = 0.5;
/// idle timeout。参考实现用 quinn 默认 30s，与最大 30s 的保活间隔赛跑；
/// 这里放到 60s，给保活留 2 倍余量。
const IDLE_TIMEOUT_MS: u32 = 60_000;
/// UDP 会话接收队列深度（满了丢弃，避免拖慢连接级 datagram 读循环）。
const UDP_QUEUE: usize = 64;
/// AUTH / TCP 响应解码上限：字段均为 u16 长度，最大值约 128 KiB。
const MAX_AUTH_RESP: usize = 132 * 1024;
const MAX_TCP_RESP: usize = 132 * 1024;

// ── 选项 ─────────────────────────────────────────────────────────────────────

struct SpOption {
    server: String,
    port: u16,
    /// JLS user iv（AUTH 请求里的 username，必须与服务端一致）。
    username: String,
    /// JLS password（AUTH 请求里的 password，必须与服务端一致）。
    password: String,
    /// TLS SNI，必须等于服务端的伪装域名（jls-upstream）。
    sni: String,
    /// 上传目标速率（字节/秒）。客户端发送端 Brutal 用；0 = BBR。
    tx_bps: u64,
    /// 下载速率声明（字节/秒）。AUTH 时告知服务端，服务端发送端用它；0 = auto。
    rx_bps: u64,
}

/// 解析可选的速率字段（`up` / `down`）：缺省 / 空 → 0（关闭 Brutal / auto），
/// 非法值 fail-fast。语法同参考实现 `parse_rate`：`100mbps` / `12500000`。
fn parse_opt_rate(raw: &Option<String>) -> Result<u64> {
    match raw {
        Some(s) if !s.trim().is_empty() => {
            parse_rate(s).map_err(|e| anyhow!("spectre: {e}"))
        }
        _ => Ok(0),
    }
}

// ── 连接 ─────────────────────────────────────────────────────────────────────

/// 一条已完成 AUTH 的 spectre QUIC 连接。
struct SpConn {
    quic: Connection,
    /// 服务端是否支持 QUIC datagram（UDP 前提）。
    datagram_supported: bool,
    /// UDP 分片上限。
    udp_mtu: usize,
    /// session_id → 该 UDP 会话的入站投递通道。
    udp_sessions: StdMutex<HashMap<u32, mpsc::Sender<(Bytes, SocketAddr)>>>,
}

// ── 出站 ─────────────────────────────────────────────────────────────────────

pub struct SpectreOutbound {
    opts: SpOption,
    endpoint: Endpoint,
    state: Mutex<ConnState>,
    next_session_id: AtomicU32,
}

struct ConnState {
    conn: Option<Arc<SpConn>>,
    last_fail: Option<(std::time::Instant, String)>,
}

impl SpectreOutbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        // SNI 必须是伪装域名（服务端 jls-upstream 的域名）：JLS 校验要求
        // ClientHello 的 SNI 与服务端配置一致，退化成 IP 会认证失败。
        let sni = cfg
            .sni
            .clone()
            .or_else(|| cfg.servername.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!("spectre: `sni` is required (must match the server's camouflage domain)")
            })?;
        let username = cfg
            .username
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("spectre: `username` is required (JLS user iv)"))?;
        let password = cfg
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("spectre: `password` is required (JLS password)"))?;

        let opts = SpOption {
            server: cfg.server.clone(),
            port: cfg.port,
            username,
            password,
            sni,
            tx_bps: parse_opt_rate(&cfg.up)?,
            rx_bps: parse_opt_rate(&cfg.down)?,
        };

        let client_config = build_quic_config(&opts)?;

        // 出站 socket 走 sockopt：SO_MARK + 绑定物理网卡（防回环）。
        // 与 tuic / hysteria2 / shadowquic 完全相同的路径。
        let udp = match crate::app::sockopt::bind_udp("[::]:0".parse().unwrap()).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(
                    "spectre: dual-stack udp bind failed ({e}); falling back to 0.0.0.0:0"
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
            next_session_id: AtomicU32::new(1),
        })
    }

    async fn ensure_conn(&self) -> Result<Arc<SpConn>> {
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
                    "spectre unavailable (retry in {}ms): {}",
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
                tracing::warn!("spectre connect failed: {msg}");
                guard.last_fail = Some((std::time::Instant::now(), msg.clone()));
                Err(anyhow!(msg))
            }
        }
    }

    async fn connect_once(&self) -> Result<Arc<SpConn>> {
        let server_addr = resolve_server(&self.opts.server, self.opts.port).await?;
        tracing::debug!(
            "spectre connecting to {} (sni={}, tx={} B/s, rx={} B/s)",
            server_addr,
            self.opts.sni,
            self.opts.tx_bps,
            self.opts.rx_bps
        );

        let connecting = self
            .endpoint
            .connect(server_addr, &self.opts.sni)
            .context("quic connect start")?;
        let quic = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("quic handshake timeout ({}s)", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("quic handshake")?;

        // JLS 认证失败（错误密码 / 错误 SNI / 非 spectre 服务端）时，
        // quinn-jls 会把后续流量转发给伪装目标，is_jls() 不会返回 Some(true)。
        if quic.is_jls() != Some(true) {
            quic.close(0u8.into(), b"");
            bail!("spectre: JLS authentication failed (wrong password/username/server-name?)");
        }

        self.auth(&quic).await?;

        let datagram_supported = quic.max_datagram_size().is_some();
        // UDP 分片上限：参考实现的 1200，再按对端协商的 datagram 上限收紧。
        let udp_mtu = DEFAULT_MAX_DATAGRAM_PAYLOAD
            .min(quic.max_datagram_size().unwrap_or(DEFAULT_MAX_DATAGRAM_PAYLOAD));
        let conn = Arc::new(SpConn {
            quic: quic.clone(),
            datagram_supported,
            udp_mtu,
            udp_sessions: StdMutex::new(HashMap::new()),
        });

        spawn_datagram_reader(conn.clone());
        spawn_padding_keepalive(conn.quic.clone());
        Ok(conn)
    }

    /// AUTH 握手：首条 bi stream，`AUTH` 请求 → `AuthResponse`。
    async fn auth(&self, conn: &Connection) -> Result<()> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("spectre open auth stream")?;
        let req = AuthRequest {
            username: self.opts.username.clone(),
            password: self.opts.password.clone(),
            rx_bps: self.opts.rx_bps,
            tx_bps: self.opts.tx_bps,
            padding: random_padding(AUTH_PADDING),
        };
        // 一次性 write_all：参考服务端用单次 read() 收整个 AUTH 帧再解码，
        // 分多次写有被判为残帧的风险。
        send
            .write_all(&req.encode())
            .await
            .map_err(io::Error::other)
            .context("spectre auth send")?;
        let (resp, _extra) =
            read_decode_remain::<AuthResponse>(&mut recv, MAX_AUTH_RESP).await?;
        if !resp.ok {
            bail!("spectre auth rejected: {}", resp.message);
        }
        tracing::debug!(
            "spectre auth ok (server rx={} B/s, tx={} B/s)",
            resp.rx_bps,
            resp.tx_bps
        );
        Ok(())
    }
}

// ── QUIC datagram 读循环（连接级） ───────────────────────────────────────────

/// 一个任务读完连接上所有 QUIC datagram：重组 → 按 session_id 路由。
/// 路由是同步的（std mutex + try_send），慢会话不会拖住读循环。
fn spawn_datagram_reader(conn: Arc<SpConn>) {
    tokio::spawn(async move {
        let mut reasm = FragmentReassembler::new();
        while let Ok(data) = conn.quic.read_datagram().await {
            match reasm.push(data) {
                Ok(Some((sid, addr, payload))) => {
                    let src = addr
                        .to_socket_addr()
                        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], addr.port)));
                    let sessions = conn.udp_sessions.lock().unwrap();
                    if let Some(tx) = sessions.get(&sid) {
                        let _ = tx.try_send((payload, src));
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::debug!("spectre udp reassembly: {e}"),
            }
        }
        tracing::debug!("spectre datagram loop end");
    });
}

// ── padding keepalive ────────────────────────────────────────────────────────

/// 用小的、不定长、不定时的 padding 流让连接保持繁忙，而不是只依赖 QUIC 自带
/// 的固定间隔 PING —— 恒定尺寸/恒定周期的保活本身就是可被被动分类器利用的
/// 时序指纹（参考实现 `spawn_padding_keepalive` 的注释）。连接断开时任务静默
/// 退出。
fn spawn_padding_keepalive(conn: Connection) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(jittered_interval(KEEPALIVE_BASE, KEEPALIVE_JITTER)).await;
            let Ok((mut send, mut recv)) = conn.open_bi().await else {
                break; // 连接已断开
            };
            let frame = PaddingFrame::random();
            if send.write_all(&frame.encode()).await.is_err() {
                break;
            }
            let _ = send.finish();
            // 读掉回包后丢弃流。quinn 的 RecvStream::read 是固有方法，
            // 返回 `io::Result<Option<usize>>`（None = 流结束）。
            let mut sink = [0u8; 64];
            while matches!(recv.read(&mut sink).await, Ok(Some(n)) if n > 0) {}
        }
    });
}

// ── 响应读取 ─────────────────────────────────────────────────────────────────

/// 可从字节缓冲解码的 spectre 响应帧（AUTH / TCP_CONNECT 响应）。
///
/// 用 trait 而不是传 `fn` 闭包：解码函数对 `Buf` 类型是泛型的，作为值传入时
/// 生命周期会被固定，触发 "implementation of `Fn` is not general enough"。
trait DecodeFrame: Sized {
    fn decode_frame(buf: &mut &[u8]) -> Result<Self, WireError>;
}

impl DecodeFrame for AuthResponse {
    fn decode_frame(buf: &mut &[u8]) -> Result<Self, WireError> {
        AuthResponse::decode(buf)
    }
}

impl DecodeFrame for TcpConnectResponse {
    fn decode_frame(buf: &mut &[u8]) -> Result<Self, WireError> {
        TcpConnectResponse::decode(buf)
    }
}

/// 从 `recv` 累积读取直到帧解码成功，返回解码值**以及响应之后的多余字节**。
///
/// 不能像参考客户端那样单次 `read()` 后整体解码：QUIC stream 不保证消息边界，
/// 一次 read 可能只拿到半个帧（需要续读），也可能把服务端的首批业务数据和
/// 响应拼在一段里（多余字节必须留给上层，不能丢）。
async fn read_decode_remain<T: DecodeFrame>(
    recv: &mut RecvStream,
    max_total: usize,
) -> Result<(T, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    loop {
        if !buf.is_empty() {
            let mut slice: &[u8] = &buf;
            match T::decode_frame(&mut slice) {
                Ok(v) => {
                    let consumed = buf.len() - slice.len();
                    return Ok((v, buf[consumed..].to_vec()));
                }
                Err(WireError::BufferTooShort) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // quinn 的 RecvStream::read 是固有方法，返回 Option（None = 流结束）。
        let Some(n) = recv.read(&mut chunk).await? else {
            bail!("spectre: stream closed before a complete response");
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_total {
            bail!("spectre: response too large (>{max_total} bytes)");
        }
    }
}

// ── TCP ──────────────────────────────────────────────────────────────────────

pub struct SpTcpStream {
    send: SendStream,
    recv: RecvStream,
    /// 读取连接响应时多读到的字节（服务端响应与首批数据可能同一段到达）。
    pending: Vec<u8>,
}

impl AsyncRead for SpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for SpTcpStream {
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
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ── UDP ──────────────────────────────────────────────────────────────────────

struct SpUdpSession {
    conn: Arc<SpConn>,
    session_id: u32,
    pkt_id: AtomicU16,
    rx: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
}

#[async_trait]
impl UdpSession for SpUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let host = match dst_host {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => dst.ip().to_string(),
        };
        let port = if dst.port() != 0 { dst.port() } else { 443 };
        let addr = Address::new(host, port);
        let pid = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        for frame in fragment_udp(self.session_id, pid, &addr, data, self.conn.udp_mtu) {
            self.conn
                .quic
                .send_datagram(frame)
                .map_err(|e| anyhow!("spectre send datagram: {e}"))?;
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let (data, src) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("spectre udp session closed"))?;
        Ok((data.to_vec(), src))
    }
}

impl Drop for SpUdpSession {
    fn drop(&mut self) {
        self.conn.udp_sessions.lock().unwrap().remove(&self.session_id);
    }
}

// ── OutboundDialer ───────────────────────────────────────────────────────────

#[async_trait]
impl OutboundDialer for SpectreOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let conn = self.ensure_conn().await?;
        let (mut send, mut recv) = conn
            .quic
            .open_bi()
            .await
            .context("spectre open bi stream")?;
        let host = match host_hint {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => addr.ip().to_string(),
        };
        let port = if addr.port() != 0 { addr.port() } else { 443 };
        let req = TcpConnectRequest {
            address: Address::new(host.clone(), port),
            padding: random_padding(TCP_REQUEST_PADDING),
        };
        send
            .write_all(&req.encode())
            .await
            .map_err(io::Error::other)
            .context("spectre send connect")?;
        let (resp, pending) =
            read_decode_remain::<TcpConnectResponse>(&mut recv, MAX_TCP_RESP).await?;
        if !resp.ok {
            bail!("spectre connect failed for {host}:{port}: {}", resp.message);
        }
        Ok(Box::new(SpTcpStream {
            send,
            recv,
            pending,
        }))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let conn = self.ensure_conn().await?;
        if !conn.datagram_supported {
            bail!("spectre: server does not support QUIC datagrams (UDP unavailable)");
        }
        // 注意：参考实现的 UDP_ASSOCIATE 控制流是可选项（PROTOCOL.md：optional
        // for the first version），数据面直接走 datagram，这里不额外开控制流。
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        conn.udp_sessions.lock().unwrap().insert(session_id, tx);
        Ok(Box::new(SpUdpSession {
            conn,
            session_id,
            pkt_id: AtomicU16::new(0),
            rx: Mutex::new(rx),
        }))
    }
}

// ── 辅助 ─────────────────────────────────────────────────────────────────────

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 域名：走 bootstrap（default-nameserver），避免 DNS 回环把拨号卡死。
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ── QUIC / JLS 配置 ──────────────────────────────────────────────────────────

/// 构造 QUIC client config：TLS(JLS) + 传输参数 + Brutal 拥塞控制。
fn build_quic_config(opts: &SpOption) -> Result<ClientConfig> {
    use quinn_jls::rustls::ClientConfig as RustlsClientConfig;

    // 空根证书库是有意为之（参考实现 `configure_client` 的注释）：
    //   * 真 spectre 服务端：JLS 通过 ServerHello.random 完成认证，
    //     rustls-jls 跳过证书链与签名校验（服务端用自签证书即可，无需 CA）。
    //   * 其他（MITM / 错误服务端 / 探测目标）：JLS 认证失败，普通校验对着
    //     零个信任根必然拒绝握手，凭据不会发送过去。
    let roots = quinn_jls::rustls::RootCertStore::empty();
    let mut crypto = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // JLS：user_pwd = password，user_iv = username（必须与服务端一致）。
    crypto.jls_config =
        quinn_jls::rustls::jls::JlsClientConfig::new(&opts.password, &opts.username);
    // 与浏览器相同：spectre 服务端只提供 h3（PROTOCOL.md：ALPN is h3 only）。
    // 自定义 ALPN 会暴露在任何人可解密的 QUIC Initial 里。
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    transport.max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
    // 客户端→服务端 = 客户端上传：按 tx_bps（`up`）发送。
    // 服务端→客户端由服务端按 AUTH 声明的 rx_bps（`down`）发送。
    tune_transport(&mut transport, BrutalHandle::new(opts.tx_bps));

    let quic_crypto = quinn_jls::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("build spectre quic client config")?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_rate_parse() {
        assert_eq!(parse_opt_rate(&Some("50mbps".into())).unwrap(), 50_000_000 / 8);
        assert_eq!(parse_opt_rate(&Some("12500000".into())).unwrap(), 12_500_000);
        assert_eq!(parse_opt_rate(&Some("0".into())).unwrap(), 0);
        assert_eq!(parse_opt_rate(&Some("".into())).unwrap(), 0);
        assert_eq!(parse_opt_rate(&None).unwrap(), 0);
        assert!(parse_opt_rate(&Some("fast".into())).is_err());
    }

    /// 构造一个最小 ProxyConfig 走 `new()` 的校验分支（不发网络）。
    fn cfg(ty: &str) -> ProxyConfig {
        ProxyConfig {
            name: "t".into(),
            ty: ty.into(),
            server: "1.2.3.4".into(),
            port: 4433,
            ..crate::app::provider_link::blank()
        }
    }

    #[tokio::test]
    async fn new_requires_sni_username_password() {
        let mut c = cfg("spectre");
        c.username = Some("u".into());
        c.password = Some("p".into());
        // 缺 sni → fail-fast
        assert!(SpectreOutbound::new(&c).await.is_err());

        c.sni = Some("www.example.com".into());
        // 缺 username
        let mut c2 = c.clone();
        c2.username = None;
        assert!(SpectreOutbound::new(&c2).await.is_err());
        // 缺 password
        let mut c3 = c.clone();
        c3.password = None;
        assert!(SpectreOutbound::new(&c3).await.is_err());

        // 非法速率 → fail-fast
        let mut c4 = c.clone();
        c4.up = Some("fast".into());
        assert!(SpectreOutbound::new(&c4).await.is_err());

        // 完整配置：构造成功（endpoint 绑定本地 UDP，无网络 IO）
        c.up = Some("50mbps".into());
        c.down = Some("200mbps".into());
        assert!(SpectreOutbound::new(&c).await.is_ok());
    }
}
