//! Trojan outbound — protocol aligned with trojan-go / sing-box / reflex.
//!
//! Transports: `tcp` | `ws` | `xhttp`; TLS layers: plain TLS (rustls) or uTLS
//! browser fingerprint (`client-fingerprint`).
//!
//! * tcp: header written eagerly after (optional) TLS handshake. The Trojan
//!   protocol has **no response header** — the server starts streaming target
//!   data right after the handshake.
//! * ws / xhttp: the Trojan header is merged into the first upstream write
//!   (same as reflex / sing-box).
//!
//! Request: `[SHA224(password) hex 56B][CRLF][CMD 1B][socks addr][CRLF]`
//! UDP over TCP: handshake with CMD=0x03, then per-packet frames
//! `[socks addr][LEN 2B BE][CRLF 2B][DATA]`.
//!
//! All dial sockets go through `crate::app::sockopt::connect_tcp`, so the
//! global `mark` (SO_MARK / interface binding) applies exactly like the
//! vless / direct outbounds — TUN loop prevention works out of the box.

use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint, UtlsVerify};
use super::vless::{build_tls_client_config, XhttpResolved};
use super::ws::{self, WsOptions, WsStream, WS_HANDSHAKE_TIMEOUT};
use super::xhttp::connect_over_stream;
use super::xhttp::XhttpConfig;
use super::xhttp_h2;
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;

const TROJAN_KEY_LEN: usize = 56; // hex(SHA-224) ASCII length
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const MAX_UDP_PAYLOAD: usize = 65535;

/// SHA-224(password) → hex → 56-byte ASCII key (trojan-go / sing-box `Key()`).
fn derive_key(password: &str) -> [u8; TROJAN_KEY_LEN] {
    let hash = Sha224::digest(password.as_bytes());
    let hex = hex::encode(hash);
    let mut key = [0u8; TROJAN_KEY_LEN];
    key.copy_from_slice(hex.as_bytes());
    key
}

#[derive(Clone)]
struct TrojanOption {
    server: String,
    port: u16,
    /// Precomputed 56-byte hex key (SHA-224 of the password).
    key: [u8; TROJAN_KEY_LEN],
    network: String,
    tls: bool,
    sni: String,
    ws_path: String,
    ws_host: String,
    /// true when the user set ws-host explicitly (Host header is then sent verbatim).
    ws_host_explicit: bool,
    ws_headers: Vec<(String, String)>,
    /// uTLS browser fingerprint (`client-fingerprint`).
    utls: Option<UtlsFingerprint>,
    /// uTLS 自实现握手的证书校验选项（skip-cert-verify / 证书 pin）。
    verify: UtlsVerify,
    /// Set when network == "xhttp".
    xhttp: Option<XhttpConfig>,
    /// xhttp 运行模式（`auto` 已在此处展开）。
    xhttp_resolved: XhttpResolved,
    /// 传给 rustls ClientConfig 与伪造 ClientHello 的有效 ALPN（二者必须一致）。
    tls_alpn: Vec<String>,
    /// xhttp packet-up / stream-up 用的 TLS 配置（ALPN 强制 h2）。
    xhttp_h2_tls: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Clone)]
pub struct TrojanOutbound {
    opts: TrojanOption,
    /// Plain-rustls client config（普通 TLS 与 uTLS 共用）。
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl TrojanOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let password = cfg
            .password
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .context("trojan requires a non-empty `password`")?;
        let sni = cfg.effective_sni();
        let ws_host_explicit = cfg.ws_host.is_some();
        let ws_host = cfg.ws_host.clone().unwrap_or_else(|| sni.clone());
        let mut ws_path = cfg.ws_path.clone().unwrap_or_else(|| "/".into());
        if !ws_path.starts_with('/') {
            ws_path.insert(0, '/');
        }
        let ws_headers = cfg
            .ws_headers
            .clone()
            .map(|m| m.into_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let alpn = cfg.alpn.clone().unwrap_or_default();
        let network = cfg.network.to_lowercase();

        // uTLS 浏览器指纹（client-fingerprint），未知值 fail-fast。
        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s).with_context(|| {
                    format!(
                        "trojan `{}`: unknown client-fingerprint {s:?} \
                         (supported: chrome/firefox/safari/edge/ios/android/360/qq/random)",
                        cfg.name
                    )
                })
            })
            .transpose()?;
        if utls.is_some() && !cfg.tls {
            tracing::warn!(
                "trojan `{}`: client-fingerprint set but tls is disabled — no effect",
                cfg.name
            );
        }

        // xhttp 运行模式解析（对齐 Xray dialer.go：auto → packet-up；无 REALITY）。
        let (xhttp, xhttp_resolved) = if network == "xhttp" {
            let host = cfg
                .xhttp_host
                .clone()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| sni.clone());
            let mut path = cfg.xhttp_path.clone().unwrap_or_else(|| "/".into());
            if !path.starts_with('/') {
                path.insert(0, '/');
            }
            let raw_mode = cfg
                .xhttp_mode
                .as_ref()
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
                .unwrap_or("auto");
            let resolved = match raw_mode {
                "auto" | "packet-up" => XhttpResolved::PacketUp,
                "stream-up" => XhttpResolved::StreamUp,
                "stream-one" => XhttpResolved::StreamOne,
                other => bail!(
                    "trojan `{}`: unknown xhttp-mode {other:?} \
                     (supported: auto/packet-up/stream-up/stream-one)",
                    cfg.name
                ),
            };
            (
                Some(XhttpConfig {
                    host,
                    path,
                    mode: raw_mode.to_string(),
                    headers: cfg.xhttp_headers.clone().unwrap_or_default(),
                }),
                resolved,
            )
        } else {
            (None, XhttpResolved::StreamOne)
        };

        let mut opts = TrojanOption {
            server: cfg.server.clone(),
            port: cfg.port,
            key: derive_key(password),
            network,
            tls: cfg.tls,
            sni: sni.clone(),
            ws_path,
            ws_host,
            ws_host_explicit,
            ws_headers,
            utls,
            verify: UtlsVerify {
                skip_cert_verify: cfg.skip_cert_verify,
                fingerprint: None,
            },
            xhttp,
            xhttp_resolved,
            tls_alpn: Vec::new(),
            xhttp_h2_tls: None,
        };

        // 有效 ALPN：伪造 ClientHello 的 ALPN 必须与 rustls config 一致。
        // ws / xhttp stream-one upgrade 走 HTTP/1.1：强制 http/1.1；
        // tcp(+utls) 未配置 ALPN 时用浏览器默认 [h2, http/1.1]。
        if opts.tls {
            let force_http11 = opts.network == "ws"
                || (opts.network == "xhttp" && opts.xhttp_resolved == XhttpResolved::StreamOne);
            let effective_alpn: Vec<String> = if force_http11 {
                vec!["http/1.1".to_string()]
            } else if !alpn.is_empty() {
                alpn.clone()
            } else if opts.utls.is_some() {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                Vec::new()
            };

            let client_config = Arc::new(build_tls_client_config(
                cfg.skip_cert_verify,
                &effective_alpn,
                None,
            )?);

            // xhttp packet-up / stream-up：独立的 h2 TLS 配置（ALPN 强制 h2，
            // 对齐 Xray downloadSettings.streamSettings 必须为 h2）。
            opts.xhttp_h2_tls = if opts.network == "xhttp"
                && opts.xhttp_resolved != XhttpResolved::StreamOne
            {
                Some(Arc::new(build_tls_client_config(
                    cfg.skip_cert_verify,
                    &["h2".to_string()],
                    None,
                )?))
            } else {
                None
            };

            opts.tls_alpn = effective_alpn;
            Ok(Self {
                opts,
                tls_config: Some(client_config),
            })
        } else {
            Ok(Self {
                opts,
                tls_config: None,
            })
        }
    }

    async fn connect_raw(&self) -> Result<TcpStream> {
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let s = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("trojan tcp connect {addr}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// 建立 rustls TLS 层（普通 rustls 或 uTLS 浏览器指纹）。
    async fn connect_tls_layer(&self, stream: TcpStream) -> Result<TlsStreamBox> {
        let cfg = self
            .tls_config
            .as_ref()
            .context("tls not configured")?;
        match self.opts.utls {
            Some(fp) => {
                // 伪造 ClientHello 的 ALPN 与 rustls config 一致（见 new()）。
                Ok(TlsStreamBox::Utls(Box::new(
                    connect_utls(
                        stream,
                        &self.opts.sni,
                        &fp,
                        &self.opts.verify,
                        &self.opts.tls_alpn,
                    )
                    .await
                    .context("trojan utls handshake")?,
                )))
            }
            None => {
                let name = ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("invalid sni {}", self.opts.sni))?;
                Ok(TlsStreamBox::Plain(
                    TlsConnector::from(cfg.clone())
                        .connect(name, stream)
                        .await
                        .context("trojan tls handshake")?,
                ))
            }
        }
    }

    /// TCP → (TLS, ALPN http/1.1) → WebSocket upgrade (see `super::ws`).
    async fn connect_ws(&self) -> Result<WebSocketStream<BoxedStream>> {
        let tcp = self.connect_raw().await?;
        let io: BoxedStream = if self.opts.tls {
            Box::new(self.connect_tls_layer(tcp).await?)
        } else {
            Box::new(tcp)
        };
        let ws_opts = WsOptions {
            host: self.opts.ws_host.clone(),
            host_explicit: self.opts.ws_host_explicit,
            port: self.opts.port,
            tls: self.opts.tls,
            path: self.opts.ws_path.clone(),
            headers: self.opts.ws_headers.clone(),
        };
        ws::connect(io, &ws_opts)
            .await
            .map_err(|e| anyhow!("trojan {e}"))
    }

    /// Open the underlying transport and send the Trojan request header.
    ///
    /// Trojan has no server response header, so the stream is returned right
    /// after the request is on the wire. For ws / xhttp the header is merged
    /// into the first upstream write (same as reflex / sing-box).
    async fn open_trojan(
        &self,
        host_hint: Option<&str>,
        addr: SocketAddr,
        cmd: u8,
    ) -> Result<BoxedStream> {
        let header = build_trojan_header(&self.opts.key, host_hint, addr, cmd);

        // XHTTP：stream-one 走手写 HTTP/1.1 单 POST 双向流；
        // packet-up / stream-up 走 hyper 客户端（TLS 时 ALPN 强制 h2）。
        if let Some(xcfg) = &self.opts.xhttp {
            match self.opts.xhttp_resolved {
                XhttpResolved::StreamOne => {
                    let tcp = self.connect_raw().await?;
                    let io: BoxedStream = if self.opts.tls {
                        Box::new(self.connect_tls_layer(tcp).await?)
                    } else {
                        Box::new(tcp)
                    };
                    let pipe = connect_over_stream(io, xcfg).await?;
                    return Ok(Box::new(TrojanStreamIo::with_header(pipe, header)));
                }
                XhttpResolved::PacketUp | XhttpResolved::StreamUp => {
                    let mode = match self.opts.xhttp_resolved {
                        XhttpResolved::PacketUp => "packet-up",
                        XhttpResolved::StreamUp => "stream-up",
                        XhttpResolved::StreamOne => unreachable!("handled above"),
                    };
                    let tls = self.opts.xhttp_h2_tls.clone().map(|config| {
                        xhttp_h2::XhttpH2Tls {
                            config,
                            server_name: self.opts.sni.clone(),
                            utls: self.opts.utls,
                            verify: self.opts.verify.clone(),
                        }
                    });
                    let pipe = xhttp_h2::connect(
                        &self.opts.server,
                        self.opts.port,
                        &xcfg.host,
                        &xcfg.path,
                        mode,
                        &xcfg.headers,
                        tls,
                    )
                    .await?;
                    return Ok(Box::new(TrojanStreamIo::with_header(pipe, header)));
                }
            }
        }

        if self.opts.network == "ws" {
            let ws = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, self.connect_ws())
                .await
                .map_err(|_| {
                    anyhow!(
                        "trojan ws handshake timed out after {}s ({}:{})",
                        WS_HANDSHAKE_TIMEOUT.as_secs(),
                        self.opts.server,
                        self.opts.port
                    )
                })??;
            return Ok(Box::new(WsStream::with_header(ws, header)));
        }

        // tcp path: write the header eagerly (no response header to read).
        let tcp = self.connect_raw().await?;
        let mut io: BoxedStream = if self.opts.tls {
            Box::new(self.connect_tls_layer(tcp).await?)
        } else {
            Box::new(tcp)
        };
        io.write_all(&header).await.context("trojan write request")?;
        Ok(io)
    }
}

#[async_trait]
impl OutboundDialer for TrojanOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let transport = self.open_trojan(host_hint, addr, CMD_TCP).await?;

        tracing::debug!(
            "trojan ok {}://{}:{} net={} → {:?}",
            if self.opts.tls { "tls" } else { "tcp" },
            self.opts.server,
            self.opts.port,
            self.opts.network,
            host_hint.unwrap_or(&addr.to_string())
        );
        Ok(transport)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(256);
        Ok(Box::new(TrojanUdpSession {
            ob: self.clone(),
            peers: Mutex::new(HashMap::new()),
            incoming: Mutex::new(rx),
            incoming_tx: tx,
        }))
    }
}

/// One Trojan UDP-over-TCP stream per destination (command=UDP).
///
/// Trojan UDP multiplexes targets on a single stream, but the session API
/// (`UdpSession::recv_from`) reports the original destination as the packet
/// source, so one stream per peer keeps the reply routing unambiguous (same
/// model as the vless outbound). Each frame still carries the full socks addr.
struct TrojanUdpSession {
    ob: TrojanOutbound,
    peers: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    incoming_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl TrojanUdpSession {
    async fn ensure_peer(
        &self,
        dst: SocketAddr,
        host: Option<&str>,
    ) -> Result<mpsc::Sender<Vec<u8>>> {
        let key = if let Some(h) = host {
            format!("{h}:{}", dst.port())
        } else {
            dst.to_string()
        };
        {
            let peers = self.peers.lock().await;
            if let Some(tx) = peers.get(&key) {
                if !tx.is_closed() {
                    return Ok(tx.clone());
                }
            }
        }
        let stream = self.ob.open_trojan(host, dst, CMD_UDP).await?;
        // Precompute the per-frame socks addr bytes (ATYP + ADDR + PORT).
        let mut addr_bytes = BytesMut::with_capacity(260);
        write_socks_addr(&mut addr_bytes, host, dst);
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let out_tx = self.incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_peer_loop(stream, dst, addr_bytes.freeze(), pkt_rx, out_tx).await {
                tracing::debug!("trojan udp peer {dst} end: {e:#}");
            }
        });
        self.peers.lock().await.insert(key, pkt_tx.clone());
        tracing::debug!("trojan udp associate {dst}");
        Ok(pkt_tx)
    }
}

#[async_trait]
impl UdpSession for TrojanUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        if data.is_empty() || data.len() > MAX_UDP_PAYLOAD {
            bail!("trojan udp: invalid payload length {}", data.len());
        }
        let tx = self.ensure_peer(dst, dst_host).await?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| anyhow!("trojan udp peer closed"))?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("trojan udp session closed"))
    }
}

async fn udp_peer_loop(
    stream: BoxedStream,
    src: SocketAddr,
    addr_bytes: Bytes,
    mut pkt_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        tokio::select! {
            pkt = pkt_rx.recv() => {
                let Some(data) = pkt else { break };
                if data.is_empty() || data.len() > MAX_UDP_PAYLOAD {
                    continue;
                }
                // Frame: [socks addr][LEN 2B BE][CRLF 2B][DATA]
                let mut frame = BytesMut::with_capacity(addr_bytes.len() + 4 + data.len());
                frame.put_slice(&addr_bytes);
                frame.put_u16(data.len() as u16);
                frame.put_slice(b"\r\n");
                frame.put_slice(&data);
                wr.write_all(&frame).await.context("trojan udp write")?;
            }
            res = read_udp_frame(&mut rd) => {
                let data = res?;
                if out_tx.send((data, src)).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Read one Trojan UDP frame payload from the stream.
/// Frame: `[ATYP 1B][ADDR 变长][PORT 2B][LEN 2B BE][CRLF 2B][DATA len B]`.
/// 地址解析与 sing-box `M.SocksaddrSerializer.ReadAddrPort` 一致。
async fn read_udp_frame<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>> {
    let mut atyp_buf = [0u8; 1];
    rd.read_exact(&mut atyp_buf).await.context("trojan udp atyp")?;
    match atyp_buf[0] {
        ATYP_IPV4 => {
            let mut rest = [0u8; 6]; // 4B ip + 2B port
            rd.read_exact(&mut rest).await.context("trojan udp ipv4 addr")?;
        }
        ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            rd.read_exact(&mut dlen).await.context("trojan udp domain len")?;
            let mut rest = vec![0u8; dlen[0] as usize + 2]; // domain + 2B port
            rd.read_exact(&mut rest).await.context("trojan udp domain addr")?;
        }
        ATYP_IPV6 => {
            let mut rest = [0u8; 18]; // 16B ip + 2B port
            rd.read_exact(&mut rest).await.context("trojan udp ipv6 addr")?;
        }
        other => bail!("trojan udp: unknown address type 0x{other:02x}"),
    }

    let mut len_buf = [0u8; 2];
    rd.read_exact(&mut len_buf).await.context("trojan udp len")?;
    let n = u16::from_be_bytes(len_buf) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut crlf = [0u8; 2];
    rd.read_exact(&mut crlf).await.context("trojan udp crlf")?;
    if &crlf != b"\r\n" {
        bail!("trojan udp: bad CRLF after length");
    }
    let mut data = vec![0u8; n];
    rd.read_exact(&mut data).await.context("trojan udp body")?;
    Ok(data)
}

/// 将目标地址写入缓冲区（SOCKS5 地址格式：ATYP + ADDR + PORT；域名优先）。
fn write_socks_addr(buf: &mut BytesMut, host_hint: Option<&str>, addr: SocketAddr) {
    if let Some(host) = host_hint {
        if host.parse::<IpAddr>().is_err() {
            let h = host.as_bytes();
            let len = h.len().min(255);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(len as u8);
            buf.put_slice(&h[..len]);
            buf.put_u16(addr.port());
            return;
        }
    }
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.octets());
            buf.put_u16(addr.port());
        }
        IpAddr::V6(v6) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.octets());
            buf.put_u16(addr.port());
        }
    }
}

/// 构建 Trojan 请求头（含 payload 之前的全部字节）：
/// `[key 56B][CRLF][CMD 1B][socks addr][CRLF]`
fn build_trojan_header(
    key: &[u8; TROJAN_KEY_LEN],
    host_hint: Option<&str>,
    addr: SocketAddr,
    cmd: u8,
) -> Bytes {
    let mut buf = BytesMut::with_capacity(TROJAN_KEY_LEN + 4 + 260);
    buf.put_slice(key);
    buf.put_slice(b"\r\n");
    buf.put_u8(cmd);
    write_socks_addr(&mut buf, host_hint, addr);
    buf.put_slice(b"\r\n");
    buf.freeze()
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 域名：default-nameserver（bootstrap）优先，系统解析回落，
    // 避免系统 DNS 指回 ant 自身时的解析回环；失败仅影响当次拨号。
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ─── Trojan stream adapter for stream transports (ws / xhttp) ───────────────

/// Wraps a stream transport carrying raw Trojan framing: the first write
/// carries the Trojan request header + first payload; reads pass through
/// (Trojan has no response header). Partial writes are buffered so no data is
/// ever dropped on `Pending` (same design as reflex `TrojanTcpStream`).
struct TrojanStreamIo<S> {
    inner: S,
    pending_header: Option<Bytes>,
    pending_write: Option<Bytes>,
    /// Bytes of the *user* payload reported as written once `pending_write`
    /// (header + payload combined) has been fully flushed.
    pending_reported: usize,
}

impl<S> TrojanStreamIo<S> {
    fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
        }
    }
}

impl<S> AsyncRead for TrojanStreamIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Trojan 服务端无响应头，直接透传。
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TrojanStreamIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Finish a partially-written combined buffer first.
        if let Some(pending) = this.pending_write.take() {
            return match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = this.pending_reported;
                    this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    this.pending_reported = 0;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    this.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. First write: merge header + data into one upstream write.
        if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match Pin::new(&mut this.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(combined.slice(n..));
                    this.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending_write = Some(combined);
                    this.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. Plain passthrough.
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-224("password") = d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
    /// 与 sing-box transport/trojan/protocol.go 的 Key() 对齐。
    #[test]
    fn derive_key_known_vector() {
        let key = derive_key("password");
        let hex = std::str::from_utf8(&key).unwrap();
        assert!(hex.starts_with("d63dc919"), "unexpected key prefix: {hex}");
        assert_eq!(key.len(), 56);
    }

    #[test]
    fn build_tcp_header_domain() {
        let key = derive_key("password");
        let hdr = build_trojan_header(
            &key,
            Some("example.com"),
            "1.2.3.4:443".parse().unwrap(),
            CMD_TCP,
        );
        // [key 56][CRLF 2][cmd 1][atyp 1][len 1][domain 11][port 2][CRLF 2] = 76
        assert_eq!(hdr.len(), 76);
        assert_eq!(&hdr[..56], &key);
        assert_eq!(&hdr[56..58], b"\r\n");
        assert_eq!(hdr[58], CMD_TCP);
        assert_eq!(hdr[59], ATYP_DOMAIN);
        assert_eq!(hdr[60], "example.com".len() as u8);
        assert_eq!(&hdr[61..72], b"example.com");
        assert_eq!(u16::from_be_bytes([hdr[72], hdr[73]]), 443);
        assert_eq!(&hdr[74..76], b"\r\n");
    }

    #[test]
    fn build_tcp_header_ipv4() {
        let key = derive_key("pass");
        let hdr = build_trojan_header(&key, None, "1.2.3.4:443".parse().unwrap(), CMD_TCP);
        // [key 56][CRLF 2][cmd 1][atyp 1][ip 4][port 2][CRLF 2] = 68
        assert_eq!(hdr.len(), 68);
        assert_eq!(hdr[59], ATYP_IPV4);
        assert_eq!(&hdr[60..64], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([hdr[64], hdr[65]]), 443);
    }

    /// Trojan over plain WS: header merged with first payload in one frame,
    /// no response header (server payload passes through verbatim).
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite handshake callback signature
    async fn trojan_ws_roundtrip() {
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::Message;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut host = String::new();
            let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                host = req.headers().get("host").unwrap().to_str().unwrap().to_string();
                assert_eq!(req.uri().path(), "/ws");
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(tcp, cb).await.unwrap();
            let frame = ws.next().await.unwrap().unwrap().into_data();
            // [key 56][CRLF][cmd 1][atyp 1][len 1][example.com 11][port 2][CRLF] = 76
            assert_eq!(frame.len(), 76 + 5);
            let key = derive_key("password");
            assert_eq!(&frame[..56], &key);
            assert_eq!(&frame[56..58], b"\r\n");
            assert_eq!(frame[58], CMD_TCP);
            assert_eq!(frame[59], ATYP_DOMAIN);
            assert_eq!(&frame[61..72], b"example.com");
            assert_eq!(&frame[76..], b"hello");
            ws.send(Message::Binary(b"world".to_vec())).await.unwrap();
            ws.flush().await.unwrap();
            host
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: trojan\nserver: '127.0.0.1'\nport: {port}\npassword: password\nnetwork: ws\ntls: false\nws-path: ws\nsni: example.com\n"
        ))
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        assert_eq!(server.await.unwrap(), format!("example.com:{port}"));
    }

    /// Trojan over plain XHTTP stream-one: POST + chunked body, Trojan header
    /// merged into the first chunk; response body passes through verbatim
    /// (no response header to skip).
    #[tokio::test]
    async fn trojan_xhttp_roundtrip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            // 1. Read until the request head is complete.
            loop {
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "server eof before request head");
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let split = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = String::from_utf8_lossy(&req[..split]).to_lowercase();
            assert!(head.starts_with("post /xhttp-t http/1.1"), "head: {head}");
            assert!(head.contains("transfer-encoding: chunked"), "head: {head}");
            assert!(head.contains("host: example.com"), "head: {head}");

            // 2. Read the first chunk size line, then exactly `size` bytes.
            let size = loop {
                if let Some(pos) = req[split..].windows(2).position(|w| w == b"\r\n") {
                    let s = String::from_utf8_lossy(&req[split..split + pos]).to_string();
                    let sz = usize::from_str_radix(&s, 16).unwrap();
                    let need = split + pos + 2 + sz;
                    while req.len() < need {
                        let n = tcp.read(&mut buf).await.unwrap();
                        assert!(n > 0, "server eof inside first chunk");
                        req.extend_from_slice(&buf[..n]);
                    }
                    break sz;
                }
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "server eof before chunk size");
                req.extend_from_slice(&buf[..n]);
            };
            let size_end = req[split..].windows(2).position(|w| w == b"\r\n").unwrap();
            let data_start = split + size_end + 2;
            let data = &req[data_start..data_start + size];
            assert_eq!(data.len(), 76 + 5, "trojan header + payload");
            let key = derive_key("password");
            assert_eq!(&data[..56], &key);
            assert_eq!(&data[56..58], b"\r\n");
            assert_eq!(data[58], CMD_TCP);
            assert_eq!(&data[74..76], b"\r\n");
            assert_eq!(&data[76..], b"hello");

            // Trojan has no response header: payload only.
            tcp.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            tcp.write_all(b"5\r\nworld\r\n0\r\n\r\n").await.unwrap();
            tcp.flush().await.unwrap();
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: trojan\nserver: '127.0.0.1'\nport: {port}\npassword: password\nnetwork: xhttp\ntls: false\nxhttp-path: /xhttp-t\nxhttp-host: example.com\nxhttp-mode: stream-one\n"
        ))
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        server.await.unwrap();
    }

    /// Trojan + UDP over plain TCP：握手 CMD=0x03，每包带 [addr][len][CRLF][data]。
    #[tokio::test]
    async fn trojan_udp_roundtrip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            // 握手：key 56 + CRLF 2 + cmd 1 + atyp 1 + ip 4 + port 2 + CRLF 2 = 68
            let mut hs = Vec::new();
            while hs.len() < 68 {
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "eof before handshake");
                hs.extend_from_slice(&buf[..n]);
            }
            assert_eq!(hs[58], CMD_UDP);
            assert_eq!(hs[59], ATYP_IPV4);
            assert_eq!(&hs[60..64], &[8, 8, 8, 8]);
            assert_eq!(u16::from_be_bytes([hs[64], hs[65]]), 53);

            // 第一帧：[atyp 1][ip 4][port 2][len 2][CRLF 2][data n] = 15B
            // TCP 是字节流：握手读可能把紧跟的第一帧字节一起读进来，
            // 必须把多余字节交给帧解析继续用，否则帧读取会永久阻塞。
            let mut frame: Vec<u8> = hs[68..].to_vec();
            while frame.len() < 11 + b"ping".len() {
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "eof before frame");
                frame.extend_from_slice(&buf[..n]);
            }
            assert_eq!(frame[0], ATYP_IPV4);
            assert_eq!(&frame[1..5], &[8, 8, 8, 8]);
            assert_eq!(u16::from_be_bytes([frame[5], frame[6]]), 53);
            let dlen = u16::from_be_bytes([frame[7], frame[8]]) as usize;
            assert_eq!(dlen, 4);
            assert_eq!(&frame[9..11], b"\r\n");
            assert_eq!(&frame[11..15], b"ping");

            // 回包：[addr 7][len 2][CRLF 2][data]
            let mut reply = vec![0x01u8];
            reply.extend_from_slice(&[8, 8, 8, 8]);
            reply.extend_from_slice(&53u16.to_be_bytes());
            reply.extend_from_slice(&5u16.to_be_bytes());
            reply.extend_from_slice(b"\r\n");
            reply.extend_from_slice(b"pong!");
            tcp.write_all(&reply).await.unwrap();
            tcp.flush().await.unwrap();
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: trojan\nserver: '127.0.0.1'\nport: {port}\npassword: password\ntls: false\n"
        ))
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        let sess = ob.dial_udp(None).await.unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        sess.send_to(b"ping", dst, None).await.unwrap();
        let (data, from) = sess.recv_from().await.unwrap();
        assert_eq!(from, dst);
        assert_eq!(&data, b"pong!");
        server.await.unwrap();
    }

    /// 配置解析：tls/utls ALPN 约定与 vless 一致；缺 password fail-fast。
    #[tokio::test]
    async fn trojan_config_parsing_and_gating() {
        // tcp + tls + utls：未配置 ALPN 时用浏览器默认 [h2, http/1.1]。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\npassword: pass\ntls: true\nsni: example.com\nclient-fingerprint: chrome\n",
        )
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.utls, Some(UtlsFingerprint::Chrome));
        assert_eq!(ob.opts.tls_alpn, vec!["h2", "http/1.1"]);
        assert!(ob.tls_config.is_some());

        // ws + tls：ALPN 强制 http/1.1。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\npassword: pass\nnetwork: ws\ntls: true\nsni: example.com\n",
        )
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.tls_alpn, vec!["http/1.1"]);

        // xhttp packet-up：需要 h2 TLS 配置；auto → packet-up。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\npassword: pass\nnetwork: xhttp\ntls: true\nsni: example.com\nxhttp-path: /xh\n",
        )
        .unwrap();
        let ob = TrojanOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::PacketUp);
        assert!(ob.opts.xhttp_h2_tls.is_some());

        // 未知 xhttp-mode fail-fast。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\npassword: pass\nnetwork: xhttp\ntls: true\nxhttp-mode: bogus\n",
        )
        .unwrap();
        assert!(
            TrojanOutbound::new(&cfg).is_err(),
            "unknown xhttp-mode must fail fast"
        );

        // 未知 client-fingerprint fail-fast。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\npassword: pass\ntls: true\nclient-fingerprint: nosuch\n",
        )
        .unwrap();
        assert!(
            TrojanOutbound::new(&cfg).is_err(),
            "unknown client-fingerprint must fail fast"
        );

        // 缺 password fail-fast。
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: trojan\nserver: '1.2.3.4'\nport: 443\ntls: true\n",
        )
        .unwrap();
        assert!(TrojanOutbound::new(&cfg).is_err(), "missing password must fail fast");
    }
}
