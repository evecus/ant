//! VLESS outbound — protocol aligned with Xray / clash-rs.
//!
//! Transports: `tcp` | `ws` | `xhttp`; TLS layers: plain TLS (rustls) or
//! REALITY (self-implemented TLS 1.3, see `super::reality`).
//!
//! * tcp / reality: header written directly, response header read eagerly.
//! * ws / xhttp: the VLESS header is merged into the first upstream write and
//!   the response header is skipped lazily on the first read (same as reflex /
//!   sing-box). Waiting for the response eagerly would deadlock, since servers
//!   only answer once they got payload.
//!
//! Request: version(1) + uuid(16) + addon_len(1) + addon + cmd(1) + port(2 BE) + atyp + addr
//! Response: version(1) + addon_len(1) + addon

use super::reality::{reality_connect, RealityDialConfig};
use super::xhttp::{connect_over_stream, XhttpConfig};
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderName, http::HeaderValue, protocol::WebSocketConfig,
    Message,
};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};
use uuid::Uuid;

/// TLS + WS upgrade timeout (matches sing-box TCPTimeout).
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const VLESS_VERSION: u8 = 0;
const VLESS_CMD_TCP: u8 = 1;
const VLESS_CMD_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

#[derive(Clone)]
struct VlessOption {
    server: String,
    port: u16,
    uuid: Uuid,
    network: String,
    tls: bool,
    sni: String,
    skip_cert_verify: bool,
    ws_path: String,
    ws_host: String,
    /// true when the user set ws-host explicitly (Host header is then sent verbatim).
    ws_host_explicit: bool,
    ws_headers: Vec<(String, String)>,
    /// Set when `reality-public-key` is configured — replaces rustls entirely.
    reality: Option<RealityDialConfig>,
    /// Set when network == "xhttp".
    xhttp: Option<XhttpConfig>,
}

#[derive(Clone)]
pub struct VlessOutbound {
    opts: VlessOption,
    tls_connector: Option<TlsConnector>,
}

impl VlessOutbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        let uuid_str = cfg.vless_uuid()?;
        let uuid = Uuid::parse_str(&uuid_str).context("invalid vless uuid")?;
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

        // REALITY: any non-empty reality-public-key enables it, overriding
        // plain rustls (same gating as reflex: reality wins over plain TLS).
        let reality_key = cfg
            .reality_public_key
            .as_ref()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());
        let reality = reality_key.map(|public_key| RealityDialConfig {
            public_key,
            short_id: cfg.reality_short_id.clone().unwrap_or_default(),
            server_name: Some(sni.clone()),
            server: cfg.server.clone(),
            alpn: alpn.clone(),
        });

        let network = cfg.network.to_lowercase();
        let xhttp = if network == "xhttp" {
            let host = cfg
                .xhttp_host
                .clone()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| sni.clone());
            let mut path = cfg.xhttp_path.clone().unwrap_or_else(|| "/".into());
            if !path.starts_with('/') {
                path.insert(0, '/');
            }
            Some(XhttpConfig {
                host,
                path,
                mode: cfg
                    .xhttp_mode
                    .clone()
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| "auto".into()),
                headers: cfg.xhttp_headers.clone().unwrap_or_default(),
            })
        } else {
            None
        };

        let opts = VlessOption {
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            network,
            // REALITY is TLS by definition.
            tls: cfg.tls || reality.is_some(),
            sni: sni.clone(),
            skip_cert_verify: cfg.skip_cert_verify,
            ws_path,
            ws_host,
            ws_host_explicit,
            ws_headers,
            reality,
            xhttp,
        };

        // Plain-rustls connector is skipped when REALITY handles TLS itself.
        // ws and xhttp upgrades speak HTTP/1.1: never let the server pick h2.
        let tls_connector = if opts.tls && opts.reality.is_none() {
            Some(build_tls_connector(
                opts.skip_cert_verify,
                opts.network == "ws" || opts.network == "xhttp",
            )?)
        } else {
            None
        };

        Ok(Self {
            opts,
            tls_connector,
        })
    }

    async fn connect_raw(&self) -> Result<TcpStream> {
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let s = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("vless tcp connect {addr}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    async fn wrap_tls(&self, stream: TcpStream) -> Result<BoxedStream> {
        let connector = self
            .tls_connector
            .as_ref()
            .context("tls not configured")?;
        let name = ServerName::try_from(self.opts.sni.clone())
            .map_err(|_| anyhow!("invalid sni {}", self.opts.sni))?;
        let tls = connector
            .connect(name, stream)
            .await
            .context("vless tls handshake")?;
        Ok(Box::new(tls))
    }

    fn is_ws(&self) -> bool {
        self.opts.network == "ws"
    }

    /// Open the underlying transport and send the VLESS request.
    ///
    /// * tcp/reality: write header, then read the response header eagerly.
    /// * ws/xhttp: the VLESS header is merged into the first upstream write
    ///   together with the first payload, and the response header is skipped
    ///   lazily on the first read (same as reflex / sing-box). Waiting for the
    ///   response here would deadlock, since servers only answer once they got
    ///   payload.
    async fn open_vless(
        &self,
        host_hint: Option<&str>,
        addr: SocketAddr,
        cmd: u8,
    ) -> Result<BoxedStream> {
        let header = build_vless_header(&self.opts.uuid, host_hint, addr, cmd);

        // XHTTP stream-one: POST with a chunked body over TCP / TLS / REALITY.
        if let Some(xcfg) = &self.opts.xhttp {
            let transport = self.connect_xhttp_transport().await?;
            let pipe = connect_over_stream(transport, xcfg).await?;
            return Ok(Box::new(VlessStreamIo::with_header(
                pipe,
                Bytes::from(header),
            )));
        }

        if self.is_ws() {
            let ws = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, self.connect_ws())
                .await
                .map_err(|_| {
                    anyhow!(
                        "vless ws handshake timed out after {}s ({}:{})",
                        WS_HANDSHAKE_TIMEOUT.as_secs(),
                        self.opts.server,
                        self.opts.port
                    )
                })??;
            return Ok(Box::new(
                WsStream::with_header(ws, Bytes::from(header)).skip_vless_response(),
            ));
        }

        // tcp / reality path.
        let tcp = self.connect_raw().await?;
        let mut transport: BoxedStream = if let Some(rcfg) = &self.opts.reality {
            Box::new(reality_connect(tcp, rcfg).await.context("vless reality handshake")?)
        } else if self.opts.tls {
            self.wrap_tls(tcp).await?
        } else {
            Box::new(tcp)
        };
        transport
            .write_all(&header)
            .await
            .context("vless write request")?;

        let mut ver = [0u8; 1];
        transport
            .read_exact(&mut ver)
            .await
            .context("vless read response version")?;
        if ver[0] != VLESS_VERSION {
            bail!("vless unexpected response version {}", ver[0]);
        }
        let mut alen = [0u8; 1];
        transport
            .read_exact(&mut alen)
            .await
            .context("vless read addon len")?;
        if alen[0] > 0 {
            let mut addon = vec![0u8; alen[0] as usize];
            transport
                .read_exact(&mut addon)
                .await
                .context("vless read addon")?;
        }
        Ok(transport)
    }

    /// Underlying stream for the XHTTP pipe: TCP → (REALITY | TLS | plain).
    async fn connect_xhttp_transport(&self) -> Result<BoxedStream> {
        let tcp = self.connect_raw().await?;
        if let Some(rcfg) = &self.opts.reality {
            return Ok(Box::new(
                reality_connect(tcp, rcfg).await.context("vless reality handshake")?,
            ));
        }
        if self.opts.tls {
            return self.wrap_tls(tcp).await;
        }
        Ok(Box::new(tcp))
    }

    /// TCP → (TLS, ALPN http/1.1) → WebSocket upgrade.
    async fn connect_ws(&self) -> Result<WebSocketStream<BoxedStream>> {
        let tcp = self.connect_raw().await?;
        let io: BoxedStream = if self.opts.tls {
            self.wrap_tls(tcp).await?
        } else {
            Box::new(tcp)
        };

        // Host header: a user supplied ws-host is sent verbatim; otherwise
        // sni[:port] with the port omitted when it is the scheme default.
        let default_port = if self.opts.tls { 443 } else { 80 };
        let authority = if self.opts.ws_host_explicit || self.opts.port == default_port {
            self.opts.ws_host.clone()
        } else {
            format!("{}:{}", self.opts.ws_host, self.opts.port)
        };
        // The URL only feeds tungstenite's request builder (Host / path);
        // TLS has already been handled above.
        let url = format!("ws://{}{}", authority, self.opts.ws_path);
        let mut request = url.clone()
            .into_client_request()
            .with_context(|| format!("invalid ws url {url}"))?;
        for (k, v) in &self.opts.ws_headers {
            request.headers_mut().insert(
                HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("bad ws header {k}"))?,
                HeaderValue::from_str(v).with_context(|| format!("bad ws header value for {k}"))?,
            );
        }
        if !request.headers().contains_key("user-agent") {
            request.headers_mut().insert(
                tokio_tungstenite::tungstenite::http::header::USER_AGENT,
                HeaderValue::from_static("Go-http-client/1.1"),
            );
        }

        // write_buffer_size = 0: every write is framed and pushed out immediately.
        let cfg = WebSocketConfig {
            write_buffer_size: 0,
            ..Default::default()
        };
        let (ws, _resp) = client_async_with_config(request, io, Some(cfg))
            .await
            .map_err(|e| anyhow!("vless ws upgrade: {e}"))?;
        Ok(ws)
    }
}

#[async_trait]
impl OutboundDialer for VlessOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let transport = self.open_vless(host_hint, addr, VLESS_CMD_TCP).await?;

        tracing::debug!(
            "vless ok {}://{}:{} net={} → {:?}",
            if self.opts.reality.is_some() {
                "reality"
            } else if self.opts.tls {
                "tls"
            } else {
                "tcp"
            },
            self.opts.server,
            self.opts.port,
            self.opts.network,
            host_hint.unwrap_or(&addr.to_string())
        );
        Ok(transport)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(256);
        Ok(Box::new(VlessUdpSession {
            ob: self.clone(),
            peers: Mutex::new(HashMap::new()),
            incoming: Mutex::new(rx),
            incoming_tx: tx,
        }))
    }
}

/// One VLESS stream per destination (command=UDP).
/// Packet framing matches clash-rs / Xray native UDP: u16be length + payload.
struct VlessUdpSession {
    ob: VlessOutbound,
    peers: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    incoming_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl VlessUdpSession {
    async fn ensure_peer(&self, dst: SocketAddr, host: Option<&str>) -> Result<mpsc::Sender<Vec<u8>>> {
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
        let stream = self.ob.open_vless(host, dst, VLESS_CMD_UDP).await?;
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let src = if let Some(h) = host {
            // Keep numeric addr for recv_from; host is only a dial hint.
            let _ = h;
            dst
        } else {
            dst
        };
        let out_tx = self.incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_peer_loop(stream, src, pkt_rx, out_tx).await {
                tracing::debug!("vless udp peer {src} end: {e:#}");
            }
        });
        self.peers.lock().await.insert(key, pkt_tx.clone());
        tracing::debug!("vless udp associate {dst}");
        Ok(pkt_tx)
    }
}

async fn udp_peer_loop(
    stream: BoxedStream,
    src: SocketAddr,
    mut pkt_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        tokio::select! {
            pkt = pkt_rx.recv() => {
                let Some(data) = pkt else { break };
                if data.is_empty() || data.len() > 65535 {
                    continue;
                }
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(&data);
                wr.write_all(&frame).await.context("vless udp write")?;
            }
            res = read_len_packet(&mut rd) => {
                let data = res?;
                if out_tx.send((data, src)).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn read_len_packet<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>> {
    let mut lenb = [0u8; 2];
    rd.read_exact(&mut lenb).await.context("vless udp len")?;
    let n = u16::from_be_bytes(lenb) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    if n > 65535 {
        bail!("vless udp packet too large");
    }
    let mut buf = vec![0u8; n];
    rd.read_exact(&mut buf).await.context("vless udp body")?;
    Ok(buf)
}

#[async_trait]
impl UdpSession for VlessUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let tx = self.ensure_peer(dst, dst_host).await?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| anyhow!("vless udp peer closed"))?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or_else(|| anyhow!("vless udp session closed"))
    }
}


fn build_vless_header(uuid: &Uuid, host_hint: Option<&str>, addr: SocketAddr, cmd: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.push(VLESS_VERSION);
    buf.extend_from_slice(uuid.as_bytes());
    buf.push(0);
    buf.push(cmd);

    let port = if addr.port() != 0 {
        addr.port()
    } else if host_hint.is_some() {
        443
    } else {
        addr.port()
    };
    buf.extend_from_slice(&port.to_be_bytes());

    if let Some(host) = host_hint {
        if host.parse::<IpAddr>().is_err() {
            let h = host.as_bytes();
            let len = h.len().min(255);
            buf.push(ATYP_DOMAIN);
            buf.push(len as u8);
            buf.extend_from_slice(&h[..len]);
            return buf;
        }
    }

    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf
}

fn build_tls_connector(skip: bool, ws: bool) -> Result<TlsConnector> {
    let mut config = if skip {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    if ws {
        // WebSocket upgrade is HTTP/1.1 only; never let the server pick h2.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Debug)]
struct SkipVerify;

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {host}"))
}

// ─── VLESS stream adapter for stream transports (xhttp, same design as reflex
// VlessTcpStream) ────────────────────────────────────────────────────────────

/// Wraps a stream transport (XHTTP pipe) carrying raw VLESS framing:
///
/// * the first write carries the VLESS request header + first payload;
/// * the VLESS response header (`ver, addon_len, addon`) is skipped on first
///   read;
/// * partial writes are buffered so no data is ever dropped on `Pending`.
struct VlessStreamIo<S> {
    inner: S,
    pending_header: Option<Bytes>,
    pending_write: Option<Bytes>,
    /// Bytes of the *user* payload reported as written once `pending_write`
    /// (header + payload combined) has been fully flushed.
    pending_reported: usize,
    raw_buf: Vec<u8>,
    read_buf: Bytes,
    response_header_skipped: bool,
}

impl<S> VlessStreamIo<S> {
    fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
            raw_buf: Vec::new(),
            read_buf: Bytes::new(),
            response_header_skipped: false,
        }
    }
}

impl<S> AsyncRead for VlessStreamIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        if !this.response_header_skipped {
            // Accumulate until the full [ver][addon_len][addon] header is here.
            loop {
                if this.raw_buf.len() >= 2 {
                    if this.raw_buf[0] != VLESS_VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("vless: bad response version {}", this.raw_buf[0]),
                        )));
                    }
                    let hdr_len = 2 + this.raw_buf[1] as usize;
                    if this.raw_buf.len() >= hdr_len {
                        this.response_header_skipped = true;
                        let payload = Bytes::copy_from_slice(&this.raw_buf[hdr_len..]);
                        this.raw_buf.clear();
                        if !payload.is_empty() {
                            this.read_buf = payload;
                            let n = buf.remaining().min(this.read_buf.len());
                            buf.put_slice(&this.read_buf[..n]);
                            this.read_buf = this.read_buf.slice(n..);
                        }
                        break;
                    }
                }
                let mut tmp = [0u8; 512];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.raw_buf.extend_from_slice(filled);
                    }
                }
            }
        }

        if !this.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for VlessStreamIo<S>
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

// ─── WebSocket stream adapter (tokio-tungstenite, same design as reflex) ────

/// Adapts a `WebSocketStream` to `AsyncRead + AsyncWrite`.
///
/// * every write becomes one binary frame;
/// * the first write carries the VLESS request header + first payload;
/// * the VLESS response header (`ver, addon_len, addon`) is skipped on first read;
/// * Ping/Pong handled by tungstenite, Close → EOF.
struct WsStream<S> {
    inner: S,
    pending_header: Option<Bytes>,
    read_buf: Bytes,
    skip_vless_response: bool,
    response_header_skipped: bool,
}

impl<S> WsStream<S> {
    fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            skip_vless_response: false,
            response_header_skipped: false,
        }
    }

    fn skip_vless_response(mut self) -> Self {
        self.skip_vless_response = true;
        self
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, e)
}

/// Returns number of bytes of the VLESS response header, or None if incomplete/invalid.
fn vless_response_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != VLESS_VERSION {
        return None;
    }
    let n = 2 + buf[1] as usize;
    (buf.len() >= n).then_some(n)
}

impl<S> AsyncRead for WsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf = this.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_err(e))),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        let data = Bytes::from(data);
                        if this.skip_vless_response && !this.response_header_skipped {
                            this.response_header_skipped = true;
                            match vless_response_len(&data) {
                                Some(skip) => this.read_buf = data.slice(skip..),
                                None => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "vless: bad response header over ws",
                                    )))
                                }
                            }
                        } else {
                            this.read_buf = data;
                        }
                    }
                    // tungstenite answers Ping automatically.
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Pin::new(&mut this.inner)
            .poll_ready(cx)
            .map_err(ws_err)?
            .is_pending()
        {
            return Poll::Pending;
        }
        // Only consume the header once start_send succeeded.
        let (payload, header_consumed) = if let Some(h) = this.pending_header.as_ref() {
            let mut b = BytesMut::with_capacity(h.len() + data.len());
            b.put_slice(h);
            b.put_slice(data);
            (b.to_vec(), true)
        } else {
            (data.to_vec(), false)
        };
        match Pin::new(&mut this.inner).start_send(Message::Binary(payload)) {
            Ok(()) => {
                if header_consumed {
                    this.pending_header = None;
                }
                Poll::Ready(Ok(data.len()))
            }
            Err(e) => Poll::Ready(Err(ws_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(ws_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    /// VLESS over plain WS: header merged with first payload in one frame,
    /// response header skipped, Host header has the port when non-default.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite handshake callback signature
    async fn vless_ws_roundtrip() {
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
            // 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11 = 34 header bytes, then payload.
            assert_eq!(frame[0], 0);
            assert_eq!(&frame[34..], b"hello");
            let mut reply = vec![0u8, 0u8];
            reply.extend_from_slice(b"world");
            ws.send(Message::Binary(reply)).await.unwrap();
            ws.flush().await.unwrap();
            host
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vless\nserver: '127.0.0.1'\nport: {port}\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: ws\ntls: false\nws-path: ws\nsni: example.com\n"
        ))
        .unwrap();
        let ob = VlessOutbound::new(&cfg).await.unwrap();
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

    /// VLESS over plain XHTTP stream-one: POST + chunked body, VLESS header
    /// merged into the first chunk, chunked response downlink with the VLESS
    /// response header at the start of the body.
    #[tokio::test]
    async fn vless_xhttp_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            let size_end = req[split..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap();
            let data_start = split + size_end + 2;
            let data = &req[data_start..data_start + size];
            assert_eq!(data[0], 0, "vless version");
            assert_eq!(&data[34..], b"hello");

            // Chunked reply: VLESS response header ([0,0]) + payload.
            let payload = [&[0u8, 0u8][..], b"world".as_slice()].concat();
            let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            reply.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            reply.extend_from_slice(&payload);
            reply.extend_from_slice(b"\r\n0\r\n\r\n");
            tcp.write_all(&reply).await.unwrap();
            tcp.flush().await.unwrap();
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vless\nserver: '127.0.0.1'\nport: {port}\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: false\nxhttp-path: /xhttp-t\nxhttp-host: example.com\n"
        ))
        .unwrap();
        let ob = VlessOutbound::new(&cfg).await.unwrap();
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

    /// XHTTP + REALITY must resolve without the plain-rustls connector being
    /// built (config sanity; a full handshake needs a REALITY server).
    #[tokio::test]
    async fn vless_reality_xhttp_config_parses() {
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: true\nsni: example.com\nreality-public-key: q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s\nreality-short-id: '0123abcd'\nxhttp-path: /xh\n",
        )
        .unwrap();
        let ob = VlessOutbound::new(&cfg).await.unwrap();
        assert!(ob.opts.reality.is_some(), "reality must be enabled");
        assert!(ob.opts.tls, "reality implies tls");
        assert!(
            ob.tls_connector.is_none(),
            "rustls connector must be skipped under REALITY"
        );
        assert_eq!(ob.opts.xhttp.as_ref().unwrap().path, "/xh");
        assert_eq!(ob.opts.xhttp.as_ref().unwrap().host, "example.com");
    }
}
