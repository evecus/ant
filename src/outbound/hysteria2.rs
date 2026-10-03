//! Hysteria2 outbound.
//!
//! Protocol frames align with the official hysteria2 / sing-box implementation;
//! handshake and transport tuning follow reflex (`src/outbound/hysteria2.rs`):
//! raw HTTP/3 auth (no `h3` crate), sing-box-matching QUIC receive/send
//! windows, BBR congestion control with a Brutal-approximation initial window
//! when `up` bandwidth is configured, and a lock-free UDP datagram router.

#[path = "hy2_codec.rs"]
mod hy2_codec;
#[path = "hy2_h3.rs"]
mod hy2_h3;

use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use hy2_codec::{encode_varint, fragment_packet, Defragger, HysUdpPacket};
use hy2_h3::{
    open_h3_control_streams, parse_headers_from_qpack, put_literal_header, random_padding,
    read_h3_frame, read_varint_async, write_h3_frame, H3_FRAME_DATA, H3_FRAME_HEADERS,
};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const RECONNECT_COOLDOWN: Duration = Duration::from_secs(3);
/// Fixed 10s, matching sing-box / reflex.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HYSTERIA_STATUS_OK: u16 = 233;

/// QUIC initial stream receive window (sing-box hysteria/protocol.go).
const QUIC_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
/// QUIC connection-level max receive window (sing-box).
const QUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 20 * 1024 * 1024;
/// Brutal approximation: RTT estimate used to pre-size the BBR initial window:
/// `cwnd = tx_bps * rtt / 8` (sing-quic hysteria/congestion/brutal.go).
const BRUTAL_APPROX_INITIAL_RTT_MS: u64 = 100;
/// DoS guards on response fields (official protocol maxima).
const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;

#[derive(Clone)]
struct HystOption {
    server: String,
    port: u16,
    password: String,
    sni: String,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    udp_mtu: usize,
    /// Local uplink bandwidth in Mbps from config `up`; 0 = auto (no Brutal).
    up_mbps: u64,
    /// Local downlink bandwidth in Mbps from config `down`; advertised to the
    /// server via `Hysteria-CC-RX`. 0 = unlimited.
    down_mbps: u64,
}

/// Results negotiated during the Hysteria2 auth handshake.
#[derive(Debug, Clone)]
struct AuthInfo {
    udp_enabled: bool,
    /// Effective tx bandwidth (bps); 0 = no Brutal-style pacing.
    tx_bps: u64,
}

pub struct Hysteria2Outbound {
    opts: HystOption,
    endpoint: Endpoint,
    state: tokio::sync::Mutex<ConnState>,
    next_session_id: AtomicU32,
}

struct ConnState {
    conn: Option<Arc<Hy2Conn>>,
    last_fail: Option<(std::time::Instant, String)>,
}

struct Hy2Conn {
    quic: Connection,
    support_udp: bool,
    /// session_id → per-session inbound channel + fragment reassembler.
    ///
    /// `std::sync::Mutex` (not tokio): never held across `.await`, so the
    /// single datagram reader is never blocked by other sessions.
    sessions: Arc<StdMutex<HashMap<u32, UdpSessionEntry>>>,
    udp_mtu: usize,
}

struct UdpSessionEntry {
    /// Outbound leg of the datagram router. Dispatched with `try_send`
    /// (drop-on-full, matching sing-quic `select/default`) so a slow consumer
    /// cannot stall the shared datagram reader.
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    defrag: Defragger,
}

/// Parse a bandwidth string (`"100 Mbps"`, `"50mbps"`, `"80"`, `"auto"`) to
/// integer Mbps; 0 means "auto / unset".
fn parse_bandwidth_mbps(raw: &Option<String>) -> u64 {
    let Some(s) = raw else { return 0 };
    let t = s.trim().to_lowercase();
    if t.is_empty() || t == "auto" {
        return 0;
    }
    let num: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num.parse::<f64>().map(|v| v as u64).unwrap_or(0)
}

impl Hysteria2Outbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        let sni = cfg.effective_sni();
        let alpn = cfg.alpn.clone().unwrap_or_else(|| vec!["h3".into()]);
        let opts = HystOption {
            server: cfg.server.clone(),
            port: cfg.port,
            password: cfg.password.clone().unwrap_or_default(),
            sni,
            alpn,
            skip_cert_verify: cfg.skip_cert_verify,
            fingerprint: cfg.fingerprint.clone(),
            udp_mtu: cfg.udp_mtu.unwrap_or(1200) as usize,
            up_mbps: parse_bandwidth_mbps(&cfg.up),
            down_mbps: parse_bandwidth_mbps(&cfg.down),
        };

        let client_config = build_quic_config(&opts)?;

        let udp = crate::app::sockopt::bind_udp("0.0.0.0:0".parse()?).await?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp.into_std()?,
            std::sync::Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            opts,
            endpoint,
            state: tokio::sync::Mutex::new(ConnState {
                conn: None,
                last_fail: None,
            }),
            next_session_id: AtomicU32::new(1),
        })
    }

    async fn ensure_conn(&self) -> Result<Arc<Hy2Conn>> {
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
                    "hysteria2 unavailable (retry in {}ms): {}",
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
                tracing::warn!("hysteria2 connect failed: {msg}");
                guard.last_fail = Some((std::time::Instant::now(), msg.clone()));
                Err(anyhow!(msg))
            }
        }
    }

    async fn connect_once(&self) -> Result<Arc<Hy2Conn>> {
        let server_addr = resolve_server(&self.opts.server, self.opts.port).await?;
        tracing::info!(
            "hysteria2 connecting to {} (sni={}, alpn={:?})",
            server_addr,
            self.opts.sni,
            self.opts.alpn
        );

        let connecting = self
            .endpoint
            .connect(server_addr, &self.opts.sni)
            .context("quic connect start")?;

        let quic = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("quic handshake timeout ({}s)", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("quic handshake")?;

        // ── Accept server uni streams (H3 control / SETTINGS) ───────────────
        // quic-go/http3 opens its control stream immediately after the
        // handshake. If the client never reads it, server-side flow control
        // fills up and the server stops processing requests.
        {
            let conn_bg = quic.clone();
            tokio::spawn(async move {
                for _ in 0..8 {
                    match tokio::time::timeout(Duration::from_secs(5), conn_bg.accept_uni()).await {
                        Ok(Ok(mut stream)) => {
                            let c = conn_bg.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let _ = stream.read(&mut buf).await;
                                // Hold the stream open until the connection ends.
                                c.closed().await;
                                drop(stream);
                            });
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            });
        }

        let auth = self.auth(&quic).await?;
        tracing::info!(
            "hysteria2 authenticated (status={HYSTERIA_STATUS_OK}, udp={}, tx_bps={})",
            auth.udp_enabled,
            auth.tx_bps
        );

        let mtu = self
            .opts
            .udp_mtu
            .min(quic.max_datagram_size().unwrap_or(self.opts.udp_mtu));

        let conn = Arc::new(Hy2Conn {
            quic: quic.clone(),
            support_udp: auth.udp_enabled,
            sessions: Arc::new(StdMutex::new(HashMap::new())),
            udp_mtu: mtu,
        });

        // ── Single datagram reader / router ─────────────────────────────────
        // One task reads every QUIC datagram and routes it by session_id.
        // Routing is synchronous (std mutex + try_send), so a slow UDP
        // session can never stall this reader.
        {
            let conn_rx = conn.clone();
            tokio::spawn(async move {
                loop {
                    match conn_rx.quic.read_datagram().await {
                        Ok(pkt) => route_incoming_datagram(&conn_rx, pkt),
                        Err(e) => {
                            tracing::warn!("hy2 datagram loop end: {e}");
                            break;
                        }
                    }
                }
            });
        }

        Ok(conn)
    }

    /// Hysteria2 auth handshake: raw HTTP/3 POST https://hysteria/auth.
    ///
    /// Replaces the `h3` crate client: opens the mandatory control/QPACK uni
    /// streams, sends one literal-encoded HEADERS frame, parses the response.
    async fn auth(&self, conn: &Connection) -> Result<AuthInfo> {
        open_h3_control_streams(conn)
            .await
            .context("open h3 control streams")?;

        let (mut send, mut recv) = conn.open_bi().await.context("open auth bi stream")?;

        // Client-advertised downlink (tells the server how much we can receive).
        let rx_bps: u64 = self.opts.down_mbps * 1_000_000;

        let mut qpack = BytesMut::new();
        qpack.extend_from_slice(&[0x00, 0x00]); // Required Insert Count=0, Delta Base=0
        put_literal_header(&mut qpack, b":method", b"POST");
        put_literal_header(&mut qpack, b":scheme", b"https");
        put_literal_header(&mut qpack, b":authority", b"hysteria");
        put_literal_header(&mut qpack, b":path", b"/auth");
        put_literal_header(&mut qpack, b"hysteria-auth", self.opts.password.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-cc-rx", rx_bps.to_string().as_bytes());
        put_literal_header(&mut qpack, b"hysteria-padding", random_padding(256, 2048).as_bytes());

        let mut frame = BytesMut::new();
        write_h3_frame(&mut frame, 0x01, &qpack); // H3 HEADERS
        send.write_all(&frame)
            .await
            .map_err(|e| anyhow!("hy2 auth send: {e}"))?;
        send.finish()
            .map_err(|e| anyhow!("hy2 auth finish: {e}"))?;

        // Read the response; quic-go may interleave DATA frames, skip them.
        let headers = loop {
            let (frame_type, payload) =
                read_h3_frame(&mut recv).await.context("hy2 auth read frame")?;
            match frame_type {
                H3_FRAME_HEADERS => break parse_headers_from_qpack(&payload).context("hy2 auth qpack")?,
                H3_FRAME_DATA => continue,
                other => bail!("hy2 auth: unexpected H3 frame type 0x{other:02x}"),
            }
        };

        let get_header = |name: &str| -> Option<&str> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };

        let status: u16 = get_header(":status")
            .unwrap_or("")
            .parse()
            .map_err(|_| anyhow!("hy2 auth: invalid :status"))?;
        if status != HYSTERIA_STATUS_OK {
            bail!("hy2 auth failed: status {status}");
        }

        let udp_enabled = get_header("hysteria-udp")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        // Effective tx = min(local up, server rx). "auto" → server unlimited.
        let tx_bps = {
            let local_tx = self.opts.up_mbps * 1_000_000;
            let server_rx: u64 = match get_header("hysteria-cc-rx") {
                Some(v) if v.eq_ignore_ascii_case("auto") => u64::MAX,
                Some(v) => v.parse().unwrap_or(0),
                None => 0,
            };
            if local_tx == 0 {
                0
            } else if server_rx == 0 {
                local_tx
            } else {
                local_tx.min(server_rx)
            }
        };

        Ok(AuthInfo { udp_enabled, tx_bps })
    }

    async fn open_tcp_stream(&self, target: &str) -> Result<Hy2TcpStream> {
        let conn = self.ensure_conn().await?;
        let (mut send, mut recv) = conn.quic.open_bi().await.context("open bi stream")?;

        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 0x401);
        encode_varint(&mut buf, target.len() as u64);
        buf.extend_from_slice(target.as_bytes());
        let pad = random_padding(64, 512);
        encode_varint(&mut buf, pad.len() as u64);
        buf.extend_from_slice(pad.as_bytes());
        send.write_all(&buf)
            .await
            .map_err(|e| anyhow!("hy2 tcp write header: {e}"))?;

        let status = recv.read_u8().await.context("read tcp status")?;
        let msg_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(msg_len <= MAX_MESSAGE_LENGTH, "hy2 response: msg too long");
        if msg_len > 0 {
            let mut msg = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg).await.context("read tcp msg")?;
            if status != 0 {
                bail!(
                    "hysteria2 tcp open failed status={status} msg={}",
                    String::from_utf8_lossy(&msg)
                );
            }
        } else if status != 0 {
            bail!("hysteria2 tcp open failed status={status}");
        }
        let pad_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(
            pad_len <= MAX_PADDING_LENGTH,
            "hy2 response: padding too long"
        );
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len as usize];
            recv.read_exact(&mut pad_buf)
                .await
                .context("read tcp resp padding")?;
        }

        tracing::debug!("hysteria2 tcp request ok for {target}");
        Ok(Hy2TcpStream { send, recv })
    }
}

/// Route one inbound QUIC datagram to its UDP session (synchronous, no await).
///
/// Decode first, then take the sessions lock briefly; `try_send` drops the
/// packet when the session's queue is full instead of blocking the reader.
fn route_incoming_datagram(conn: &Hy2Conn, pkt: Bytes) {
    let mut buf: BytesMut = pkt.into();
    let Ok(decoded) = HysUdpPacket::decode(&mut buf) else {
        return;
    };
    let mut sessions = conn.sessions.lock().unwrap();
    let Some(entry) = sessions.get_mut(&decoded.session_id) else {
        drop(sessions);
        tracing::debug!("hy2 udp session not found: {}", decoded.session_id);
        return;
    };
    if let Some(full) = entry.defrag.feed(decoded) {
        let src =
            parse_addr_str(&full.addr).unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let _ = entry.tx.try_send((full.data, src));
    }
}

#[async_trait]
impl OutboundDialer for Hysteria2Outbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let target = if let Some(h) = host_hint {
            format!("{}:{}", h, if addr.port() != 0 { addr.port() } else { 443 })
        } else {
            addr.to_string()
        };
        Ok(Box::new(self.open_tcp_stream(&target).await?))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let conn = self.ensure_conn().await?;
        if !conn.support_udp {
            bail!("hysteria2 server does not support UDP");
        }
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(64);
        conn.sessions.lock().unwrap().insert(
            session_id,
            UdpSessionEntry {
                tx,
                defrag: Defragger::default(),
            },
        );
        Ok(Box::new(Hy2UdpSession {
            conn,
            session_id,
            pkt_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
        }))
    }
}

struct Hy2UdpSession {
    conn: Arc<Hy2Conn>,
    session_id: u32,
    pkt_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

#[async_trait]
impl UdpSession for Hy2UdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let addr_str = if let Some(h) = dst_host {
            format!("{}:{}", h, dst.port())
        } else {
            dst.to_string()
        };
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        let max_pkt = self
            .conn
            .quic
            .max_datagram_size()
            .unwrap_or(self.conn.udp_mtu)
            .min(self.conn.udp_mtu);
        for frag in fragment_packet(self.session_id, pkt_id, &addr_str, max_pkt, data) {
            self.conn
                .quic
                .send_datagram(frag)
                .map_err(|e| anyhow!("send datagram: {e}"))?;
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("hy2 udp session closed"))
    }
}

impl Drop for Hy2UdpSession {
    fn drop(&mut self) {
        // Sessions map uses a std mutex held only briefly — safe to clean up
        // synchronously here (no spawned task needed).
        self.conn.sessions.lock().unwrap().remove(&self.session_id);
    }
}

pub struct Hy2TcpStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        <RecvStream as AsyncRead>::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for Hy2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        <SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        <SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {host}"))
}

fn parse_addr_str(s: &str) -> Option<SocketAddr> {
    s.parse().ok().or_else(|| {
        let (h, p) = s.rsplit_once(':')?;
        let port: u16 = p.parse().ok()?;
        let ip: std::net::IpAddr = h.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    })
}

/// Build the QUIC client config (TLS + transport + congestion control).
///
/// Windows match sing-box hysteria (8 MiB stream / 20 MiB connection receive,
/// 20 MiB send) — quinn's defaults are far smaller and throttle single-stream
/// throughput on high-BDP links. Congestion control is BBR; when `up` is
/// configured, the initial window is pre-sized to `up_bps * 100ms / 8`,
/// approximating Brutal's "start at full speed" behavior.
fn build_quic_config(opts: &HystOption) -> Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {
            skip: opts.skip_cert_verify,
            fingerprint: opts.fingerprint.clone(),
        }))
        .with_no_client_auth();
    crypto.alpn_protocols = opts.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    crypto.enable_sni = true;

    let mut transport = TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW).unwrap());
    transport.receive_window(quinn::VarInt::from_u64(QUIC_MAX_CONNECTION_RECEIVE_WINDOW).unwrap());
    transport.send_window(QUIC_MAX_CONNECTION_RECEIVE_WINDOW);
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        if opts.up_mbps > 0 {
            let brutal_cwnd =
                (opts.up_mbps * 1_000_000 / 8 / 1000 * BRUTAL_APPROX_INITIAL_RTT_MS).max(1024);
            tracing::debug!(
                "hy2: BBR with Brutal-like initial window ({} bytes, up={}Mbps)",
                brutal_cwnd,
                opts.up_mbps
            );
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(brutal_cwnd);
            Arc::new(bbr)
        } else {
            Arc::new(quinn::congestion::BbrConfig::default())
        };
    transport.congestion_controller_factory(cc_factory);

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("build quic client config")?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

#[derive(Debug)]
struct SkipServerVerification {
    skip: bool,
    fingerprint: Option<String>,
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Some(ref fp) = self.fingerprint {
            let hash = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
            let hex_fp = hex::encode(hash.as_ref());
            if hex_fp.eq_ignore_ascii_case(fp) {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(TlsError::General("certificate fingerprint mismatch".into()));
        }
        let _ = self.skip;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_parse() {
        assert_eq!(parse_bandwidth_mbps(&Some("100 Mbps".into())), 100);
        assert_eq!(parse_bandwidth_mbps(&Some("50mbps".into())), 50);
        assert_eq!(parse_bandwidth_mbps(&Some("80".into())), 80);
        assert_eq!(parse_bandwidth_mbps(&Some("auto".into())), 0);
        assert_eq!(parse_bandwidth_mbps(&Some("".into())), 0);
        assert_eq!(parse_bandwidth_mbps(&None), 0);
    }

    #[test]
    fn qpack_literal_roundtrip() {
        use bytes::BufMut as _;
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        buf.put_u8(0x00);
        put_literal_header(&mut buf, b":status", b"233");
        put_literal_header(&mut buf, b"hysteria-udp", b"true");
        let headers = parse_headers_from_qpack(&buf.freeze()).unwrap();
        assert!(headers.contains(&(":status".to_string(), "233".to_string())));
        assert!(headers.contains(&("hysteria-udp".to_string(), "true".to_string())));
    }
}
