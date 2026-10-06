use super::hysteria2::SkipServerVerification;
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

// ── 协议常量 ─────────────────────────────────────────────────────────────────

/// TUIC protocol version (v5)
const VERSION: u8 = 0x05;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const ATYP_FQDN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
/// Empty ADDR placeholder on non-first fragments
const ATYP_EMPTY: u8 = 0xff;

/// QUIC transport: per-stream receive window (reflex / sing-tuic)
const QUIC_STREAM_WINDOW: u64 = 8 * 1024 * 1024;
/// QUIC transport: connection-level receive window
const QUIC_CONN_WINDOW: u64 = 15 * 1024 * 1024;
/// QUIC max idle timeout (ms)
const IDLE_TIMEOUT_MS: u32 = 30_000;
/// QUIC transport keep-alive interval (sing-tuic)
const KEEP_ALIVE_SECS: u64 = 10;
/// Default app-level heartbeat interval when `heartbeat` is unset
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(10);
/// Max UDP payload carried by a single datagram (`udpMTU = 1200 - 3`, sing-box
/// tuic/packet.go). Larger packets are fragmented.
const MAX_DATAGRAM_PAYLOAD: usize = 1197;
/// Timeout for an incomplete fragment group before it is dropped
const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Fixed 10s handshake timeout, matching hysteria2.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(3);

// ── 帧编解码原语（仅客户端需要的部分）───────────────────────────────────────

#[derive(Debug, Clone)]
enum Target {
    Domain(String, u16),
    Socket(SocketAddr),
}

/// Parse a UUID string (with or without dashes) into 16 raw bytes.
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "tuic: invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

/// Encode a TUIC address (sing-tuic AddressSerializer, NOT SOCKS5).
fn write_target(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(ATYP_FQDN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

/// Serialized byte length of [`write_target`] (fragment budget).
fn addr_serialize_len(target: &Target) -> usize {
    match target {
        Target::Domain(host, _) => 1 + 1 + host.len() + 2,
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(_) => 1 + 4 + 2,
            IpAddr::V6(_) => 1 + 16 + 2,
        },
    }
}

/// Authenticate frame: `[Ver][Cmd=0x00][UUID 16B][Token 32B]` (50B).
fn build_authenticate_frame(uuid: &[u8; 16], token: &[u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 16 + 32);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_AUTHENTICATE);
    buf.put_slice(uuid);
    buf.put_slice(token);
    buf.freeze()
}

/// TCP Connect header (no user data; merged with the first write).
fn build_connect_header(target: &Target) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 64);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_CONNECT);
    write_target(&mut buf, target);
    buf.freeze()
}

/// Dissociate frame (uni stream): `[Ver][Cmd=0x03][SessionID 2B BE]`.
fn build_dissociate_frame(session_id: u16) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_DISSOCIATE);
    buf.put_u16(session_id);
    buf.freeze()
}

/// Heartbeat datagram: `[Ver][Cmd=0x04]`.
fn build_heartbeat_frame() -> Bytes {
    Bytes::from_static(&[VERSION, CMD_HEARTBEAT])
}

/// Build a single-fragment UDP Packet datagram (sing-tuic `udpMessage.pack`):
/// `[Ver][Cmd=0x02][SessionID 2B][PacketID 2B][FragTotal][FragID][DataLen 2B][ADDR][DATA]`.
/// Note FragTotal comes before FragID.
fn build_udp_packet(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: &Target,
    data: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(10 + 64 + data.len());
    buf.put_u8(VERSION);
    buf.put_u8(CMD_PACKET);
    buf.put_u16(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_total);
    buf.put_u8(frag_id);
    buf.put_u16(data.len() as u16);
    write_target(&mut buf, target);
    buf.put_slice(data);
    buf.freeze()
}

fn udp_fragment_chunk_size(target: &Target) -> usize {
    MAX_DATAGRAM_PAYLOAD
        .saturating_sub(10 + addr_serialize_len(target) + 2)
        .max(1)
}

/// Fragment a UDP packet across QUIC datagrams (sing-box `fragUDPMessage`):
/// only frag_id=0 carries the real ADDR, later fragments use Empty(0xff).
fn send_udp_fragmented(
    conn: &Connection,
    session_id: u16,
    packet_id: u16,
    target: &Target,
    data: &[u8],
) -> Result<()> {
    let chunk_size = udp_fragment_chunk_size(target);

    if data.len() <= chunk_size {
        let pkt = build_udp_packet(session_id, packet_id, 0, 1, target, data);
        conn.send_datagram(pkt)
            .map_err(|e| anyhow!("tuic send datagram: {e}"))?;
        return Ok(());
    }

    let frag_total = data.len().div_ceil(chunk_size);
    anyhow::ensure!(
        frag_total <= u8::MAX as usize,
        "tuic udp: too many fragments ({frag_total})"
    );
    for (frag_id, chunk) in data.chunks(chunk_size).enumerate() {
        let mut buf = BytesMut::with_capacity(10 + addr_serialize_len(target) + 2 + chunk.len());
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(session_id);
        buf.put_u16(packet_id);
        buf.put_u8(frag_total as u8);
        buf.put_u8(frag_id as u8);
        buf.put_u16(chunk.len() as u16);
        if frag_id == 0 {
            write_target(&mut buf, target);
        } else {
            buf.put_u8(ATYP_EMPTY);
        }
        buf.put_slice(chunk);
        conn.send_datagram(buf.freeze())
            .map_err(|e| anyhow!("tuic send datagram: {e}"))?;
    }
    Ok(())
}

/// Parse the fixed header of a UDP Packet datagram.
/// Returns `(session_id, packet_id, frag_total, frag_id, data_len, data_offset)`.
fn parse_udp_packet_meta(data: &[u8]) -> Option<(u16, u16, u8, u8, usize, usize)> {
    const MIN_HDR: usize = 10;
    if data.len() < MIN_HDR || data[0] != VERSION || data[1] != CMD_PACKET {
        return None;
    }
    let session_id = u16::from_be_bytes([data[2], data[3]]);
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let frag_total = data[6];
    let frag_id = data[7];
    let data_len = u16::from_be_bytes([data[8], data[9]]) as usize;

    // Skip the variable-length ADDR to locate DATA
    let mut cur = 10usize;
    if cur >= data.len() {
        return None;
    }
    match data[cur] {
        ATYP_FQDN => {
            cur += 1;
            if cur >= data.len() {
                return None;
            }
            cur += 1 + data[cur] as usize + 2;
        }
        ATYP_IPV4 => cur += 1 + 4 + 2,
        ATYP_IPV6 => cur += 1 + 16 + 2,
        ATYP_EMPTY => cur += 1,
        _ => return None,
    }
    if cur + data_len > data.len() {
        return None;
    }
    Some((session_id, packet_id, frag_total, frag_id, data_len, cur))
}

/// Extract the server-echoed destination as a source address for `recv_from`
/// (IPv4/IPv6 only; domain targets yield `None` → caller falls back to 0.0.0.0:0,
/// same as hysteria2).
fn addr_from_datagram(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 11 {
        return None;
    }
    match data[10] {
        ATYP_IPV4 if data.len() >= 17 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(data[11], data[12], data[13], data[14])),
            u16::from_be_bytes([data[15], data[16]]),
        )),
        ATYP_IPV6 if data.len() >= 29 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[11..27]);
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([data[27], data[28]]),
            ))
        }
        _ => None,
    }
}

// ── UDP datagram 路由（Mutex<HashMap>）──────────────────────────────────────

/// One registered UDP session: inbound queue + fragment reassembly state.
struct SessionSink {
    /// Dispatched with `try_send` (drop-on-full, sing-quic `select/default`
    /// semantics) so a slow consumer cannot stall the shared datagram reader.
    tx: mpsc::Sender<(Bytes, SocketAddr)>,
    /// packet_id → incomplete fragment group
    reasm: HashMap<u16, FragGroup>,
}

struct FragGroup {
    total: u8,
    frags: Vec<Option<Bytes>>,
    last: Instant,
}

/// Routes inbound QUIC datagrams to UDP sessions by SessionID (offset 2-3 of
/// the Packet frame). Brief mutex on the shared datagram reader path.
struct DatagramRouter {
    sessions: StdMutex<HashMap<u16, SessionSink>>,
}

impl DatagramRouter {
    fn new() -> Self {
        Self {
            sessions: StdMutex::new(HashMap::new()),
        }
    }

    fn register(&self, session_id: u16, tx: mpsc::Sender<(Bytes, SocketAddr)>) {
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id, SessionSink { tx, reasm: HashMap::new() });
    }

    fn unregister(&self, session_id: u16) {
        self.sessions.lock().unwrap().remove(&session_id);
    }

    /// Synchronous (no `.await`) — safe to call from the shared reader task.
    fn dispatch(&self, data: Bytes) {
        let Some((sid, pid, frag_total, frag_id, dlen, doff)) = parse_udp_packet_meta(&data)
        else {
            return;
        };
        let src = addr_from_datagram(&data).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        // Zero-copy slice: `data` is a reference-counted quinn datagram buffer.
        let payload = data.slice(doff..doff + dlen);

        let mut sessions = self.sessions.lock().unwrap();
        let Some(sink) = sessions.get_mut(&sid) else {
            return;
        };

        if frag_total <= 1 {
            let _ = sink.tx.try_send((payload, src));
            return;
        }

        // Fragment reassembly, keyed by packet_id (sing-box tuic udpDefragger).
        let now = Instant::now();
        let mut completed: Option<Vec<Bytes>> = None;
        {
            let entry = sink
                .reasm
                .entry(pid)
                .or_insert_with(|| FragGroup {
                    total: frag_total,
                    frags: vec![None; frag_total as usize],
                    last: now,
                });
            // FragTotal mismatch (server retransmission?) → rebuild the group
            if entry.total != frag_total {
                *entry = FragGroup {
                    total: frag_total,
                    frags: vec![None; frag_total as usize],
                    last: now,
                };
            }
            entry.last = now;
            let idx = frag_id as usize;
            if idx < entry.frags.len() && entry.frags[idx].is_none() {
                entry.frags[idx] = Some(payload);
            }
            if entry.frags.iter().all(|f| f.is_some()) {
                completed = Some(entry.frags.iter().flatten().cloned().collect());
            }
        }
        if completed.is_some() {
            sink.reasm.remove(&pid);
        }
        if let Some(frags) = completed {
            let total: usize = frags.iter().map(|b| b.len()).sum();
            let mut out = BytesMut::with_capacity(total);
            for frag in &frags {
                out.put_slice(frag);
            }
            let _ = sink.tx.try_send((out.freeze(), src));
        }
        // Drop timed-out incomplete groups to avoid unbounded growth
        if sink.reasm.len() > 8 {
            sink.reasm
                .retain(|_, g| now.duration_since(g.last) < FRAG_REASSEMBLY_TIMEOUT);
        }
    }
}

// ── 出站 ─────────────────────────────────────────────────────────────────────

struct TuicOption {
    server: String,
    port: u16,
    uuid: [u8; 16],
    password: String,
    sni: String,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    congestion_control: String,
    heartbeat: Duration,
}

pub struct TuicOutbound {
    opts: TuicOption,
    endpoint: Endpoint,
    state: tokio::sync::Mutex<ConnState>,
    next_session: AtomicU16,
}

struct ConnState {
    conn: Option<Arc<TuicConn>>,
    last_fail: Option<(Instant, String)>,
}

struct TuicConn {
    quic: Connection,
    router: Arc<DatagramRouter>,
}

/// Parse the `heartbeat` config value: `"10s"` / `"1500ms"` / `"10"` (seconds).
/// Invalid values fail fast (config error, not silent fallback).
fn parse_heartbeat(raw: &Option<String>) -> Result<Duration> {
    let Some(s) = raw else {
        return Ok(DEFAULT_HEARTBEAT);
    };
    let t = s.trim().to_lowercase();
    let (num, mul) = if let Some(n) = t.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('s') {
        (n, 1000)
    } else {
        (t.as_str(), 1000)
    };
    let ms: u64 = num
        .parse()
        .map_err(|_| anyhow!("tuic: invalid heartbeat {s:?} (expected e.g. \"10s\" or \"500ms\")"))?;
    anyhow::ensure!(ms * mul > 0, "tuic: heartbeat must be > 0");
    Ok(Duration::from_millis(ms * mul))
}

/// Validate `congestion-control` (fail-fast on unknown values).
fn validate_congestion_control(raw: &Option<String>) -> Result<String> {
    let s = raw.clone().unwrap_or_default().to_ascii_lowercase();
    match s.as_str() {
        "" | "cubic" => Ok("cubic".into()),
        "bbr" => Ok("bbr".into()),
        "new_reno" | "newreno" | "reno" => Ok(s),
        other => bail!("tuic: unknown congestion-control {other:?} (cubic | bbr | new_reno)"),
    }
}

impl TuicOutbound {
    pub async fn new(cfg: &ProxyConfig) -> Result<Self> {
        let uuid_str = cfg
            .uuid
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("tuic: `uuid` is required"))?;
        let password = cfg
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("tuic: `password` is required"))?;
        let opts = TuicOption {
            server: cfg.server.clone(),
            port: cfg.port,
            uuid: parse_uuid(uuid_str)?,
            password,
            sni: cfg.effective_sni(),
            alpn: cfg.alpn.clone().unwrap_or_else(|| vec!["h3".into()]),
            skip_cert_verify: cfg.skip_cert_verify,
            fingerprint: cfg.fingerprint.clone(),
            congestion_control: validate_congestion_control(&cfg.congestion_control)?,
            heartbeat: parse_heartbeat(&cfg.heartbeat)?,
        };

        let client_config = build_quic_config(&opts)?;

        // Dual-stack wildcard so IPv6 servers work; fall back to v4-only when
        // the host has IPv6 disabled. The socket goes through
        // sockopt::bind_udp → SO_MARK + interface binding (loop prevention),
        // same as hysteria2.
        let udp = match crate::app::sockopt::bind_udp("[::]:0".parse().unwrap()).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("tuic: dual-stack udp bind failed ({e}); falling back to 0.0.0.0:0");
                crate::app::sockopt::bind_udp("0.0.0.0:0".parse().unwrap()).await?
            }
        };
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            opts,
            endpoint,
            state: tokio::sync::Mutex::new(ConnState {
                conn: None,
                last_fail: None,
            }),
            next_session: AtomicU16::new(0),
        })
    }

    async fn ensure_conn(&self) -> Result<Arc<TuicConn>> {
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
                    "tuic unavailable (retry in {}ms): {}",
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
                tracing::warn!("tuic connect failed: {msg}");
                guard.last_fail = Some((Instant::now(), msg.clone()));
                Err(anyhow!(msg))
            }
        }
    }

    async fn connect_once(&self) -> Result<Arc<TuicConn>> {
        let server_addr = resolve_server(&self.opts.server, self.opts.port).await?;
        tracing::info!(
            "tuic connecting to {} (sni={}, alpn={:?}, cc={})",
            server_addr,
            self.opts.sni,
            self.opts.alpn,
            self.opts.congestion_control
        );

        let connecting = self
            .endpoint
            .connect(server_addr, &self.opts.sni)
            .context("quic connect start")?;

        let quic = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| anyhow!("quic handshake timeout ({}s)", HANDSHAKE_TIMEOUT.as_secs()))?
            .context("quic handshake")?;

        self.authenticate(&quic).await?;

        let conn = Arc::new(TuicConn {
            quic: quic.clone(),
            router: Arc::new(DatagramRouter::new()),
        });

        // ── Single datagram reader / router ─────────────────────────────────
        // One task reads every QUIC datagram and routes it by SessionID
        // (frame offset 2-3). Dispatch is synchronous (Mutex + try_send).
        {
            let c = conn.clone();
            tokio::spawn(async move {
                while let Ok(data) = c.quic.read_datagram().await {
                    c.router.dispatch(data);
                }
                tracing::warn!("tuic datagram loop end");
            });
        }

        // ── App-level heartbeat ─────────────────────────────────────────────
        // sing-tuic loopHeartbeats: without periodic Heartbeat datagrams the
        // server tears the connection down after idle_timeout.
        {
            let c = conn.clone();
            let interval = self.opts.heartbeat;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // skip the immediate first tick
                loop {
                    ticker.tick().await;
                    if c.quic.send_datagram(build_heartbeat_frame()).is_err() {
                        break;
                    }
                }
            });
        }

        Ok(conn)
    }

    /// Send the Authenticate frame on a uni stream.
    ///
    /// The token MUST be derived from the established TLS session via
    /// `export_keying_material(label=uuid, context=password, 32B)` — exactly
    /// what sing-tuic `clientHandshake` does.
    async fn authenticate(&self, conn: &Connection) -> Result<()> {
        let mut stream = conn
            .open_uni()
            .await
            .context("tuic open auth uni stream")?;

        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &self.opts.uuid, self.opts.password.as_bytes())
            .map_err(|e| anyhow!("tuic export keying material: {e:?}"))?;

        stream
            .write_all(&build_authenticate_frame(&self.opts.uuid, &token))
            .await
            .context("tuic send authenticate")?;
        stream.finish().context("tuic finish auth stream")?;
        Ok(())
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Domain: default-nameserver (bootstrap) first, then the system resolver,
    // so a DNS loop back into ant cannot wedge the dial.
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

#[async_trait]
impl OutboundDialer for TuicOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let target = if let Some(h) = host_hint {
            Target::Domain(
                h.to_string(),
                if addr.port() != 0 { addr.port() } else { 443 },
            )
        } else {
            Target::Socket(addr)
        };
        let conn = self.ensure_conn().await?;
        let (send, recv) = conn
            .quic
            .open_bi()
            .await
            .context("tuic open bi stream")?;
        let header = build_connect_header(&target);
        Ok(Box::new(TuicTcpStream::new(send, recv, header)))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let conn = self.ensure_conn().await?;
        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(64);
        conn.router.register(session_id, tx);
        Ok(Box::new(TuicUdpSession {
            conn,
            session_id,
            pkt_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
        }))
    }
}

struct TuicUdpSession {
    conn: Arc<TuicConn>,
    session_id: u16,
    pkt_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
}

#[async_trait]
impl UdpSession for TuicUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let target = match dst_host {
            Some(h) => Target::Domain(h.to_string(), dst.port()),
            None => Target::Socket(dst),
        };
        // packet_id increases monotonically within the session (server-side
        // dedup / ordering); the session_id stays constant so the server can
        // correlate uplink and downlink.
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        send_udp_fragmented(&self.conn.quic, self.session_id, pkt_id, &target, data)
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let (data, src) = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("tuic udp session closed"))?;
        Ok((data.to_vec(), src))
    }
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.conn.router.unregister(self.session_id);
        // Dissociate goes over a uni stream (not a datagram): the server
        // parses commands on uni streams only — a datagram Dissociate would be
        // treated as a UDP Packet (CMD=0x02 path) and silently ignored.
        let quic = self.conn.quic.clone();
        let session_id = self.session_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Ok(mut stream) = quic.open_uni().await {
                    let _ = stream.write_all(&build_dissociate_frame(session_id)).await;
                    let _ = stream.finish();
                }
            });
        }
    }
}

// ── TuicTcpStream：bi-stream + Connect 帧首写合并 ───────────────────────────
//
// sing-tuic `clientConn.Write` alignment: the Connect header is NOT written
// separately at handshake time; the first write merges it with user data:
// `[Ver][Cmd=0x01][ADDR][user data]`. TUIC TCP Connect has no response header
// to skip.

pub struct TuicTcpStream {
    send: SendStream,
    recv: RecvStream,
    /// Connect header merged into the first write
    pending_header: Option<Bytes>,
    /// Remaining bytes of a partially-written merged buffer
    pending_write: Option<Bytes>,
    /// "Written" count to report once pending_write drains (original data len)
    pending_reported: usize,
}

impl TuicTcpStream {
    fn new(send: SendStream, recv: RecvStream, header: Bytes) -> Self {
        Self {
            send,
            recv,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
        }
    }
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 1. Finish a partially-written merged buffer first
        if let Some(pending) = self.pending_write.take() {
            return match Pin::new(&mut self.send).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = self.pending_reported;
                    self.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    self.pending_reported = 0;
                    Poll::Ready(Err(e.into()))
                }
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. First write: merge header + data (sing-tuic clientConn.Write)
        if let Some(header) = self.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match Pin::new(&mut self.send).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    self.pending_write = Some(combined.slice(n..));
                    self.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Pending => {
                    self.pending_write = Some(combined);
                    self.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. Steady state: pass through
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ── QUIC 配置 ────────────────────────────────────────────────────────────────

/// Build the QUIC client config: TLS + transport + congestion control.
/// Windows match sing-tuic (8 MiB stream / 15 MiB connection windows).
fn build_quic_config(opts: &TuicOption) -> Result<ClientConfig> {
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
    transport.stream_receive_window(quinn::VarInt::from_u64(QUIC_STREAM_WINDOW).unwrap());
    transport.receive_window(quinn::VarInt::from_u64(QUIC_CONN_WINDOW).unwrap());
    transport.send_window(QUIC_CONN_WINDOW);
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
    transport.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_SECS)));

    // Congestion control (sing-box tuic: cubic default, bbr optional). quinn
    // has no standalone NewReno; it degrades to Cubic (both loss-based).
    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match opts.congestion_control.as_str() {
            "bbr" => {
                tracing::debug!("tuic: using BBR congestion control");
                Arc::new(quinn::congestion::BbrConfig::default())
            }
            "new_reno" | "newreno" | "reno" => {
                tracing::debug!("tuic: NewReno not built-in, falling back to Cubic");
                Arc::new(quinn::congestion::CubicConfig::default())
            }
            _ => Arc::new(quinn::congestion::CubicConfig::default()),
        };
    transport.congestion_controller_factory(cc_factory);

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("build quic client config")?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn parse_uuid_no_dashes() {
        assert_eq!(parse_uuid("aabbccdd11223344aabbccdd11223344").unwrap().len(), 16);
    }

    #[test]
    fn parse_uuid_invalid() {
        assert!(parse_uuid("zzzz").is_err());
        assert!(parse_uuid("").is_err());
    }

    #[test]
    fn connect_header_layout() {
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_connect_header(&target);
        assert_eq!(hdr[0], VERSION);
        assert_eq!(hdr[1], CMD_CONNECT);
        assert_eq!(hdr[2], ATYP_FQDN);
        assert_eq!(hdr[3], 11);
        assert_eq!(&hdr[4..15], b"example.com");
        assert_eq!(u16::from_be_bytes([hdr[15], hdr[16]]), 443);
    }

    #[test]
    fn authenticate_frame_layout() {
        let uuid = [0xAA; 16];
        let token = [0xBB; 32];
        let f = build_authenticate_frame(&uuid, &token);
        assert_eq!(f.len(), 50);
        assert_eq!(f[0], VERSION);
        assert_eq!(f[1], CMD_AUTHENTICATE);
        assert_eq!(&f[2..18], &uuid[..]);
        assert_eq!(&f[18..50], &token[..]);
    }

    #[test]
    fn dissociate_frame_layout() {
        assert_eq!(
            build_dissociate_frame(0x1234).as_ref(),
            &[0x05, 0x03, 0x12, 0x34]
        );
    }

    #[test]
    fn heartbeat_frame_layout() {
        assert_eq!(build_heartbeat_frame().as_ref(), &[0x05, 0x04]);
    }

    #[test]
    fn udp_packet_layout() {
        let target = Target::Domain("example.com".into(), 443);
        let pkt = build_udp_packet(0x1234, 0x5678, 0, 1, &target, b"hello");
        assert_eq!(pkt[0], VERSION);
        assert_eq!(pkt[1], CMD_PACKET);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x5678);
        assert_eq!(pkt[6], 1); // frag_total
        assert_eq!(pkt[7], 0); // frag_id
        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 5); // data_len
        assert_eq!(pkt[10], ATYP_FQDN);
        assert_eq!(pkt[11], 11);
        assert_eq!(&pkt[12..23], b"example.com");
        assert_eq!(u16::from_be_bytes([pkt[23], pkt[24]]), 443);
        assert_eq!(&pkt[25..30], b"hello");

        let (sid, pid, ft, fid, dlen, doff) = parse_udp_packet_meta(&pkt).unwrap();
        assert_eq!((sid, pid, ft, fid, dlen, doff), (0x1234, 0x5678, 1, 0, 5, 25));
    }

    #[test]
    fn parse_meta_empty_addr_fragment() {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(0x1234u16);
        buf.put_u16(0x0001u16);
        buf.put_u8(2); // frag_total
        buf.put_u8(1); // frag_id
        buf.put_u16(4u16);
        buf.put_u8(0xff); // Empty ADDR
        buf.put_slice(b"frag");
        let meta = parse_udp_packet_meta(&buf).expect("parse ok");
        assert_eq!(meta, (0x1234, 0x0001, 2, 1, 4, 11));
    }

    #[test]
    fn addr_from_datagram_v4() {
        let target = Target::Socket("1.2.3.4:53".parse().unwrap());
        let pkt = build_udp_packet(1, 0, 0, 1, &target, b"x");
        assert_eq!(
            addr_from_datagram(&pkt),
            Some("1.2.3.4:53".parse().unwrap())
        );
    }

    #[test]
    fn addr_from_datagram_domain_yields_none() {
        let target = Target::Domain("example.com".into(), 443);
        let pkt = build_udp_packet(1, 0, 0, 1, &target, b"x");
        assert_eq!(addr_from_datagram(&pkt), None);
    }

    #[test]
    fn heartbeat_parse() {
        assert_eq!(parse_heartbeat(&None).unwrap(), Duration::from_secs(10));
        assert_eq!(
            parse_heartbeat(&Some("10s".into())).unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(
            parse_heartbeat(&Some("10".into())).unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(
            parse_heartbeat(&Some("500ms".into())).unwrap(),
            Duration::from_millis(500)
        );
        assert!(parse_heartbeat(&Some("abc".into())).is_err());
        assert!(parse_heartbeat(&Some("0s".into())).is_err());
    }

    #[test]
    fn congestion_control_validate() {
        assert_eq!(
            validate_congestion_control(&None).unwrap(),
            "cubic"
        );
        assert_eq!(
            validate_congestion_control(&Some("BBR".into())).unwrap(),
            "bbr"
        );
        assert_eq!(
            validate_congestion_control(&Some("new_reno".into())).unwrap(),
            "new_reno"
        );
        assert!(validate_congestion_control(&Some("vegas".into())).is_err());
    }
}
