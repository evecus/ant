//! AnyTLS outbound (client only — ant has no AnyTLS inbound).
//!
//! Behavior aligns with sing-box `protocol/anytls/outbound.go` / anytls-go:
//! one TLS connection carries multiplexed streams with traffic padding; idle
//! sessions are pooled and reused. UDP rides sing UoT v2 over a stream to the
//! magic address `sp.v2.udp-over-tcp.arpa`.
//!
//! ## Wire format (anytls-go / sing-anytls)
//!
//! ### Auth frame (first TLS record payload right after the TLS handshake)
//! `[sha256(password) 32B][padding0_len 2B BE][padding0]`
//!
//! ### Session frames (multiplexed inside the TLS stream)
//! `[CMD 1B][STREAM_ID 4B BE][DATA_LEN 2B BE][DATA]` with commands:
//! 0=Waste(padding) 1=SYN 2=PSH 3=FIN 4=Settings 5=Alert 6=UpdatePadding
//! 7=SYNACK 8=HeartRequest 9=HeartResponse 10=ServerSettings.
//! A PSH payload larger than 0xFFFF is split across frames.
//!
//! ### Stream open payload (first PSH after SYN)
//! SOCKS5 address: `[ATYP][ADDR][PORT 2B BE]`, ATYP=0x01/0x03/0x04.
//!
//! ### UDP over session (sing UoT v2)
//! Stream to the magic address; request header
//! `[isConnect=0][SOCKS5 ATYP target][PORT]` (connectionless mode) then one
//! packet per datagram `[sing ATYP][ADDR][PORT][LEN 2B BE][DATA]` — note the
//! per-packet ATYP table (0x00/0x01/0x02) differs from the SOCKS5 header ATYP.
//!
//! The dial socket is created via `app::sockopt::connect_tcp`, so the outbound
//! TCP socket carries SO_MARK / interface binding like every other outbound
//! (loop prevention).

use super::hysteria2::SkipServerVerification;
use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint, UtlsVerify};
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use md5::Md5;
use rand::Rng;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tracing::debug;

// ── 协议常量 ─────────────────────────────────────────────────────────────────

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

/// Frame header: cmd(1) + streamId(4) + data_len(2)
const FRAME_HEADER_SIZE: usize = 7;
/// Max payload of a single frame (DATA_LEN is u16)
const MAX_FRAME_DATA: usize = 0xFFFF;

/// Standard SOCKS5 ATYP (stream-open payload and UoT v2 request header)
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// sing UoT v2 magic address (TCP requests to it carry UDP over the session)
const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_MAGIC_PORT: u16 = 443;
/// sing UoT v2 per-packet ATYP (differs from SOCKS5 ATYP; sing/common/uot)
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

/// Padding size marker: "stop padding once payload is exhausted"
const PADDING_CHECK_MARK: i32 = -1;

/// Default padding scheme (anytls-go reference)
const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

/// Idle pool tuning (sing-box defaults)
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

// ── Padding scheme ───────────────────────────────────────────────────────────

/// Padding scheme: shapes the first N TLS records to defeat traffic fingerprinting.
#[derive(Clone)]
struct PaddingScheme {
    /// Stop padding at this packet number (exclusive); pkt >= stop sends raw
    stop: u32,
    /// Raw scheme text (ranges are re-randomized per use)
    raw: Vec<u8>,
    /// Lowercase hex md5 of the raw scheme (negotiation comparison)
    md5_hex: String,
}

impl PaddingScheme {
    fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop = 0u32;
        let mut has_stop = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, val) = line.split_once('=')?;
            if key.trim() == "stop" {
                stop = val.trim().parse().ok()?;
                has_stop = true;
            }
        }
        if !has_stop {
            return None;
        }
        let md5_hex = format!("{:x}", Md5::digest(raw));
        Some(PaddingScheme {
            stop,
            raw: raw.to_vec(),
            md5_hex,
        })
    }

    /// Actual sizes for one packet number (re-randomized on each call).
    /// Empty list = send raw.
    fn generate_sizes(&self, pkt: u32) -> Vec<i32> {
        let text = match std::str::from_utf8(&self.raw) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let prefix = format!("{pkt}=");
        for line in text.lines() {
            if line.trim().starts_with(&prefix) {
                if let Some(val) = line.trim().get(prefix.len()..) {
                    return Self::parse_sizes(val.trim());
                }
            }
        }
        vec![]
    }

    fn parse_sizes(s: &str) -> Vec<i32> {
        let mut out = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part == "c" {
                out.push(PADDING_CHECK_MARK);
            } else if let Some((lo, hi)) = part.split_once('-') {
                let lo: i32 = lo.trim().parse().unwrap_or(0);
                let hi: i32 = hi.trim().parse().unwrap_or(0);
                let (lo, hi) = (lo.min(hi), lo.max(hi));
                if lo > 0 && hi > 0 {
                    if lo == hi {
                        out.push(lo);
                    } else {
                        let size = rand::thread_rng().gen_range(lo..hi);
                        out.push(size);
                    }
                }
            }
        }
        out
    }
}

/// Thread-safe, hot-swappable padding scheme holder (clones share one lock).
#[derive(Clone)]
struct SharedPadding {
    scheme: Arc<RwLock<PaddingScheme>>,
}

impl SharedPadding {
    fn new_default() -> Self {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME)
            .expect("default padding should parse");
        SharedPadding {
            scheme: Arc::new(RwLock::new(scheme)),
        }
    }

    fn get(&self) -> PaddingScheme {
        self.scheme.read().unwrap().clone()
    }

    /// Replace the scheme; returns false and keeps the old one if invalid.
    fn update(&self, raw: &[u8]) -> bool {
        if let Some(new_scheme) = PaddingScheme::parse(raw) {
            *self.scheme.write().unwrap() = new_scheme;
            true
        } else {
            false
        }
    }

    fn md5(&self) -> String {
        self.scheme.read().unwrap().md5_hex.clone()
    }
}

// ── 帧编解码原语（仅客户端需要的部分）───────────────────────────────────────

/// 出站目标：域名 + 端口，或已解析的 SocketAddr。
/// naive 出站复用（UoT v2 / CONNECT authority）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Domain(String, u16),
    Socket(SocketAddr),
}

/// Build one session frame: `[CMD][STREAM_ID 4B BE][DATA_LEN 2B BE][DATA]`.
fn build_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&sid.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Apply padding to an outbound write unit (anytls-go writeConn).
///
/// anytls-go counts packets with `pkt = pktCounter.Add(1)` (returns the NEW
/// value, first packet = 1). Rust's `fetch_add` returns the OLD value, hence
/// the internal `+ 1`. Scheme rule "0=..." is reserved for the auth frame's
/// padding0 and must never be picked by the session layer.
fn apply_padding(pkt_counter: &AtomicU32, padding: &PaddingScheme, data: Vec<u8>) -> Vec<u8> {
    let pkt = pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;

    if pkt >= padding.stop {
        return data;
    }

    let sizes = padding.generate_sizes(pkt);
    if sizes.is_empty() {
        return data;
    }

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + 512);
    let mut remaining = data;

    for size in sizes {
        if size == PADDING_CHECK_MARK {
            if remaining.is_empty() {
                break;
            }
            continue;
        }
        let size = size as usize;
        let rem_len = remaining.len();

        if rem_len > size {
            // This chunk is pure payload
            out.extend_from_slice(&remaining[..size]);
            remaining = remaining[size..].to_vec();
        } else if rem_len > 0 {
            // Payload exhausted; pad up to `size` with a Waste frame
            let padding_data_len = size.saturating_sub(rem_len + FRAME_HEADER_SIZE);
            out.extend_from_slice(&remaining);
            remaining.clear();
            if padding_data_len > 0 {
                out.push(CMD_WASTE);
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(&(padding_data_len as u16).to_be_bytes());
                out.extend(std::iter::repeat_n(0u8, padding_data_len));
            }
        } else {
            // Pure padding packet
            out.push(CMD_WASTE);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&(size as u16).to_be_bytes());
            out.extend(std::iter::repeat_n(0u8, size));
        }
    }

    if !remaining.is_empty() {
        out.extend_from_slice(&remaining);
    }
    out
}

fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

/// Client auth frame: `[sha256(password) 32B][padding0_len 2B BE][padding0]`.
/// padding0 size comes from the scheme's "0=..." rule (default "0=30-30").
fn build_auth_packet(password: &str, padding: &PaddingScheme) -> Vec<u8> {
    let hash = password_hash(password);
    let padding_sizes = padding.generate_sizes(0);
    let padding_len = padding_sizes.first().copied().unwrap_or(0).max(0) as usize;

    let mut out = Vec::with_capacity(32 + 2 + padding_len);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, padding_len));
    out
}

/// Write a SOCKS5 address (standard ATYP 0x01/0x03/0x04).
fn write_socks_addr_to(buf: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.push(SOCKS_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(SOCKS_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(SOCKS_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

fn encode_socks_addr(target: &Target) -> Vec<u8> {
    let mut buf = Vec::new();
    write_socks_addr_to(&mut buf, target);
    buf
}

/// UoT v2 request header: `[isConnect=0][SOCKS5 ATYP target][PORT]`
/// (connectionless mode — every packet carries its own address).
///
/// `pub(crate)`：naive 出站的 UDP 走同一套 UoT v2 封装。
pub(crate) fn build_uot_request(target: &Target) -> Vec<u8> {
    let mut buf = vec![0u8];
    write_socks_addr_to(&mut buf, target);
    buf
}

/// One UoT v2 UDP packet (connectionless mode):
/// `[sing ATYP][ADDR][PORT][LEN 2B BE][DATA]`.
pub(crate) fn build_uot_packet(target: &Target, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    match target {
        Target::Domain(host, port) => {
            buf.push(UOT_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(UOT_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(UOT_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Read one UoT v2 UDP packet (connectionless mode) from a byte stream.
/// Per-packet addresses use the sing ATYP table, NOT standard SOCKS5.
async fn read_uot_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Target, Bytes)> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;

    let target = match atyp[0] {
        UOT_ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            reader.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            Target::Socket(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([buf[4], buf[5]]),
            ))
        }
        UOT_ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            reader.read_exact(&mut buf).await?;
            let ip: [u8; 16] = buf[..16].try_into().unwrap();
            Target::Socket(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes([buf[16], buf[17]]),
            ))
        }
        UOT_ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            reader.read_exact(&mut dlen).await?;
            let mut domain = vec![0u8; dlen[0] as usize];
            reader.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf).await?;
            Target::Domain(String::from_utf8(domain)?, u16::from_be_bytes(port_buf))
        }
        other => bail!("anytls uot: unknown per-packet atyp 0x{other:02x}"),
    };

    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let data_len = u16::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data).await?;

    Ok((target, Bytes::from(data)))
}

// ── 会话（单条 TLS 连接上的多路复用）────────────────────────────────────────

/// Messages for the per-session write task.
enum WriteMsg {
    /// Control frame (FIN / HEART...): written directly, bypasses padding
    Control(Vec<u8>),
    /// Data frame: buffered while the session is in buffering mode
    Frame(Vec<u8>),
    /// Stop buffering; write pending + this data through the padding path
    Flush(Vec<u8>),
    /// Shut the session down
    Close,
}

struct AnyTlsSession {
    /// Frames for the write task
    write_tx: mpsc::UnboundedSender<WriteMsg>,
    /// Active stream data channels: sid → inbound PSH payloads
    streams: StdMutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>,
    next_stream_id: AtomicU32,
    /// Padding write-unit counter (pkt starts at 1, anytls-go alignment)
    pkt_counter: AtomicU32,
    /// Server protocol version (from cmdServerSettings)
    peer_version: AtomicU8,
    is_closed: AtomicBool,
    closed_notify: Arc<Notify>,
    padding: Arc<SharedPadding>,
    /// Session number (pool bookkeeping)
    seq: u64,
    /// Time the session entered the idle pool
    idle_since: RwLock<Option<Instant>>,
    /// Live client streams; when it drops to 0 the session returns to the pool
    live_streams: AtomicUsize,
    /// Back-pointer to the owning client (Weak: no cycle)
    client: Weak<AnyTlsClient>,
}

impl AnyTlsSession {
    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: BoxedStream,
        padding: Arc<SharedPadding>,
        seq: u64,
        client: Weak<AnyTlsClient>,
    ) -> Arc<Self> {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteMsg>();
        let closed_notify = Arc::new(Notify::new());
        let (read_half, write_half) = tokio::io::split(conn);

        let session = Arc::new(Self {
            write_tx,
            streams: StdMutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            peer_version: AtomicU8::new(1),
            is_closed: AtomicBool::new(false),
            closed_notify: closed_notify.clone(),
            padding,
            seq,
            idle_since: RwLock::new(None),
            live_streams: AtomicUsize::new(0),
            client,
        });

        tokio::spawn(write_task(write_half, write_rx, session.clone()));
        tokio::spawn(recv_loop(read_half, session.clone()));

        session
    }

    fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if !self.is_closed.swap(true, Ordering::AcqRel) {
            self.closed_notify.notify_waiters();
            let _ = self.write_tx.send(WriteMsg::Close);
        }
    }

    /// Send a control frame (bypasses buffering and padding)
    fn write_control(&self, cmd: u8, sid: u32, data: &[u8]) -> std::io::Result<()> {
        self.write_tx
            .send(WriteMsg::Control(build_frame(cmd, sid, data)))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    /// Send PSH data frames (split above the single-frame limit, sing-anytls
    /// `writeDataFrame`). One Flush unit = one padding packet, matching
    /// anytls-go's single writeConn call.
    fn write_data(&self, sid: u32, data: &[u8]) -> std::io::Result<usize> {
        if self.is_closed() {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let len = data.len();
        let mut buf = Vec::with_capacity(len + 16);
        for chunk in data.chunks(MAX_FRAME_DATA) {
            buf.extend_from_slice(&build_frame(CMD_PSH, sid, chunk));
        }
        self.write_tx
            .send(WriteMsg::Flush(buf))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(len)
    }

    /// Open a new multiplexed stream.
    async fn open_stream(self: &Arc<Self>) -> Result<AnyTlsStream> {
        if self.is_closed() {
            bail!("anytls session is closed");
        }

        let sid = self.next_stream_id.fetch_add(1, Ordering::SeqCst) + 1;

        // First stream: send cmdSettings while still buffering, so settings +
        // SYN + first PSH(addr) coalesce into one TLS write (= pkt 1, scheme
        // "1=100-400"), matching anytls-go.
        if sid == 1 {
            let settings = format!(
                "v=2\nclient=ant/anytls\npadding-md5={}",
                self.padding.md5()
            );
            let _ = self
                .write_tx
                .send(WriteMsg::Frame(build_frame(
                    CMD_SETTINGS,
                    0,
                    settings.as_bytes(),
                )));
        }

        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        self.streams.lock().unwrap().insert(sid, data_tx);

        // SYN joins the buffer; the next write_data (target address) triggers
        // the Flush that puts everything on the wire.
        let _ = self.write_tx.send(WriteMsg::Frame(build_frame(CMD_SYN, sid, &[])));
        self.live_streams.fetch_add(1, Ordering::AcqRel);

        Ok(AnyTlsStream {
            sid,
            session: self.clone(),
            data_rx,
            read_buf: Bytes::new(),
        })
    }

    fn close_stream_local(&self, sid: u32) {
        if !self.is_closed() {
            let _ = self.write_control(CMD_FIN, sid, &[]);
        }
        self.streams.lock().unwrap().remove(&sid);
    }

    /// A client stream went away (drop / shutdown). When the last one closes,
    /// return the session to the client's idle pool.
    fn on_stream_closed(self: &Arc<Self>) {
        if self.live_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            if let Some(client) = self.client.upgrade() {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let s = self.clone();
                    handle.spawn(async move { client.return_idle(s).await });
                }
            }
        }
    }
}

// ── 写任务 ───────────────────────────────────────────────────────────────────

async fn write_task(
    mut writer: WriteHalf<BoxedStream>,
    mut rx: mpsc::UnboundedReceiver<WriteMsg>,
    session: Arc<AnyTlsSession>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buffering = true;

    while let Some(msg) = rx.recv().await {
        match msg {
            WriteMsg::Close => {
                let _ = writer.shutdown().await;
                return;
            }
            WriteMsg::Control(data) => {
                // Control frames bypass padding and buffering state
                if writer.write_all(&data).await.is_err() {
                    session.close();
                    return;
                }
            }
            WriteMsg::Frame(data) => {
                if buffering {
                    pending.extend_from_slice(&data);
                } else {
                    let out = apply_padding(&session.pkt_counter, &session.padding.get(), data);
                    if writer.write_all(&out).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
            WriteMsg::Flush(data) => {
                buffering = false;
                let combined = if !pending.is_empty() {
                    let mut c = std::mem::take(&mut pending);
                    c.extend_from_slice(&data);
                    c
                } else {
                    data
                };
                let out = apply_padding(&session.pkt_counter, &session.padding.get(), combined);
                if writer.write_all(&out).await.is_err() {
                    session.close();
                    return;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

// ── 接收循环 ─────────────────────────────────────────────────────────────────

async fn recv_loop(mut reader: ReadHalf<BoxedStream>, session: Arc<AnyTlsSession>) {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];

    loop {
        if session.is_closed() {
            return;
        }
        if reader.read_exact(&mut hdr).await.is_err() {
            session.close();
            return;
        }

        let cmd = hdr[0];
        let sid = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
        let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;

        // Reads a frame body when present; on IO error closes the session.
        macro_rules! read_body {
            () => {{
                let mut buf = vec![0u8; data_len];
                if reader.read_exact(&mut buf).await.is_err() {
                    session.close();
                    return;
                }
                buf
            }};
        }

        match cmd {
            CMD_PSH => {
                if data_len > 0 {
                    let buf = read_body!();
                    if let Some(tx) = session.streams.lock().unwrap().get(&sid) {
                        let _ = tx.send(Bytes::from(buf));
                    }
                }
            }
            CMD_FIN => {
                session.streams.lock().unwrap().remove(&sid);
            }
            CMD_WASTE | CMD_SYN => {
                // Waste = padding, drop; SYN never comes from a server here
                if data_len > 0 {
                    read_body!();
                }
            }
            CMD_ALERT => {
                if data_len > 0 {
                    let buf = read_body!();
                    tracing::warn!(
                        seq = session.seq,
                        msg = %String::from_utf8_lossy(&buf),
                        "anytls server alert"
                    );
                }
                session.close();
                return;
            }
            CMD_UPDATE_PADDING => {
                if data_len > 0 {
                    let raw = read_body!();
                    if session.padding.update(&raw) {
                        debug!(seq = session.seq, "anytls padding scheme updated");
                    } else {
                        tracing::warn!(seq = session.seq, "anytls invalid padding scheme update");
                    }
                }
            }
            CMD_SYNACK => {
                // data_len == 0: stream confirmed; > 0: server rejected
                if data_len > 0 {
                    let buf = read_body!();
                    tracing::warn!(
                        seq = session.seq,
                        sid,
                        msg = %String::from_utf8_lossy(&buf),
                        "anytls server rejected stream"
                    );
                    // Removing the sender closes the channel: the stream's
                    // poll_read observes EOF/Reset. Sending FIN back is
                    // unnecessary (the server already knows).
                    session.streams.lock().unwrap().remove(&sid);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session.write_control(CMD_HEART_RESPONSE, sid, &[]);
            }
            CMD_HEART_RESPONSE => { /* ignore */ }
            CMD_SERVER_SETTINGS => {
                if data_len > 0 {
                    let buf = read_body!();
                    if let Ok(text) = std::str::from_utf8(&buf) {
                        for line in text.lines() {
                            if let Some(v) = line.strip_prefix("v=") {
                                if let Ok(ver) = v.trim().parse::<u8>() {
                                    session.peer_version.store(ver, Ordering::Release);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Unknown command: read and discard the body
                if data_len > 0 {
                    read_body!();
                }
            }
        }
    }
}

// ── 客户端 stream ────────────────────────────────────────────────────────────

pub struct AnyTlsStream {
    sid: u32,
    session: Arc<AnyTlsSession>,
    data_rx: mpsc::UnboundedReceiver<Bytes>,
    read_buf: Bytes,
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.close_stream_local(self.sid);
        self.session.on_stream_closed();
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Consume the leftover buffer first
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf = self.read_buf.slice(n..);
            return std::task::Poll::Ready(Ok(()));
        }

        match self.data_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data.slice(n..);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // Channel closed → normal EOF, or Reset if the session died
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Ready(Ok(()))
                }
            }
            std::task::Poll::Pending => {
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(self.session.write_data(self.sid, data))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Frames go through the channel immediately; no extra flush needed
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.session.close_stream_local(self.sid);
        std::task::Poll::Ready(Ok(()))
    }
}

// ── 客户端（会话池）─────────────────────────────────────────────────────────

struct ClientInner {
    /// Idle session pool (kept sorted by seq; pop takes the newest)
    idle_sessions: Vec<Arc<AnyTlsSession>>,
    /// All live sessions
    all_sessions: HashMap<u64, Arc<AnyTlsSession>>,
    session_seq: u64,
}

struct AnyTlsOption {
    server: String,
    port: u16,
    password: String,
    sni: String,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    utls: Option<UtlsFingerprint>,
}

pub struct AnyTlsClient {
    inner: Arc<TokioMutex<ClientInner>>,
    padding: Arc<SharedPadding>,
    opts: AnyTlsOption,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AnyTlsClient {
    fn new(cfg: &ProxyConfig) -> Result<Arc<Self>> {
        let opts = AnyTlsOption {
            server: cfg.server.clone(),
            port: cfg.port,
            password: cfg
                .password
                .clone()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("anytls: `password` is required"))?,
            sni: cfg.effective_sni(),
            alpn: cfg.alpn.clone().unwrap_or_default(),
            skip_cert_verify: cfg.skip_cert_verify,
            fingerprint: cfg.fingerprint.clone(),
            utls: cfg
                .client_fingerprint
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| {
                    UtlsFingerprint::parse(s).with_context(|| {
                        format!(
                            "anytls `{}`: unknown client-fingerprint {s:?}",
                            cfg.name
                        )
                    })
                })
                .transpose()?,
        };

        let tls_config = Arc::new(build_tls_config(
            opts.skip_cert_verify,
            &opts.fingerprint,
            &opts.alpn,
        )?);

        let client = Arc::new(Self {
            inner: Arc::new(TokioMutex::new(ClientInner {
                idle_sessions: Vec::new(),
                all_sessions: HashMap::new(),
                session_seq: 0,
            })),
            padding: Arc::new(SharedPadding::new_default()),
            opts,
            tls_config,
        });

        // Idle pool sweeper
        let c = client.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
                c.cleanup_idle().await;
            }
        });

        Ok(client)
    }

    async fn get_or_create_session(self: &Arc<Self>) -> Result<Arc<AnyTlsSession>> {
        {
            let mut inner = self.inner.lock().await;
            while let Some(s) = inner.idle_sessions.pop() {
                if !s.is_closed() {
                    debug!(seq = s.seq, "anytls reuse idle session");
                    return Ok(s);
                }
            }
        }
        self.create_session().await
    }

    async fn create_session(self: &Arc<Self>) -> Result<Arc<AnyTlsSession>> {
        let conn = self.dial_tls().await?;
        let session = {
            let mut inner = self.inner.lock().await;
            inner.session_seq += 1;
            let seq = inner.session_seq;
            let session = AnyTlsSession::new(
                conn,
                self.padding.clone(),
                seq,
                Arc::downgrade(self),
            );
            inner.all_sessions.insert(seq, session.clone());
            session
        };

        // Cleanup hook: drop the session from bookkeeping once closed
        {
            let inner = Arc::downgrade(&self.inner);
            let s = session.clone();
            tokio::spawn(async move {
                s.closed_notify.notified().await;
                if let Some(inner) = inner.upgrade() {
                    let mut g = inner.lock().await;
                    g.all_sessions.remove(&s.seq);
                    g.idle_sessions.retain(|x| x.seq != s.seq);
                }
            });
        }

        debug!(seq = session.seq, "anytls new session created");
        Ok(session)
    }

    /// TLS dial + auth frame. The TCP socket goes through
    /// `sockopt::connect_tcp` → SO_MARK / interface binding (loop prevention).
    async fn dial_tls(&self) -> Result<BoxedStream> {
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let tcp = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("anytls tcp connect {addr}"))?;
        let _ = tcp.set_nodelay(true);

        let tls: TlsStreamBox = match self.opts.utls {
            Some(ref fp) => TlsStreamBox::Utls(Box::new(
                connect_utls(
                    tcp,
                    &self.opts.sni,
                    fp,
                    &UtlsVerify {
                        skip_cert_verify: self.opts.skip_cert_verify,
                        fingerprint: self.opts.fingerprint.clone(),
                    },
                    &self.opts.alpn,
                )
                    .await
                    .context("anytls utls handshake")?,
            )),
            None => {
                let name = ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("anytls: invalid sni {}", self.opts.sni))?;
                TlsStreamBox::Plain(
                    tokio_rustls::TlsConnector::from(self.tls_config.clone())
                        .connect(name, tcp)
                        .await
                        .context("anytls tls handshake")?,
                )
            }
        };

        let mut stream: BoxedStream = Box::new(tls);

        // Auth frame: sha256(password)[32] + padding0_len[2] + padding0
        let auth = build_auth_packet(&self.opts.password, &self.padding.get());
        stream
            .write_all(&auth)
            .await
            .context("anytls send auth")?;
        stream.flush().await?;

        Ok(stream)
    }

    /// Open a proxied stream to `target` (TCP or the UoT magic address).
    async fn create_proxy(self: &Arc<Self>, target: &Target) -> Result<AnyTlsStream> {
        let session = self.get_or_create_session().await?;
        let mut stream = session.open_stream().await?;
        let addr = encode_socks_addr(target);
        stream
            .write_all(&addr)
            .await
            .context("anytls send target addr")?;
        Ok(stream)
    }

    /// Put a session back into the idle pool after its last stream closed.
    async fn return_idle(&self, session: Arc<AnyTlsSession>) {
        if session.is_closed() {
            return;
        }
        *session.idle_since.write().unwrap() = Some(Instant::now());
        let mut inner = self.inner.lock().await;
        // Sorted insert by seq (pop takes the largest seq = newest)
        let pos = inner
            .idle_sessions
            .partition_point(|s| s.seq < session.seq);
        inner.idle_sessions.insert(pos, session);
    }

    /// Close idle sessions past the timeout.
    async fn cleanup_idle(&self) {
        let mut inner = self.inner.lock().await;
        let idle = &mut inner.idle_sessions;
        let mut to_close: Vec<Arc<AnyTlsSession>> = Vec::new();
        idle.retain(|s| {
            let expired = s
                .idle_since
                .read()
                .unwrap()
                .map(|t| t.elapsed() > IDLE_SESSION_TIMEOUT)
                .unwrap_or(false);
            if expired {
                to_close.push(s.clone());
                false
            } else {
                true
            }
        });
        drop(inner);

        for s in to_close {
            debug!(seq = s.seq, "anytls cleanup idle session");
            s.close();
        }
    }
}

/// rustls client config: webpki roots by default; `skip-cert-verify` and/or a
/// sha256 cert `fingerprint` pin switch to the shared custom verifier.
/// `pub(crate)`：naive 出站复用同一套验证逻辑（skip-cert-verify / fingerprint）。
pub(crate) fn build_tls_config(
    skip: bool,
    fingerprint: &Option<String>,
    alpn: &[String],
) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    let mut config = if skip || fingerprint.is_some() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification {
                skip,
                fingerprint: fingerprint.clone(),
            }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(config)
}

/// `pub(crate)`：naive 出站复用（bootstrap DNS 优先，避免解析回环）。
pub(crate) async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Domain: default-nameserver (bootstrap) first, then the system resolver,
    // so a DNS loop back into ant cannot wedge the dial.
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ── 出站 ─────────────────────────────────────────────────────────────────────

pub struct AnyTlsOutbound {
    client: Arc<AnyTlsClient>,
}

impl AnyTlsOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        Ok(Self {
            client: AnyTlsClient::new(cfg)?,
        })
    }
}

#[async_trait]
impl OutboundDialer for AnyTlsOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let target = if let Some(h) = host_hint {
            Target::Domain(
                h.to_string(),
                if addr.port() != 0 { addr.port() } else { 443 },
            )
        } else {
            Target::Socket(addr)
        };
        let stream = self.client.create_proxy(&target).await?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(64);
        Ok(Box::new(AnyTlsUdpSession {
            client: self.client.clone(),
            io: TokioMutex::new(None),
            tx,
            rx: TokioMutex::new(rx),
        }))
    }
}

pub(crate) fn uot_magic_target() -> Target {
    Target::Domain(UOT_MAGIC_ADDRESS.to_string(), UOT_MAGIC_PORT)
}

/// UDP over AnyTLS session via sing UoT v2 (connectionless mode). The stream
/// to the magic address is created lazily on the first `send_to`; the request
/// header uses that first destination, and every datagram carries its own
/// address afterwards.
struct AnyTlsUdpSession {
    client: Arc<AnyTlsClient>,
    /// writer half + header state, created on first send
    io: TokioMutex<Option<UdpIo>>,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    rx: TokioMutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

struct UdpIo {
    writer: WriteHalf<AnyTlsStream>,
    header_sent: bool,
}

#[async_trait]
impl UdpSession for AnyTlsUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let target = match dst_host {
            Some(h) => Target::Domain(h.to_string(), dst.port()),
            None => Target::Socket(dst),
        };
        let mut io = self.io.lock().await;
        if io.is_none() {
            let stream = self.client.create_proxy(&uot_magic_target()).await?;
            let (read_half, writer) = tokio::io::split(stream);
            let tx = self.tx.clone();
            tokio::spawn(async move {
                uot_read_loop(read_half, tx).await;
            });
            *io = Some(UdpIo {
                writer,
                header_sent: false,
            });
        }
        let io = io.as_mut().unwrap();
        if !io.header_sent {
            io.writer
                .write_all(&build_uot_request(&target))
                .await
                .context("anytls uot send header")?;
            io.header_sent = true;
        }
        io.writer
            .write_all(&build_uot_packet(&target, data))
            .await
            .context("anytls uot send packet")?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("anytls udp session closed"))
    }
}

/// Downlink UoT reader: parses UDP packets from the session stream and
/// forwards them to the UdpSession's receive channel.
///
/// 泛型化以便 naive 出站复用（它的隧道流是 `NaiveStream` 而非 AnyTLS 流）。
pub(crate) async fn uot_read_loop<R: AsyncRead + Unpin + Send + 'static>(
    mut rh: R,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) {
    while let Ok((target, data)) = read_uot_packet(&mut rh).await {
        // Domain replies carry no routable IP; report 0.0.0.0:0 like
        // the hysteria2 / tuic outbounds do.
        let src = match target {
            Target::Socket(a) => a,
            Target::Domain(..) => SocketAddr::from(([0, 0, 0, 0], 0)),
        };
        if tx.send((data.to_vec(), src)).await.is_err() {
            break;
        }
    }
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_scheme_parse_default() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.md5_hex.len(), 32);
    }

    #[test]
    fn padding_scheme_generate() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let sizes = scheme.generate_sizes(0);
        assert_eq!(sizes, vec![30]);
        assert!(scheme.generate_sizes(8).is_empty());
    }

    #[test]
    fn socks_addr_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_IPV4);
        assert_eq!(&b[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 80);
    }

    #[test]
    fn socks_addr_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_DOMAIN);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([b[13], b[14]]), 443);
    }

    #[test]
    fn uot_request_header() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let hdr = build_uot_request(&target);
        assert_eq!(hdr[0], 0u8); // isConnect = 0 (connectionless)
        assert_eq!(hdr[1], SOCKS_ATYP_IPV4);
        assert_eq!(&hdr[2..6], &[8, 8, 8, 8]);
        assert_eq!(u16::from_be_bytes([hdr[6], hdr[7]]), 53);
    }

    #[test]
    fn uot_packet_build() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let data = b"dns-query";
        let pkt = build_uot_packet(&target, data);
        assert_eq!(pkt[0], UOT_ATYP_IPV4); // sing ATYP, not SOCKS5
        let data_len = u16::from_be_bytes([pkt[7], pkt[8]]) as usize;
        assert_eq!(data_len, data.len());
        assert_eq!(&pkt[9..9 + data_len], data);
    }

    #[test]
    fn frame_build_syn() {
        let f = build_frame(CMD_SYN, 42, &[]);
        assert_eq!(f[0], CMD_SYN);
        assert_eq!(u32::from_be_bytes(f[1..5].try_into().unwrap()), 42);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 0);
        assert_eq!(f.len(), FRAME_HEADER_SIZE);
    }

    #[test]
    fn frame_build_psh() {
        let data = b"hello";
        let f = build_frame(CMD_PSH, 1, data);
        assert_eq!(f[0], CMD_PSH);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 5);
        assert_eq!(&f[7..], data);
    }

    #[test]
    fn sha256_auth() {
        let hash = password_hash("password");
        assert_eq!(hash[0], 0x5e); // sha256("password") first byte
    }

    #[test]
    fn auth_packet_layout() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let pkt = build_auth_packet("password", &scheme);
        assert_eq!(pkt.len(), 32 + 2 + 30);
        assert_eq!(&pkt[..32], &password_hash("password")[..]);
        assert_eq!(u16::from_be_bytes([pkt[32], pkt[33]]), 30);
    }

    #[test]
    fn padding_apply_noop_after_stop() {
        let scheme = PaddingScheme {
            stop: 0,
            raw: b"stop=0".to_vec(),
            md5_hex: "deadbeef".to_string(),
        };
        let counter = AtomicU32::new(0);
        let data = vec![1u8, 2, 3, 4];
        assert_eq!(apply_padding(&counter, &scheme, data.clone()), data);
    }

    #[test]
    fn padding_first_pkt_uses_scheme_1_not_0() {
        // anytls-go alignment: the first session write must get pkt=1
        // (scheme "1=100-400"), never pkt=0 (reserved for auth padding0).
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let counter = AtomicU32::new(0);
        let data = vec![0xABu8; 10];
        let out = apply_padding(&counter, &scheme, data);
        assert!(
            out.len() >= 100 && out.len() <= 400,
            "expected pkt=1 padding (100..=400 bytes), got {}",
            out.len()
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
