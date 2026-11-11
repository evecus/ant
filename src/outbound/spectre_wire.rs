//! Spectre 线格式 + UDP 分片（从 spectre-master `src/protocol/{mod,udp}.rs` 移植）。
//!
//! 只保留客户端需要的部分：Command / Address / TCP_CONNECT / AUTH /
//! Padding 帧的编解码，以及 QUIC datagram 的 UDP 帧封装与重组。
//! 服务端专用内容（会话表、secure_eq、relay）不移植 —— ant 的出站只需要
//! 单向的客户端视角。
//!
//! ## 与参考实现的差异
//!
//! * **IPv6 字面量加方括号**：参考实现的 `Address` 直接 `format!("{host}:{port}")`，
//!   IPv6 主机名（`2001:db8::1`）会编成 `2001:db8::1:443` 这种无法反解的字符串，
//!   对端 `rsplit_once(':')` 切出的端口是 `1:443`，解析必失败。这里在编码时对
//!   IPv6 字面量套上方括号（`[2001:db8::1]:443`）—— 参考服务端只是把字符串交给
//!   `TcpStream::connect` / `lookup_host`，两者都能正确解析方括号形式，因此对
//!   v4 / 域名目标完全线兼容，同时修掉 IPv6 拨号。
//! * **解码先试 `SocketAddr`**：兼容方括号 IPv6 与 v4，失败再按域名
//!   `rsplit_once(':')`（参考实现的行为）。
//!
//! 注意：参考服务端回传 UDP 响应时用 `from.ip().to_string()` 作主机名，IPv6
//! 场景下同样产出无方括号的歧义字符串（`2001:db8::1:443`），客户端无法无歧义
//! 切分 —— 这是协议固有的限制，参考客户端同样收不到这类包，此处不绕开。

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::Error;

/// 协议版本（PROTOCOL.md v0.1）。
pub const VERSION: u8 = 0x01;

/// bi stream 上的命令字（首字节）。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    TcpConnect = 0x01,
    UdpAssociate = 0x02,
    Auth = 0x03,
    Padding = 0xFF,
}

impl TryFrom<u8> for Command {
    type Error = WireError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Command::TcpConnect),
            0x02 => Ok(Command::UdpAssociate),
            0x03 => Ok(Command::Auth),
            0xFF => Ok(Command::Padding),
            _ => Err(WireError::UnknownCommand(v)),
        }
    }
}

#[derive(Error, Debug)]
pub enum WireError {
    #[error("unknown command: {0:#x}")]
    UnknownCommand(u8),
    #[error("invalid address")]
    InvalidAddress,
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid status")]
    InvalidStatus,
}

/// 地址编码：UTF-8 `host:port`（IPv6 字面量带方括号），u16 长度前缀。
#[derive(Debug, Clone)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

impl Address {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn to_socket_addr_string(&self) -> String {
        if self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// 主机是 IP 字面量时返回 `SocketAddr`；域名返回 `None`。
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        let ip: IpAddr = self.host.parse().ok()?;
        Some(SocketAddr::new(ip, self.port))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let s = self.to_socket_addr_string();
        let len = s.len() as u16;
        buf.put_u16(len);
        buf.put_slice(s.as_bytes());
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        if buf.remaining() < 2 {
            return Err(WireError::BufferTooShort);
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(WireError::BufferTooShort);
        }
        let mut bytes = vec![0u8; len];
        buf.copy_to_slice(&mut bytes);
        let s = String::from_utf8(bytes).map_err(|_| WireError::InvalidAddress)?;
        // 方括号 IPv6 / v4 字面量整体解析；其余（域名）按参考实现切分。
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Self {
                host: addr.ip().to_string(),
                port: addr.port(),
            });
        }
        let (host, port_str) = s.rsplit_once(':').ok_or(WireError::InvalidAddress)?;
        let port: u16 = port_str.parse().map_err(|_| WireError::InvalidAddress)?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

/// TCP_CONNECT（0x01）请求。客户端只编码不解码（服务端才解码请求）。
#[derive(Debug)]
pub struct TcpConnectRequest {
    pub address: Address,
    pub padding: Vec<u8>,
}

impl TcpConnectRequest {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::TcpConnect as u8);
        self.address.encode(&mut buf);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }
}

/// TCP_CONNECT 响应（status + msg + padding）。
#[derive(Debug)]
pub struct TcpConnectResponse {
    pub ok: bool,
    pub message: String,
}

impl TcpConnectResponse {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        if buf.remaining() < 1 {
            return Err(WireError::BufferTooShort);
        }
        let status = buf.get_u8();
        let ok = match status {
            0x00 => true,
            0x01 => false,
            _ => return Err(WireError::InvalidStatus),
        };
        if buf.remaining() < 2 {
            return Err(WireError::BufferTooShort);
        }
        let msg_len = buf.get_u16() as usize;
        if buf.remaining() < msg_len {
            return Err(WireError::BufferTooShort);
        }
        let mut msg_bytes = vec![0u8; msg_len];
        buf.copy_to_slice(&mut msg_bytes);
        let message = String::from_utf8_lossy(&msg_bytes).into_owned();

        // padding 必须消费掉（后续字节属于数据流，见出站的 read_decode_remain），
        // 但其内容是随机字节，无需保留。
        if buf.remaining() < 2 {
            return Err(WireError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(WireError::BufferTooShort);
        }
        buf.advance(pad_len);

        Ok(Self { ok, message })
    }
}

/// AUTH（0x03）请求：显式认证 + Brutal 速率声明。
#[derive(Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    /// 客户端期望的接收速率（下载，字节/秒）。0 = auto。
    pub rx_bps: u64,
    /// 客户端期望的发送速率（上传，字节/秒）。0 = auto。
    pub tx_bps: u64,
    pub padding: Vec<u8>,
}

impl AuthRequest {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Auth as u8);
        buf.put_u8(VERSION);

        let u = self.username.as_bytes();
        buf.put_u16(u.len() as u16);
        buf.put_slice(u);

        let p = self.password.as_bytes();
        buf.put_u16(p.len() as u16);
        buf.put_slice(p);

        buf.put_u64(self.rx_bps);
        buf.put_u64(self.tx_bps);

        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }
}

/// AUTH 响应（status + 协商速率 + msg + padding）。
#[derive(Debug)]
pub struct AuthResponse {
    pub ok: bool,
    /// 服务端偏好接收速率（客户端应以此发送）。
    pub rx_bps: u64,
    /// 服务端偏好发送速率。
    pub tx_bps: u64,
    pub message: String,
}

impl AuthResponse {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        if buf.remaining() < 1 + 8 + 8 + 2 {
            return Err(WireError::BufferTooShort);
        }
        let status = buf.get_u8();
        let ok = status == 0x00;
        let rx_bps = buf.get_u64();
        let tx_bps = buf.get_u64();
        let msg_len = buf.get_u16() as usize;
        if buf.remaining() < msg_len {
            return Err(WireError::BufferTooShort);
        }
        let mut mb = vec![0u8; msg_len];
        buf.copy_to_slice(&mut mb);
        let message = String::from_utf8_lossy(&mb).into_owned();

        // padding 必须消费掉；内容随机，无需保留（同 TcpConnectResponse）。
        if buf.remaining() < 2 {
            return Err(WireError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(WireError::BufferTooShort);
        }
        buf.advance(pad_len);

        Ok(Self {
            ok,
            rx_bps,
            tx_bps,
            message,
        })
    }
}

/// UDP datagram 头（QUIC datagram 负载前缀）。
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        self.address.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        if buf.remaining() < 4 + 2 + 1 + 1 {
            return Err(WireError::BufferTooShort);
        }
        let session_id = buf.get_u32();
        let packet_id = buf.get_u16();
        let fragment_id = buf.get_u8();
        let fragment_count = buf.get_u8();
        let address = Address::decode(buf)?;
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
        })
    }
}

// ── padding ─────────────────────────────────────────────────────────────────

/// 生成 `[range)` 长度内的随机 padding。
pub fn random_padding(range: std::ops::Range<usize>) -> Vec<u8> {
    use rand::{Rng, RngCore};
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// padding 尺寸分档（参考实现 protocol/mod.rs：AUTH 128..1024，TCP 请求
/// 24..256，keepalive 16..512）。宽窄随消息类型变化，避免所有控制消息聚集在
/// 同一尺寸区间形成统计特征。
pub const AUTH_PADDING: std::ops::Range<usize> = 128..1024;
pub const TCP_REQUEST_PADDING: std::ops::Range<usize> = 24..256;
/// 应用层 keepalive（`PaddingFrame`）的 padding 区间。
pub const KEEPALIVE_PADDING: std::ops::Range<usize> = 16..512;

/// 纯 padding / keepalive 帧（0xFF）。
#[derive(Debug)]
pub struct PaddingFrame {
    pub padding: Vec<u8>,
}

impl PaddingFrame {
    /// 从 `KEEPALIVE_PADDING` 随机取长度。
    pub fn random() -> Self {
        Self {
            padding: random_padding(KEEPALIVE_PADDING),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Padding as u8);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }
}

/// 抖动间隔：`base` 加上最大 `jitter_frac * base` 的均匀随机抖动，
/// 使相邻间隔不完全相同（固定间隔的 keepalive 本身是时序指纹）。
pub fn jittered_interval(base: Duration, jitter_frac: f64) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(0.0..jitter_frac.max(0.0));
    base.mul_f64(1.0 + jitter)
}

// ── UDP 分片与重组 ───────────────────────────────────────────────────────────

/// 单个 QUIC datagram 试图承载的最大 payload（不含 UDP 帧头）。
pub const DEFAULT_MAX_DATAGRAM_PAYLOAD: usize = 1200;
/// 接受的最大分片数。
const MAX_FRAGMENTS: u8 = 64;
/// 每会话最大未完成重组槽位数。
const MAX_REASSEMBLY_SLOTS: usize = 256;
/// 未完成分片包的过期时间。
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);

/// 一个在途分片包的键。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    session_id: u32,
    packet_id: u16,
}

#[derive(Debug)]
struct FragSlot {
    total: u8,
    parts: HashMap<u8, Bytes>,
    address: Address,
    created: Instant,
}

impl FragSlot {
    fn new(total: u8, address: Address) -> Self {
        Self {
            total,
            parts: HashMap::new(),
            address,
            created: Instant::now(),
        }
    }

    /// 插入一个分片；全部到齐时返回完整 payload。
    fn insert(&mut self, id: u8, data: Bytes) -> Option<(Address, Bytes)> {
        if id >= self.total {
            return None;
        }
        self.parts.insert(id, data);
        if self.parts.len() == self.total as usize {
            let mut out = BytesMut::new();
            for i in 0..self.total {
                let p = self.parts.remove(&i)?;
                out.extend_from_slice(&p);
            }
            Some((self.address.clone(), out.freeze()))
        } else {
            None
        }
    }
}

/// Spectre UDP datagram 重组器（可能分片的入站 datagram）。
pub struct FragmentReassembler {
    slots: HashMap<FragKey, FragSlot>,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    /// 喂入一个 datagram 负载（已解密的 QUIC datagram body）。
    /// 完整包就绪时返回 `Some((session_id, address, payload))`。
    pub fn push(&mut self, data: Bytes) -> Result<Option<(u32, Address, Bytes)>, WireError> {
        self.gc();
        let mut buf = data.clone();
        let header = UdpHeader::decode(&mut buf)?;
        let payload = buf.copy_to_bytes(buf.remaining());

        if header.fragment_count == 0 || header.fragment_count > MAX_FRAGMENTS {
            return Err(WireError::BufferTooShort);
        }

        // 未分片快路径
        if header.fragment_count == 1 {
            return Ok(Some((header.session_id, header.address, payload)));
        }

        let key = FragKey {
            session_id: header.session_id,
            packet_id: header.packet_id,
        };

        if self.slots.len() >= MAX_REASSEMBLY_SLOTS && !self.slots.contains_key(&key) {
            // 淘汰最旧的槽
            if let Some(old) = self
                .slots
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| *k)
            {
                self.slots.remove(&old);
            }
        }

        let slot = self
            .slots
            .entry(key)
            .or_insert_with(|| FragSlot::new(header.fragment_count, header.address.clone()));

        if slot.total != header.fragment_count {
            // 分片数不一致 —— 丢弃该槽
            self.slots.remove(&key);
            return Ok(None);
        }

        if let Some((addr, full)) = slot.insert(header.fragment_id, payload) {
            self.slots.remove(&key);
            Ok(Some((header.session_id, addr, full)))
        } else {
            Ok(None)
        }
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.slots
            .retain(|_, s| now.duration_since(s.created) < REASSEMBLY_TTL);
    }
}

/// 把一个大 UDP payload 切成可装入 `max_datagram` 的 Spectre UDP 帧。
pub fn fragment_udp(
    session_id: u32,
    packet_id: u16,
    address: &Address,
    payload: &[u8],
    max_datagram: usize,
) -> Vec<Bytes> {
    // 帧头估算：4+2+1+1 + 2+addr + 余量
    let addr_len = address.to_socket_addr_string().len() + 2;
    let hdr_overhead = 4 + 2 + 1 + 1 + addr_len + 8;
    let max_payload = max_datagram.saturating_sub(hdr_overhead).max(200);

    if payload.len() <= max_payload {
        let mut buf = BytesMut::with_capacity(hdr_overhead + payload.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(payload);
        return vec![buf.freeze()];
    }

    let chunks: Vec<&[u8]> = payload.chunks(max_payload).collect();
    let total = chunks.len().min(MAX_FRAGMENTS as usize) as u8;
    let mut out = Vec::with_capacity(total as usize);
    for (i, chunk) in chunks.iter().enumerate().take(total as usize) {
        let mut buf = BytesMut::with_capacity(hdr_overhead + chunk.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: i as u8,
            fragment_count: total,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(chunk);
        out.push(buf.freeze());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_v4_roundtrip() {
        let a = Address::new("1.2.3.4", 443);
        let mut b = BytesMut::new();
        a.encode(&mut b);
        assert_eq!(&b[..2], &[0, 11]); // "1.2.3.4:443" len
        let mut slice: &[u8] = &b;
        let got = Address::decode(&mut slice).unwrap();
        assert_eq!(got.host, "1.2.3.4");
        assert_eq!(got.port, 443);
        assert!(slice.is_empty());
    }

    #[test]
    fn address_domain_roundtrip() {
        let a = Address::new("example.com", 8443);
        let mut b = BytesMut::new();
        a.encode(&mut b);
        let mut slice: &[u8] = &b;
        let got = Address::decode(&mut slice).unwrap();
        assert_eq!(got.host, "example.com");
        assert_eq!(got.port, 8443);
    }

    #[test]
    fn address_ipv6_bracketed() {
        // 编码时 IPv6 字面量带方括号；解码走 SocketAddr 快路径。
        let a = Address::new("2001:db8::1", 443);
        let s = a.to_socket_addr_string();
        assert_eq!(s, "[2001:db8::1]:443");
        let mut b = BytesMut::new();
        a.encode(&mut b);
        let mut slice: &[u8] = &b;
        let got = Address::decode(&mut slice).unwrap();
        assert_eq!(got.host, "2001:db8::1");
        assert_eq!(got.port, 443);
        assert_eq!(got.to_socket_addr(), Some("[2001:db8::1]:443".parse().unwrap()));
    }

    #[test]
    fn address_decode_rejects_garbage() {
        let mut b = BytesMut::new();
        b.put_u16(4);
        b.put_slice(b"nope");
        let mut slice: &[u8] = &b;
        assert!(Address::decode(&mut slice).is_err());
        // 端口非数字
        let mut b = BytesMut::new();
        b.put_u16(12);
        b.put_slice(b"example:abc");
        let mut slice: &[u8] = &b;
        assert!(Address::decode(&mut slice).is_err());
    }

    #[test]
    fn tcp_connect_request_layout() {
        // 客户端只编码请求；用运行时会用到的 Address::decode 手工走一遍帧布局。
        let req = TcpConnectRequest {
            address: Address::new("example.com", 443),
            padding: vec![1, 2, 3],
        };
        let buf = req.encode();
        let mut slice: &[u8] = &buf;
        let cmd = Command::try_from(slice.get_u8()).unwrap();
        assert_eq!(cmd, Command::TcpConnect);
        let addr = Address::decode(&mut slice).unwrap();
        assert_eq!(addr.host, "example.com");
        assert_eq!(addr.port, 443);
        let pad_len = slice.get_u16();
        assert_eq!(pad_len, 3);
        let mut pad = vec![0u8; pad_len as usize];
        slice.copy_to_slice(&mut pad);
        assert_eq!(pad, vec![1, 2, 3]);
        assert!(slice.is_empty());
    }

    #[test]
    fn tcp_connect_response_ok_and_err() {
        // 手工编码 ok 响应：status=0, msg_len=0, pad_len=2, pad
        let mut b = BytesMut::new();
        b.put_u8(0x00);
        b.put_u16(0);
        b.put_u16(2);
        b.put_slice(&[0xaa, 0xbb]);
        let mut slice: &[u8] = &b;
        let resp = TcpConnectResponse::decode(&mut slice).unwrap();
        assert!(resp.ok);

        // err 响应带消息
        let mut b = BytesMut::new();
        b.put_u8(0x01);
        let msg = b"refused";
        b.put_u16(msg.len() as u16);
        b.put_slice(msg);
        b.put_u16(0);
        let mut slice: &[u8] = &b;
        let resp = TcpConnectResponse::decode(&mut slice).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.message, "refused");

        // 非 0/1 状态 → InvalidStatus
        let mut b = BytesMut::new();
        b.put_u8(0x07);
        let mut slice: &[u8] = &b;
        assert!(matches!(
            TcpConnectResponse::decode(&mut slice),
            Err(WireError::InvalidStatus)
        ));

        // 截断 → BufferTooShort
        let mut slice: &[u8] = &[0x00u8][..];
        assert!(matches!(
            TcpConnectResponse::decode(&mut slice),
            Err(WireError::BufferTooShort)
        ));
    }

    #[test]
    fn auth_roundtrip() {
        let req = AuthRequest {
            username: "spectre".into(),
            password: "s3cret".into(),
            rx_bps: 200 * 1024 * 1024,
            tx_bps: 50 * 1024 * 1024,
            padding: vec![9; 16],
        };
        let buf = req.encode();
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], VERSION);

        // ok 响应：status=0 + rx + tx + msg_len=0 + pad_len=0
        let mut rb = BytesMut::new();
        rb.put_u8(0x00);
        rb.put_u64(111);
        rb.put_u64(222);
        rb.put_u16(0);
        rb.put_u16(0);
        let mut slice: &[u8] = &rb;
        let resp = AuthResponse::decode(&mut slice).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.rx_bps, 111);
        assert_eq!(resp.tx_bps, 222);

        // 非 0 状态 → not ok（参考实现语义）
        let mut rb = BytesMut::new();
        rb.put_u8(0x01);
        rb.put_u64(0);
        rb.put_u64(0);
        rb.put_u16(0);
        rb.put_u16(0);
        let mut slice: &[u8] = &rb;
        let resp = AuthResponse::decode(&mut slice).unwrap();
        assert!(!resp.ok);
    }

    #[test]
    fn udp_single_fragment_roundtrip() {
        let addr = Address::new("8.8.8.8", 53);
        let frames = fragment_udp(7, 1, &addr, b"hello dns", DEFAULT_MAX_DATAGRAM_PAYLOAD);
        assert_eq!(frames.len(), 1);
        let mut reasm = FragmentReassembler::new();
        let (sid, got_addr, payload) = reasm.push(frames[0].clone()).unwrap().unwrap();
        assert_eq!(sid, 7);
        assert_eq!(got_addr.host, "8.8.8.8");
        assert_eq!(got_addr.port, 53);
        assert_eq!(&payload[..], b"hello dns");
    }

    #[test]
    fn udp_multi_fragment_roundtrip() {
        let addr = Address::new("example.com", 1234);
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        // 强制小 datagram 触发分片
        let frames = fragment_udp(42, 9, &addr, &payload, 800);
        assert!(frames.len() > 1);
        assert!(frames.len() <= 64);
        let mut reasm = FragmentReassembler::new();
        let mut out = None;
        for f in frames {
            if let Some(v) = reasm.push(f).unwrap() {
                assert!(out.is_none(), "complete packet emitted twice");
                out = Some(v);
            }
        }
        let (sid, got_addr, full) = out.expect("reassembled");
        assert_eq!(sid, 42);
        assert_eq!(got_addr.host, "example.com");
        assert_eq!(full.len(), payload.len());
        assert_eq!(&full[..], &payload[..]);
    }

    #[test]
    fn udp_bad_fragment_count_rejected() {
        let addr = Address::new("8.8.8.8", 53);
        let mut b = BytesMut::new();
        let h = UdpHeader {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 0,
            address: addr,
        };
        h.encode(&mut b);
        b.extend_from_slice(b"x");
        let mut reasm = FragmentReassembler::new();
        assert!(reasm.push(b.freeze()).is_err());
    }

    #[test]
    fn padding_frame_and_jitter() {
        let f = PaddingFrame::random();
        let buf = f.encode();
        assert_eq!(buf[0], 0xFF);
        assert!(buf.len() >= 2 + 16 && buf.len() <= 2 + 512);

        let base = Duration::from_secs(20);
        for _ in 0..32 {
            let j = jittered_interval(base, 0.5);
            assert!(j >= base && j <= base.mul_f64(1.5));
        }
    }

    #[test]
    fn command_try_from() {
        assert_eq!(Command::try_from(0x01).unwrap(), Command::TcpConnect);
        assert_eq!(Command::try_from(0xFF).unwrap(), Command::Padding);
        assert!(Command::try_from(0x99).is_err());
    }
}
