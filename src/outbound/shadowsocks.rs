//! Shadowsocks 出站 —— ported from reflex `src/outbound/shadowsocks.rs`
//! （对齐 sing-box / sing-shadowsocks2 规范）。
//!
//! 加密方法
//! * 传统 AEAD：`aes-128-gcm` / `aes-256-gcm` / `chacha20-ietf-poly1305`
//! * AEAD-2022：`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
//!   `2022-blake3-chacha20-poly1305`（密码为 base64 PSK）
//! * `none`：明文（仅测试用）
//!
//! 传输与加密
//! * `network` = `tcp` | `ws` | `xhttp`，与 vless / vmess 复用同一套
//!   `ws` / `xhttp`(stream-one) / `xhttp_h2`(packet-up, stream-up) 实现。
//! * TLS 层复用 `vless::build_tls_client_config`；`client-fingerprint`
//!   走 uTLS 浏览器指纹。
//!
//! 防回环（SO_MARK）
//! * 所有出站 socket 一律走 `app::sockopt::connect_tcp` / `bind_udp`，
//!   SO_MARK + SO_BINDTODEVICE 与其他协议、直连完全一致，无需额外传参。
//!
//! UDP
//! * Shadowsocks 的 UDP 是**原生 UDP 中继**（每包自带 SOCKS5 地址头），
//!   因此只有 `network: tcp` 支持；ws / xhttp 没有 UoT，`dial_udp` 直接报错
//!   （fail-fast，而不是静默退化成不可用连接）。

use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint};
use super::vless::{build_tls_client_config, XhttpResolved};
use super::ws::{self, WsOptions, WsStream, WS_HANDSHAKE_TIMEOUT};
use super::xhttp::{connect_over_stream, XhttpConfig};
use super::xhttp_h2;
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;

// ── 加密方法 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022ChaCha20Poly1305,
    None,
}

impl Method {
    /// 解析配置字符串（`cipher` / `method` 字段）。未知值 fail-fast。
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Self::ChaCha20Poly1305,
            "2022-blake3-aes-128-gcm" => Self::Ss2022Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Ss2022Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Ss2022ChaCha20Poly1305,
            "none" | "plain" => Self::None,
            other => bail!(
                "unsupported shadowsocks method `{other}`; \
                 supported: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, \
                 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, \
                 2022-blake3-chacha20-poly1305, none"
            ),
        })
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Ss2022Aes256Gcm
            | Self::Ss2022ChaCha20Poly1305 => 32,
            Self::None => 0,
        }
    }

    /// SS 的 salt 长度等于 key 长度（传统 AEAD 与 AEAD-2022 皆然）。
    fn salt_len(self) -> usize {
        self.key_len()
    }

    fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022ChaCha20Poly1305
        )
    }
}

/// 配置校验入口（`config.rs` 的 validate 复用，保证与运行时是同一张方法表）。
pub fn validate_method(s: &str) -> Result<()> {
    Method::parse(s).map(|_| ())
}

const TAG_LEN: usize = 16;
/// SS 单个 chunk 的明文上限（长度字段是 u16 且最高两位保留）。
const MAX_PAYLOAD: usize = 0x3FFF;
/// AEAD-2022 UDP：AES 变体用 16 字节 AES-ECB 加密头。
const SS2022_AES_HEADER_LEN: usize = 16;
/// AEAD-2022 UDP：ChaCha 变体用 24 字节 XChaCha20 nonce。
const SS2022_CHACHA_NONCE_LEN: usize = 24;
const SS2022_HEADER_TYPE_CLIENT: u8 = 0;
const SS2022_HEADER_TYPE_SERVER: u8 = 1;
const SS2022_MAX_PADDING: usize = 900;
/// AEAD-2022 BLAKE3 `derive_key` 上下文（sing-shadowsocks2 固定字符串）。
const SS2022_DERIVE_KEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
/// 时间戳容差（秒），超过即判定为重放。
const TIMESTAMP_TOLERANCE: u64 = 30;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

// ── 密钥派生 ──────────────────────────────────────────────────────────────────

/// EVP_BytesToKey（MD5 KDF）：密码字符串 → master key（传统 AEAD）。
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// HKDF-SHA1：master key + salt → session subkey（传统 AEAD）。
fn hkdf_sha1(master_key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<sha1::Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF-SHA1 expand failed");
    okm
}

/// BLAKE3-KDF：PSK + salt → session subkey（AEAD-2022）。
///
/// 规范用 BLAKE3 的 `derive_key` 模式（不是 `keyed_hash`），上下文固定为
/// `"shadowsocks 2022 session subkey"`。`derive_key` 内部会把 context 哈希成
/// 内部密钥，因此 PSK 可以是 16 或 32 字节。
fn ss2022_session_key(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(psk.len() + salt.len());
    input.extend_from_slice(psk);
    input.extend_from_slice(salt);
    let derived = blake3::derive_key(SS2022_DERIVE_KEY_CONTEXT, &input);
    derived[..key_len].to_vec()
}

// ── AEAD 加解密 ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AeadCipher {
    method: Method,
    subkey: Vec<u8>,
    counter: u64,
}

impl AeadCipher {
    fn new(method: Method, subkey: Vec<u8>) -> Self {
        Self {
            method,
            subkey,
            counter: 0,
        }
    }

    /// 指定 counter 的版本：UDP 的 nonce 由报文头给出，不走自增。
    fn with_counter(method: Method, subkey: Vec<u8>, counter: u64) -> Self {
        Self {
            method,
            subkey,
            counter,
        }
    }

    /// Shadowsocks 的 nonce = 计数器小端写入前 8 字节，后 4 字节为 0。
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// 原地加密并追加 16B tag，递增 counter。
    fn seal(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let nonce = self.nonce();
        self.seal_with(&nonce, buf)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    fn seal_with(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let tag = self.seal_inner(nonce, buf)?;
        buf.extend_from_slice(&tag);
        Ok(())
    }

    fn seal_inner(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        macro_rules! do_seal {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey).context("cipher init")?;
                let tag = c
                    .encrypt_in_place_detached(nonce.into(), b"", buf)
                    .map_err(|_| anyhow!("ss encrypt failed"))?;
                let mut out = [0u8; TAG_LEN];
                out.copy_from_slice(tag.as_slice());
                out
            }};
        }
        Ok(match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_seal!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_seal!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => {
                do_seal!(ChaCha20Poly1305)
            }
            Method::None => [0u8; TAG_LEN],
        })
    }

    /// 原地解密（含尾部 tag），去掉 tag，递增 counter。
    fn open(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        if buf.len() < TAG_LEN {
            bail!("ss ciphertext too short");
        }
        let nonce = self.nonce();
        self.open_with(&nonce, buf)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    fn open_with(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        if buf.len() < TAG_LEN {
            bail!("ss ciphertext too short");
        }
        macro_rules! do_open {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey).context("cipher init")?;
                c.decrypt_in_place(nonce.into(), b"", buf)
                    .map_err(|_| anyhow!("ss decrypt failed"))?;
            }};
        }
        match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_open!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_open!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => {
                do_open!(ChaCha20Poly1305)
            }
            Method::None => {}
        }
        Ok(())
    }

    /// 预检解密（不推进 counter）：只为了提前读出 payload 长度。
    fn peek_open(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> bool {
        self.open_with(nonce, buf).is_ok()
    }
}

// ── AEAD-2022 UDP 报文 ────────────────────────────────────────────────────────

fn ss2022_is_aes(method: Method) -> bool {
    matches!(method, Method::Ss2022Aes128Gcm | Method::Ss2022Aes256Gcm)
}

/// 用 PSK 做单块 AES-ECB 加密（AEAD-2022 UDP 报文头）。
fn aes_ecb_encrypt_block(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let mut b = aes::Block::clone_from_slice(block);
    if key.len() == 16 {
        aes::Aes128::new_from_slice(key).expect("aes-128 psk").encrypt_block(&mut b);
    } else {
        aes::Aes256::new_from_slice(key).expect("aes-256 psk").encrypt_block(&mut b);
    }
    block.copy_from_slice(&b);
}

fn aes_ecb_decrypt_block(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let mut b = aes::Block::clone_from_slice(block);
    if key.len() == 16 {
        aes::Aes128::new_from_slice(key).expect("aes-128 psk").decrypt_block(&mut b);
    } else {
        aes::Aes256::new_from_slice(key).expect("aes-256 psk").decrypt_block(&mut b);
    }
    block.copy_from_slice(&b);
}

/// AEAD-2022 UDP 封包（AES 变体）。
///
/// `body` 明文必须已含 `[headerType][timestamp][paddingLen][padding][SOCKS 地址][payload]`。
fn ss2022_udp_seal_aes(
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    body: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    let key_len = psk.len();
    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&session_id.to_be_bytes());
    hdr[8..].copy_from_slice(&packet_id.to_be_bytes());
    // nonce 取**加密前**的 header[4..16]（同 sing-shadowsocks2 WritePacket）。
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    let subkey = ss2022_session_key(psk, &session_id.to_be_bytes(), key_len);
    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    AeadCipher::with_counter(method, subkey, 0).seal_with(&nonce, body)?;

    aes_ecb_encrypt_block(&mut hdr, psk);
    let mut wire = Vec::with_capacity(SS2022_AES_HEADER_LEN + body.len());
    wire.extend_from_slice(&hdr);
    wire.extend_from_slice(body);
    Ok(wire)
}

fn ss2022_udp_open_aes(psk: &[u8], buf: &[u8]) -> Result<Vec<u8>> {
    if buf.len() <= SS2022_AES_HEADER_LEN + TAG_LEN {
        bail!("ss2022 udp: frame too short");
    }
    let key_len = psk.len();
    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&buf[..SS2022_AES_HEADER_LEN]);
    aes_ecb_decrypt_block(&mut hdr, psk);

    let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());
    let subkey = ss2022_session_key(psk, &session_id.to_be_bytes(), key_len);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    let mut ct = buf[SS2022_AES_HEADER_LEN..].to_vec();
    AeadCipher::with_counter(method, subkey, 0).open_with(&nonce, &mut ct)?;
    Ok(ct)
}

/// AEAD-2022 UDP 封包（ChaCha 变体：XChaCha20-Poly1305，nonce 24B 明文在前）。
fn ss2022_udp_seal_chacha(
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    nonce24: &[u8; 24],
    body: &mut [u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        XChaCha20Poly1305,
    };
    let mut plaintext = Vec::with_capacity(16 + body.len());
    plaintext.extend_from_slice(&session_id.to_be_bytes());
    plaintext.extend_from_slice(&packet_id.to_be_bytes());
    plaintext.extend_from_slice(body);

    let cipher = XChaCha20Poly1305::new_from_slice(psk).context("xchacha20 key init")?;
    let tag = cipher
        .encrypt_in_place_detached(nonce24.into(), b"", &mut plaintext)
        .map_err(|_| anyhow!("ss2022 udp encrypt failed"))?;

    let mut wire = Vec::with_capacity(SS2022_CHACHA_NONCE_LEN + plaintext.len() + TAG_LEN);
    wire.extend_from_slice(nonce24);
    wire.extend_from_slice(&plaintext);
    wire.extend_from_slice(&tag);
    Ok(wire)
}

fn ss2022_udp_open_chacha(psk: &[u8], buf: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{aead::KeyInit, XChaCha20Poly1305};
    if buf.len() <= SS2022_CHACHA_NONCE_LEN + TAG_LEN {
        bail!("ss2022 udp chacha: frame too short");
    }
    let nonce24: &[u8; 24] = buf[..SS2022_CHACHA_NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("ss2022 udp: bad nonce"))?;
    let mut ct = buf[SS2022_CHACHA_NONCE_LEN..].to_vec();
    let cipher = XChaCha20Poly1305::new_from_slice(psk).context("xchacha20 key init")?;
    cipher
        .decrypt_in_place(nonce24.into(), b"", &mut ct)
        .map_err(|_| anyhow!("ss2022 udp decrypt failed"))?;
    if ct.len() < 16 {
        bail!("ss2022 udp chacha: body too short");
    }
    Ok(ct[16..].to_vec())
}

/// 构造 AEAD-2022 UDP 客户端请求体（加密前明文）。
fn ss2022_udp_client_body(timestamp: u64, socks_addr: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 8 + 2 + socks_addr.len() + payload.len());
    body.push(SS2022_HEADER_TYPE_CLIENT);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // paddingLen = 0
    body.extend_from_slice(socks_addr);
    body.extend_from_slice(payload);
    body
}

/// 切分 AEAD-2022 UDP 服务端响应体，返回 `(SOCKS 地址字节, payload)`。
///
/// 响应体格式：`[type=1][timestamp 8B][clientSessionId 8B][paddingLen 2B][padding][SOCKS 地址][payload]`
fn ss2022_udp_split_server_body(body: &[u8]) -> Option<(&[u8], &[u8])> {
    if body.len() < 19 {
        return None;
    }
    if body[0] != SS2022_HEADER_TYPE_SERVER {
        return None;
    }
    let epoch = u64::from_be_bytes(body[1..9].try_into().ok()?);
    if now_secs().abs_diff(epoch) > TIMESTAMP_TOLERANCE {
        return None;
    }
    let padding_len = u16::from_be_bytes([body[17], body[18]]) as usize;
    let start = 19 + padding_len;
    if body.len() < start {
        return None;
    }
    split_socks_addr(&body[start..])
}

// ── SOCKS5 地址编解码 ─────────────────────────────────────────────────────────

/// 目标地址 → SOCKS5 地址字节（含端口）。有 `host_hint` 且不是 IP 时用域名形式，
/// 保证服务端拿到的是原始域名（与 vless / vmess 的 host_hint 语义一致）。
fn encode_target(addr: SocketAddr, host_hint: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    if let Some(host) = host_hint {
        if !host.is_empty() && host.parse::<IpAddr>().is_err() {
            let h = host.as_bytes();
            let len = h.len().min(255);
            buf.push(ATYP_DOMAIN);
            buf.push(len as u8);
            buf.extend_from_slice(&h[..len]);
            buf.extend_from_slice(&addr.port().to_be_bytes());
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
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}

/// 切出 `(完整 SOCKS 地址字节, 后续 payload)`。
fn split_socks_addr(pkt: &[u8]) -> Option<(&[u8], &[u8])> {
    let (atyp, rest) = pkt.split_first()?;
    let body_len = match *atyp {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let l = *rest.first()? as usize;
            1 + l + 2
        }
        _ => return None,
    };
    let end = 1 + body_len;
    if pkt.len() < end {
        return None;
    }
    Some((&pkt[..end], &pkt[end..]))
}

/// SOCKS5 地址字节 → SocketAddr（域名形式无法转换，返回 None）。
fn socks_addr_to_socket(addr: &[u8]) -> Option<SocketAddr> {
    let ip = match *addr.first()? {
        ATYP_IPV4 => IpAddr::V4(std::net::Ipv4Addr::new(
            addr.get(1).copied()?,
            addr.get(2).copied()?,
            addr.get(3).copied()?,
            addr.get(4).copied()?,
        )),
        ATYP_IPV6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(addr.get(1..17)?);
            IpAddr::V6(std::net::Ipv6Addr::from(o))
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([addr[addr.len() - 2], addr[addr.len() - 1]]);
    Some(SocketAddr::new(ip, port))
}

// ── SS 流（AEAD 分帧）─────────────────────────────────────────────────────────

/// 把任意 `AsyncRead + AsyncWrite` 流包装成 Shadowsocks 加解密流。
///
/// 写侧：每次 write 的数据按 `MAX_PAYLOAD` 切块，逐块写 `[enc(len 2B)+tag][enc(payload)+tag]`。
/// 读侧：首次读时先消费服务端 salt（AEAD-2022 还有响应头 + padding），再进入标准分帧。
struct SsStream<S> {
    inner: S,
    enc: AeadCipher,
    /// 延迟初始化：salt 到达后派生服务端 subkey 才建立。
    dec: Option<AeadCipher>,
    method: Method,
    /// PSK（AEAD-2022）或 master key（传统 AEAD），用于派生服务端 subkey。
    key_material: Vec<u8>,
    /// AEAD-2022 请求 salt，用于校验响应里的 responseSalt。
    request_salt: Option<Vec<u8>>,
    /// 已解密但尚未交给调用方的明文。
    read_buf: Vec<u8>,
    /// 从底层读到的密文缓冲。
    raw_buf: Vec<u8>,
    /// 已加密但底层尚未接收的字节（底层写缓冲满时暂存）。
    write_buf: Vec<u8>,
    /// AEAD-2022 响应头是否已读完。
    ss2022_response_read: bool,
}

impl<S> SsStream<S> {
    fn new(
        inner: S,
        enc: AeadCipher,
        method: Method,
        key_material: Vec<u8>,
        request_salt: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            enc,
            dec: None,
            method,
            key_material,
            request_salt,
            read_buf: Vec::new(),
            raw_buf: Vec::new(),
            write_buf: Vec::new(),
            ss2022_response_read: false,
        }
    }
}

/// 从底层读一段数据追加到 `raw`。`Ok(true)` = 读到数据，`Ok(false)` = EOF。
fn poll_fill<S: AsyncRead + Unpin>(
    inner: &mut S,
    raw: &mut Vec<u8>,
    cx: &mut TaskContext<'_>,
) -> Poll<io::Result<bool>> {
    let mut tmp = [0u8; 8192];
    let mut rb = ReadBuf::new(&mut tmp);
    match Pin::new(inner).poll_read(cx, &mut rb) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Ready(Ok(())) => {
            let filled = rb.filled();
            if filled.is_empty() {
                Poll::Ready(Ok(false))
            } else {
                raw.extend_from_slice(filled);
                Poll::Ready(Ok(true))
            }
        }
    }
}

fn ss_io_err(e: anyhow::Error) -> io::Error {
    io::Error::other(e)
}

impl<S> AsyncRead for SsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
                this.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }

            // 阶段 0：读服务端 salt，派生解密 subkey。
            if this.dec.is_none() {
                let salt_len = this.method.salt_len();
                if this.raw_buf.len() < salt_len {
                    match poll_fill(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let salt: Vec<u8> = this.raw_buf[..salt_len].to_vec();
                this.raw_buf.drain(..salt_len);
                let key_len = this.method.key_len();
                let subkey = if this.method.is_2022() {
                    ss2022_session_key(&this.key_material, &salt, key_len)
                } else {
                    hkdf_sha1(&this.key_material, &salt, key_len)
                };
                this.dec = Some(AeadCipher::new(this.method, subkey));
                continue;
            }

            // 阶段 1（AEAD-2022）：fixed response header（nonce 0）+ padding buffer（nonce 1）。
            if this.method.is_2022() && !this.ss2022_response_read {
                let key_len = this.method.key_len();
                let fixed_len = 1 + 8 + key_len + 2 + TAG_LEN;
                if this.raw_buf.len() < fixed_len {
                    match poll_fill(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ss2022 response: EOF during fixed header",
                            )))
                        }
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let mut fixed = this.raw_buf[..fixed_len].to_vec();
                this.raw_buf.drain(..fixed_len);
                let dec = this.dec.as_mut().expect("dec initialized");
                dec.open(&mut fixed).map_err(ss_io_err)?;
                if fixed[0] != SS2022_HEADER_TYPE_SERVER {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "ss2022 response: bad header type {}, expected {}",
                        fixed[0], SS2022_HEADER_TYPE_SERVER
                    ))));
                }
                let epoch = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
                if now_secs().abs_diff(epoch) > TIMESTAMP_TOLERANCE {
                    return Poll::Ready(Err(io::Error::other(
                        "ss2022 response: bad timestamp",
                    )));
                }
                if let Some(req) = &this.request_salt {
                    if &fixed[9..9 + key_len] != req.as_slice() {
                        return Poll::Ready(Err(io::Error::other(
                            "ss2022 response: response salt mismatch",
                        )));
                    }
                }
                let padding_len =
                    u16::from_be_bytes([fixed[9 + key_len], fixed[10 + key_len]]) as usize;
                let pad_needed = padding_len + TAG_LEN;
                if this.raw_buf.len() < pad_needed {
                    match poll_fill(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ss2022 response: EOF during padding",
                            )))
                        }
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let mut pad = this.raw_buf[..pad_needed].to_vec();
                this.raw_buf.drain(..pad_needed);
                let dec = this.dec.as_mut().expect("dec initialized");
                dec.open(&mut pad).map_err(ss_io_err)?;
                this.ss2022_response_read = true;
                continue;
            }

            // 阶段 2：标准分帧 `[enc(len 2B)+tag][enc(payload)+tag]`。
            let len_chunk = 2 + TAG_LEN;
            if this.raw_buf.len() >= len_chunk {
                let dec = this.dec.as_ref().expect("dec initialized");
                let nonce = dec.nonce();
                let mut peek = this.raw_buf[..len_chunk].to_vec();
                if !dec.peek_open(&nonce, &mut peek) {
                    return Poll::Ready(Err(io::Error::other(
                        "ss: length chunk decrypt failed",
                    )));
                }
                let payload_len = u16::from_be_bytes([peek[0], peek[1]]) as usize;
                let total = len_chunk + payload_len + TAG_LEN;
                if this.raw_buf.len() >= total {
                    let mut len_part = this.raw_buf[..len_chunk].to_vec();
                    let mut payload_part = this.raw_buf[len_chunk..total].to_vec();
                    this.raw_buf.drain(..total);
                    let dec = this.dec.as_mut().expect("dec initialized");
                    dec.open(&mut len_part).map_err(ss_io_err)?;
                    dec.open(&mut payload_part).map_err(ss_io_err)?;
                    this.read_buf.extend_from_slice(&payload_part);
                    continue;
                }
            }

            match poll_fill(&mut this.inner, &mut this.raw_buf, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(true)) => {}
            }
        }
    }
}

impl<S> AsyncWrite for SsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1) 先把上一次没写完的密文推干净。推不完就直接 Pending：此时 `data`
        //    还没被加密，调用方用同一份 data 重试不会产出重复密文。
        {
            let inner = &mut this.inner;
            let write_buf = &mut this.write_buf;
            while !write_buf.is_empty() {
                match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(m)) => { write_buf.drain(..m); }
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            if !write_buf.is_empty() {
                return Poll::Pending;
            }
        }

        // 2) 用计数器副本加密：只有底层真正收下字节后才提交计数器，
        //    底层 Pending 时直接丢弃这份副本，counter 不推进。
        let mut trial = this.enc.clone();
        let mut out: Vec<u8> = Vec::with_capacity(data.len() + 2 * (2 + TAG_LEN));
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + MAX_PAYLOAD).min(data.len());
            let chunk = &data[offset..end];
            let mut len_part = (chunk.len() as u16).to_be_bytes().to_vec();
            trial.seal(&mut len_part).map_err(ss_io_err)?;
            out.extend_from_slice(&len_part);
            let mut payload_part = chunk.to_vec();
            trial.seal(&mut payload_part).map_err(ss_io_err)?;
            out.extend_from_slice(&payload_part);
            offset = end;
        }

        let inner = &mut this.inner;
        let write_buf = &mut this.write_buf;
        let enc = &mut this.enc;
        match Pin::new(&mut *inner).poll_write(cx, &out) {
            Poll::Ready(Ok(m)) => {
                if m < out.len() {
                    write_buf.extend_from_slice(&out[m..]);
                }
                *enc = trial;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        let write_buf = &mut this.write_buf;
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(m)) => { write_buf.drain(..m); }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        if !write_buf.is_empty() {
            return Poll::Pending;
        }
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        let write_buf = &mut this.write_buf;
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(m)) => { write_buf.drain(..m); }
                Poll::Pending | Poll::Ready(Err(_)) => break,
            }
        }
        Pin::new(inner).poll_shutdown(cx)
    }
}

/// 在已建立的流上完成 SS 握手：发送 salt + 首个加密块（目标地址）。
///
/// * 传统 AEAD：`[salt][enc(len 2B)+tag][enc(addr)+tag]`，后续 chunk 从 nonce 2 开始。
/// * AEAD-2022：`[salt][enc(type=0 + timestamp 8B + variableHeaderLen 2B, nonce=0)+tag]`
///   `[enc(SOCKS 地址 + paddingLen 2B + padding, nonce=1)+tag]`，后续从 nonce 2 开始。
/// * `none`：明文写出 SOCKS 地址后直接返回原始流（无长度分帧）。
async fn wrap_ss<S>(mut stream: S, m: &SsMethod, first_payload: Vec<u8>) -> Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if m.method == Method::None {
        stream.write_all(&first_payload).await?;
        return Ok(Box::new(stream));
    }

    let salt = random_bytes(m.method.salt_len());
    let subkey = if m.method.is_2022() {
        ss2022_session_key(&m.key_material, &salt, m.method.key_len())
    } else {
        hkdf_sha1(&m.key_material, &salt, m.method.key_len())
    };
    let mut enc = AeadCipher::new(m.method, subkey);
    let request_salt = if m.method.is_2022() {
        Some(salt.clone())
    } else {
        None
    };

    stream.write_all(&salt).await.context("ss write salt")?;

    if m.method.is_2022() {
        let padding_len = rand::thread_rng().gen_range(1..=SS2022_MAX_PADDING);
        let padding = random_bytes(padding_len);
        let variable_header_len = first_payload.len() + 2 + padding_len;

        let mut fixed = Vec::with_capacity(11 + TAG_LEN);
        fixed.push(SS2022_HEADER_TYPE_CLIENT);
        fixed.extend_from_slice(&now_secs().to_be_bytes());
        fixed.extend_from_slice(&(variable_header_len as u16).to_be_bytes());
        enc.seal(&mut fixed)?; // nonce 0 → 1
        stream.write_all(&fixed).await.context("ss write request")?;

        let mut variable = Vec::with_capacity(variable_header_len + TAG_LEN);
        variable.extend_from_slice(&first_payload);
        variable.extend_from_slice(&(padding_len as u16).to_be_bytes());
        variable.extend_from_slice(&padding);
        enc.seal(&mut variable)?; // nonce 1 → 2
        stream.write_all(&variable).await.context("ss write request")?;
    } else {
        let mut len_part = (first_payload.len() as u16).to_be_bytes().to_vec();
        enc.seal(&mut len_part)?;
        stream.write_all(&len_part).await.context("ss write request")?;

        let mut payload_part = first_payload;
        enc.seal(&mut payload_part)?;
        stream.write_all(&payload_part).await.context("ss write request")?;
    }

    Ok(Box::new(SsStream::new(
        stream,
        enc,
        m.method,
        m.key_material.clone(),
        request_salt,
    )))
}

/// 加密材料（构造期派生一次，运行时只读共享）。
#[derive(Clone)]
struct SsMethod {
    method: Method,
    /// 传统 AEAD：EVP_BytesToKey 派生的 master key；AEAD-2022：base64 解码的 PSK。
    key_material: Vec<u8>,
}

// ── 出站 ──────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SsOption {
    server: String,
    port: u16,
    network: String,
    tls: bool,
    sni: String,
    utls: Option<UtlsFingerprint>,
    tls_alpn: Vec<String>,
    ws_path: String,
    ws_host: String,
    ws_host_explicit: bool,
    ws_headers: Vec<(String, String)>,
    xhttp: Option<XhttpConfig>,
    xhttp_resolved: XhttpResolved,
    xhttp_h2_tls: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    opts: SsOption,
    m: SsMethod,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl ShadowsocksOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let method_str = cfg
            .cipher
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!("shadowsocks `{}` requires `cipher` (or `method`)", cfg.name)
            })?;
        let method = Method::parse(method_str)
            .with_context(|| format!("shadowsocks `{}`", cfg.name))?;
        let password = cfg
            .password
            .as_deref()
            .with_context(|| format!("shadowsocks `{}` requires `password`", cfg.name))?;

        let key_material = if method.is_2022() {
            use base64::Engine as _;
            let psk = base64::engine::general_purpose::STANDARD
                .decode(password.trim())
                .with_context(|| format!("shadowsocks `{}`: 2022 PSK base64", cfg.name))?;
            if psk.len() != method.key_len() {
                bail!(
                    "shadowsocks `{}`: 2022 PSK length mismatch (expected {} bytes, got {})",
                    cfg.name,
                    method.key_len(),
                    psk.len()
                );
            }
            psk
        } else if method == Method::None {
            Vec::new()
        } else {
            evp_bytes_to_key(password.as_bytes(), method.key_len())
        };

        let network = cfg.network.to_lowercase();
        if network != "tcp" && network != "ws" && network != "xhttp" {
            bail!(
                "shadowsocks `{}`: network must be \"tcp\", \"ws\" or \"xhttp\", got {}",
                cfg.name,
                cfg.network
            );
        }

        // TLS 门控：`ProxyConfig::tls` 全局默认 true，但 SS 裸 TCP 通常不套 TLS，
        // 因此 SS 只在**显式给出 SNI**（或 uTLS 指纹）时才启用 TLS——没有 SNI 的
        // TLS 握手本身也没有意义。要关闭就写 `tls: false`。
        let sni = cfg.effective_sni();
        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s).with_context(|| {
                    format!(
                        "shadowsocks `{}`: unknown client-fingerprint {s:?} \
                         (supported: chrome/firefox/safari/edge/ios/android/360/qq/random)",
                        cfg.name
                    )
                })
            })
            .transpose()?;
        let tls = cfg.tls && (cfg.sni.is_some() || cfg.servername.is_some() || utls.is_some());
        if utls.is_some() && !tls {
            tracing::warn!(
                "shadowsocks `{}`: client-fingerprint set but tls is disabled — no effect",
                cfg.name
            );
        }

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

        // xhttp 运行模式：与 vless 一致（auto → packet-up）。
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
                    "shadowsocks `{}`: unknown xhttp-mode {other:?} \
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

        let alpn = cfg.alpn.clone().unwrap_or_default();
        let tls_config = if tls {
            let force_http11 =
                network == "ws" || (network == "xhttp" && xhttp_resolved == XhttpResolved::StreamOne);
            let effective_alpn: Vec<String> = if force_http11 {
                vec!["http/1.1".to_string()]
            } else if !alpn.is_empty() {
                alpn.clone()
            } else if utls.is_some() {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                Vec::new()
            };
            let cfg_tls = Arc::new(build_tls_client_config(
                cfg.skip_cert_verify,
                &effective_alpn,
                None,
            )?);
            // packet-up / stream-up 走 hyper，ALPN 强制 h2（同 vless）。
            let h2_tls = if network == "xhttp" && xhttp_resolved != XhttpResolved::StreamOne {
                Some(Arc::new(build_tls_client_config(
                    cfg.skip_cert_verify,
                    &["h2".to_string()],
                    None,
                )?))
            } else {
                None
            };
            (
                effective_alpn,
                Some(cfg_tls),
                h2_tls,
            )
        } else {
            (Vec::new(), None, None)
        };
        let (tls_alpn, tls_config, xhttp_h2_tls) = tls_config;

        Ok(Self {
            opts: SsOption {
                server: cfg.server.clone(),
                port: cfg.port,
                network,
                tls,
                sni,
                utls,
                tls_alpn,
                ws_path,
                ws_host,
                ws_host_explicit,
                ws_headers,
                xhttp,
                xhttp_resolved,
                xhttp_h2_tls,
            },
            m: SsMethod {
                method,
                key_material,
            },
            tls_config,
        })
    }

    /// 出站 TCP：走 `sockopt::connect_tcp`，SO_MARK / SO_BINDTODEVICE 自动生效。
    async fn connect_raw(&self) -> Result<TcpStream> {
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let s = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("ss tcp connect {addr}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// rustls TLS 或 uTLS 浏览器指纹（与 vless / vmess 同一条路径）。
    async fn connect_tls_layer(&self, stream: TcpStream) -> Result<TlsStreamBox> {
        let cfg = self.tls_config.as_ref().context("ss tls not configured")?;
        match self.opts.utls {
            Some(fp) => Ok(TlsStreamBox::Utls(Box::new(
                connect_utls(
                    stream,
                    &self.opts.sni,
                    &fp,
                    cfg.clone(),
                    &self.opts.tls_alpn,
                )
                .await
                .context("ss utls handshake")?,
            ))),
            None => {
                let name = rustls::pki_types::ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("ss invalid sni {}", self.opts.sni))?;
                Ok(TlsStreamBox::Plain(
                    TlsConnector::from(cfg.clone())
                        .connect(name, stream)
                        .await
                        .context("ss tls handshake")?,
                ))
            }
        }
    }

    async fn wrap_tls(&self, stream: TcpStream) -> Result<BoxedStream> {
        Ok(Box::new(self.connect_tls_layer(stream).await?))
    }

    /// TCP → (TLS, ALPN http/1.1) → WebSocket upgrade。
    async fn connect_ws(&self) -> Result<WebSocketStream<BoxedStream>> {
        let tcp = self.connect_raw().await?;
        let io: BoxedStream = if self.opts.tls {
            self.wrap_tls(tcp).await?
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
            .map_err(|e| anyhow!("ss {e}"))
    }

    /// 建立底层传输并完成 SS 握手（salt + 目标地址），返回可直接转发的流。
    async fn open_ss(
        &self,
        addr: SocketAddr,
        host_hint: Option<&str>,
    ) -> Result<BoxedStream> {
        let first_payload = encode_target(addr, host_hint);

        if let Some(xcfg) = &self.opts.xhttp {
            match self.opts.xhttp_resolved {
                XhttpResolved::StreamOne => {
                    let tcp = self.connect_raw().await?;
                    let io: BoxedStream = if self.opts.tls {
                        self.wrap_tls(tcp).await?
                    } else {
                        Box::new(tcp)
                    };
                    let pipe = connect_over_stream(io, xcfg).await?;
                    return wrap_ss(pipe, &self.m, first_payload).await;
                }
                XhttpResolved::PacketUp | XhttpResolved::StreamUp => {
                    let mode = if self.opts.xhttp_resolved == XhttpResolved::PacketUp {
                        "packet-up"
                    } else {
                        "stream-up"
                    };
                    let tls = self.opts.xhttp_h2_tls.clone().map(|config| {
                        xhttp_h2::XhttpH2Tls {
                            config,
                            server_name: self.opts.sni.clone(),
                            utls: self.opts.utls,
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
                    return wrap_ss(pipe, &self.m, first_payload).await;
                }
            }
        }

        if self.opts.network == "ws" {
            let ws = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, self.connect_ws())
                .await
                .map_err(|_| {
                    anyhow!(
                        "ss ws handshake timed out after {}s ({}:{})",
                        WS_HANDSHAKE_TIMEOUT.as_secs(),
                        self.opts.server,
                        self.opts.port
                    )
                })??;
            // SS 没有响应头需要剥离，header 传空即可。
            let io = WsStream::with_header(ws, Bytes::new());
            return wrap_ss(io, &self.m, first_payload).await;
        }

        let tcp = self.connect_raw().await?;
        let io: BoxedStream = if self.opts.tls {
            self.wrap_tls(tcp).await?
        } else {
            Box::new(tcp)
        };
        wrap_ss(io, &self.m, first_payload).await
    }
}

#[async_trait]
impl OutboundDialer for ShadowsocksOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let stream = self.open_ss(addr, host_hint).await?;
        tracing::debug!(
            "ss ok {}://{}:{} net={} → {:?}",
            if self.opts.tls { "tls" } else { "tcp" },
            self.opts.server,
            self.opts.port,
            self.opts.network,
            host_hint.unwrap_or(&addr.to_string())
        );
        Ok(stream)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        // Shadowsocks 的 UDP 是原生 UDP 中继，只有裸 TCP 节点才有意义；
        // ws / xhttp 承载的是 TCP 流，没有 UDP over TCP 的约定。
        if self.opts.network != "tcp" {
            bail!(
                "shadowsocks UDP is not available over network={} (only network: tcp); \
                 SS UDP is a native UDP relay and this node has no UDP-over-TCP fallback",
                self.opts.network
            );
        }
        let server = resolve_server(&self.opts.server, self.opts.port).await?;
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        // mark 在 bind_udp 内部统一设置，与其他出站一致。
        let sock = crate::app::sockopt::bind_udp(bind)
            .await
            .context("ss udp bind")?;
        sock.connect(server).await.context("ss udp connect")?;

        let session_id = if self.m.method.is_2022() {
            u64::from_be_bytes(random_bytes(8).try_into().unwrap())
        } else {
            0
        };

        Ok(Box::new(SsUdpSession {
            sock: Arc::new(sock),
            server,
            m: self.m.clone(),
            session_id,
            packet_id: AtomicU64::new(1),
            addrs: Mutex::new(HashMap::new()),
        }))
    }
}

/// 一个 UDP association 对应一条 SS UDP 会话（连到同一个服务器端口）。
struct SsUdpSession {
    sock: Arc<UdpSocket>,
    server: SocketAddr,
    m: SsMethod,
    session_id: u64,
    /// AEAD-2022 的 packetId，从 1 开始递增。
    packet_id: AtomicU64,
    /// SOCKS 地址字节 → 客户端实际使用的 SocketAddr（域名目标无法回推，靠此表还原）。
    addrs: Mutex<HashMap<Vec<u8>, SocketAddr>>,
}

impl SsUdpSession {
    fn seal_packet(&self, socks: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if self.m.method == Method::None {
            let mut w = socks.to_vec();
            w.extend_from_slice(data);
            return Ok(w);
        }
        if self.m.method.is_2022() {
            let mut body = ss2022_udp_client_body(now_secs(), socks, data);
            let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
            if ss2022_is_aes(self.m.method) {
                ss2022_udp_seal_aes(&self.m.key_material, self.session_id, pid, &mut body)
            } else {
                let nonce = random_bytes(SS2022_CHACHA_NONCE_LEN);
                let nonce24: &[u8; 24] = nonce.as_slice().try_into().unwrap();
                ss2022_udp_seal_chacha(
                    &self.m.key_material,
                    self.session_id,
                    pid,
                    nonce24,
                    &mut body,
                )
            }
        } else {
            let salt = random_bytes(self.m.method.salt_len());
            let subkey = hkdf_sha1(&self.m.key_material, &salt, self.m.method.key_len());
            let mut cipher = AeadCipher::new(self.m.method, subkey);
            let mut body = socks.to_vec();
            body.extend_from_slice(data);
            cipher.seal(&mut body)?;
            let mut pkt = salt;
            pkt.extend_from_slice(&body);
            Ok(pkt)
        }
    }

    /// 解密一个下行报文，返回 `(SOCKS 地址字节, payload)`；解密失败返回 None（跳过）。
    ///
    /// 解密出的明文是局部缓冲，因此返回的是拷贝而非切片。
    fn open_packet(&self, pkt: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.m.method == Method::None {
            let (a, p) = split_socks_addr(pkt)?;
            return Some((a.to_vec(), p.to_vec()));
        }
        if self.m.method.is_2022() {
            let body = if ss2022_is_aes(self.m.method) {
                ss2022_udp_open_aes(&self.m.key_material, pkt).ok()?
            } else {
                ss2022_udp_open_chacha(&self.m.key_material, pkt).ok()?
            };
            let (a, p) = ss2022_udp_split_server_body(&body)?;
            return Some((a.to_vec(), p.to_vec()));
        }
        let salt_len = self.m.method.salt_len();
        if pkt.len() <= salt_len + TAG_LEN {
            return None;
        }
        let (salt, ct) = pkt.split_at(salt_len);
        let subkey = hkdf_sha1(&self.m.key_material, salt, self.m.method.key_len());
        let mut cipher = AeadCipher::new(self.m.method, subkey);
        let mut body = ct.to_vec();
        cipher.open(&mut body).ok()?;
        let (a, p) = split_socks_addr(&body)?;
        Some((a.to_vec(), p.to_vec()))
    }
}

#[async_trait]
impl UdpSession for SsUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let socks = encode_target(dst, dst_host);
        self.addrs.lock().await.insert(socks.clone(), dst);
        let wire = self.seal_packet(&socks, data)?;
        self.sock.send(&wire).await.context("ss udp send")?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self.sock.recv(&mut buf).await.context("ss udp recv")?;
            if let Some((addr_bytes, payload)) = self.open_packet(&buf[..n]) {
                let src = match self.addrs.lock().await.get(&addr_bytes) {
                    Some(a) => *a,
                    None => socks_addr_to_socket(&addr_bytes).unwrap_or(self.server),
                };
                return Ok((payload, src));
            }
            tracing::debug!("ss udp: dropped an undecryptable packet");
        }
    }
}

/// 服务器域名解析：IP 直用；域名走 bootstrap DNS，避免解析回环。
async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    crate::dns::resolve_host_via_bootstrap(host, port).await
}
