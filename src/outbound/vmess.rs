//! VMess outbound (AEAD, `alterId == 0`) — protocol aligned with sing-vmess /
//! Xray / reflex.
//!
//! Transports: `tcp` | `ws` | `xhttp`; TLS layers: plain TLS (rustls) or uTLS
//! browser fingerprint (`client-fingerprint`). VMess has no REALITY variant.
//!
//! * tcp: the handshake is written eagerly and the response header is read
//!   eagerly (servers answer immediately).
//! * ws / xhttp: the handshake is merged into the first upstream write and the
//!   response header is skipped lazily on the first read — same as the vless /
//!   trojan outbounds, waiting for it eagerly would deadlock.
//!
//! All dial sockets go through `crate::app::sockopt::connect_tcp`, so the global
//! `mark` (SO_MARK / interface binding) applies exactly like the vless /
//! trojan / direct outbounds — TUN loop prevention works out of the box.
//!
//! ```text
//! handshake: [AuthID 16B][EncHeaderLen 2+16B][ConnNonce 8B][EncHeader N+16B]
//! header:    [Ver 1B][ReqNonce 16B][ReqKey 16B][RespV 1B][Option 1B]
//!            [PadLen<<4|Security 1B][Reserved 1B][Cmd 1B][Port 2B BE]
//!            [Atyp 1B][Addr][Padding][FNV1a 4B]
//! response:  [EncRespLen 2+16B][EncRespHeader 4+16B]
//! data:      [len 2B (masked)][ciphertext + TAG 16B], nonce = [count u16 BE][base[2..12]]
//! ```
//!
//! UDP uses one VMess connection per destination (`CMD_UDP` with the real
//! target in the request header, one datagram per AEAD chunk) — the same model
//! as the vless / trojan UDP sessions, and the framing every v2ray / Xray /
//! sing-box server supports without extra packet-encoding negotiation.

use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint};
use super::vless::{build_tls_client_config, XhttpResolved};
use super::ws::{self, WsOptions, WsStream, WS_HANDSHAKE_TIMEOUT};
use super::xhttp::connect_over_stream;
use super::xhttp::XhttpConfig;
use super::xhttp_h2;
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::Digest as Md5Digest;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;

// ── 常量 ────────────────────────────────────────────────────────────────────

pub const VERSION: u8 = 1;
pub const CIPHER_OVERHEAD: usize = 16;

/// `none`：保留 VMess 消息结构但不加密。
pub const SECURITY_NONE: u8 = 5;
pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;

pub const OPT_CHUNK_STREAM: u8 = 1;
pub const OPT_CHUNK_MASKING: u8 = 4;

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// AEAD 响应头长度帧 `[len 2B + TAG]`，以及固定 4 字节响应体。
const RESP_LEN_FRAME: usize = 2 + CIPHER_OVERHEAD;
const RESP_HEADER_LEN: usize = 4;

// KDF salt（同 sing-vmess/protocol.go）
const KDF_SALT_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &str = "AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &str = "VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &str = "VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &str = "VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &str = "VMess Header AEAD Nonce";
const KDF_SALT_RESP_LEN_KEY: &str = "AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_IV: &str = "AEAD Resp Header Len IV";
const KDF_SALT_RESP_KEY: &str = "AEAD Resp Header Key";
const KDF_SALT_RESP_IV: &str = "AEAD Resp Header IV";

// ── KDF（嵌套 HMAC-SHA256，对应 sing-vmess/kdf.go 的 hMacCreator）──────────
//
// Go 侧是 `hmac.New(h.parent.Create, h.value)`：外层 HMAC 的“哈希函数”本身
// 又是一个 HMAC 实例，因此每一层都是嵌套的 HMAC(HMAC(...))，而不是
// `HMAC(key=prev_output, msg=next_input)` 的简单链式调用。旧的链式实现与
// sing-vmess 输出完全不同，握手必然失败。

const SHA256_BLOCK_SIZE: usize = 64;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

trait KdfHashFn {
    fn call(&self, data: &[u8]) -> Vec<u8>;
    fn block_size(&self) -> usize {
        SHA256_BLOCK_SIZE
    }
}

struct Sha256Hasher;
impl KdfHashFn for Sha256Hasher {
    fn call(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }
}

/// 嵌套 HMAC：以 `inner` 作为内部哈希函数，`key` 作为 HMAC 密钥（RFC 2104）。
struct NestedHmac {
    key: Vec<u8>,
    inner: Box<dyn KdfHashFn + Send>,
}

impl KdfHashFn for NestedHmac {
    fn call(&self, data: &[u8]) -> Vec<u8> {
        let block_size = self.inner.block_size();
        let key_padded: Vec<u8> = if self.key.len() > block_size {
            let mut v = self.inner.call(&self.key);
            v.resize(block_size, 0);
            v
        } else {
            let mut v = self.key.clone();
            v.resize(block_size, 0);
            v
        };

        let mut ipad = key_padded.clone();
        let mut opad = key_padded;
        for b in &mut ipad {
            *b ^= HMAC_IPAD;
        }
        for b in &mut opad {
            *b ^= HMAC_OPAD;
        }

        ipad.extend_from_slice(data);
        let inner = self.inner.call(&ipad);
        opad.extend_from_slice(&inner);
        self.inner.call(&opad)
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }
}

fn build_kdf_chain(keys: &[Vec<u8>]) -> Box<dyn KdfHashFn + Send> {
    let mut hash: Box<dyn KdfHashFn + Send> = Box::new(Sha256Hasher);
    for k in keys {
        hash = Box::new(NestedHmac {
            key: k.clone(),
            inner: hash,
        });
    }
    hash
}

/// VMess AEAD KDF：`KDF(key, salt, path...)`，与 sing-vmess 字节级一致。
pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> Vec<u8> {
    let mut all_keys: Vec<Vec<u8>> = vec![
        KDF_SALT_VMESS_AEAD_KDF.as_bytes().to_vec(),
        salt.as_bytes().to_vec(),
    ];
    for p in path {
        all_keys.push(p.to_vec());
    }
    build_kdf_chain(&all_keys).call(key)
}

// ── AuthID（AES-128-ECB 加密的 8B 时间戳 + 4B 随机 + 4B CRC32）─────────────

pub fn build_auth_id(key: &[u8; 16]) -> [u8; 16] {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ts.to_be_bytes());
    buf[8..12].copy_from_slice(&rand_array::<4>());

    let checksum = crc32fast::hash(&buf[..12]);
    buf[12..16].copy_from_slice(&checksum.to_be_bytes());

    let enc_key = kdf(key, KDF_SALT_AUTH_ID, &[]);
    aes_ecb_encrypt_inplace(&mut buf, &enc_key[..16]);
    buf
}

/// AES-128-ECB 加密单个 16 字节块（无 padding）。
fn aes_ecb_encrypt_inplace(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

// ── 请求头 ──────────────────────────────────────────────────────────────────

pub struct RequestHeader {
    pub req_key: [u8; 16],
    pub req_nonce: [u8; 16],
    /// 随机 1 字节，服务端必须在响应头中原样回显。
    pub resp_header: u8,
    pub option: u8,
    pub security: u8,
    pub command: u8,
}

impl RequestHeader {
    pub fn new(security: u8, command: u8) -> Self {
        // 与 sing-vmess/client.go dialRaw() 一致：AEAD 加密时启用
        // ChunkStream + ChunkMasking；明文时仅 UDP 需要 ChunkStream（否则裸流）。
        let option = match security {
            SECURITY_NONE => {
                if command == CMD_UDP {
                    OPT_CHUNK_STREAM
                } else {
                    0
                }
            }
            SECURITY_AES128_GCM | SECURITY_CHACHA20_POLY1305 => {
                OPT_CHUNK_STREAM | OPT_CHUNK_MASKING
            }
            _ => 0,
        };
        Self {
            req_key: rand_array::<16>(),
            req_nonce: rand_array::<16>(),
            resp_header: rand_array::<1>()[0],
            option,
            security,
            command,
        }
    }

    /// 明文 header（含末尾 FNV1a-32 校验）。
    pub fn encode(&self, host_hint: Option<&str>, addr: SocketAddr) -> Bytes {
        let padding_len = (rand_array::<1>()[0] % 16) as usize;

        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(VERSION);
        buf.put_slice(&self.req_nonce);
        buf.put_slice(&self.req_key);
        buf.put_u8(self.resp_header);
        buf.put_u8(self.option);
        buf.put_u8((padding_len as u8) << 4 | self.security);
        buf.put_u8(0x00); // reserved
        buf.put_u8(self.command);
        write_target(&mut buf, host_hint, addr);
        for _ in 0..padding_len {
            buf.put_u8(0);
        }
        buf.put_u32(fnv1a32(&buf));
        buf.freeze()
    }
}

fn write_target(buf: &mut BytesMut, host_hint: Option<&str>, addr: SocketAddr) {
    buf.put_u16(addr.port());
    if let Some(host) = host_hint.filter(|h| h.parse::<IpAddr>().is_err()) {
        let h = host.as_bytes();
        let len = h.len().min(255);
        buf.put_u8(ATYP_DOMAIN);
        buf.put_u8(len as u8);
        buf.put_slice(&h[..len]);
        return;
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
}

/// FNV-1a 32（sing-vmess header 校验），不额外引入依赖。
fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// 完整握手字节流：`[AuthID][EncHeaderLen][ConnNonce][EncHeader]`。
pub fn build_handshake(
    user_key: &[u8; 16],
    req_hdr: &RequestHeader,
    host_hint: Option<&str>,
    addr: SocketAddr,
) -> Bytes {
    let auth_id = build_auth_id(user_key);
    let conn_nonce: [u8; 8] = rand_array();
    let header_plain = req_hdr.encode(host_hint, addr);

    let mut len_plain = [0u8; 2];
    len_plain.copy_from_slice(&(header_plain.len() as u16).to_be_bytes());
    let enc_len = aead_seal(
        &kdf(user_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &conn_nonce])[..16],
        &kdf(user_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &conn_nonce])[..12],
        &len_plain,
        &auth_id,
    );

    let enc_hdr = aead_seal(
        &kdf(user_key, KDF_SALT_HEADER_KEY, &[&auth_id, &conn_nonce])[..16],
        &kdf(user_key, KDF_SALT_HEADER_IV, &[&auth_id, &conn_nonce])[..12],
        &header_plain,
        &auth_id,
    );

    let mut out = BytesMut::with_capacity(16 + enc_len.len() + 8 + enc_hdr.len());
    out.put_slice(&auth_id);
    out.put_slice(&enc_len);
    out.put_slice(&conn_nonce);
    out.put_slice(&enc_hdr);
    out.freeze()
}

fn aead_seal(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("aes key");
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
        .expect("encrypt")
}

fn aead_open(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg, aad })
        .ok()
}

// ── 响应头 ──────────────────────────────────────────────────────────────────

/// 校验响应头所需的每连接状态。
struct RespCheck {
    req_key: [u8; 16],
    req_nonce: [u8; 16],
    expect: u8,
}

impl RespCheck {
    fn new(hdr: &RequestHeader) -> Self {
        Self {
            req_key: hdr.req_key,
            req_nonce: hdr.req_nonce,
            expect: hdr.resp_header,
        }
    }

    fn resp_key(&self) -> [u8; 16] {
        resp_data_key(&self.req_key)
    }
    fn resp_nonce(&self) -> [u8; 16] {
        resp_data_nonce(&self.req_nonce)
    }
}

enum RespState {
    Len,
    Header(usize),
    Done,
}

/// 增量解析 VMess AEAD 响应头：`[EncLen 2+16B][EncHeader N+16B]`。
struct RespReader {
    state: RespState,
    raw: Vec<u8>,
    chk: RespCheck,
}

impl RespReader {
    fn new(chk: RespCheck) -> Self {
        Self {
            state: RespState::Len,
            raw: Vec::new(),
            chk,
        }
    }

    /// 追加数据后尝试解析。
    /// `Ok(Some(rest))`：响应头已解析并校验通过，`rest` 是随后的业务数据。
    /// `Ok(None)`：数据不足，继续读。
    fn parse(&mut self) -> io::Result<Option<Vec<u8>>> {
        let resp_key = self.chk.resp_key();
        let resp_nonce = self.chk.resp_nonce();
        loop {
            match self.state {
                RespState::Done => return Ok(Some(Vec::new())),
                RespState::Len => {
                    if self.raw.len() < RESP_LEN_FRAME {
                        return Ok(None);
                    }
                    let key = kdf(&resp_key, KDF_SALT_RESP_LEN_KEY, &[]);
                    let iv = kdf(&resp_nonce, KDF_SALT_RESP_LEN_IV, &[]);
                    let dec = aead_open(&key[..16], &iv[..12], &self.raw[..RESP_LEN_FRAME], b"")
                        .ok_or_else(|| invalid("vmess: decrypt response length failed"))?;
                    let header_len = u16::from_be_bytes([dec[0], dec[1]]) as usize;
                    let _ = self.raw.drain(..RESP_LEN_FRAME);
                    self.state = RespState::Header(header_len);
                }
                RespState::Header(n) => {
                    if self.raw.len() < n + CIPHER_OVERHEAD {
                        return Ok(None);
                    }
                    let key = kdf(&resp_key, KDF_SALT_RESP_KEY, &[]);
                    let iv = kdf(&resp_nonce, KDF_SALT_RESP_IV, &[]);
                    let dec = aead_open(
                        &key[..16],
                        &iv[..12],
                        &self.raw[..n + CIPHER_OVERHEAD],
                        b"",
                    )
                    .ok_or_else(|| invalid("vmess: decrypt response header failed"))?;
                    if dec.len() < RESP_HEADER_LEN {
                        return Err(invalid("vmess: response header too short"));
                    }
                    // dec[0] 是服务端回显的 resp_v（每连接随机），必须与请求头一致。
                    // 注意它不是 “version”，旧实现断言 == 0 会让 ~99.6% 连接失败。
                    let token = dec[0];
                    if token != self.chk.expect {
                        return Err(invalid(&format!(
                            "vmess: response token mismatch (got {token:#04x}, expected {:#04x})",
                            self.chk.expect
                        )));
                    }
                    let _ = self.raw.drain(..n + CIPHER_OVERHEAD);
                    self.state = RespState::Done;
                    return Ok(Some(std::mem::take(&mut self.raw)));
                }
            }
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

// ── 杂项工具 ────────────────────────────────────────────────────────────────

pub fn resp_data_key(req_key: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_key).into();
    h[..16].try_into().expect("slice")
}

pub fn resp_data_nonce(req_nonce: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_nonce).into();
    h[..16].try_into().expect("slice")
}

/// N 字节密码学安全随机（OsRng）。
pub fn rand_array<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// UUID 字符串 → 16 字节（接受带/不带连字符的 32 位十六进制）。
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("invalid vmess uuid {s:?} (expected 32 hex digits)");
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

/// 从 uuid 派生 user key：`MD5(uuid_bytes + 固定盐)`。
pub fn user_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut h = md5::Md5::new();
    h.update(uuid_bytes);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

pub fn resolve_security(security: &str) -> Result<u8> {
    match security {
        "auto" | "aes-128-gcm" => Ok(SECURITY_AES128_GCM),
        "chacha20-poly1305" => Ok(SECURITY_CHACHA20_POLY1305),
        "none" | "zero" => Ok(SECURITY_NONE),
        "aes-128-cfb" => bail!(
            "vmess: aes-128-cfb (legacy alterId) is not supported; use aes-128-gcm, \
             chacha20-poly1305, none or zero"
        ),
        other => bail!("vmess: unknown cipher {other:?}"),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// AEAD 数据传输层：分帧读写器
// ════════════════════════════════════════════════════════════════════════════
//
// 每帧 `[len 2B][ciphertext + TAG 16B]`；nonce 前 2 字节为大端计数器，后 10
// 字节取自 base[2..12]。上行用 req_key/req_nonce，下行用 SHA256(...) 的前 16
// 字节。计数器只有 16 位，wrap 会复用 nonce 破坏 GCM 安全性，因此显式拒绝。

#[allow(clippy::large_enum_variant)]
enum VmessAeadCipher {
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
}

impl VmessAeadCipher {
    fn new(security: u8, key: &[u8]) -> Self {
        match security {
            SECURITY_CHACHA20_POLY1305 => {
                let full_key = chacha20_key(key);
                VmessAeadCipher::Chacha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(&full_key).expect("chacha key"),
                )
            }
            _ => VmessAeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(key).expect("aes key")),
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.encrypt(n, plaintext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.encrypt(n, plaintext),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.decrypt(n, ciphertext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.decrypt(n, ciphertext),
        }
    }
}

fn chacha20_key(key: &[u8]) -> [u8; 32] {
    let h1: [u8; 16] = md5::Md5::digest(key).into();
    let h2: [u8; 16] = md5::Md5::digest(h1).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&h1);
    out[16..].copy_from_slice(&h2);
    out
}

fn make_shake128_reader(seed: &[u8]) -> impl XofReader {
    use sha3::digest::Update;
    let mut h = Shake128::default();
    h.update(seed);
    h.finalize_xof()
}

fn next_mask_u16(reader: &mut dyn XofReader) -> u16 {
    let mut b = [0u8; 2];
    reader.read(&mut b);
    u16::from_be_bytes(b)
}

fn make_nonce(count: u16, base: &[u8; 16]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&count.to_be_bytes());
    n[2..].copy_from_slice(&base[2..12]);
    n
}

const NONCE_OVERFLOW_ERR: &str = "vmess: chunk counter overflow (would reuse nonce)";
const MAX_CHUNK: usize = 15000;

pub struct VmessEncoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    security: u8,
    option: u8,
}

impl VmessEncoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)) as Box<dyn XofReader + Send>)
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            security,
            option,
        }
    }

    pub fn encode(&mut self, plaintext: &[u8]) -> io::Result<Bytes> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            return Ok(Bytes::copy_from_slice(plaintext));
        }
        if self.security == SECURITY_NONE {
            let mut len = plaintext.len() as u16;
            if let Some(m) = self.masking.as_mut() {
                len ^= next_mask_u16(m.as_mut());
            }
            let mut out = BytesMut::with_capacity(2 + plaintext.len());
            out.put_u16(len);
            out.put_slice(plaintext);
            return Ok(out.freeze());
        }
        if self.count == u16::MAX {
            return Err(io::Error::other(NONCE_OVERFLOW_ERR));
        }
        let nonce = make_nonce(self.count, &self.base_nonce);
        self.count += 1;
        let ct = self
            .cipher
            .as_ref()
            .expect("cipher")
            .encrypt(&nonce, plaintext)
            .map_err(|e| io::Error::other(format!("vmess encrypt: {e:?}")))?;
        let mut chunk_len = ct.len() as u16;
        if let Some(m) = self.masking.as_mut() {
            chunk_len ^= next_mask_u16(m.as_mut());
        }
        let mut out = BytesMut::with_capacity(2 + ct.len());
        out.put_u16(chunk_len);
        out.put_slice(&ct);
        Ok(out.freeze())
    }
}

enum DecodeState {
    Len,
    Data(usize),
}

pub struct VmessDecoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    state: DecodeState,
    security: u8,
    option: u8,
}

impl VmessDecoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)) as Box<dyn XofReader + Send>)
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            state: DecodeState::Len,
            security,
            option,
        }
    }

    /// 尝试从 `raw` 解码一个完整 chunk；`Ok(None)` 表示数据不足。
    pub fn try_decode(&mut self, raw: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Ok(Some(raw.split().freeze()));
        }
        loop {
            match self.state {
                DecodeState::Len => {
                    if raw.len() < 2 {
                        return Ok(None);
                    }
                    let mut raw_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
                    raw.advance(2);
                    if let Some(m) = self.masking.as_mut() {
                        raw_len ^= next_mask_u16(m.as_mut()) as usize;
                    }
                    if raw_len == 0 {
                        return Ok(Some(Bytes::new())); // 结束信号
                    }
                    self.state = DecodeState::Data(raw_len);
                }
                DecodeState::Data(expected) => {
                    if raw.len() < expected {
                        return Ok(None);
                    }
                    let chunk = raw.split_to(expected);
                    self.state = DecodeState::Len;
                    if self.security == SECURITY_NONE {
                        return Ok(Some(chunk.freeze()));
                    }
                    if self.count == u16::MAX {
                        return Err(io::Error::other(NONCE_OVERFLOW_ERR));
                    }
                    let nonce = make_nonce(self.count, &self.base_nonce);
                    self.count += 1;
                    let pt = self
                        .cipher
                        .as_ref()
                        .expect("cipher")
                        .decrypt(&nonce, &chunk)
                        .map_err(|e| invalid(&format!("vmess decrypt: {e:?}")))?;
                    return Ok(Some(Bytes::from(pt)));
                }
            }
        }
    }
}

// ── 读写半流 ────────────────────────────────────────────────────────────────

pub struct VmessReadHalf<R> {
    inner: R,
    decoder: VmessDecoder,
    raw_buf: BytesMut,
    decoded_buf: Bytes,
}

impl<R: AsyncRead + Unpin> VmessReadHalf<R> {
    pub fn new(inner: R, decoder: VmessDecoder) -> Self {
        Self {
            inner,
            decoder,
            raw_buf: BytesMut::new(),
            decoded_buf: Bytes::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for VmessReadHalf<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.decoded_buf.is_empty() {
                let n = buf.remaining().min(this.decoded_buf.len());
                buf.put_slice(&this.decoded_buf[..n]);
                let _ = this.decoded_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }
            match this.decoder.try_decode(&mut this.raw_buf)? {
                Some(data) if data.is_empty() => return Poll::Ready(Ok(())),
                Some(data) => {
                    this.decoded_buf = data;
                    continue;
                }
                None => {}
            }
            let before = this.raw_buf.len();
            this.raw_buf.reserve(4096);
            let spare = this.raw_buf.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(spare);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: `read_buf.filled()` 证明前 n 字节已初始化。
                    unsafe { this.raw_buf.set_len(before + n) };
                }
            }
        }
    }
}

pub struct VmessWriteHalf<W> {
    inner: W,
    encoder: VmessEncoder,
    /// 已编码但底层未写完整的帧（部分写）。
    pending: Option<Bytes>,
    /// `pending` 对应的用户字节数，写完后一次性上报。
    pending_reported: usize,
}

impl<W: AsyncWrite + Unpin> VmessWriteHalf<W> {
    pub fn new(inner: W, encoder: VmessEncoder) -> Self {
        Self {
            inner,
            encoder,
            pending: None,
            pending_reported: 0,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for VmessWriteHalf<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. 先写完上次残留的帧。注意：只要 pending 非空，本次 data 就**不能**
        //    再编码（上层会用同一份 data 重试），否则会重复发送。
        if let Some(pending) = this.pending.take() {
            return match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = this.pending_reported;
                    this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    this.pending_reported = 0;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    this.pending = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. 编码一段（chunk 上限 15000B）并立即写到底层。
        let chunk = &data[..data.len().min(MAX_CHUNK)];
        let frame = this.encoder.encode(chunk)?;
        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) if n >= frame.len() => Poll::Ready(Ok(chunk.len())),
            Poll::Ready(Ok(n)) => {
                this.pending = Some(frame.slice(n..));
                this.pending_reported = chunk.len();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.pending = Some(frame);
                this.pending_reported = chunk.len();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = this.pending.take() {
            match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    this.pending_reported = 0;
                }
                Poll::Ready(Ok(n)) => {
                    this.pending = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// VMess 数据流：上行用 req_key/req_nonce 加密，下行用 SHA256(...) 派生密钥解密。
pub struct VmessStream<S> {
    read: VmessReadHalf<ReadHalf<S>>,
    write: VmessWriteHalf<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VmessStream<S> {
    pub fn new(inner: S, security: u8, option: u8, req_key: &[u8; 16], req_nonce: &[u8; 16]) -> Self {
        let resp_key = resp_data_key(req_key);
        let resp_nonce = resp_data_nonce(req_nonce);
        let encoder = VmessEncoder::new(security, option, req_key, req_nonce);
        let decoder = VmessDecoder::new(security, option, &resp_key, &resp_nonce);
        let (rh, wh) = tokio::io::split(inner);
        Self {
            read: VmessReadHalf::new(rh, decoder),
            write: VmessWriteHalf::new(wh, encoder),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 传输适配层：握手合并 + 响应头惰性剥离
// ════════════════════════════════════════════════════════════════════════════

/// 包在传输流（xhttp pipe / ws 适配器）外面：
/// * 首次写：把 VMess 握手帧与首段负载合并成一次上游写；
/// * 首次读：读满并校验响应头（38 字节），剩余字节作为业务数据吐出。
struct VmessStreamIo<S> {
    inner: S,
    pending_header: Option<Bytes>,
    pending_write: Option<Bytes>,
    pending_reported: usize,
    resp: Option<RespReader>,
    raw_buf: Vec<u8>,
    read_buf: Bytes,
    response_done: bool,
}

impl<S> VmessStreamIo<S> {
    /// 需要自己合并握手帧（xhttp）。
    fn with_header(inner: S, header: Bytes, chk: RespCheck) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
            resp: Some(RespReader::new(chk)),
            raw_buf: Vec::new(),
            read_buf: Bytes::new(),
            response_done: false,
        }
    }

    /// 握手帧已由下层（ws）合并，只做响应头处理。
    fn new(inner: S, chk: RespCheck) -> Self {
        Self {
            inner,
            pending_header: None,
            pending_write: None,
            pending_reported: 0,
            resp: Some(RespReader::new(chk)),
            raw_buf: Vec::new(),
            read_buf: Bytes::new(),
            response_done: false,
        }
    }

    /// 响应头已经在外部 eager 解析完毕（tcp 路径），`rest` 是响应头之后紧随的
    /// 业务数据，必须先吐给上层再读底层流。
    fn after_handshake(inner: S, rest: Vec<u8>) -> Self {
        Self {
            inner,
            pending_header: None,
            pending_write: None,
            pending_reported: 0,
            resp: None,
            raw_buf: Vec::new(),
            read_buf: Bytes::from(rest),
            response_done: true,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStreamIo<S> {
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

        if !this.response_done {
            let mut tmp = [0u8; 1024];
            loop {
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
                let parsed = this.resp.as_mut().expect("resp reader").parse()?;
                if let Some(rest) = parsed {
                    this.response_done = true;
                    this.resp = None;
                    this.raw_buf.clear();
                    this.read_buf = Bytes::from(rest);
                    break;
                }
            }
        }

        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStreamIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. 先写完上次残留（握手帧 + 负载的合并缓冲）。
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

        // 2. 首次写：握手帧 + 首段负载合并为一次上游写。
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

        // 3. 直通。
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = this.pending_write.as_ref() {
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    this.pending_write = None;
                    this.pending_reported = 0;
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 出站
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct VmessOption {
    server: String,
    port: u16,
    user_key: [u8; 16],
    security: u8,
    network: String,
    tls: bool,
    sni: String,
    ws_path: String,
    ws_host: String,
    ws_host_explicit: bool,
    ws_headers: Vec<(String, String)>,
    utls: Option<UtlsFingerprint>,
    xhttp: Option<XhttpConfig>,
    xhttp_resolved: XhttpResolved,
    tls_alpn: Vec<String>,
    xhttp_h2_tls: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Clone)]
pub struct VmessOutbound {
    opts: VmessOption,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl VmessOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let uuid_str = cfg
            .uuid
            .clone()
            .or_else(|| cfg.password.clone())
            .context("vmess requires `uuid` (or `password` as uuid)")?;
        let uuid = parse_uuid(&uuid_str).with_context(|| format!("vmess `{}`", cfg.name))?;
        let user_key = user_key(&uuid);

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

        // 与 sing-box protocol/vmess/outbound.go 对齐：security 为空 → auto；
        // auto + TLS → zero（外层 TLS 已提供机密性，内层再加密是冗余）。
        let cipher = cfg
            .cipher
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("auto");
        let effective = match (cipher, cfg.tls) {
            ("auto", true) => "zero",
            (s, _) => s,
        };
        let security = resolve_security(effective)
            .with_context(|| format!("vmess `{}`: unknown cipher {cipher:?}", cfg.name))?;

        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s).with_context(|| {
                    format!(
                        "vmess `{}`: unknown client-fingerprint {s:?} \
                         (supported: chrome/firefox/safari/edge/ios/android/360/qq/random)",
                        cfg.name
                    )
                })
            })
            .transpose()?;
        if utls.is_some() && !cfg.tls {
            tracing::warn!(
                "vmess `{}`: client-fingerprint set but tls is disabled — no effect",
                cfg.name
            );
        }

        // xhttp 运行模式解析（与 trojan/vless 一致：auto → packet-up）。
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
                    "vmess `{}`: unknown xhttp-mode {other:?} \
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

        let mut opts = VmessOption {
            server: cfg.server.clone(),
            port: cfg.port,
            user_key,
            security,
            network,
            tls: cfg.tls,
            sni,
            ws_path,
            ws_host,
            ws_host_explicit,
            ws_headers,
            utls,
            xhttp,
            xhttp_resolved,
            tls_alpn: Vec::new(),
            xhttp_h2_tls: None,
        };

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
            .with_context(|| format!("vmess tcp connect {addr}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// rustls TLS 或 uTLS 浏览器指纹。
    async fn connect_tls_layer(&self, stream: TcpStream) -> Result<TlsStreamBox> {
        let cfg = self.tls_config.as_ref().context("tls not configured")?;
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
                .context("vmess utls handshake")?,
            ))),
            None => {
                let name = rustls::pki_types::ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("invalid sni {}", self.opts.sni))?;
                Ok(TlsStreamBox::Plain(
                    TlsConnector::from(cfg.clone())
                        .connect(name, stream)
                        .await
                        .context("vmess tls handshake")?,
                ))
            }
        }
    }

    /// TCP → (TLS, ALPN http/1.1) → WebSocket upgrade（见 `super::ws`）。
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
            .map_err(|e| anyhow!("vmess {e}"))
    }

    /// 建立传输并完成 VMess 握手（含响应头校验）。
    async fn open_vmess(
        &self,
        host_hint: Option<&str>,
        addr: SocketAddr,
        cmd: u8,
    ) -> Result<BoxedStream> {
        let req_hdr = RequestHeader::new(self.opts.security, cmd);
        let handshake = build_handshake(&self.opts.user_key, &req_hdr, host_hint, addr);
        let chk = RespCheck::new(&req_hdr);

        if let Some(xcfg) = &self.opts.xhttp {
            let pipe: BoxedStream = match self.opts.xhttp_resolved {
                XhttpResolved::StreamOne => {
                    let tcp = self.connect_raw().await?;
                    let io: BoxedStream = if self.opts.tls {
                        Box::new(self.connect_tls_layer(tcp).await?)
                    } else {
                        Box::new(tcp)
                    };
                    Box::new(connect_over_stream(io, xcfg).await?)
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
                    Box::new(
                        xhttp_h2::connect(
                            &self.opts.server,
                            self.opts.port,
                            &xcfg.host,
                            &xcfg.path,
                            mode,
                            &xcfg.headers,
                            tls,
                        )
                        .await?,
                    ) as BoxedStream
                }
            };
            return Ok(Box::new(VmessStream::new(
                VmessStreamIo::with_header(pipe, handshake, chk),
                self.opts.security,
                req_hdr.option,
                &req_hdr.req_key,
                &req_hdr.req_nonce,
            )));
        }

        if self.opts.network == "ws" {
            let ws = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, self.connect_ws())
                .await
                .map_err(|_| {
                    anyhow!(
                        "vmess ws handshake timed out after {}s ({}:{})",
                        WS_HANDSHAKE_TIMEOUT.as_secs(),
                        self.opts.server,
                        self.opts.port
                    )
                })??;
            let io = WsStream::with_header(ws, handshake);
            return Ok(Box::new(VmessStream::new(
                VmessStreamIo::new(io, chk),
                self.opts.security,
                req_hdr.option,
                &req_hdr.req_key,
                &req_hdr.req_nonce,
            )));
        }

        // tcp：握手 eager 写出并立即读响应头（服务端握手后立即返回）。
        let tcp = self.connect_raw().await?;
        let mut transport: BoxedStream = if self.opts.tls {
            Box::new(self.connect_tls_layer(tcp).await?)
        } else {
            Box::new(tcp)
        };
        transport
            .write_all(&handshake)
            .await
            .context("vmess write handshake")?;
        transport.flush().await.context("vmess flush handshake")?;

        let mut reader = RespReader::new(chk);
        let mut tmp = [0u8; 512];
        let rest = loop {
            if let Some(rest) = reader.parse()? {
                break rest;
            }
            let n = transport.read(&mut tmp).await.context("vmess read response")?;
            if n == 0 {
                bail!("vmess: connection closed during handshake");
            }
            reader.raw.extend_from_slice(&tmp[..n]);
        };
        if !rest.is_empty() {
            tracing::debug!("vmess: {} bytes already queued after response header", rest.len());
        }

        Ok(Box::new(VmessStream::new(
            VmessStreamIo::after_handshake(transport, rest),
            self.opts.security,
            req_hdr.option,
            &req_hdr.req_key,
            &req_hdr.req_nonce,
        )))
    }
}

#[async_trait]
impl OutboundDialer for VmessOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let stream = self.open_vmess(host_hint, addr, CMD_TCP).await?;
        tracing::debug!(
            "vmess ok {}://{}:{} net={} → {:?}",
            if self.opts.tls { "tls" } else { "tcp" },
            self.opts.server,
            self.opts.port,
            self.opts.network,
            host_hint.unwrap_or(&addr.to_string())
        );
        Ok(stream)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(256);
        Ok(Box::new(VmessUdpSession {
            ob: self.clone(),
            peers: Mutex::new(std::collections::HashMap::new()),
            incoming: Mutex::new(rx),
            incoming_tx: tx,
        }))
    }
}

/// 每个目标一条 VMess UDP 连接（CMD_UDP，目标写在请求头里，一个数据报一个 chunk）。
/// 与 vless / trojan 的 UDP session 同构：回复的 src 即为该 peer 的目标地址。
struct VmessUdpSession {
    ob: VmessOutbound,
    peers: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    incoming_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl VmessUdpSession {
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
        let stream = self.ob.open_vmess(host, dst, CMD_UDP).await?;
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let out_tx = self.incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_peer_loop(stream, dst, pkt_rx, out_tx).await {
                tracing::debug!("vmess udp peer {dst} end: {e:#}");
            }
        });
        self.peers.lock().await.insert(key, pkt_tx.clone());
        tracing::debug!("vmess udp associate {dst}");
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
                // 一次 write = 一个 AEAD chunk = 一个 UDP 数据报。
                wr.write_all(&data).await.context("vmess udp write")?;
                wr.flush().await.context("vmess udp flush")?;
            }
            res = read_datagram(&mut rd) => {
                let data = res?;
                if out_tx.send((data, src)).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// 读一个下行 chunk（即一个 UDP 数据报）。VMess 的分帧解码器保证一次 read
/// 返回一个完整 chunk；0 长度表示流结束。
async fn read_datagram<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    let n = rd.read(&mut buf).await.context("vmess udp read")?;
    buf.truncate(n);
    Ok(buf)
}

#[async_trait]
impl UdpSession for VmessUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        if data.is_empty() || data.len() > 65535 {
            bail!("vmess udp: invalid payload length {}", data.len());
        }
        let tx = self.ensure_peer(dst, dst_host).await?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| anyhow!("vmess udp peer closed"))?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("vmess udp session closed"))
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 域名：default-nameserver（bootstrap）优先，系统解析回落，
    // 避免系统 DNS 指回 ant 自身时的解析回环；失败仅影响当次拨号。
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ════════════════════════════════════════════════════════════════════════════
// 单元测试
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn test_user_key() -> [u8; 16] {
        user_key(&parse_uuid(TEST_UUID).unwrap())
    }

    #[test]
    fn uuid_and_security() {
        assert_eq!(parse_uuid(TEST_UUID).unwrap()[0], 0xaa);
        assert!(parse_uuid("aaabbbccdd").is_err(), "short uuid must be rejected");
        assert_eq!(resolve_security("auto").unwrap(), SECURITY_AES128_GCM);
        assert_eq!(resolve_security("none").unwrap(), SECURITY_NONE);
        assert_eq!(
            resolve_security("chacha20-poly1305").unwrap(),
            SECURITY_CHACHA20_POLY1305
        );
        assert!(resolve_security("aes-128-cfb").is_err());
    }

    #[test]
    fn kdf_is_deterministic_and_32_bytes() {
        let key = [0x42u8; 16];
        let a = kdf(&key, KDF_SALT_AUTH_ID, &[]);
        assert_eq!(a, kdf(&key, KDF_SALT_AUTH_ID, &[]));
        assert_eq!(a.len(), 32);
        // path 参与派生
        assert_ne!(a, kdf(&key, KDF_SALT_AUTH_ID, &[b"x"]));
    }

    /// 服务端视角：解析客户端握手帧，产出会话密钥与响应字节。
    struct ServerSession {
        security: u8,
        cmd: u8,
        decoder: VmessDecoder,
        encoder: VmessEncoder,
        /// 目标地址（`host:port`）
        target: String,
        /// 要回给客户端的 AEAD 响应头
        response: Vec<u8>,
    }

    /// 返回 `(session, consumed)`：`consumed` 是握手帧占用的字节数（后续字节
    /// 可能已经是上行 chunk —— ws 会把握手与首段负载合进同一帧）。
    fn server_accept(hs: &[u8], user_key: &[u8; 16]) -> Result<(ServerSession, usize)> {
        assert!(hs.len() > 42, "handshake too short: {}", hs.len());
        let auth_id = &hs[..16];
        let enc_len = &hs[16..34];
        let conn_nonce = &hs[34..42];

        let len_key = kdf(user_key, KDF_SALT_HEADER_LEN_KEY, &[auth_id, conn_nonce]);
        let len_iv = kdf(user_key, KDF_SALT_HEADER_LEN_IV, &[auth_id, conn_nonce]);
        let plain_len = aead_open(&len_key[..16], &len_iv[..12], enc_len, auth_id)
            .context("server: decrypt header length")?;
        let header_len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
        let consumed = 42 + header_len + CIPHER_OVERHEAD;
        assert!(
            hs.len() >= consumed,
            "handshake truncated: {} < {consumed}",
            hs.len()
        );
        let enc_hdr = &hs[42..consumed];

        let hdr_key = kdf(user_key, KDF_SALT_HEADER_KEY, &[auth_id, conn_nonce]);
        let hdr_iv = kdf(user_key, KDF_SALT_HEADER_IV, &[auth_id, conn_nonce]);
        let plain = aead_open(&hdr_key[..16], &hdr_iv[..12], enc_hdr, auth_id)
            .context("server: decrypt header")?;

        // [ver][nonce 16][key 16][respV][option][pad<<4|sec][reserved][cmd][port][atyp][addr..][pad][fnv]
        assert_eq!(plain[0], VERSION, "version");
        let req_nonce: [u8; 16] = plain[1..17].try_into().unwrap();
        let req_key: [u8; 16] = plain[17..33].try_into().unwrap();
        let resp_v = plain[33];
        let option = plain[34];
        let security = plain[35] & 0x0f;
        let cmd = plain[37];
        let port = u16::from_be_bytes([plain[38], plain[39]]);
        let atyp = plain[40];
        let addr = match atyp {
            ATYP_IPV4 => {
                let ip = std::net::Ipv4Addr::new(plain[41], plain[42], plain[43], plain[44]);
                ip.to_string()
            }
            ATYP_DOMAIN => {
                let l = plain[41] as usize;
                String::from_utf8_lossy(&plain[42..42 + l]).to_string()
            }
            ATYP_IPV6 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&plain[41..57]);
                std::net::Ipv6Addr::from(b).to_string()
            }
            other => bail!("server: unknown atyp {other:#04x}"),
        };

        // FNV1a 校验覆盖 header（除最后 4 字节）
        let body_len = plain.len() - 4;
        assert_eq!(fnv1a32(&plain[..body_len]), {
            let mut b = [0u8; 4];
            b.copy_from_slice(&plain[body_len..]);
            u32::from_be_bytes(b)
        });

        // 响应头：[respV][option][0][0]
        let resp_key = resp_data_key(&req_key);
        let resp_nonce = resp_data_nonce(&req_nonce);
        let rk = kdf(&resp_key, KDF_SALT_RESP_LEN_KEY, &[]);
        let riv = kdf(&resp_nonce, KDF_SALT_RESP_LEN_IV, &[]);
        let enc_resp_len = aead_seal(
            &rk[..16],
            &riv[..12],
            &(RESP_HEADER_LEN as u16).to_be_bytes(),
            b"",
        );
        let hk = kdf(&resp_key, KDF_SALT_RESP_KEY, &[]);
        let hiv = kdf(&resp_nonce, KDF_SALT_RESP_IV, &[]);
        let enc_resp_hdr = aead_seal(&hk[..16], &hiv[..12], &[resp_v, option, 0, 0], b"");
        let mut response = enc_resp_len;
        response.extend_from_slice(&enc_resp_hdr);
        assert_eq!(response.len(), 38);

        Ok((
            ServerSession {
                security,
                cmd,
                decoder: VmessDecoder::new(security, option, &req_key, &req_nonce),
                encoder: VmessEncoder::new(security, option, &resp_key, &resp_nonce),
                target: format!("{addr}:{port}"),
                response,
            },
            consumed,
        ))
    }

    /// VMess over TCP 回环：真实握手 + AEAD 双向收发。
    #[tokio::test]
    async fn vmess_tcp_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let user_key = test_user_key();

        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            // 1. 握手固定部分（16 + 18 + 8）
            let mut fixed = [0u8; 42];
            tcp.read_exact(&mut fixed).await.unwrap();
            let len_key = kdf(&user_key, KDF_SALT_HEADER_LEN_KEY, &[&fixed[..16], &fixed[34..42]]);
            let len_iv = kdf(&user_key, KDF_SALT_HEADER_LEN_IV, &[&fixed[..16], &fixed[34..42]]);
            let plain_len = aead_open(&len_key[..16], &len_iv[..12], &fixed[16..34], &fixed[..16])
                .unwrap();
            let hdr_len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
            let mut rest = vec![0u8; hdr_len + CIPHER_OVERHEAD];
            tcp.read_exact(&mut rest).await.unwrap();
            let mut hs = fixed.to_vec();
            hs.extend_from_slice(&rest);

            let (mut sess, consumed) = server_accept(&hs, &user_key).unwrap();
            assert_eq!(consumed, hs.len(), "tcp: 握手独占前 {} 字节", consumed);
            assert_eq!(sess.target, "example.com:443");
            assert_eq!(sess.cmd, CMD_TCP);
            // 2. 响应头
            tcp.write_all(&sess.response).await.unwrap();
            tcp.flush().await.unwrap();

            // 3. 收一个 chunk（应解密出 hello）
            let mut raw = BytesMut::new();
            let got = loop {
                if let Some(d) = sess.decoder.try_decode(&mut raw).unwrap() {
                    break d;
                }
                let mut tmp = [0u8; 1024];
                let n = tcp.read(&mut tmp).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&tmp[..n]);
            };
            assert_eq!(&got[..], b"hello");

            // 4. 回一个 chunk（world）
            let frame = sess.encoder.encode(b"world").unwrap();
            tcp.write_all(&frame).await.unwrap();
            tcp.flush().await.unwrap();
            sess.target
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vmess\nname: vm\nserver: '127.0.0.1'\nport: {port}\nuuid: {TEST_UUID}\nnetwork: tcp\ntls: false\ncipher: aes-128-gcm\nsni: example.com\n"
        ))
        .unwrap();
        let ob = VmessOutbound::new(&cfg).unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        assert_eq!(server.await.unwrap(), "example.com:443");
    }

    /// VMess over WS：握手帧合并进第一个 binary frame，响应头在首个下行帧里
    /// 被惰性剥离并校验，随后是 AEAD chunk 双向流。
    #[tokio::test]
    async fn vmess_ws_roundtrip() {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let user_key = test_user_key();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            // 1. 第一帧 = 握手（VmessStreamIo 会把它与首段负载合并成一帧）
            let frame = match ws.next().await.unwrap().unwrap() {
                Message::Binary(b) => b,
                other => panic!("unexpected frame {other:?}"),
            };
            let (mut sess, consumed) = server_accept(&frame, &user_key).unwrap();
            assert_eq!(sess.target, "example.com:443");
            assert_eq!(sess.cmd, CMD_TCP);
            assert!(
                frame.len() > consumed,
                "ws: 握手必须与首段负载在同一帧（{} vs {consumed}）",
                frame.len()
            );
            ws.send(Message::Binary(sess.response.clone())).await.unwrap();
            ws.flush().await.unwrap();

            // 2. 同一帧里剩下的就是上行 chunk
            let mut raw = BytesMut::from(&frame[consumed..]);
            let got = sess.decoder.try_decode(&mut raw).unwrap().expect("decode");
            assert_eq!(&got[..], b"hello");

            // 3. 回帧后优雅关闭（直接 drop 会让客户端在 EOF 处收到
            //    ResetWithoutClosingHandshake，吞掉已缓冲的帧）
            let out = sess.encoder.encode(b"world").unwrap();
            ws.send(Message::Binary(out.to_vec())).await.unwrap();
            ws.flush().await.unwrap();
            let _ = ws.close(None).await;
            sess.target
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vmess\nname: vm\nserver: '127.0.0.1'\nport: {port}\nuuid: {TEST_UUID}\nnetwork: ws\ntls: false\nws-path: /vm\nsni: example.com\n"
        ))
        .unwrap();
        let ob = VmessOutbound::new(&cfg).unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        // 服务端若中途 panic，在这里以 JoinError 暴露
        assert_eq!(server.await.unwrap(), "example.com:443");
    }

    /// 配置：network / cipher / utls 组合的解析与 fail-fast。
    #[tokio::test]
    async fn vmess_config_gating() {
        let base = format!("type: vmess\nname: vm\nserver: '1.2.3.4'\nport: 443\nuuid: {TEST_UUID}\n");

        // tcp + tls：cipher auto 在 TLS 下降级为 zero（无内层加密）
        let cfg: ProxyConfig = serde_yaml::from_str(&format!("{base}network: tcp\ntls: true\nsni: example.com\n")).unwrap();
        let ob = VmessOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.security, SECURITY_NONE);
        assert_eq!(ob.opts.tls_alpn, Vec::<String>::new());

        // 显式 cipher
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}network: tcp\ntls: false\ncipher: chacha20-poly1305\n")).unwrap();
        assert_eq!(VmessOutbound::new(&cfg).unwrap().opts.security, SECURITY_CHACHA20_POLY1305);

        // 未知 cipher → fail-fast
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}network: tcp\ntls: false\ncipher: aes-256-gcm\n")).unwrap();
        assert!(VmessOutbound::new(&cfg).is_err(), "unknown cipher must fail fast");

        // 缺 uuid → fail-fast
        let cfg: ProxyConfig =
            serde_yaml::from_str("type: vmess\nname: vm\nserver: '1.2.3.4'\nport: 443\n").unwrap();
        assert!(VmessOutbound::new(&cfg).is_err(), "missing uuid must fail fast");

        // 未知 xhttp-mode → fail-fast
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}network: xhttp\ntls: true\nsni: e.com\nxhttp-mode: bogus\n"
        ))
        .unwrap();
        assert!(VmessOutbound::new(&cfg).is_err(), "unknown xhttp-mode must fail fast");

        // xhttp auto → packet-up（h2 TLS 配置就绪）
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}network: xhttp\ntls: true\nsni: e.com\n"
        ))
        .unwrap();
        let ob = VmessOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::PacketUp);
        assert!(ob.opts.xhttp_h2_tls.is_some());

        // ws + utls：ALPN 强制 http/1.1（伪造 hello 与 rustls config 一致）
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}network: ws\ntls: true\nsni: e.com\nclient-fingerprint: firefox\n"
        ))
        .unwrap();
        let ob = VmessOutbound::new(&cfg).unwrap();
        assert_eq!(ob.opts.tls_alpn, vec!["http/1.1".to_string()]);
        assert_eq!(ob.opts.ws_host, "e.com");

        // 未知 client-fingerprint → fail-fast
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}network: tcp\ntls: true\nclient-fingerprint: nosuch\n"
        ))
        .unwrap();
        assert!(VmessOutbound::new(&cfg).is_err(), "unknown fingerprint must fail fast");
    }

    /// 请求头编码：地址类型与 FNV 校验；UDP 命令带 ChunkStream。
    #[test]
    fn request_header_layout() {
        let hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        let enc = hdr.encode(Some("example.com"), "1.2.3.4:443".parse().unwrap());
        assert_eq!(enc[0], VERSION);
        assert_eq!(&enc[1..17], &hdr.req_nonce);
        assert_eq!(&enc[17..33], &hdr.req_key);
        assert_eq!(enc[33], hdr.resp_header);
        assert_eq!(enc[34], OPT_CHUNK_STREAM | OPT_CHUNK_MASKING);
        assert_eq!(enc[35] & 0x0f, SECURITY_AES128_GCM);
        assert_eq!(enc[37], CMD_TCP);
        // port + atyp(domain) + len
        assert_eq!(&enc[38..40], &443u16.to_be_bytes());
        assert_eq!(enc[40], ATYP_DOMAIN);
        assert_eq!(enc[41], 11);
        assert_eq!(&enc[42..53], b"example.com");

        // IP 直连走 IPv4 atyp
        let enc = hdr.encode(None, "1.2.3.4:443".parse().unwrap());
        assert_eq!(enc[40], ATYP_IPV4);
        assert_eq!(&enc[41..45], &[1, 2, 3, 4]);
        // host_hint 是 IP 时不走域名 atyp
        let enc = hdr.encode(Some("1.2.3.4"), "1.2.3.4:443".parse().unwrap());
        assert_eq!(enc[40], ATYP_IPV4);

        // security=none + TCP：option = 0（裸流，无分帧）
        let hdr = RequestHeader::new(SECURITY_NONE, CMD_TCP);
        assert_eq!(hdr.option, 0);
        // security=none + UDP：option = ChunkStream
        let hdr = RequestHeader::new(SECURITY_NONE, CMD_UDP);
        assert_eq!(hdr.option, OPT_CHUNK_STREAM);
    }

    /// 编码器/解码器对称：AES-GCM chunk 往返，含长度掩码。
    #[test]
    fn aead_chunk_roundtrip() {
        let key = [7u8; 16];
        let nonce = [9u8; 16];
        let mut enc = VmessEncoder::new(SECURITY_AES128_GCM, OPT_CHUNK_STREAM | OPT_CHUNK_MASKING, &key, &nonce);
        let mut dec = VmessDecoder::new(
            SECURITY_AES128_GCM,
            OPT_CHUNK_STREAM | OPT_CHUNK_MASKING,
            &key,
            &nonce,
        );
        for payload in [b"a".as_slice(), b"hello world".as_slice(), &[0u8; 100][..]] {
            let frame = enc.encode(payload).unwrap();
            // 长度被 Shake128 掩码，不等于明文长度 + tag
            assert_ne!(u16::from_be_bytes([frame[0], frame[1]]) as usize, payload.len() + 16);
            let mut raw = BytesMut::from(&frame[..]);
            let got = dec.try_decode(&mut raw).unwrap().expect("decode");
            assert_eq!(&got[..], payload);
            assert!(raw.is_empty());
        }

        // 计数器 wrap 保护
        let mut enc = VmessEncoder::new(SECURITY_AES128_GCM, OPT_CHUNK_STREAM, &key, &nonce);
        enc.count = u16::MAX;
        assert!(enc.encode(b"x").is_err());
    }

    /// UDP：目标地址写入请求头，一个数据报一个 chunk。
    #[test]
    fn udp_request_header_carries_target() {
        let hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_UDP);
        let hs = build_handshake(
            &test_user_key(),
            &hdr,
            Some("dns.example"),
            "8.8.8.8:53".parse().unwrap(),
        );
        let (sess, consumed) = server_accept(&hs, &test_user_key()).unwrap();
        assert_eq!(consumed, hs.len());
        assert_eq!(sess.target, "dns.example:53");
        assert_eq!(sess.cmd, CMD_UDP, "UDP 目标写在请求头里（非 packetaddr）");
        assert_eq!(sess.security, SECURITY_AES128_GCM);
        assert_eq!(sess.response.len(), 38);
    }}
