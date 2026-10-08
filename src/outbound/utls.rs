//! uTLS — 浏览器 TLS 指纹伪造（ClientHello forgery）。ported from reflex
//! `src/outbound/tls/utls.rs`（其对齐 sing-box badtls/registry_utls.go 思路）。
//!
//! 原理：rustls 的 ClientHello 指纹（扩展顺序、cipher suites、GREASE 等）
//! 是明显的非浏览器特征。本模块构造真实浏览器（Chrome/Firefox/Safari/Edge）
//! 形状的 ClientHello TLS Record，在 rustls 发起握手时拦截其第一次写入并
//! 替换为伪造的 ClientHello；后续 I/O 全部透传。
//!
//! 关键点：伪造 ClientHello 中的 x25519 key_share 公钥必须与 rustls 内部
//! 私钥配对——`UtlsStream::poll_write` 拦截到 rustls 的真实 ClientHello 时，
//! 解析其中 key_share 扩展的公钥并 patch 进伪造 ClientHello，否则服务端与
//! rustls 的 ECDH 共享密钥不一致，Finished MAC 必然失败。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tracing::debug;

// ── TLS 记录层常量 ────────────────────────────────────────────────────────────

const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_LEGACY: u16 = 0x0301; // TLS 1.0（ClientHello legacy version）
const HS_CLIENT_HELLO: u8 = 0x01;

// ── 指纹配置 ──────────────────────────────────────────────────────────────────

/// uTLS 浏览器指纹，与 sing-box `utls.fingerprint` / reflex `UtlsFingerprint`
/// 对齐。配置字符串不区分大小写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Random,
    Ios,
    Android,
    Browser360,
    Qq,
}

impl UtlsFingerprint {
    /// 解析配置字符串（clash `client-fingerprint` / sing-box `utls.fingerprint`）。
    /// 未知值返回 None，调用方 fail-fast。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            "safari" => Some(Self::Safari),
            "edge" => Some(Self::Edge),
            "random" => Some(Self::Random),
            "ios" => Some(Self::Ios),
            "android" => Some(Self::Android),
            "360" | "browser360" => Some(Self::Browser360),
            "qq" => Some(Self::Qq),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum FpKind {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Random,
}

impl From<&UtlsFingerprint> for FpKind {
    fn from(fp: &UtlsFingerprint) -> Self {
        match fp {
            UtlsFingerprint::Chrome | UtlsFingerprint::Android => FpKind::Chrome,
            UtlsFingerprint::Firefox => FpKind::Firefox,
            UtlsFingerprint::Safari | UtlsFingerprint::Ios => FpKind::Safari,
            UtlsFingerprint::Edge => FpKind::Edge,
            UtlsFingerprint::Browser360 | UtlsFingerprint::Qq => FpKind::Chrome,
            UtlsFingerprint::Random => FpKind::Random,
        }
    }
}

fn resolve_fingerprint(fp: &UtlsFingerprint) -> FpKind {
    fp.into()
}

// ── 公开 API ──────────────────────────────────────────────────────────────────

/// 在 TCP 流上执行 uTLS 握手，返回经过 rustls 加密的 TLS 流。
///
/// 内部创建 [`UtlsStream`] 拦截 rustls 的第一次 ClientHello 写入，
/// 替换为对应 `fingerprint` 浏览器的 ClientHello 字节。
///
/// `alpn`：写入伪造 ClientHello 的 ALPN。必须与 `tls_config` 的
/// `alpn_protocols` 一致——服务端按伪造 ClientHello 选择协议，rustls
/// 会拒绝自身未 offer 的选择。
pub async fn connect_utls(
    tcp: TcpStream,
    server_name: &str,
    fingerprint: &UtlsFingerprint,
    tls_config: std::sync::Arc<rustls::ClientConfig>,
    alpn: &[String],
) -> anyhow::Result<tokio_rustls::client::TlsStream<UtlsStream>> {
    let fp = resolve_fingerprint(fingerprint);
    let hello_bytes = build_client_hello(server_name, fp, alpn);
    let wrapped = UtlsStream::new(tcp, hello_bytes);

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let sni = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("utls: invalid server name: {server_name}"))?;

    let tls = connector
        .connect(sni, wrapped)
        .await
        .map_err(|e| anyhow::anyhow!("utls handshake failed: {e}"))?;
    Ok(tls)
}

// ── ClientHello 构造 ──────────────────────────────────────────────────────────

/// 构造完整的 TLS 1.3 ClientHello TLS Record（含 TLS 记录头）。
///
/// 使用真实随机 random (32B) 和 session_id (32B)，
/// key_share 中的 x25519 公钥也随机生成（服务端只用于验证，rustls 会再次协商；
/// 发送前由 `patch_key_share` 替换为 rustls 的真实公钥）。
fn build_client_hello(sni: &str, fp: FpKind, alpn_override: &[String]) -> Vec<u8> {
    let fp = match fp {
        FpKind::Random => {
            let choices = [
                FpKind::Chrome,
                FpKind::Firefox,
                FpKind::Safari,
                FpKind::Edge,
            ];
            choices[rand::thread_rng().gen_range(0..choices.len())]
        }
        other => other,
    };

    let body = build_hello_body(sni, fp, alpn_override);

    // Handshake header: type(1) + length(3)
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(HS_CLIENT_HELLO);
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xff) as u8);
    hs.push(((blen >> 8) & 0xff) as u8);
    hs.push((blen & 0xff) as u8);
    hs.extend_from_slice(&body);

    // TLS Record header: content_type(1) + legacy_version(2) + length(2)
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(TLS_CONTENT_HANDSHAKE);
    rec.push(((TLS_VERSION_LEGACY >> 8) & 0xff) as u8);
    rec.push((TLS_VERSION_LEGACY & 0xff) as u8);
    let hlen = hs.len() as u16;
    rec.push(((hlen >> 8) & 0xff) as u8);
    rec.push((hlen & 0xff) as u8);
    rec.extend_from_slice(&hs);
    rec
}

fn build_hello_body(sni: &str, fp: FpKind, alpn_override: &[String]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // random (32B)
    let mut random = [0u8; 32];
    rng.fill(&mut random);

    // session_id (32B)
    let mut session_id = [0u8; 32];
    rng.fill(&mut session_id);

    // x25519 key_share public key (32B, random placeholder)
    let mut ks_pub = [0u8; 32];
    rng.fill(&mut ks_pub);

    let cipher_suites = cipher_suites_for(fp);
    let extensions = build_extensions(sni, fp, &ks_pub, alpn_override);

    let mut b = Vec::new();
    // legacy_version TLS 1.2
    b.extend_from_slice(&[0x03, 0x03]);
    // random
    b.extend_from_slice(&random);
    // session_id length + data
    b.push(32u8);
    b.extend_from_slice(&session_id);
    // cipher_suites
    let cs_len = (cipher_suites.len() * 2) as u16;
    b.push(((cs_len >> 8) & 0xff) as u8);
    b.push((cs_len & 0xff) as u8);
    for cs in &cipher_suites {
        b.push(((cs >> 8) & 0xff) as u8);
        b.push((cs & 0xff) as u8);
    }
    // compression methods: [1, 0x00]
    b.extend_from_slice(&[0x01, 0x00]);
    // extensions
    let ext_len = extensions.len() as u16;
    b.push(((ext_len >> 8) & 0xff) as u8);
    b.push((ext_len & 0xff) as u8);
    b.extend_from_slice(&extensions);
    b
}

// ── Cipher Suites ─────────────────────────────────────────────────────────────

/// Chrome 120 cipher suites (JA3 顺序)
const CHROME_CIPHERS: &[u16] = &[
    0xdada, // GREASE
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc00a, 0xc013,
    0xc014, 0x002f, 0x0035,
];

const SAFARI_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024, 0xc023, 0xc028,
    0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
];

fn cipher_suites_for(fp: FpKind) -> Vec<u16> {
    let base: &[u16] = match fp {
        FpKind::Chrome | FpKind::Edge | FpKind::Random => CHROME_CIPHERS,
        FpKind::Firefox => FIREFOX_CIPHERS,
        FpKind::Safari => SAFARI_CIPHERS,
    };
    // 将 GREASE 0xdada 替换为随机 GREASE 值（格式：0xXAXA，X 随机）
    base.iter()
        .map(|&cs| {
            if cs == 0xdada {
                // GREASE 值格式 0xXAXA（X = 0..15），与 grease_value() 一致用 0x1010 步长。
                // 旧实现用 0x1111 步长，当 x=15 时 15*0x1111+0x0a0a = 0x10A09 溢出 u16。
                let idx = rand::thread_rng().gen_range(0u16..16);
                0x0a0a + idx * 0x1010
            } else {
                cs
            }
        })
        .collect()
}

// ── Extensions ───────────────────────────────────────────────────────────────

fn build_extensions(sni: &str, fp: FpKind, ks_pub: &[u8; 32], alpn_override: &[String]) -> Vec<u8> {
    let mut exts = Vec::new();

    // GREASE extension (Chrome/Edge)
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        let grease = grease_value();
        append_ext(&mut exts, grease, &[0u8; 0]); // empty GREASE
    }

    // SNI (0x0000)
    {
        let name = sni.as_bytes();
        let mut d = Vec::new();
        // ServerNameList length
        let list_len = (name.len() + 3) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        // NameType host_name = 0
        d.push(0x00);
        let name_len = name.len() as u16;
        d.push(((name_len >> 8) & 0xff) as u8);
        d.push((name_len & 0xff) as u8);
        d.extend_from_slice(name);
        append_ext(&mut exts, 0x0000, &d);
    }

    // extended_master_secret (0x0017)
    append_ext(&mut exts, 0x0017, &[]);

    // renegotiation_info (0xff01)
    append_ext(&mut exts, 0xff01, &[0x00]);

    // supported_groups (0x000a)
    {
        let groups: &[u16] = match fp {
            FpKind::Chrome | FpKind::Edge => &[0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
            FpKind::Firefox => &[0x001d, 0x0017, 0x0018, 0x0019],
            FpKind::Safari | FpKind::Random => &[0x001d, 0x0017, 0x001e, 0x0018, 0x0019],
        };
        let mut d = Vec::new();
        let list_len = (groups.len() * 2) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        for g in groups {
            d.push(((g >> 8) & 0xff) as u8);
            d.push((g & 0xff) as u8);
        }
        append_ext(&mut exts, 0x000a, &d);
    }

    // ec_point_formats (0x000b)
    append_ext(&mut exts, 0x000b, &[0x01, 0x00]);

    // session_ticket (0x0023) - empty
    append_ext(&mut exts, 0x0023, &[]);

    // ALPN (0x0010)
    {
        let proto_list: Vec<&str> = if !alpn_override.is_empty() {
            alpn_override.iter().map(|s| s.as_str()).collect()
        } else {
            match fp {
                FpKind::Chrome | FpKind::Edge => vec!["h2", "http/1.1"],
                FpKind::Firefox => vec!["h2", "http/1.1"],
                FpKind::Safari | FpKind::Random => vec!["h2", "http/1.1"],
            }
        };
        let mut proto_bytes = Vec::new();
        for p in &proto_list {
            proto_bytes.push(p.len() as u8);
            proto_bytes.extend_from_slice(p.as_bytes());
        }
        let inner_len = proto_bytes.len() as u16;
        let mut d = Vec::new();
        d.push(((inner_len >> 8) & 0xff) as u8);
        d.push((inner_len & 0xff) as u8);
        d.extend_from_slice(&proto_bytes);
        append_ext(&mut exts, 0x0010, &d);
    }

    // status_request OCSP (0x0005)
    append_ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // signature_algorithms (0x000d)
    {
        let algs: &[u16] = match fp {
            FpKind::Firefox => &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ],
            _ => &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        };
        let mut d = Vec::new();
        let list_len = (algs.len() * 2) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        for a in algs {
            d.push(((a >> 8) & 0xff) as u8);
            d.push((a & 0xff) as u8);
        }
        append_ext(&mut exts, 0x000d, &d);
    }

    // signed_cert_timestamps (0x0012) - empty
    append_ext(&mut exts, 0x0012, &[]);

    // key_share (0x0033) - x25519 only
    {
        // ClientShares: one entry for x25519 (0x001d)
        let mut share = vec![0x00];
        share.push(0x1d); // group x25519
        share.push(0x00);
        share.push(0x20); // key_exchange length 32
        share.extend_from_slice(ks_pub);

        let shares_len = share.len() as u16;
        let mut d = Vec::new();
        d.push(((shares_len >> 8) & 0xff) as u8);
        d.push((shares_len & 0xff) as u8);
        d.extend_from_slice(&share);
        append_ext(&mut exts, 0x0033, &d);
    }

    // psk_key_exchange_modes (0x002d)
    append_ext(&mut exts, 0x002d, &[0x01, 0x01]); // psk_dhe_ke

    // supported_versions (0x002b) TLS 1.3 + 1.2
    {
        let versions: &[u16] = &[0x0304, 0x0303]; // TLS 1.3, TLS 1.2
        let mut d = Vec::new();
        d.push((versions.len() * 2) as u8);
        for v in versions {
            d.push(((v >> 8) & 0xff) as u8);
            d.push((v & 0xff) as u8);
        }
        append_ext(&mut exts, 0x002b, &d);
    }

    // compress_certificate (0x001b) - Chrome/Edge
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        append_ext(&mut exts, 0x001b, &[0x02, 0x00, 0x02]); // brotli
    }

    // application_settings (0x4469) - Chrome ALPS
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        // Advertise h2 support
        append_ext(&mut exts, 0x4469, &[0x00, 0x03, 0x02, b'h', b'2']);
    }

    // padding (0x0015) - Chrome pads to avoid fingerprinting on length
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        // Add padding to reach ~512 byte total extensions; calculate needed
        let current = exts.len() + 4; // +4 for this extension's header
        let target = 512usize;
        if current < target {
            let pad_len = target - current;
            let padding = vec![0u8; pad_len];
            append_ext(&mut exts, 0x0015, &padding);
        }
    }

    exts
}

fn append_ext(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.push(((ext_type >> 8) & 0xff) as u8);
    buf.push((ext_type & 0xff) as u8);
    let dlen = data.len() as u16;
    buf.push(((dlen >> 8) & 0xff) as u8);
    buf.push((dlen & 0xff) as u8);
    buf.extend_from_slice(data);
}

fn grease_value() -> u16 {
    // GREASE values: 0x0A0A, 0x1A1A, ..., 0xFAFA
    let idx = rand::thread_rng().gen_range(0u16..16);
    0x0a0a + idx * 0x1010
}

// ── key_share patch ──────────────────────────────────────────────────────────

/// 从 rustls 生成的 ClientHello 中提取 key_share 扩展里的 x25519 公钥，
/// 然后把伪造 ClientHello 中对应位置的随机公钥替换为真实公钥。
///
/// **背景**：旧实现用随机生成的 x25519 公钥填充伪造 ClientHello 的 key_share，
/// 但 rustls 内部使用自己的私钥计算 ECDH 共享密钥。服务端用伪造的公钥 →
/// 共享密钥 A，rustls 用自己的私钥 → 共享密钥 B，两者不匹配 → Finished MAC
/// 失败，握手必然失败。这就是 uTLS 被静默回退到 rustls 的根本原因。
///
/// **修正**：在 UtlsStream::poll_write 拦截到 rustls 的 ClientHello 时，
/// 解析其中的 key_share 扩展（extension type 0x0033），提取 x25519 (group 0x001d)
/// 的 32 字节公钥，然后 patch 到伪造 ClientHello 的对应位置。这样服务端和
/// rustls 使用相同的公钥/私钥对，ECDH 共享密钥一致，Finished MAC 通过。
fn patch_key_share(fake: &mut [u8], rustls_hello: &[u8]) {
    let real_key = match extract_x25519_key_share(rustls_hello) {
        Some(k) => k,
        None => {
            debug!(
                "utls: failed to extract x25519 key_share from rustls ClientHello ({} bytes), \
                 keeping random key_share — handshake will likely fail",
                rustls_hello.len()
            );
            return;
        }
    };

    if let Some(pos) = find_x25519_key_share_pos(fake) {
        fake[pos..pos + 32].copy_from_slice(&real_key);
        debug!(
            "utls: patched fake ClientHello key_share at offset {} with real rustls x25519 pubkey",
            pos
        );
    } else {
        debug!("utls: fake ClientHello has no x25519 key_share to patch");
    }
}

/// 从 TLS ClientHello record 中解析 key_share 扩展，提取 x25519 (group 0x001d) 的公钥。
///
/// ClientHello record 布局：
/// ```text
/// [record: type=0x16 ver=0x0301 len=2B]
///   [handshake: type=0x01 len=3B]
///     [body: legacy_ver=2B random=32B session_id_len=1B session_id=N
///            cipher_suites_len=2B cipher_suites comp_len=1B comp=N
///            extensions_len=2B extensions...]
///       extension: type=2B len=2B data
///         key_share (0x0033): client_shares_len=2B
///           share: group=2B key_len=2B key=N
/// ```
fn extract_x25519_key_share(record: &[u8]) -> Option<[u8; 32]> {
    // 跳过 record header (5B) + handshake type (1B)
    if record.len() < 9 {
        return None;
    }
    if record[0] != 0x16 {
        return None;
    }
    // handshake length (3B)：record[6..9]（record header 5B 之后是 handshake
    // type 1B + length 3B）。注意：reflex 原实现从 record[3..6] 读取——那里
    // 实际是 record length (2B) + handshake type (1B)，导致 hs_len 恒为超大值、
    // 解析必然失败、key_share 永远不会被 patch。
    let hs_len =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | (record[8] as usize);
    if record.len() < 5 + 1 + 3 + hs_len {
        return None;
    }
    // 跳到 handshake body
    let body = &record[5 + 1 + 3..];
    // 跳过 legacy_version (2B) + random (32B)
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34;
    // 跳过 session_id
    let sid_len = *body.get(pos)?;
    pos += 1 + sid_len as usize;
    // 跳过 cipher_suites
    let cs_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2 + cs_len;
    // 跳过 compression_methods
    let cm_len = *body.get(pos)?;
    pos += 1 + cm_len as usize;
    // extensions
    let ext_total_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;

    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = ((body[pos] as u16) << 8) | (body[pos + 1] as u16);
        let ext_len = ((body[pos + 2] as usize) << 8) | (body[pos + 3] as usize);
        pos += 4;
        if pos + ext_len > body.len() {
            break;
        }
        if ext_type == 0x0033 {
            // key_share extension
            return parse_key_share_extension(&body[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    None
}

/// 解析 key_share 扩展数据，找到 x25519 (group 0x001d) 的公钥。
fn parse_key_share_extension(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 2 {
        return None;
    }
    let total_len = ((data[0] as usize) << 8) | (data[1] as usize);
    let mut pos = 2;
    let end = 2 + total_len.min(data.len() - 2);
    while pos + 4 <= end {
        let group = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let key_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;
        if pos + key_len > data.len() {
            break;
        }
        if group == 0x001d && key_len == 32 {
            // x25519
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            return Some(key);
        }
        pos += key_len;
    }
    None
}

/// 在伪造的 ClientHello 中找到 x25519 key_share 公钥的位置（offset）。
/// 返回公钥 32 字节的起始偏移。
fn find_x25519_key_share_pos(record: &[u8]) -> Option<usize> {
    // 与 extract_x25519_key_share 类似的解析逻辑，但返回位置而非值。
    if record.len() < 6 || record[0] != 0x16 {
        return None;
    }
    let body = &record[5 + 1 + 3..];
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34;
    let sid_len = *body.get(pos)?;
    pos += 1 + sid_len as usize;
    let cs_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2 + cs_len;
    let cm_len = *body.get(pos)?;
    pos += 1 + cm_len as usize;
    let ext_total_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;

    let body_start = 5 + 1 + 3; // body 在 record 中的绝对偏移
    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = ((body[pos] as u16) << 8) | (body[pos + 1] as u16);
        let ext_len = ((body[pos + 2] as usize) << 8) | (body[pos + 3] as usize);
        let ext_data_pos = pos + 4;
        if ext_data_pos + ext_len > body.len() {
            break;
        }
        if ext_type == 0x0033 {
            // key_share extension: client_shares_len(2B) + shares
            let shares_data = &body[ext_data_pos..ext_data_pos + ext_len];
            if shares_data.len() < 2 {
                break;
            }
            let total = ((shares_data[0] as usize) << 8) | (shares_data[1] as usize);
            let mut sp = 2;
            let s_end = 2 + total.min(shares_data.len() - 2);
            while sp + 4 <= s_end {
                let group = ((shares_data[sp] as u16) << 8) | (shares_data[sp + 1] as u16);
                let key_len =
                    ((shares_data[sp + 2] as usize) << 8) | (shares_data[sp + 3] as usize);
                let key_pos = sp + 4;
                if key_pos + key_len > shares_data.len() {
                    break;
                }
                if group == 0x001d && key_len == 32 {
                    // 返回在 record 中的绝对偏移
                    return Some(body_start + ext_data_pos + key_pos);
                }
                sp = key_pos + key_len;
            }
            break;
        }
        pos = ext_data_pos + ext_len;
    }
    None
}

// ── UtlsStream ────────────────────────────────────────────────────────────────

/// TCP 流包装器，拦截 rustls 的第一次 write（ClientHello），
/// 替换为浏览器伪造的 ClientHello TLS Record。
// 后续所有 I/O 正常透传。
// 仅含 TcpStream（Unpin）与 Option<Vec<u8>>，自动 Unpin，无需 pin-project。
pub struct UtlsStream {
    inner: TcpStream,
    /// 替换用的伪造 ClientHello；None 表示已发送过
    fake_hello: Option<Vec<u8>>,
}

impl UtlsStream {
    pub fn new(inner: TcpStream, fake_hello: Vec<u8>) -> Self {
        Self {
            inner,
            fake_hello: Some(fake_hello),
        }
    }

    /// direct 模式（Vision）需要底层裸 TCP 绕过 AEAD 时使用。
    pub fn get_mut_tcp(&mut self) -> &mut TcpStream {
        &mut self.inner
    }
}

impl AsyncRead for UtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UtlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(hello) = this.fake_hello.as_mut() {
            // 拦截到 rustls 的第一次 write（ClientHello）。
            // 此时 `data` 是 rustls 生成的真实 ClientHello，从中提取 x25519 公钥
            // 并 patch 到伪造的 ClientHello（hello）中，修复 key_share 不匹配问题。
            //
            // 注意：仅当 data 看起来是 TLS Handshake record (type=0x16) 时才 patch，
            // 避免误处理非 ClientHello 的写入。
            if data.len() > 5 && data[0] == 0x16 {
                patch_key_share(hello, data);
            }

            // 循环发送伪造 ClientHello，正确处理 TCP 部分写入。
            loop {
                match Pin::new(&mut this.inner).poll_write(cx, hello) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "utls: write zero sending fake ClientHello",
                        )));
                    }
                    Poll::Ready(Ok(written)) => {
                        if written >= hello.len() {
                            debug!(
                                "utls: intercepted rustls ClientHello ({} bytes), \
                                 sent fake ClientHello ({} bytes)",
                                data.len(),
                                written
                            );
                            this.fake_hello = None;
                            return Poll::Ready(Ok(data.len()));
                        }
                        // 部分写入，drain 已写入部分，继续发送剩余
                        hello.drain(..written);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        } else {
            Pin::new(&mut this.inner).poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── TlsStreamBox：统一普通 rustls 与 uTLS 的 I/O 类型 ────────────────────────

/// 包装 rustls TLS 流或 uTLS 流，向上层提供统一的 `AsyncRead + AsyncWrite`。
#[allow(clippy::large_enum_variant)]
pub enum TlsStreamBox {
    /// 普通 rustls TLS 流
    Plain(tokio_rustls::client::TlsStream<TcpStream>),
    /// uTLS 流（浏览器指纹）
    Utls(Box<tokio_rustls::client::TlsStream<UtlsStream>>),
}

impl AsyncRead for TlsStreamBox {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStreamBox {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_write(cx, data),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_flush(cx),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parse() {
        assert_eq!(UtlsFingerprint::parse("chrome"), Some(UtlsFingerprint::Chrome));
        assert_eq!(
            UtlsFingerprint::parse(" FireFox "),
            Some(UtlsFingerprint::Firefox)
        );
        assert_eq!(UtlsFingerprint::parse("360"), Some(UtlsFingerprint::Browser360));
        assert_eq!(UtlsFingerprint::parse("qq"), Some(UtlsFingerprint::Qq));
        assert_eq!(UtlsFingerprint::parse("nosuch"), None);
        assert_eq!(UtlsFingerprint::parse(""), None);
    }

    #[test]
    fn chrome_hello_is_valid_tls_record() {
        let hello = build_client_hello("example.com", FpKind::Chrome, &[]);
        // TLS record header
        assert_eq!(hello[0], TLS_CONTENT_HANDSHAKE);
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
        // Handshake type = ClientHello
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], HS_CLIENT_HELLO);
    }

    #[test]
    fn firefox_hello_contains_sni() {
        let hello = build_client_hello("test.example.com", FpKind::Firefox, &[]);
        let bytes = hello.as_slice();
        let found = bytes.windows(16).any(|w| w == b"test.example.com");
        assert!(found, "SNI not found in Firefox ClientHello");
    }

    #[test]
    fn safari_hello_is_valid() {
        let hello = build_client_hello("safari.example.com", FpKind::Safari, &[]);
        assert!(hello.len() > 100);
        assert_eq!(hello[0], TLS_CONTENT_HANDSHAKE);
    }

    #[test]
    fn alpn_override_applied() {
        let hello = build_client_hello("sni.example.com", FpKind::Chrome, &["h2".to_string()]);
        let found = hello.windows(2).any(|w| w == b"h2");
        assert!(found, "ALPN h2 not found in ClientHello");
    }

    #[test]
    fn grease_value_is_grease() {
        for _ in 0..100 {
            let g = grease_value();
            let valid = [
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
                0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
            ];
            assert!(valid.contains(&g), "0x{g:04x} is not a valid GREASE value");
        }
    }

    /// key_share patch：伪造 hello 的随机公钥必须被 rustls hello 的真实公钥替换。
    #[test]
    fn patch_key_share_replaces_pubkey() {
        let fake = build_client_hello("example.com", FpKind::Chrome, &[]);
        // 构造一个最小 rustls 风格 hello：手工拼 record，使 key_share 可解析。
        let real_key = [0xABu8; 32];
        let rustls_hello = record_with_x25519_key_share(&real_key);

        let mut patched = fake.clone();
        patch_key_share(&mut patched, &rustls_hello);

        let pos = find_x25519_key_share_pos(&patched).expect("x25519 key_share pos");
        assert_eq!(&patched[pos..pos + 32], &real_key);
    }

    /// 手工构造一个带 x25519 key_share 的最小 ClientHello record（仅用于测试解析）。
    fn record_with_x25519_key_share(key: &[u8; 32]) -> Vec<u8> {
        // extensions: 仅 key_share
        let mut share = Vec::new();
        share.extend_from_slice(&36u16.to_be_bytes()); // client_shares_len（1 个 x25519 条目：2+2+32）
        share.extend_from_slice(&0x001du16.to_be_bytes()); // group x25519
        share.extend_from_slice(&32u16.to_be_bytes()); // key len
        share.extend_from_slice(key);

        let mut exts = Vec::new();
        append_ext(&mut exts, 0x0033, &share);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&0u16.to_be_bytes()); // cipher_suites len
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HS_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![TLS_CONTENT_HANDSHAKE];
        rec.extend_from_slice(&TLS_VERSION_LEGACY.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// 用真实 rustls ClientHello 验证 key_share 提取与 patch：
    /// handshake length 必须从 record[6..9] 读取（reflex 原实现偏移错误，
    /// 导致解析永远失败、key_share 永远不被 patch、uTLS 握手必然失败）。
    #[tokio::test]
    async fn extract_and_patch_real_rustls_hello() {
        use std::sync::Arc;

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let sni = rustls::pki_types::ServerName::try_from("example.com".to_string()).unwrap();
        tokio::spawn(async move {
            // 没有服务端响应也无妨：ClientHello 会在第一次 flush 时写出。
            let _ = connector.connect(sni, client).await;
        });

        // 读取第一个完整的 TLS record（0x16 开头）。
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut server, &mut chunk)
                .await
                .unwrap();
            assert!(n > 0, "eof before ClientHello");
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 9 && buf[0] == 0x16 {
                let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                if buf.len() >= 5 + rec_len {
                    break;
                }
            }
        }

        let key = extract_x25519_key_share(&buf)
            .expect("must extract x25519 key_share from a real rustls ClientHello");

        // patch 后伪造 hello 的 key_share 必须等于 rustls 真实公钥。
        let mut fake = build_client_hello("example.com", FpKind::Chrome, &[]);
        patch_key_share(&mut fake, &buf);
        let pos = find_x25519_key_share_pos(&fake).expect("fake hello has x25519 key_share");
        assert_eq!(&fake[pos..pos + 32], &key);
    }
}
