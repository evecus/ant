//! uTLS — 浏览器 TLS 指纹伪造（ClientHello forgery）。ported from reflex
//! `src/outbound/tls/utls.rs`（其对齐 sing-box badtls/registry_utls.go 思路）。
//!
//! ## 为什么不再「拦截 rustls 的 ClientHello 换成伪造 hello」
//!
//! TLS 1.3 的握手密钥是从**握手 transcript**（ClientHello..ServerHello 的哈希）
//! 派生的：服务端对自己**收到的** ClientHello 算 transcript，rustls 对自己
//! **生成的** ClientHello 算 transcript。旧实现在 socket 层把 ClientHello 换成
//! 浏览器形状的字节，两侧 transcript 必然不一致 —— 服务端发出 ServerHello 之后
//! 的所有加密报文 rustls 都解不开，日志上就是：
//!
//! ```text
//! utls handshake failed: cannot decrypt peer's message
//! ```
//!
//! 于是「不配 client-fingerprint 能连、配了就废」。这是协议层死结：
//! `s hs traffic` / `c hs traffic` 密钥取决于 transcript 哈希，靠 patch
//! key_share（只修 ECDH 共享密钥）无论如何补不上。
//!
//! mihomo / Xray 的做法（Go uTLS）是把 ClientHello 的控制权留在 TLS 库内部，
//! 让「线上字节」与「transcript 输入」是同一份数据；upstream rustls 明确拒绝
//! 提供 parroting API（rustls#1932），因此这里沿用本项目 REALITY 的思路：
//! **自己跑 TLS 1.3 client 握手**（record 层、key schedule、应用数据流复用
//! [`super::reality`]），ClientHello 完全由本模块构造 —— transcript 与线上字节
//! 天然一致，握手能正常完成。

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, Context as _, Result};
use once_cell::sync::Lazy;
use rand::Rng;
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tracing::{debug, warn};

use super::reality::{
    fill_decrypted_handshake, parse_server_hello, pop_handshake_message, put_u16, put_u24,
    read_plain_handshake, take, take_u16, take_u8, verify_finished, wrap_plain_record,
    ApplicationKeys, CipherSuite, HandshakeKeys, Tls13Stream, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY,
    HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_NEW_SESSION_TICKET, HS_SERVER_HELLO,
    TLS_RECORD_HANDSHAKE,
};

// ── ClientHello 布局常量 ─────────────────────────────────────────────────────

/// 浏览器 ClientHello 的 padding 目标长度（RFC 7685 padding 扩展，Chrome 行为）。
const HELLO_PAD_TARGET: usize = 512;

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

/// 实际下发的 Hello 模板。`Edge` / `360` / `QQ` / `Android` 都是 Chromium 系，
/// `Ios` 与 Safari 同源，去重后只有三套（与 mihomo 的 utls HelloID 同理）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum FpKind {
    Chrome,
    Firefox,
    Safari,
}

impl FpKind {
    fn pads(self) -> bool {
        // 只有 Chromium 系会把首个 ClientHello 补到 512 字节。
        matches!(self, Self::Chrome)
    }
}

fn resolve_fingerprint(fp: &UtlsFingerprint) -> FpKind {
    match fp {
        UtlsFingerprint::Chrome
        | UtlsFingerprint::Edge
        | UtlsFingerprint::Android
        | UtlsFingerprint::Browser360
        | UtlsFingerprint::Qq => FpKind::Chrome,
        UtlsFingerprint::Firefox => FpKind::Firefox,
        UtlsFingerprint::Safari | UtlsFingerprint::Ios => FpKind::Safari,
        // random：每次连接随机挑一套（与 mihomo `random` 一致）。
        UtlsFingerprint::Random => {
            let choices = [FpKind::Chrome, FpKind::Firefox, FpKind::Safari];
            let idx = rand::thread_rng().gen_range(0..choices.len());
            choices[idx]
        }
    }
}

// ── 证书校验参数 ──────────────────────────────────────────────────────────────

/// uTLS 握手的证书校验选项（取代原先传入的 `Arc<rustls::ClientConfig>`）。
///
/// 自实现握手不再走 rustls，而 rustls 的 `ClientConfig` 无法反查其 verifier
/// （字段私有），因此把 `skip-cert-verify` 与 sha256 证书 pin 显式传进来。
#[derive(Clone, Debug, Default)]
pub struct UtlsVerify {
    /// `skip-cert-verify`：跳过证书链与主机名校验。
    pub skip_cert_verify: bool,
    /// `fingerprint`：叶子证书 sha256（hex，大小写不敏感）。
    pub fingerprint: Option<String>,
}

/// webpki 根证书验证器（进程内只构建一次；utls 握手复用它做链 + 主机名校验，
/// 以及 CertificateVerify 签名校验）。
static ROOT_VERIFIER: Lazy<Arc<WebPkiServerVerifier>> = Lazy::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("utls: build webpki server verifier")
});

// ── 公开 API ──────────────────────────────────────────────────────────────────

/// 在 TCP 流上完成带浏览器指纹的 TLS 1.3 握手，返回应用数据流。
///
/// 与 mihomo 的差异只在实现路径：那里是 Go uTLS 改 `crypto/tls` 的 hello
/// 构造，这里是本包自实现的 TLS 1.3 client（见模块文档），语义一致 ——
/// ClientHello 的每一字节都由 `alpn` / `fingerprint` 决定。
pub async fn connect_utls(
    tcp: TcpStream,
    server_name: &str,
    fingerprint: &UtlsFingerprint,
    verify: &UtlsVerify,
    alpn: &[String],
) -> Result<Tls13Stream> {
    let mut inner = tcp;
    let fp = resolve_fingerprint(fingerprint);

    // 1. 每连接的随机材料：client_random、middlebox-compat session_id、
    //    x25519 密钥对（transcript 里的 key_share 公钥与本地私钥同源）。
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = x25519_dalek::PublicKey::from(&client_secret);

    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rng.fill(&mut random);
    rng.fill(&mut session_id);
    let randoms = HelloRandoms {
        random: &random,
        session_id: &session_id,
        key_share: client_public.as_bytes(),
    };

    // 2. 构造并发送 ClientHello（这份字节同时用于 handshake transcript）。
    let client_hello = build_client_hello(server_name, fp, alpn, &randoms)?;
    let record = wrap_plain_record(TLS_RECORD_HANDSHAKE, &client_hello)?;
    debug!(
        fp = ?fingerprint,
        hello_len = client_hello.len(),
        "utls: sending ClientHello"
    );
    inner.write_all(&record).await?;
    inner.flush().await?;

    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&client_hello);

    // 3. ServerHello：确定 cipher suite 与服务端 key_share。
    let server_hello = read_plain_handshake(&mut inner, HS_SERVER_HELLO).await?;
    let parsed = parse_server_hello(&server_hello).context("utls: parse ServerHello")?;
    transcript.extend_from_slice(&server_hello);

    let server_public = x25519_dalek::PublicKey::from(parsed.key_share);
    let shared_secret = client_secret.diffie_hellman(&server_public).to_bytes();

    let cipher = CipherSuite::try_from(parsed.cipher_suite)?;
    let hs = HandshakeKeys::derive(cipher, &shared_secret, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    // 4. 读取并解密服务端握手消息：EE → Certificate → CertificateVerify → Finished。
    let mut handshake_buf = VecDeque::new();
    let mut chain: Option<CertChain> = None;
    let mut saw_encrypted_extensions = false;
    let mut saw_certificate_verify = false;
    let server_finished;

    loop {
        // 服务端可能把 EE + Certificate + CertificateVerify + Finished 塞进同一个
        // record，必须先消费缓冲区，否则会在服务端等 Finished 时阻塞读新 record。
        let msg = match pop_handshake_message(&mut handshake_buf) {
            Some(m) => m,
            None => {
                fill_decrypted_handshake(&mut inner, &mut server_hs, &mut handshake_buf).await?;
                pop_handshake_message(&mut handshake_buf)
                    .ok_or_else(|| anyhow!("utls: decrypted empty handshake record"))?
            }
        };
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS => {
                check_server_alpn(&msg.body, alpn);
                transcript.extend_from_slice(&msg.raw);
                saw_encrypted_extensions = true;
            }
            HS_CERTIFICATE => {
                let parsed_chain = parse_certificate_chain(&msg.body)?;
                transcript.extend_from_slice(&msg.raw);
                chain = Some(parsed_chain);
            }
            HS_CERTIFICATE_VERIFY => {
                let chain = chain
                    .as_ref()
                    .ok_or_else(|| anyhow!("utls: CertificateVerify without Certificate"))?;
                // transcript 此时已含 ClientHello..Certificate。
                verify_certificate_verify(&msg.body, &chain.leaf, &transcript)?;
                transcript.extend_from_slice(&msg.raw);
                saw_certificate_verify = true;
            }
            HS_FINISHED => {
                verify_finished(cipher.hash_kind(), &hs.server_secret, &transcript, &msg.body)?;
                server_finished = msg.raw;
                break;
            }
            HS_NEW_SESSION_TICKET => {
                // 握手尾部的 session ticket：不支持也不使用，忽略。
            }
            other => bail!("utls: unexpected handshake message {other}"),
        }
    }

    if !saw_encrypted_extensions || !saw_certificate_verify {
        bail!("utls: incomplete server handshake");
    }
    let chain = chain.ok_or_else(|| anyhow!("utls: missing server certificate"))?;
    verify_server_certificate(&chain, server_name, verify)?;

    // 5. 应用密钥（transcript 含到服务端 Finished）+ 客户端 Finished。
    transcript.extend_from_slice(&server_finished);
    let app = ApplicationKeys::derive(cipher, &hs.master_secret, &transcript);

    let finished_body = cipher
        .hash_kind()
        .finished_verify_data(&hs.client_secret, &transcript);
    let mut client_finished = Vec::with_capacity(4 + finished_body.len());
    client_finished.push(HS_FINISHED);
    put_u24(finished_body.len(), &mut client_finished);
    client_finished.extend_from_slice(&finished_body);
    let finished_record = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished)?;
    inner.write_all(&finished_record).await?;
    inner.flush().await?;

    debug!(
        fp = ?fingerprint,
        cipher_suite = format_args!("0x{:04x}", parsed.cipher_suite),
        "utls: TLS 1.3 handshake complete"
    );
    Ok(Tls13Stream::new(inner, app.server, app.client))
}

// ── ClientHello 构造 ──────────────────────────────────────────────────────────

/// 构造 ClientHello 所需的每连接随机材料。
struct HelloRandoms<'a> {
    random: &'a [u8; 32],
    session_id: &'a [u8; 32],
    key_share: &'a [u8; 32],
}

/// 构造完整的 ClientHello handshake message（含 4 字节 handshake 头）。
fn build_client_hello(
    sni: &str,
    fp: FpKind,
    alpn: &[String],
    randoms: &HelloRandoms<'_>,
) -> Result<Vec<u8>> {
    let cipher_suites = cipher_suites_for(fp);

    let mut body = Vec::with_capacity(HELLO_PAD_TARGET);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(randoms.random);
    body.push(32u8); // session_id length（Chrome 的 middlebox-compat 32B）
    body.extend_from_slice(randoms.session_id);
    put_u16((cipher_suites.len() * 2) as u16, &mut body);
    for cs in &cipher_suites {
        put_u16(*cs, &mut body);
    }
    body.push(0x01); // compression_methods: [null]
    body.push(0x00);

    let mut plan = extension_plan(fp, sni, alpn, randoms.key_share);
    if fp.pads() {
        // 4B handshake 头 + body + 2B extensions length + 扩展条目（4B 头 + data）
        let mut current = 4 + body.len() + 2;
        for (_, data) in &plan {
            current += 4 + data.len();
        }
        if current < HELLO_PAD_TARGET {
            let deficit = HELLO_PAD_TARGET - current;
            match plan.last_mut() {
                // Chrome 模板末尾已放好 padding 条目，直接把 data 补到目标长度。
                Some((typ, data)) if *typ == 0x0015 => data.resize(deficit, 0),
                _ => plan.push((0x0015, vec![0u8; deficit.saturating_sub(4)])),
            }
        }
    }

    let mut extensions = Vec::with_capacity(HELLO_PAD_TARGET);
    for (typ, data) in &plan {
        put_u16(*typ, &mut extensions);
        put_u16(data.len() as u16, &mut extensions);
        extensions.extend_from_slice(data);
    }
    put_u16(extensions.len() as u16, &mut body);
    body.extend_from_slice(&extensions);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);
    Ok(hello)
}

/// 按浏览器顺序排好扩展列表 `(type, data)`。
///
/// 扩展顺序是 JA3 / JA4 指纹的主要来源，所以每套模板按对应浏览器的真实顺序
/// 下发：Chromium 系（Chrome/Edge/360/QQ/Android）带 GREASE、ALPS 与 padding，
/// Firefox 与 Safari 不带 padding，Safari 不 announce SCT。
fn extension_plan(
    fp: FpKind,
    sni: &str,
    alpn: &[String],
    key_share: &[u8; 32],
) -> Vec<(u16, Vec<u8>)> {
    let grease = grease_value();
    let mut plan: Vec<(u16, Vec<u8>)> = Vec::with_capacity(18);

    match fp {
        FpKind::Chrome => {
            plan.push((grease, Vec::new())); // GREASE
            plan.push((0x0000, ext_server_name(sni)));
            plan.push((0x0017, Vec::new())); // extended_master_secret
            plan.push((0xff01, vec![0x00])); // renegotiation_info
            plan.push((0x000a, ext_u16_list(&[0x001d, 0x0017, 0x0018])));
            plan.push((0x000b, vec![0x01, 0x00])); // ec_point_formats: uncompressed
            plan.push((0x0023, Vec::new())); // session_ticket
            if let Some(d) = ext_alpn(alpn) {
                plan.push((0x0010, d));
            }
            plan.push((0x0005, ext_status_request()));
            plan.push((0x000d, ext_u16_list(CHROME_SIGNATURE_ALGORITHMS)));
            plan.push((0x0012, Vec::new())); // signed_certificate_timestamp
            plan.push((0x0033, ext_key_share(key_share)));
            plan.push((0x002d, vec![0x01, 0x01])); // psk_dhe_ke
            plan.push((0x002b, ext_supported_versions(grease)));
            plan.push((0x001b, vec![0x02, 0x00, 0x02])); // compress_certificate: brotli
            plan.push((0x4469, vec![0x00, 0x03, 0x02, b'h', b'2'])); // ALPS
            plan.push((0x0015, Vec::new())); // padding（长度在 build 时回填）
        }
        FpKind::Firefox => {
            plan.push((0x0000, ext_server_name(sni)));
            plan.push((0x0017, Vec::new()));
            plan.push((0xff01, vec![0x00]));
            plan.push((0x000a, ext_u16_list(&[0x001d, 0x0017, 0x0018, 0x0019])));
            plan.push((0x000b, vec![0x01, 0x00]));
            if let Some(d) = ext_alpn(alpn) {
                plan.push((0x0010, d));
            }
            plan.push((0x0005, ext_status_request()));
            plan.push((0x000d, ext_u16_list(FIREFOX_SIGNATURE_ALGORITHMS)));
            plan.push((0x0033, ext_key_share(key_share)));
            plan.push((0x002d, vec![0x01, 0x01]));
            // Firefox 的 supported_versions 里只有一个 GREASE 占位：这里直接只列 TLS 1.3。
            plan.push((0x002b, ext_supported_versions_only_13()));
        }
        FpKind::Safari => {
            plan.push((0x0000, ext_server_name(sni)));
            plan.push((0x0017, Vec::new()));
            plan.push((0xff01, vec![0x00]));
            plan.push((0x000a, ext_u16_list(&[0x001d, 0x0017, 0x0018])));
            plan.push((0x000b, vec![0x01, 0x00]));
            if let Some(d) = ext_alpn(alpn) {
                plan.push((0x0010, d));
            }
            plan.push((0x0005, ext_status_request()));
            plan.push((0x000d, ext_u16_list(SAFARI_SIGNATURE_ALGORITHMS)));
            plan.push((0x0033, ext_key_share(key_share)));
            plan.push((0x002b, ext_supported_versions_only_13()));
            plan.push((0x002d, vec![0x01, 0x01]));
        }
    }

    plan
}

// ── Cipher Suites ─────────────────────────────────────────────────────────────

/// Chrome cipher suites（JA3 顺序，首个是随机 GREASE 值）
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

const CHROME_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

const FIREFOX_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const SAFARI_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

fn cipher_suites_for(fp: FpKind) -> Vec<u16> {
    let base: &[u16] = match fp {
        FpKind::Chrome => CHROME_CIPHERS,
        FpKind::Firefox => FIREFOX_CIPHERS,
        FpKind::Safari => SAFARI_CIPHERS,
    };
    // GREASE 值格式 0xXAXA（X = 0..15）；步长 0x1010 保证 x=15 时不溢出 u16。
    base.iter()
        .map(|&cs| {
            if cs == 0xdada {
                grease_value()
            } else {
                cs
            }
        })
        .collect()
}

// ── 扩展内容 ──────────────────────────────────────────────────────────────────

fn ext_server_name(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut d = Vec::with_capacity(name.len() + 5);
    put_u16((name.len() + 3) as u16, &mut d); // ServerNameList length
    d.push(0x00); // NameType host_name
    put_u16(name.len() as u16, &mut d);
    d.extend_from_slice(name);
    d
}

fn ext_u16_list(values: &[u16]) -> Vec<u8> {
    let mut d = Vec::with_capacity(2 + values.len() * 2);
    put_u16((values.len() * 2) as u16, &mut d);
    for v in values {
        put_u16(*v, &mut d);
    }
    d
}

/// ALPN 扩展内容；`alpn` 为空时返回 None（不发送该扩展）。
fn ext_alpn(alpn: &[String]) -> Option<Vec<u8>> {
    let mut list = Vec::new();
    for p in alpn {
        if p.is_empty() || p.len() > 255 {
            continue;
        }
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    if list.is_empty() {
        return None;
    }
    let mut d = Vec::with_capacity(2 + list.len());
    put_u16(list.len() as u16, &mut d);
    d.extend_from_slice(&list);
    Some(d)
}

/// key_share：只带 x25519 一份（服务端必须支持 X25519，否则会回 HelloRetryRequest）。
fn ext_key_share(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(2 + 2 + 2 + 32);
    put_u16(36u16, &mut d); // client_shares length: group(2) + len(2) + key(32)
    put_u16(0x001d, &mut d); // x25519
    put_u16(32u16, &mut d);
    d.extend_from_slice(pubkey);
    d
}

fn ext_status_request() -> Vec<u8> {
    // OCSP: status_type(1) + no responder_ids + no request_extensions
    vec![0x01, 0x00, 0x00, 0x00, 0x00]
}

/// supported_versions：GREASE + TLS 1.3。
///
/// 真实浏览器会带上 1.2，但本实现只支持 TLS 1.3 —— 列 1.2 只会让服务端选到
/// 我们走不完的版本，所以只 offer 1.3（几乎所有节点都支持）。
fn ext_supported_versions(grease: u16) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + 4);
    d.push(4u8); // versions length: 2 * 2B
    put_u16(grease, &mut d);
    put_u16(0x0304, &mut d); // TLS 1.3
    d
}

fn ext_supported_versions_only_13() -> Vec<u8> {
    let mut d = Vec::with_capacity(3);
    d.push(2u8);
    put_u16(0x0304, &mut d);
    d
}

fn grease_value() -> u16 {
    // GREASE 值：0x0A0A, 0x1A1A, ..., 0xFAFA（RFC 8701）
    let idx = rand::thread_rng().gen_range(0u16..16);
    0x0a0a + idx * 0x1010
}

// ── 服务端证书 ────────────────────────────────────────────────────────────────

struct CertChain {
    leaf: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
}

/// 解析 Certificate handshake message（RFC 8446 §4.4.2）。
fn parse_certificate_chain(body: &[u8]) -> Result<CertChain> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    take(body, &mut pos, ctx_len)?;
    let list_len = take_u24_bytes(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;

    let mut certs = Vec::new();
    let mut p = 0;
    while p < list.len() {
        let cert_len = take_u24_bytes(list, &mut p)?;
        certs.push(take(list, &mut p, cert_len)?.to_vec());
        let ext_len = take_u16(list, &mut p)? as usize;
        take(list, &mut p, ext_len)?; // certificate extensions（OCSP/SCT 等）
    }

    let mut iter = certs.into_iter();
    let leaf = iter
        .next()
        .ok_or_else(|| anyhow!("utls: empty certificate chain"))?;
    Ok(CertChain {
        leaf,
        intermediates: iter.collect(),
    })
}

fn take_u24_bytes(input: &[u8], pos: &mut usize) -> Result<usize> {
    let bytes = take(input, pos, 3)?;
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

/// 证书链 / 主机名 / pin 校验。语义与 rustls 路径一致：
/// `fingerprint` 命中即通过（不校验链），否则看 `skip-cert-verify`。
fn verify_server_certificate(
    chain: &CertChain,
    server_name: &str,
    verify: &UtlsVerify,
) -> Result<()> {
    if let Some(pin) = &verify.fingerprint {
        let got = hex::encode(Sha256::digest(&chain.leaf));
        if !got.eq_ignore_ascii_case(pin) {
            bail!("utls: certificate fingerprint mismatch: got {got}, expected {pin}");
        }
        return Ok(());
    }
    if verify.skip_cert_verify {
        return Ok(());
    }

    let leaf = CertificateDer::from(chain.leaf.clone());
    let intermediates: Vec<CertificateDer<'_>> = chain
        .intermediates
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("utls: invalid server name {server_name}"))?;
    ROOT_VERIFIER
        .verify_server_cert(&leaf, &intermediates, &name, &[], UnixTime::now())
        .map_err(|e| anyhow!("utls: certificate verification failed: {e}"))?;
    Ok(())
}

/// CertificateVerify（RFC 8446 §4.4.3）：验证服务端持有证书私钥。
///
/// 即使 `skip-cert-verify` 也要验这一步 —— 否则伪装园区证书的中间人可以
/// 用任意签名顶掉握手，这是我们能在自实现握手里保住的最后一道真实性检查。
fn verify_certificate_verify(body: &[u8], leaf: &[u8], transcript: &[u8]) -> Result<()> {
    let mut pos = 0;
    let raw_scheme = take_u16(body, &mut pos)?;
    let sig_len = take_u16(body, &mut pos)? as usize;
    let signature = take(body, &mut pos, sig_len)?;
    let (scheme, hash) = signature_scheme(raw_scheme)?;

    let transcript_hash = hash.digest(transcript);
    let mut content = Vec::with_capacity(64 + 33 + transcript_hash.len());
    content.extend_from_slice(&[0x20u8; 64]);
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(&transcript_hash);

    let dss = DigitallySignedStruct::new(scheme, signature.to_vec());
    let leaf_der = CertificateDer::from(leaf.to_vec());
    ROOT_VERIFIER
        .verify_tls13_signature(&content, &leaf_der, &dss)
        .map_err(|e| anyhow!("utls: CertificateVerify failed: {e}"))?;
    Ok(())
}

/// CertificateVerify 所用的摘要（RFC 8446 §4.4.3）。
/// Ed25519 自身不 pre-hash，TLS 1.3 为其配套的摘要是 SHA-512。
#[derive(Clone, Copy)]
enum CvHash {
    Sha256,
    Sha384,
    Sha512,
}

impl CvHash {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

fn signature_scheme(raw: u16) -> Result<(SignatureScheme, CvHash)> {
    Ok(match raw {
        0x0403 => (SignatureScheme::ECDSA_NISTP256_SHA256, CvHash::Sha256),
        0x0503 => (SignatureScheme::ECDSA_NISTP384_SHA384, CvHash::Sha384),
        0x0804 | 0x0809 => (SignatureScheme::RSA_PSS_SHA256, CvHash::Sha256),
        0x0805 | 0x080a => (SignatureScheme::RSA_PSS_SHA384, CvHash::Sha384),
        0x0806 | 0x080b => (SignatureScheme::RSA_PSS_SHA512, CvHash::Sha512),
        0x0807 => (SignatureScheme::ED25519, CvHash::Sha512),
        other => bail!("utls: unsupported CertificateVerify signature scheme 0x{other:04x}"),
    })
}

/// 校验服务端在 EncryptedExtensions 里选的 ALPN 确实是我们 offer 过的。
/// 只 warn 不中断：某些服务端实现会把 ER 填得很随意，但后续应用层仍走约定协议。
fn check_server_alpn(body: &[u8], offered: &[String]) {
    if offered.is_empty() {
        return;
    }
    let mut pos = 0;
    let Ok(total) = take_u16(body, &mut pos) else {
        return;
    };
    let Ok(exts) = take(body, &mut pos, total as usize) else {
        return;
    };

    let mut ep = 0;
    while let Ok((typ, data)) = next_extension(exts, &mut ep) {
        if typ != 0x0010 {
            continue;
        }
        let mut p = 0;
        if take_u16(data, &mut p).is_err() {
            return;
        }
        while let Ok(len) = take_u8(data, &mut p) {
            let Ok(proto) = take(data, &mut p, len as usize) else {
                return;
            };
            let selected = String::from_utf8_lossy(proto).to_string();
            if offered.iter().any(|a| a == &selected) {
                debug!("utls: server selected ALPN {selected}");
            } else {
                warn!("utls: server selected ALPN {selected:?}, offered {offered:?}");
            }
            return;
        }
        return;
    }
}

fn next_extension<'a>(input: &'a [u8], pos: &mut usize) -> Result<(u16, &'a [u8])> {
    let typ = take_u16(input, pos)?;
    let len = take_u16(input, pos)? as usize;
    let data = take(input, pos, len)?;
    Ok((typ, data))
}

// ── TlsStreamBox：统一普通 rustls 与 uTLS 的 I/O 类型 ────────────────────────

/// 包装 rustls TLS 流或自实现 uTLS 流，向上层提供统一的 `AsyncRead + AsyncWrite`。
#[allow(clippy::large_enum_variant)]
pub enum TlsStreamBox {
    /// 普通 rustls TLS 流
    Plain(tokio_rustls::client::TlsStream<TcpStream>),
    /// uTLS 流（浏览器指纹，自实现 TLS 1.3）
    Utls(Box<Tls13Stream>),
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

    fn randoms<'a>(
        random: &'a [u8; 32],
        session_id: &'a [u8; 32],
        key_share: &'a [u8; 32],
    ) -> HelloRandoms<'a> {
        HelloRandoms {
            random,
            session_id,
            key_share,
        }
    }

    fn plan_for(fp: FpKind, alpn: &[String]) -> Vec<(u16, Vec<u8>)> {
        extension_plan(fp, "example.com", alpn, &[0u8; 32])
    }

    #[test]
    fn fingerprint_parse() {
        assert_eq!(UtlsFingerprint::parse("chrome"), Some(UtlsFingerprint::Chrome));
        assert_eq!(
            UtlsFingerprint::parse(" FireFox "),
            Some(UtlsFingerprint::Firefox)
        );
        assert_eq!(
            UtlsFingerprint::parse("360"),
            Some(UtlsFingerprint::Browser360)
        );
        assert_eq!(UtlsFingerprint::parse("qq"), Some(UtlsFingerprint::Qq));
        assert_eq!(UtlsFingerprint::parse("nosuch"), None);
        assert_eq!(UtlsFingerprint::parse(""), None);
    }

    #[test]
    fn grease_value_is_grease() {
        for _ in 0..100 {
            let g = grease_value();
            let valid = [
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
                0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
            ];
            assert!(valid.contains(&g), "0x{g:04x} 不是合法 GREASE 值");
        }
    }

    /// Chrome 的扩展顺序必须与真实 Chrome 一致（JA3 依据的顺序就是这里定的）。
    #[test]
    fn chrome_extension_order() {
        let plan = plan_for(FpKind::Chrome, &["h2".into(), "http/1.1".into()]);
        let order: Vec<u16> = plan.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            order,
            vec![
                // GREASE（随机值，位置固定为第一个）
                order[0],
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // ALPN
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x0033, // key_share
                0x002d, // psk_key_exchange_modes
                0x002b, // supported_versions
                0x001b, // compress_certificate
                0x4469, // application_settings (ALPS)
                0x0015, // padding
            ]
        );
        let valid_grease: Vec<u16> = (0..16u16).map(|i| 0x0a0a + i * 0x1010).collect();
        assert!(valid_grease.contains(&order[0]), "首项必须是 GREASE");
    }

    #[test]
    fn firefox_and_safari_skip_padding() {
        let ff = plan_for(FpKind::Firefox, &[]);
        let sf = plan_for(FpKind::Safari, &[]);
        assert!(ff.iter().all(|(t, _)| *t != 0x0015));
        assert!(sf.iter().all(|(t, _)| *t != 0x0015));
        // 未配置 ALPN 时不发送 ALPN 扩展
        assert!(ff.iter().all(|(t, _)| *t != 0x0010));
    }

    #[test]
    fn hello_carries_sni_random_and_key_share() {
        let random = [0x11u8; 32];
        let session_id = [0x22u8; 32];
        let key_share = [0x33u8; 32];
        let h = randoms(&random, &session_id, &key_share);
        let hello = build_client_hello("nodes.example.com", FpKind::Chrome, &[], &h).unwrap();

        // handshake 头：type 0x01 + 3B length
        assert_eq!(hello[0], HS_CLIENT_HELLO);
        let hs_len =
            ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | (hello[3] as usize);
        assert_eq!(hello.len(), 4 + hs_len);
        // random / session_id / key_share 都位在 body 里
        assert!(hello.windows(32).any(|w| w == random.as_slice()));
        assert!(hello.windows(32).any(|w| w == session_id.as_slice()));
        assert!(hello.windows(32).any(|w| w == key_share.as_slice()));
        // SNI
        assert!(hello
            .windows(17)
            .any(|w| w == b"nodes.example.com"));
    }

    #[test]
    fn chrome_hello_is_padded_to_512() {
        let random = [0u8; 32];
        let session_id = [0u8; 32];
        let key_share = [0u8; 32];
        let h = randoms(&random, &session_id, &key_share);
        let hello = build_client_hello("example.com", FpKind::Chrome, &[], &h).unwrap();
        assert!(hello.len() >= HELLO_PAD_TARGET, "hello len = {}", hello.len());
    }

    #[test]
    fn alpn_roundtrip() {
        let random = [0u8; 32];
        let session_id = [0u8; 32];
        let key_share = [0u8; 32];
        let h = randoms(&random, &session_id, &key_share);
        let alpn = vec!["h2".to_string()];
        let hello = build_client_hello("example.com", FpKind::Chrome, &alpn, &h).unwrap();
        // ALPN 内容：protocol_name_list = len(2) + [len(1) + "h2"]
        let want = [0x00u8, 0x03, 0x02, b'h', b'2'];
        assert!(hello.windows(5).any(|w| w == want.as_slice()));
    }

    #[test]
    fn server_alpn_mismatch_only_warns() {
        // 不 panic 即可：服务端回了一个我们没 offer 的协议时只告警。
        let mut body = Vec::new();
        put_u16(0x0010, &mut body); // ext type ALPN
        let mut proto = Vec::new();
        proto.push(2u8);
        proto.extend_from_slice(b"h3");
        let mut d = Vec::new();
        put_u16(proto.len() as u16, &mut d);
        d.extend_from_slice(&proto);
        put_u16(d.len() as u16, &mut body);
        body.extend_from_slice(&d);

        let mut ee = Vec::new();
        put_u16(body.len() as u16, &mut ee);
        ee.extend_from_slice(&body);
        check_server_alpn(&ee, &["h2".to_string()]);
    }

    #[test]
    fn certificate_verify_scheme_mapping() {
        assert!(signature_scheme(0x0403).is_ok());
        assert!(signature_scheme(0x0804).is_ok());
        assert!(signature_scheme(0x0807).is_ok());
        // MD5 / SHA1 时代的方案不该被接受
        assert!(signature_scheme(0x0101).is_err());
    }
}
