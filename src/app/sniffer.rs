//! Protocol sniffing: TLS ClientHello SNI, HTTP Host, QUIC Initial SNI.
//!
//! QUIC path follows the same approach as mihomo / v2ray:
//! decrypt the first Initial packet (AES-128-GCM + header protection),
//! collect CRYPTO frames, then parse TLS ClientHello for SNI.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf::{self, KeyType, Prk, HKDF_SHA256};

/// Result of sniffing the first packet(s).
#[derive(Debug, Clone, Default)]
pub struct SniffResult {
    pub domain: Option<String>,
    /// Set when the payload looks like a DNS query (only when DNS sniff is requested).
    /// Read by the DNS-hijack path in tproxy/redir inbounds (linux/android only).
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub dns: bool,
    /// UDP 路径：首个数据报被识别为 QUIC（Initial 解密成功）。
    /// 供连接面板显示流量类型 quic（读取方为 tproxy UDP，Linux/Android）。
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub quic: bool,
}

/// Sniff the beginning of a TCP stream buffer.
///
/// `sniff` enables protocol domain sniffing (TLS SNI / HTTP Host), controlled by the
/// top-level `sniff` config. `dns` enables DNS-query detection (TCP length-prefixed),
/// controlled by `dns.route-hijack` — it runs regardless of `sniff`.
pub fn sniff_tcp_ex(buf: &[u8], sniff: bool, dns: bool) -> SniffResult {
    if dns && is_dns_stream(buf) {
        return SniffResult { dns: true, ..SniffResult::default() };
    }
    if !sniff {
        return SniffResult::default();
    }
    if let Some(sni) = sniff_tls_sni(buf) {
        return SniffResult { domain: Some(sni), ..SniffResult::default() };
    }
    if let Some(host) = sniff_http_host(buf) {
        return SniffResult { domain: Some(host), ..SniffResult::default() };
    }
    SniffResult::default()
}

/// Sniff a UDP datagram (QUIC Initial SNI).
///
/// `sniff` enables QUIC domain sniffing, controlled by the top-level `sniff` config.
/// `dns` enables DNS-query detection, controlled by `dns.route-hijack` — it runs
/// regardless of `sniff`.
pub fn sniff_udp_ex(buf: &[u8], sniff: bool, dns: bool) -> SniffResult {
    if dns && is_dns_packet(buf) {
        return SniffResult { dns: true, ..SniffResult::default() };
    }
    if !sniff {
        return SniffResult::default();
    }
    if let Some(sni) = sniff_quic(buf) {
        return SniffResult { domain: Some(sni), quic: true, ..SniffResult::default() };
    }
    SniffResult::default()
}

/// UDP DNS query: QR=0, QDCOUNT>0, ANCOUNT=0, NSCOUNT=0. Same checks as sing-box.
pub fn is_dns_packet(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        return false;
    }
    if packet[2] & 0x80 != 0 {
        return false;
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]);
    if qd == 0 {
        return false;
    }
    let an = u16::from_be_bytes([packet[6], packet[7]]);
    let ns = u16::from_be_bytes([packet[8], packet[9]]);
    an == 0 && ns == 0
}

/// TCP DNS: 2-byte length prefix + DNS query.
pub fn is_dns_stream(buf: &[u8]) -> bool {
    if buf.len() < 14 {
        return false;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len < 12 || 2 + len > buf.len() {
        return false;
    }
    is_dns_packet(&buf[2..2 + len])
}

/// TLS ClientHello SNI from a TLS *record* (byte0 == 0x16).
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 || data[0] != 0x16 {
        return None;
    }
    let hs = data[5];
    if hs != 0x01 {
        return None;
    }
    // Record header 5 bytes; handshake starts at 5.
    sniff_client_hello_sni(&data[5..])
}

/// Parse SNI from a raw TLS handshake message starting with type 0x01 (ClientHello).
/// Used both for TCP TLS records and for QUIC CRYPTO stream payload.
fn sniff_client_hello_sni(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let body_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    let hello_end = (4 + body_len).min(data.len());
    if hello_end < 4 + 2 + 32 + 1 {
        return None;
    }
    // skip: type(1)+len(3) + legacy_version(2) + random(32)
    let mut i = 4 + 2 + 32;
    if i >= hello_end {
        return None;
    }
    let sid_len = data[i] as usize;
    i += 1 + sid_len;
    if i + 2 > hello_end {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2 + cs_len;
    if i + 1 > hello_end {
        return None;
    }
    let comp_len = data[i] as usize;
    i += 1 + comp_len;
    if i + 2 > hello_end {
        return None;
    }
    let ext_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let end = (i + ext_len).min(hello_end);
    while i + 4 <= end {
        let etype = u16::from_be_bytes([data[i], data[i + 1]]);
        let elen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + elen > end {
            break;
        }
        if etype == 0x0000 {
            // server_name extension
            if elen < 5 {
                break;
            }
            // list_len(2) + name_type(1) + name_len(2) + name
            let name_type = data[i + 2];
            if name_type != 0 {
                break;
            }
            let nlen = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
            if 5 + nlen > elen {
                break;
            }
            let name = &data[i + 5..i + 5 + nlen];
            if let Ok(s) = std::str::from_utf8(name) {
                return Some(s.to_lowercase());
            }
            break;
        }
        i += elen;
    }
    None
}

fn sniff_http_host(data: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(data).ok()?;
    let looks_http = s.starts_with("GET ")
        || s.starts_with("POST ")
        || s.starts_with("HEAD ")
        || s.starts_with("PUT ")
        || s.starts_with("CONNECT ")
        || s.starts_with("OPTIONS ")
        || s.starts_with("HTTP/");
    if !looks_http && !s.contains("Host:") && !s.contains("host:") {
        return None;
    }
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let host = rest.trim();
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Some(host.to_lowercase());
            }
        }
    }
    None
}

// ─── QUIC Initial sniffing ───────────────────────────────────────────────────
// Reference: mihomo component/sniffer/quic_sniffer.go (v2ray-derived).

struct QuicVersion {
    ver: u32,
    type_initial: u8,
    type_retry: u8,
    initial_salt: &'static [u8],
    /// HKDF label prefix: "quic" or "quicv2"
    label_prefix: &'static str,
}

const QUIC_DRAFT29: QuicVersion = QuicVersion {
    ver: 0xff00001d,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: &[
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    label_prefix: "quic",
};

const QUIC_V1: QuicVersion = QuicVersion {
    ver: 0x00000001,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    label_prefix: "quic",
};

const QUIC_V2: QuicVersion = QuicVersion {
    ver: 0x6b3343cf,
    type_initial: 0b01,
    type_retry: 0b00,
    initial_salt: &[
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    label_prefix: "quicv2",
};

const QUIC_VERSIONS: &[QuicVersion] = &[QUIC_DRAFT29, QUIC_V1, QUIC_V2];

const FRAME_PADDING: u8 = 0x00;
const FRAME_PING: u8 = 0x01;
const FRAME_ACK: u8 = 0x02;
const FRAME_ACK_ECN: u8 = 0x03;
const FRAME_CRYPTO: u8 = 0x06;
const FRAME_CONNECTION_CLOSE: u8 = 0x1c;

/// Extract SNI from a UDP datagram that may contain coalesced QUIC packets.
/// Only inspects Initial packets (single-datagram; no multi-packet reassembly).
pub fn sniff_quic(datagram: &[u8]) -> Option<String> {
    let mut b = datagram;
    let mut first = true;
    while !b.is_empty() {
        match read_one_quic_packet(b, !first) {
            Ok((_, Some(sni))) => return Some(sni),
            Ok((consumed, None)) => {
                if consumed == 0 || consumed > b.len() {
                    break;
                }
                b = &b[consumed..];
                first = false;
            }
            Err(()) => break,
        }
    }
    None
}

fn read_one_quic_packet(b: &[u8], coalesced: bool) -> Result<(usize, Option<String>), ()> {
    if b.is_empty() {
        return Err(());
    }
    let type_byte = b[0];
    // Short header → only valid after a long-header packet in the same datagram.
    if type_byte & 0x80 == 0 {
        if coalesced {
            return Ok((b.len(), None));
        }
        return Err(());
    }
    // Fixed bit must be 1 for QUIC long header.
    if type_byte & 0x40 == 0 {
        return Err(());
    }
    if b.len() < 6 {
        return Err(());
    }
    let ver = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    let s = QUIC_VERSIONS.iter().find(|v| v.ver == ver).ok_or(())?;

    let mut i = 5;
    // Destination Connection ID
    let dcid_len = b[i] as usize;
    i += 1;
    if dcid_len == 0 || i + dcid_len > b.len() {
        return Err(());
    }
    let dcid = &b[i..i + dcid_len];
    i += dcid_len;

    // Source Connection ID
    if i >= b.len() {
        return Err(());
    }
    let scid_len = b[i] as usize;
    i += 1;
    if i + scid_len > b.len() {
        return Err(());
    }
    i += scid_len;

    let packet_type = (type_byte & 0x30) >> 4;
    if packet_type == s.type_retry {
        // Retry has no Length field — consumes rest of datagram.
        return Ok((b.len(), None));
    }

    if packet_type == s.type_initial {
        // Token length (varint) + token
        let (token_len, n) = read_varint(&b[i..]).ok_or(())?;
        i += n;
        if token_len as usize > b.len().saturating_sub(i) {
            return Err(());
        }
        i += token_len as usize;
    }

    let (packet_len, n) = read_varint(&b[i..]).ok_or(())?;
    i += n;
    let hdr_len = i;
    if packet_len as usize > b.len().saturating_sub(hdr_len) {
        return Err(());
    }
    let packet_end = hdr_len + packet_len as usize;

    if packet_type != s.type_initial {
        // Skip 0-RTT / Handshake at declared boundary.
        return Ok((packet_end, None));
    }

    let decrypted = decrypt_quic_initial(b, hdr_len, packet_end, dcid, s)?;
    let crypto = collect_crypto_frames(&decrypted)?;
    let sni = sniff_client_hello_sni(&crypto);
    Ok((packet_end, sni))
}

struct QuicLabels {
    hp: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

fn expand_labels(dcid: &[u8], s: &QuicVersion) -> Option<QuicLabels> {
    // initial_secret = HKDF-Extract(salt, dcid)
    let salt = hkdf::Salt::new(HKDF_SHA256, s.initial_salt);
    let prk = salt.extract(dcid);
    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", _, 32)
    let client_secret = hkdf_expand_label(&prk, "client in", 32)?;
    let client_prk = Prk::new_less_safe(HKDF_SHA256, &client_secret);

    let lp = s.label_prefix;
    let hp = hkdf_expand_label(&client_prk, &format!("{lp} hp"), 16)?;
    let key = hkdf_expand_label(&client_prk, &format!("{lp} key"), 16)?;
    let iv = hkdf_expand_label(&client_prk, &format!("{lp} iv"), 12)?;

    let mut labels = QuicLabels {
        hp: [0u8; 16],
        key: [0u8; 16],
        iv: [0u8; 12],
    };
    labels.hp.copy_from_slice(&hp);
    labels.key.copy_from_slice(&key);
    labels.iv.copy_from_slice(&iv);
    Some(labels)
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
fn hkdf_expand_label(prk: &Prk, label: &str, length: usize) -> Option<Vec<u8>> {
    // struct {
    //   uint16 length = Length;
    //   opaque label<7..255> = "tls13 " + Label;
    //   opaque context<0..255> = Context;
    // } HkdfLabel;
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context

    struct Len(usize);
    impl KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let info_ref = [info.as_slice()];
    let okm = prk.expand(&info_ref, Len(length)).ok()?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).ok()?;
    Some(out)
}

fn decrypt_quic_initial(
    b: &[u8],
    hdr_len: usize,
    packet_end: usize,
    dcid: &[u8],
    s: &QuicVersion,
) -> Result<Vec<u8>, ()> {
    let labels = expand_labels(dcid, s).ok_or(())?;

    // Need sample of 16 bytes starting at hdr_len+4 (pn offset assumes max 4-byte PN).
    if hdr_len + 4 + 16 > packet_end {
        return Err(());
    }

    // Header protection: AES-ECB encrypt sample → mask
    let sample = &b[hdr_len + 4..hdr_len + 4 + 16];
    let mask = aes_ecb_encrypt(&labels.hp, sample)?;

    let mut first_byte = b[0];
    // Long headers: only low 4 bits are protected.
    first_byte ^= mask[0] & 0x0f;
    let pn_len = ((first_byte & 0x03) + 1) as usize; // 1..=4
    let ext_hdr_len = hdr_len + pn_len;
    if ext_hdr_len > packet_end {
        return Err(());
    }

    // Reconstruct unprotected header for AEAD AAD.
    let mut ext_hdr = b[..ext_hdr_len].to_vec();
    ext_hdr[0] = first_byte;
    for i in 0..pn_len {
        ext_hdr[hdr_len + i] ^= mask[1 + i];
    }

    // Packet number (for nonce); we only need the truncated value for first packet (largest=-1).
    let mut truncated_pn: i64 = 0;
    for i in 0..pn_len {
        truncated_pn = (truncated_pn << 8) | (ext_hdr[hdr_len + i] as i64);
    }
    let decoded_pn = decode_packet_number(pn_len, -1, truncated_pn);

    // Nonce = IV XOR packet_number (last 8 bytes)
    let mut nonce_bytes = labels.iv;
    for i in 0..8 {
        nonce_bytes[12 - 1 - i] ^= ((decoded_pn as u64) >> (8 * i)) as u8;
    }

    let ciphertext = &b[ext_hdr_len..packet_end];
    let unbound = UnboundKey::new(&AES_128_GCM, &labels.key).map_err(|_| ())?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| ())?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(&ext_hdr), &mut in_out)
        .map_err(|_| ())?;
    Ok(plaintext.to_vec())
}

fn aes_ecb_encrypt(key: &[u8; 16], block: &[u8]) -> Result<[u8; 16], ()> {
    Ok(aes128_encrypt_block(key, block))
}

// Minimal AES-128 single-block encrypt (ECB) for header protection sample.
fn aes128_encrypt_block(key: &[u8; 16], input: &[u8]) -> [u8; 16] {
    let rk = aes128_key_expansion(key);
    let mut state = [0u8; 16];
    state.copy_from_slice(&input[..16]);
    add_round_key(&mut state, &rk[0..16]);
    for round in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &rk[round * 16..(round + 1) * 16]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &rk[160..176]);
    state
}

fn aes128_key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key);
    let rcon: [u8; 11] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];
    let mut i = 16;
    let mut rcon_i = 1;
    while i < 176 {
        let mut t = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
        if i % 16 == 0 {
            let tmp = t[0];
            t[0] = t[1];
            t[1] = t[2];
            t[2] = t[3];
            t[3] = tmp;
            for b in &mut t {
                *b = SBOX[*b as usize];
            }
            t[0] ^= rcon[rcon_i];
            rcon_i += 1;
        }
        for j in 0..4 {
            w[i + j] = w[i + j - 16] ^ t[j];
        }
        i += 4;
    }
    w
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        state[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn decode_packet_number(length: usize, largest: i64, truncated: i64) -> i64 {
    let expected = largest + 1;
    let window = 1i64 << (length * 8);
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected - half && candidate < (1i64 << 62) - window {
        return candidate + window;
    }
    if candidate > expected + half && candidate >= window {
        return candidate - window;
    }
    candidate
}

fn collect_crypto_frames(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        while i < data.len() && data[i] == FRAME_PADDING {
            i += 1;
        }
        if i >= data.len() {
            break;
        }
        let ft = data[i];
        i += 1;
        match ft {
            FRAME_PADDING => {}
            FRAME_PING => {}
            FRAME_ACK | FRAME_ACK_ECN => {
                let (_, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (_, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (range_count, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (_, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                for _ in 0..range_count {
                    let (_, n) = read_varint(&data[i..]).ok_or(())?;
                    i += n;
                    let (_, n) = read_varint(&data[i..]).ok_or(())?;
                    i += n;
                }
                if ft == FRAME_ACK_ECN {
                    for _ in 0..3 {
                        let (_, n) = read_varint(&data[i..]).ok_or(())?;
                        i += n;
                    }
                }
            }
            FRAME_CRYPTO => {
                let (offset, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (length, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                if i + length as usize > data.len() {
                    return Err(());
                }
                chunks.push((offset, data[i..i + length as usize].to_vec()));
                i += length as usize;
            }
            FRAME_CONNECTION_CLOSE => {
                let (_, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (_, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                let (rlen, n) = read_varint(&data[i..]).ok_or(())?;
                i += n;
                i += rlen as usize;
            }
            _ => return Err(()),
        }
    }

    if chunks.is_empty() {
        return Err(());
    }
    chunks.sort_by_key(|(o, _)| *o);
    let mut out = Vec::new();
    let mut expect = 0u64;
    for (off, data) in chunks {
        if off > expect {
            break;
        }
        if off + data.len() as u64 <= expect {
            continue;
        }
        let skip = (expect - off) as usize;
        out.extend_from_slice(&data[skip..]);
        expect = off + data.len() as u64;
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    if b.is_empty() {
        return None;
    }
    let prefix = b[0] >> 6;
    let len = 1usize << prefix;
    if b.len() < len {
        return None;
    }
    let mut v = (b[0] & 0x3f) as u64;
    for &byte in b.iter().take(len).skip(1) {
        v = (v << 8) | (byte as u64);
    }
    Some((v, len))
}
