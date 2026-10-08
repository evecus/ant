//! IP/TCP/UDP checksums, MSS clamp, RST builders, UDP reply helpers.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const TCP_OPT_EOL: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_MSS_LEN: u8 = 4;
const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;

/// Fold a 32/64-bit one's-complement accumulator down to 16 bits
/// (no final complement — callers apply `!` where the checksum value is needed).
#[inline]
fn fold_sum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// One's-complement sum of `data` (big-endian 16-bit words, odd trailing byte
/// treated as high byte) added into `sum`.
///
/// 32-bit words are combined and the carries folded at the end — the classic
/// deferred-carry trick; identical result to per-word 16-bit accumulation but
/// ~4x fewer adds. u64 accumulator defers folding across payloads up to 64 KiB.
#[inline]
fn ones_complement_sum(mut sum: u64, data: &[u8]) -> u64 {
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        sum += u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        sum += u64::from(u32::from_be_bytes([c[4], c[5], c[6], c[7]]));
    }
    let r = chunks.remainder();
    let mut i = 0;
    while i + 1 < r.len() {
        sum += u16::from_be_bytes([r[i], r[i + 1]]) as u64;
        i += 2;
    }
    if i < r.len() {
        sum += u64::from(r[i]) << 8;
    }
    sum
}

/// RFC 1624 incremental checksum update for one replaced 16-bit word:
/// HC' = ~(~HC + ~m + m').
///
/// Used by the system-stack TCP NAT: rewriting IP src/dst + TCP ports touches
/// only a few words, so an O(1) update replaces the full O(payload) rescan on
/// every forwarded packet (the dominant CPU cost on Linux).
#[inline]
fn csum_update_word(hc: u16, old_w: u16, new_w: u16) -> u16 {
    !fold_sum(u64::from(!hc) + u64::from(!old_w) + u64::from(new_w))
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    !fold_sum(ones_complement_sum(0, data))
}

pub fn recompute_ipv4_checksum(pkt: &mut [u8]) {
    if pkt.len() < 20 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    pkt[10] = 0;
    pkt[11] = 0;
    let c = internet_checksum(&pkt[..ihl]);
    pkt[10] = (c >> 8) as u8;
    pkt[11] = (c & 0xff) as u8;
}

/// Incremental IPv4 header checksum update after src/dst rewrite (RFC 1624).
/// `old_*` are the pre-rewrite addresses; new values are read from the packet.
pub fn nat_update_ip_checksum_v4(pkt: &mut [u8], old_src: [u8; 4], old_dst: [u8; 4]) {
    if pkt.len() < 20 {
        return;
    }
    let mut hc = u16::from_be_bytes([pkt[10], pkt[11]]);
    for i in [0usize, 2] {
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_src[i], old_src[i + 1]]),
            u16::from_be_bytes([pkt[12 + i], pkt[13 + i]]),
        );
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_dst[i], old_dst[i + 1]]),
            u16::from_be_bytes([pkt[16 + i], pkt[17 + i]]),
        );
    }
    pkt[10] = (hc >> 8) as u8;
    pkt[11] = (hc & 0xff) as u8;
}

/// Incremental TCP checksum update after NAT rewrite of IP src/dst and TCP
/// src/dst ports (RFC 1624). The pseudo-header contains the IP addresses, so
/// those words are folded into the TCP checksum too. Call AFTER the fields
/// have been overwritten; `old_*` are the pre-rewrite values.
pub fn nat_update_tcp_checksum_v4(
    pkt: &mut [u8],
    ihl: usize,
    old_src: [u8; 4],
    old_dst: [u8; 4],
    old_sport: u16,
    old_dport: u16,
) {
    if pkt.len() < ihl + 20 {
        return;
    }
    let tcp = ihl;
    let mut hc = u16::from_be_bytes([pkt[tcp + 16], pkt[tcp + 17]]);
    for i in [0usize, 2] {
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_src[i], old_src[i + 1]]),
            u16::from_be_bytes([pkt[12 + i], pkt[13 + i]]),
        );
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_dst[i], old_dst[i + 1]]),
            u16::from_be_bytes([pkt[16 + i], pkt[17 + i]]),
        );
    }
    hc = csum_update_word(hc, old_sport, u16::from_be_bytes([pkt[tcp], pkt[tcp + 1]]));
    hc = csum_update_word(
        hc,
        old_dport,
        u16::from_be_bytes([pkt[tcp + 2], pkt[tcp + 3]]),
    );
    pkt[tcp + 16] = (hc >> 8) as u8;
    pkt[tcp + 17] = (hc & 0xff) as u8;
}

/// Incremental TCP checksum update after NAT rewrite of IPv6 src/dst and TCP
/// ports (pseudo-header includes the 32-byte address pair). Call AFTER the
/// fields have been overwritten; `old_*` are the pre-rewrite values.
pub fn nat_update_tcp_checksum_v6(
    pkt: &mut [u8],
    tcp_off: usize,
    old_src: [u8; 16],
    old_dst: [u8; 16],
    old_sport: u16,
    old_dport: u16,
) {
    if pkt.len() < tcp_off + 20 || pkt.len() < 40 {
        return;
    }
    let mut hc = u16::from_be_bytes([pkt[tcp_off + 16], pkt[tcp_off + 17]]);
    for i in (0..16).step_by(2) {
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_src[i], old_src[i + 1]]),
            u16::from_be_bytes([pkt[8 + i], pkt[9 + i]]),
        );
        hc = csum_update_word(
            hc,
            u16::from_be_bytes([old_dst[i], old_dst[i + 1]]),
            u16::from_be_bytes([pkt[24 + i], pkt[25 + i]]),
        );
    }
    hc = csum_update_word(
        hc,
        old_sport,
        u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]),
    );
    hc = csum_update_word(
        hc,
        old_dport,
        u16::from_be_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]),
    );
    pkt[tcp_off + 16] = (hc >> 8) as u8;
    pkt[tcp_off + 17] = (hc & 0xff) as u8;
}

fn pseudo_sum_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += proto as u32;
    sum += len as u32;
    sum
}

fn pseudo_sum_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, len: usize) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    for chunk in s.chunks(2).chain(d.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (len as u32) >> 16;
    sum += (len as u32) & 0xffff;
    sum += proto as u32;
    sum
}

pub fn recompute_tcp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 20 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let tcp = &mut pkt[ihl..];
    tcp[16] = 0;
    tcp[17] = 0;
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v4(src, dst, 6, tcp.len())),
        tcp,
    );
    let c = !fold_sum(sum);
    tcp[16] = (c >> 8) as u8;
    tcp[17] = (c & 0xff) as u8;
}

/// Diagnostic: verify IPv4 header + TCP checksum of a finished packet.
pub fn verify_checksums_v4(pkt: &[u8], ihl: usize) -> (bool, bool) {
    if pkt.len() < ihl + 20 {
        return (false, false);
    }
    let ip_ok = internet_checksum(&pkt[..ihl]) == 0;
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let tcp = &pkt[ihl..];
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v4(src, dst, 6, tcp.len())),
        tcp,
    );
    // Valid packet: sum including the stored checksum field folds to 0xffff.
    let tcp_ok = fold_sum(sum) == 0xffff;
    (ip_ok, tcp_ok)
}

pub fn recompute_tcp_checksum_v6(pkt: &mut [u8], tcp_off: usize) {
    if pkt.len() < tcp_off + 20 || pkt.len() < 40 {
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let tcp_len = pkt.len() - tcp_off;
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let tcp = &pkt[tcp_off..];
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v6(src, dst, 6, tcp_len)),
        tcp,
    );
    let c = !fold_sum(sum);
    pkt[tcp_off + 16] = (c >> 8) as u8;
    pkt[tcp_off + 17] = (c & 0xff) as u8;
}

pub fn recompute_udp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 8 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let udp = &mut pkt[ihl..];
    udp[6] = 0;
    udp[7] = 0;
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v4(src, dst, 17, udp.len())),
        udp,
    );
    let c = !fold_sum(sum);
    let c = if c == 0 { 0xffff } else { c };
    udp[6] = (c >> 8) as u8;
    udp[7] = (c & 0xff) as u8;
}

pub fn recompute_udp_checksum_v6(pkt: &mut [u8], udp_off: usize) {
    if pkt.len() < udp_off + 8 || pkt.len() < 40 {
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let udp_len = pkt.len() - udp_off;
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let udp = &pkt[udp_off..];
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v6(src, dst, 17, udp_len)),
        udp,
    );
    let c = !fold_sum(sum);
    let c = if c == 0 { 0xffff } else { c };
    pkt[udp_off + 6] = (c >> 8) as u8;
    pkt[udp_off + 7] = (c & 0xff) as u8;
}

pub fn clamp_tcp_mss(pkt: &mut [u8], tcp_off: usize, max_mss: u16) -> bool {
    if pkt.len() < tcp_off + TCP_MIN_HEADER_LEN + 4 {
        return false;
    }
    let data_offset = (pkt[tcp_off + 12] >> 4) as usize * 4;
    if data_offset < TCP_MIN_HEADER_LEN || tcp_off + data_offset > pkt.len() {
        return false;
    }
    if pkt[tcp_off + 13] & TCP_FLAG_SYN == 0 {
        return false;
    }
    let options = &mut pkt[tcp_off + TCP_MIN_HEADER_LEN..tcp_off + data_offset];
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            TCP_OPT_EOL => return false,
            TCP_OPT_NOP => {
                i += 1;
            }
            TCP_OPT_MSS => {
                if i + 4 > options.len() || options[i + 1] != TCP_OPT_MSS_LEN {
                    return false;
                }
                let current = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                if current <= max_mss {
                    return false;
                }
                options[i + 2] = (max_mss >> 8) as u8;
                options[i + 3] = (max_mss & 0xff) as u8;
                // MSS word changed: incremental TCP checksum update (RFC 1624)
                // instead of a full payload rescan. Clamping only happens on
                // SYN packets, but callers NAT-rewrite with incremental updates
                // too — keeping the whole path O(1) per packet.
                if pkt.len() >= tcp_off + 20 {
                    let hc = u16::from_be_bytes([pkt[tcp_off + 16], pkt[tcp_off + 17]]);
                    let hc = csum_update_word(hc, current, max_mss);
                    pkt[tcp_off + 16] = (hc >> 8) as u8;
                    pkt[tcp_off + 17] = (hc & 0xff) as u8;
                }
                return true;
            }
            _ => {
                if i + 2 > options.len() {
                    return false;
                }
                let opt_len = options[i + 1] as usize;
                if opt_len < 2 || i + opt_len > options.len() {
                    return false;
                }
                i += opt_len;
            }
        }
    }
    false
}

pub fn compute_effective_mss(_tcp_mss: Option<u16>, mtu: u32) -> Option<u16> {
    if mtu > 60 {
        Some((mtu - 60) as u16)
    } else {
        None
    }
}

pub fn build_tcp_rst_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ack_seq: u32,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack_seq.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = TCP_FLAG_RST | TCP_FLAG_ACK;
    recompute_tcp_checksum_v4(&mut pkt, 20);
    recompute_ipv4_checksum(&mut pkt);
    pkt
}

pub fn build_tcp_rst_v6(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    ack_seq: u32,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
    pkt[6] = 6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[48..52].copy_from_slice(&ack_seq.to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = TCP_FLAG_RST | TCP_FLAG_ACK;
    recompute_tcp_checksum_v6(&mut pkt, 40);
    pkt
}

#[cfg(not(unix))]
pub fn build_icmp_echo_reply_v4(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 28 {
        return None;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if ihl < 20 || raw.len() < ihl + 8 {
        return None;
    }
    if raw[9] != 1 || raw[ihl] != 8 {
        return None;
    }
    let mut pkt = raw.to_vec();
    let src = pkt[12..16].to_vec();
    let dst = pkt[16..20].to_vec();
    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);
    pkt[ihl] = 0;
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let c = internet_checksum(&pkt[ihl..]);
    pkt[ihl + 2] = (c >> 8) as u8;
    pkt[ihl + 3] = (c & 0xff) as u8;
    recompute_ipv4_checksum(&mut pkt);
    Some(pkt)
}

#[cfg(not(unix))]
pub fn build_icmp_echo_reply_v6(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 48 || raw[6] != 58 || raw[40] != 128 {
        return None;
    }
    let mut pkt = raw.to_vec();
    let src = pkt[8..24].to_vec();
    let dst = pkt[24..40].to_vec();
    pkt[8..24].copy_from_slice(&dst);
    pkt[24..40].copy_from_slice(&src);
    pkt[40] = 129;
    pkt[42] = 0;
    pkt[43] = 0;
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
    let icmp_len = pkt.len() - 40;
    let sum = ones_complement_sum(
        u64::from(pseudo_sum_v6(src_ip, dst_ip, 58, icmp_len)),
        &pkt[40..],
    );
    let c = !fold_sum(sum);
    pkt[42] = (c >> 8) as u8;
    pkt[43] = (c & 0xff) as u8;
    Some(pkt)
}

pub fn build_udp_reply_v4(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total = (20 + udp_len as usize) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.push(0x45);
    pkt.push(0);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    recompute_udp_checksum_v4(&mut pkt, 20);
    recompute_ipv4_checksum(&mut pkt);
    pkt
}

pub fn build_udp_reply_v6(src: SocketAddrV6, dst: SocketAddrV6, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(40 + udp_len as usize);
    pkt.push(0x60);
    pkt.extend_from_slice(&[0, 0, 0]);
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.push(17);
    pkt.push(64);
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    recompute_udp_checksum_v6(&mut pkt, 40);
    pkt
}

pub fn build_udp_reply(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => Some(build_udp_reply_v4(s, d, payload)),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => Some(build_udp_reply_v6(s, d, payload)),
        _ => None,
    }
}

pub fn build_udp_reply_with_template(
    template: &[u8],
    reply_src: SocketAddr,
    reply_dst: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.is_empty() {
        return build_udp_reply(reply_src, reply_dst, payload);
    }
    match (reply_src, reply_dst, template[0] >> 4) {
        (SocketAddr::V4(s), SocketAddr::V4(d), 4) => {
            build_udp_reply_v4_template(template, s, d, payload)
        }
        (SocketAddr::V6(s), SocketAddr::V6(d), 6) => {
            build_udp_reply_v6_template(template, s, d, payload)
        }
        _ => build_udp_reply(reply_src, reply_dst, payload),
    }
}

fn build_udp_reply_v4_template(
    template: &[u8],
    reply_src: SocketAddrV4,
    reply_dst: SocketAddrV4,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.len() < 28 {
        return None;
    }
    let ihl = ((template[0] & 0x0f) as usize) * 4;
    if ihl < 20 || template.len() < ihl + 8 {
        return None;
    }
    let udp_len = (8 + payload.len()) as u16;
    let total = (ihl as u16) + udp_len;
    let mut pkt = template[..ihl + 8].to_vec();
    pkt.extend_from_slice(payload);
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[12..16].copy_from_slice(&reply_src.ip().octets());
    pkt[16..20].copy_from_slice(&reply_dst.ip().octets());
    pkt[ihl..ihl + 2].copy_from_slice(&reply_src.port().to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&reply_dst.port().to_be_bytes());
    pkt[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
    recompute_udp_checksum_v4(&mut pkt, ihl);
    recompute_ipv4_checksum(&mut pkt);
    Some(pkt)
}

fn build_udp_reply_v6_template(
    template: &[u8],
    reply_src: SocketAddrV6,
    reply_dst: SocketAddrV6,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.len() < 48 {
        return None;
    }
    let udp_len = (8 + payload.len()) as u16;
    let mut pkt = template[..48].to_vec();
    pkt.extend_from_slice(payload);
    pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[8..24].copy_from_slice(&reply_src.ip().octets());
    pkt[24..40].copy_from_slice(&reply_dst.ip().octets());
    pkt[40..42].copy_from_slice(&reply_src.port().to_be_bytes());
    pkt[42..44].copy_from_slice(&reply_dst.port().to_be_bytes());
    pkt[44..46].copy_from_slice(&udp_len.to_be_bytes());
    recompute_udp_checksum_v6(&mut pkt, 40);
    Some(pkt)
}

pub fn is_global_unicast_v4(addr: Ipv4Addr) -> bool {
    if addr.is_unspecified() || addr.is_broadcast() {
        return false;
    }
    let o = addr.octets();
    if o[0] >= 224 && o[0] < 240 {
        return false;
    }
    true
}

pub fn is_global_unicast_v6(addr: Ipv6Addr) -> bool {
    if addr.is_unspecified() || addr.is_loopback() {
        return false;
    }
    let seg0 = addr.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    if (seg0 & 0xff00) == 0xff00 {
        return false;
    }
    true
}

pub fn broadcast_addr_v4(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len.min(32))) - 1)
    };
    let net = u32::from(network) & mask;
    Ipv4Addr::from(net | !mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift PRNG — deterministic, no deps.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    /// Build an IPv4 TCP packet with a pseudo-random payload and valid checksums.
    fn build_tcp4(rng: &mut Rng, payload_len: usize) -> Vec<u8> {
        let ihl = 20;
        let total = ihl + 20 + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, (rng.next() % 256) as u8, 2]);
        pkt[16..20].copy_from_slice(&[93, 46, (rng.next() % 256) as u8, 8]);
        pkt[ihl..ihl + 2].copy_from_slice(&((rng.next() % 65536) as u16).to_be_bytes());
        pkt[ihl + 2..ihl + 4].copy_from_slice(&(443u16).to_be_bytes());
        for b in pkt[ihl + 20..].iter_mut() {
            *b = (rng.next() % 256) as u8;
        }
        recompute_tcp_checksum_v4(&mut pkt, ihl);
        recompute_ipv4_checksum(&mut pkt);
        pkt
    }

    /// Build an IPv6 TCP packet with valid checksum.
    fn build_tcp6(rng: &mut Rng, payload_len: usize) -> Vec<u8> {
        let total = 40 + 20 + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        pkt[6] = 6;
        for (i, b) in pkt[8..24].iter_mut().enumerate() {
            *b = (rng.next() % 256) as u8;
            let _ = i;
        }
        for (i, b) in pkt[24..40].iter_mut().enumerate() {
            *b = (rng.next() % 256) as u8;
            let _ = i;
        }
        pkt[40..42].copy_from_slice(&((rng.next() % 65536) as u16).to_be_bytes());
        pkt[42..44].copy_from_slice(&(8080u16).to_be_bytes());
        for b in pkt[60..].iter_mut() {
            *b = (rng.next() % 256) as u8;
        }
        recompute_tcp_checksum_v6(&mut pkt, 40);
        pkt
    }

    fn tcp_csum_ok(pkt: &[u8], off: usize, is_v6: bool) -> bool {
        let (src, dst): (Vec<u8>, Vec<u8>) = if is_v6 {
            (pkt[8..24].to_vec(), pkt[24..40].to_vec())
        } else {
            (pkt[12..16].to_vec(), pkt[16..20].to_vec())
        };
        let l4 = &pkt[off..];
        let mut sum = if is_v6 {
            u64::from(pseudo_sum_v6(
                Ipv6Addr::from(<[u8; 16]>::try_from(&src[..]).unwrap()),
                Ipv6Addr::from(<[u8; 16]>::try_from(&dst[..]).unwrap()),
                6,
                l4.len(),
            ))
        } else {
            u64::from(pseudo_sum_v4(
                Ipv4Addr::from(<[u8; 4]>::try_from(&src[..]).unwrap()),
                Ipv4Addr::from(<[u8; 4]>::try_from(&dst[..]).unwrap()),
                6,
                l4.len(),
            ))
        };
        sum = ones_complement_sum(sum, l4);
        fold_sum(sum) == 0xffff
    }

    #[test]
    fn incremental_nat_rewrite_matches_full_recompute_v4() {
        let mut rng = Rng(0x1234_5678);
        for payload_len in [0usize, 1, 7, 8, 100, 1460, 5321] {
            let old_src = Ipv4Addr::new(192, 168, 1, 55);
            let old_dst = Ipv4Addr::new(1, 2, 3, 4);
            let (old_sp, old_dp) = (54321u16, 9999u16);
            let new_src = Ipv4Addr::new(198, 18, 0, 2);
            let new_dst = Ipv4Addr::new(8, 8, 8, 8);
            let (new_sp, new_dp) = (10123u16, 5353u16);

            // Base packet carries the OLD (pre-NAT) addresses with valid checksums.
            let mut base = build_tcp4(&mut rng, payload_len);
            base[12..16].copy_from_slice(&old_src.octets());
            base[16..20].copy_from_slice(&old_dst.octets());
            base[20..22].copy_from_slice(&old_sp.to_be_bytes());
            base[22..24].copy_from_slice(&old_dp.to_be_bytes());
            recompute_tcp_checksum_v4(&mut base, 20);
            recompute_ipv4_checksum(&mut base);

            // Reference: full recompute after in-place rewrite.
            let mut a = base.clone();
            a[12..16].copy_from_slice(&new_src.octets());
            a[16..20].copy_from_slice(&new_dst.octets());
            a[20..22].copy_from_slice(&new_sp.to_be_bytes());
            a[22..24].copy_from_slice(&new_dp.to_be_bytes());
            recompute_tcp_checksum_v4(&mut a, 20);
            recompute_ipv4_checksum(&mut a);

            // Incremental: RFC 1624 update after the same rewrite.
            let mut b = base.clone();
            b[12..16].copy_from_slice(&new_src.octets());
            b[16..20].copy_from_slice(&new_dst.octets());
            b[20..22].copy_from_slice(&new_sp.to_be_bytes());
            b[22..24].copy_from_slice(&new_dp.to_be_bytes());
            nat_update_tcp_checksum_v4(
                &mut b,
                20,
                old_src.octets(),
                old_dst.octets(),
                old_sp,
                old_dp,
            );
            nat_update_ip_checksum_v4(&mut b, old_src.octets(), old_dst.octets());

            assert_eq!(a, b, "payload_len={payload_len}");
            assert!(tcp_csum_ok(&b, 20, false));
            assert_eq!(internet_checksum(&b[..20]), 0);
        }
    }

    #[test]
    fn incremental_nat_rewrite_matches_full_recompute_v6() {
        let mut rng = Rng(0xABCD_EF01);
        for payload_len in [0usize, 1, 100, 1400] {
            let old_src = Ipv6Addr::LOCALHOST;
            let old_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
            let new_src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
            let new_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
            let (old_sp, old_dp) = (40000u16, 53u16);
            let (new_sp, new_dp) = (60123u16, 853u16);

            let mut base = build_tcp6(&mut rng, payload_len);
            base[8..24].copy_from_slice(&old_src.octets());
            base[24..40].copy_from_slice(&old_dst.octets());
            base[40..42].copy_from_slice(&old_sp.to_be_bytes());
            base[42..44].copy_from_slice(&old_dp.to_be_bytes());
            recompute_tcp_checksum_v6(&mut base, 40);

            let mut a = base.clone();
            a[8..24].copy_from_slice(&new_src.octets());
            a[24..40].copy_from_slice(&new_dst.octets());
            a[40..42].copy_from_slice(&new_sp.to_be_bytes());
            a[42..44].copy_from_slice(&new_dp.to_be_bytes());
            recompute_tcp_checksum_v6(&mut a, 40);

            let mut b = base.clone();
            b[8..24].copy_from_slice(&new_src.octets());
            b[24..40].copy_from_slice(&new_dst.octets());
            b[40..42].copy_from_slice(&new_sp.to_be_bytes());
            b[42..44].copy_from_slice(&new_dp.to_be_bytes());
            nat_update_tcp_checksum_v6(
                &mut b,
                40,
                old_src.octets(),
                old_dst.octets(),
                old_sp,
                old_dp,
            );

            assert_eq!(a, b, "payload_len={payload_len}");
            assert!(tcp_csum_ok(&b, 40, true));
        }
    }

    #[test]
    fn mss_clamp_updates_checksum_incrementally() {
        // SYN packet with MSS option 1460, clamp to 1400.
        let mut pkt = vec![0u8; 20 + 24 + 5];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((20 + 24 + 5) as u16).to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&1000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        pkt[20 + 12] = 0x60; // data offset 24
        pkt[20 + 13] = TCP_FLAG_SYN;
        pkt[20 + 16..20 + 18].copy_from_slice(&[0, 0]); // csum placeholder
        pkt[20 + 20] = TCP_OPT_MSS;
        pkt[20 + 21] = 4;
        pkt[20 + 22..20 + 24].copy_from_slice(&1460u16.to_be_bytes());
        pkt[20 + 24..].copy_from_slice(b"hello");

        // Reference: clamp with checksum zeroed then full recompute.
        let mut a = pkt.clone();
        a[20 + 22..20 + 24].copy_from_slice(&1400u16.to_be_bytes());
        recompute_tcp_checksum_v4(&mut a, 20);
        recompute_ipv4_checksum(&mut a);

        // Incremental: valid checksum first, then clamp (which updates itself).
        let mut b = pkt.clone();
        recompute_tcp_checksum_v4(&mut b, 20);
        recompute_ipv4_checksum(&mut b);
        assert!(clamp_tcp_mss(&mut b, 20, 1400));

        assert_eq!(a, b);
    }

    #[test]
    fn ones_complement_sum_matches_naive_on_odd_lengths() {
        let mut rng = Rng(0x00c0_ffee);
        for len in [0usize, 1, 2, 3, 15, 16, 17, 63, 517] {
            let data: Vec<u8> = (0..len).map(|_| (rng.next() % 256) as u8).collect();
            let fast = !fold_sum(ones_complement_sum(0, &data));
            let mut naive: u32 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                naive += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
                i += 2;
            }
            if i < data.len() {
                naive += (data[i] as u32) << 8;
            }
            while (naive >> 16) != 0 {
                naive = (naive & 0xffff) + (naive >> 16);
            }
            assert_eq!(fast, !(naive as u16), "len={len}");
        }
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;

    /// UDP reply builders must emit packets whose checksum validates
    /// (sum incl. stored field folds to 0xffff).
    #[test]
    fn udp_reply_checksums_validate() {
        for payload_len in [0usize, 1, 7, 64, 517, 1200] {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i * 37 % 251) as u8).collect();
            let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
            let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 9), 51344));
            let pkt = build_udp_reply(src, dst, &payload).unwrap();
            let sum = ones_complement_sum(
                u64::from(pseudo_sum_v4(
                    Ipv4Addr::new(8, 8, 8, 8),
                    Ipv4Addr::new(192, 168, 1, 9),
                    17,
                    pkt.len() - 20,
                )),
                &pkt[20..],
            );
            assert_eq!(fold_sum(sum), 0xffff, "v4 payload_len={payload_len}");
            assert_eq!(internet_checksum(&pkt[..20]), 0);

            let src6 = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x8888),
                53,
                0,
                0,
            ));
            let dst6 = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                51344,
                0,
                0,
            ));
            let pkt6 = build_udp_reply(src6, dst6, &payload).unwrap();
            let sum6 = ones_complement_sum(
                u64::from(pseudo_sum_v6(
                    Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x8888),
                    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                    17,
                    pkt6.len() - 40,
                )),
                &pkt6[40..],
            );
            assert_eq!(fold_sum(sum6), 0xffff, "v6 payload_len={payload_len}");
        }
    }

    /// TCP RST builders must emit valid checksums.
    #[test]
    fn tcp_rst_checksums_validate() {
        let rst = build_tcp_rst_v4(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(10, 0, 0, 5),
            443,
            54321,
            0xdead_beef,
        );
        assert_eq!(internet_checksum(&rst[..20]), 0);
        let sum = ones_complement_sum(
            u64::from(pseudo_sum_v4(
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(10, 0, 0, 5),
                6,
                20,
            )),
            &rst[20..],
        );
        assert_eq!(fold_sum(sum), 0xffff);

        let rst6 = build_tcp_rst_v6(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            54321,
            7,
        );
        let sum6 = ones_complement_sum(
            u64::from(pseudo_sum_v6(
                Ipv6Addr::LOCALHOST,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                6,
                20,
            )),
            &rst6[40..],
        );
        assert_eq!(fold_sum(sum6), 0xffff);
    }
}
