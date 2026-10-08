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

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
    let mut sum = pseudo_sum_v4(src, dst, 6, tcp.len());
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
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
    let mut sum = pseudo_sum_v4(src, dst, 6, tcp.len());
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    let tcp_ok = fold_checksum(sum) == 0;
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
    let mut sum = pseudo_sum_v6(src, dst, 6, tcp_len);
    let tcp = &pkt[tcp_off..];
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
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
    let mut sum = pseudo_sum_v4(src, dst, 17, udp.len());
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
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
    let mut sum = pseudo_sum_v6(src, dst, 17, udp_len);
    let udp = &pkt[udp_off..];
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
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
    let mut sum = pseudo_sum_v6(src_ip, dst_ip, 58, icmp_len);
    let mut i = 40;
    while i + 1 < pkt.len() {
        sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        i += 2;
    }
    if i < pkt.len() {
        sum += (pkt[i] as u32) << 8;
    }
    let c = fold_checksum(sum);
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
