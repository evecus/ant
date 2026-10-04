#![allow(dead_code)]
use std::collections::HashMap;

// ── 常量（对齐 sing-tun tun_offload_linux.go）─────────────────────────────────

pub const VIRTIO_NET_HDR_LEN: usize = 10;
pub const GSO_MAX_SIZE: usize = 65536;
pub const IDEAL_BATCH_SIZE: usize = 128;

/// GRO 合并后的单个 IP 包长度上限。
///
/// IPv4 total length 与 IPv6 payload length 都是 u16，合并结果超出会溢出。
/// 对齐 sing-tun（其缓冲池按 65535 分配，合并前检查剩余容量）。
const MAX_COALESCED_PACKET_LEN: usize = 65535;

// virtio_net_hdr flags
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

// virtio_net_hdr gsoType
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 3;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;

// TUN offload flags (TUNSETOFFLOAD)
pub const TUN_F_CSUM: u32 = 0x01;
pub const TUN_F_TSO4: u32 = 0x02;
pub const TUN_F_TSO6: u32 = 0x04;
pub const TUN_F_USO4: u32 = 0x10;
pub const TUN_F_USO6: u32 = 0x20;

// IP/TCP/UDP 常量
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const UDP_HDR_LEN: usize = 8;
const IPV4_FLAG_MORE_FRAGMENTS: u8 = 0x20;

// ── VirtioNetHdr ──────────────────────────────────────────────────────────────

/// virtio_net_hdr 结构体（10 字节），对齐 Linux 内核 `struct virtio_net_hdr`。
///
/// 字段布局（原生字节序，但字段本身是大端编码到 wire format）：
/// - flags:      u8  (offset 0)
/// - gso_type:   u8  (offset 1)
/// - hdr_len:    u16 (offset 2, native endian)
/// - gso_size:   u16 (offset 4, native endian)
/// - csum_start: u16 (offset 6, native endian)
/// - csum_offset:u16 (offset 8, native endian)
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// 从字节切片解析（native endian，与内核 ABI 一致）。
    pub fn decode(b: &[u8]) -> std::io::Result<Self> {
        if b.len() < VIRTIO_NET_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "virtio_net_hdr too short",
            ));
        }
        // 内核以 native endian 写入 u16 字段
        #[cfg(target_endian = "little")]
        {
            Ok(VirtioNetHdr {
                flags: b[0],
                gso_type: b[1],
                hdr_len: u16::from_le_bytes([b[2], b[3]]),
                gso_size: u16::from_le_bytes([b[4], b[5]]),
                csum_start: u16::from_le_bytes([b[6], b[7]]),
                csum_offset: u16::from_le_bytes([b[8], b[9]]),
            })
        }
        #[cfg(target_endian = "big")]
        {
            Ok(VirtioNetHdr {
                flags: b[0],
                gso_type: b[1],
                hdr_len: u16::from_be_bytes([b[2], b[3]]),
                gso_size: u16::from_be_bytes([b[4], b[5]]),
                csum_start: u16::from_be_bytes([b[6], b[7]]),
                csum_offset: u16::from_be_bytes([b[8], b[9]]),
            })
        }
    }

    /// 编码到字节切片（native endian）。
    pub fn encode(&self, b: &mut [u8]) -> std::io::Result<()> {
        if b.len() < VIRTIO_NET_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "virtio_net_hdr encode buffer too short",
            ));
        }
        b[0] = self.flags;
        b[1] = self.gso_type;
        #[cfg(target_endian = "little")]
        {
            b[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
            b[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
            b[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
            b[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        }
        #[cfg(target_endian = "big")]
        {
            b[2..4].copy_from_slice(&self.hdr_len.to_be_bytes());
            b[4..6].copy_from_slice(&self.gso_size.to_be_bytes());
            b[6..8].copy_from_slice(&self.csum_start.to_be_bytes());
            b[8..10].copy_from_slice(&self.csum_offset.to_be_bytes());
        }
        Ok(())
    }

    pub fn is_gso(&self) -> bool {
        self.gso_type != VIRTIO_NET_HDR_GSO_NONE
    }

    pub fn needs_csum(&self) -> bool {
        self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0
    }
}

// ── GSOType / GsoOptions ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum GsoType {
    #[default]
    None,
    TcpV4,
    TcpV6,
    UdpL4,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GsoOptions {
    pub gso_type: GsoType,
    pub hdr_len: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub gso_size: u16,
    pub needs_csum: bool,
}

impl VirtioNetHdr {
    pub fn to_gso_options(self) -> std::io::Result<GsoOptions> {
        let gso_type = match self.gso_type {
            VIRTIO_NET_HDR_GSO_NONE => GsoType::None,
            VIRTIO_NET_HDR_GSO_TCPV4 => GsoType::TcpV4,
            VIRTIO_NET_HDR_GSO_TCPV6 => GsoType::TcpV6,
            VIRTIO_NET_HDR_GSO_UDP_L4 => GsoType::UdpL4,
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported virtio gsoType: {other}"),
                ))
            }
        };
        Ok(GsoOptions {
            gso_type,
            hdr_len: self.hdr_len,
            csum_start: self.csum_start,
            csum_offset: self.csum_offset,
            gso_size: self.gso_size,
            needs_csum: self.needs_csum(),
        })
    }
}

/// 修正内核提供的 HdrLen（对齐 sing-tun tun_linux.go:366-384 handleVirtioRead）。
///
/// 不能信任内核的 HdrLen：当内核在 FORWARD 路径处理包时，HdrLen 可能等于
/// 整个首包的长度。正确做法是解析传输层头部长度并加到 CsumStart（即 IP 头
/// 长度）上。仅对 GSO 包修正（GSONone 路径不使用 HdrLen 进行切分）。
pub fn correct_gso_hdr_len(options: &mut GsoOptions, packet: &[u8]) -> std::io::Result<()> {
    match options.gso_type {
        GsoType::UdpL4 => {
            options.hdr_len = options.csum_start + UDP_HDR_LEN as u16;
        }
        GsoType::TcpV4 | GsoType::TcpV6 => {
            // 解析 TCP data offset 字段得到 TCP 头长度（必须为 20..=60 字节）
            let flags_at = options.csum_start as usize + 12;
            if packet.len() <= flags_at {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packet is too short",
                ));
            }
            let tcp_h_len = (packet[flags_at] >> 4) as u16 * 4;
            if !(20..=60).contains(&tcp_h_len) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("tcp header len is invalid: {tcp_h_len}"),
                ));
            }
            options.hdr_len = options.csum_start + tcp_h_len;
        }
        GsoType::None => {}
    }
    Ok(())
}

// ── 校验和工具 ─────────────────────────────────────────────────────────────────

/// 计算 internet checksum（对齐 sing-tun gtcpip/checksum.Checksum）。
/// 返回的是未取反的累加值；调用方需 `^result` 得到最终校验和。
pub fn checksum(data: &[u8], initial: u16) -> u16 {
    let mut sum: u32 = initial as u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// 合并两个校验和（对齐 sing-tun checksum.Combine）。
pub fn checksum_combine(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// 计算伪头部校验和（对齐 sing-tun header.PseudoHeaderChecksum）。
pub fn pseudo_header_checksum(protocol: u8, src: &[u8], dst: &[u8], length: u16) -> u16 {
    let mut sum: u32 = 0;
    // src + dst
    let mut i = 0;
    while i + 1 < src.len() {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        i += 2;
    }
    let mut j = 0;
    while j + 1 < dst.len() {
        sum += u16::from_be_bytes([dst[j], dst[j + 1]]) as u32;
        j += 2;
    }
    // protocol + length
    sum += protocol as u32;
    sum += length as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// 验证传输层校验和（对齐 sing-tun checksumValid）。
fn checksum_valid(pkt: &[u8], iph_len: u8, proto: u8, is_v6: bool) -> bool {
    let src_off = if is_v6 {
        IPV6_SRC_ADDR_OFFSET
    } else {
        IPV4_SRC_ADDR_OFFSET
    };
    let addr_len = if is_v6 { 16 } else { 4 };
    if pkt.len() < src_off + addr_len * 2 {
        return false;
    }
    let len_for_pseudo = (pkt.len() - iph_len as usize) as u16;
    let psum = pseudo_header_checksum(
        proto,
        &pkt[src_off..src_off + addr_len],
        &pkt[src_off + addr_len..src_off + addr_len * 2],
        len_for_pseudo,
    );
    !checksum(&pkt[iph_len as usize..], psum) == 0
}

// ── GSO Split（读方向：拆分大包）──────────────────────────────────────────────

/// 将一个 GSO 大包拆分为多个 segment（对齐 sing-tun GSOSplit）。
///
/// `input` 为去掉 virtio_net_hdr 后的 IP 包。`options` 来自 virtio_net_hdr。
/// `out_bufs` 和 `sizes` 由调用方提供，返回写入的 segment 数量。
///
/// 每个 segment 是一个独立的 IP 包，带有正确的 IP 头（含递增的 ID、重算的
/// total_length/checksum）和 TCP 头（含递增的 seq、清除 FIN/PSH）。
pub fn gso_split(
    input: &[u8],
    options: &GsoOptions,
    out_bufs: &mut [Vec<u8>],
    sizes: &mut [usize],
) -> std::io::Result<usize> {
    let csum_at = options.csum_start as usize + options.csum_offset as usize;
    if csum_at + 1 >= input.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checksum offset exceeds packet length",
        ));
    }
    if input.len() < options.hdr_len as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "packet length < GSO HdrLen",
        ));
    }

    let payload_len = input.len() - options.hdr_len as usize;

    // 非分段或 payload 小于 gso_size：直接拷贝单个包
    if options.gso_type == GsoType::None || payload_len < options.gso_size as usize {
        if out_bufs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no output buffers",
            ));
        }
        let mut pkt = input.to_vec();
        if options.needs_csum {
            let initial = u16::from_be_bytes([pkt[csum_at], pkt[csum_at + 1]]);
            pkt[csum_at] = 0;
            pkt[csum_at + 1] = 0;
            let cs = !checksum(&pkt[options.csum_start as usize..], initial);
            pkt[csum_at..csum_at + 2].copy_from_slice(&cs.to_be_bytes());
        }
        out_bufs[0] = pkt;
        sizes[0] = input.len();
        return Ok(1);
    }

    if options.hdr_len < options.csum_start {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "GSO HdrLen < CsumStart",
        ));
    }

    let ip_version = input[0] >> 4;
    // 校验 IP 版本与 GSO 类型一致性及最小头长度（对齐 sing-tun
    // tun_offload.go:124-142 的 sanity 检查）。
    match ip_version {
        4 => {
            if options.gso_type != GsoType::TcpV4 && options.gso_type != GsoType::UdpL4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "ip header version: {ip_version}, gso type: {:?}",
                        options.gso_type
                    ),
                ));
            }
            if input.len() < 20 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("length of packet ({}) < minimum ipv4 header size (20)", input.len()),
                ));
            }
        }
        6 => {
            if options.gso_type != GsoType::TcpV6 && options.gso_type != GsoType::UdpL4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "ip header version: {ip_version}, gso type: {:?}",
                        options.gso_type
                    ),
                ));
            }
            if input.len() < 40 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("length of packet ({}) < minimum ipv6 header size (40)", input.len()),
                ));
            }
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid ip header version: {other}"),
            ));
        }
    }
    let iph_len = options.csum_start as usize;
    let (src_off, addr_len) = if ip_version == 4 {
        (IPV4_SRC_ADDR_OFFSET, 4)
    } else {
        (IPV6_SRC_ADDR_OFFSET, 16)
    };

    let transport_csum_at = options.csum_start as usize + options.csum_offset as usize;
    let protocol = match options.gso_type {
        GsoType::TcpV4 | GsoType::TcpV6 => 6,
        GsoType::UdpL4 => 17,
        GsoType::None => return Ok(0),
    };

    let first_tcp_seq_num = if protocol == 6 {
        if input.len() < options.csum_start as usize + 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "packet too short for TCP header",
            ));
        }
        u32::from_be_bytes([
            input[options.csum_start as usize + 4],
            input[options.csum_start as usize + 5],
            input[options.csum_start as usize + 6],
            input[options.csum_start as usize + 7],
        ])
    } else {
        0
    };

    let pseudo_sum_base = pseudo_header_checksum(
        protocol,
        &input[src_off..src_off + addr_len],
        &input[src_off + addr_len..src_off + addr_len * 2],
        0,
    );

    let mut next_segment_data_at = options.hdr_len as usize;
    let mut i = 0;
    while next_segment_data_at < input.len() {
        if i >= out_bufs.len() {
            // 段数超出输出缓冲：保留已生成的段并截断尾部（对齐 sing-tun
            // ErrTooManySegments 语义：返回 i-1 个有效段，不应导致读取终止，
            // tun_offload_errors.go:7-10）。
            break;
        }
        let next_segment_end = std::cmp::min(
            next_segment_data_at + options.gso_size as usize,
            input.len(),
        );
        let segment_data_len = next_segment_end - next_segment_data_at;
        let total_len = options.hdr_len as usize + segment_data_len;
        sizes[i] = total_len;

        let mut out = vec![0u8; total_len];
        // 拷贝头部
        out[..options.hdr_len as usize].copy_from_slice(&input[..options.hdr_len as usize]);

        if ip_version == 4 {
            // 递增 ID、重算 total_length + IP checksum
            if i > 0 {
                let id = u16::from_be_bytes([out[4], out[5]]);
                let id = id.wrapping_add(i as u16);
                out[4..6].copy_from_slice(&id.to_be_bytes());
            }
            out[10] = 0;
            out[11] = 0;
            out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            let ip_csum = !checksum(&out[..iph_len], 0);
            out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        } else {
            // IPv6: 更新 payload length
            out[4..6].copy_from_slice(&((total_len - iph_len) as u16).to_be_bytes());
        }

        if protocol == 6 {
            // 设置 TCP seq
            let tcp_seq = first_tcp_seq_num.wrapping_add(options.gso_size as u32 * i as u32);
            out[options.csum_start as usize + 4..options.csum_start as usize + 8]
                .copy_from_slice(&tcp_seq.to_be_bytes());
            // 非 last segment 清除 FIN/PSH
            if next_segment_end != input.len() {
                out[options.csum_start as usize + TCP_FLAGS_OFFSET] &=
                    !(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }
        } else {
            // UDP: 设置 length
            let udp_len = segment_data_len as u16 + (options.hdr_len - options.csum_start);
            out[options.csum_start as usize + 4..options.csum_start as usize + 6]
                .copy_from_slice(&udp_len.to_be_bytes());
        }

        // 拷贝 payload
        out[options.hdr_len as usize..]
            .copy_from_slice(&input[next_segment_data_at..next_segment_end]);

        // 重算传输层校验和
        out[transport_csum_at] = 0;
        out[transport_csum_at + 1] = 0;
        let transport_header_len = options.hdr_len - options.csum_start;
        let len_for_pseudo = transport_header_len + segment_data_len as u16;
        let transport_csum = checksum_combine(pseudo_sum_base, len_for_pseudo);
        let transport_csum =
            !checksum(&out[options.csum_start as usize..total_len], transport_csum);
        out[transport_csum_at..transport_csum_at + 2]
            .copy_from_slice(&transport_csum.to_be_bytes());

        out_bufs[i] = out;
        next_segment_data_at += options.gso_size as usize;
        i += 1;
    }
    Ok(i)
}

// ── GRO Coalescing（写方向：合并小包）─────────────────────────────────────────

/// GRO 候选类型
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroCandidateType {
    NotCandidate,
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

/// GRO 禁用标志
#[derive(Clone, Copy, Default)]
pub struct GroDisablementFlags(u8);

const TCP_GRO_DISABLED: u8 = 1;
const UDP_GRO_DISABLED: u8 = 2;

impl GroDisablementFlags {
    pub fn disable_tcp(&mut self) {
        self.0 |= TCP_GRO_DISABLED;
    }
    pub fn can_tcp(&self) -> bool {
        self.0 & TCP_GRO_DISABLED == 0
    }
    pub fn disable_udp(&mut self) {
        self.0 |= UDP_GRO_DISABLED;
    }
    pub fn can_udp(&self) -> bool {
        self.0 & UDP_GRO_DISABLED == 0
    }
}

fn packet_is_gro_candidate(b: &[u8], gro: GroDisablementFlags) -> GroCandidateType {
    if b.len() < 28 {
        return GroCandidateType::NotCandidate;
    }
    match b[0] >> 4 {
        4 => {
            if b[0] & 0x0f != 5 {
                return GroCandidateType::NotCandidate; // IP options 不合并
            }
            if b[9] == 6 && b.len() >= 40 && gro.can_tcp() {
                return GroCandidateType::Tcp4;
            }
            if b[9] == 17 && gro.can_udp() {
                return GroCandidateType::Udp4;
            }
        }
        6 => {
            if b[6] == 6 && b.len() >= 60 && gro.can_tcp() {
                return GroCandidateType::Tcp6;
            }
            if b[6] == 17 && b.len() >= 48 && gro.can_udp() {
                return GroCandidateType::Udp6;
            }
        }
        _ => {}
    }
    GroCandidateType::NotCandidate
}

/// TCP flow key（对齐 sing-tun tcpFlowKey）
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    rx_ack: u32,
    is_v6: bool,
}

impl TcpFlowKey {
    fn new(pkt: &[u8], src_off: usize, dst_off: usize, tcph_off: usize) -> Self {
        let addr_size = dst_off - src_off;
        let mut key = TcpFlowKey {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: u16::from_be_bytes([pkt[tcph_off], pkt[tcph_off + 1]]),
            dst_port: u16::from_be_bytes([pkt[tcph_off + 2], pkt[tcph_off + 3]]),
            rx_ack: u32::from_be_bytes([
                pkt[tcph_off + 8],
                pkt[tcph_off + 9],
                pkt[tcph_off + 10],
                pkt[tcph_off + 11],
            ]),
            is_v6: addr_size == 16,
        };
        key.src_addr[..addr_size].copy_from_slice(&pkt[src_off..dst_off]);
        key.dst_addr[..addr_size].copy_from_slice(&pkt[dst_off..dst_off + addr_size]);
        key
    }
}

/// UDP flow key
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    is_v6: bool,
}

impl UdpFlowKey {
    fn new(pkt: &[u8], src_off: usize, dst_off: usize, udph_off: usize) -> Self {
        let addr_size = dst_off - src_off;
        let mut key = UdpFlowKey {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: u16::from_be_bytes([pkt[udph_off], pkt[udph_off + 1]]),
            dst_port: u16::from_be_bytes([pkt[udph_off + 2], pkt[udph_off + 3]]),
            is_v6: addr_size == 16,
        };
        key.src_addr[..addr_size].copy_from_slice(&pkt[src_off..dst_off]);
        key.dst_addr[..addr_size].copy_from_slice(&pkt[dst_off..dst_off + addr_size]);
        key
    }
}

#[derive(Clone, Debug)]
struct TcpGroItem {
    key: TcpFlowKey,
    sent_seq: u32,
    bufs_index: usize,
    num_merged: u16,
    gso_size: u16,
    iph_len: u8,
    tcph_len: u8,
    psh_set: bool,
}

#[derive(Clone, Debug)]
struct UdpGroItem {
    key: UdpFlowKey,
    bufs_index: usize,
    num_merged: u16,
    gso_size: u16,
    iph_len: u8,
}

/// TCP GRO 表
pub struct TcpGroTable {
    items_by_flow: HashMap<TcpFlowKey, Vec<TcpGroItem>>,
}

impl Default for TcpGroTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpGroTable {
    pub fn new() -> Self {
        Self {
            items_by_flow: HashMap::with_capacity(IDEAL_BATCH_SIZE),
        }
    }
    pub fn reset(&mut self) {
        self.items_by_flow.clear();
    }
}

/// UDP GRO 表
pub struct UdpGroTable {
    items_by_flow: HashMap<UdpFlowKey, Vec<UdpGroItem>>,
}

impl Default for UdpGroTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpGroTable {
    pub fn new() -> Self {
        Self {
            items_by_flow: HashMap::with_capacity(IDEAL_BATCH_SIZE),
        }
    }
    pub fn reset(&mut self) {
        self.items_by_flow.clear();
    }
}

/// Coalesce 方向
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanCoalesce {
    Prepend,
    Unavailable,
    Append,
}

/// IP 头部是否可合并
fn ip_headers_can_coalesce(pkt_a: &[u8], pkt_b: &[u8]) -> bool {
    if pkt_a.len() < 9 || pkt_b.len() < 9 {
        return false;
    }
    if pkt_a[0] >> 4 == 6 {
        if pkt_a[0] != pkt_b[0] || pkt_a[1] >> 4 != pkt_b[1] >> 4 {
            return false;
        }
        if pkt_a[7] != pkt_b[7] {
            return false;
        }
    } else {
        if pkt_a[1] != pkt_b[1] {
            return false;
        }
        if pkt_a[6] >> 5 != pkt_b[6] >> 5 {
            return false;
        }
        if pkt_a[8] != pkt_b[8] {
            return false;
        }
    }
    true
}

/// TCP 包是否可合并
#[allow(clippy::too_many_arguments)]
fn tcp_packets_can_coalesce(
    pkt: &[u8],
    iph_len: u8,
    tcph_len: u8,
    seq: u32,
    psh_set: bool,
    gso_size: u16,
    item: &TcpGroItem,
    bufs: &[Vec<u8>],
    offset: usize,
) -> CanCoalesce {
    let pkt_target = &bufs[item.bufs_index][offset..];
    if tcph_len != item.tcph_len {
        return CanCoalesce::Unavailable;
    }
    if tcph_len > 20
        && pkt[iph_len as usize + 20..iph_len as usize + tcph_len as usize]
            != pkt_target[item.iph_len as usize + 20..item.iph_len as usize + tcph_len as usize]
    {
        return CanCoalesce::Unavailable;
    }
    if !ip_headers_can_coalesce(pkt, pkt_target) {
        return CanCoalesce::Unavailable;
    }
    let lhs_len = item.gso_size as u32 + item.num_merged as u32 * item.gso_size as u32;
    if seq == item.sent_seq.wrapping_add(lhs_len) {
        // append
        if item.psh_set {
            return CanCoalesce::Unavailable;
        }
        if !(pkt_target.len() - iph_len as usize - tcph_len as usize)
            .is_multiple_of(item.gso_size as usize)
        {
            return CanCoalesce::Unavailable;
        }
        if gso_size > item.gso_size {
            return CanCoalesce::Unavailable;
        }
        CanCoalesce::Append
    } else if seq.wrapping_add(gso_size as u32) == item.sent_seq {
        // prepend
        if psh_set {
            return CanCoalesce::Unavailable;
        }
        if gso_size < item.gso_size {
            return CanCoalesce::Unavailable;
        }
        if gso_size > item.gso_size && item.num_merged > 0 {
            return CanCoalesce::Unavailable;
        }
        CanCoalesce::Prepend
    } else {
        CanCoalesce::Unavailable
    }
}

/// UDP 包是否可合并
fn udp_packets_can_coalesce(
    _pkt: &[u8],
    iph_len: u8,
    gso_size: u16,
    item: &UdpGroItem,
    bufs: &[Vec<u8>],
    offset: usize,
) -> CanCoalesce {
    let pkt_target = &bufs[item.bufs_index][offset..];
    if !ip_headers_can_coalesce(_pkt, pkt_target) {
        return CanCoalesce::Unavailable;
    }
    if !(pkt_target.len() - iph_len as usize - UDP_HDR_LEN).is_multiple_of(item.gso_size as usize) {
        return CanCoalesce::Unavailable;
    }
    if gso_size > item.gso_size {
        return CanCoalesce::Unavailable;
    }
    CanCoalesce::Append
}

/// Coalesce 结果
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoalesceResult {
    InsufficientCap,
    PshEnding,
    ItemInvalidCsum,
    PktInvalidCsum,
    Success,
}

/// 合并两个 TCP 包
#[allow(clippy::too_many_arguments)]
fn coalesce_tcp_packets(
    mode: CanCoalesce,
    pkt: &[u8],
    pkt_bufs_index: usize,
    gso_size: u16,
    seq: u32,
    psh_set: bool,
    item: &mut TcpGroItem,
    bufs: &mut [Vec<u8>],
    offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let headers_len = item.iph_len as usize + item.tcph_len as usize;
    let item_idx = item.bufs_index;
    let coalesced_len = bufs[item_idx].len() - offset + pkt.len() - headers_len;

    if mode == CanCoalesce::Prepend {
        // prepend: pkt 在前，item 的 payload 追加到 pkt 之后，最后交换 bufs。
        // R1：旧实现检查 `capacity() - offset < coalesced_len`，但调用方
        // （native_tun.rs do_batch_write）按 `with_capacity(offset + p.len())`
        // 精确分配容量，该条件恒为真，导致 GRO 从不合并（性能特性完全失效）。
        // Vec::resize 本可自动扩容，这里只需防止合并结果超出 IP 包长度上限
        // （IPv4 total length / IPv6 payload length 均为 u16，溢出会被静默截断）。
        if coalesced_len > MAX_COALESCED_PACKET_LEN {
            return CoalesceResult::InsufficientCap;
        }
        if psh_set {
            return CoalesceResult::PshEnding;
        }
        if item.num_merged == 0
            && !checksum_valid(&bufs[item_idx][offset..], item.iph_len, 6, is_v6)
        {
            return CoalesceResult::ItemInvalidCsum;
        }
        if !checksum_valid(pkt, item.iph_len, 6, is_v6) {
            return CoalesceResult::PktInvalidCsum;
        }
        item.sent_seq = seq;
        // 先把 item 的 payload（去掉头部）拷贝到临时缓冲，避免同时借用 bufs 的两个槽位。
        let item_payload: Vec<u8> = bufs[item_idx][offset + headers_len..].to_vec();
        let pkt_len_in_buf = bufs[pkt_bufs_index].len() - offset;
        let extend_by = coalesced_len - pkt_len_in_buf;
        let old_len = bufs[pkt_bufs_index].len();
        bufs[pkt_bufs_index].resize(old_len + extend_by, 0);
        bufs[pkt_bufs_index][offset + pkt_len_in_buf..offset + pkt_len_in_buf + item_payload.len()]
            .copy_from_slice(&item_payload);
        // 交换 bufs 槽位：item 索引指向合并后的大包，pkt 索引释放。
        bufs.swap(item_idx, pkt_bufs_index);
        item.bufs_index = pkt_bufs_index;
        // 交换后 item_idx 现在指向旧 pkt 位置（已被释放/旧数据），pkt_bufs_index 指向合并后的大包
        // 修正：swap 后 item.bufs_index 应指向持有合并数据的位置
        item.bufs_index = item_idx; // item_idx 仍持有合并后的数据（因为 swap 把 pkt_buf 内容放到了 item_idx）
    } else {
        // append: item 在前，pkt 追加（R1：同上，改为 IP 包长度上限检查）
        let pkt_head_len = bufs[item_idx].len() - offset;
        if coalesced_len > MAX_COALESCED_PACKET_LEN {
            return CoalesceResult::InsufficientCap;
        }
        if item.num_merged == 0
            && !checksum_valid(&bufs[item_idx][offset..], item.iph_len, 6, is_v6)
        {
            return CoalesceResult::ItemInvalidCsum;
        }
        if !checksum_valid(pkt, item.iph_len, 6, is_v6) {
            return CoalesceResult::PktInvalidCsum;
        }
        if psh_set {
            item.psh_set = true;
            bufs[item_idx][offset + item.iph_len as usize + TCP_FLAGS_OFFSET] |= TCP_FLAG_PSH;
        }
        let extend_by = pkt.len() - headers_len;
        let old_len = bufs[item_idx].len();
        bufs[item_idx].resize(old_len + extend_by, 0);
        bufs[item_idx][offset + pkt_head_len..offset + pkt_head_len + extend_by]
            .copy_from_slice(&pkt[headers_len..]);
    }
    if gso_size > item.gso_size {
        item.gso_size = gso_size;
    }
    item.num_merged += 1;
    CoalesceResult::Success
}

/// 合并两个 UDP 包
fn coalesce_udp_packets(
    pkt: &[u8],
    item: &mut UdpGroItem,
    bufs: &mut [Vec<u8>],
    offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let headers_len = item.iph_len as usize + UDP_HDR_LEN;
    let item_idx = item.bufs_index;
    let iph_len = item.iph_len;
    let coalesced_len = bufs[item_idx].len() - offset + pkt.len() - headers_len;

    // R1：同 coalesce_tcp_packets，容量预检改为 IP 包长度上限检查
    if coalesced_len > MAX_COALESCED_PACKET_LEN {
        return CoalesceResult::InsufficientCap;
    }
    if item.num_merged == 0 && !checksum_valid(&bufs[item_idx][offset..], iph_len, 17, is_v6) {
        return CoalesceResult::ItemInvalidCsum;
    }
    if !checksum_valid(pkt, iph_len, 17, is_v6) {
        return CoalesceResult::PktInvalidCsum;
    }
    let extend_by = pkt.len() - headers_len;
    let pkt_head_len = bufs[item_idx].len() - offset;
    let old_len = bufs[item_idx].len();
    bufs[item_idx].resize(old_len + extend_by, 0);
    bufs[item_idx][offset + pkt_head_len..offset + pkt_head_len + extend_by]
        .copy_from_slice(&pkt[headers_len..]);
    item.num_merged += 1;
    CoalesceResult::Success
}

/// GRO 结果
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroResult {
    Noop,
    TableInsert,
    Coalesced,
}

/// TCP GRO 评估
fn tcp_gro(
    bufs: &mut [Vec<u8>],
    offset: usize,
    pkt_i: usize,
    table: &mut TcpGroTable,
    is_v6: bool,
) -> GroResult {
    // 先将 pkt 拷贝到本地，避免后续可变借用 bufs 时冲突。
    let pkt_owned: Vec<u8> = bufs[pkt_i][offset..].to_vec();
    let pkt = pkt_owned.as_slice();
    if pkt.len() > 65535 {
        return GroResult::Noop;
    }
    let iph_len = if is_v6 {
        40
    } else {
        (pkt[0] & 0x0f) as usize * 4
    };
    // 校验长度一致性
    if is_v6 {
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }
    if pkt.len() < iph_len {
        return GroResult::Noop;
    }
    let tcph_len = (pkt[iph_len + 12] >> 4) as usize * 4;
    if !(20..=60).contains(&tcph_len) {
        return GroResult::Noop;
    }
    if pkt.len() < iph_len + tcph_len {
        return GroResult::Noop;
    }
    if !is_v6 && (pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0) {
        return GroResult::Noop;
    }
    let tcp_flags = pkt[iph_len + TCP_FLAGS_OFFSET];
    let psh_set = if tcp_flags != TCP_FLAG_ACK {
        if tcp_flags != (TCP_FLAG_ACK | TCP_FLAG_PSH) {
            return GroResult::Noop;
        }
        true
    } else {
        false
    };
    let gso_size = (pkt.len() - tcph_len - iph_len) as u16;
    if gso_size < 1 {
        return GroResult::Noop;
    }
    let seq = u32::from_be_bytes([
        pkt[iph_len + 4],
        pkt[iph_len + 5],
        pkt[iph_len + 6],
        pkt[iph_len + 7],
    ]);
    let (src_off, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };
    let key = TcpFlowKey::new(pkt, src_off, src_off + addr_len, iph_len);
    let existing = table.items_by_flow.contains_key(&key);
    if !existing {
        let item = TcpGroItem {
            key: key.clone(),
            sent_seq: seq,
            bufs_index: pkt_i,
            num_merged: 0,
            gso_size,
            iph_len: iph_len as u8,
            tcph_len: tcph_len as u8,
            psh_set,
        };
        table.items_by_flow.entry(key).or_default().push(item);
        return GroResult::TableInsert;
    }
    let items = table.items_by_flow.get_mut(&key).unwrap();
    // 反向遍历
    let mut coalesced = false;
    let mut i = items.len();
    while i > 0 {
        i -= 1;
        let item_clone = items[i].clone();
        let can = tcp_packets_can_coalesce(
            pkt,
            iph_len as u8,
            tcph_len as u8,
            seq,
            psh_set,
            gso_size,
            &item_clone,
            bufs,
            offset,
        );
        if can != CanCoalesce::Unavailable {
            let mut item = items[i].clone();
            let result = coalesce_tcp_packets(
                can, pkt, pkt_i, gso_size, seq, psh_set, &mut item, bufs, offset, is_v6,
            );
            match result {
                CoalesceResult::Success => {
                    items[i] = item;
                    coalesced = true;
                    break;
                }
                CoalesceResult::ItemInvalidCsum => {
                    items.remove(i);
                }
                CoalesceResult::PktInvalidCsum => {
                    return GroResult::Noop;
                }
                _ => {}
            }
        }
    }
    if coalesced {
        return GroResult::Coalesced;
    }
    // 合并失败，插入新 item
    let item = TcpGroItem {
        key: key.clone(),
        sent_seq: seq,
        bufs_index: pkt_i,
        num_merged: 0,
        gso_size,
        iph_len: iph_len as u8,
        tcph_len: tcph_len as u8,
        psh_set,
    };
    table.items_by_flow.entry(key).or_default().push(item);
    GroResult::TableInsert
}

/// UDP GRO 评估
fn udp_gro(
    bufs: &mut [Vec<u8>],
    offset: usize,
    pkt_i: usize,
    table: &mut UdpGroTable,
    is_v6: bool,
) -> GroResult {
    // 先将 pkt 拷贝到本地，避免后续可变借用 bufs 时冲突。
    let pkt_owned: Vec<u8> = bufs[pkt_i][offset..].to_vec();
    let pkt = pkt_owned.as_slice();
    if pkt.len() > 65535 {
        return GroResult::Noop;
    }
    let iph_len = if is_v6 {
        40
    } else {
        (pkt[0] & 0x0f) as usize * 4
    };
    if is_v6 {
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }
    if pkt.len() < iph_len || pkt.len() < iph_len + UDP_HDR_LEN {
        return GroResult::Noop;
    }
    if !is_v6 && (pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0) {
        return GroResult::Noop;
    }
    let gso_size = (pkt.len() - UDP_HDR_LEN - iph_len) as u16;
    if gso_size < 1 {
        return GroResult::Noop;
    }
    let (src_off, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };
    let key = UdpFlowKey::new(pkt, src_off, src_off + addr_len, iph_len);
    let existing = table.items_by_flow.contains_key(&key);
    if !existing {
        let item = UdpGroItem {
            key: key.clone(),
            bufs_index: pkt_i,
            num_merged: 0,
            gso_size,
            iph_len: iph_len as u8,
        };
        table.items_by_flow.entry(key).or_default().push(item);
        return GroResult::TableInsert;
    }
    let items = table.items_by_flow.get_mut(&key).unwrap();
    let item_clone = items.last().unwrap().clone();
    let can = udp_packets_can_coalesce(pkt, iph_len as u8, gso_size, &item_clone, bufs, offset);
    if can == CanCoalesce::Append {
        let mut item = items.last_mut().unwrap().clone();
        let result = coalesce_udp_packets(pkt, &mut item, bufs, offset, is_v6);
        if result == CoalesceResult::Success {
            *items.last_mut().unwrap() = item;
            return GroResult::Coalesced;
        }
    }
    // 插入新 item
    let item = UdpGroItem {
        key: key.clone(),
        bufs_index: pkt_i,
        num_merged: 0,
        gso_size,
        iph_len: iph_len as u8,
    };
    table.items_by_flow.entry(key).or_default().push(item);
    GroResult::TableInsert
}

/// 更新合并后的 TCP 包的 virtio_net_hdr 和长度/校验和
fn apply_tcp_coalesce_accounting(bufs: &mut [Vec<u8>], offset: usize, table: &TcpGroTable) {
    for items in table.items_by_flow.values() {
        for item in items {
            if item.num_merged > 0 {
                let hdr = VirtioNetHdr {
                    flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    gso_type: if item.key.is_v6 {
                        VIRTIO_NET_HDR_GSO_TCPV6
                    } else {
                        VIRTIO_NET_HDR_GSO_TCPV4
                    },
                    hdr_len: item.iph_len as u16 + item.tcph_len as u16,
                    gso_size: item.gso_size,
                    csum_start: item.iph_len as u16,
                    csum_offset: 16,
                };
                let pkt = &mut bufs[item.bufs_index];
                // 确保有空间写 virtio_net_hdr
                if offset >= VIRTIO_NET_HDR_LEN {
                    hdr.encode(&mut pkt[offset - VIRTIO_NET_HDR_LEN..offset])
                        .ok();
                }
                let pkt_data = &mut bufs[item.bufs_index][offset..];
                // 重算 total_len / payload_len + IP checksum
                if item.key.is_v6 {
                    let plen = (pkt_data.len() - item.iph_len as usize) as u16;
                    pkt_data[4..6].copy_from_slice(&plen.to_be_bytes());
                } else {
                    pkt_data[10] = 0;
                    pkt_data[11] = 0;
                    let total = pkt_data.len() as u16;
                    pkt_data[2..4].copy_from_slice(&total.to_be_bytes());
                    let ip_csum = !checksum(&pkt_data[..item.iph_len as usize], 0);
                    pkt_data[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                }
                // 伪头部校验和写入 TCP checksum 位置
                let (addr_off, addr_len) = if item.key.is_v6 {
                    (IPV6_SRC_ADDR_OFFSET, 16)
                } else {
                    (IPV4_SRC_ADDR_OFFSET, 4)
                };
                let len_for_pseudo = (pkt_data.len() - item.iph_len as usize) as u16;
                let psum = pseudo_header_checksum(
                    6,
                    &pkt_data[addr_off..addr_off + addr_len],
                    &pkt_data[addr_off + addr_len..addr_off + addr_len * 2],
                    len_for_pseudo,
                );
                let csum_at = item.iph_len as usize + 16; // csum_start + csum_offset
                if csum_at + 2 <= pkt_data.len() {
                    let cs = checksum(&[], psum);
                    pkt_data[csum_at..csum_at + 2].copy_from_slice(&cs.to_be_bytes());
                }
            } else if offset >= VIRTIO_NET_HDR_LEN {
                let hdr = VirtioNetHdr::default();
                hdr.encode(&mut bufs[item.bufs_index][offset - VIRTIO_NET_HDR_LEN..offset])
                    .ok();
            }
        }
    }
}

/// 更新合并后的 UDP 包的 virtio_net_hdr 和长度/校验和
fn apply_udp_coalesce_accounting(bufs: &mut [Vec<u8>], offset: usize, table: &UdpGroTable) {
    for items in table.items_by_flow.values() {
        for item in items {
            if item.num_merged > 0 {
                let hdr = VirtioNetHdr {
                    flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
                    hdr_len: item.iph_len as u16 + UDP_HDR_LEN as u16,
                    gso_size: item.gso_size,
                    csum_start: item.iph_len as u16,
                    csum_offset: 6,
                };
                let pkt = &mut bufs[item.bufs_index];
                if offset >= VIRTIO_NET_HDR_LEN {
                    hdr.encode(&mut pkt[offset - VIRTIO_NET_HDR_LEN..offset])
                        .ok();
                }
                let pkt_data = &mut bufs[item.bufs_index][offset..];
                if item.key.is_v6 {
                    let plen = (pkt_data.len() - item.iph_len as usize) as u16;
                    pkt_data[4..6].copy_from_slice(&plen.to_be_bytes());
                } else {
                    pkt_data[10] = 0;
                    pkt_data[11] = 0;
                    let total = pkt_data.len() as u16;
                    pkt_data[2..4].copy_from_slice(&total.to_be_bytes());
                    let ip_csum = !checksum(&pkt_data[..item.iph_len as usize], 0);
                    pkt_data[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                }
                // UDP length
                let udp_len = (pkt_data.len() - item.iph_len as usize) as u16;
                pkt_data[item.iph_len as usize + 4..item.iph_len as usize + 6]
                    .copy_from_slice(&udp_len.to_be_bytes());
                // 伪头部校验和
                let (addr_off, addr_len) = if item.key.is_v6 {
                    (IPV6_SRC_ADDR_OFFSET, 16)
                } else {
                    (IPV4_SRC_ADDR_OFFSET, 4)
                };
                let len_for_pseudo = (pkt_data.len() - item.iph_len as usize) as u16;
                let psum = pseudo_header_checksum(
                    17,
                    &pkt_data[addr_off..addr_off + addr_len],
                    &pkt_data[addr_off + addr_len..addr_off + addr_len * 2],
                    len_for_pseudo,
                );
                let csum_at = item.iph_len as usize + 6;
                if csum_at + 2 <= pkt_data.len() {
                    let cs = checksum(&[], psum);
                    pkt_data[csum_at..csum_at + 2].copy_from_slice(&cs.to_be_bytes());
                }
            } else if offset >= VIRTIO_NET_HDR_LEN {
                let hdr = VirtioNetHdr::default();
                hdr.encode(&mut bufs[item.bufs_index][offset - VIRTIO_NET_HDR_LEN..offset])
                    .ok();
            }
        }
    }
}

/// handleGRO：对一批出站包执行 GRO 合并（对齐 sing-tun handleGRO）。
///
/// `bufs` 为待发送的包列表，每个 buf 在 `[offset..]` 处存放 IP 包数据，
/// `[offset - VIRTIO_NET_HDR_LEN..offset]` 处存放 virtio_net_hdr。
/// `to_write` 输出需要写入 TUN 的 buf 索引列表。
pub fn handle_gro(
    bufs: &mut [Vec<u8>],
    offset: usize,
    tcp_table: &mut TcpGroTable,
    udp_table: &mut UdpGroTable,
    mut gro_flags: GroDisablementFlags,
    to_write: &mut Vec<usize>,
) -> std::io::Result<()> {
    for i in 0..bufs.len() {
        if offset < VIRTIO_NET_HDR_LEN || offset > bufs[i].len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid offset for GRO",
            ));
        }
        let candidate = packet_is_gro_candidate(&bufs[i][offset..], gro_flags);
        let result = match candidate {
            GroCandidateType::Tcp4 => tcp_gro(bufs, offset, i, tcp_table, false),
            GroCandidateType::Tcp6 => tcp_gro(bufs, offset, i, tcp_table, true),
            GroCandidateType::Udp4 => udp_gro(bufs, offset, i, udp_table, false),
            GroCandidateType::Udp6 => udp_gro(bufs, offset, i, udp_table, true),
            GroCandidateType::NotCandidate => GroResult::Noop,
        };
        match result {
            GroResult::Noop => {
                // 写空 virtio_net_hdr
                if offset >= VIRTIO_NET_HDR_LEN {
                    let hdr = VirtioNetHdr::default();
                    hdr.encode(&mut bufs[i][offset - VIRTIO_NET_HDR_LEN..offset])
                        .ok();
                }
                to_write.push(i);
            }
            GroResult::TableInsert => {
                to_write.push(i);
            }
            GroResult::Coalesced => {
                // 已合并到另一个 buf，不写入当前索引
            }
        }
        // 如果内核不支持某种 GRO，探测后禁用
        let _ = &mut gro_flags;
    }
    apply_tcp_coalesce_accounting(bufs, offset, tcp_table);
    apply_udp_coalesce_accounting(bufs, offset, udp_table);
    Ok(())
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_net_hdr_encode_decode() {
        let hdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1448,
            csum_start: 20,
            csum_offset: 16,
        };
        let mut buf = [0u8; VIRTIO_NET_HDR_LEN];
        hdr.encode(&mut buf).unwrap();
        let decoded = VirtioNetHdr::decode(&buf).unwrap();
        assert_eq!(decoded.flags, hdr.flags);
        assert_eq!(decoded.gso_type, hdr.gso_type);
        assert_eq!(decoded.hdr_len, hdr.hdr_len);
        assert_eq!(decoded.gso_size, hdr.gso_size);
        assert_eq!(decoded.csum_start, hdr.csum_start);
        assert_eq!(decoded.csum_offset, hdr.csum_offset);
    }

    #[test]
    fn test_gso_split_tcp_v4() {
        // 构造一个 GSO TCPv4 大包：20 IP + 20 TCP + 2896 payload (2 * 1448)
        let hdr_len = 40usize;
        let gso_size = 1448u16;
        let payload_len = gso_size as usize * 2;
        let total_len = hdr_len + payload_len;
        let mut input = vec![0u8; total_len];
        input[0] = 0x45; // v4, IHL=5
        input[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        input[4..6].copy_from_slice(&100u16.to_be_bytes()); // ID
        input[6] = 0x40; // DF
        input[8] = 64; // TTL
        input[9] = 6; // TCP
        input[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        input[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
                                                       // IP checksum
        let ip_csum = !checksum(&input[..20], 0);
        input[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        // TCP header
        input[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        input[22..24].copy_from_slice(&80u16.to_be_bytes()); // dst port
        input[24..28].copy_from_slice(&1000u32.to_be_bytes()); // seq
        input[28..32].copy_from_slice(&2000u32.to_be_bytes()); // ack
        input[32] = 0x50; // data offset = 5
        input[33] = TCP_FLAG_ACK | TCP_FLAG_PSH; // flags
        input[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window
                                                                // payload
        for i in 0..payload_len {
            input[hdr_len + i] = (i % 256) as u8;
        }

        let options = GsoOptions {
            gso_type: GsoType::TcpV4,
            hdr_len: hdr_len as u16,
            csum_start: 20,
            csum_offset: 16,
            gso_size,
            needs_csum: true,
        };

        let mut out_bufs = vec![Vec::new(); 4];
        let mut sizes = [0usize; 4];
        let n = gso_split(&input, &options, &mut out_bufs, &mut sizes).unwrap();
        assert_eq!(n, 2);
        assert_eq!(sizes[0], hdr_len + gso_size as usize);
        assert_eq!(sizes[1], hdr_len + gso_size as usize);

        // 验证 segment 0
        let seg0 = &out_bufs[0];
        assert_eq!(seg0.len(), hdr_len + gso_size as usize);
        // IP ID 递增：segment 0 = 100, segment 1 = 101
        assert_eq!(u16::from_be_bytes([seg0[4], seg0[5]]), 100);
        // TCP seq: segment 0 = 1000, segment 1 = 1000 + 1448
        let seq0 = u32::from_be_bytes([seg0[24], seg0[25], seg0[26], seg0[27]]);
        assert_eq!(seq0, 1000);

        // 验证 segment 1
        let seg1 = &out_bufs[1];
        assert_eq!(u16::from_be_bytes([seg1[4], seg1[5]]), 101);
        let seq1 = u32::from_be_bytes([seg1[24], seg1[25], seg1[26], seg1[27]]);
        assert_eq!(seq1, 1000 + gso_size as u32);
    }

    #[test]
    fn test_gso_split_no_gso() {
        let input = vec![0x45u8; 40];
        let options = GsoOptions {
            gso_type: GsoType::None,
            ..Default::default()
        };
        let mut out_bufs = vec![Vec::new(); 1];
        let mut sizes = [0usize; 1];
        let n = gso_split(&input, &options, &mut out_bufs, &mut sizes).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out_bufs[0], input);
    }

    #[test]
    fn test_checksum_basic() {
        // 空数据 checksum = initial
        assert_eq!(checksum(&[], 0), 0);
        // 单字节
        assert_eq!(checksum(&[0x01], 0), 0x0100);
    }

    #[test]
    fn test_handle_gro_noop() {
        let mut bufs = vec![{
            let mut b = vec![0u8; VIRTIO_NET_HDR_LEN + 20];
            b[VIRTIO_NET_HDR_LEN] = 0x45;
            b
        }];
        let offset = VIRTIO_NET_HDR_LEN;
        let mut tcp_table = TcpGroTable::new();
        let mut udp_table = UdpGroTable::new();
        let mut to_write = Vec::new();
        handle_gro(
            &mut bufs,
            offset,
            &mut tcp_table,
            &mut udp_table,
            GroDisablementFlags::default(),
            &mut to_write,
        )
        .unwrap();
        assert_eq!(to_write, vec![0]);
    }
}
