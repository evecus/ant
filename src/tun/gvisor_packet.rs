use std::net::IpAddr;

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};

#[derive(Debug)]
pub(crate) enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

impl<T: AsRef<[u8]> + Copy> IpPacket<T> {
    pub fn new_checked(packet: T) -> smoltcp::wire::Result<IpPacket<T>> {
        let buffer = packet.as_ref();
        match IpVersion::of_packet(buffer)? {
            IpVersion::Ipv4 => Ok(IpPacket::Ipv4(Ipv4Packet::new_checked(packet)?)),
            IpVersion::Ipv6 => Ok(IpPacket::Ipv6(Ipv6Packet::new_checked(packet)?)),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.src_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.src_addr()),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.dst_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.dst_addr()),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IpPacket<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.payload(),
            IpPacket::Ipv6(ref packet) => packet.payload(),
        }
    }

    /// 返回 (传输层协议, 传输层载荷)。
    ///
    /// 移植自 clash-rs 并修复：clash-rs 原版各处用 `protocol()`（IPv6 固定头
    /// 的 Next Header 字段）+ `payload()`（紧跟固定头后的切片），带扩展头
    /// （hop-by-hop / routing / dstopts）的包会被误判协议且载荷错位，导致
    /// 包被静默丢弃。本方法跳过 IPv6 扩展头链，返回真正的传输层协议与载荷；
    /// 无法安全定位传输层（扩展头越界 / 分片包）时返回 None。
    pub fn transport(&self) -> Option<(IpProtocol, &'a [u8])> {
        match *self {
            IpPacket::Ipv4(ref packet) => Some((packet.next_header(), packet.payload())),
            IpPacket::Ipv6(ref packet) => {
                let mut proto = packet.next_header();
                let mut payload = packet.payload();
                loop {
                    match proto {
                        IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                            if payload.len() < 2 {
                                return None;
                            }
                            // 扩展头长度 = (Hdr Ext Len 字段 + 1) * 8 字节
                            let ext_len = (payload[1] as usize + 1) * 8;
                            if payload.len() < ext_len {
                                return None;
                            }
                            proto = IpProtocol::from(payload[0]); // Next Header
                            payload = &payload[ext_len..];
                        }
                        IpProtocol::Ipv6Frag => {
                            // 分片包：非首片不含传输层头，无法安全定位；
                            // IPv6 重组由上层（ip_defrag）负责，这里丢弃
                            return None;
                        }
                        p => return Some((p, payload)),
                    }
                }
            }
        }
    }
}
