use super::{packet::IpPacket, Packet};
use etherparse::PacketBuilder;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{error, trace};

/// UDP 转发通道上的一个包：数据 + 两个方向的 socket 地址。
///
/// `local_addr` = TUN 内应用侧地址（会话源），
/// `remote_addr` = 目标地址。回包时二者互换。
pub struct UdpPacket {
    pub data: Packet,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// 纯封包/解包的 UDP 通道（clash-rs 原样移植）：
/// - 读：从栈收 IP 包，剥出 UDP 载荷与 src/dst；
/// - 写：把载荷 + 两个地址封成 IP/UDP 包交回栈（→ TUN）。
///
/// 不经过 smoltcp UDP socket —— UDP 无状态转发即可。
pub struct UdpSocket {
    inbound: mpsc::UnboundedReceiver<Packet>,
    outbound: mpsc::Sender<Packet>,
}

impl UdpSocket {
    pub fn new(inbound: mpsc::UnboundedReceiver<Packet>, outbound: mpsc::Sender<Packet>) -> Self {
        Self { inbound, outbound }
    }

    pub fn split(self) -> (super::udp_socket::SplitRead, SplitWrite) {
        let read = SplitRead { recv: self.inbound };
        let write = SplitWrite { send: self.outbound };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::UnboundedReceiver<Packet>,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.recv.recv().await.and_then(|data| {
            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    return None;
                }
            };

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match smoltcp::wire::UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid UDP packet: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}");
                    return None;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("udp packet {src_addr} <-> {dst_addr}");

            Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            })
        })
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        if packet.data.data().is_empty() {
            return Ok(());
        }

        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut ip_packet_writer = Vec::with_capacity(builder.size(packet.data.data().len()));
        builder
            .write(&mut ip_packet_writer, packet.data.data())
            .map_err(std::io::Error::other)?;

        // UDP is inherently unreliable — drop the packet if the outbound
        // channel is full rather than blocking the UDP handler task.
        match self.send.try_send(Packet::new(ip_packet_writer)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(std::io::Error::other("packet outbound channel closed"))
            }
        }
    }
}
