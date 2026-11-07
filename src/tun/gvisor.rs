//! 用户态 TCP/IP 协议栈（smoltcp）—— ant 的 `tun.stack: gvisor` 实现。
//!
//! 参考 clash-rs `clash-netstack`（watfaq_netstack）移植，作为 TUN inbound 的
//! 用户态协议栈：TUN 收到的 IP 包注入 NetStack，TCP 由 smoltcp 终结成
//! `TcpStream`（AsyncRead + AsyncWrite），UDP 走纯封包/解包转发通道，
//! ICMP echo 由 smoltcp Interface 自动应答。
//!
//! 与 system 栈（`system_stack.rs` 的 NAT + 本地 listener）相比：
//! - 无内核 socket 对：每条 TCP 连接不再创建 `<tun addr>:port` 的本地内核
//!   socket（Windows 上这是内存占用的主要来源，内核自动调优缓冲很大）；
//! - 无逐包 NAT 改写 + 校验和重算：Linux 上 CPU 占用显著降低；
//! - 每连接内存可控：smoltcp 缓冲 + 应用侧 ring 共 512KiB，且有并发上限。
//!
//! 相对 clash-rs 原版的移植差异：
//! 1. `log` → `tracing`（ant 无 log crate）；
//! 2. `TcpListener::new` / `NetstackDevice::new` 增加 `mtu` 参数
//!    （clash-rs 硬编码 1500，ant MTU 可配置）；
//! 3. `IpPacket::transport()`：跳过 IPv6 扩展头链定位传输层（clash-rs 用
//!    `protocol()` + `payload()`，对 hop-by-hop/routing/dstopts 包会误判
//!    协议且 TCP 载荷错位）；
//! 4. iface notifier 发送失败不再 panic（栈关闭期属正常路径）；
//! 5. TCP 缓冲 256KiB → 128KiB + 并发 socket 上限 1024（SYN 洪泛内存放大
//!    防护；对齐 mihomo「内存占用优先于峰值性能」的取舍）；
//! 6. `TcpStream::abort()`：dial 失败/规则拒绝时发 RST（对齐 sing-tun NAT
//!    失败语义），而非 Drop 的 drain-then-FIN。

#[path = "gvisor_debug.rs"]
mod debug;
#[path = "gvisor_device.rs"]
mod device;
#[path = "gvisor_packet.rs"]
mod packet;
#[path = "gvisor_ring_buffer.rs"]
mod ring_buffer;
#[path = "gvisor_stack.rs"]
mod stack;
#[path = "gvisor_tcp_listener.rs"]
mod tcp_listener;
#[path = "gvisor_tcp_stream.rs"]
mod tcp_stream;
#[path = "gvisor_udp_socket.rs"]
mod udp_socket;

pub use stack::{NetStack, Packet};
pub use tcp_stream::TcpStream;
pub use udp_socket::{SplitWrite, UdpSocket};
