use std::net::{Ipv4Addr, Ipv6Addr};

/// 深度 trace：打印 IP 包摘要（版本/协议/长度/源目地址）。
///
/// clash-rs 原版用 smoltcp `PrettyPrinter`（需要 verbose/log feature）；
/// ant 无这些 feature，改为轻量摘要。仅在高 fan-out 诊断时开启 TRACE。
pub(crate) fn trace_ip_packet(message: &str, packet: &[u8]) {
    if !tracing::enabled!(tracing::Level::TRACE) {
        return;
    }
    if packet.len() < 20 {
        tracing::trace!(target: "gvisor", message, len = packet.len(), "short packet");
        return;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            let proto = packet[9];
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            tracing::trace!(target: "gvisor", message, proto, len = packet.len(), src = %src, dst = %dst, "ipv4");
        }
        6 => {
            let proto = packet[6];
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            tracing::trace!(target: "gvisor", message, proto, len = packet.len(), src = %src, dst = %dst, "ipv6");
        }
        v => {
            tracing::trace!(target: "gvisor", message, version = v, len = packet.len(), "unknown ip version");
        }
    }
}
