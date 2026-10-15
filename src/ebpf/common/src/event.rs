//! Ring-buffer event submitted by the datapath to userspace.

/// Event kinds carried on `EVENT_RINGBUF`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntEventType {
    /// A new flow was classified by the TC ingress program (observability;
    /// emitted at most once per flow, throttled by conntrack).
    NewFlow = 0,
    /// A map insert failed (capacity overflow or memory pressure).
    MapOverflow = 1,
    /// A flow was dropped by a `block` routing decision.
    Blocked = 2,
}

const _ANT_EVENT_TYPE_SIZE: () = assert!(core::mem::size_of::<AntEventType>() == 4);

/// Layout (repr(C), total 56 bytes, alignment 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AntEvent {
    pub timestamp: u64,
    pub type_: u32,
    /// RouteAction applied to the flow.
    pub action: u8,
    /// L4 protocol (IPPROTO_TCP / IPPROTO_UDP).
    pub l4proto: u8,
    pub pad: [u8; 2],
    /// Rule id behind the decision (0 = default catch-all).
    pub rule_id: u32,
    pub sip: [u32; 4],
    pub dip: [u32; 4],
    pub sport: u16,
    pub dport: u16,
}

const _ANT_EVENT_SIZE: () = assert!(core::mem::size_of::<AntEvent>() == 56);
const _ANT_EVENT_ALIGN: () = assert!(core::mem::align_of::<AntEvent>() == 8);
const _ANT_EVENT_TIMESTAMP_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, timestamp) == 0);
const _ANT_EVENT_TYPE_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, type_) == 8);
const _ANT_EVENT_ACTION_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, action) == 12);
const _ANT_EVENT_L4PROTO_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, l4proto) == 13);
const _ANT_EVENT_RULE_ID_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, rule_id) == 16);
const _ANT_EVENT_SIP_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, sip) == 20);
const _ANT_EVENT_DIP_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, dip) == 36);
const _ANT_EVENT_SPORT_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, sport) == 52);
const _ANT_EVENT_DPORT_OFFSET: () = assert!(core::mem::offset_of!(AntEvent, dport) == 54);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for AntEvent {}

/// Format an [`AntEvent`] address field (four network-order words holding an
/// IPv6 address or an IPv4-mapped one) for logging.
#[cfg(not(target_arch = "bpf"))]
pub fn event_ip(chunks: &[u32; 4]) -> core::net::IpAddr {
    let mut bytes = [0u8; 16];
    for (i, chunk) in chunks.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk.to_ne_bytes());
    }
    let v6 = core::net::Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => core::net::IpAddr::V4(v4),
        None => core::net::IpAddr::V6(v6),
    }
}
