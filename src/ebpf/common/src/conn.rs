//! Connection state shared between the eBPF datapath and the userspace
//! janitor. All fields are `repr(C)` so the binary layout is identical
//! regardless of compiler or target triple.

use crate::{ACTION_MARK_MASK, ACTION_MARK_SHIFT, TPROXY_MARK};
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Unified connection state stored in CONN_STATE_MAP (hash map).
///
/// Layout (repr(C), total 24 bytes):
///   offset 0:  last_seen_ns: u64
///   offset 8:  state: u8 (TcpState for TCP)
///   offset 9:  action: u8 (cached RouteAction)
///   offset 10: padding: [u8; 2]
///   offset 12: rule_id: u32
///   offset 16: padding: [u8; 8]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnState {
    pub last_seen_ns: u64,
    pub state: u8,
    pub action: u8,
    pub padding: [u8; 2],
    pub rule_id: u32,
    pub padding2: [u8; 8],
}

const _CONN_STATE_SIZE: () = assert!(core::mem::size_of::<ConnState>() == 24);
const _CONN_STATE_ALIGN: () = assert!(core::mem::align_of::<ConnState>() == 8);
const _CONN_STATE_LAST_SEEN_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, last_seen_ns) == 0);
const _CONN_STATE_STATE_OFFSET: () = assert!(core::mem::offset_of!(ConnState, state) == 8);
const _CONN_STATE_ACTION_OFFSET: () = assert!(core::mem::offset_of!(ConnState, action) == 9);
const _CONN_STATE_RULE_ID_OFFSET: () = assert!(core::mem::offset_of!(ConnState, rule_id) == 12);

/// CONN_STATE_MAP capacity.
pub const MAX_CONN_STATE_NUM: u32 = 65536 * 4;

/// Conn-state entry timeouts used by the eBPF datapath and userspace janitor.
pub const TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s
pub const TCP_CONN_STATE_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10 s
pub const UDP_CONN_STATE_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s backstop

/// Slots of the CONN_STATE_OCCUPANCY per-CPU array.
pub const OCCUPANCY_INSERTS: u32 = 0;
pub const OCCUPANCY_EBPF_DELETES: u32 = 1;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Active = 0,
    Closing = 1,
}

/// Matches the C enum bpf_stats_key (u32 underlying type).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfStatsKey {
    TcpConnOverflow = 0,
    RedirectTrackInsertFailure = 1,
    CookiePidInsertFailure = 2,
    LpmRouteInsertFailure = 3,
    ConnStateInsertFailure = 4,
}

pub const BPF_STATS_MAP_LEN: u32 = 5;

#[inline(always)]
pub fn tcp_conn_state_expired(state: &ConnState, elapsed_ns: u64) -> bool {
    if state.state == TcpState::Closing as u8 {
        elapsed_ns > TCP_CONN_STATE_CLOSING_TIMEOUT_NS
    } else {
        // Active backstop: a silently abandoned connection must not pin a
        // map slot forever.
        elapsed_ns > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
    }
}

/// Encode the datapath action into the skb mark, preserving the tproxy
/// fwmark low bits (the fwmark mask `0xffffff80` only touches bits 0-6).
#[inline(always)]
pub const fn mark_with_action(mark: u32, action: u8) -> u32 {
    (mark & !ACTION_MARK_MASK) | ((action as u32) << ACTION_MARK_SHIFT)
}

/// Extract the datapath action code from an skb mark.
#[inline(always)]
pub const fn mark_action(mark: u32) -> u8 {
    ((mark & ACTION_MARK_MASK) >> ACTION_MARK_SHIFT) as u8
}

const _MARK_HELPERS: () = {
    let m = mark_with_action(TPROXY_MARK, 3);
    assert!(m & !ACTION_MARK_MASK == TPROXY_MARK);
    assert!(mark_action(m) == 3);
    assert!(mark_action(TPROXY_MARK) == 0);
};

/// Scratch context for the packet parser (per-CPU, one slot).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParseTransportCtx {
    pub ethh: EthHdr,      // struct ethhdr
    pub iph: Ipv4Hdr,      // struct ipv4hdr
    pub ipv6h: Ipv6Hdr,    // struct ipv6hdr
    pub icmp6h: Icmpv6Hdr, // struct icmp6hdr
    pub tcph: TcpHdr,      // struct tcphdr
    pub udph: UdpHdr,      // struct udphdr
    pub ihl: u8,           // IP header length in 4-byte units
    pub l4proto: u8,       // Actual L4 protocol
    pub listener_l4proto: u8,
    pub is_fragmented: u8,
}

/// Parsed packet view handed to the routing decision.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParsedPacket {
    pub ethh: EthHdr,
    pub tuples: Tuples,
    pub tcph: TcpHdr,
    pub udph: UdpHdr,
    pub l4proto: u8,
    pub listener_l4proto: u8,
    pub is_fragmented: u8,
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ConnState {}

use crate::redirect::Tuples;
