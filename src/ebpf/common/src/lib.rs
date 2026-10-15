#![no_std]

//! Types and constants shared between the ant userspace eBPF manager
//! (`src/ebpf`) and the eBPF datapath (`src/ebpf/program`).
//!
//! Both sides must agree on struct layouts and map keys; layout assertions
//! at the bottom of each module pin the ABI.

pub mod conn;
pub mod dae_ip;
pub mod event;
pub mod redirect;

pub use crate::conn::{ConnState, TcpState};
pub use crate::event::{AntEvent, AntEventType};
pub use crate::redirect::{PIDName, RedirectEntry, RedirectTuple, Tuples, TuplesKey};

pub const TASK_COMM_LEN: usize = 16;

/// skb mark written on hijacked traffic that must go to the tproxy inbound.
/// Aligned with `ip_auto_route::TPROXY_FWMARK` so the existing policy-routing
/// pipeline (`ip rule fwmark 0x80 → table local → lo → tproxy`) delivers the
/// packet unchanged.
pub const TPROXY_MARK: u32 = 0x0000_0080;

/// Bit offset of the datapath action code inside the skb mark (bits 16-23).
/// The low bits keep the tproxy fwmark intact; bits 24-31 stay free for the
/// fwmark mask used by ip-auto-route (`meta mark & 0xffffff80 | 0x80`).
pub const ACTION_MARK_SHIFT: u32 = 16;
pub const ACTION_MARK_MASK: u32 = 0xff << ACTION_MARK_SHIFT;

/// Socket mark bit used by the control plane to tell the eBPF datapath to
/// pass its own traffic through without touching it. ant sets this via
/// `global.mark` (SO_MARK); the datapath compares the whole mark.
pub const ANT_BYPASS_MARK: u32 = 0x0000_0100;

/// Datapath readiness flag: while 0, the TC ingress program passes every
/// packet untouched. Userspace flips it to 1 only after the routing tables
/// are published.
pub const DATAPATH_FLAG_READY: u32 = 1 << 0;

/// Datapath actions (values stored in maps and in the skb mark).
/// Kept small and stable — they double as `OUTBOUND_STATS` slot indices.
///
/// `0` is deliberately *not* an action: an unset action code means "the
/// datapath made no decision", which is what the nft fallback rules key on
/// (`meta mark & 0x00ff0000 == 0` → legacy mark + tproxy path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteAction {
    /// Pass through untouched (no proxy).
    Direct = 1,
    /// Drop the packet.
    Block = 2,
    /// Mark for the tproxy inbound; userspace makes the final decision
    /// (domain sniffing, proxy-group selection).
    Proxy = 3,
}

impl RouteAction {
    #[inline(always)]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Direct),
            2 => Some(Self::Block),
            3 => Some(Self::Proxy),
            _ => None,
        }
    }

    /// Map the action to its `OUTBOUND_STATS` per-CPU array slot.
    /// Slot 0..3 minus the reserved "no decision" code 0.
    #[inline(always)]
    pub const fn stats_slot(self) -> u32 {
        self as u32 - 1
    }
}

/// Number of `OUTBOUND_STATS` slots: one per [`RouteAction`].
pub const OUTBOUND_STATS_MAP_LEN: u32 = 3;

/// LPM trie key for IP/CIDR routing.
/// Matches the kernel's `struct bpf_lpm_trie_key` layout:
/// prefixlen (u32) + data (4 × u32 = IPv6 / IPv4-mapped).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct LpmKey {
    pub prefix_len: u32,
    pub data: [u32; 4],
}

impl LpmKey {
    /// Build an LPM key from an IPv4 CIDR (`a.b.c.d/len`).
    #[cfg(not(target_arch = "bpf"))]
    pub fn from_ipv4(addr: core::net::Ipv4Addr, prefix_len: u32) -> Self {
        let mut data = [0u32; 4];
        data[3] = u32::from(addr).to_be();
        Self {
            prefix_len: prefix_len + 96,
            data,
        }
    }

    /// Build an LPM key from an IPv6 CIDR.
    #[cfg(not(target_arch = "bpf"))]
    pub fn from_ipv6(addr: core::net::Ipv6Addr, prefix_len: u32) -> Self {
        let octets = addr.octets();
        let mut data = [0u32; 4];
        for (i, chunk) in data.iter_mut().enumerate() {
            *chunk = u32::from_be_bytes([
                octets[i * 4],
                octets[i * 4 + 1],
                octets[i * 4 + 2],
                octets[i * 4 + 3],
            ]);
        }
        Self {
            prefix_len,
            data,
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for LpmKey {}

/// One routing entry stored in the `ROUTE_LPM_MAP` trie / `DEFAULT_ROUTE`
/// array: what the datapath does with a matching flow.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RouteDecision {
    pub action: u8,
    pub pad: [u8; 3],
    /// Index of the ant route rule that produced this entry (for events and
    /// debugging; 0 = default catch-all).
    pub rule_id: u32,
}

const _ROUTE_DECISION_SIZE: () = assert!(core::mem::size_of::<RouteDecision>() == 8);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RouteDecision {}

/// Fixed parameters written once at load time by userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AntParam {
    /// Local tproxy inbound port (0 = none published).
    pub tproxy_port: u32,
    /// PID of the ant process; packets from this PID bypass the datapath.
    pub ant_pid: u32,
    /// skb mark identifying ant's own sockets (`global.mark`).
    pub ant_socket_mark: u32,
    /// `lo` interface index — the `wan_egress` redirect target that feeds
    /// locally-generated traffic back through the host's tproxy pipeline.
    pub lo_ifindex: u32,
    /// Primary IPv4 address of the LAN (or WAN when single-homed) interface,
    /// host byte order. `wan_egress` passes traffic destined for it through
    /// untouched so connections to ant's own management ports cannot loop.
    pub local_ip: u32,
    /// Whether `bpf_get_current_task` is available (argv0 process names).
    pub has_bpf_get_current_task: u8,
    pub pad: [u8; 3],
}

impl AntParam {
    pub const DEFAULT: Self = Self {
        tproxy_port: 0,
        ant_pid: 0,
        ant_socket_mark: 0,
        lo_ifindex: 0,
        local_ip: 0,
        has_bpf_get_current_task: 0,
        pad: [0; 3],
    };
}

impl Default for AntParam {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _ANT_PARAM_SIZE: () = assert!(core::mem::size_of::<AntParam>() == 24);
const _ANT_PARAM_ALIGN: () = assert!(core::mem::align_of::<AntParam>() == 4);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for AntParam {}

/// Per-action traffic counters for the TC datapath.
///
/// Counters live in the per-CPU `OUTBOUND_STATS` array so the per-packet
/// update never contends across CPUs. `tx` (client → decision point) is
/// counted at ingress when the routing decision lands; `rx` (decision point
/// → client) is counted at egress on the reply path.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct OutboundStatsCounters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

impl OutboundStatsCounters {
    #[inline(always)]
    pub const fn for_action(action: RouteAction) -> u32 {
        action.stats_slot()
    }

    #[inline(always)]
    pub fn add_tx(&mut self, bytes: u64) {
        self.tx_packets = self.tx_packets.wrapping_add(1);
        self.tx_bytes = self.tx_bytes.wrapping_add(bytes);
    }

    #[inline(always)]
    pub fn add_rx(&mut self, bytes: u64) {
        self.rx_packets = self.rx_packets.wrapping_add(1);
        self.rx_bytes = self.rx_bytes.wrapping_add(bytes);
    }
}

const _OUTBOUND_STATS_SIZE: () = assert!(core::mem::size_of::<OutboundStatsCounters>() == 32);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for OutboundStatsCounters {}
