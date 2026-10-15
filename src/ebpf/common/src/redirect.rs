//! Flow tuple types shared between the datapath and userspace.

use crate::dae_ip::In6Addr;

/// Directional five-tuple used as the `REDIRECT_TRACK` map key.
///
/// The key is deliberately not canonicalized: the redirecting packet is
/// stored in its original direction and the reply path looks it up using
/// the exact reverse tuple. Keeping both ports and L4 protocol prevents
/// flows sharing an address pair from overwriting one another.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TuplesKey {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
}

const _TUPLES_KEY_SIZE: () = assert!(core::mem::size_of::<TuplesKey>() == 40);

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Tuples {
    pub five: TuplesKey,
    pub dscp: u8,
}

/// Five-tuple plus the action/rule recorded at redirect time; used as the
/// `REDIRECT_TRACK` key (directional, like [`TuplesKey`]).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RedirectTuple {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

impl RedirectTuple {
    /// Construct the directional key from the parsed datapath five-tuple.
    #[inline(always)]
    pub const fn from_tuples(tuples: &TuplesKey) -> Self {
        Self {
            src_ip: tuples.src_ip,
            dst_ip: tuples.dst_ip,
            src_port: tuples.src_port,
            dst_port: tuples.dst_port,
            l4proto: tuples.l4proto,
            padding: [0; 3],
        }
    }

    /// Build the opposite-direction key for a reply packet.
    #[inline(always)]
    pub const fn reverse(self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            l4proto: self.l4proto,
            padding: [0; 3],
        }
    }
}

/// Entry recorded when a flow is marked for the tproxy inbound. The egress
/// program looks the reverse tuple up to (a) strip the hijack mark from
/// reply packets so they reach the client instead of looping back into the
/// local table, and (b) attribute reply traffic in `OUTBOUND_STATS`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RedirectEntry {
    pub last_seen_ns: u64,
    /// Interface the original packet arrived on.
    pub ifindex: u32,
    /// Action applied to the original (request-direction) packet.
    pub action: u8,
    pub padding: [u8; 3],
    /// Rule that produced the decision.
    pub rule_id: u32,
}

const _REDIRECT_ENTRY_SIZE: () = assert!(core::mem::size_of::<RedirectEntry>() == 24);

/// Process identity captured by the cgroup hooks.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PIDName {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; crate::TASK_COMM_LEN],
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TuplesKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RedirectTuple {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RedirectEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for PIDName {}
