//! Flow-level connection tracking for the ant datapath.
//!
//! Simplified relative to honk: ant's datapath only *marks* packets and
//! lets the existing nft/ip-rule pipeline deliver them to the tproxy
//! inbound, so there is no UDP decision-token machinery, no WAN/LAN
//! direction bit and no routing-generation handoff. What remains is the
//! per-flow decision cache:
//!
//! - TCP: only pure SYNs are classified; every other segment of a flow we
//!   opened is served from the cache (the cached `proxy` mark is what keeps
//!   established segments on the local-delivery path).
//! - UDP: the first datagram is classified, the rest hit the cache until
//!   the entry expires (lazily on hit, or swept by the userspace janitor).

use crate::maps::{
    CONN_STATE_MAP, TCP_CONN_STATE_UPDATE_INTERVAL_NS, conn_state_expire_if_stale,
    increment_bpf_stat, occupancy_add,
};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use ant_ebpf_common::{
    conn::{BpfStatsKey, ConnState, OCCUPANCY_INSERTS, TcpState},
    redirect::TuplesKey,
};
use network_types::tcp::TcpHdr;

/// Refresh `last_seen_ns` lazily: only write back once the shared one-second
/// interval has elapsed, so high-rate flows do not hammer the same cache
/// line. Time comparisons use `wrapping_sub` (verifier-friendly monotonic
/// arithmetic).
#[inline(always)]
fn refresh_last_seen(state: &mut ConnState, now: u64) {
    if now.wrapping_sub(state.last_seen_ns) >= TCP_CONN_STATE_UPDATE_INTERVAL_NS {
        state.last_seen_ns = now;
    }
}

/// Read the entry back through a volatile load: the value lives in map
/// memory, so the compiler must not assume anything about it.
#[inline(always)]
fn snapshot(state: &ConnState) -> ConnState {
    unsafe { core::ptr::read_volatile(state as *const ConnState) }
}

/// Cached decision for an established (non-SYN) TCP segment.
///
/// Returns `None` when the flow is unknown — the caller must then pass the
/// packet through untouched: an established flow whose SYN the datapath
/// never saw was never proxied by it.
#[inline(always)]
pub fn tcp_cached(key: &TuplesKey, tcph: &TcpHdr) -> Option<ConnState> {
    conn_state_expire_if_stale(key, false);
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    let state = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    refresh_last_seen(state, now);
    if tcph.fin() != 0 || tcph.rst() != 0 {
        state.state = TcpState::Closing as u8;
    }
    Some(snapshot(state))
}

/// Cached decision for a UDP flow (any datagram of the tuple).
#[inline(always)]
pub fn udp_cached(key: &TuplesKey) -> Option<ConnState> {
    conn_state_expire_if_stale(key, true);
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    let state = unsafe { &mut *ptr };
    refresh_last_seen(state, unsafe { bpf_ktime_get_ns() });
    Some(snapshot(state))
}

/// Insert (or confirm) a flow decision.
///
/// Returns `false` only when the map is genuinely full — a concurrent
/// insert that won the race counts as success, since its entry stands.
#[inline(always)]
pub fn record(key: &TuplesKey, action: u8, rule_id: u32) -> bool {
    let state = ConnState {
        last_seen_ns: unsafe { bpf_ktime_get_ns() },
        state: TcpState::Active as u8,
        action,
        padding: [0; 2],
        rule_id,
        padding2: [0; 8],
    };
    if CONN_STATE_MAP.insert(key, state, 0u64).is_ok() {
        occupancy_add(OCCUPANCY_INSERTS);
        true
    } else if CONN_STATE_MAP.get_ptr(key).is_none() {
        increment_bpf_stat(BpfStatsKey::ConnStateInsertFailure);
        false
    } else {
        true
    }
}
