//! Map definitions for the ant eBPF datapath.
//!
//! All maps are BTF maps (`#[btf_map]`), so the kernel creates them with
//! BTF-typed key/value sizes and userspace (aya) can read/write them with
//! plain Rust structs.

use aya_ebpf::btf_maps::{Array, HashMap, LpmTrie, PerCpuArray, RingBuf};
use aya_ebpf::macros::btf_map;
use aya_ebpf::Global;
use ant_ebpf_common::{
    conn::{
        BpfStatsKey, BPF_STATS_MAP_LEN, ConnState, MAX_CONN_STATE_NUM, OCCUPANCY_EBPF_DELETES,
        ParseTransportCtx, ParsedPacket, tcp_conn_state_expired,
    },
    redirect::{PIDName, RedirectEntry, RedirectTuple, TuplesKey},
    AntParam, OutboundStatsCounters, RouteAction, RouteDecision, OUTBOUND_STATS_MAP_LEN,
};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

/// Cookie → PID/process-name mapping filled by the cgroup hooks.
pub const MAX_COOKIE_PID_PNAME_MAPPING_NUM: usize = 65536;
/// REDIRECT_TRACK capacity (live redirected flows).
pub const MAX_REDIRECT_TRACK_NUM: usize = 65536;
/// ROUTE_LPM_MAP capacity (IP-CIDR rules synced from userspace).
pub const MAX_ROUTE_LPM_NUM: usize = 262144;
/// EVENT_RINGBUF size in bytes.
pub const EVENT_RINGBUF_SIZE: usize = 262144;

/// Lazy-timestamp update interval: only bump `last_seen_ns` when > 1 s
/// elapsed. Time comparisons use `wrapping_sub` for verifier-friendly
/// monotonic arithmetic.
pub const AUXILIARY_MAP_REFRESH_INTERVAL_NS: u64 = 1_000_000_000;

pub const TCP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000; // 1 second

/// Fixed datapath parameters, written once at load time.
#[unsafe(no_mangle)]
pub static PARAM: Global<AntParam> = Global::new(AntParam::DEFAULT);

/// Datapath readiness + admission flags. Bit 0 = DATAPATH_FLAG_READY.
#[btf_map]
pub static DATAPATH_FLAGS_MAP: Array<u32, 1> = Array::new();

#[inline(always)]
pub fn datapath_ready() -> bool {
    DATAPATH_FLAGS_MAP
        .get(0)
        .is_some_and(|flags| *flags & ant_ebpf_common::DATAPATH_FLAG_READY != 0)
}

/// cookie → process identity (cgroup sock hooks).
#[btf_map]
pub static COOKIE_PID_MAP: HashMap<u64, PIDName, MAX_COOKIE_PID_PNAME_MAPPING_NUM, 1> =
    HashMap::new();

/// IP-CIDR → routing decision (synced from ant's route rules).
///
/// The map key is aya's `Key<[u32; 4]>`: a `u32` prefix length in bits
/// followed by four big-endian words. IPv4 entries are stored IPv4-mapped,
/// so a `/24` uses `prefix_len = 96 + 24` and a full-address lookup uses
/// `prefix_len = 128`.
#[btf_map]
pub static ROUTE_LPM_MAP: LpmTrie<[u32; 4], RouteDecision, MAX_ROUTE_LPM_NUM> = LpmTrie::new();

/// Catch-all decision when no LPM entry matches (ant's `MATCH` rule).
#[btf_map]
pub static DEFAULT_ROUTE: Array<RouteDecision, 1> = Array::new();

/// Connection tracking for classified flows.
#[btf_map]
pub static CONN_STATE_MAP: HashMap<TuplesKey, ConnState, { MAX_CONN_STATE_NUM as usize }, 1> =
    HashMap::new();

/// Occupancy gauge for CONN_STATE_MAP (per-CPU, contention-free).
#[btf_map]
pub static CONN_STATE_OCCUPANCY: PerCpuArray<u64, 2> = PerCpuArray::new();

/// Insert failures: conn TCP, redirect-track, cookie-PID.
#[btf_map]
pub static BPF_STATS_MAP: Array<u64, { BPF_STATS_MAP_LEN as usize }> = Array::new();

#[inline(always)]
pub fn increment_bpf_stat(key: BpfStatsKey) {
    if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(key as u32) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Request-direction flow tracking (original tuple → decision).
#[btf_map]
pub static REDIRECT_TRACK: HashMap<RedirectTuple, RedirectEntry, MAX_REDIRECT_TRACK_NUM, 1> =
    HashMap::new();

/// Per-action traffic counters (per-CPU).
#[btf_map]
pub static OUTBOUND_STATS: PerCpuArray<
    OutboundStatsCounters,
    { OUTBOUND_STATS_MAP_LEN as usize },
> = PerCpuArray::new();

/// Events submitted to userspace.
#[btf_map]
pub static EVENT_RINGBUF: RingBuf<ant_ebpf_common::AntEvent, EVENT_RINGBUF_SIZE> = RingBuf::new();

/// Per-CPU scratch for the packet parser.
#[btf_map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx, 1> = PerCpuArray::new();

/// Per-CPU scratch for the parsed packet view.
#[btf_map]
pub static PKT_SCRATCH_KEY: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();

#[inline(always)]
pub fn occupancy_add(slot: u32) {
    if let Some(counter) = CONN_STATE_OCCUPANCY.get_ptr_mut(slot) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Expire a conntrack entry lazily on hit (TCP closing / UDP timeout).
#[inline(always)]
pub fn conn_state_expire_if_stale(key: &TuplesKey, is_udp: bool) {
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return;
    };
    let state = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    let elapsed = now.wrapping_sub(state.last_seen_ns);
    let expired = if is_udp {
        elapsed > ant_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS
    } else {
        tcp_conn_state_expired(state, elapsed)
    };
    if expired && CONN_STATE_MAP.remove(key).is_ok() {
        occupancy_add(OCCUPANCY_EBPF_DELETES);
    }
}

/// Refresh (or create) the request-direction redirect entry.
#[inline(always)]
pub fn redirect_track_touch(
    key: &RedirectTuple,
    ifindex: u32,
    action: u8,
    rule_id: u32,
) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(ptr) = REDIRECT_TRACK.get_ptr_mut(key) {
        let entry = unsafe { &mut *ptr };
        if now.wrapping_sub(entry.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
            entry.last_seen_ns = now;
        }
        return true;
    }
    let entry = RedirectEntry {
        last_seen_ns: now,
        ifindex,
        action,
        padding: [0; 3],
        rule_id,
    };
    if REDIRECT_TRACK.insert(key, entry, 0).is_err() {
        increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
        return false;
    }
    true
}

/// Refresh only `last_seen_ns` of an existing redirect entry (egress reply
/// path): the original `ifindex` / action / rule must not be overwritten.
#[inline(always)]
pub fn redirect_track_refresh(key: &RedirectTuple) {
    let Some(ptr) = REDIRECT_TRACK.get_ptr_mut(key) else {
        return;
    };
    let entry = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    if now.wrapping_sub(entry.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        entry.last_seen_ns = now;
    }
}

/// Stats slot helper re-export for the datapath modules.
#[inline(always)]
pub fn stats_slot(action: u8) -> u32 {
    RouteAction::from_u8(action).map_or(0, |a| a.stats_slot())
}
