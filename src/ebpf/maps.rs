//! Typed handles over the datapath maps.
//!
//! Maps are *taken* out of the loaded `Ebpf` object so they can be owned
//! independently: the control maps stay with the manager (route sync,
//! readiness, stats), the flow maps move into the janitor task and the
//! ring buffer into the event consumer.

use aya::{
    Ebpf,
    maps::{Array, HashMap, LpmTrie, MapData, PerCpuArray, RingBuf, lpm_trie::Key},
};
use anyhow::{Context, Result};

use ant_ebpf_common::{
    DATAPATH_FLAG_READY, OutboundStatsCounters, RouteAction, RouteDecision,
    conn::{BpfStatsKey, ConnState},
    redirect::{PIDName, RedirectEntry, RedirectTuple},
    TuplesKey,
};

/// Maps the manager keeps (routing + observability).
pub(super) struct ControlMaps {
    flags: Array<MapData, u32>,
    pub route_lpm: LpmTrie<MapData, [u32; 4], RouteDecision>,
    pub default_route: Array<MapData, RouteDecision>,
    stats: PerCpuArray<MapData, OutboundStatsCounters>,
    bpf_stats: Array<MapData, u64>,
    occupancy: PerCpuArray<MapData, u64>,
}

/// Maps the janitor sweeps (per-flow state).
pub(super) struct FlowMaps {
    pub conn_state: HashMap<MapData, TuplesKey, ConnState>,
    pub redirect_track: HashMap<MapData, RedirectTuple, RedirectEntry>,
    pub cookie_pid: HashMap<MapData, u64, PIDName>,
}

/// Aggregate counters exposed to the API / logs.
#[derive(Debug, Default, Clone)]
pub struct DatapathStats {
    pub direct: OutboundStatsCounters,
    pub block: OutboundStatsCounters,
    pub proxy: OutboundStatsCounters,
    pub conn_state_inserts: u64,
    pub conn_state_deletes: u64,
    pub tcp_conn_overflow: u64,
    pub redirect_insert_failures: u64,
    pub cookie_insert_failures: u64,
    pub conn_state_insert_failures: u64,
}

pub(super) fn take_control(bpf: &mut Ebpf) -> Result<ControlMaps> {
    Ok(ControlMaps {
        flags: Array::try_from(take(bpf, "DATAPATH_FLAGS_MAP")?)?,
        route_lpm: LpmTrie::try_from(take(bpf, "ROUTE_LPM_MAP")?)?,
        default_route: Array::try_from(take(bpf, "DEFAULT_ROUTE")?)?,
        stats: PerCpuArray::try_from(take(bpf, "OUTBOUND_STATS")?)?,
        bpf_stats: Array::try_from(take(bpf, "BPF_STATS_MAP")?)?,
        occupancy: PerCpuArray::try_from(take(bpf, "CONN_STATE_OCCUPANCY")?)?,
    })
}

pub(super) fn take_flow(bpf: &mut Ebpf) -> Result<FlowMaps> {
    Ok(FlowMaps {
        conn_state: HashMap::try_from(take(bpf, "CONN_STATE_MAP")?)?,
        redirect_track: HashMap::try_from(take(bpf, "REDIRECT_TRACK")?)?,
        cookie_pid: HashMap::try_from(take(bpf, "COOKIE_PID_MAP")?)?,
    })
}

pub(super) fn take_ringbuf(bpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    RingBuf::try_from(take(bpf, "EVENT_RINGBUF")?).context("EVENT_RINGBUF")
}

fn take(bpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map> {
    bpf.take_map(name).with_context(|| format!("map `{name}` missing from eBPF object"))
}

impl ControlMaps {
    /// Flip the readiness gate. While it is clear, the TC programs pass
    /// every packet through, which is the state ant keeps until a routing
    /// table has been published.
    pub fn set_ready(&mut self, ready: bool) -> Result<()> {
        let value = u32::from(ready) * DATAPATH_FLAG_READY;
        self.flags.set(0, value, 0)?;
        Ok(())
    }

    pub fn ready(&self) -> Result<bool> {
        Ok(self.flags.get(&0, 0)? & DATAPATH_FLAG_READY != 0)
    }

    pub fn stats(&self) -> Result<DatapathStats> {
        let mut out = DatapathStats::default();
        for action in [RouteAction::Direct, RouteAction::Block, RouteAction::Proxy] {
            let slot = action.stats_slot();
            let per_cpu = self.stats.get(&slot, 0)?;
            let mut acc = OutboundStatsCounters::default();
            for counters in per_cpu.iter() {
                acc.tx_packets += counters.tx_packets;
                acc.tx_bytes += counters.tx_bytes;
                acc.rx_packets += counters.rx_packets;
                acc.rx_bytes += counters.rx_bytes;
            }
            match action {
                RouteAction::Direct => out.direct = acc,
                RouteAction::Block => out.block = acc,
                RouteAction::Proxy => out.proxy = acc,
            }
        }

        let stat = |key: BpfStatsKey| -> u64 { self.bpf_stats.get(&(key as u32), 0).unwrap_or(0) };
        out.tcp_conn_overflow = stat(BpfStatsKey::TcpConnOverflow);
        out.redirect_insert_failures = stat(BpfStatsKey::RedirectTrackInsertFailure);
        out.cookie_insert_failures = stat(BpfStatsKey::CookiePidInsertFailure);
        out.conn_state_insert_failures = stat(BpfStatsKey::ConnStateInsertFailure);

        let per_cpu = self.occupancy.get(&0, 0);
        if let Ok(values) = per_cpu {
            out.conn_state_inserts = values.iter().sum();
        }
        let per_cpu = self.occupancy.get(&1, 0);
        if let Ok(values) = per_cpu {
            out.conn_state_deletes = values.iter().sum();
        }
        Ok(out)
    }

    /// Remove previously published LPM entries before publishing a new table.
    pub fn clear_routes(&mut self, keys: &[Key<[u32; 4]>]) {
        for key in keys {
            let _ = self.route_lpm.remove(key);
        }
    }

    pub fn insert_route(&mut self, key: &Key<[u32; 4]>, decision: RouteDecision) -> Result<()> {
        self.route_lpm.insert(key, decision, 0)?;
        Ok(())
    }

    pub fn set_default_route(&mut self, decision: RouteDecision) -> Result<()> {
        self.default_route.set(0, decision, 0)?;
        Ok(())
    }
}
