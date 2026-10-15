//! Periodic sweep of the per-flow maps.
//!
//! The datapath already expires entries lazily on hit, but a flow that goes
//! silent never gets a hit again, so something has to reap it. Sweep
//! intervals are deliberately long: the maps are large and iteration is not
//! free.
//!
//! The sweep also implements route-table invalidation: when
//! [`EbpfManager::sync_routes`] publishes a new table it bumps a generation
//! counter, and the next sweep flushes every cached decision so flows are
//! re-evaluated against the new rules.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::debug;

use super::maps::FlowMaps;
use super::probe::ktime_now_ns;
use ant_ebpf_common::conn::{
    ConnState, TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS,
    TcpState, UDP_CONN_STATE_TIMEOUT_NS,
};

/// Sweep period.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// COOKIE_PID_MAP entries linger far longer than flows: the socket release
/// hook usually removes them first, this is the backstop.
const COOKIE_PID_TIMEOUT_NS: u64 = 300_000_000_000;

pub(super) fn spawn(
    mut flow: FlowMaps,
    generation: Arc<AtomicU64>,
    mut shutdown: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut last_generation = generation.load(Ordering::Relaxed);
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        // The first tick completes immediately; skip it.
        tick.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = tick.tick() => {}
            }
            let current = generation.load(Ordering::Relaxed);
            if current != last_generation {
                last_generation = current;
                debug!("ebpf: route table changed — flushing cached flow decisions");
                flush(&mut flow);
                continue;
            }
            sweep(&mut flow);
        }
    });
}

fn flush(flow: &mut FlowMaps) {
    let mut cleared = 0usize;
    cleared += drain(&mut flow.conn_state);
    cleared += drain(&mut flow.redirect_track);
    debug!("ebpf: janitor flushed {cleared} cached flow entries");
}

fn drain<K, V>(map: &mut aya::maps::HashMap<aya::maps::MapData, K, V>) -> usize
where
    K: aya::Pod,
    V: aya::Pod,
{
    let keys: Vec<K> = map.keys().filter_map(|k| k.ok()).collect();
    let mut removed = 0;
    for key in keys {
        if map.remove(&key).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn sweep(flow: &mut FlowMaps) {
    let now = ktime_now_ns();
    if now == 0 {
        return;
    }

    let conn_expired: Vec<_> = flow
        .conn_state
        .iter()
        .filter_map(|item| item.ok())
        .filter(|(_, state)| conn_state_expired(state, now))
        .map(|(key, _)| key)
        .collect();
    let mut expired = conn_expired.len();
    for key in conn_expired {
        let _ = flow.conn_state.remove(&key);
    }

    let redirect_expired: Vec<_> = flow
        .redirect_track
        .iter()
        .filter_map(|item| item.ok())
        .filter(|(_, entry)| now.wrapping_sub(entry.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS)
        .map(|(key, _)| key)
        .collect();
    expired += redirect_expired.len();
    for key in redirect_expired {
        let _ = flow.redirect_track.remove(&key);
    }

    let cookie_expired: Vec<u64> = flow
        .cookie_pid
        .iter()
        .filter_map(|item| item.ok())
        .filter(|(_, entry)| now.wrapping_sub(entry.last_seen_ns) > COOKIE_PID_TIMEOUT_NS)
        .map(|(key, _)| key)
        .collect();
    for key in cookie_expired {
        let _ = flow.cookie_pid.remove(&key);
    }

    if expired > 0 {
        debug!("ebpf: janitor expired {expired} flow entries");
    }
}

fn conn_state_expired(state: &ConnState, now: u64) -> bool {
    let elapsed = now.wrapping_sub(state.last_seen_ns);
    if state.state == TcpState::Closing as u8 {
        elapsed > TCP_CONN_STATE_CLOSING_TIMEOUT_NS
    } else {
        // Active TCP and UDP share the backstop.
        elapsed > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS.min(UDP_CONN_STATE_TIMEOUT_NS)
    }
}
