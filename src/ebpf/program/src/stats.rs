//! Per-action traffic counters for the TC datapath.
//!
//! Counters live in the per-CPU `OUTBOUND_STATS` array (see `maps.rs`) so
//! the per-packet update never contends across CPUs. `tx` (client →
//! decision point) is counted at ingress when the routing decision lands;
//! `rx` (decision point → client) is counted at egress on the reply path.

use crate::maps::{OUTBOUND_STATS, stats_slot};
use aya_ebpf::programs::TcContext;

#[inline(always)]
fn add_tx(action: u8, bytes: u64) {
    if let Some(ptr) = OUTBOUND_STATS.get_ptr_mut(stats_slot(action)) {
        unsafe { (&mut *ptr).add_tx(bytes) }
    }
}

#[inline(always)]
fn add_rx(action: u8, bytes: u64) {
    if let Some(ptr) = OUTBOUND_STATS.get_ptr_mut(stats_slot(action)) {
        unsafe { (&mut *ptr).add_rx(bytes) }
    }
}

/// Account one packet in the request direction.
#[inline(always)]
pub fn count_tx(ctx: &TcContext, action: u8) {
    add_tx(action, ctx.len() as u64);
}

/// Account one packet in the reply direction.
#[inline(always)]
pub fn count_rx(ctx: &TcContext, action: u8) {
    add_rx(action, ctx.len() as u64);
}
