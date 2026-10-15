//! Ring-buffer event submission to userspace.

use crate::maps::EVENT_RINGBUF;
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use ant_ebpf_common::event::{AntEvent, AntEventType};

#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn send_ant_event(
    type_: AntEventType,
    action: u8,
    l4proto: u8,
    rule_id: u32,
    sip: &[u32; 4],
    dip: &[u32; 4],
    sport: u16,
    dport: u16,
) {
    let mut e: AntEvent = unsafe { core::mem::zeroed() };
    e.timestamp = unsafe { bpf_ktime_get_ns() };
    e.type_ = type_ as u32;
    e.action = action;
    e.l4proto = l4proto;
    e.rule_id = rule_id;
    e.sip.copy_from_slice(sip);
    e.dip.copy_from_slice(dip);
    e.sport = sport;
    e.dport = dport;
    let _ = EVENT_RINGBUF.output(e, 0);
}
