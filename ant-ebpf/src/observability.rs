//! [方案六] per-CPU 数据面计数 + 每源新流限速，移植自 honk 的
//! `stats.rs` / `new_flow_limit.rs`。
//!
//! 计数放进 PerCpuArray：每包只写本 CPU 的槽位，没有原子操作也没有跨核
//! 缓存行竞争；用户态定期把各 CPU 的值加起来输出。新流预算放进
//! LruPerCpuHashMap，窗口切换是一次就地写，满表只遗忘某个源最近的计数。

use crate::maps::{DATAPATH_STATS, NEW_FLOW_RATE, PARAM};
use crate::packet::Pkt;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use ant_ebpf_common::NewFlowWindow;

#[inline(always)]
fn direct(bytes: u64) {
    if let Some(p) = DATAPATH_STATS.get_ptr_mut(0) {
        let c = unsafe { &mut *p };
        c.direct_pkts += 1;
        c.direct_bytes += bytes;
    }
}

#[inline(always)]
fn proxy(bytes: u64) {
    if let Some(p) = DATAPATH_STATS.get_ptr_mut(0) {
        let c = unsafe { &mut *p };
        c.proxy_pkts += 1;
        c.proxy_bytes += bytes;
    }
}

#[inline(always)]
fn reply(bytes: u64) {
    if let Some(p) = DATAPATH_STATS.get_ptr_mut(0) {
        let c = unsafe { &mut *p };
        c.reply_pkts += 1;
        c.reply_bytes += bytes;
    }
}

#[inline(always)]
fn bump_one(field: u8) {
    if let Some(p) = DATAPATH_STATS.get_ptr_mut(0) {
        let c = unsafe { &mut *p };
        match field {
            0 => c.block_pkts += 1,
            1 => c.frag_inherited += 1,
            2 => c.new_flow_limited += 1,
            // [方案七] 流表写入失败与 TCP 生命周期事件。
            3 => c.track_insert_failed += 1,
            4 => c.tcp_syn_reset += 1,
            5 => c.tcp_closing += 1,
            // [方案八] TCP/53 DNS-over-TCP 劫持命中数。
            6 => c.dns_tcp_pkts += 1,
            _ => {}
        }
    }
}

pub fn count_direct(ctx_len: u32) {
    direct(ctx_len as u64);
}
pub fn count_proxy(ctx_len: u32) {
    proxy(ctx_len as u64);
}
pub fn count_reply(ctx_len: u32) {
    reply(ctx_len as u64);
}
pub fn count_block() {
    bump_one(0);
}
pub fn count_frag_inherited() {
    bump_one(1);
}
pub fn count_new_flow_limited() {
    bump_one(2);
}
pub fn count_track_insert_failed() {
    bump_one(3);
}
pub fn count_tcp_syn_reset() {
    bump_one(4);
}
pub fn count_tcp_closing() {
    bump_one(5);
}
/// [方案八] 一个 TCP/53 包被判进用户态 DNS 引擎。
pub fn count_dns_tcp() {
    bump_one(6);
}

/// 每源每秒新流预算。`PARAM.new_flow_limit == 0` 时整条路径短路返回，
/// 不读任何表（默认关闭，不改变原有行为）。返回 true 表示预算已耗尽，
/// 调用方应丢弃这个新流首包。
#[inline(always)]
pub fn new_flow_exceeded(pkt: &Pkt) -> bool {
    let limit = PARAM.load().new_flow_limit;
    if limit == 0 {
        return false;
    }
    let second = (unsafe { bpf_ktime_get_ns() } / 1_000_000_000) as u32;
    let src = pkt.src_ip;
    if let Some(p) = NEW_FLOW_RATE.get_ptr_mut(src) {
        let w = unsafe { &mut *p };
        if w.second != second {
            w.second = second;
            w.count = 1;
            return false;
        }
        if w.count >= limit {
            return true;
        }
        w.count += 1;
        false
    } else {
        // 插入失败只让这一次尝试不被计数，不影响转发。
        let _ = NEW_FLOW_RATE.insert(
            src,
            NewFlowWindow {
                second,
                count: 1,
            },
            0,
        );
        false
    }
}
