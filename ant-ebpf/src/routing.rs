//! Kernel routing decision: the whole point of the datapath.
//!
//! Decision order (first match wins), all resolved inside the kernel so
//! direct traffic never leaves the TC hook:
//!   1. DNS hijack   — TCP/UDP dst port 53 (steered to the userspace DNS engine)
//!   2. DOMAIN_ROUTE — per-IP verdicts published by the DNS engine
//!   3. CIDR tries   — longest prefix match on the destination
//!   4. PORT_ROUTE   — destination port table
//!   5. PARAM.default_verdict

use crate::maps::{
    route_generation, CIDR_V4, CIDR_V6, DOMAIN_ROUTE, FLOW_DECISION, PARAM, PORT_ROUTE,
};
use crate::packet::Pkt;
use aya_ebpf::maps::lpm_trie::Key;
use ant_ebpf_common::{DNS_PORT, FlowDecisionEntry, RouteEntry, VERDICT_BLOCK, VERDICT_PROXY};

/// 静态规则条目是否属于当前世代。`generation == 0` 是启动期的通配条目，
/// 永远生效；正数条目只在 ROUTE_GENERATION 相同时生效。这是两阶段原子
/// 换代的读侧：切换完成后上一代被删掉的条目即使还留在 map 里也自动失效。
#[inline(always)]
fn live_verdict(e: RouteEntry, generation: u32) -> Option<u8> {
    if (e.generation == 0 || e.generation == generation) && e.verdict != 0 {
        Some(e.verdict)
    } else {
        None
    }
}

/// Full per-packet decision. Fragmented packets cannot be routed on L4 and
/// fall through to the address-only surfaces (2/3/5), like dae.
/// `generation` 由调用方传入，避免热路径重复读 ROUTE_GENERATION。
#[inline(always)]
pub fn decide(pkt: &Pkt, generation: u32) -> u8 {
    let param = PARAM.load();

    // 1. DNS hijack: the userspace DNS engine answers and publishes
    //    DOMAIN_ROUTE entries so later data packets route by domain.
    // [方案八] TCP/53 (DNS over TCP, RFC 7766) 同样劫持。此前只认 UDP，
    // TCP DNS 查询会落到 CIDR/PORT/default，经常被送进代理节点，域名分流
    // 对这些查询完全失效；honk 的 datapath.md 明确 "TCP and UDP port 53
    // are exempt"（health gating 豁免）且两者都走 DNS 策略。
    // 注意 cgroup 强制路径 decide_forced() 里 VERDICT_PROXY 直接返回，
    // 所以 DNS 仍不受强制节点影响，与 honk 一致。
    if param.dns_hijack != 0 && pkt.dport == DNS_PORT && !pkt.is_fragment {
        return VERDICT_PROXY;
    }

    // 2. Domain-derived verdict for this destination address. DNS 表是动态
    //    发布的，不按世代过滤；规则变化由 publish_domain_ip 递增世代处理。
    if let Some(entry) = DOMAIN_ROUTE.get_ptr(pkt.dst_ip) {
        let v = unsafe { (*entry).verdict };
        if v != 0 {
            return v;
        }
    }

    // 3. CIDR longest prefix match.
    if pkt.dst_ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&pkt.dst_ip[12..16]);
        if let Some(e) = CIDR_V4.get(Key::new(32, v4)) {
            if let Some(v) = live_verdict(*e, generation) {
                return v;
            }
        }
    } else {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(&pkt.dst_ip);
        if let Some(e) = CIDR_V6.get(Key::new(128, v6)) {
            if let Some(v) = live_verdict(*e, generation) {
                return v;
            }
        }
    }

    // 4. Port table (only meaningful for unfragmented packets).
    if !pkt.is_fragment {
        if let Some(e) = PORT_ROUTE.get_ptr(pkt.dport) {
            if let Some(v) = live_verdict(unsafe { *e }, generation) {
                return v;
            }
        }
    }

    // 5. Default.
    param.default_verdict
}

/// [方案一] 每流判决入口：同流后续包只查一次 FLOW_DECISION，命中即用；
/// 未命中（或世代过期）才跑完整 decide() 并把结果连同当前世代写回缓存。
///
/// 三类包不缓存：分片（L4 字段不可靠，且本来只能走地址级规则）、DNS
/// 查询（每个查询都是不同 FlowKey，缓存只会白占 LRU）、以及 cgroup 强制
/// 路径（按进程判定，不能按五元组缓存，由 tc.rs 直接调 decide_forced）。
#[inline(always)]
pub fn decide_flow(pkt: &Pkt) -> u8 {
    let generation = route_generation();
    if PARAM.load().flow_cache == 0 || pkt.is_fragment || pkt.dport == DNS_PORT {
        return decide(pkt, generation);
    }

    let key = pkt.flow_key();
    if let Some(e) = FLOW_DECISION.get_ptr(key) {
        let e = unsafe { *e };
        if e.generation == generation && e.verdict != 0 {
            return e.verdict;
        }
        // 世代不匹配：旧缓存作废，落到下面重新判决并覆盖。
    }

    let v = decide(pkt, generation);
    let _ = FLOW_DECISION.insert(key, FlowDecisionEntry::new(v, generation), 0);
    v
}

/// Local / private / link-local / multicast destinations (never forced to the
/// proxy). `ip` is the 16-byte form, IPv4 v4-mapped.
#[inline(always)]
fn is_local_or_private(ip: &[u8; 16]) -> bool {
    if ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        let a = ip[12];
        let b = ip[13];
        return a == 10
            || a == 127
            || (a == 172 && (b & 0xf0) == 16)
            || (a == 192 && b == 168)
            || (a == 169 && b == 254)
            || (a == 100 && (b & 0xc0) == 64)
            || a >= 224;
    }
    (ip[0] & 0xfe) == 0xfc                       // fc00::/7
        || (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) // fe80::/10
        || ip[0] == 0xff                          // ff00::/8
        || (ip[0..15] == [0u8; 15] && ip[15] == 1) // ::1
}

/// Decision for a cgroup forced to a node (`node` is VERDICT_NODE_BASE + i):
/// whatever the normal surfaces say, public destinations go through that
/// node. BLOCK still blocks, the DNS hijack (bare VERDICT_PROXY) stays, and
/// local or private destinations keep their normal verdict.
#[inline(always)]
pub fn decide_forced(pkt: &Pkt, node: u8, generation: u32) -> u8 {
    let v = decide(pkt, generation);
    if v == VERDICT_BLOCK || v == VERDICT_PROXY {
        return v;
    }
    if is_local_or_private(&pkt.dst_ip) {
        return v;
    }
    node
}
