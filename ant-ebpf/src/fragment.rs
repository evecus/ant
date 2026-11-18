//! [方案四] 分片判决继承，移植自 honk 的 `fragment.rs`。
//!
//! 只有首片带 L4 端口，能跑完整规则判决；后续片既读不到端口，也不该重新
//! 判一次（同一数据报的分片必须同命运）。做法：首片判为 PROXY / BLOCK 时
//! 把结果按 (src, dst, id, l4proto) 记进 FRAG_VERDICT，后续片查表继承；
//! 首片判 DIRECT 时删掉同 key 的旧记录，避免 IP ID 复用把新数据报误伤。

use crate::maps::FRAG_VERDICT;
use crate::packet::Pkt;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use ant_ebpf_common::{
    verdict_is_proxy, FragmentKey, FragmentVerdict, FRAGMENT_VERDICT_TTL_NS, VERDICT_BLOCK,
};

#[inline(always)]
fn key(pkt: &Pkt) -> FragmentKey {
    // RFC 8200 只按 (src, dst, id) 重组；IPv6 后续片停在 Fragment header
    // 后面，解析不到上层协议，所以 v6 的 l4proto 一律置 0 与首片对齐。
    let proto = if pkt.is_v4() { pkt.l4_proto } else { 0 };
    FragmentKey::new(pkt.src_ip, pkt.dst_ip, pkt.frag_id, proto)
}

/// 非首片查询首片留下的判决；返回 0 表示没有可继承的记录（含已过期）。
/// `#[inline(never)]` 让 40 字节的 key 独占栈帧，不挤进调用链里已经接近
/// 512 字节上限的那一层（honk 的同一手法）。
#[inline(never)]
pub fn inherited(pkt: &Pkt) -> u8 {
    let Some(ptr) = FRAG_VERDICT.get_ptr(key(pkt)) else {
        return 0;
    };
    let e = unsafe { *ptr };
    let age = unsafe { bpf_ktime_get_ns() }.wrapping_sub(e.ktime_ns);
    if age > FRAGMENT_VERDICT_TTL_NS {
        return 0;
    }
    e.verdict
}

/// 首片判完之后调用。BLOCK 与所有代理类判决会被继承；DIRECT 只做清理。
#[inline(always)]
pub fn record(pkt: &Pkt, verdict: u8) {
    if !pkt.is_first_fragment {
        return;
    }
    let k = key(pkt);
    if verdict != VERDICT_BLOCK && !verdict_is_proxy(verdict) {
        // IP ID 是 16/32 位，会复用；一个新数据报的首片判 DIRECT 时必须
        // 抹掉旧记录，否则它的后续片可能继承上一个数据报的 PROXY/BLOCK。
        let _ = FRAG_VERDICT.remove(k);
        return;
    }
    let e = FragmentVerdict {
        verdict,
        _pad: [0; 7],
        ktime_ns: unsafe { bpf_ktime_get_ns() },
    };
    let _ = FRAG_VERDICT.insert(k, e, 0);
}
