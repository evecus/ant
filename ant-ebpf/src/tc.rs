//! TC program bodies: `lan_ingress`, `wan_egress`, `ant0peer_ingress`,
//! `ant0_ingress`.
//!
//! Capture (lan_ingress / wan_egress): decide() in the kernel; DIRECT passes
//! into the host stack untouched, BLOCK is shot, PROXY publishes FLOW_TRACK
//! framing and redirects the skb into `ant0` (host side of the pair bridging
//! into the `antns` proxy namespace). "PROXY" means any node verdict
//! (VERDICT_NODE_BASE + i); the verdict is recorded in FLOW_TRACK so userspace
//! knows which node the flow belongs to.
//!
//! Reply (ant0_ingress): reverse-lookup FLOW_TRACK, restore original framing,
//! TX back to the LAN client or inject into WAN RX (BPF_F_INGRESS) so the
//! host stack delivers the packet to the originating socket.

use crate::action::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict};
use crate::fragment;
use crate::maps::{
    cgroup_mode, datapath_ready, is_control_plane_socket, route_generation, FLOW_DECISION,
    FLOW_TRACK, PARAM,
};
use crate::observability;
use crate::packet::{dst_is_special, parse, Pkt};
use crate::routing::{decide_flow, decide_forced};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::helpers::{bpf_redirect, bpf_skb_store_bytes};
use ant_ebpf_common::{
    verdict_is_proxy, CGROUP_MODE_BYPASS, DNS_PORT, FlowKey, IPPROTO_TCP, TPROXY_MARK, TrackEntry,
    CLASSIFIED_MARK, FLOW_TRACK_REFRESH_NS, TCP_STATE_CLOSING, TCP_STATE_OPEN, VERDICT_BLOCK,
    VERDICT_DIRECT, VERDICT_NODE_BASE,
};

const PACKET_HOST: u32 = 0;
const PACKET_OTHERHOST: u32 = 1;
const BPF_F_INGRESS: u64 = 1;

// Ethernet MAC field offsets (network_types::eth::EthHdr layout).
const OFF_ETH_DST: u32 = 0;
const OFF_ETH_SRC: u32 = 6;

/// Common capture path shared by lan_ingress and wan_egress.
#[inline(always)]
fn do_capture(ctx: &TcContext, from_wan: u8) -> Verdict {
    // [方案七] 准入门控：hook 已 attach、但静态规则 / 监听器 / recv 循环
    // 尚未就绪的窗口里，一律让包走原栈（fail-open），既不误代理也不丢包。
    // 对齐 honk 每个 TC 入口的 `datapath_ready()` 检查。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    let in_mark = unsafe { (*ctx.skb.skb).mark };
    // [方案一] 已判决包的快速通道：LAN ingress 判为 DIRECT 的包会被内核
    // 转发到 WAN egress，第二次进入 capture hook 时在这里直接放行，省掉
    // 重复解析与判决（honk 的 CLASSIFIED_MARK 思路）。控制面 socket 带的是
    // CONTROL_MARK，不含这一位，不会误伤。
    if in_mark & CLASSIFIED_MARK != 0 {
        return Ok(TC_ACT_OK);
    }
    if is_control_plane_socket(ctx.skb.skb) {
        // Control plane's own dials (SOCKS5, DNS upstream) must never loop.
        return Ok(TC_ACT_OK);
    }
    // Per-process policy: only host-originated packets carry a socket (and so
    // a cgroup); forwarded LAN traffic never matches.
    let param = PARAM.load();
    let mut forced_node = 0u8;
    if from_wan == 1 && param.cgroup_rules != 0 {
        let mode = cgroup_mode(ctx.skb.skb);
        if mode == CGROUP_MODE_BYPASS {
            return Ok(TC_ACT_OK);
        }
        if mode >= VERDICT_NODE_BASE {
            forced_node = mode;
        }
    }

    let pkt = parse(ctx)?;

    // [方案七] 基础设施流量直通：L2 广播/组播、0.0.0.0、
    // 255.255.255.255、224.0.0.0/4、ff00::/8 与 veth own-link。
    // 必须排在 decide()（尤其 UDP/53 劫持）之前，并且不打任何 mark：
    // 用户态 CIDR 表达不了 L2 广播 MAC，而用户规则可以用更具体的 LPM
    // 覆盖私有直连。见 packet::dst_is_special。
    if dst_is_special(&pkt) {
        return Ok(TC_ACT_OK);
    }

    // [方案四] 非首片优先继承首片判决；没有记录（TTL 过期 / ID 首次出现）
    // 才退回原来的地址级规则。这样同一数据报的剩余分片不会各自判一次，
    // 也不会出现「首片进代理、后续片直连」的半截连接。
    if pkt.is_fragment {
        let inherited = fragment::inherited(&pkt);
        if inherited == VERDICT_BLOCK {
            observability::count_block();
            return Err(TC_ACT_SHOT);
        }
        if verdict_is_proxy(inherited) {
            observability::count_frag_inherited();
            // 非首片读不到五元组端口，绝不能用垃圾端口写 FLOW_TRACK：
            // 回程查的是首片建立的那条真实五元组记录，多写只会污染表。
            return steer_to_antns(ctx);
        }
    }

    // [方案六] 每源每秒新流预算。默认关闭；开启时只对 LAN ingress 上
    // FLOW_DECISION 未命中的首包生效（DNS 查询与分片豁免，避免误伤）。
    if from_wan == 0
        && param.new_flow_limit != 0
        && param.flow_cache != 0
        && !pkt.is_fragment
        && pkt.dport != DNS_PORT
        && FLOW_DECISION.get_ptr(pkt.flow_key()).is_none()
        && observability::new_flow_exceeded(&pkt)
    {
        observability::count_new_flow_limited();
        return Err(TC_ACT_SHOT);
    }

    // cgroup 强制路径是按进程判定的，不能按五元组缓存，直接走完整判决；
    // 其余流量走 decide_flow()，同流后续包由 FLOW_DECISION 命中即返回。
    let verdict = if forced_node != 0 {
        decide_forced(&pkt, forced_node, route_generation())
    } else {
        decide_flow(&pkt)
    };

    // 首片把最终判决写进 FRAG_VERDICT；DIRECT 会顺带清掉 ID 复用残留。
    fragment::record(&pkt, verdict);

    if verdict == VERDICT_DIRECT {
        observability::count_direct(ctx.skb.len());
        // 保留原 mark 低位（Android netd 用低 16 位当 netId），只置已分类位。
        ctx.skb.set_mark(in_mark | CLASSIFIED_MARK);
        Ok(TC_ACT_OK)
    } else if verdict == VERDICT_BLOCK {
        observability::count_block();
        Err(TC_ACT_SHOT)
    } else if verdict_is_proxy(verdict) {
        observability::count_proxy(ctx.skb.len());
        // [方案八] 确认 TCP/53 劫持路径真的走到用户态（UDP/53 不计）。
        if pkt.l4_proto == IPPROTO_TCP && pkt.dport == DNS_PORT {
            observability::count_dns_tcp();
        }
        redirect_to_proxy(ctx, &pkt, from_wan, verdict)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// 纯粹的转向动作：打 mark、备份到 cb[0]、redirect 到 ant0。
/// 分片后续片也走这里，只是不写 FLOW_TRACK（见 do_capture）。
#[inline(always)]
fn steer_to_antns(ctx: &TcContext) -> Verdict {
    let param = PARAM.load();
    if param.ant0_ifindex == 0 {
        return Err(TC_ACT_UNSPEC);
    }
    // Reply path authority: mark + tracked framing. ant0peer_ingress restores
    // the mark from cb[0] because the link crossing may scrub skb->mark.
    ctx.skb.set_mark(TPROXY_MARK);
    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
    }
    // bpf_redirect_peer would bypass the backlog but is egress-only; TC
    // egress capture uses plain bpf_redirect, ingress capture may use either.
    let _ = unsafe { bpf_redirect(param.ant0_ifindex, 0) };
    Ok(crate::action::TC_ACT_REDIRECT)
}

/// 构造一份完整的捕获档案。新 SYN 覆盖与首次插入共用同一处，避免两处
/// 字段漂移；单独成函数也让 48 字节的结构体只占一层栈帧。
#[inline(always)]
fn new_track_entry(
    ctx: &TcContext,
    pkt: &Pkt,
    from_wan: u8,
    verdict: u8,
    now: u64,
    closing: bool,
) -> TrackEntry {
    TrackEntry {
        ifindex: unsafe { (*ctx.skb.skb).ifindex },
        from_wan,
        verdict,
        tcp_state: if closing {
            TCP_STATE_CLOSING
        } else {
            TCP_STATE_OPEN
        },
        _pad: [0; 1],
        smac: pkt.smac,
        dmac: pkt.dmac,
        last_seen_ns: now,
    }
}

/// Record framing and steer the packet into the proxy namespace.
#[inline(always)]
fn redirect_to_proxy(ctx: &TcContext, pkt: &Pkt, from_wan: u8, verdict: u8) -> Verdict {
    let key = pkt.flow_key();
    let now = unsafe { bpf_ktime_get_ns() };
    // [方案七] TCP 首部 flags 决定这条记录是"新连接 / 正在关闭 / 普通包"。
    let new_syn = pkt.is_new_syn();
    let closing = pkt.is_fin_or_rst();

    // [方案五] FLOW_TRACK 换成普通 HashMap 后不再被内核静默驱逐，但仍要
    // 告诉用户态 janitor 这条流还活着。普通包按 30s 节流刷新（只写 8
    // 字节，不重建整条档案）。
    if let Some(ptr) = FLOW_TRACK.get_ptr_mut(key) {
        let e = unsafe { &mut *ptr };
        if new_syn {
            // [方案七] 五元组复用：客户端在 TIME_WAIT 后面用同一 sport
            // 重连，或 Wi-Fi→蜂窝切换导致 ifindex 变化。只刷新时间戳会让
            // 新流沿用旧 incarnation 的 MAC / ifindex / verdict，回程被
            // 送到错误接口或错误节点。纯 SYN 是"新连接声明"，整条覆盖。
            // 对齐 honk 的 forward-SYN-only publication，但不需要它的
            // conntrack / sock_ops / retirement fence 全套。
            *e = new_track_entry(ctx, pkt, from_wan, verdict, now, false);
            observability::count_tcp_syn_reset();
        } else {
            // FIN/RST 与 CLOSING 期间的包都强制刷新：30 s 节流会让短回收
            // 窗口从"上一次刷新"起算，并把仍在半关闭（client 发完 FIN、
            // server 继续推数据）的流提前删掉。OPEN 才保留原来的节流。
            if closing
                || e.tcp_state == TCP_STATE_CLOSING
                || now.wrapping_sub(e.last_seen_ns) > FLOW_TRACK_REFRESH_NS
            {
                e.last_seen_ns = now;
            }
            // CLOSING 是单向状态：只有新 SYN 能重置它。FIN 之后的 ACK /
            // 重传不会把流"复活"回 120 s 生命周期。
            if closing {
                e.tcp_state = TCP_STATE_CLOSING;
                observability::count_tcp_closing();
            }
        }
    } else {
        let entry = new_track_entry(ctx, pkt, from_wan, verdict, now, closing);
        // 表满时 insert 只是失败（可观测、可重试），仍继续 redirect，
        // 退化成「该流回程无记录」而不是内核 LRU 静默驱逐活跃长连接。
        if FLOW_TRACK.insert(key, entry, 0).is_err() {
            observability::count_track_insert_failed();
        }
    }
    steer_to_antns(ctx)
}

/// LAN forwarded traffic capture (ingress on the LAN interface).
#[inline(always)]
fn do_lan_ingress(ctx: &TcContext) -> Verdict {
    do_capture(ctx, 0)
}

/// Host-originated traffic capture (egress on the WAN interface).
#[inline(always)]
fn do_wan_egress(ctx: &TcContext) -> Verdict {
    do_capture(ctx, 1)
}

/// Packets arriving in `antns` on `ant0peer`: restore the mark scrubbed by
/// the link crossing, then let the `antns` policy routing (fwmark ->
/// local table) plus the sk_lookup program deliver to the transparent
/// listeners.
#[inline(always)]
fn do_ant0peer_ingress(ctx: &TcContext) -> Verdict {
    // [方案七] 与 capture hook 共用同一道准入门控，避免启动窗口里对
    // 半初始化的 skb 改 mark / pkt_type。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    if cb0 == TPROXY_MARK {
        ctx.skb.set_mark(TPROXY_MARK);
    }
    // The redirected frame still carries the original destination MAC, so
    // the veth crossing classifies it PACKET_OTHERHOST and ip_rcv() would
    // drop it before sk_lookup. Force PACKET_HOST (honk does the same).
    let _ = ctx.skb.change_type(PACKET_HOST);
    Ok(TC_ACT_OK)
}

/// Replies from the transparent listeners leaving `antns` through `ant0`:
/// restore the original framing and hand the packet back to its capture
/// interface. This is where proxied traffic exits back to clients without
/// ever touching host IP forwarding.
#[inline(always)]
fn do_ant0_ingress(ctx: &TcContext) -> Verdict {
    // [方案七] 准入门控；退出时先清门再拆监听器，回程不再被改写。
    if !datapath_ready() {
        return Ok(TC_ACT_OK);
    }
    let pkt = match parse(ctx) {
        Ok(p) => p,
        Err(_) => return Err(TC_ACT_UNSPEC),
    };

    // Replies travel in the reverse direction of the tracked flow.
    let key: FlowKey = pkt.flow_key().reverse();
    let Some(ptr) = FLOW_TRACK.get_ptr_mut(key) else {
        // Unknown reply: not ours to place.
        return Err(TC_ACT_UNSPEC);
    };
    let e = unsafe { &mut *ptr };
    let track: TrackEntry = *e;
    // [方案七] 回程也刷新 last_seen_ns：单向长流（只有 server→client
    // 数据，如推送 / 视频 / 长轮询）此前只靠正向包刷新，会在 120 s 后
    // 被 janitor 当成空闲删掉，回程随即丢帧。CLOSING 期间每个回程包都
    // 强制刷新，半关闭时 server 继续推数据就不会被 5 s 短窗口误删；
    // OPEN 仍按 30 s 节流，避免每包写放大。
    let now = unsafe { bpf_ktime_get_ns() };
    if track.tcp_state == TCP_STATE_CLOSING
        || now.wrapping_sub(track.last_seen_ns) > FLOW_TRACK_REFRESH_NS
    {
        e.last_seen_ns = now;
    }
    // [方案六] 回程流量计数（LAN 回客户端 / 本机注入 WAN RX 都算）。
    observability::count_reply(ctx.skb.len());

    // Restore LAN framing: swap captured MACs back in.
    unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb,
            OFF_ETH_SRC,
            track.dmac.as_ptr() as *const _,
            6,
            0,
        );
        bpf_skb_store_bytes(
            ctx.skb.skb,
            OFF_ETH_DST,
            track.smac.as_ptr() as *const _,
            6,
            0,
        );
    }

    let param = PARAM.load();
    if track.from_wan != 0 {
        // Host-originated: inject into the WAN RX path as PACKET_HOST so the
        // local stack delivers it to the originating socket.
        let _ = ctx.skb.change_type(PACKET_HOST);
        // Reply goes back in on the interface the flow left through (recorded
        // at capture), so wlan0 <-> mobile-data switches keep working.
        let wan_if = if track.ifindex != 0 { track.ifindex } else { param.wan_ifindex };
        let _ = unsafe { bpf_redirect(wan_if, BPF_F_INGRESS) };
    } else {
        // LAN client: TX onto the LAN interface as OTHERHOST (frame leaving).
        let _ = ctx.skb.change_type(PACKET_OTHERHOST);
        let _ = unsafe { bpf_redirect(track.ifindex, 0) };
    }
    Ok(crate::action::TC_ACT_REDIRECT)
}

pub fn lan_ingress_body(ctx: &TcContext) -> Verdict {
    do_lan_ingress(ctx)
}

pub fn wan_egress_body(ctx: &TcContext) -> Verdict {
    do_wan_egress(ctx)
}

pub fn ant0peer_ingress_body(ctx: &TcContext) -> Verdict {
    do_ant0peer_ingress(ctx)
}

pub fn ant0_ingress_body(ctx: &TcContext) -> Verdict {
    do_ant0_ingress(ctx)
}
