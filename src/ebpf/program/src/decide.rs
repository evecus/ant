//! Shared L3 decision logic for the `lan_ingress` and `wan_egress` roles.
//!
//! Both roles classify a packet destination against the synced LPM trie and
//! apply the same three verdicts; the only difference is what a `proxy`
//! verdict *does*:
//!
//! | role          | `proxy` action                                                     |
//! |---------------|---------------------------------------------------------------------|
//! | `lan_ingress` | stamp the tproxy mark and let the kernel's policy routing carry the |
//! |               | packet to `lo` (the packet already traverses an input path)         |
//! | `wan_egress`  | stamp the mark **and** `bpf_redirect` the packet onto `lo` with     |
//! |               | `BPF_F_INGRESS` — locally-generated skbs have no input path of      |
//! |               | their own, so the redirect *is* the delivery (honk's equivalent of  |
//! |               | `bpf_redirect(dae0, 0)`)                                           |
//!
//! The split is the [`ProxySink`] trait; everything else (bypass guards,
//! conntrack lookups, LPM matching, stats) is shared verbatim.

use core::{ffi::c_void, mem};

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::{BPF_FIB_LKUP_RET_NOT_FWDED, bpf_fib_lookup as BpfFibLookup},
    helpers::bpf_fib_lookup,
};

use crate::{
    action::{TC_ACT_OK, TC_ACT_SHOT, Verdict},
    contrack::{record, tcp_cached, udp_cached},
    event::send_ant_event,
    maps::{DEFAULT_ROUTE, ROUTE_LPM_MAP, redirect_track_touch},
    stats::count_tx,
    transport::{IPPROTO_TCP, IPPROTO_UDP, is_pure_syn},
};
use ant_ebpf_common::{
    RouteAction, RouteDecision, TPROXY_MARK,
    conn::{ConnState, mark_with_action},
    event::AntEventType,
    redirect::{RedirectTuple, TuplesKey},
};

use aya_ebpf::btf_maps::lpm_trie::Key;
use network_types::tcp::TcpHdr;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// DNS stays on the nft pipeline: ant hijacks it with a `redirect` in
/// `dstnat`, and the datapath must not pre-empt that decision.
pub const DNS_PORT: u16 = 53;
/// Ethernet header length (L2 attachment); `0` selects the L3 variant.
pub const LINK_H_LEN_L2: u32 = 14;

/// Bits another subsystem owns inside the skb mark: the nft hijack fwmark
/// (`0x80`) and the TUN fwmark (`0x81`) both live in the low byte, so any
/// non-zero low byte means "already claimed".
pub const HIJACK_MARK_WINDOW: u32 = 0x0000_00ff;

#[inline(always)]
pub fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}

#[inline(always)]
pub fn skb_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ifindex }
}

/// Network-order address words of a tuple (IPv4 is stored IPv4-mapped).
#[inline(always)]
pub fn tuple_addrs(tuple: &TuplesKey) -> ([u32; 4], [u32; 4]) {
    unsafe { (tuple.src_ip.u6_addr32, tuple.dst_ip.u6_addr32) }
}

/// Longest-prefix match of the packet destination against the synced
/// IP-CIDR rules; falls back to the MATCH catch-all published by userspace.
///
/// IPv4 entries are stored IPv4-mapped, so one 128-bit lookup covers both
/// families: a `/24` rule is `prefix_len = 96 + 24`, a full-address lookup
/// is `prefix_len = 128`.
#[inline(always)]
pub fn route_decision(dst: &[u32; 4]) -> Option<RouteDecision> {
    if let Some(decision) = ROUTE_LPM_MAP.get(&Key::new(128, *dst)) {
        return Some(*decision);
    }
    DEFAULT_ROUTE.get(0).copied()
}

/// True when the destination resolves to a host-local route.
///
/// Replies that come back to ant's *own* outbound sockets and connections
/// to local services take this path; classifying them would hijack traffic
/// the kernel is about to deliver locally (the reply's destination port
/// belongs to ant's ephemeral socket, not to any listener).
#[inline(always)]
pub fn dst_is_local(
    ctx: &TcContext,
    l4proto: u8,
    is_v4: bool,
    src: &[u32; 4],
    dst: &[u32; 4],
) -> bool {
    let mut fib: BpfFibLookup = unsafe { mem::zeroed() };
    fib.family = if is_v4 { AF_INET } else { AF_INET6 };
    fib.l4_protocol = l4proto;
    fib.ifindex = skb_ifindex(ctx);
    unsafe {
        fib.__bindgen_anon_1.tot_len = (*ctx.skb.skb).len as u16;
        if is_v4 {
            fib.__bindgen_anon_3.ipv4_src = src[3];
            fib.__bindgen_anon_4.ipv4_dst = dst[3];
        } else {
            fib.__bindgen_anon_3.ipv6_src = *src;
            fib.__bindgen_anon_4.ipv6_dst = *dst;
        }
    }
    let ret = unsafe {
        bpf_fib_lookup(
            ctx.skb.skb as *mut c_void,
            &mut fib as *mut _,
            mem::size_of::<BpfFibLookup>() as i32,
            0,
        )
    };
    ret == BPF_FIB_LKUP_RET_NOT_FWDED as i64
}

/// Stamp the tproxy fwmark and record the flow for the reply path.
#[inline(always)]
pub fn mark_for_tproxy(ctx: &TcContext, tuple: &TuplesKey, action: u8, rule_id: u32) {
    ctx.skb
        .set_mark(mark_with_action(skb_mark(ctx) | TPROXY_MARK, action));
    let redirect_key = RedirectTuple::from_tuples(tuple);
    redirect_track_touch(&redirect_key, skb_ifindex(ctx), action, rule_id);
}

/// Stamp the datapath action code **without** the tproxy fwmark.
///
/// A `direct` decision must stay on the native path (honk's equivalent:
/// `ctx.set_mark(mark)` with the direct mark, then `TC_ACT_OK`). ant has no
/// `daens` to hide the packet in, so the decision is carried in the mark:
/// the nft fallback rules only hijack packets whose action window is zero
/// (`meta mark & 0x00ff0000 == 0`), while the `ip rule fwmark 0x80` lookup
/// ignores a mark whose low byte is zero — the kernel forwards the flow and
/// userspace never sees it.
#[inline(always)]
pub fn mark_for_direct(ctx: &TcContext) {
    ctx.skb
        .set_mark(mark_with_action(skb_mark(ctx), RouteAction::Direct as u8));
}

/// What a role does with a flow the shared classifier decided `proxy`.
///
/// The implementation stamps the tproxy mark itself (via
/// [`mark_for_tproxy`], which also records the flow for reply-path
/// accounting) and then performs its role-specific handoff: the mark (low
/// byte `0x80` + action code in bits 16-23) is what the nft `tproxy` rule
/// and the `ip rule fwmark` lookup downstream key on.
pub trait ProxySink {
    fn sink(ctx: &TcContext, tuple: &TuplesKey, action: u8, rule_id: u32) -> Verdict;
}

/// `lan_ingress` — the packet already traverses an input path; policy
/// routing delivers the marked packet to `lo` without further help.
pub struct LanSink;

impl ProxySink for LanSink {
    #[inline(always)]
    fn sink(ctx: &TcContext, tuple: &TuplesKey, action: u8, rule_id: u32) -> Verdict {
        mark_for_tproxy(ctx, tuple, action, rule_id);
        Err(TC_ACT_OK)
    }
}

/// Re-apply a decision that was already made for this flow (conntrack hit).
#[inline(always)]
pub fn apply_cached<S: ProxySink>(ctx: &TcContext, tuple: &TuplesKey, state: &ConnState) -> Verdict {
    let action = state.action;
    match RouteAction::from_u8(action) {
        Some(RouteAction::Block) => {
            count_tx(ctx, action);
            Err(TC_ACT_SHOT)
        }
        Some(RouteAction::Direct) => {
            count_tx(ctx, action);
            // Re-stamp the action code: established segments of a direct flow
            // must keep skipping the nft fallback hijack.
            mark_for_direct(ctx);
            Err(TC_ACT_OK)
        }
        Some(RouteAction::Proxy) => {
            count_tx(ctx, action);
            // The sink re-stamps the mark: established segments of a proxied
            // flow must keep reaching the local-delivery path.
            S::sink(ctx, tuple, action, state.rule_id)
        }
        None => Err(TC_ACT_OK),
    }
}

/// Apply a freshly routed decision to a new flow.
#[inline(always)]
pub fn apply_decision<S: ProxySink>(
    ctx: &TcContext,
    tuple: &TuplesKey,
    decision: RouteDecision,
    l4proto: u8,
) -> Verdict {
    let action = decision.action;
    let Some(route_action) = RouteAction::from_u8(action) else {
        return Err(TC_ACT_OK);
    };
    let (sip, dip) = tuple_addrs(tuple);

    match route_action {
        RouteAction::Block => {
            count_tx(ctx, action);
            send_ant_event(
                AntEventType::Blocked,
                action,
                l4proto,
                decision.rule_id,
                &sip,
                &dip,
                tuple.src_port,
                tuple.dst_port,
            );
            Err(TC_ACT_SHOT)
        }
        RouteAction::Direct => {
            count_tx(ctx, action);
            // Stamp the action code so the nft fallback rules (`meta mark &
            // 0x00ff0000 == 0` → mark + tproxy) skip this flow: the kernel
            // forwards it natively and ant never sees it.
            mark_for_direct(ctx);
            // TCP direct flows are re-classified from their (rare) SYNs, so
            // only UDP needs a cache entry to skip the LPM lookup per
            // datagram.
            if l4proto == IPPROTO_UDP {
                let _ = record(tuple, action, decision.rule_id);
            }
            Err(TC_ACT_OK)
        }
        RouteAction::Proxy => {
            // Record first: if the conntrack map is full we cannot keep
            // established segments on the local path, so hand the flow back
            // to the nft pipeline (which marks unconditionally) instead of
            // marking it ourselves and breaking it halfway.
            if !record(tuple, action, decision.rule_id) {
                send_ant_event(
                    AntEventType::MapOverflow,
                    action,
                    l4proto,
                    decision.rule_id,
                    &sip,
                    &dip,
                    tuple.src_port,
                    tuple.dst_port,
                );
                return Err(TC_ACT_OK);
            }

            send_ant_event(
                AntEventType::NewFlow,
                action,
                l4proto,
                decision.rule_id,
                &sip,
                &dip,
                tuple.src_port,
                tuple.dst_port,
            );
            count_tx(ctx, action);
            S::sink(ctx, tuple, action, decision.rule_id)
        }
    }
}

/// TCP non-SYN path: reuse the decision recorded when the flow opened.
/// `None` means "no cached state" — the caller passes the packet through.
#[inline(always)]
pub fn tcp_established<S: ProxySink>(
    ctx: &TcContext,
    tuple: &TuplesKey,
    tcph: &TcpHdr,
) -> Option<Verdict> {
    let state = tcp_cached(tuple, tcph)?;
    Some(apply_cached::<S>(ctx, tuple, &state))
}

/// UDP path: cached decision when present, otherwise a fresh LPM lookup
/// (and a cache entry so later datagrams skip the trie).
#[inline(always)]
pub fn udp_decide<S: ProxySink>(ctx: &TcContext, tuple: &TuplesKey) -> Verdict {
    if let Some(state) = udp_cached(tuple) {
        return apply_cached::<S>(ctx, tuple, &state);
    }
    let (_, dip) = tuple_addrs(tuple);
    let decision = route_decision(&dip)?;
    apply_decision::<S>(ctx, tuple, decision, IPPROTO_UDP)
}

/// TCP pure-SYN path: a brand-new flow needs a fresh LPM decision.
#[inline(always)]
pub fn tcp_new_flow<S: ProxySink>(ctx: &TcContext, tuple: &TuplesKey) -> Verdict {
    let (_, dip) = tuple_addrs(tuple);
    let decision = route_decision(&dip)?;
    apply_decision::<S>(ctx, tuple, decision, IPPROTO_TCP)
}

/// True when the TCP header describes a pure SYN (new connection).
#[inline(always)]
pub fn tcp_is_new_flow(tcph: &TcpHdr) -> bool {
    is_pure_syn(tcph)
}
