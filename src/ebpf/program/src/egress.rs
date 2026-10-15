//! TC egress classifiers: the WAN half of honk's four-role datapath layout.
//!
//! ## Roles
//!
//! | program            | attached to      | job                                                   |
//! |--------------------|------------------|-------------------------------------------------------|
//! | `lan_egress_l2/l3` | LAN egress       | reply-path accounting for LAN-hijacked flows          |
//! | `wan_ingress_l2/l3`| WAN ingress      | reply-path accounting for WAN-egress-hijacked flows   |
//! | `wan_egress_l2/l3` | WAN egress       | **take over locally-generated traffic**               |
//!
//! ## `wan_egress` — how it mirrors honk
//!
//! honk's `wan_egress` intercepts the host's own outbound packets (the ones
//! with `skb_ingress_ifindex == NOWHERE_IFINDEX`) and hands them to the
//! control plane with `bpf_redirect(dae0, 0)` into an isolated namespace.
//! ant has no `daens`: the redirect target is `lo` itself, and the handoff
//! goes through the very same `ip rule fwmark → table 82 → nft tproxy`
//! pipeline the LAN role uses.
//!
//! `bpf_redirect(lo, BPF_F_INGRESS)` is deliberate — the egress variant
//! (`flags == 0`) is **not** usable here:
//!
//! - egress semantics run `__bpf_tx_skb` → `dev_queue_xmit(lo)`, which
//!   keeps the skb's output-side `dst` attached. `ip_rcv_finish_core` then
//!   sees a valid dst and skips the input route lookup, so the `ip rule
//!   fwmark 0x80` never fires and the packet is forwarded, not delivered.
//! - `BPF_F_INGRESS` runs `____dev_forward_skb` → `skb_scrub_packet`, which
//!   **drops the dst** (forcing a fresh input lookup that evaluates the
//!   fwmark rule) and — because `lo` shares the netns with the WAN NIC —
//!   leaves `skb->mark` untouched (`xnet == false`).
//!
//! Two kernel details the program must respect after the crossing:
//!
//! - `__dev_forward_skb2` calls `eth_type_trans`, which re-derives
//!   `pkt_type` from the destination MAC against `lo`'s (all-zero)
//!   `dev_addr`; a non-zero dst MAC would be dropped as
//!   `PACKET_OTHERHOST`. The program therefore zeroes it before the
//!   redirect (honk writes `dae0peer_mac` for the same reason).
//! - `skb_scrub_packet` resets conntrack, so the reply accounting lives on
//!   `wan_ingress` instead of this hook.

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::bindings::__sk_buff;
use core::ffi::c_long;

use crate::{
    action::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict, flatten},
    decide::{
        DNS_PORT, HIJACK_MARK_WINDOW, LINK_H_LEN_L2, dst_is_local, mark_for_tproxy, skb_mark,
        tcp_established, tcp_is_new_flow, tcp_new_flow, tuple_addrs, udp_decide,
    },
    maps::{PARAM, PKT_SCRATCH_KEY, REDIRECT_TRACK, datapath_ready, redirect_track_refresh},
    stats::count_rx,
    transport::{IPPROTO_TCP, IPPROTO_UDP, dst_is_special, parse_packet},
};
use ant_ebpf_common::redirect::RedirectTuple;

/// `BPF_F_INGRESS` — deliver through the target device's RX path.
const BPF_F_INGRESS: u64 = 2;

/// `wan_egress` proxy sink: stamp the mark, then hand the packet to the
/// host pipeline via the `lo` crossing (see the module docs for why
/// `BPF_F_INGRESS` and not the egress semantics).
pub struct WanSink;

impl crate::decide::ProxySink for WanSink {
    #[inline(always)]
    fn sink(
        ctx: &TcContext,
        tuple: &ant_ebpf_common::redirect::TuplesKey,
        action: u8,
        rule_id: u32,
    ) -> Verdict {
        mark_for_tproxy(ctx, tuple, action, rule_id);
        redirect_to_control_plane_egress(ctx)
    }
}

// ── reply-path accounting (lan_egress / wan_ingress) ───────────────────────

/// Attribute reply bytes of a hijacked flow to the action that created it.
///
/// A reply's tuple reversed is exactly the request tuple the takeover
/// program recorded, so one shared body serves both directions:
/// `lan_egress` sees replies of LAN-hijacked flows, `wan_ingress` the ones
/// for locally-generated (wan_egress) flows.
#[inline(always)]
fn count_reply(ctx: &TcContext, link_h_len: u32) -> Verdict {
    if !datapath_ready() {
        return Err(TC_ACT_OK);
    }

    let param = PARAM.load();
    let mark = skb_mark(ctx);
    // ant's own outbound sockets (SO_MARK = global.mark) are not replies to
    // a hijacked flow — they are the proxy leaving towards the upstream.
    if param.ant_socket_mark != 0 && mark == param.ant_socket_mark {
        return Err(TC_ACT_OK);
    }
    // Packets on their way to local delivery carry the hijack fwmark.
    if mark & HIJACK_MARK_WINDOW != 0 {
        return Err(TC_ACT_OK);
    }

    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        return Err(if ret < 0 { TC_ACT_SHOT } else { TC_ACT_OK });
    }

    let l4proto = pkt.l4proto;
    if l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP {
        return Err(TC_ACT_OK);
    }

    let key = RedirectTuple::from_tuples(&pkt.tuples.five).reverse();
    // SAFETY: the map is a BTF-typed hash map of POD values.
    if let Some(entry) = unsafe { REDIRECT_TRACK.get(&key) } {
        let action = entry.action;
        count_rx(ctx, action);
        redirect_track_refresh(&key);
    }

    Err(TC_ACT_OK)
}

#[inline(always)]
fn do_tproxy_lan_egress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    count_reply(ctx, link_h_len)
}

#[inline(always)]
fn do_tproxy_wan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    count_reply(ctx, link_h_len)
}

// ── wan_egress: locally-generated traffic takeover ─────────────────────────

/// Redirect a classified locally-generated packet onto `lo` so the host's
/// tproxy pipeline picks it up — ant's equivalent of honk's
/// `redirect_to_control_plane_egress` (`bpf_redirect(dae0, 0)`).
///
/// Only reachable with `link_h_len == ETH_HLEN`: userspace attaches the WAN
/// role to ARPHRD_ETHER interfaces only (see `attach.rs`).
#[inline(always)]
fn redirect_to_control_plane_egress(ctx: &TcContext) -> Verdict {
    let param = PARAM.load();
    if param.lo_ifindex == 0 {
        // Userspace failed to resolve `lo`: refuse rather than blackhole.
        return Err(TC_ACT_SHOT);
    }
    let zero_mac = [0u8; 6];
    // Zero the destination MAC: after the crossing `eth_type_trans`
    // compares it against lo's (all-zero) dev_addr, and anything else is
    // dropped as PACKET_OTHERHOST.
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_skb_store_bytes(
            ctx.skb.skb,
            0, // offsetof(struct ethhdr, h_dest)
            zero_mac.as_ptr() as *const _,
            6,
            0,
        )
    };
    if ret != 0 {
        return Err(TC_ACT_SHOT);
    }
    Ok(unsafe { aya_ebpf_bindings::helpers::bpf_redirect(param.lo_ifindex, BPF_F_INGRESS) } as c_long)
}

/// `wan_egress` — take over the traffic the ant host itself originates.
///
/// The bypass chain mirrors honk's `do_tproxy_wan_egress`:
/// parse → ant's own socket mark → already-claimed mark → **ingress_ifindex
/// must be 0** (pure forwarded traffic belongs to `lan_ingress`) → special
/// destinations → DNS (nft owns it) → host-local destinations → ant's own
/// management IP → classify → sink.
#[inline(always)]
fn do_tproxy_wan_egress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    // While userspace has not published a routing table, every packet
    // leaves through the untouched nft pipeline.
    if !datapath_ready() {
        return Err(TC_ACT_OK);
    }

    let param = PARAM.load();
    let mark = skb_mark(ctx);
    // ant's own sockets carry `global.mark` (SO_MARK) — including the
    // tproxy listener replies, which must never re-enter the datapath.
    if param.ant_socket_mark != 0 && mark == param.ant_socket_mark {
        return Err(TC_ACT_OK);
    }
    // Already claimed by the nft hijack rules, the TUN pipeline, or our own
    // datapath (loop guard): never re-classify.
    if mark & HIJACK_MARK_WINDOW != 0 {
        return Err(TC_ACT_OK);
    }

    // Parse before reading further `__sk_buff` fields: the parse proves to
    // the verifier that `ctx.skb.skb` is a valid non-null pointer.
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };
    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        return Err(if ret < 0 { TC_ACT_SHOT } else { TC_ACT_OK });
    }

    let l4proto = pkt.l4proto;
    if l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP {
        return Err(TC_ACT_OK);
    }

    // Only locally-generated traffic: anything with an ingress interface is
    // forwarded and belongs to the `lan_ingress` role. `TC_ACT_UNSPEC`
    // lets another classifier (or the default accept) handle it.
    if unsafe { (*ctx.skb.skb).ingress_ifindex } != 0 {
        return Err(TC_ACT_UNSPEC);
    }

    let tuple = &pkt.tuples.five;
    let is_v4 = tuple.dst_ip.is_v4_mapped();
    let (sip, dip) = tuple_addrs(tuple);

    // Broadcast/multicast is never re-routed.
    if dst_is_special(pkt, link_h_len) {
        return Err(TC_ACT_OK);
    }
    // DNS belongs to the nft dstnat redirect.
    if tuple.dst_port == DNS_PORT {
        return Err(TC_ACT_OK);
    }
    // Host-local destination: replies to ant's own sockets, local services.
    if dst_is_local(ctx, l4proto, is_v4, &sip, &dip) {
        return Err(TC_ACT_OK);
    }
    // Connections to ant's own management IP would loop back into the
    // datapath (honk's `param.local_ip` check). `dip` is the raw address
    // words; for IPv4 the mapped word is the last one.
    if param.local_ip != 0 && is_v4 && dip[3] == param.local_ip {
        return Err(TC_ACT_OK);
    }

    if l4proto == IPPROTO_TCP {
        if !tcp_is_new_flow(&pkt.tcph) {
            // Established segment: only flows whose SYN we classified have
            // a cache entry; the rest pass through untouched.
            return tcp_established::<WanSink>(ctx, tuple, &pkt.tcph).unwrap_or(Err(TC_ACT_OK));
        }
        return tcp_new_flow::<WanSink>(ctx, tuple);
    }

    udp_decide::<WanSink>(ctx, tuple)
}

// TC entry points use a raw `__sk_buff` pointer for verifier compatibility
// ("Arg#0 type STRUCT not supported" on kernel >= 7.0).

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_egress(&TcContext::new(ctx), LINK_H_LEN_L2))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_egress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), LINK_H_LEN_L2))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_egress(&TcContext::new(ctx), LINK_H_LEN_L2))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_egress(&TcContext::new(ctx), 0))
}
