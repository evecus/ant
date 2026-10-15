//! TC ingress classifier: L3 routing decisions for forwarded (LAN) traffic.
//!
//! ## Where this fits in ant
//!
//! ant's transparent-proxy pipeline is `datapath mark 0x80 → ip rule fwmark →
//! table 82 (local default dev lo) → nft tproxy → tproxy inbound`. This
//! program replaces the *decision* half of that pipeline for forwarded
//! (LAN) traffic:
//!
//! - `proxy`  — stamp `TPROXY_MARK` (bits 0-7) plus an action code in bits
//!   16-23; the nft rules recognise the mark and assign the
//!   transparent listener socket. The final outbound choice still happens
//!   in userspace (domain rules, sniffing, proxy-group selection).
//! - `direct` — leave the packet unmarked; the kernel forwards it normally
//!   and the flow never wakes ant's inbound at all.
//! - `block`  — drop it at L3 without ever reaching the socket layer.
//!
//! Locally-generated traffic (the ant host itself) is handled by the
//! `wan_egress` role in `egress.rs`, which redirects it onto `lo` so the
//! very same pipeline picks it up. The two compose because the action code
//! lives in bits 16-23: the nft rules skip any packet that already carries
//! a datapath decision (`meta mark & 0x00ff0000 == 0` guards the legacy
//! mark + tproxy rule).
//!
//! ## Not ported from honk
//!
//! - No `sk_lookup` / listener socket map: honk runs an isolated `daens`
//!   namespace that needs BPF socket assignment; ant's nft `tproxy` target
//!   already does it in the host netns.
//! - No L2 redirect / MAC rewriting on the LAN side: ant marks and lets
//!   the kernel route (only `wan_egress` performs the `bpf_redirect` to
//!   `lo`, mirroring honk's `bpf_redirect` to `dae0`).
//! - No UDP decision tokens: decisions come from the LPM trie, and
//!   userspace still re-evaluates every proxied flow.

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::bindings::__sk_buff;

use crate::{
    action::{TC_ACT_OK, TC_ACT_SHOT, Verdict, flatten},
    decide::{
        DNS_PORT, HIJACK_MARK_WINDOW, LINK_H_LEN_L2, LanSink, dst_is_local, skb_mark,
        tcp_established, tcp_is_new_flow, tcp_new_flow, tuple_addrs, udp_decide,
    },
    maps::{PARAM, PKT_SCRATCH_KEY, datapath_ready},
    transport::{IPPROTO_TCP, IPPROTO_UDP, dst_is_special, parse_packet},
};
use ant_ebpf_common::redirect::TuplesKey;

#[inline(always)]
pub fn do_tproxy_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    // While userspace has not published a routing table, every packet
    // leaves through the untouched nft pipeline.
    if !datapath_ready() {
        return Err(TC_ACT_OK);
    }

    let param = PARAM.load();
    let mark = skb_mark(ctx);

    // ant's own sockets carry `global.mark` (SO_MARK).
    if param.ant_socket_mark != 0 && mark == param.ant_socket_mark {
        return Err(TC_ACT_OK);
    }
    // Already claimed by the nft hijack rules, the TUN pipeline, or our own
    // datapath (loop guard): never re-classify.
    if mark & HIJACK_MARK_WINDOW != 0 {
        return Err(TC_ACT_OK);
    }

    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        // Malformed → drop; unsupported / fragment / ICMPv6 → pass.
        return Err(if ret < 0 { TC_ACT_SHOT } else { TC_ACT_OK });
    }

    let l4proto = pkt.l4proto;
    if l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP {
        return Err(TC_ACT_OK);
    }

    let tuple: &TuplesKey = &pkt.tuples.five;
    let is_v4 = tuple.dst_ip.is_v4_mapped();
    let (sip, dip) = tuple_addrs(tuple);

    // Broadcast/multicast: DHCP, mDNS, SSDP and LLMNR ride these.
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

    if l4proto == IPPROTO_TCP {
        if !tcp_is_new_flow(&pkt.tcph) {
            // Established segment: only flows we opened have a cache entry.
            return tcp_established::<LanSink>(ctx, tuple, &pkt.tcph).unwrap_or(Err(TC_ACT_OK));
        }
        return tcp_new_flow::<LanSink>(ctx, tuple);
    }

    udp_decide::<LanSink>(ctx, tuple)
}

// TC entry points use a raw `__sk_buff` pointer for verifier compatibility
// ("Arg#0 type STRUCT not supported" on kernel >= 7.0).
//
// Role: `lan_ingress` — the client-facing (LAN) half of honk's four-role
// datapath layout. `wan_ingress` lives in `egress.rs` next to the other
// WAN-side roles.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_ingress(&TcContext::new(ctx), LINK_H_LEN_L2))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_ingress(&TcContext::new(ctx), 0))
}
