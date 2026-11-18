//! sk_lookup program running inside `antns`.
//!
//! Proxy-bound packets arrive with the original remote destination, so normal
//! socket lookup fails. This program assigns the transparent listener socket
//! from LISTEN_SOCKETS, letting the kernel deliver the packet with the
//! original destination intact (getsockname on the listener shows it).

use crate::maps::{KEY_TCP4, KEY_TCP6, KEY_UDP4_BASE, KEY_UDP6_BASE, LISTEN_SOCKETS, PARAM};
use aya_ebpf::bindings::bpf_sk_lookup;
use aya_ebpf::programs::SkLookupContext;
use ant_ebpf_common::{IPPROTO_TCP, IPPROTO_UDP, UDP_LISTENER_MAX};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

/// [方案二] 把一条流的五元组折叠成 [0, workers) 的槽位索引。
///
/// 这是唯一的定义：sk_lookup 是分配 socket 的唯一入口，同一流（含重传、
/// 分片后续包）算出同一个值，才会始终落到同一个 socket，用户态每个
/// socket 各自持有的 flow 表才不会分裂。哈希形式与 honk 保持一致。
#[inline(always)]
fn udp_listener_index(src: u32, dst: u32, sport: u16, dport: u16, workers: u32) -> u32 {
    let ports = ((sport as u32) << 16) | dport as u32;
    // 不能直接写 `% workers`：运行时取余会带出 `panic_const_rem_by_zero`
    // （`-> !`），LLVM 把它编成子程序末尾的一条 call 且后面不补 exit，
    // verifier 会报 "Subprogram can fall through"。checked_rem 无 panic 分支；
    // workers 已由 udp_workers() 保证非零，unwrap_or(0) 只是不可达的兜底。
    src.wrapping_add(dst.rotate_left(8))
        .wrapping_add(ports.rotate_left(16))
        .checked_rem(workers)
        .unwrap_or(0)
}

/// 模数必须与用户态实际发布的槽位数严格一致，否则会算出未发布的 key
/// 而把包 SK_DROP。越界时回退到编译期上限。
#[inline(always)]
fn udp_workers() -> u32 {
    let n = PARAM.load().udp_workers as u32;
    if n == 0 || n > UDP_LISTENER_MAX {
        UDP_LISTENER_MAX
    } else {
        n
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "sk_lookup")]
pub fn tproxy_sk_lookup(ctx: *mut bpf_sk_lookup) -> u32 {
    let ctx = SkLookupContext::new(ctx);
    do_sk_lookup(&ctx)
}

#[inline(always)]
fn do_sk_lookup(ctx: &SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let key = match (lookup.family, lookup.protocol as u8) {
        (AF_INET, IPPROTO_TCP) => KEY_TCP4,
        (AF_INET6, IPPROTO_TCP) => KEY_TCP6,
        (AF_INET, IPPROTO_UDP) => udp_listener_key_v4(ctx.lookup),
        (AF_INET6, IPPROTO_UDP) => udp_listener_key_v6(ctx.lookup),
        _ => return SK_PASS,
    };
    match LISTEN_SOCKETS.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}

// `#[inline(never)]` 不是可选的：在 opt-level=2 下 LLVM 会把两个 family
// 分支 if-convert 成一次"通过计算出偏移的 ctx 指针读取"，verifier 会以
// "dereference of modified ctx ptr" 拒绝（honk 踩过同样的坑）。拆成独立
// subprogram 后每次 ctx 读都是常量偏移。
#[inline(never)]
fn udp_listener_key_v4(lookup: *const bpf_sk_lookup) -> u32 {
    let lookup = unsafe { &*lookup };
    let h = udp_listener_index(
        u32::from_be(lookup.remote_ip4),
        u32::from_be(lookup.local_ip4),
        u16::from_be(lookup.remote_port),
        lookup.local_port as u16,
        udp_workers(),
    );
    KEY_UDP4_BASE + h
}

#[inline(never)]
fn udp_listener_key_v6(lookup: *const bpf_sk_lookup) -> u32 {
    let lookup = unsafe { &*lookup };
    let h = udp_listener_index(
        u32::from_be(lookup.remote_ip6[3]),
        u32::from_be(lookup.local_ip6[3]),
        u16::from_be(lookup.remote_port),
        lookup.local_port as u16,
        udp_workers(),
    );
    KEY_UDP6_BASE + h
}
