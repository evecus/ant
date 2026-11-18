//! ant-ebpf: trimmed transparent-proxy datapath, design follows honk/dae.
#![no_std]
#![no_main]

mod action;
mod fragment;
mod maps;
mod observability;
mod packet;
mod routing;
mod sk_lookup;
mod tc;

use action::flatten;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::bindings::__sk_buff;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// TC entry points use the raw __sk_buff pointer, matching honk's convention
// to avoid verifier "Arg#0 type STRUCT not supported" issues on newer kernels.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::lan_ingress_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::wan_egress_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn ant0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::ant0peer_ingress_body(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn ant0_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(tc::ant0_ingress_body(&TcContext::new(ctx)))
}
