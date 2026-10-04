//! Linux TUN IFF_VNET_HDR / TUNSETOFFLOAD probing (aligned with sing-tun).

/// Result of TUNSETOFFLOAD probing.
#[derive(Clone, Copy, Debug, Default)]
pub struct TunOffload {
    /// IFF_VNET_HDR is active — every R/W is prefixed with virtio_net_hdr.
    pub vnet_hdr: bool,
    /// TCP GSO (TSO4|TSO6) accepted by kernel.
    pub tcp_gso: bool,
    /// UDP GSO (USO4|USO6) accepted by kernel.
    pub udp_gso: bool,
}

#[cfg(target_os = "linux")]
const TUNSETOFFLOAD: u64 = 0x4004_54d0;
#[cfg(target_os = "linux")]
const TUNGETIFF: u64 = 0x8004_54d2;
#[cfg(target_os = "linux")]
const IFF_VNET_HDR: u16 = 0x4000;
#[cfg(target_os = "linux")]
const TUN_F_CSUM: u32 = 0x01;
#[cfg(target_os = "linux")]
const TUN_F_TSO4: u32 = 0x02;
#[cfg(target_os = "linux")]
const TUN_F_TSO6: u32 = 0x04;
#[cfg(target_os = "linux")]
const TUN_F_USO4: u32 = 0x10;
#[cfg(target_os = "linux")]
const TUN_F_USO6: u32 = 0x20;

#[cfg(target_os = "linux")]
pub fn tun_has_vnet_hdr(fd: std::os::fd::RawFd) -> bool {
    let mut ifr = [0u8; 24];
    let ret = unsafe { libc::ioctl(fd, TUNGETIFF as _, ifr.as_mut_ptr()) };
    if ret != 0 {
        return false;
    }
    let flags = u16::from_ne_bytes([ifr[16], ifr[17]]);
    flags & IFF_VNET_HDR != 0
}

#[cfg(not(target_os = "linux"))]
pub fn tun_has_vnet_hdr(_fd: i32) -> bool {
    false
}

/// Probe and enable TUN offloads. Failure of TUNSETOFFLOAD does not clear
/// `vnet_hdr` — if the flag is set, every R/W still carries virtio_net_hdr.
#[cfg(target_os = "linux")]
pub fn setup_tun_offload(fd: std::os::fd::RawFd) -> TunOffload {
    use tracing::{info, warn};

    let mut result = TunOffload::default();
    if !tun_has_vnet_hdr(fd) {
        warn!("tun: IFF_VNET_HDR not enabled, virtio_net_hdr absent, GSO/GRO disabled");
        return result;
    }
    result.vnet_hdr = true;

    let tcp_offloads = (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6) as libc::c_int;
    let ret = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, tcp_offloads) };
    if ret != 0 {
        warn!("tun: TUNSETOFFLOAD(TSO) failed, TCP & UDP GRO disabled");
        return result;
    }
    result.tcp_gso = true;

    let full =
        (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6) as libc::c_int;
    let ret = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, full) };
    if ret != 0 {
        warn!("tun: TUNSETOFFLOAD(USO) failed, UDP GRO disabled");
        return result;
    }
    result.udp_gso = true;
    info!("tun: TUNSETOFFLOAD enabled (CSUM|TSO4|TSO6|USO4|USO6), vnet_hdr active");
    result
}

#[cfg(not(target_os = "linux"))]
pub fn setup_tun_offload(_fd: i32) -> TunOffload {
    TunOffload::default()
}
