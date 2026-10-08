//! TUN inbound (`stack: gvisor` user-space stack by default, `system` opt-in).
//!
//! Creates a virtual NIC, optionally installs auto-route / auto-redirect /
//! auto-detect-interface, runs the selected stack with optional dns-hijack.
//! gvisor = user-space smoltcp netstack (`netstack/`, ported from clash-rs
//! clash-netstack): no kernel socket pairs, no per-packet NAT rewrite.
//! system = kernel NAT + local TCP listener (legacy).
//!
//! Platforms: Linux + Windows + macOS + Android (external FD). Address
//! configuration uses `ip` (Linux), `ifconfig` (macOS), or `netsh` (Windows).
//! On Android / iOS-style hosts, pass an existing TUN fd via
//! `tun.file-descriptor` or env `ANT_TUN_FD` (sing-tun `FileDescriptor`
//! equivalent); OS address/route setup is then skipped.

mod device;
mod gso;
#[cfg(unix)]
mod icmp_forwarder;
pub(crate) mod iface;
mod ip_defrag;
mod marks;
mod netstack;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod darwin_batch;
mod nat;
mod native_tun;
mod packet;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod offload;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod redirect;
mod route;
mod stack;
#[cfg(target_os = "windows")]
mod wfp;

/// Used by `app::sockopt` for interface binding (unix: SO_BINDTODEVICE /
/// IP_BOUND_IF). Windows uses `iface::bind_interface_index()` instead.
#[cfg(unix)]
pub use iface::bind_interface;

/// Output mark for dialers (used by main before TUN starts).
pub fn marks_resolve(
    user_mark: u32,
    auto_route: bool,
    auto_redirect: bool,
    auto_detect: bool,
) -> u32 {
    marks::TunMarks::resolve(user_mark, auto_route, auto_redirect, auto_detect).output
}

use crate::app::router::Router;
use crate::config::Config;
use crate::outbound::OutboundManager;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{info, warn};

/// Entry point used by `main`.
pub async fn run_tun(
    cfg: Arc<Config>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let mut tun_cfg = cfg.tun.clone();
    if !tun_cfg.enable {
        return Ok(());
    }

    // External FD mode (Android VpnService / iOS / parent): the OS already owns
    // addresses + routing. Force-disable OS control-plane options that need root
    // / netlink, matching sing-tun when FileDescriptor != 0.
    let external_fd = tun_cfg.is_external_fd();
    if external_fd {
        if tun_cfg.auto_route {
            warn!("tun: external fd — ignoring auto-route (OS/VpnService owns routes)");
            tun_cfg.auto_route = false;
        }
        if tun_cfg.auto_redirect {
            warn!("tun: external fd — ignoring auto-redirect (needs root netfilter)");
            tun_cfg.auto_redirect = false;
        }
        if tun_cfg.strict_route {
            warn!("tun: external fd — ignoring strict-route");
            tun_cfg.strict_route = false;
        }
    }

    // mihomo server.go: `auto-route` is required by `auto-redirect` — without
    // auto-route there is nothing to push UDP/DNS into the TUN and the output
    // redirect (oifname tun) never matches, so the TUN silently does nothing.
    if tun_cfg.auto_redirect && !tun_cfg.auto_route {
        bail!("tun: `auto-route` is required by `auto-redirect`");
    }

    let (dev, if_name) = device::create_device(&tun_cfg)
        .await
        .context("create TUN device")?;

    // Address assignment (side-effect on the OS interface).
    // Always parse for the in-process system stack (NAT / DNS hijack targets),
    // even when external FD — values must match what VpnService configured.
    let mut inet4_server = None;
    let mut inet4_client = None;
    let mut inet6_server = None;
    let mut inet6_client = None;
    let mut prefixes_v4 = Vec::new();
    let mut v4_list = Vec::new();
    let mut v6_list = Vec::new();

    let addrs = if tun_cfg.address.is_empty() {
        // Default pair used by many clients.
        vec!["198.18.0.1/30".to_string()]
    } else {
        tun_cfg.address.clone()
    };

    for a in &addrs {
        let (ip, pl) = parse_addr_prefix(a)?;
        match ip {
            IpAddr::V4(v4) => {
                if !has_next_addr_v4(v4, pl) {
                    bail!("tun address {a}: need room for addr+1 (avoid /32)");
                }
                let client = next_v4(v4);
                if inet4_server.is_none() {
                    inet4_server = Some(v4);
                    inet4_client = Some(client);
                }
                prefixes_v4.push((v4, pl));
                v4_list.push((v4, pl));
            }
            IpAddr::V6(v6) => {
                if !has_next_addr_v6(v6, pl) {
                    bail!("tun address {a}: need room for addr+1 (avoid /128)");
                }
                let client = next_v6(v6);
                if inet6_server.is_none() {
                    inet6_server = Some(v6);
                    inet6_client = Some(client);
                }
                v6_list.push((v6, pl));
            }
        }
    }

    if external_fd {
        // sing-tun: when FileDescriptor != 0, skip configure/start that mutates
        // the OS interface — VpnService already set addresses / brought it up.
        info!(
            interface = %if_name,
            mtu = tun_cfg.mtu,
            v4 = ?inet4_server,
            v6 = ?inet6_server,
            "tun: device ready (external fd; OS config skipped)"
        );
    } else {
        device::configure_addresses(&if_name, &tun_cfg, &v4_list, &v6_list)
            .await
            .context("configure TUN addresses")?;

        info!(
            interface = %if_name,
            mtu = tun_cfg.mtu,
            v4 = ?inet4_server,
            v6 = ?inet6_server,
            "tun: device ready"
        );
    }

    // Marks (single route mark; auto-redirect uses the classic topology, same
    // as mihomo without route-address-set). Prefer values set by main.
    // External FD: marks still useful for loop prevention if the host allows
    // SO_MARK; otherwise auto-detect-interface / VpnService.protect is preferred.
    let marks = marks::TunMarks::resolve(
        crate::app::sockopt::fwmark(),
        tun_cfg.auto_route,
        tun_cfg.auto_redirect,
        tun_cfg.auto_detect_interface,
    );
    // Ensure dialer SO_MARK uses the resolved mark.
    crate::app::sockopt::set_fwmark(marks.output);
    if marks.output != 0 {
        info!(mark = format!("0x{:x}", marks.output), "tun: route mark");
    }

    // auto-detect-interface
    if tun_cfg.auto_detect_interface {
        iface::start_monitor(if_name.clone(), true);
    } else if tun_cfg.auto_route || tun_cfg.auto_redirect {
        warn!(
            "tun: auto-route/auto-redirect without auto-detect-interface — unbound dialer \
             sockets may re-enter the TUN (redirect loop); bind them or set `mark`"
        );
    }

    let has_v4 = inet4_server.is_some();
    let has_v6 = inet6_server.is_some();

    // DNS hijack active? mihomo hijacks the TUN gateway DNS addr even without
    // an explicit `dns-hijack` list (dnsAdds always contains Inet4/6Address
    // next():53). Config validation guarantees the DNS module always has an
    // answer path (rule-follow-route → direct/proxy-nameserver; custom →
    // dns.rules/nameserver), so gateway hijack is always available.
    let dns_hijack_enabled = true;

    // auto-route / strict-route
    let _route_guard = if tun_cfg.auto_route {
        Some(
            route::install_routes(&if_name, &tun_cfg, has_v4, has_v6, dns_hijack_enabled)
                .await
                .context("auto-route")?,
        )
    } else {
        None
    };

    // auto-redirect: internal listener + nft/iptables (no redir-port)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _redirect_guard = if tun_cfg.auto_redirect {
        let params = redirect::RedirectParams {
            tun_if: if_name.clone(),
            has_v4,
            has_v6,
            strict_route: tun_cfg.strict_route,
            dns_hijack: !tun_cfg.dns_hijack.is_empty(),
            // TUN-side DNS address (client addr) — same target the stack-side
            // hijack list registers, so DNAT-ed DNS lands in the TUN device.
            dns_v4: inet4_server.map(next_v4),
            dns_v6: inet6_server.map(next_v6),
        };
        match redirect::start_auto_redirect(params, router.clone(), outbounds.clone()).await {
            Ok(g) => Some(g),
            Err(e) => {
                warn!("tun: auto-redirect skipped: {e:#}");
                None
            }
        }
    } else {
        None
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    if tun_cfg.auto_redirect {
        warn!("tun: auto-redirect is Linux-only; ignored");
    }

    // Linux: probe IFF_VNET_HDR + TUNSETOFFLOAD for GSO/GRO.
    let (vnet_hdr, gro_flags) = {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let off = offload::setup_tun_offload(dev.as_raw_fd());
            info!(
                vnet_hdr = off.vnet_hdr,
                tcp_gso = off.tcp_gso,
                udp_gso = off.udp_gso,
                "tun: offload probe"
            );
            let mut gro = gso::GroDisablementFlags::default();
            if !off.tcp_gso {
                gro.disable_tcp();
            }
            if !off.udp_gso {
                gro.disable_udp();
            }
            (off.vnet_hdr, gro)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            info!("tun: non-Linux path (macOS/Windows) — pure IP frames, no kernel vnet_hdr/GSO");
            (false, gso::GroDisablementFlags::default())
        }
    };

    // DNS hijack context
    // dns-hijack: user list + TUN gateway:53 (mihomo behaviour — dnsAdds
    // always contains the Inet4/6Address next():53 entries).
    let mut dns_list = tun_cfg.dns_hijack.clone();
    if !dns_list.is_empty() {
        if let Some(a) = inet4_server {
            // gateway is often addr+1 (client); hijack both server and next
            dns_list.push(format!("{a}:53"));
            dns_list.push(format!("{}:53", next_v4(a)));
        }
        if let Some(a) = inet6_server {
            dns_list.push(format!("[{a}]:53"));
            dns_list.push(format!("[{}]:53", next_v6(a)));
        }
        // any:53 already covers all; keep explicit gateways for clarity
    } else {
        // Gateway-only hijack (mihomo behaviour without an explicit list).
        if let Some(a) = inet4_server {
            dns_list.push(format!("{}:53", next_v4(a)));
        }
        if let Some(a) = inet6_server {
            dns_list.push(format!("[{}]:53", next_v6(a)));
        }
    }
    let dns_hijack = stack::parse_dns_hijack(&dns_list);
    if !dns_hijack.is_empty() {
        info!(rules = dns_hijack.len(), "tun: dns-hijack enabled");
    }

    // Brief wait so the OS registers the address before we bind listeners.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Windows: allow inbound TCP to our listener. The system stack's NAT
    // rewrites TUN SYNs to <tun addr>:port, so from Windows Firewall's view
    // every proxied TCP connection is an **inbound** connection to ant.exe —
    // the default block policy silently drops them (sing-tun
    // fixWindowsFirewall does exactly this).
    #[cfg(target_os = "windows")]
    device::ensure_firewall_rule();

    // Keep route/redirect guards alive for the lifetime of the stack.
    let result = match tun_cfg.stack {
        crate::config::TunStack::System => {
            info!("tun: system stack (kernel NAT + local listener)");
            stack::run_system_stack(stack::TunStackParams {
                dev,
                if_name,
                cfg: tun_cfg,
                addrs: stack::StackAddrs {
                    inet4_server,
                    inet4_client,
                    inet6_server,
                    inet6_client,
                    prefixes_v4,
                },
                router,
                outbounds,
                vnet_hdr,
                gro_flags,
                dns_hijack,
            })
            .await
        }
        crate::config::TunStack::Gvisor => {
            info!("tun: gvisor stack (user-space smoltcp netstack)");
            stack::run_gvisor_stack(stack::TunStackParams {
                dev,
                if_name,
                cfg: tun_cfg,
                addrs: stack::StackAddrs {
                    inet4_server,
                    inet4_client,
                    inet6_server,
                    inet6_client,
                    prefixes_v4,
                },
                router,
                outbounds,
                vnet_hdr,
                gro_flags,
                dns_hijack,
            })
            .await
        }
    };

    // Explicit drop order: stack ends first, then guards clean up.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    drop(_redirect_guard);
    drop(_route_guard);
    result
}

fn parse_addr_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let (ip_str, pl_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected addr/prefix, got `{s}`"))?;
    let ip: IpAddr = ip_str.parse().context("parse IP")?;
    let pl: u8 = pl_str.parse().context("parse prefix length")?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if pl > max {
        bail!("prefix length {pl} > {max}");
    }
    Ok((ip, pl))
}

fn next_v4(ip: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip).wrapping_add(1))
}

fn next_v6(ip: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(ip).wrapping_add(1))
}

fn has_next_addr_v4(ip: Ipv4Addr, pl: u8) -> bool {
    let cur = u32::from(ip);
    if cur == u32::MAX {
        return false;
    }
    let next = cur + 1;
    let mask = if pl == 0 {
        0u32
    } else {
        !((1u32 << (32 - pl.min(32))) - 1)
    };
    (cur & mask) == (next & mask)
}

fn has_next_addr_v6(ip: Ipv6Addr, pl: u8) -> bool {
    let cur = u128::from(ip);
    if cur == u128::MAX {
        return false;
    }
    let next = cur + 1;
    let mask = if pl == 0 {
        0u128
    } else {
        !((1u128 << (128 - pl.min(128))) - 1)
    };
    (cur & mask) == (next & mask)
}
