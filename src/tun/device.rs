//! TUN device create + address setup (no routes).

use crate::config::TunConfig;
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::{info, warn};

/// Create an async TUN device. Returns (device, interface name).
pub async fn create_device(cfg: &TunConfig) -> Result<(tun::AsyncDevice, String)> {
    let mut tun_cfg = tun::Configuration::default();
    tun_cfg.mtu(cfg.mtu as u16);
    tun_cfg.up();

    // Interface name
    #[cfg(target_os = "windows")]
    {
        let name = cfg.device.as_deref().filter(|s| !s.is_empty()).unwrap_or("ant-tun");
        tun_cfg.tun_name(name);
        // wintun.dll is loaded via the tun crate (wintun-bindings, bare name
        // "wintun.dll" → LoadLibrary default search order): exe directory
        // first, then System32, cwd, PATH. Ship it next to ant.exe.
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(ref name) = cfg.device {
            if !name.is_empty() {
                tun_cfg.tun_name(name);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // IFF_VNET_HDR enables virtio_net_hdr on every R/W (required for GSO/GRO).
        tun_cfg.platform_config(|p| {
            p.ensure_root_privileges(true);
            p.vnet_hdr(true);
        });
    }

    let dev = tun::create_as_async(&tun_cfg).context(
        "create TUN device (Linux: CAP_NET_ADMIN; Windows: wintun.dll next to binary or in PATH)",
    )?;

    let if_name = resolve_if_name(&dev, cfg);
    Ok((dev, if_name))
}

fn resolve_if_name(dev: &tun::AsyncDevice, cfg: &TunConfig) -> String {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        use tun::AbstractDevice as _;
        if let Ok(name) = dev.tun_name() {
            if !name.is_empty() {
                return name;
            }
        }
    }
    cfg.device
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            #[cfg(target_os = "windows")]
            {
                "ant-tun".into()
            }
            #[cfg(not(target_os = "windows"))]
            {
                "tun0".into()
            }
        })
}

/// Assign addresses and MTU. Does **not** add default routes or policy rules.
pub async fn configure_addresses(
    if_name: &str,
    cfg: &TunConfig,
    v4: &[(Ipv4Addr, u8)],
    v6: &[(Ipv6Addr, u8)],
) -> Result<()> {
    let if_name = if_name.to_string();
    let mtu = cfg.mtu;
    // Only consumed by the Windows DNS-registration branch below.
    #[cfg(target_os = "windows")]
    let auto_route = cfg.auto_route;
    let v4 = v4.to_vec();
    let v6 = v6.to_vec();

    tokio::task::spawn_blocking(move || {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            run_ip(&["link", "set", "dev", &if_name, "mtu", &mtu.to_string()]);
            run_ip(&["link", "set", "dev", &if_name, "up"]);
            for (ip, pl) in &v4 {
                run_ip(&[
                    "addr",
                    "replace",
                    &format!("{ip}/{pl}"),
                    "dev",
                    &if_name,
                ]);
            }
            for (ip, pl) in &v6 {
                run_ip(&[
                    "-6",
                    "addr",
                    "replace",
                    &format!("{ip}/{pl}"),
                    "dev",
                    &if_name,
                ]);
            }
            info!(interface = %if_name, "tun: addresses configured via ip");
        }

        #[cfg(target_os = "windows")]
        {
            // sing-tun configure(): DadTransmits=0 / RouterDiscovery disabled
            // on BOTH families **before** addresses exist. netsh-assigned
            // addresses otherwise sit in IPv4 DAD (tentative) for ~2s and
            // binding them fails with WSAEADDRNOTAVAIL (10049).
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "interface",
                    &format!("interface={if_name}"),
                    "dadtransmits=0",
                    "forwarding=enabled",
                    "store=active",
                ],
            );
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "set",
                    "interface",
                    &format!("interface={if_name}"),
                    "dadtransmits=0",
                    "routerdiscovery=disabled",
                    "managedaddress=disabled",
                    "otherstateful=disabled",
                    "store=active",
                ],
            );

            for (ip, pl) in &v4 {
                let mask = prefix_to_mask_v4(*pl);
                let ok = run_cmd(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "set",
                        "address",
                        &format!("name={if_name}"),
                        "source=static",
                        &format!("addr={ip}"),
                        &format!("mask={mask}"),
                    ],
                );
                if !ok {
                    run_cmd(
                        "netsh",
                        &[
                            "interface",
                            "ipv4",
                            "add",
                            "address",
                            &format!("name={if_name}"),
                            &format!("addr={ip}"),
                            &format!("mask={mask}"),
                        ],
                    );
                }
            }
            for (ip, pl) in &v6 {
                run_cmd(
                    "netsh",
                    &[
                        "interface",
                        "ipv6",
                        "set",
                        "address",
                        &format!("interface={if_name}"),
                        &format!("address={ip}/{pl}"),
                    ],
                );
            }
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "subinterface",
                    &format!("interface={if_name}"),
                    &format!("mtu={mtu}"),
                    "store=active",
                ],
            );

            // sing-tun configure(): when AutoRoute (and DNS hijack not
            // disabled) the TUN interface gets DNS = next address of the
            // first v4/v6 address, so the OS resolver sends queries into the
            // TUN where the hijack rules answer them. `register=none` covers
            // sing-tun's DisableDNSRegistration.
            if auto_route {
                if let Some((ip, _)) = v4.first() {
                    let next = Ipv4Addr::from(u32::from(*ip).wrapping_add(1));
                    run_cmd(
                        "netsh",
                        &[
                            "interface",
                            "ipv4",
                            "set",
                            "dnsservers",
                            &format!("name={if_name}"),
                            "source=static",
                            &format!("address={next}"),
                            "register=none",
                            "validate=no",
                        ],
                    );
                }
                if let Some((ip, _)) = v6.first() {
                    let next = Ipv6Addr::from(u128::from(*ip).wrapping_add(1));
                    run_cmd(
                        "netsh",
                        &[
                            "interface",
                            "ipv6",
                            "set",
                            "dnsservers",
                            &format!("interface={if_name}"),
                            "source=static",
                            &format!("address={next}"),
                            "register=none",
                            "validate=no",
                        ],
                    );
                }
                // sing-tun configure(): FlushResolverCache after route/DNS
                // changes; repeated again on cleanup.
                run_cmd("ipconfig", &["/flushdns"]);
            }

            info!(interface = %if_name, "tun: addresses configured via netsh");
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows"
        )))]
        {
            let _ = (if_name, mtu, v4, v6);
            warn!("tun: address configuration not implemented on this platform");
        }
    })
    .await
    .context("configure_addresses task failed")?;

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_ip(args: &[&str]) {
    match Command::new("ip").args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            cmd = ?args,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "ip command failed"
        ),
        Err(e) => warn!(cmd = ?args, err = %e, "failed to run ip"),
    }
}

#[cfg(target_os = "windows")]
fn run_cmd(bin: &str, args: &[&str]) -> bool {
    match Command::new(bin).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            warn!(
                cmd = %bin,
                args = ?args,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "command failed"
            );
            false
        }
        Err(e) => {
            warn!(cmd = %bin, err = %e, "failed to run command");
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn prefix_to_mask_v4(pl: u8) -> Ipv4Addr {
    let pl = pl.min(32);
    let mask = if pl == 0 {
        0u32
    } else {
        !((1u32 << (32 - pl)) - 1)
    };
    Ipv4Addr::from(mask)
}

/// sing-tun `fixWindowsFirewall()` alignment: the system stack's NAT rewrites
/// TUN TCP SYNs to our listener address, so Windows Firewall sees every
/// proxied connection as an **inbound** TCP connection to ant.exe and the
/// default block policy silently drops them. Add an inbound allow rule for
/// this executable (idempotent: delete + add; rule persists like sing-tun's).
#[cfg(target_os = "windows")]
pub fn ensure_firewall_rule() {
    let Ok(exe) = std::env::current_exe() else {
        warn!("tun: cannot resolve current exe, skipping firewall rule");
        return;
    };
    let prog = exe.to_string_lossy().to_string();
    let name = format!("ant ({prog})");
    // Clean previous rule (same name), then add. Failure is non-fatal: the
    // user may have allowed ant manually; warn so the cause is discoverable.
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")])
        .output();
    let out = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name}"),
            "dir=in",
            "action=allow",
            &format!("program={prog}"),
            "protocol=TCP",
            "profile=any",
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {
            info!(program = %prog, "tun: firewall inbound allow rule installed");
        }
        Ok(out) => warn!(
            program = %prog,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "tun: failed to add firewall rule (inbound TCP may be blocked)"
        ),
        Err(e) => warn!(program = %prog, err = %e, "failed to run netsh advfirewall"),
    }
}
