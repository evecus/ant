//! TUN device create + address setup (no routes).

use crate::config::TunConfig;
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
use std::process::Command;
use tracing::info;
#[cfg(not(target_os = "macos"))]
use tracing::warn;

/// Create an async TUN device. Returns (device, interface name).
///
/// When `cfg.resolved_file_descriptor()` is `Some(fd)` (config `file-descriptor`
/// or env `ANT_TUN_FD`), adopt that fd — same pattern as sing-tun's
/// `Options.FileDescriptor` for Android VpnService / iOS PacketTunnelProvider.
pub async fn create_device(cfg: &TunConfig) -> Result<(tun::AsyncDevice, String)> {
    let mut tun_cfg = tun::Configuration::default();
    tun_cfg.mtu(cfg.mtu as u16);

    // --- External FD path (Android VpnService / iOS / parent process) ---
    // Mirrors sing-tun: if FileDescriptor != 0, wrap the fd and skip open().
    #[cfg(unix)]
    if let Some(fd) = cfg.resolved_file_descriptor() {
        info!(fd, close_on_drop = cfg.close_fd_on_drop, "tun: adopting external file descriptor");
        tun_cfg.raw_fd(fd);
        tun_cfg.close_fd_on_drop(cfg.close_fd_on_drop);
        // Do not call up() / ensure_root / vnet_hdr — the provider already
        // configured the interface (VpnService.Builder / NEPacketTunnel).
        let dev = tun::create_as_async(&tun_cfg).context(
            "adopt external TUN fd (Android VpnService / iOS PacketTunnel / parent)",
        )?;
        let if_name = resolve_if_name(&dev, cfg);
        return Ok((dev, if_name));
    }

    #[cfg(not(unix))]
    if cfg.resolved_file_descriptor().is_some() {
        warn!("tun: file-descriptor / ANT_TUN_FD is Unix-only; ignored on this platform");
    }

    // --- Normal create path ---
    // Android without an external FD: root self-create via /dev/tun +
    // TUNSETIFF (requires root / CAP_NET_ADMIN). The resulting fd is wrapped
    // exactly like a VpnService fd; auto-route is then handled by route.rs
    // with `ip rule` / `ip route` (rtnetlink enabled for root mode).
    #[cfg(target_os = "android")]
    {
        let (fd, if_name) = open_tun_root(cfg.device.as_deref())?;
        info!(
            fd,
            interface = %if_name,
            "tun: root self-created TUN via /dev/tun (IFF_TUN|IFF_NO_PI)"
        );
        tun_cfg.raw_fd(fd);
        tun_cfg.close_fd_on_drop(true); // we own this fd
        let dev = tun::create_as_async(&tun_cfg).context("adopt root TUN fd")?;
        return Ok((dev, if_name));
    }

    #[cfg(not(target_os = "android"))]
    {
        tun_cfg.up();

        // Interface name
        #[cfg(target_os = "windows")]
        {
            let name = cfg.device.as_deref().filter(|s| !s.is_empty()).unwrap_or("ant-tun");
            tun_cfg.tun_name(name);
            // wintun.dll is loaded via the tun crate (wintun-bindings, bare name
            // "wintun.dll" → LoadLibrary default search order): exe directory
            // first, then System32, cwd, PATH. Ship it next to ant.exe.
            // Ring size: the tun crate defaults to WINTUN_MAX_RING_CAPACITY
            // (64 MiB of contiguous non-paged kernel memory per adapter);
            // sing-tun/mihomo uses 0x800000 (8 MiB) — 8 MiB is far beyond any
            // realistic burst window at typical TUN MTUs and cuts the ring's
            // kernel memory footprint 8x. (sing-tun tun_windows.go:60)
            tun_cfg.ring_capacity(0x800000);
        }
        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref name) = cfg.device {
                if !name.is_empty() {
                    tun_cfg.tun_name(name);
                }
            }
        }

        // Linux only: IFF_VNET_HDR for GSO/GRO. Android PlatformConfig has no
        // vnet_hdr/ensure_root — the root path above creates the device with
        // TUNSETIFF directly, so no offload there (GSO/GRO stay disabled).
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        {
            tun_cfg.platform_config(|p| {
                p.ensure_root_privileges(true);
                p.vnet_hdr(true);
            });
        }

        // macOS: utun always has a 4-byte AF family PI header at the kernel
        // boundary. Keep packet_information=true so the `tun` crate strips on
        // read / prepends on write — upper layers see pure IP (same as
        // sing-tun PacketOffset handling). Disable crate auto-routing; we
        // configure addresses ourselves via ioctl and leave routes to the
        // (optional) auto-route module.
        #[cfg(target_os = "macos")]
        {
            // Name must be utunN if set (sing-tun parses utun%d). Empty → system picks.
            if let Some(ref name) = cfg.device {
                if !name.is_empty() && !name.starts_with("utun") {
                    anyhow::bail!(
                        "tun: on macOS device name must be utunN (got `{name}`);                          leave empty to let the system allocate"
                    );
                }
            }
            tun_cfg.platform_config(|p| {
                p.packet_information(true);
                p.enable_routing(false);
            });
        }

        let dev = tun::create_as_async(&tun_cfg).context(
            "create TUN device (Linux: CAP_NET_ADMIN; macOS: root/utun; Windows: wintun.dll next to binary or in PATH)",
        )?;

        let if_name = resolve_if_name(&dev, cfg);

        // macOS: enlarge SO_RCVBUF on the utun fd (sing-tun configure()).
        #[cfg(target_os = "macos")]
        {
            // AsyncDevice does not implement AsRawFd itself; the inner Device does
            // (tun crate). Reach it via Deref.
            use std::os::unix::io::AsRawFd;
            let applied = super::macos::tune_recv_buffer((*dev).as_raw_fd(), cfg.mtu);
            tracing::info!(rcvbuf = applied, interface = %if_name, "tun: utun SO_RCVBUF tuned");
        }

        Ok((dev, if_name))
    }
}

/// Android root self-create: open `/dev/tun` and run TUNSETIFF with
/// IFF_TUN | IFF_NO_PI (layer-3, pure IP — matches the VpnService fd contract
/// the rest of the TUN stack expects). Requires root / CAP_NET_ADMIN.
/// Returns (fd, interface name assigned by the kernel — `tunN` when the
/// requested name is empty).
#[cfg(target_os = "android")]
fn open_tun_root(device: Option<&str>) -> Result<(std::os::fd::RawFd, String)> {
    use std::os::fd::RawFd;

    // _IOW('T', 202, int) — same value as Linux (asm-generic).
    const TUNSETIFF: libc::c_int = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    /// struct ifreq as the kernel sees it: 16-byte name + union, 40 bytes on
    /// every Android ABI. Defined locally so we don't depend on the libc
    /// crate's anonymous-union field naming.
    #[repr(C)]
    struct ifreq_tun {
        ifr_name: [libc::c_char; 16],
        ifr_flags: libc::c_short,
        ifr_pad: [u8; 22],
    }

    // /dev/tun is the standard Android path; /dev/net/tun as fallback.
    let mut fd: RawFd = -1;
    for path in ["/dev/tun\0", "/dev/net/tun\0"] {
        fd = unsafe {
            libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break;
        }
    }
    if fd < 0 {
        anyhow::bail!(
            "open /dev/tun: {} (root self-create requires running as root; \
             for VpnService use tun.file-descriptor / ANT_TUN_FD instead)",
            std::io::Error::last_os_error()
        );
    }

    let mut ifr: ifreq_tun = unsafe { std::mem::zeroed() };
    if let Some(name) = device.filter(|s| !s.is_empty()) {
        let bytes = name.as_bytes();
        let n = bytes.len().min(15); // keep NUL
        for (i, &b) in bytes[..n].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
    } // empty name → kernel assigns tunN
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    let rc = unsafe {
        libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut ifreq_tun as *mut libc::c_void)
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        anyhow::bail!("TUNSETIFF: {err} (need root / CAP_NET_ADMIN)");
    }

    let name_len = ifr
        .ifr_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(16);
    let name: String = ifr.ifr_name[..name_len]
        .iter()
        .map(|&c| c as u8 as char)
        .collect();
    Ok((fd, name))
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
            #[cfg(target_os = "macos")]
            {
                "utun0".into()
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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

        #[cfg(target_os = "macos")]
        {
            // Full ioctl path — sing-tun tun_darwin.go create() equivalent.
            // Fail-fast: without addresses the system stack has nowhere to bind.
            super::macos::configure_interface(&if_name, mtu, &v4, &v6)?;
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (if_name, mtu, v4, v6);
            warn!("tun: address configuration not implemented on this platform");
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("configure_addresses task failed")?
    .context("configure_addresses")?;

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
            remove_blocking_rules_for_exe(&prog);
        }
        Ok(out) => warn!(
            program = %prog,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "tun: failed to add firewall rule (inbound TCP may be blocked)"
        ),
        Err(e) => warn!(program = %prog, err = %e, "failed to run netsh advfirewall"),
    }
}

/// Remove enabled *inbound Block* rules bound to this executable. Windows
/// creates them when the "allow this app through the firewall" prompt is
/// dismissed; an explicit Block beats our Allow rule, so the NAT-ed inbound
/// SYNs to the TUN listener are silently dropped and no TCP ever connects.
#[cfg(target_os = "windows")]
fn remove_blocking_rules_for_exe(prog: &str) {
    const SCRIPT: &str = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
        Get-NetFirewallApplicationFilter -Program '@PROG@' -ErrorAction SilentlyContinue | \
        Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and \
        $_.Action -eq 'Block' -and $_.Enabled -eq 'True' } | ForEach-Object { \
        $_.DisplayName + '|' + $_.Profile; $_ | Remove-NetFirewallRule }";
    let script = SCRIPT.replace("@PROG@", prog);
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                warn!(
                    rule = %line,
                    "tun: removed inbound Block firewall rule for this exe (it overrides the Allow rule and drops TUN TCP)"
                );
            }
        }
        Err(e) => warn!(err = %e, "tun: failed to run powershell to remove blocking firewall rules"),
    }
}
