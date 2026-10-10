//! Policy routing + link setup (nexa `proxy.init:188-233`).
//!
//! - tproxy: `ip rule add pref P fwmark M/mask table T` +
//!   `ip route add local default dev lo table T`
//! - tun:    same rule shape + `ip route add default dev <tun> table T`
//! - fake-ip6: dummy device + `ip -6 route add <fakeip6-range> dev <dummy>`
//! - `mode: tun` waits for the TUN device to come up first (nexa `waitForTUN`)
//!
//! Installation uses **rtnetlink**; teardown shells out to `ip` so it works
//! from `Drop` without a tokio runtime handle.
//! Tables 80/81 stay clear of `tun.iproute2-table-index` (1982).

use super::{Params, DUMMY_DEVICE, TUN_TIMEOUT};
use anyhow::{Context, Result};
use netlink_packet_route::route::{RouteScope, RouteType};
use netlink_packet_route::rule::{RuleAction, RuleAttribute};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;
use tracing::{info, warn};

pub async fn install(p: &Params) -> Result<()> {
    // TUN device is created by the TUN inbound, which may not have come up yet.
    if p.needs_tun() && !wait_for_tun(&p.tun_device, TUN_TIMEOUT) {
        anyhow::bail!(
            "ip-auto-route: TUN device `{}` did not come up within {}s",
            p.tun_device,
            TUN_TIMEOUT
        );
    }

    let (conn, handle, _) = rtnetlink::new_connection().context("rtnetlink connect")?;
    tokio::spawn(conn);

    if p.needs_tproxy() {
        install_tproxy(&handle, p)
            .await
            .context("tproxy policy routing")?;
        info!(
            table = p.tproxy_table,
            pref = p.tproxy_pref,
            mark = format!("0x{:x}", p.tproxy_mark),
            "ip-auto-route: tproxy policy routing installed (rtnetlink)"
        );
    }
    if p.needs_tun() {
        install_tun(&handle, p)
            .await
            .context("tun policy routing")?;
        info!(
            table = p.tun_table,
            pref = p.tun_pref,
            mark = format!("0x{:x}", p.tun_mark),
            device = %p.tun_device,
            "ip-auto-route: tun policy routing installed (rtnetlink)"
        );
    }

    install_dummy(p);
    Ok(())
}

/// Synchronous teardown: ip rules, table routes, and the fake-ip6 dummy device.
pub fn cleanup(p: &Params) {
    let families: &[&str] = if p.ipv6 { &["-4", "-6"] } else { &["-4"] };
    for fam in families {
        for table in [p.tproxy_table, p.tun_table] {
            // Delete by pref first (exact), then sweep anything left in the table.
            let _ = Command::new("ip")
                .args([
                    fam,
                    "rule",
                    "del",
                    "pref",
                    &p.tproxy_pref.to_string(),
                    "table",
                    &table.to_string(),
                ])
                .output();
            let _ = Command::new("ip")
                .args([
                    fam,
                    "rule",
                    "del",
                    "pref",
                    &p.tun_pref.to_string(),
                    "table",
                    &table.to_string(),
                ])
                .output();
            let _ = Command::new("ip")
                .args([fam, "rule", "del", "table", &table.to_string()])
                .output();
            let _ = Command::new("ip")
                .args([fam, "route", "flush", "table", &table.to_string()])
                .output();
        }
    }
    remove_dummy(p);
}

/// `ip link add <dev> type dummy` + `ip -6 route add <fakeip6> dev <dev>`
/// (nexa proxy.init:229-233) — gives the Fake-IP v6 range a route so the
/// kernel hands those packets to us instead of returning ENETUNREACH.
fn install_dummy(p: &Params) {
    let Some(range) = p.fakeip_v6.as_deref() else {
        return;
    };
    let dev = DUMMY_DEVICE;
    let _ = Command::new("ip")
        .args(["link", "add", dev, "type", "dummy"])
        .output();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", dev, "up"])
        .output();
    let out = Command::new("ip")
        .args(["-6", "route", "add", range, "dev", dev])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            info!(device = %dev, range = %range, "ip-auto-route: fake-ip6 dummy route installed");
        }
        Ok(o) => {
            warn!(
                err = %String::from_utf8_lossy(&o.stderr).trim(),
                device = %dev,
                range = %range,
                "ip-auto-route: fake-ip6 dummy route failed"
            );
        }
        Err(e) => warn!(err = %e, "ip-auto-route: ip command failed for dummy route"),
    }
}

fn remove_dummy(p: &Params) {
    if p.fakeip_v6.is_none() {
        return;
    }
    let _ = Command::new("ip")
        .args(["link", "del", DUMMY_DEVICE])
        .output();
}

/// Poll `/sys/class/net/<dev>/flags` until `IFF_UP` (bit 0) is set
/// (nexa `waitForTUN`, 1s interval).
fn wait_for_tun(dev: &str, timeout: u32) -> bool {
    let path = format!("/sys/class/net/{dev}/flags");
    for _ in 0..timeout.max(1) {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(flags) = u32::from_str_radix(s.trim().trim_start_matches("0x"), 16) {
                if flags & 0x1 != 0 {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

async fn install_tproxy(handle: &rtnetlink::Handle, p: &Params) -> Result<()> {
    let lo_index = if_nametoindex("lo").context("resolve lo")?;

    for v6 in [false, true] {
        if v6 && !p.ipv6 {
            continue;
        }
        add_local_default(handle, p.tproxy_table, lo_index, v6)
            .await
            .with_context(|| format!("local default lo table {} v6={v6}", p.tproxy_table))?;
        add_fwmark_rule(
            handle,
            p.tproxy_pref,
            p.tproxy_mark,
            p.tproxy_mask,
            p.tproxy_table,
            v6,
        )
        .await
        .with_context(|| format!("fwmark rule tproxy v6={v6}"))?;
    }
    Ok(())
}

async fn install_tun(handle: &rtnetlink::Handle, p: &Params) -> Result<()> {
    let if_index = if_nametoindex(&p.tun_device)
        .with_context(|| format!("tun device `{}` not found", p.tun_device))?;

    for v6 in [false, true] {
        if v6 && !p.ipv6 {
            continue;
        }
        add_unicast_default(handle, p.tun_table, if_index, v6)
            .await
            .with_context(|| format!("default dev tun table {} v6={v6}", p.tun_table))?;
        add_fwmark_rule(handle, p.tun_pref, p.tun_mark, p.tun_mask, p.tun_table, v6)
            .await
            .with_context(|| format!("fwmark rule tun v6={v6}"))?;
    }
    Ok(())
}

/// `ip rule add pref P fwmark M/mask table T`
async fn add_fwmark_rule(
    handle: &rtnetlink::Handle,
    pref: u32,
    mark: u32,
    mask: u32,
    table: u32,
    v6: bool,
) -> Result<()> {
    // v4/v6 RuleAddRequest are distinct types — cannot share one binding.
    let result = if v6 {
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(pref)
            .fw_mark(mark)
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut()
            .attributes
            .push(RuleAttribute::FwMask(mask));
        req.execute().await
    } else {
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(pref)
            .fw_mark(mark)
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut()
            .attributes
            .push(RuleAttribute::FwMask(mask));
        req.execute().await
    };

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let s = e.to_string();
            if s.contains("exists") || s.contains("File exists") || s.contains("EEXIST") {
                warn!(%s, pref, table, "ip-auto-route: rule exists, ok");
                Ok(())
            } else {
                Err(anyhow::anyhow!("{e}"))
            }
        }
    }
}

/// `ip route replace local default dev lo table T`
async fn add_local_default(
    handle: &rtnetlink::Handle,
    table: u32,
    lo_index: u32,
    v6: bool,
) -> Result<()> {
    if v6 {
        handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(lo_index)
            .table_id(table)
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .replace()
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        handle
            .route()
            .add()
            .v4()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(lo_index)
            .table_id(table)
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .replace()
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

/// `ip route replace default dev <tun> table T`
async fn add_unicast_default(
    handle: &rtnetlink::Handle,
    table: u32,
    if_index: u32,
    v6: bool,
) -> Result<()> {
    if v6 {
        handle
            .route()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(if_index)
            .table_id(table)
            .kind(RouteType::Unicast)
            .replace()
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        handle
            .route()
            .add()
            .v4()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(if_index)
            .table_id(table)
            .kind(RouteType::Unicast)
            .replace()
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

fn if_nametoindex(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface `{name}` not found");
    }
    Ok(idx)
}
