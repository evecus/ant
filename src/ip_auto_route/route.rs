//! Policy routing via pure **rtnetlink** + **netlink-packet-route**.
//!
//! - tproxy: `fwmark mark/mask → table T` + `local default dev lo table T`
//! - tun:    `fwmark mark/mask → table T` + `default dev <tun> table T`
//!
//! Tables 80/81 stay clear of `tun.iproute2-table-index` (1982).

use super::Params;
use anyhow::{Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteScope, RouteType};
use netlink_packet_route::rule::{RuleAction, RuleAttribute};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

pub async fn install(p: &Params) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection().context("rtnetlink connect")?;
    tokio::spawn(conn);

    if p.needs_tproxy_route() {
        install_tproxy(&handle, p)
            .await
            .context("tproxy policy routing")?;
        info!(
            table = p.tproxy_table,
            pref = p.tproxy_pref,
            mark = p.mark,
            "ip-auto-route: tproxy policy routing installed (rtnetlink)"
        );
    }
    if p.needs_tun_route() {
        install_tun(&handle, p)
            .await
            .context("tun policy routing")?;
        info!(
            table = p.tun_table,
            pref = p.tun_pref,
            device = %p.tun_device,
            "ip-auto-route: tun policy routing installed (rtnetlink)"
        );
    }
    Ok(())
}

pub async fn cleanup(p: &Params) -> Result<()> {
    let (conn, handle, _) = match rtnetlink::new_connection() {
        Ok(c) => c,
        Err(e) => {
            warn!(err = %e, "ip-auto-route: rtnetlink cleanup connect failed");
            cleanup_sync(p);
            return Ok(());
        }
    };
    tokio::spawn(conn);
    cleanup_with_handle(&handle, p).await;
    Ok(())
}

/// Sync fallback used from Drop when no runtime handle is available.
pub fn cleanup_sync(p: &Params) {
    use std::process::Command;
    for fam in ["-4", "-6"] {
        if fam == "-6" && !p.ipv6 {
            continue;
        }
        for (pref, table) in [
            (p.tproxy_pref, p.tproxy_table),
            (p.tun_pref, p.tun_table),
        ] {
            let _ = Command::new("ip")
                .args([
                    fam,
                    "rule",
                    "del",
                    "pref",
                    &pref.to_string(),
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
}

async fn cleanup_with_handle(handle: &rtnetlink::Handle, p: &Params) {
    for v6 in [false, true] {
        if v6 && !p.ipv6 {
            continue;
        }
        let mut rules = if v6 {
            handle.rule().get(rtnetlink::IpVersion::V6).execute()
        } else {
            handle.rule().get(rtnetlink::IpVersion::V4).execute()
        };
        let mut to_del = Vec::new();
        while let Ok(Some(msg)) = rules.try_next().await {
            let table = msg
                .attributes
                .iter()
                .find_map(|a| match a {
                    // iter() yields &RuleAttribute → field binds as &u32
                    RuleAttribute::Table(t) => Some(*t),
                    _ => None,
                })
                .unwrap_or(msg.header.table as u32);
            if table == p.tproxy_table || table == p.tun_table {
                to_del.push(msg);
            }
        }
        for msg in to_del {
            if let Err(e) = handle.rule().del(msg).execute().await {
                warn!(err = %e, "ip-auto-route: rule del");
            }
        }
    }

    for v6 in [false, true] {
        if v6 && !p.ipv6 {
            continue;
        }
        for table in [p.tproxy_table, p.tun_table] {
            flush_table_routes(handle, table, v6).await;
        }
    }
}

async fn flush_table_routes(handle: &rtnetlink::Handle, table: u32, v6: bool) {
    use netlink_packet_route::route::RouteAttribute;
    let mut routes = if v6 {
        handle.route().get(rtnetlink::IpVersion::V6).execute()
    } else {
        handle.route().get(rtnetlink::IpVersion::V4).execute()
    };
    let mut to_del = Vec::new();
    while let Ok(Some(msg)) = routes.try_next().await {
        let t = msg
            .attributes
            .iter()
            .find_map(|a| match a {
                // iter() yields &RouteAttribute → field binds as &u32
                RouteAttribute::Table(t) => Some(*t),
                _ => None,
            })
            .unwrap_or(msg.header.table as u32);
        if t == table {
            to_del.push(msg);
        }
    }
    for msg in to_del {
        if let Err(e) = handle.route().del(msg).execute().await {
            warn!(err = %e, table, "ip-auto-route: route del");
        }
    }
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
            p.mark,
            p.mark_mask,
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
        add_fwmark_rule(handle, p.tun_pref, p.mark, p.mark_mask, p.tun_table, v6)
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
