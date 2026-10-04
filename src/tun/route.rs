//! auto-route / strict-route — **faithful port of sing-tun NativeTun.rules()**.
//!
//! Classic topology (used both for plain auto-route and auto-redirect, matching
//! mihomo without route-address-set):
//!
//! 1. non-DNS → lookup main with suppress_prefixlength 0 (skip default routes)
//! 2. iif TUN → nop
//! 3. **not iif lo** → TUN table   (forwarded only; local SSH replies stay local)
//! 4. iif lo from 0.0.0.0/32 → TUN (unbound local clients)
//! 5. iif lo from <tun-addrs> → TUN
//! 6. fall through → main (bound local replies e.g. SSH)

use crate::config::TunConfig;
use anyhow::{Context, Result};
use std::net::IpAddr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::info;
#[cfg(target_os = "windows")]
use tracing::warn;

pub struct RouteGuard {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    linux: Option<LinuxInstalled>,
    #[cfg(target_os = "windows")]
    win: Option<WindowsGuard>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct LinuxInstalled {
    #[allow(dead_code)]
    if_index: u32,
    table: u32,
    /// Base priority used for this install (for full window cleanup on Drop).
    rule_start: u32,
    routes: Vec<(bool, String)>,
    rules: Vec<(u32, bool)>,
}

#[cfg(target_os = "windows")]
struct WindowsGuard {
    if_name: String,
    routes: Vec<(bool, String)>,
    /// strict-route WFP filters; dropped (session closed) before routes.
    wfp: Option<super::wfp::WfpGuard>,
}impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(ref inst) = self.linux {
                // 1) Routes we installed in the TUN table
                for (v6, dest) in &inst.routes {
                    let fam = if *v6 { "-6" } else { "-4" };
                    let _ = Command::new("ip")
                        .args([fam, "route", "del", dest, "table", &inst.table.to_string()])
                        .output();
                }
                // 2) sing-tun unsetRules: delete *entire* priority window, not only
                //    rules we tracked (avoids leftovers after EEXIST / partial install).
                let start = inst.rule_start;
                cleanup_rule_window(start);
                // Also delete any remaining tracked priorities (idempotent)
                for (prio, v6) in &inst.rules {
                    let mut cmd = Command::new("ip");
                    if *v6 {
                        cmd.arg("-6");
                    } else {
                        cmd.arg("-4");
                    }
                    let _ = cmd
                        .args(["rule", "del", "priority", &prio.to_string()])
                        .output();
                }
                let _ = Command::new("ip")
                    .args(["route", "flush", "table", &inst.table.to_string()])
                    .output();
                info!(
                    table = inst.table,
                    rule_start = start,
                    "tun: auto-route fully cleaned (routes + rule priority window)"
                );
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(g) = self.win.take() {
                // 1) WFP first: filters reference the interface, close the
                //    dynamic session so every filter disappears (sing-tun
                //    FwpmEngineClose0).
                drop(g.wfp);
                // 2) Routes we installed (store=active, so a reboot clears
                //    leftovers too — sing-tun instead removes the adapter).
                for (v6, dest) in &g.routes {
                    let family = if *v6 { "ipv6" } else { "ipv4" };
                    let _ = Command::new("netsh")
                        .args([
                            "interface",
                            family,
                            "delete",
                            "route",
                            dest,
                            &format!("interface={}", g.if_name),
                        ])
                        .output();
                }
                // 3) sing-tun Close(): FlushResolverCache when AutoRoute.
                flush_dns_cache();
                info!(
                    interface = %g.if_name,
                    routes = g.routes.len(),
                    "tun: auto-route cleaned up (routes + WFP)"
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn flush_dns_cache() {
    match Command::new("ipconfig").arg("/flushdns").output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "ipconfig /flushdns failed"
        ),
        Err(e) => warn!(err = %e, "failed to run ipconfig /flushdns"),
    }
}

fn prefixes(cfg: &TunConfig) -> Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    if cfg.route_address.is_empty() {
        for (s, v6) in [
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false),
            ("::/1", true),
            ("8000::/1", true),
        ] {
            if !cfg.route_exclude_address.iter().any(|e| e == s) {
                out.push((s.into(), v6));
            }
        }
    } else {
        for s in &cfg.route_address {
            if cfg.route_exclude_address.iter().any(|e| e == s) {
                continue;
            }
            let (ip, pl) = s
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("route-address CIDR required: {s}"))?;
            let _: IpAddr = ip.parse().context("route-address")?;
            let pl: u8 = pl.parse().context("prefix")?;
            let v6 = s.contains(':');
            if pl > if v6 { 128 } else { 32 } {
                anyhow::bail!("bad prefix {pl}");
            }
            out.push((s.clone(), v6));
        }
    }
    Ok(out)
}

/// Parse TUN interface address CIDRs from config for lo-src rules.
#[cfg(any(target_os = "linux", target_os = "android"))]
type AddrPrefix4 = Vec<(Ipv4Addr, u8)>;
#[cfg(any(target_os = "linux", target_os = "android"))]
type AddrPrefix6 = Vec<(Ipv6Addr, u8)>;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn tun_address_prefixes(cfg: &TunConfig) -> (AddrPrefix4, AddrPrefix6) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for s in &cfg.address {
        let Some((ip_s, pl_s)) = s.split_once('/') else {
            continue;
        };
        let Ok(pl) = pl_s.parse::<u8>() else {
            continue;
        };
        if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
            // Masked network like sing-tun address.Masked()
            let mask = if pl == 0 { 0u32 } else { !0u32 << (32 - pl) };
            let net = Ipv4Addr::from(u32::from(ip) & mask);
            v4.push((net, pl));
            v4.push((ip, 32)); // also host address
        } else if let Ok(ip) = ip_s.parse::<Ipv6Addr>() {
            v6.push((ip, pl.min(128)));
        }
    }
    (v4, v6)
}

#[allow(clippy::needless_return)]
pub async fn install_routes(
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))] dns_hijack: bool,
) -> Result<RouteGuard> {
    let pfx = prefixes(cfg)?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let linux = install_linux(if_name, cfg, has_v4, has_v6, &pfx).await?;
        return Ok(RouteGuard { linux: Some(linux) });
    }

    #[cfg(target_os = "windows")]
    {
        let win = install_windows(if_name, cfg, has_v4, has_v6, dns_hijack, &pfx)?;
        return Ok(RouteGuard { win: Some(win) });
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
    {
        let _ = (if_name, cfg, has_v4, has_v6, pfx);
        Ok(RouteGuard {})
    }
}

/// Remove all ip rules in our priority window (sing-tun unsetRules).
/// Called only from RouteGuard::Drop on stop — not on startup.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cleanup_rule_window(rule_start: u32) {
    use crate::tun::marks::DEFAULT_FALLBACK_RULE_PRIORITY;
    use std::process::Stdio;
    let lo = rule_start.saturating_sub(20);
    let hi = rule_start + 30;
    // Quiet: "RTNETLINK answers: No such file or directory" is normal when empty.
    let del = |fam: &str, prio: u32| -> bool {
        Command::new("ip")
            .args([fam, "rule", "del", "priority", &prio.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    for prio in lo..=hi {
        for _ in 0..8 {
            let r4 = del("-4", prio);
            let r6 = del("-6", prio);
            if !r4 && !r6 {
                break;
            }
        }
    }
    let fb = DEFAULT_FALLBACK_RULE_PRIORITY as u32;
    for _ in 0..4 {
        let r4 = del("-4", fb);
        let r6 = del("-6", fb);
        if !r4 && !r6 {
            break;
        }
    }
    info!(
        from = lo,
        to = hi,
        "tun: cleaned ip rules in priority window"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn install_linux(
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    pfx: &[(String, bool)],
) -> Result<LinuxInstalled> {
    use crate::tun::marks::{DEFAULT_RULE_PRIORITY, DEFAULT_TABLE};
    use futures::stream::TryStreamExt;
    use rtnetlink::new_connection;
    use tracing::warn;

    let (conn, handle, _) = new_connection().context("rtnetlink connect")?;
    tokio::spawn(conn);

    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();
    let link = links
        .try_next()
        .await
        .context("link get")?
        .ok_or_else(|| anyhow::anyhow!("interface {if_name} not found"))?;
    let if_index = link.header.index;

    let table = if cfg.iproute2_table_index != 0 {
        cfg.iproute2_table_index as u32
    } else {
        DEFAULT_TABLE as u32
    };
    let rule_start = if cfg.iproute2_rule_index != 0 {
        cfg.iproute2_rule_index as u32
    } else {
        DEFAULT_RULE_PRIORITY as u32
    };

    let mut installed = LinuxInstalled {
        if_index,
        table,
        rule_start,
        routes: Vec::new(),
        rules: Vec::new(),
    };

    for (dest, v6) in pfx {
        if (*v6 && !has_v6) || (!*v6 && !has_v4) {
            continue;
        }
        match add_route(&handle, if_index, table, dest, *v6).await {
            Ok(()) => installed.routes.push((*v6, dest.clone())),
            Err(e) => warn!(dest = %dest, err = %e, "route add failed"),
        }
    }

    add_rules_classic_mihomo(
        &handle,
        if_name,
        cfg,
        has_v4,
        has_v6,
        table,
        rule_start,
        &mut installed,
    )
    .await;

    info!(
        interface = %if_name,
        if_index,
        table,
        routes = installed.routes.len(),
        rules = installed.rules.len(),
        "tun: auto-route installed (sing-tun / mihomo classic topology)"
    );
    Ok(installed)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn add_route(
    handle: &rtnetlink::Handle,
    if_index: u32,
    table: u32,
    dest: &str,
    v6: bool,
) -> Result<()> {
    let (ip_s, pl_s) = dest
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("bad CIDR {dest}"))?;
    let pl: u8 = pl_s.parse()?;
    if v6 {
        let ip: Ipv6Addr = ip_s.parse()?;
        handle
            .route()
            .add()
            .v6()
            .destination_prefix(ip, pl)
            .output_interface(if_index)
            .table_id(table)
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let ip: Ipv4Addr = ip_s.parse()?;
        handle
            .route()
            .add()
            .v4()
            .destination_prefix(ip, pl)
            .output_interface(if_index)
            .table_id(table)
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

/// Classic auto-route — full sing-tun / mihomo topology (non-Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::too_many_arguments)]
async fn add_rules_classic_mihomo(
    handle: &rtnetlink::Handle,
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    table: u32,
    rule_start: u32,
    inst: &mut LinuxInstalled,
) {
    use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleFlag, RulePortRange};
    use tracing::warn;

    let nop = rule_start + 10;
    let mut prio4 = rule_start;
    let mut prio6 = rule_start;
    let (tun_v4, tun_v6) = tun_address_prefixes(cfg);

    // --- strict-route: unreachable for missing family ---
    if cfg.strict_route {
        if !has_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio4)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio4, false)),
                Err(e) => warn!(err = %e, "strict v4"),
            }
            prio4 += 1;
        }
        if !has_v6 {
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio6)
                .action(RuleAction::Unreachable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio6, true)),
                Err(e) => warn!(err = %e, "strict v6"),
            }
            prio6 += 1;
        }
    }

    // --- dst = tun addresses → TUN table ---
    if has_v4 {
        for (ip, pl) in &tun_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio4)
                .destination_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio4, false)),
                Err(e) => warn!(err = %e, "dst tun v4"),
            }
        }
        prio4 += 1;
    }

    // --- invert dport 53, table main, suppress_prefixlength 0 ---
    // Non-DNS: try main without default routes; DNS skips this rule.
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .table_id(254)
            .action(RuleAction::ToTable);
        {
            let msg = req.message_mut();
            msg.header.flags.push(RuleFlag::Invert);
            msg.attributes
                .push(RuleAttribute::DestinationPortRange(RulePortRange {
                    start: 53,
                    end: 53,
                }));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "suppress dns v4"),
        }
        prio4 += 1;
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .table_id(254)
            .action(RuleAction::ToTable);
        {
            let msg = req.message_mut();
            msg.header.flags.push(RuleFlag::Invert);
            msg.attributes
                .push(RuleAttribute::DestinationPortRange(RulePortRange {
                    start: 53,
                    end: 53,
                }));
            msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        }
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "suppress dns v6"),
        }
        prio6 += 1;
    }

    // --- iif TUN → goto nop ---
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface(if_name.to_string())
            .action(RuleAction::Goto);
        req.message_mut().attributes.push(RuleAttribute::Goto(nop));
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "iif tun v4"),
        }
        prio4 += 1;
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .input_interface(if_name.to_string())
            .action(RuleAction::Goto);
        req.message_mut().attributes.push(RuleAttribute::Goto(nop));
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "iif tun v6"),
        }
        prio6 += 1;
    }

    // --- not iif lo → TUN table  (FORWARDED only; local SSH replies are iif=lo) ---
    if has_v4 {
        let prio = prio4;
        let mut req = handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface("lo".into())
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut().header.flags.push(RuleFlag::Invert);
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "not iif lo v4"),
        }
        // same priority for lo-src rules below (sing-tun shares priority)
    }
    if has_v6 {
        let prio = prio6;
        let mut req = handle
            .rule()
            .add()
            .v6()
            .priority(prio)
            .input_interface("lo".into())
            .table_id(table)
            .action(RuleAction::ToTable);
        req.message_mut().header.flags.push(RuleFlag::Invert);
        match req.execute().await {
            Ok(()) => inst.rules.push((prio, true)),
            Err(e) => warn!(err = %e, "not iif lo v6"),
        }
    }

    // --- iif lo from 0.0.0.0/32 → TUN ---
    if has_v4 {
        let prio = prio4;
        match handle
            .rule()
            .add()
            .v4()
            .priority(prio)
            .input_interface("lo".into())
            .source_prefix(Ipv4Addr::UNSPECIFIED, 32)
            .table_id(table)
            .action(RuleAction::ToTable)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((prio, false)),
            Err(e) => warn!(err = %e, "lo from 0.0.0.0/32"),
        }
        // --- iif lo from tun addresses → TUN ---
        for (ip, pl) in &tun_v4 {
            match handle
                .rule()
                .add()
                .v4()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, false)),
                Err(e) => warn!(err = %e, "lo from tun v4"),
            }
        }
        prio4 += 1;
    }

    if has_v6 {
        // iif lo from ::/1 and 8000::/1 → goto nop (sing-tun)
        for (ip, pl) in [
            (Ipv6Addr::UNSPECIFIED, 1u8),
            (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1u8),
        ] {
            let prio = prio6;
            let mut req = handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(ip, pl)
                .action(RuleAction::Goto);
            req.message_mut().attributes.push(RuleAttribute::Goto(nop));
            match req.execute().await {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "lo from v6 half"),
            }
        }
        prio6 += 1;
        for (ip, pl) in &tun_v6 {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .input_interface("lo".into())
                .source_prefix(*ip, *pl)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "lo from tun v6"),
            }
        }
        prio6 += 1;
        // v6 catch-all → TUN (sing-tun has this for v6 only)
        {
            let prio = prio6;
            match handle
                .rule()
                .add()
                .v6()
                .priority(prio)
                .table_id(table)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((prio, true)),
                Err(e) => warn!(err = %e, "v6 catch-all"),
            }
        }
    }

    // --- user route-exclude → main (higher priority than rule_start) ---
    let ex_prio = rule_start.saturating_sub(5);
    for s in &cfg.route_exclude_address {
        if let Ok((ip, pl)) = parse_v4_cidr(s) {
            match handle
                .rule()
                .add()
                .v4()
                .priority(ex_prio)
                .destination_prefix(ip, pl)
                .table_id(254)
                .action(RuleAction::ToTable)
                .execute()
                .await
            {
                Ok(()) => inst.rules.push((ex_prio, false)),
                Err(e) => warn!(err = %e, "exclude"),
            }
        }
    }

    // --- nop anchors ---
    if has_v4 {
        match handle
            .rule()
            .add()
            .v4()
            .priority(nop)
            .action(RuleAction::Nop)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, false)),
            Err(e) => warn!(err = %e, "nop4"),
        }
    }
    if has_v6 {
        match handle
            .rule()
            .add()
            .v6()
            .priority(nop)
            .action(RuleAction::Nop)
            .execute()
            .await
        {
            Ok(()) => inst.rules.push((nop, true)),
            Err(e) => warn!(err = %e, "nop6"),
        }
    }

    let _ = prio4;
    let _ = prio6;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, pl) = s.split_once('/').ok_or_else(|| anyhow::anyhow!("cidr"))?;
    Ok((ip.parse()?, pl.parse()?))
}

#[cfg(target_os = "windows")]
fn install_windows(
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    dns_hijack: bool,
    pfx: &[(String, bool)],
) -> Result<WindowsGuard> {
    use std::net::IpAddr;

    // sing-tun Windows gateway: Inet4/6GatewayAddr → next address of the first
    // TUN address. mod.rs already validated that addr+1 fits the prefix
    // (rejects /32), so next is always valid here.
    fn gateway(cfg: &TunConfig, v6: bool) -> Option<IpAddr> {
        for s in &cfg.address {
            let Some((ip_s, _pl)) = s.split_once('/') else { continue };
            if s.contains(':') != v6 {
                continue;
            }
            if let Ok(ip) = ip_s.parse::<IpAddr>() {
                return Some(match ip {
                    IpAddr::V4(a) => IpAddr::V4(next_v4(a)),
                    IpAddr::V6(a) => IpAddr::V6(next_v6(a)),
                });
            }
        }
        None
    }
    fn next_v4(ip: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from(ip).wrapping_add(1))
    }
    fn next_v6(ip: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from(ip).wrapping_add(1))
    }

    let gw4 = gateway(cfg, false);
    let gw6 = gateway(cfg, true);

    let mut routes = Vec::new();
    for (dest, v6) in pfx {
        if (*v6 && !has_v6) || (!*v6 && !has_v4) {
            continue;
        }
        let family = if *v6 { "ipv6" } else { "ipv4" };
        let mut args: Vec<String> = vec![
            "interface".into(),
            family.into(),
            "add".into(),
            "route".into(),
            dest.clone(),
            format!("interface={if_name}"),
        ];
        // nexthop = TUN gateway (addr+1) — avoids on-link neighbour resolution,
        // which WinTun does not answer (sing-tun AddRoute(prefix, gateway, 0)).
        if let Some(gw) = if *v6 { gw6 } else { gw4 } {
            args.push(format!("nexthop={gw}"));
        }
        // metric 0 so the TUN split routes always beat the physical default
        // (sing-tun sets interface Metric=0 + route metric 0).
        args.push("metric=0".into());
        args.push("store=active".into());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = Command::new("netsh").args(&arg_refs).output();
        match out {
            Ok(out) if out.status.success() => routes.push((*v6, dest.clone())),
            Ok(out) => warn!(
                dest = %dest,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                stdout = %String::from_utf8_lossy(&out.stdout).trim(),
                "tun: netsh route add failed"
            ),
            Err(e) => warn!(dest = %dest, err = %e, "failed to run netsh"),
        }
    }

    // Interface parameters: metric 0 + forwarding (sing-tun inetIf.Set()).
    // store=active so nothing survives a reboot if the process is killed.
    // Interface metric 0 (sing-tun: UseAutomaticMetric=false, Metric=0 when
    // AutoRoute). dadtransmits/forwarding/routerdiscovery live in
    // device.rs — they must be set BEFORE the address exists (IPv4 DAD).
    if has_v4 {
        run_quiet(&[
            "interface", "ipv4", "set", "subinterface", &format!("interface={if_name}"),
            "metric=0", "store=active",
        ]);
    }
    if has_v6 {
        run_quiet(&[
            "interface", "ipv6", "set", "subinterface", &format!("interface={if_name}"),
            "metric=0", "store=active",
        ]);
    }

    // strict-route: sing-tun installs WFP filters; failure is fatal there and
    // stays fatal here (fail-fast, no silent downgrade).
    let wfp = if cfg.strict_route {
        let idx = windows_if_index(if_name)
            .ok_or_else(|| anyhow::anyhow!("strict-route: cannot resolve TUN interface index"))?;
        Some(
            super::wfp::install(idx, has_v4, has_v6, dns_hijack)
                .context("strict-route (WFP)")?,
        )
    } else {
        None
    };

    info!(interface = %if_name, routes = routes.len(), "tun: auto-route (netsh, nexthop+metric=0)");
    Ok(WindowsGuard { if_name: if_name.to_string(), routes, wfp })
}

#[cfg(target_os = "windows")]
fn run_quiet(args: &[&str]) {
    match Command::new("netsh").args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            cmd = ?args,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "netsh failed"
        ),
        Err(e) => warn!(cmd = ?args, err = %e, "failed to run netsh"),
    }
}

/// Resolve the TUN interface index by alias. Windows `if_nametoindex` does
/// NOT accept the friendly alias (returns 0 / "no such device"), so enumerate
/// the interface table via `GetIfTable2` and match `Alias`.
#[cfg(target_os = "windows")]
fn windows_if_index(if_name: &str) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    unsafe {
        if GetIfTable2(&mut table) != 0 || table.is_null() {
            return None;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let mut found = None;
        for row in rows {
            let len = row.Alias.iter().position(|&c| c == 0).unwrap_or(257);
            let alias = String::from_utf16_lossy(&row.Alias[..len]);
            if alias == if_name {
                found = Some(row.InterfaceIndex);
                break;
            }
        }
        FreeMibTable(table as *const _);
        found
    }
}
