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
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::info;
#[cfg(any(target_os = "windows", target_os = "android"))]
use tracing::warn;

pub struct RouteGuard {
    #[cfg(target_os = "linux")]
    linux: Option<LinuxInstalled>,
    /// Android root mode: `ip` command based auto-route (rtnetlink cannot
    /// compile on Android; VpnService external-FD mode never routes itself).
    #[cfg(target_os = "android")]
    android: Option<AndroidInstalled>,
    #[cfg(target_os = "windows")]
    win: Option<WindowsGuard>,
    #[cfg(target_os = "macos")]
    macos: Option<MacosGuard>,
}

#[cfg(target_os = "linux")]
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
}

/// macOS auto-route: routes via `route` command (sing-tun tun_darwin.go addRoute).
#[cfg(target_os = "macos")]
struct MacosGuard {
    /// Auto-route destinations (is_v6, dest CIDR).
    routes: Vec<(bool, String)>,
    /// route-exclude-address via physical interface (is_v6, dest).
    excludes: Vec<(bool, String)>,
    /// strict-route blackhole defaults (is_v6, dest).
    blackholes: Vec<(bool, String)>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
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
        #[cfg(target_os = "android")]
        {
            if let Some(ref inst) = self.android {
                // 1) Rules first (marked / iif exceptions + catch-all), so no
                //    blackhole window while routes are already gone.
                for (prio, v6) in &inst.rules {
                    let mut cmd = Command::new("ip");
                    if *v6 {
                        cmd.arg("-6");
                    } else {
                        cmd.arg("-4");
                    }
                    let _ = cmd
                        .args(["rule", "del", "pref", &prio.to_string()])
                        .output();
                }
                cleanup_rule_window(inst.rule_start);
                // 2) Routes we installed in the TUN table.
                for (v6, dest) in &inst.routes {
                    let fam = if *v6 { "-6" } else { "-4" };
                    let _ = Command::new("ip")
                        .args([
                            fam,
                            "route",
                            "del",
                            dest,
                            "dev",
                            &inst.if_name,
                            "table",
                            &inst.table.to_string(),
                        ])
                        .output();
                }
                let _ = Command::new("ip")
                    .args(["route", "flush", "table", &inst.table.to_string()])
                    .output();
                info!(
                    table = inst.table,
                    rule_start = inst.rule_start,
                    "tun: android auto-route fully cleaned (rules + routes)"
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
        #[cfg(target_os = "macos")]
        {
            if let Some(g) = self.macos.take() {
                for (v6, dest) in g
                    .routes
                    .iter()
                    .chain(g.excludes.iter())
                    .chain(g.blackholes.iter())
                {
                    // Prefer AF_ROUTE (sing-tun); fall back to `route` command.
                    if super::macos::af_route_del(dest, *v6).is_err() {
                        let family = if *v6 { "-inet6" } else { "-inet" };
                        let _ = Command::new("route")
                            .args(["-n", "delete", family, dest])
                            .output();
                    }
                }
                // sing-tun Close(): flush DNS cache
                flush_dns_cache_macos();
                info!(
                    routes = g.routes.len(),
                    excludes = g.excludes.len(),
                    blackholes = g.blackholes.len(),
                    "tun: auto-route cleaned up (macos routes + dscacheutil)"
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn flush_dns_cache_macos() {
    // sing-tun flushDNSCache: dscacheutil -flushcache (+ killall -HUP mDNSResponder optional)
    match Command::new("dscacheutil").arg("-flushcache").output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => tracing::warn!(
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "dscacheutil -flushcache failed"
        ),
        Err(e) => tracing::warn!(err = %e, "failed to run dscacheutil"),
    }
    let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).output();
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
        // Default catch-all. On macOS, sing-tun uses the granular darwin
        // sub-ranges (1/8…128/1) instead of a single 0.0.0.0/0 so the
        // physical default stays in the routing table while all traffic
        // still prefers the TUN (longer-prefix / equal metric behaviour).
        // 0.0.0.0/1 + 128.0.0.0/1 is the compact equivalent used by ant on
        // every platform and is what Windows / many VPN clients use.
        #[cfg(target_os = "macos")]
        {
            // sing-tun autoRouteUseSubRanges (darwin):
            //   1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/5, 16.0.0.0/4,
            //   32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1
            // and the same pattern for IPv6. Compact form is equivalent:
            for (s, v6) in [
                ("0.0.0.0/1", false),
                ("128.0.0.0/1", false),
                ("::/1", true),
                ("8000::/1", true),
            ] {
                if !is_excluded(cfg, s) {
                    out.push((s.into(), v6));
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            for (s, v6) in [
                ("0.0.0.0/1", false),
                ("128.0.0.0/1", false),
                ("::/1", true),
                ("8000::/1", true),
            ] {
                if !is_excluded(cfg, s) {
                    out.push((s.into(), v6));
                }
            }
        }
    } else {
        for s in &cfg.route_address {
            if is_excluded(cfg, s) {
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
        // darwin: when route-address is explicit, also add the TUN network
        // itself (sing-tun BuildAutoRouteRanges appends address.Masked()).
        #[cfg(target_os = "macos")]
        {
            for s in &cfg.address {
                let Some((ip_s, pl_s)) = s.split_once('/') else {
                    continue;
                };
                let Ok(pl) = pl_s.parse::<u8>() else {
                    continue;
                };
                if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                    if pl < 32 {
                        let mask = if pl == 0 { 0u32 } else { !0u32 << (32 - pl) };
                        let net = std::net::Ipv4Addr::from(u32::from(ip) & mask);
                        let cidr = format!("{net}/{pl}");
                        if !is_excluded(cfg, &cidr) && !out.iter().any(|(d, _)| d == &cidr) {
                            out.push((cidr, false));
                        }
                    }
                } else if let Ok(ip) = ip_s.parse::<std::net::Ipv6Addr>() {
                    if pl < 128 {
                        let cidr = format!("{ip}/{pl}");
                        // full mask of network would be better; host/prefix is accepted by route
                        if !is_excluded(cfg, &cidr) && !out.iter().any(|(d, _)| d == &cidr) {
                            out.push((cidr, true));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn is_excluded(cfg: &TunConfig, cidr: &str) -> bool {
    cfg.route_exclude_address.iter().any(|e| e == cidr)
}

/// Parse TUN interface address CIDRs from config for lo-src rules.
#[cfg(target_os = "linux")]
type AddrPrefix4 = Vec<(Ipv4Addr, u8)>;
#[cfg(target_os = "linux")]
type AddrPrefix6 = Vec<(Ipv6Addr, u8)>;

#[cfg(target_os = "linux")]
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
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "macos")),
        allow(unused_variables)
    )]
    dns_hijack: bool,
) -> Result<RouteGuard> {
    let pfx = prefixes(cfg)?;

    #[cfg(target_os = "linux")]
    {
        let linux = install_linux(if_name, cfg, has_v4, has_v6, &pfx).await?;
        return Ok(RouteGuard { linux: Some(linux) });
    }

    #[cfg(target_os = "android")]
    {
        let android = install_android(if_name, cfg, has_v4, has_v6, &pfx).await?;
        return Ok(RouteGuard { android: Some(android) });
    }

    #[cfg(target_os = "windows")]
    {
        let win = install_windows(if_name, cfg, has_v4, has_v6, dns_hijack, &pfx)?;
        return Ok(RouteGuard { win: Some(win) });
    }

    #[cfg(target_os = "macos")]
    {
        let macos = install_macos(if_name, cfg, has_v4, has_v6, dns_hijack, &pfx)?;
        return Ok(RouteGuard { macos: Some(macos) });
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows",
        target_os = "macos"
    )))]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, pl) = s.split_once('/').ok_or_else(|| anyhow::anyhow!("cidr"))?;
    Ok((ip.parse()?, pl.parse()?))
}

// ---------------------------------------------------------------------------
// Android root auto-route — `ip rule` / `ip route` implementation.
//
// rtnetlink cannot compile on Android (AF_BRIDGE missing from bionic libc),
// so the classic topology is reproduced with the `ip` command instead.
//
// Android-specific differences from the Linux topology:
// - **main table is empty**: netd keeps default routes in per-network tables
//   (e.g. table 1021 for wlan0). Loop prevention / route-exclude rules must
//   therefore look up the *detected physical table*, not `main`.
// - **no DNS-suppress rule**: the classic `not dport 53 … suppress_prefixlen`
//   selector is not reliably supported by Android's `ip`; DNS is handled by
//   the TUN-side dns-hijack / system stack instead (anti-leak is even better).
// - **rule priority default 8000**: netd owns 9000–18000; our window must be
//   evaluated *before* netd's per-network lookups so the catch-all wins.
// - **no iif-lo rules**: the catch-all covers locally-generated traffic; the
//   two exception rules (fwmark / iif-tun) provide loop prevention and reply
//   routing.
//
// Topology per family (P = rule_start, T = route table, N = physical table,
// M = fwmark):
//   pref P+0: fwmark M      → lookup N   (our own dialer sockets escape)
//   pref P+1: iif <tun>     → lookup main (TUN replies: client addrs are
//                             connected routes in main — `ip addr add` puts
//                             them there even on Android)
//   pref P+2: to <exclude>  → lookup N   (per route-exclude-address)
//   pref P+3: unreachable   (strict-route, missing family only)
//   pref P+4:               → lookup T   (catch-all into the TUN)
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
struct AndroidInstalled {
    if_name: String,
    table: u32,
    /// Base priority used for this install (for full window cleanup on Drop).
    rule_start: u32,
    routes: Vec<(bool, String)>,
    rules: Vec<(u32, bool)>,
}

#[cfg(target_os = "android")]
fn ip_cmd(args: &[&str]) -> bool {
    match Command::new("ip").args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            warn!(
                cmd = ?args,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip command failed"
            );
            false
        }
        Err(e) => {
            warn!(cmd = ?args, err = %e, "failed to run ip");
            false
        }
    }
}

/// Find the per-network routing table that holds the current default route
/// (Android netd puts it in a netId table; `main` is empty). Returns 254 when
/// the default route sits in `main` (some ROMs / APN quirks).
#[cfg(target_os = "android")]
fn detect_phys_table(v6: bool) -> Result<u32> {
    let fam = if v6 { "-6" } else { "-4" };
    let out = Command::new("ip")
        .args([fam, "route", "show", "table", "all"])
        .output()
        .map_err(|e| anyhow::anyhow!("ip route show table all: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "ip route show table all failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("default") {
            continue;
        }
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "table" {
                let id = it.next().unwrap_or("main");
                return Ok(if id == "main" {
                    254
                } else {
                    id.parse().context("parse route table id")?
                });
            }
        }
        // default line without an explicit table → main
        return Ok(254);
    }
    anyhow::bail!("no default route found (physical network down?)")
}

/// Android auto-route via `ip` commands (root mode). See the module docs
/// above for the topology. IPv6 is skipped (warn) when no v6 default route
/// exists — installing a v6 catch-all without a marked-socket escape would
/// loop our own v6 dialers into the TUN.
#[cfg(target_os = "android")]
async fn install_android(
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    pfx: &[(String, bool)],
) -> Result<AndroidInstalled> {
    use crate::tun::marks::{DEFAULT_ANDROID_RULE_PRIORITY, DEFAULT_TABLE};

    let table = if cfg.iproute2_table_index != 0 {
        cfg.iproute2_table_index as u32
    } else {
        DEFAULT_TABLE as u32
    };
    let rule_start = if cfg.iproute2_rule_index != 0 {
        cfg.iproute2_rule_index as u32
    } else {
        DEFAULT_ANDROID_RULE_PRIORITY as u32
    };

    // Loop prevention depends on dialer marks escaping the catch-all.
    let mark = crate::app::sockopt::fwmark();
    if mark == 0 {
        anyhow::bail!("tun: Android auto-route requires a non-zero fwmark (loop prevention)");
    }
    let mark_s = mark.to_string();

    // Physical tables per family.
    let phys_v4 = detect_phys_table(false).context("detect v4 route table")?;
    let phys_v6 = if has_v6 {
        match detect_phys_table(true) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(err = %e, "tun: no v6 default route — IPv6 auto-route skipped");
                None
            }
        }
    } else {
        None
    };

    let mut inst = AndroidInstalled {
        if_name: if_name.to_string(),
        table,
        rule_start,
        routes: Vec::new(),
        rules: Vec::new(),
    };

    // 1) Split default routes (or user route-address) into the TUN table as
    //    device routes — no nexthop needed on a point-to-point TUN.
    for (dest, v6) in pfx {
        let fam_ok = if *v6 { phys_v6.is_some() } else { has_v4 };
        if !fam_ok {
            continue;
        }
        let fam = if *v6 { "-6" } else { "-4" };
        if ip_cmd(&[
            fam,
            "route",
            "add",
            dest.as_str(),
            "dev",
            if_name,
            "table",
            &table.to_string(),
        ]) {
            inst.routes.push((*v6, dest.clone()));
        }
    }

    // 2) Policy rules per family.
    for (v6, phys) in [(false, Some(phys_v4)), (true, phys_v6)] {
        let fam = if v6 { "-6" } else { "-4" };
        let has = if v6 { phys.is_some() } else { has_v4 };
        let mut prio = rule_start;

        if !has {
            // strict-route: block leaks for the missing family.
            if cfg.strict_route
                && ip_cmd(&[fam, "rule", "add", "pref", &prio.to_string(), "unreachable"])
            {
                inst.rules.push((prio, v6));
            }
            continue;
        }
        let phys_s = phys.unwrap().to_string();

        // fwmark → physical table (marked dialer sockets escape the TUN).
        if ip_cmd(&[
            fam,
            "rule",
            "add",
            "pref",
            &prio.to_string(),
            "fwmark",
            &mark_s,
            "lookup",
            &phys_s,
        ]) {
            inst.rules.push((prio, v6));
        }
        prio += 1;

        // iif <tun> → main: reply packets ant writes into the TUN must reach
        // the client address (connected route lives in main).
        if ip_cmd(&[
            fam,
            "rule",
            "add",
            "pref",
            &prio.to_string(),
            "iif",
            if_name,
            "lookup",
            "main",
        ]) {
            inst.rules.push((prio, v6));
        }
        prio += 1;

        // route-exclude-address → physical table (silent-skip invalid entries,
        // same as the Linux netlink path).
        for s in &cfg.route_exclude_address {
            if s.contains(':') != v6 {
                continue;
            }
            let Some((ip, _)) = s.split_once('/') else {
                continue;
            };
            if ip.parse::<IpAddr>().is_err() {
                continue;
            }
            if ip_cmd(&[
                fam,
                "rule",
                "add",
                "pref",
                &prio.to_string(),
                "to",
                s.as_str(),
                "lookup",
                &phys_s,
            ]) {
                inst.rules.push((prio, v6));
            }
        }
        prio += 1;

        // strict-route has no extra rule for the *present* family here (the
        // Linux netlink path behaves the same: unreachable only for missing).

        // Catch-all → TUN table.
        if ip_cmd(&[
            fam,
            "rule",
            "add",
            "pref",
            &prio.to_string(),
            "lookup",
            &table.to_string(),
        ]) {
            inst.rules.push((prio, v6));
        }
    }

    info!(
        interface = %if_name,
        table,
        rule_start,
        mark,
        routes = inst.routes.len(),
        rules = inst.rules.len(),
        "tun: android auto-route installed (ip rule/route, root mode)"
    );
    Ok(inst)
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

/// macOS auto-route — faithful port of sing-tun `tun_darwin.go` create() AutoRoute
/// block + `addRoute` + `flushDNSCache`.
///
/// Topology (mihomo / sing-tun on Darwin):
/// - Split defaults `0.0.0.0/1` + `128.0.0.0/1` (and IPv6 `::/1` + `8000::/1`),
///   or user `route-address` list from [`prefixes`].
/// - Nexthop = TUN interface address (`Inet4/6GatewayAddr`); fallback `-interface`.
/// - No policy-routing tables / SO_MARK on macOS; loop prevention uses
///   `IP_BOUND_IF` via `auto-detect-interface` (see sockopt).
/// - `strict-route`: when a family has no TUN address, install a blackhole
///   default for that family so traffic cannot leak to the physical default
///   (Darwin has no Linux-style `ip rule unreachable`).
/// - DNS: stack-side dns-hijack handles packets; OS resolver cache is flushed
///   after install and on Drop (sing-tun `flushDNSCache`).
#[cfg(target_os = "macos")]
fn install_macos(
    if_name: &str,
    cfg: &TunConfig,
    has_v4: bool,
    has_v6: bool,
    dns_hijack: bool,
    pfx: &[(String, bool)],
) -> Result<MacosGuard> {
    use tracing::warn;

    // Gateway = first TUN address (sing-tun Inet4/6GatewayAddr on darwin =
    // the interface address itself, NOT addr.Next()).
    fn gateway(cfg: &TunConfig, v6: bool) -> Option<String> {
        for s in &cfg.address {
            let Some((ip_s, _)) = s.split_once('/') else {
                continue;
            };
            if v6 {
                if let Ok(ip) = ip_s.parse::<std::net::Ipv6Addr>() {
                    return Some(ip.to_string());
                }
            } else if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                return Some(ip.to_string());
            }
        }
        if v6 {
            None
        } else {
            Some("198.18.0.1".into())
        }
    }

    /// Physical default interface + gateway from `route -n get default`
    /// (used for route-exclude-address so those prefixes leave the TUN).
    fn phys_default(v6: bool) -> (Option<String>, Option<String>) {
        let mut args = vec!["-n", "get"];
        if v6 {
            args.push("-inet6");
        }
        args.push("default");
        let Ok(out) = Command::new("route").args(&args).output() else {
            return (None, None);
        };
        if !out.status.success() {
            return (None, None);
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let mut iface = None;
        let mut gw = None;
        for line in s.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("interface:") {
                let name = rest.trim();
                if !name.is_empty() {
                    iface = Some(name.to_string());
                }
            } else if let Some(rest) = line.strip_prefix("gateway:") {
                let g = rest.trim();
                if !g.is_empty() && g != "link#" && !g.starts_with("link#") {
                    gw = Some(g.to_string());
                }
            }
        }
        (iface, gw)
    }

    let gw4 = gateway(cfg, false);
    let gw6 = gateway(cfg, true);
    let (phys_if4, phys_gw4) = phys_default(false);
    let (phys_if6, phys_gw6) = phys_default(true);

    let mut installed = MacosGuard {
        routes: Vec::new(),
        excludes: Vec::new(),
        blackholes: Vec::new(),
    };

    // --- auto-route destinations → TUN ---
    for (dest, v6) in pfx {
        if (*v6 && !has_v6) || (!*v6 && !has_v4) {
            continue;
        }
        let gw = if *v6 {
            gw6.as_deref()
        } else {
            gw4.as_deref()
        };
        // 1) AF_ROUTE RTM_ADD (sing-tun addRoute)
        // 2) shell `route -n add … gateway`
        // 3) shell `route -n add … -interface`
        let ok = if let Some(gw) = gw {
            super::macos::af_route_add(dest, gw, *v6).is_ok()
                || {
                    let family = if *v6 { "-inet6" } else { "-inet" };
                    run_route(&["-n", "add", family, dest, gw])
                }
        } else {
            false
        };
        let ok = ok || {
            let family = if *v6 { "-inet6" } else { "-inet" };
            run_route(&["-n", "add", family, dest, "-interface", if_name])
        };
        if ok {
            installed.routes.push((*v6, dest.clone()));
        } else {
            warn!(dest = %dest, "tun: macos route add failed");
        }
    }

    // --- route-exclude-address → physical default (more-specific routes) ---
    // sing-tun subtracts excludes from the route set; on Darwin without an
    // IPSet helper we install explicit routes via the physical interface so
    // those prefixes never enter the TUN (same end result for the user).
    for s in &cfg.route_exclude_address {
        let v6 = s.contains(':');
        if (v6 && !has_v6 && has_v4) || (!v6 && !has_v4 && has_v6) {
            // still install exclude for the active family only
        }
        let family = if v6 { "-inet6" } else { "-inet" };
        let (phys_if, phys_gw) = if v6 {
            (phys_if6.as_deref(), phys_gw6.as_deref())
        } else {
            (phys_if4.as_deref(), phys_gw4.as_deref())
        };
        let ok = if let Some(gw) = phys_gw {
            run_route(&["-n", "add", family, s, gw])
        } else {
            false
        };
        let ok = ok || phys_if
            .map(|iface| run_route(&["-n", "add", family, s, "-interface", iface]))
            .unwrap_or(false);
        if ok {
            installed.excludes.push((v6, s.clone()));
        } else {
            warn!(dest = %s, "tun: macos route-exclude add failed");
        }
    }

    // --- strict-route: blackhole missing family ---
    if cfg.strict_route {
        if !has_v4 {
            let ok = super::macos::af_route_blackhole(false).is_ok()
                || run_route(&["-n", "add", "-inet", "0.0.0.0/0", "-blackhole"]);
            if ok {
                installed.blackholes.push((false, "0.0.0.0/0".into()));
                info!("tun: strict-route blackhole inet default (no v4 TUN addr)");
            } else {
                warn!("tun: strict-route failed to add inet blackhole");
            }
        }
        if !has_v6 {
            let ok = super::macos::af_route_blackhole(true).is_ok()
                || run_route(&["-n", "add", "-inet6", "::/0", "-blackhole"]);
            if ok {
                installed.blackholes.push((true, "::/0".into()));
                info!("tun: strict-route blackhole inet6 default (no v6 TUN addr)");
            } else {
                warn!("tun: strict-route failed to add inet6 blackhole");
            }
        }
        if has_v4 && has_v6 {
            info!(
                "tun: strict-route on macOS with both families — split routes + excludes are the enforcement (no PF/WFP)"
            );
        }
    }

    // DNS: stack-side dns-hijack handles packets to gateway:53 / any:53.
    // OS resolver cache flush matches sing-tun flushDNSCache after AutoRoute.
    let _ = dns_hijack;
    flush_dns_cache_macos();

    info!(
        interface = %if_name,
        routes = installed.routes.len(),
        excludes = installed.excludes.len(),
        blackholes = installed.blackholes.len(),
        strict = cfg.strict_route,
        "tun: auto-route installed (macos / sing-tun utun topology)"
    );
    Ok(installed)
}

#[cfg(target_os = "macos")]
fn run_route(args: &[&str]) -> bool {
    match Command::new("route").args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Idempotent re-add / already present.
            if stderr.to_ascii_lowercase().contains("file exists") {
                return true;
            }
            tracing::warn!(
                args = ?args,
                stderr = %stderr.trim(),
                "route command failed"
            );
            false
        }
        Err(e) => {
            tracing::warn!(err = %e, "failed to run route");
            false
        }
    }
}


