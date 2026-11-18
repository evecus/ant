//! eBPF transparent datapath (Linux/Android, feature `ebpf`).
//!
//! Bring-up order is significant: create netns/veth → load
//! & attach TC/sk_lookup → write static maps → publish transparent listeners
//! into the sockmap → spawn relay loops → `set_ready(true)` LAST so no packet
//! is judged PROXY while the sockmap is still empty. Teardown reverses it.

#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod bpf_raw;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod cgroup;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod datapath;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod dns;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod listener;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod maintenance;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod ns;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod relay;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
mod rules;

use anyhow::Result;
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
use anyhow::Context;

/// Entry point called from `main.rs` when `ebpf.enable` is set. On platforms
/// or builds without the feature this fails fast (config validation should
/// have rejected it already).
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
pub async fn run_ebpf(
    cfg: std::sync::Arc<crate::config::Config>,
    router: std::sync::Arc<crate::app::router::Router>,
    outbounds: std::sync::Arc<crate::outbound::OutboundManager>,
) -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::Mutex as AsyncMutex;

    let e = &cfg.ebpf;

    // 1. netns + veth + policy routing.
    ns::create_antns()?;
    datapath::setup_links()?;

    // 2. Resolve capture interfaces.
    let lan = datapath::resolve_interface(e.lan.as_deref().unwrap_or(""))?;
    let wan = datapath::resolve_interface(e.wan.as_deref().unwrap_or(""))?;
    // Android: route control-plane sockets (SO_MARK) via the WAN table so
    // dials don't fall into netd's unreachable rule (no-op on desktop Linux).
    datapath::setup_android_control_route(wan.as_ref().map(|(n, _)| n.as_str()));

    // 3. Ordered node list; index encodes the kernel verdict. Default is the
    //    final MATCH outbound of ant's route table.
    let nodes = outbounds.node_names();
    let default_verdict = {
        let final_ob = router.match_outbound(None, None);
        rules::Verdict::parse(&final_ob.label(), &nodes)?
    };

    // 4. Load eBPF object + attach all hooks; take map handles.
    let mut dp = datapath::load_and_attach(
        lan,
        wan,
        default_verdict,
        !e.bypass_cgroup.is_empty(),
        true, // flow cache on
        e.udp_workers,
        0,    // new-flow rate limit off (ant config has no field yet)
    )?;
    datapath::install_control_marker(&dp)?;

    let mut maps = dp.take_maps();

    // 5. Static kernel tables: private/link-local ranges, this host's own
    //    addresses, fake-IP range (forced PROXY) and any bypass rulesets (DIRECT).
    maps.add_private_direct()?;
    let local = maps.add_local_direct().unwrap_or(0);
    tracing::info!(local, "local-direct CIDRs installed");
    if cfg.dns.mode.eq_ignore_ascii_case("fakeip") {
        if let Some(range) = &cfg.dns.fakeip_range {
            maps.add_cidr(range, rules::Verdict::Proxy)?;
        }
        if let Some(range) = &cfg.dns.fakeip6_range {
            maps.add_cidr(range, rules::Verdict::Proxy)?;
        }
    }
    install_bypass_rulesets(&mut maps, &e.bypass_ruleset)?;

    let maps = Arc::new(AsyncMutex::new(maps));

    // 6. Transparent listeners inside antns → publish fds into the sockmap.
    let has_v6 = cfg.global.ipv6;
    let workers = e.udp_workers.clamp(1, 4) as usize;
    let listeners = listener::create(&mut dp, has_v6, workers)?;

    // 7. Relay context + control-socket marker used by outbound dials.
    let ctx = Arc::new(relay::RelayCtx {
        router: router.clone(),
        outbounds: outbounds.clone(),
        maps: maps.clone(),
        nodes,
    });
    let mut tcp_listeners = vec![listeners.tcp4];
    if let Some(tcp6) = listeners.tcp6 {
        tcp_listeners.push(tcp6);
    }
    let tcp_task = relay::run_tcp(tcp_listeners, ctx.clone());
    let udp_task = relay::run_udp(listeners.udp4, ctx.clone());
    let udp6_task = if listeners.udp6.is_empty() {
        None
    } else {
        Some(relay::run_udp(listeners.udp6, ctx.clone()))
    };

    // 8. Background cgroup watcher + flow-table janitor.
    cgroup::start(&e.bypass_cgroup, maps.clone())?;
    let stop = Arc::new(tokio::sync::Notify::new());
    let janitor = maintenance::spawn(maps, stop.clone());

    // 9. Open the datapath gate only now that listeners + maps are live.
    dp.set_ready(true)?;
    tracing::info!("ant eBPF datapath ready");

    // Run until ctrl-c or a relay loop fails.
    let result = tokio::select! {
        r = tcp_task => r.context("tcp relay"),
        r = udp_task => r.context("udp relay"),
        r = async { match udp6_task { Some(t) => t.await, None => std::future::pending().await } } => r.context("udp6 relay"),
        _ = tokio::signal::ctrl_c() => Ok(()),
    };

    // Teardown: close gate first, then stop janitor, drop dp (detaches hooks).
    dp.set_ready(false)?;
    stop.notify_one();
    janitor.abort();
    drop(dp);
    ns::cleanup(None, None, datapath::ANT0_HOST);
    result
}

/// Parse `bypass-ruleset` files and insert their IP/CIDR networks as DIRECT.
/// Accepts .ars (ARST binary), JSON/YAML text rule-sets. Only IP networks are
/// used; domain entries are ignored (routing stays in ant's userspace Router).
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
fn install_bypass_rulesets(
    maps: &mut rules::StaticMaps,
    paths: &[String],
) -> Result<()> {
    for path in paths {
        let data = std::fs::read(path)
            .with_context(|| format!("read bypass-ruleset {path}"))?;
        let cidrs = parse_ip_rules(&data, path)?;
        for cidr in &cidrs {
            if let Err(e) = maps.add_cidr(cidr, rules::Verdict::Direct) {
                tracing::warn!(error = %e, cidr, "bypass-ruleset CIDR");
            }
        }
        tracing::info!(path, cidrs = cidrs.len(), "bypass-ruleset loaded");
    }
    Ok(())
}

/// Extract IP/CIDR strings from a rule-set file. For text formats, any token
/// that parses as an IP network is collected; for .ars the IP-CIDR FST section
/// is currently not decoded (text sources are the supported bypass format).
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
fn parse_ip_rules(data: &[u8], path: &str) -> Result<Vec<String>> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Collect any whitespace/comma-separated token that parses as CIDR/IP.
        for tok in line.split(|c: char| c.is_whitespace() || c == ',') {
            let tok = tok.trim_matches(|c: char| c == '\'' || c == '"');
            if tok.is_empty() {
                continue;
            }
            let cidr = if tok.contains('/') {
                tok.to_string()
            } else if tok.parse::<std::net::IpAddr>().is_ok() {
                format!("{tok}/32")
            } else {
                continue;
            };
            if rules::parse_v4_cidr(&cidr).is_ok() || rules::parse_v6_cidr(&cidr).is_ok() {
                out.push(cidr);
            }
        }
    }
    if out.is_empty() {
        tracing::warn!(path, "no IP/CIDR entries found in bypass-ruleset");
    }
    Ok(out)
}

/// Stub for builds without the feature / on unsupported platforms.
#[cfg(not(all(feature = "ebpf", any(target_os = "linux", target_os = "android"))))]
pub async fn run_ebpf(
    _cfg: std::sync::Arc<crate::config::Config>,
    _router: std::sync::Arc<crate::app::router::Router>,
    _outbounds: std::sync::Arc<crate::outbound::OutboundManager>,
) -> Result<()> {
    anyhow::bail!("eBPF datapath requires a Linux/Android build with the `ebpf` feature")
}
