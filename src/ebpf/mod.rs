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
pub(crate) mod datapath;
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
    use tokio::task::JoinHandle;

    /// Owns every piece of kernel state created during bring-up and tears it
    /// down in reverse order on `Drop`. Fields are filled in as each step
    /// succeeds, so a `?` failure partway through startup cleans up exactly
    /// the same resources as a normal Ctrl-C/SIGTERM exit — no partial state.
    struct Teardown {
        /// netns / veth / policy routing created (step 1).
        netns: bool,
        /// BPF object loaded and hooks attached (step 4). Dropping the loader
        /// detaches the TC / sk_lookup programs.
        dp: Option<datapath::Datapath>,
        /// Admission gate was opened (step 9); must close before hooks drop.
        gate_open: bool,
        /// Flow-table janitor + its stop notifier (step 8).
        janitor: Option<JoinHandle<()>>,
        stop: Option<Arc<tokio::sync::Notify>>,
        /// cgroup bypass watcher (step 8).
        cgroup: Option<JoinHandle<()>>,
    }

    impl Teardown {
        fn dp(&mut self) -> &mut datapath::Datapath {
            self.dp.as_mut().expect("datapath not created")
        }
    }

    impl Drop for Teardown {
        fn drop(&mut self) {
            // Reverse of bring-up: gate → background tasks → hooks → netns.
            if self.gate_open {
                if let Err(e) = self.dp().set_ready(false) {
                    tracing::warn!(error = %e, "teardown: close datapath gate");
                }
            }
            if let Some(stop) = &self.stop {
                stop.notify_one();
            }
            if let Some(j) = self.janitor.take() {
                j.abort();
            }
            if let Some(j) = self.cgroup.take() {
                j.abort();
            }
            // Detach TC / sk_lookup programs by dropping the aya loader.
            self.dp.take();
            if self.netns {
                ns::cleanup(None, None, datapath::ANT0_HOST);
            }
        }
    }

    let e = &cfg.ebpf;
    // One guard for the whole lifecycle; normal exit and early `?` failures
    // both unwind through its Drop, so teardown lives in exactly one place.
    let mut td = Teardown {
        netns: false,
        dp: None,
        gate_open: false,
        janitor: None,
        stop: None,
        cgroup: None,
    };

    // 0. Pre-resolve node server hostnames while no TC hook exists yet
    //    (aligns with silk's `resolve_server` loop before `create_silkns`).
    //    The results are cached in the DNS module and reused by later dials,
    //    so startup does not depend on our own DNS path surviving capture.
    crate::dns::pre_resolve_servers(&outbounds.server_addrs()).await;

    // 1. netns + veth + policy routing. Set `netns` only after success so a
    //    failure here does not try to clean up a namespace we never made.
    ns::create_antns()?;
    td.netns = true;
    datapath::setup_links()?;

    // 2. Resolve capture interfaces.
    let lan = datapath::resolve_interface(e.lan.as_deref().unwrap_or(""))?;
    let wan = datapath::resolve_interface(e.wan.as_deref().unwrap_or(""))?;
    // Android: route control-plane sockets (SO_MARK) via the WAN table so
    // dials don't fall into netd's unreachable rule (no-op on desktop Linux).
    datapath::setup_android_control_route(wan.as_ref().map(|(n, _)| n.as_str()));

    // 3. Ordered node list; index encodes the kernel verdict. The kernel's
    //    default verdict is just "capture and let userspace decide": the relay
    //    re-runs the full route (incl. proxy-group selection) per flow, so a
    //    coarse VERDICT_PROXY is correct here. Using the MATCH outbound label
    //    would fail because a proxy-group name (e.g. PROXY) is not a concrete
    //    node and is therefore absent from `node_names()`.
    let nodes = outbounds.node_names();
    let default_verdict = rules::Verdict::Proxy;

    // 4. Load eBPF object + attach all hooks; take map handles. Hand the
    //    loader to the guard right away so a later `?` still detaches hooks.
    let dp = datapath::load_and_attach(
        lan,
        wan,
        default_verdict,
        !e.bypass_cgroup.is_empty(),
        true, // flow cache on
        e.udp_workers,
        0,    // new-flow rate limit off (ant config has no field yet)
    )?;
    datapath::install_control_marker(&dp)?;
    td.dp = Some(dp);

    let mut maps = td.dp().take_maps();

    // 5. Static kernel tables: private/link-local ranges (unless bypass-private
    //    is off), this host's own addresses, fake-IP range (forced PROXY) and
    //    any bypass rulesets (DIRECT).
    if e.bypass_private {
        maps.add_private_direct()?;
    } else {
        tracing::info!("bypass-private=false: reserved ranges left to route table");
    }
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
    install_bypass_ip(&mut maps, &router, &e.bypass_ip)?;

    let maps = Arc::new(AsyncMutex::new(maps));

    // 6. Transparent listeners inside antns → publish fds into the sockmap.
    let has_v6 = cfg.global.ipv6;
    let workers = e.udp_workers.clamp(1, 4) as usize;
    let listeners = listener::create(td.dp(), has_v6, workers)?;

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

    // 8. Background cgroup watcher + flow-table janitor. Keep their handles
    //    in the guard so they are stopped during teardown.
    td.cgroup = Some(cgroup::start(&e.bypass_cgroup, maps.clone())?);
    let stop = Arc::new(tokio::sync::Notify::new());
    td.janitor = Some(maintenance::spawn(maps, stop.clone()));
    td.stop = Some(stop);

    // 9. Open the datapath gate only now that listeners + maps are live.
    td.dp().set_ready(true)?;
    td.gate_open = true;
    tracing::info!("ant eBPF datapath ready");

    // Run until Ctrl-C, SIGTERM, or a relay loop fails. In every case the
    // guard's Drop reverses all of the above. This whole function compiles
    // only on Linux/Android (both unix), so tokio's unix signals are safe.
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("install SIGTERM handler")?;
    let result = tokio::select! {
        r = tcp_task => r.context("tcp relay"),
        r = udp_task => r.context("udp relay"),
        r = async { match udp6_task { Some(t) => t.await, None => std::future::pending().await } } => r.context("udp6 relay"),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    };
    // Explicit drop makes the teardown point obvious; `result` is returned
    // afterwards. The guard also covers every early `?` above.
    drop(td);
    result
}

/// Install the IP networks of the `bypass-ip` rulesets as DIRECT in the kernel.
///
/// Names refer to `rule-providers:` entries, exactly like `RULE-SET` in `route:`.
/// The providers are loaded once by the Router at startup; we reuse that
/// in-memory copy so bypass semantics match routing semantics byte-for-byte.
/// Only the IP-CIDR portion is used; domain entries are ignored (routing stays
/// in ant's userspace Router).
#[cfg(all(feature = "ebpf", any(target_os = "linux", target_os = "android")))]
fn install_bypass_ip(
    maps: &mut rules::StaticMaps,
    router: &crate::app::router::Router,
    names: &[String],
) -> Result<()> {
    for name in names {
        let Some((v4, v6)) = router.ruleset_ip_cidrs(name) else {
            anyhow::bail!("ebpf.bypass-ip: rule-provider `{name}` not loaded");
        };
        if v4.is_empty() && v6.is_empty() {
            anyhow::bail!("ebpf.bypass-ip: rule-provider `{name}` has no IP-CIDR entries");
        }
        let mut count = 0usize;
        for (addr, plen) in &v4 {
            let cidr = format!("{addr}/{plen}");
            if let Err(e) = maps.add_cidr(&cidr, rules::Verdict::Direct) {
                tracing::warn!(error = %e, cidr, "bypass-ip CIDR");
            } else {
                count += 1;
            }
        }
        for (addr, plen) in &v6 {
            let cidr = format!("{addr}/{plen}");
            if let Err(e) = maps.add_cidr(&cidr, rules::Verdict::Direct) {
                tracing::warn!(error = %e, cidr, "bypass-ip CIDR");
            } else {
                count += 1;
            }
        }
        tracing::info!(name, cidrs = count, "bypass-ip installed");
    }
    Ok(())
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
