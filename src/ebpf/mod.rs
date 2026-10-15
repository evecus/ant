//! Linux-only eBPF datapath — a **stand-alone** control plane.
//!
//! ## What it does
//!
//! ant normally steers traffic with `nftables`: every LAN packet is marked
//! `0x80` and handed to the tproxy inbound, and userspace decides what to do
//! with it. That is simple and correct, but it means **every** flow wakes
//! userspace, even flows that a single IP-CIDR rule could settle.
//!
//! With `ebpf.enabled`, four TC classifiers evaluate the IP-CIDR part of the
//! route table in kernel (honk's four-role layout):
//!
//! | decision | datapath action                                              |
//! |----------|--------------------------------------------------------------|
//! | `proxy`  | mark `0x80` (+ action code in bits 16-23) → own nft tproxy    |
//! | `direct` | action code only → forwarded by the kernel, ant never sees it |
//! | `block`  | `TC_ACT_SHOT` — dropped at L3                                  |
//!
//! | role          | attached to | covers                                   |
//! |---------------|-------------|------------------------------------------|
//! | `lan_ingress` | LAN ingress | forwarded (client) traffic              |
//! | `lan_egress`  | LAN egress  | reply accounting for LAN-hijacked flows  |
//! | `wan_ingress` | WAN ingress | reply accounting for local-hijacked flows|
//! | `wan_egress`  | WAN egress  | **locally-generated traffic**            |
//!
//! Domain rules, sniffing and proxy-group selection stay in userspace: a flow
//! the datapath marks as `proxy` still lands in the tproxy inbound, where the
//! real [`Router`] runs. The datapath never decides *which node* to use.
//!
//! ## Independence from `ip_auto_route`
//!
//! The two control planes are **mutually exclusive** (`Config::validate`
//! rejects both at once). The datapath owns:
//!
//! | resource          | datapath                       | `ip_auto_route`        |
//! |-------------------|--------------------------------|------------------------|
//! | nft table         | `inet ant-ebpf`                | `inet ant-ip-auto-route` |
//! | policy route      | table 82, pref 1026            | table 80/81, pref 1024/1025 |
//! | interfaces        | `ebpf.lan-interfaces` / `-wan-`| `ip-auto-route.lan-interface` |
//! | reserved IPs      | own copy in this module        | `RESERVED_IP4/6`       |
//!
//! Everything lives behind `#[cfg(all(target_os = "linux", feature = "ebpf"))]`
//! in `main.rs` and `Cargo.toml`, so macOS/Windows builds never see aya.

mod attach;
mod btf;
mod config;
mod events;
mod janitor;
mod loader;
mod maps;
mod nft;
mod probe;
mod route;
mod route_sync;

pub use config::EbpfConfig;
pub use maps::DatapathStats;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aya::Ebpf;
use aya::maps::lpm_trie::Key;
use anyhow::{Context, Result, bail};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use ant_ebpf_common::AntParam;

use crate::app::router::Router;

/// Runtime values the datapath needs from ant's config.
#[derive(Debug, Clone)]
pub struct Params {
    /// `global.mark` — the SO_MARK ant stamps on its own sockets. The
    /// datapath uses it to recognise (and ignore) its own traffic, and the
    /// `nat_output` chain uses it to keep ant's own DNS unhijacked.
    pub socket_mark: u32,
    /// Local tproxy inbound port.
    pub tproxy_port: u16,
    /// DNS listener port (for the datapath's own DNS hijack chains).
    pub dns_port: u16,
    /// Whether IPv6 rules/routes are emitted.
    pub ipv6: bool,
}

/// Reserved IPv4 destinations that are never hijacked — the datapath's own
/// copy of `ip_auto_route`'s list (identical content, deliberately not
/// shared: the two control planes must not depend on each other).
const RESERVED_IP4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Reserved IPv6 destinations (see [`RESERVED_IP4`]).
const RESERVED_IP6: &[&str] = &[
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "100::/64",
    "64:ff9b::/96",
    "2001::/32",
    "2001:10::/28",
    "2001:20::/28",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

fn ifindex_of(iface: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(iface) else {
        return 0;
    };
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// Resolve the effective interface plan: configured masters (bridge master
/// substituted for a bridge slave), or auto-discovered when a list is empty.
///
/// LAN auto-discovery = every non-loopback up interface that is not a WAN
/// interface; WAN auto-discovery = the default-route interfaces.
fn resolve_interfaces(
    config: &EbpfConfig,
    _params: &Params,
    ipv6: bool,
) -> (Vec<String>, Vec<String>, bool) {
    let resolve = |list: &[String], discovered: Vec<String>| -> Vec<String> {
        let raw = if !list.is_empty() { list.to_vec() } else { discovered };
        let mut out: Vec<String> = Vec::new();
        for iface in raw {
            // A configured bridge slave stands for its master: forwarded L2
            // traffic traverses the master's hooks (and its slaves', which
            // `attach_roles` covers separately).
            let master = attach::bridge_master(&iface).unwrap_or(iface);
            if !out.contains(&master) {
                out.push(master);
            }
        }
        out
    };

    let wan = resolve(
        &config.wan_interfaces,
        attach::discover_wan_interfaces(ipv6),
    );
    let lan = resolve(
        &config.lan_interfaces,
        attach::discover_interfaces()
            .into_iter()
            .filter(|iface| !wan.contains(iface))
            .collect(),
    );
    let single_homed = lan.iter().any(|iface| wan.contains(iface));
    (lan, wan, single_homed)
}

/// Owns the loaded object, its attachments and the background tasks.
pub struct EbpfManager {
    bpf: Arc<Mutex<Ebpf>>,
    control: maps::ControlMaps,
    attached: attach::AttachmentSet,
    published_keys: Vec<Key<[u32; 4]>>,
    generation: Arc<AtomicU64>,
    config: EbpfConfig,
    params: Params,
    /// Effective LAN masters the nft fallback set currently gates on.
    lan_masters: Vec<String>,
    wan_masters: Vec<String>,
    single_homed: bool,
    wan_egress_ok: bool,
    _shutdown: broadcast::Sender<()>,
}

impl EbpfManager {
    /// Load, attach and start the background tasks.
    ///
    /// Returns `Err` when the kernel cannot host the datapath or any attach
    /// step fails. Because `ebpf.enabled` makes this module the sole
    /// transparent-proxy control plane, the caller treats that as fatal.
    pub fn start(config: &EbpfConfig, params: Params) -> Result<Self> {
        probe::bump_memlock_rlimit();

        let support = probe::Support::detect();
        if !support.datapath_ok() {
            bail!(
                "kernel {:?} is too old for the eBPF datapath (need >= 5.10 with BTF; \
                 `wan_egress` reads `__sk_buff.ingress_ifindex`, added in 5.10)",
                support.kernel
            );
        }

        let mode = loader::select_pname_mode(support.process_name);
        info!(
            "ebpf: datapath starting (process name: {:?}, kernel {:?})",
            mode, support.kernel
        );

        // ── interface plan ─────────────────────────────────────────────
        let (lan_masters, wan_masters, single_homed) =
            resolve_interfaces(config, &params, params.ipv6);
        if lan_masters.is_empty() && wan_masters.is_empty() {
            warn!("ebpf: no LAN or WAN interface resolved — datapath will not see traffic");
        }
        info!(
            "ebpf: interface plan lan={:?} wan={:?} single_homed={single_homed}",
            lan_masters, wan_masters
        );

        // `wan_egress` redirects onto `lo`; `local_ip` keeps connections to
        // ant's own management IP out of the datapath (honk's `param.local_ip`).
        let lo_ifindex = ifindex_of("lo");
        anyhow::ensure!(lo_ifindex != 0, "cannot resolve `lo` ifindex");
        let local_ip = lan_masters
            .iter()
            .find_map(|iface| attach::iface_ipv4(iface))
            .or_else(|| wan_masters.iter().find_map(|iface| attach::iface_ipv4(iface)))
            .unwrap_or(0);

        let param = AntParam {
            tproxy_port: params.tproxy_port as u32,
            ant_pid: std::process::id(),
            ant_socket_mark: params.socket_mark,
            lo_ifindex,
            local_ip,
            has_bpf_get_current_task: u8::from(matches!(mode, loader::PnameMode::Argv0)),
            pad: [0; 3],
        };

        let mut bpf = loader::load(param, support.process_name, mode)?;
        let mut control = maps::take_control(&mut bpf)?;
        let flow = maps::take_flow(&mut bpf)?;
        let ring = maps::take_ringbuf(&mut bpf).ok();

        // ── TC attach: the four roles ──────────────────────────────────
        let mut attached = attach::AttachmentSet::default();
        let plan = attach::AttachPlan {
            lan_masters: &lan_masters,
            wan_masters: &wan_masters,
            single_homed,
            wan_egress_ok: support.wan_egress_ok(),
        };
        // A failure here drops `bpf`, which detaches every link created so
        // far; nothing else has been installed yet.
        attach::attach_roles(&mut bpf, &plan, &mut attached)?;

        if config.cgroup {
            let path = config
                .cgroup_path
                .clone()
                .map(std::path::PathBuf::from)
                .or(support.cgroup2.clone());
            match path {
                Some(path) => {
                    if let Err(e) = attach::attach_cgroup(&mut bpf, &path, mode, &mut attached) {
                        warn!("ebpf: cgroup hooks unavailable ({e}); process attribution disabled");
                    }
                }
                None => warn!("ebpf: no cgroup v2 mount found; process attribution disabled"),
            }
        }

        // ── nft table + policy routing (datapath-owned) ────────────────
        let nft_params = nft::NftParams {
            lan_interfaces: &lan_masters,
            tproxy_port: params.tproxy_port,
            dns_port: params.dns_port,
            dns_hijack: config.dns_hijack,
            socket_mark: params.socket_mark,
            ipv6: params.ipv6,
            reserved4: RESERVED_IP4,
            reserved6: RESERVED_IP6,
        };
        if let Err(e) = nft::apply(&nft_params) {
            nft::cleanup();
            return Err(e.context("ebpf: nftables"));
        }
        if let Err(e) = route::install(params.ipv6) {
            nft::cleanup();
            route::cleanup();
            return Err(e.context("ebpf: policy routing"));
        }

        // Stay transparent until a routing table exists.
        control.set_ready(false)?;

        let bpf = Arc::new(Mutex::new(bpf));
        let (shutdown, _) = broadcast::channel(1);
        let generation = Arc::new(AtomicU64::new(0));

        if let Some(ring) = ring {
            events::spawn(ring, shutdown.subscribe());
        }
        janitor::spawn(flow, generation.clone(), shutdown.subscribe());
        if config.interface_rescan_secs > 0 {
            spawn_interface_rescan(RescanCtx {
                bpf: bpf.clone(),
                config: config.clone(),
                params: params.clone(),
                attached: attached.clone(),
                lan_masters: lan_masters.clone(),
                wan_egress_ok: support.wan_egress_ok(),
                secs: config.interface_rescan_secs,
                shutdown: shutdown.subscribe(),
            });
        }

        info!(
            "ebpf: attached to {} interface(s): {:?}",
            attached.interfaces.len(),
            attached.interfaces
        );

        Ok(Self {
            bpf,
            control,
            attached,
            published_keys: Vec::new(),
            generation,
            config: config.clone(),
            params,
            lan_masters,
            wan_masters,
            single_homed,
            wan_egress_ok: support.wan_egress_ok(),
            _shutdown: shutdown,
        })
    }

    /// Publish the IP-CIDR part of the route table and open the datapath.
    pub fn sync_routes(&mut self, router: &Router, ipv6: bool) -> Result<()> {
        // Pick up interfaces that appeared since startup (hot-plug / VPN).
        let _ = self.refresh_interfaces();

        let reserved = reserved_destinations(ipv6);
        let table = route_sync::build(router, ipv6, &reserved);

        self.control.clear_routes(&self.published_keys);
        for (key, decision) in &table.entries {
            self.control
                .insert_route(key, *decision)
                .context("insert LPM route")?;
        }
        self.control
            .set_default_route(table.default)
            .context("publish default route")?;
        self.published_keys = table.entries.iter().map(|(key, _)| *key).collect();
        // Cached decisions belong to the previous table.
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.control.set_ready(true)?;

        info!(
            "ebpf: published {} IP-CIDR route(s), default = {:?}",
            table.len(),
            ant_ebpf_common::RouteAction::from_u8(table.default.action)
        );
        Ok(())
    }

    /// Close the datapath without unloading: every packet goes back to the
    /// untouched kernel path (the nft fallback stays installed).
    pub fn suspend(&mut self) -> Result<()> {
        self.control.set_ready(false)
    }

    pub fn ready(&self) -> Result<bool> {
        self.control.ready()
    }

    /// Aggregate traffic / health counters.
    pub fn stats(&self) -> Result<DatapathStats> {
        self.control.stats()
    }

    /// Attach to interfaces that appeared after startup. Called on every
    /// route sync and by the rescan task. Also re-applies the nft table
    /// when the LAN set changed (the fallback chain gates on it).
    pub fn refresh_interfaces(&mut self) -> usize {
        let (lan, wan, single_homed) =
            resolve_interfaces(&self.config, &self.params, self.params.ipv6);
        let plan = attach::AttachPlan {
            lan_masters: &lan,
            wan_masters: &wan,
            single_homed,
            wan_egress_ok: self.wan_egress_ok,
        };

        let before = self.attached.interfaces.len();
        let mut attached = self.attached.clone();
        {
            let Ok(mut bpf) = self.bpf.lock() else {
                return 0;
            };
            if let Err(e) = attach::attach_roles(&mut bpf, &plan, &mut attached) {
                warn!("ebpf: rescan attach failed: {e}");
                return 0;
            }
        }
        self.attached.clone_from(&attached);
        let added = self.attached.interfaces.len().saturating_sub(before);
        if added > 0 {
            info!("ebpf: attached to {added} new interface(s)");
        }

        if lan != self.lan_masters {
            let nft_params = nft::NftParams {
                lan_interfaces: &lan,
                tproxy_port: self.params.tproxy_port,
                dns_port: self.params.dns_port,
                dns_hijack: self.config.dns_hijack,
                socket_mark: self.params.socket_mark,
                ipv6: self.params.ipv6,
                reserved4: RESERVED_IP4,
                reserved6: RESERVED_IP6,
            };
            if let Err(e) = nft::apply(&nft_params) {
                warn!("ebpf: nft re-apply after interface change failed: {e}");
            } else {
                info!("ebpf: nft fallback set updated for LAN {:?}", lan);
            }
            self.lan_masters = lan;
        }
        self.wan_masters = wan;
        self.single_homed = single_homed;
        added
    }

    /// Interfaces the datapath is currently attached to.
    pub fn interfaces(&self) -> &[String] {
        &self.attached.interfaces
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        // Stop new marks first, then remove the pipeline the datapath owns.
        // In-flight packets that already carry the mark are routed to `lo`
        // by the (about to be deleted) rule and simply get delivered
        // locally for the microseconds before the rule is gone.
        let _ = self.control.set_ready(false);
        nft::cleanup();
        route::cleanup();
        debug!("ebpf: datapath shutting down");
    }
}

/// The destinations the datapath publishes as `direct` so LAN-to-LAN
/// traffic, inbound port forwards and replies coming back to LAN clients
/// keep the exact behaviour the nft pipeline gave them.
fn reserved_destinations(ipv6: bool) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = RESERVED_IP4.to_vec();
    if ipv6 {
        out.extend_from_slice(RESERVED_IP6);
    }
    out
}

/// Everything the interface rescan task needs (bundled so the spawn
/// signature stays within clippy's argument budget).
struct RescanCtx {
    bpf: Arc<Mutex<Ebpf>>,
    config: EbpfConfig,
    params: Params,
    attached: attach::AttachmentSet,
    lan_masters: Vec<String>,
    wan_egress_ok: bool,
    secs: u64,
    shutdown: broadcast::Receiver<()>,
}

fn spawn_interface_rescan(ctx: RescanCtx) {
    let RescanCtx {
        bpf,
        config,
        params,
        mut attached,
        mut lan_masters,
        wan_egress_ok,
        secs,
        mut shutdown,
    } = ctx;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs.max(5)));
        tick.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = tick.tick() => {}
            }
            let (lan, wan, single_homed) = resolve_interfaces(&config, &params, params.ipv6);
            let plan = attach::AttachPlan {
                lan_masters: &lan,
                wan_masters: &wan,
                single_homed,
                wan_egress_ok,
            };
            let before = attached.interfaces.len();
            let mut next = attached.clone();
            {
                let Ok(mut bpf) = bpf.lock() else {
                    continue;
                };
                if let Err(e) = attach::attach_roles(&mut bpf, &plan, &mut next) {
                    warn!("ebpf: rescan attach failed: {e}");
                    continue;
                }
            }
            if next.interfaces.len() != before {
                info!(
                    "ebpf: attached to new interface(s): {:?}",
                    next.interfaces
                        .iter()
                        .filter(|name| !attached.interfaces.contains(name))
                        .collect::<Vec<_>>()
                );
                attached.clone_from(&next);
            }
            if lan != lan_masters {
                let nft_params = nft::NftParams {
                    lan_interfaces: &lan,
                    tproxy_port: params.tproxy_port,
                    dns_port: params.dns_port,
                    dns_hijack: config.dns_hijack,
                    socket_mark: params.socket_mark,
                    ipv6: params.ipv6,
                    reserved4: RESERVED_IP4,
                    reserved6: RESERVED_IP6,
                };
                match nft::apply(&nft_params) {
                    Ok(()) => {
                        info!("ebpf: nft fallback set updated for LAN {:?}", lan);
                        lan_masters = lan;
                    }
                    Err(e) => warn!("ebpf: nft re-apply after interface change failed: {e}"),
                }
            }
        }
    });
}

/// Cheap pre-flight check so ant can log a clear reason instead of failing
/// deep inside aya.
pub fn supported() -> Result<()> {
    let support = probe::Support::detect();
    if !support.datapath_ok() {
        bail!(
            "eBPF datapath needs Linux >= 5.10 with /sys/kernel/btf/vmlinux (found kernel {:?})",
            support.kernel
        );
    }
    Ok(())
}
