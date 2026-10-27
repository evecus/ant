//! Linux system-wide transparent proxy control plane (`ip-auto-route`).
//!
//! Rule semantics are aligned with **nexa** (`internal/nfttemplate/tmpl.go` +
//! `internal/netmanager/{netmanager,iptables}.go`):
//!
//! - Prefer **nftables**, fall back to **iptables/ip6tables**
//! - Policy routing via **rtnetlink** (fwmark → table): tproxy → `local default
//!   dev lo`, tun → `default dev <tun>`
//! - Loop prevention: **cgroup** (preferred, nexa `bypass_cgroup`), **gid**
//!   (`bypass-type: gid`, process effective GID / `primary-gid`), or
//!   **fwmark** (`bypass-type: mark`, ant's own SO_MARK) — see [`BypassType`]
//! - TUN traffic allowed through the host firewall (`fw4`/`filter` input+forward)
//! - Full cleanup on stop or apply failure
//!
//! Only active on Linux and Android (netlink via `rtnetlink-android`).
//! On Android the feature needs a rooted device with a working
//! `nft`/`iptables`; `backend::detect` reports `None` when neither exists.
//!
//! ## Why the hijack fwmark is *not* the SO_MARK
//!
//! The fwmark that policy routing keys on (`0x80/0xff`) is deliberately
//! different from ant's SO_MARK (`global.mark`). If they were the same value,
//! every socket ant opens would already carry the hijack mark, so `ip rule
//! fwmark …` would send ant's *own* traffic into `lo`/TUN → tproxy → ant →
//! loop. nexa never hits this because its core process carries no fwmark at
//! all; ant shares `global.mark` with TUN auto-route, so the two values have
//! to be kept apart.

use crate::config::Config;
use anyhow::Result;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod backend;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod cgroup;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod fw_include;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod iptables;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod nft;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod route;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sysctl;

/// Comment tag used for every rule ant installs (iptables `-m comment`,
/// nft `comment "…"` in the host fw4/filter table). Mirrors nexa's `nexa` tag.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const COMMENT: &str = "ant-ip-auto-route";

/// Reserved IPv4 destinations that are never hijacked (nexa `proxy.reserved_ip`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const RESERVED_IP4: &[&str] = &[
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

/// Reserved IPv6 destinations that are never hijacked (nexa `proxy.reserved_ip6`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const RESERVED_IP6: &[&str] = &[
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

/// Dummy device carrying the Fake-IP v6 route (nexa `routing.dummy_device`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const DUMMY_DEVICE: &str = "ant-dummy";

/// Seconds to wait for the TUN device to come up (nexa `proxy.tun_timeout`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const TUN_TIMEOUT: u32 = 30;

/// fwmark written on hijacked TCP/UDP that must go to the tproxy inbound
/// (nexa `routing.tproxy_fw_mark`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const TPROXY_FWMARK: u32 = 0x0000_0080;

/// fwmark for traffic routed into the TUN device (nexa `routing.tun_fw_mark`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const TUN_FWMARK: u32 = 0x0000_0081;

/// Bit window the hijack marks own — nexa `routing.tproxy_fw_mask`.
/// Only these bits are touched, so marks set by other services survive
/// (`meta mark set meta mark & 0xffffff80 | 0x00000080`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const FW_MASK: u32 = 0x0000_00ff;

/// Default cgroup v2 name → `/sys/fs/cgroup/services/ant`
/// (nexa `routing.cgroup_name` = `proxy`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const CGROUP_NAME: &str = "ant";

/// cgroup v1 net_cls classid (nexa `routing.cgroup_id`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const CGROUP_ID: &str = "0x07250725";

/// How ant's own traffic is recognised and let through the hijack rules.
/// Supports cgroup (default when available), gid (explicit, needs early
/// setgid via [`early_prepare`]), or mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassType {
    /// `socket cgroupv2 level 2 "services/<name>"` (v2) / `meta cgroup <id>`
    /// (v1) — matches the *process*, immune to mark collisions.
    Cgroup,
    /// `meta skgid { <primary_gid> }` / iptables `-m owner --gid-owner` —
    /// matches sockets created under the process effective GID (after optional
    /// `setgid` to `primary-gid`).
    Gid,
    /// `meta mark & 0xffffffff == <global.mark>` — matches ant's SO_MARK.
    Mark,
}

/// Resolved runtime parameters derived from Config.
#[derive(Debug, Clone)]
pub struct Params {
    pub ipv6: bool,
    pub dns_hijack: bool,
    pub dns_port: u16,
    pub fakeip_ping: bool,
    pub fakeip_v4: Option<String>,
    pub fakeip_v6: Option<String>,
    pub tcp_mode: Option<TcpMode>,
    pub udp_mode: Option<UdpMode>,
    pub redir_port: u16,
    pub tproxy_port: u16,
    pub tun_device: String,
    /// Hijack locally-originated traffic (nexa `router_proxy`).
    pub router_proxy: bool,
    pub lan_proxy: bool,
    pub lan_interface: Vec<String>,
    pub lan_bypass_ip: Vec<String>,
    pub lan_bypass_mac: Vec<String>,
    pub bypass_uid: Vec<u32>,
    pub bypass_gid: Vec<u32>,
    pub bypass_cgroup: Vec<String>,
    /// Loop-prevention method actually in effect (resolved from `bypass-type`
    /// + runtime cgroup detection).
    pub bypass_type: BypassType,
    /// cgroup v2 sub-name under `services/` (nexa `routing.cgroup_name`).
    pub cgroup_name: String,
    /// cgroup v1 net_cls classid (nexa `routing.cgroup_id`).
    pub cgroup_id: String,
    /// Directory the core process actually lives in: relative to the cgroup2
    /// root for v2 (`services/ant`), to the net_cls mount for v1 (`ant`).
    pub cgroup_path: String,
    /// Depth of `cgroup_path` — nft needs it as `socket cgroupv2 level <n>`.
    pub cgroup_level: usize,
    /// True when the detected cgroup flavour is v2 (false → v1 `meta cgroup`).
    pub cgroup_v2: bool,
    /// Effective GID used for `BypassType::Gid` loop prevention
    /// (`meta skgid` / `--gid-owner`). Set from `primary-gid` (after optional
    /// `setgid`) or the process egid when omitted.
    pub primary_gid: u32,
    /// ant's own SO_MARK (`global.mark`) — consumed by `BypassType::Mark`.
    pub mark: u32,
    pub bypass_ip: Vec<String>,
    pub bypass_ip6: Vec<String>,
    /// fwmark + mask policy routing keys on for the tproxy path.
    pub tproxy_fwmark: u32,
    pub tproxy_fwmask: u32,
    /// fwmark + mask policy routing keys on for the tun path.
    pub tun_fwmark: u32,
    pub tun_fwmask: u32,
    pub tproxy_table: u32,
    pub tproxy_pref: u32,
    pub tun_table: u32,
    pub tun_pref: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    Redir,
    Tproxy,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    Tproxy,
    Tun,
}

impl Params {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let iar = &cfg.ip_auto_route;
        // `mark` is guaranteed non-zero by Config::validate_ip_auto_route.
        let mark = cfg.global.mark;
        let tcp_mode =
            iar.tcp_mode
                .as_deref()
                .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                    "redir" => Some(TcpMode::Redir),
                    "tproxy" => Some(TcpMode::Tproxy),
                    "tun" => Some(TcpMode::Tun),
                    _ => None,
                });
        let udp_mode =
            iar.udp_mode
                .as_deref()
                .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                    "tproxy" => Some(UdpMode::Tproxy),
                    "tun" => Some(UdpMode::Tun),
                    _ => None,
                });
        let tun_device = cfg
            .tun
            .device
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "tun0".into());
        // ── hijack fwmarks ─────────────────────────────────────────────────
        // Fixed values, same as nexa `routing.tproxy_fw_mark` / `tun_fw_mark`,
        // and deliberately **not** ant's SO_MARK: if the two were equal, every
        // socket ant opens would already match `ip rule fwmark …` and be routed
        // back into lo/TUN (self-loop). The mask keeps only the low 8 bits, so
        // marks owned by other services are preserved:
        //   `meta mark set meta mark & 0xffffff80 | 0x00000080`
        let tproxy_fwmark = TPROXY_FWMARK;
        let tproxy_fwmask = FW_MASK;
        let tun_fwmark = TUN_FWMARK;
        let tun_fwmask = FW_MASK;

        // ── loop prevention: cgroup (preferred) / gid / mark ────────────────
        // Default auto-pick: cgroup when a writable mount exists, otherwise
        // mark. `bypass-type: gid` is explicit only (never an automatic
        // fallback) because it requires a non-zero GID and early setgid.
        let requested = match iar
            .bypass_type
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("") | None => None,
            Some("cgroup") => Some(BypassType::Cgroup),
            Some("gid") => Some(BypassType::Gid),
            Some("mark") => Some(BypassType::Mark),
            Some(other) => anyhow::bail!(
                "ip-auto-route.bypass-type `{other}` is invalid; expected cgroup|gid|mark"
            ),
        };
        let version = cgroup::detect();
        let bypass_type = match requested {
            Some(BypassType::Mark) => BypassType::Mark,
            Some(BypassType::Gid) => BypassType::Gid,
            Some(BypassType::Cgroup) if version == cgroup::Version::None => {
                tracing::warn!(
                    "ip-auto-route: bypass-type=cgroup requested, but no writable cgroup \
                     mount was found; falling back to bypass-type=mark"
                );
                BypassType::Mark
            }
            Some(BypassType::Cgroup) => BypassType::Cgroup,
            None if version == cgroup::Version::None => {
                tracing::warn!(
                    "ip-auto-route: cgroup unavailable, using mark for loop prevention"
                );
                BypassType::Mark
            }
            None => BypassType::Cgroup,
        };
        let cgroup_name = iar
            .cgroup_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| CGROUP_NAME.to_string());
        let cgroup_id = iar
            .cgroup_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| CGROUP_ID.to_string());
        // Default rule path; `apply` overwrites it with the directory the
        // process actually landed in (`cgroup::enter` may fall back upwards).
        let cgroup_path = format!("services/{cgroup_name}");
        // Placeholder; `apply` resolves the real value (optional setgid + egid).
        let primary_gid = iar.primary_gid.unwrap_or(0);

        Ok(Self {
            ipv6: iar.ipv6 && cfg.global.ipv6,
            dns_hijack: iar.dns_hijack_to_port,
            dns_port: cfg.dns.listen_port(),
            fakeip_ping: iar.fakeip_ping_hijack,
            fakeip_v4: cfg
                .dns
                .fakeip_range
                .clone()
                .filter(|s| !s.trim().is_empty()),
            fakeip_v6: cfg
                .dns
                .fakeip6_range
                .clone()
                .filter(|s| !s.trim().is_empty()),
            tcp_mode,
            udp_mode,
            redir_port: cfg.global.redir_port.unwrap_or(0),
            tproxy_port: cfg.global.tproxy_port.unwrap_or(0),
            tun_device,
            router_proxy: iar.router_proxy,
            lan_proxy: iar.lan_proxy,
            lan_interface: iar
                .lan_interface
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            lan_bypass_ip: iar
                .lan_bypass_ip
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            lan_bypass_mac: iar
                .lan_bypass_mac
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            bypass_uid: iar.bypass_uid.clone(),
            bypass_gid: iar.bypass_gid.clone(),
            bypass_cgroup: iar
                .bypass_cgroup
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            bypass_type,
            cgroup_name,
            cgroup_id,
            cgroup_path,
            cgroup_level: 2,
            cgroup_v2: version == cgroup::Version::V2,
            primary_gid,
            mark,
            bypass_ip: RESERVED_IP4.iter().map(|s| s.to_string()).collect(),
            bypass_ip6: RESERVED_IP6.iter().map(|s| s.to_string()).collect(),
            tproxy_fwmark,
            tproxy_fwmask,
            tun_fwmark,
            tun_fwmask,
            tproxy_table: 80,
            tproxy_pref: 1024,
            tun_table: 81,
            tun_pref: 1025,
        })
    }

    pub fn needs_tproxy(&self) -> bool {
        self.tcp_mode == Some(TcpMode::Tproxy) || self.udp_mode == Some(UdpMode::Tproxy)
    }

    pub fn needs_tun(&self) -> bool {
        self.tcp_mode == Some(TcpMode::Tun) || self.udp_mode == Some(UdpMode::Tun)
    }

    pub fn needs_redir(&self) -> bool {
        self.tcp_mode == Some(TcpMode::Redir)
    }
}

/// Fix the process effective GID for `BypassType::Gid` loop prevention.
///
/// * If `primary_gid` is `Some(g)` and differs from the current egid, call
///   `setgid(g)` only (does **not** touch supplementary groups via
///   `setgroups`, so group-based file permissions stay intact).
/// * If `primary_gid` is `None`, keep the current egid.
///
/// Returns the final egid. Refuses a final GID of 0: matching `skgid 0` /
/// `--gid-owner 0` would let **every** process in the root group bypass the
/// hijack rules, not just ant.
///
/// **Must be called from [`early_prepare`] before any outbound / provider /
/// DNS / inbound sockets are created** — `skgid` is stamped at socket
/// creation time and cannot be changed afterwards.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fix_primary_gid(primary_gid: Option<u32>) -> Result<u32> {
    let current = unsafe { libc::getegid() } as u32;
    let target = primary_gid.unwrap_or(current);
    if target == 0 {
        anyhow::bail!(
            "ip-auto-route.bypass-type=gid requires a non-zero GID \
             (current egid is 0 and primary-gid is unset or 0). \
             Matching skgid/gid-owner 0 would bypass the proxy for \
             every process in the root group, not only ant. \
             Set `primary-gid: <non-zero>` (and run with CAP_SETGID) \
             or use bypass-type: cgroup|mark instead"
        );
    }
    if target != current {
        let g = target as libc::gid_t;
        // Only setgid — do NOT call setgroups(). Clearing supplementary
        // groups would break access to config/log/rules files that rely
        // on group permissions.
        let rc = unsafe { libc::setgid(g) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "setgid({target}): {} (need CAP_SETGID / root)",
                std::io::Error::last_os_error()
            ));
        }
        let after = unsafe { libc::getegid() } as u32;
        if after != target {
            return Err(anyhow::anyhow!(
                "setgid({target}) reported success but egid is still {after}"
            ));
        }
        tracing::info!(
            from = current,
            to = target,
            "ip-auto-route: setgid for GID loop prevention"
        );
        return Ok(after);
    }
    Ok(current)
}

/// Early identity setup that **must** run before any network sockets are
/// created (providers, DNS, outbounds, inbounds).
///
/// Currently only handles `bypass-type: gid` (`setgid`). Cgroup placement
/// stays in [`apply`] because it does not rewrite existing socket
/// credentials the same way.
///
/// No-op when `ip-auto-route` is disabled or bypass-type is not `gid`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn early_prepare(cfg: &Config) -> Result<()> {
    if !cfg.ip_auto_route.enable {
        return Ok(());
    }
    let requested = cfg
        .ip_auto_route
        .bypass_type
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase());
    match requested.as_deref() {
        Some("gid") => {
            let gid = fix_primary_gid(cfg.ip_auto_route.primary_gid)?;
            tracing::info!(
                gid,
                "ip-auto-route: early GID fixed for loop prevention (before sockets)"
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn early_prepare(_cfg: &Config) -> Result<()> {
    Ok(())
}

/// RAII guard: cleanup firewall + routes on drop.
pub struct Guard {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inner: Option<Params>,
}

/// Apply ip-auto-route. On failure, cleans partial state and returns Err.
pub async fn apply(cfg: &Config) -> Result<Guard> {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = cfg;
        anyhow::bail!("ip-auto-route is only supported on Linux and Android");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut params = Params::from_config(cfg)?;

        // 0. Loop prevention identity.
        //    - cgroup: join now (process-level; new sockets inherit the cgroup).
        //    - gid: MUST already have been fixed by [`early_prepare`] before any
        //      outbound/provider/DNS/inbound sockets were created. Here we only
        //      read the current egid for the rule; we never setgid at this
        //      late point (existing sockets would keep the old skgid → loop).
        //    If the chosen method cannot be realised, degrade to mark.
        if params.bypass_type == BypassType::Cgroup {
            match cgroup::enter(&params.cgroup_name, &params.cgroup_id) {
                Ok(pl) => {
                    params.cgroup_path = pl.path;
                    params.cgroup_level = pl.level;
                    params.cgroup_v2 = pl.version == cgroup::Version::V2;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "ip-auto-route: could not join cgroup, falling back to mark bypass"
                    );
                    params.bypass_type = BypassType::Mark;
                }
            }
        } else if params.bypass_type == BypassType::Gid {
            let gid = unsafe { libc::getegid() } as u32;
            if gid == 0 {
                tracing::warn!(
                    "ip-auto-route: bypass-type=gid but egid is still 0 at apply \
                     time (early_prepare missing or failed?); falling back to mark \
                     to avoid bypassing every root-group process"
                );
                params.bypass_type = BypassType::Mark;
            } else {
                params.primary_gid = gid;
                tracing::info!(
                    gid,
                    "ip-auto-route: using current egid for GID loop prevention"
                );
            }
        }

        tracing::info!(
            tcp = ?params.tcp_mode,
            udp = ?params.udp_mode,
            bypass = ?params.bypass_type,
            cgroup = %params.cgroup_path,
            primary_gid = params.primary_gid,
            tproxy_fwmark = format!("0x{:x}/0x{:x}", params.tproxy_fwmark, params.tproxy_fwmask),
            tun_fwmark = format!("0x{:x}/0x{:x}", params.tun_fwmark, params.tun_fwmask),
            router = params.router_proxy,
            lan = params.lan_proxy,
            "ip-auto-route: applying"
        );

        // 1. bridge-nf compatibility (nexa proxy.init:170-185).
        sysctl::prepare(&params);

        // 2. Policy routing: TUN wait + fake-ip6 dummy + ip rule/route.
        if let Err(e) = route::install(&params).await {
            cleanup_all(&params);
            return Err(e.context("ip-auto-route: policy routing"));
        }

        // 3. Traffic hijack: nftables (preferred) or iptables.
        let backend = backend::detect();
        tracing::info!(?backend, "ip-auto-route: firewall backend");
        let mut used_nft = false;
        let fw =
            match backend {
                backend::Backend::Nftables => match nft::apply(&params) {
                    Ok(()) => {
                        used_nft = true;
                        Ok(())
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "ip-auto-route: nftables apply failed, trying iptables fallback"
                        );
                        nft::cleanup();
                        match iptables::apply(&params) {
                            Ok(()) => Ok(()),
                            Err(e2) => Err(e2
                                .context(format!("iptables fallback failed (nft error was: {e})"))),
                        }
                    }
                },
                backend::Backend::Iptables => iptables::apply(&params),
                backend::Backend::None => Err(anyhow::anyhow!(
                    "neither nftables nor iptables is available"
                )),
            };

        if let Err(e) = fw {
            cleanup_all(&params);
            return Err(e.context("ip-auto-route: firewall rules"));
        }

        // 4. Host-firewall TUN passthrough (nexa firewall_include.sh). The
        //    iptables backend already inserted `filter INPUT/FORWARD` accept
        //    rules, so this only applies to the nftables backend.
        if used_nft {
            fw_include::apply(&params);
        }

        Ok(Guard {
            inner: Some(params),
        })
    }
}

/// Full teardown: hijack rules (both backends) + host firewall TUN accept +
/// policy routing + dummy device + ipset + restored sysctls.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cleanup_all(p: &Params) {
    nft::cleanup();
    iptables::cleanup(p);
    fw_include::cleanup(p);
    route::cleanup(p);
    sysctl::restore();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for Guard {
    fn drop(&mut self) {
        let Some(params) = self.inner.take() else {
            return;
        };
        tracing::info!("ip-auto-route: cleanup on drop");
        cleanup_all(&params);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Drop for Guard {
    fn drop(&mut self) {}
}
