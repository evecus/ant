//! Linux system-wide transparent proxy control plane (`ip-auto-route`).
//!
//! Rule semantics are aligned with **nexa** (`internal/nfttemplate/tmpl.go` +
//! `internal/netmanager/{netmanager,iptables}.go`):
//!
//! - Prefer **nftables**, fall back to **iptables/ip6tables**
//! - Policy routing via **rtnetlink** (fwmark → table): tproxy → `local default
//!   dev lo`, tun → `default dev <tun>`
//! - Loop prevention via mark (shared with top-level `mark` = ant's SO_MARK)
//! - TUN traffic allowed through the host firewall (`fw4`/`filter` input+forward)
//! - Full cleanup on stop or apply failure
//!
//! Only active on Linux.

use crate::config::Config;
use anyhow::Result;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod fw_include;
#[cfg(target_os = "linux")]
mod iptables;
#[cfg(target_os = "linux")]
mod nft;
#[cfg(target_os = "linux")]
mod route;
#[cfg(target_os = "linux")]
mod sysctl;

/// Comment tag used for every rule ant installs (iptables `-m comment`,
/// nft `comment "…"` in the host fw4/filter table). Mirrors nexa's `nexa` tag.
#[cfg(target_os = "linux")]
pub(crate) const COMMENT: &str = "ant-ip-auto-route";

/// Reserved IPv4 destinations that are never hijacked (nexa `proxy.reserved_ip`).
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub(crate) const DUMMY_DEVICE: &str = "ant-dummy";

/// Seconds to wait for the TUN device to come up (nexa `proxy.tun_timeout`).
#[cfg(target_os = "linux")]
pub(crate) const TUN_TIMEOUT: u32 = 30;

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
    /// Loop-prevention / anti-self mark: equals ant's SO_MARK (`global.mark`).
    pub mark: u32,
    pub bypass_ip: Vec<String>,
    pub bypass_ip6: Vec<String>,
    pub tproxy_mark: u32,
    pub tproxy_mask: u32,
    pub tun_mark: u32,
    pub tun_mask: u32,
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
    #[cfg(target_os = "linux")]
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
        let needs_tproxy = tcp_mode == Some(TcpMode::Tproxy) || udp_mode == Some(UdpMode::Tproxy);
        let needs_tun = tcp_mode == Some(TcpMode::Tun) || udp_mode == Some(UdpMode::Tun);

        // Distinct marks per mode → distinct route tables (nexa tproxy_fw_mark /
        // tun_fw_mark). tun uses mark+1 only when tproxy is active too, so a
        // single-mode setup keeps hijack mark == SO_MARK.
        let tproxy_mark = mark;
        let tproxy_mask = 0xffff_ffff;
        let tun_mark = if needs_tproxy && needs_tun {
            mark.wrapping_add(1)
        } else {
            mark
        };
        let tun_mask = 0xffff_ffff;

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
            mark,
            bypass_ip: RESERVED_IP4.iter().map(|s| s.to_string()).collect(),
            bypass_ip6: RESERVED_IP6.iter().map(|s| s.to_string()).collect(),
            tproxy_mark,
            tproxy_mask,
            tun_mark,
            tun_mask,
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

/// RAII guard: cleanup firewall + routes on drop.
pub struct Guard {
    #[cfg(target_os = "linux")]
    inner: Option<Params>,
}

/// Apply ip-auto-route. On failure, cleans partial state and returns Err.
pub async fn apply(cfg: &Config) -> Result<Guard> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        anyhow::bail!("ip-auto-route is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    {
        let params = Params::from_config(cfg)?;
        tracing::info!(
            tcp = ?params.tcp_mode,
            udp = ?params.udp_mode,
            tproxy_mark = format!("0x{:x}/0x{:x}", params.tproxy_mark, params.tproxy_mask),
            tun_mark = format!("0x{:x}/0x{:x}", params.tun_mark, params.tun_mask),
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
#[cfg(target_os = "linux")]
fn cleanup_all(p: &Params) {
    nft::cleanup();
    iptables::cleanup(p);
    fw_include::cleanup(p);
    route::cleanup(p);
    sysctl::restore();
}

#[cfg(target_os = "linux")]
impl Drop for Guard {
    fn drop(&mut self) {
        let Some(params) = self.inner.take() else {
            return;
        };
        tracing::info!("ip-auto-route: cleanup on drop");
        cleanup_all(&params);
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for Guard {
    fn drop(&mut self) {}
}
