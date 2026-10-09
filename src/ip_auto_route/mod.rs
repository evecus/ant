//! Linux system-wide transparent proxy control plane (`ip-auto-route`).
//!
//! - Prefer **nftables**, fall back to **iptables/ip6tables**
//! - Policy routing via **rtnetlink** (fwmark → table)
//! - Loop prevention via mark (shared with top-level `mark`)
//! - Full cleanup on stop or apply failure
//!
//! Only active on Linux.

use crate::config::Config;
use anyhow::Result;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod iptables;
#[cfg(target_os = "linux")]
mod nft;
#[cfg(target_os = "linux")]
mod route;

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
    pub lan_proxy: bool,
    pub lan_interface: Vec<String>,
    pub bypass_uid: Vec<u32>,
    pub bypass_gid: Vec<u32>,
    pub bypass_cgroup: Vec<String>,
    /// Shared bypass / policy mark (from global `mark`, default 255).
    pub mark: u32,
    pub mark_mask: u32,
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
    pub fn from_config(cfg: &Config) -> Self {
        let iar = &cfg.ip_auto_route;
        let mark = if cfg.global.mark != 0 {
            cfg.global.mark
        } else {
            255
        };
        let tcp_mode = iar.tcp_mode.as_deref().and_then(|s| {
            match s.trim().to_ascii_lowercase().as_str() {
                "redir" => Some(TcpMode::Redir),
                "tproxy" => Some(TcpMode::Tproxy),
                "tun" => Some(TcpMode::Tun),
                _ => None,
            }
        });
        let udp_mode = iar.udp_mode.as_deref().and_then(|s| {
            match s.trim().to_ascii_lowercase().as_str() {
                "tproxy" => Some(UdpMode::Tproxy),
                "tun" => Some(UdpMode::Tun),
                _ => None,
            }
        });
        let tun_device = cfg
            .tun
            .device
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "tun0".into());
        Self {
            ipv6: iar.ipv6 && cfg.global.ipv6,
            dns_hijack: iar.dns_hijack_to_port,
            dns_port: cfg.dns.listen_port(),
            fakeip_ping: iar.fakeip_ping_hijack,
            fakeip_v4: cfg.dns.fakeip_range.clone(),
            fakeip_v6: cfg.dns.fakeip6_range.clone(),
            tcp_mode,
            udp_mode,
            redir_port: cfg.global.redir_port.unwrap_or(0),
            tproxy_port: cfg.global.tproxy_port.unwrap_or(0),
            tun_device,
            lan_proxy: iar.lan_proxy,
            lan_interface: iar
                .lan_interface
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
            mark_mask: 0xff,
            tproxy_table: 80,
            tproxy_pref: 1024,
            tun_table: 81,
            tun_pref: 1025,
        }
    }

    pub fn needs_tproxy_route(&self) -> bool {
        self.tcp_mode == Some(TcpMode::Tproxy) || self.udp_mode == Some(UdpMode::Tproxy)
    }

    pub fn needs_tun_route(&self) -> bool {
        self.tcp_mode == Some(TcpMode::Tun) || self.udp_mode == Some(UdpMode::Tun)
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
        let params = Params::from_config(cfg);
        tracing::info!(
            tcp = ?params.tcp_mode,
            udp = ?params.udp_mode,
            mark = params.mark,
            lan = params.lan_proxy,
            "ip-auto-route: applying"
        );

        if let Err(e) = route::install(&params).await {
            let _ = route::cleanup(&params).await;
            return Err(e.context("ip-auto-route: policy routing"));
        }

        let backend = backend::detect();
        tracing::info!(?backend, "ip-auto-route: firewall backend");
        let fw = match backend {
            backend::Backend::Nftables => nft::apply(&params),
            backend::Backend::Iptables => iptables::apply(&params),
            backend::Backend::None => Err(anyhow::anyhow!(
                "neither nftables nor iptables is available"
            )),
        };

        if let Err(e) = fw {
            match backend {
                backend::Backend::Nftables => nft::cleanup(),
                backend::Backend::Iptables => iptables::cleanup(&params),
                backend::Backend::None => {}
            }
            let _ = route::cleanup(&params).await;
            return Err(e.context("ip-auto-route: firewall rules"));
        }

        Ok(Guard {
            inner: Some(params),
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for Guard {
    fn drop(&mut self) {
        let Some(params) = self.inner.take() else {
            return;
        };
        tracing::info!("ip-auto-route: cleanup on drop");
        nft::cleanup();
        iptables::cleanup(&params);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let p = params.clone();
            handle.spawn(async move {
                let _ = route::cleanup(&p).await;
            });
            // Give the task a brief chance; main also sleeps on shutdown.
        } else {
            route::cleanup_sync(&params);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for Guard {
    fn drop(&mut self) {}
}
