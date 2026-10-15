//! Configuration for the Linux-only eBPF datapath (`ebpf:` YAML section).
//!
//! The datapath is a **stand-alone control plane**: when `ebpf.enabled` is
//! set, `ip-auto-route.enable` must be off (config validation rejects both
//! at once). It owns its own nft table (`ant-ebpf`), its own policy-routing
//! table (82 / pref 1026) and its own interface attach logic — nothing is
//! shared with `ip_auto_route`.
//!
//! ## Roles (honk's four-role layout)
//!
//! | program            | attached to     | job                                            |
//! |--------------------|-----------------|------------------------------------------------|
//! | `lan_ingress_l*`   | LAN ingress     | classify client (forwarded) traffic            |
//! | `lan_egress_l*`    | LAN egress      | reply-path accounting for LAN-hijacked flows   |
//! | `wan_ingress_l*`   | WAN ingress     | reply-path accounting for local-hijacked flows |
//! | `wan_egress_l*`    | WAN egress      | take over locally-generated traffic            |
//!
//! Single-homed setups (LAN and WAN share one interface) attach
//! `lan_ingress` + `wan_egress` only, exactly like honk.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EbpfConfig {
    /// Enable the eBPF datapath. Linux only, needs `CAP_BPF` + `CAP_NET_ADMIN`,
    /// a kernel with BTF (`/sys/kernel/btf/vmlinux`) and >= 5.10 (the
    /// `wan_egress` role reads `__sk_buff.ingress_ifindex`, added in 5.10).
    ///
    /// Mutually exclusive with `ip-auto-route.enable`.
    pub enabled: bool,

    /// Client-facing (LAN) interfaces.
    ///
    /// Empty = auto-discover: every non-loopback interface that is up and
    /// not listed in (or discovered as) a WAN interface.
    #[serde(rename = "lan-interfaces")]
    pub lan_interfaces: Vec<String>,

    /// Upstream-facing (WAN) interfaces.
    ///
    /// Empty = auto-discover from the default route. At least one is
    /// required for the `wan_egress` role (locally-generated traffic
    /// takeover); when none can be found the WAN roles are skipped with a
    /// warning and only the LAN half of the datapath runs.
    #[serde(rename = "wan-interfaces")]
    pub wan_interfaces: Vec<String>,

    /// Hijack DNS (tcp/udp :53) to ant's DNS listener inside the datapath's
    /// own nft table — LAN clients and locally-generated queries alike.
    /// The TC programs deliberately pass :53 through so this rule owns it.
    #[serde(rename = "dns-hijack")]
    pub dns_hijack: bool,

    /// Attach the cgroup `sock` hooks that map socket cookies to PID /
    /// process names (observability only).
    pub cgroup: bool,

    /// cgroup v2 path to attach to. `None` = auto-detect from
    /// `/proc/self/mounts`.
    #[serde(rename = "cgroup-path")]
    pub cgroup_path: Option<String>,

    /// Seconds between interface rescans (hot-plugged NICs). `0` disables
    /// the rescan.
    #[serde(rename = "interface-rescan-secs")]
    pub interface_rescan_secs: u64,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lan_interfaces: Vec::new(),
            wan_interfaces: Vec::new(),
            dns_hijack: true,
            cgroup: true,
            cgroup_path: None,
            interface_rescan_secs: 30,
        }
    }
}

impl EbpfConfig {
    /// Normalize and reject nonsensical values. Called from
    /// `Config::validate` so bad input fails at startup, not at attach time.
    pub fn validate(&mut self) -> anyhow::Result<()> {
        for field in [
            (&mut self.lan_interfaces, "ebpf.lan-interfaces"),
            (&mut self.wan_interfaces, "ebpf.wan-interfaces"),
        ] {
            let (list, name) = field;
            for iface in list.iter_mut() {
                *iface = iface.trim().to_string();
                if iface.is_empty() {
                    anyhow::bail!("{name} contains an empty interface name");
                }
                if iface.len() > 15 {
                    anyhow::bail!("{name}: `{iface}` is longer than IFNAMSIZ (15)");
                }
            }
        }
        Ok(())
    }
}
