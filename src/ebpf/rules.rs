//! Routing verdicts + eBPF map writers (userspace side).
//!
//! The kernel only understands three concrete surfaces: CIDR (LPM), ports and
//! per-IP verdicts published from DNS (`DOMAIN_ROUTE`). Domain *strings* are
//! matched by ant's own `Router` in the DNS/relay path; the resulting verdict
//! is published per answered IP here. Following the upstream design where the
//! eBPF program never inspects domain names.
//!
//! SIGHUP hot-reload is intentionally not ported:
//! static CIDR/port tables are written once at startup. Domain verdicts stay
//! live via `publish_domain_ip`.

use anyhow::{Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, MapData, PerCpuArray};
use ant_ebpf_common::{
    DomainRouteEntry, FlowKey, RouteEntry, StatsCounters, TrackEntry, VERDICT_BLOCK,
    VERDICT_DIRECT, VERDICT_NODE_BASE,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Routing decision for a surface. `Direct`/`Block` are resolved entirely in
/// the kernel; `Node(i)` sends the flow into userspace, where `i` indexes the
/// node-name list shared with the kernel verdict encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Direct,
    Block,
    /// Userspace, no node chosen (DNS hijack); userspace picks the default.
    Proxy,
    Node(u8),
}

impl Verdict {
    /// Parse "direct" | "block" | a node name (`nodes` = configured names in
    /// order). Reserved names follow ant's `Outbound::from_str` semantics.
    pub fn parse(s: &str, nodes: &[String]) -> Result<Verdict> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("direct") {
            return Ok(Verdict::Direct);
        }
        if s.eq_ignore_ascii_case("block") || s.eq_ignore_ascii_case("reject") {
            return Ok(Verdict::Block);
        }
        match nodes.iter().position(|n| n == s) {
            Some(i) => Ok(Verdict::Node(i as u8)),
            None => anyhow::bail!("unknown verdict or node: {s}"),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Verdict::Direct => VERDICT_DIRECT,
            Verdict::Block => VERDICT_BLOCK,
            Verdict::Proxy => ant_ebpf_common::VERDICT_PROXY,
            Verdict::Node(i) => VERDICT_NODE_BASE + i,
        }
    }

    /// Inverse of [`Verdict::to_u8`]. `None` for 0 and for the bare
    /// "userspace, no node" verdict (DNS hijack).
    #[allow(dead_code)]
    pub fn from_u8(v: u8) -> Option<Verdict> {
        match v {
            VERDICT_DIRECT => Some(Verdict::Direct),
            VERDICT_BLOCK => Some(Verdict::Block),
            v if v >= VERDICT_NODE_BASE => Some(Verdict::Node(v - VERDICT_NODE_BASE)),
            _ => None,
        }
    }
}

/// All maps the control plane drives. Mirrors the upstream `StaticMaps` minus the
/// two-generation reload bookkeeping (no SIGHUP reload in this port).
pub struct StaticMaps {
    pub domain_route: HashMap<MapData, [u8; 16], DomainRouteEntry>,
    #[allow(dead_code)]
    pub port_route: HashMap<MapData, u16, RouteEntry>,
    /// cgroup v2 id -> CGROUP_MODE_BYPASS (kept fresh by `cgroup.rs`).
    pub cgroup_rules: HashMap<MapData, u64, u8>,
    /// Capture-time flow records; userspace reads the node verdict from it.
    pub flow_track: HashMap<MapData, FlowKey, TrackEntry>,
    pub cidr_v4: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 4], RouteEntry>,
    pub cidr_v6: aya::maps::lpm_trie::LpmTrie<MapData, [u8; 16], RouteEntry>,
    pub route_generation: HashMap<MapData, u32, u32>,
    pub datapath_stats: PerCpuArray<MapData, StatsCounters>,
}

impl StaticMaps {
    /// Private/link-local/multicast ranges go direct. Call before user CIDRs.
    pub fn add_private_direct(&mut self) -> Result<()> {
        for c in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "224.0.0.0/4",
            "fe80::/10",
            "fc00::/7",
            "ff00::/8",
        ] {
            self.insert_cidr(c, VERDICT_DIRECT)?;
        }
        Ok(())
    }

    /// This host's own addresses must never be captured by LAN ingress.
    pub fn add_local_direct(&mut self) -> Result<usize> {
        let out = std::process::Command::new("ip")
            .args(["-o", "addr", "show"])
            .output()
            .context("run `ip -o addr show`")?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut n = 0;
        for line in text.lines() {
            let mut it = line.split_whitespace();
            while let Some(tok) = it.next() {
                if tok == "inet" || tok == "inet6" {
                    if let Some(addr) = it.next().and_then(|a| a.split('/').next()) {
                        let cidr = if tok == "inet" {
                            format!("{addr}/32")
                        } else {
                            format!("{addr}/128")
                        };
                        if self.insert_cidr(&cidr, VERDICT_DIRECT).is_ok() {
                            n += 1;
                        }
                    }
                    break;
                }
            }
        }
        Ok(n)
    }

    /// The kernel verdict recorded when the datapath captured this flow.
    #[allow(dead_code)]
    pub fn flow_verdict(
        &self,
        client: std::net::SocketAddr,
        orig: std::net::SocketAddr,
        udp: bool,
    ) -> Option<Verdict> {
        let entry = self.flow_track.get(&flow_key(client, orig, udp), 0).ok()?;
        Verdict::from_u8(entry.verdict)
    }

    /// Add one CIDR with an explicit verdict (used for the fake-IP range and
    /// `bypass-ip` ruleset networks).
    pub fn add_cidr(&mut self, cidr: &str, verdict: Verdict) -> Result<()> {
        self.insert_cidr(cidr, verdict.to_u8())
    }

    fn insert_cidr(&mut self, value: &str, verdict: u8) -> Result<()> {
        // generation = 0 (wildcard): always live, no hot-reload in this port.
        let e = RouteEntry::new(verdict, 0);
        if let Ok((v4, plen)) = parse_v4_cidr(value) {
            self.cidr_v4
                .insert(&Key::new(plen as u32, v4.octets()), e, 0)?;
        } else if let Ok((v6, plen)) = parse_v6_cidr(value) {
            self.cidr_v6
                .insert(&Key::new(plen as u32, v6.octets()), e, 0)?;
        } else {
            anyhow::bail!("bad CIDR: {value}");
        }
        Ok(())
    }

    /// Insert a port with an explicit verdict.
    #[allow(dead_code)]
    pub fn add_port(&mut self, port: u16, verdict: Verdict) -> Result<()> {
        self.port_route
            .insert(port, RouteEntry::new(verdict.to_u8(), 0), 0)?;
        Ok(())
    }

    /// Publish one DNS-answered address with the verdict its domain resolves
    /// to. Called by the DNS path for every A/AAAA record.
    pub fn publish_domain_ip(&mut self, ip: IpAddr, verdict: Verdict) -> Result<()> {
        let key = v6_mapped(ip);
        let v = verdict.to_u8();
        if let Ok(old) = self.domain_route.get(&key, 0) {
            if old.verdict != v {
                self.bump_generation()?;
            }
        }
        let entry = DomainRouteEntry {
            verdict: v,
            _pad: [0; 7],
        };
        self.domain_route.insert(key, entry, 0)?;
        Ok(())
    }

    pub fn generation(&self) -> Result<u32> {
        Ok(self.route_generation.get(&0u32, 0).unwrap_or(0))
    }

    fn bump_generation(&mut self) -> Result<()> {
        let next = self.generation()?.wrapping_add(1).max(1);
        self.route_generation.insert(0u32, next, 0)?;
        Ok(())
    }
}

/// 16-byte address form used by the maps (IPv4 is v4-mapped).
pub fn v6_mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut k = [0u8; 16];
            k[10] = 0xff;
            k[11] = 0xff;
            k[12..16].copy_from_slice(&v4.octets());
            k
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Construct the FLOW_TRACK lookup key. Must match the kernel `Pkt::flow_key()`
/// byte-for-byte: ports are numeric values (`(wire_hi << 8) | wire_lo`), NOT
/// network byte order (the upstream implementation hit and fixed exactly this bug).
#[allow(dead_code)]
fn flow_key(client: std::net::SocketAddr, orig: std::net::SocketAddr, udp: bool) -> FlowKey {
    FlowKey {
        src_ip: v6_mapped(client.ip()),
        dst_ip: v6_mapped(orig.ip()),
        sport: client.port(),
        dport: orig.port(),
        proto: if udp {
            ant_ebpf_common::IPPROTO_UDP
        } else {
            ant_ebpf_common::IPPROTO_TCP
        },
        _pad: [0; 7],
    }
}

pub fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv4Addr::from_str(addr)?, plen.parse()?))
}

pub fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, plen) = s
        .split_once('/')
        .with_context(|| format!("bad CIDR: {s}"))?;
    Ok((Ipv6Addr::from_str(addr)?, plen.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_ports_are_numeric_values() {
        let client: std::net::SocketAddr = "10.0.0.2:54321".parse().unwrap();
        let orig: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let key = flow_key(client, orig, false);
        assert_eq!(key.sport, client.port());
        assert_eq!(key.dport, orig.port());
        assert_ne!(key.sport, client.port().to_be());
    }
}
