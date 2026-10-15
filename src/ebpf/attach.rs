//! TC attachment for the four-role datapath — a direct port of honk's
//! `attach.rs` layout, minus the `daens`/`dae0` pieces ant does not have.
//!
//! ## Role matrix (honk parity)
//!
//! | interface                     | ingress          | egress           |
//! |-------------------------------|------------------|------------------|
//! | LAN master                    | `lan_ingress_l*` | `lan_egress_l*`  |
//! | WAN master                    | `wan_ingress_l*` | `wan_egress_l*`  |
//! | LAN bridge slave              | `lan_ingress_l2` | `lan_egress_l2`  |
//! | LAN bond slave                | `lan_ingress_l*` | `wan_egress_l2`  |
//! | WAN bond slave                | —                | `wan_egress_l2`  |
//!
//! Single-homed setups (LAN and WAN share an interface) attach only
//! `lan_ingress` + `wan_egress`: `lan_egress` on the host's only outbound
//! interface would fight the host's own traffic, and `wan_ingress` would
//! duplicate the hook `lan_ingress` already owns.
//!
//! `l2` / `l3` follows the interface type: `ARPHRD_ETHER` carries a
//! 14-byte Ethernet header the program must skip, everything else (TUN,
//! WireGuard) starts at the IP header.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::{
    programs::{
        tc::{self, TcAttachType},
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier,
    },
    Ebpf,
};
use tracing::{debug, info, warn};

use super::loader::PnameMode;

/// Programs currently attached, deduplicated by `(ifindex, direction)` so a
/// rescan only fills gaps. Links stay owned by the `Ebpf` object — dropping
/// it detaches everything.
#[derive(Debug, Default, Clone)]
pub(super) struct AttachmentSet {
    hooks: Vec<(u32, bool)>,
    pub interfaces: Vec<String>,
    pub cgroup: Option<PathBuf>,
}

impl AttachmentSet {
    fn hooked(&self, ifindex: u32, is_egress: bool) -> bool {
        self.hooks
            .iter()
            .any(|(i, e)| *i == ifindex && *e == is_egress)
    }

    fn mark(&mut self, ifindex: u32, is_egress: bool, iface: &str) {
        if !self.interfaces.iter().any(|name| name == iface) {
            self.interfaces.push(iface.to_string());
        }
        if !self.hooked(ifindex, is_egress) {
            self.hooks.push((ifindex, is_egress));
        }
    }
}

/// Resolved interface plan for the role matrix.
pub(super) struct AttachPlan<'a> {
    /// Effective LAN masters (bridge master already resolved).
    pub lan_masters: &'a [String],
    /// Effective WAN masters (bridge master already resolved).
    pub wan_masters: &'a [String],
    /// LAN and WAN share at least one interface.
    pub single_homed: bool,
    /// Kernel >= 5.10 (`wan_egress` reads `__sk_buff.ingress_ifindex`).
    pub wan_egress_ok: bool,
}

/// Every non-loopback interface that reports carrier-up.
pub(super) fn discover_interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        // Skip down interfaces: they cannot carry the qdisc anyway.
        let operstate = std::fs::read_to_string(entry.path().join("operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !operstate.is_empty() && operstate != "up" && operstate != "unknown" {
            continue;
        }
        out.push(name);
    }
    out.sort();
    out
}

/// Interfaces owning an IPv4 (and, when `ipv6`, IPv6) default route.
///
/// `/proc/net/route` columns: `Iface Destination Gateway Flags …`; a default
/// route has an all-zero destination. `/proc/net/ipv6_route` columns:
/// `Destination DestLen … Device`; a default route has an all-zero
/// destination with prefix length `00`.
pub(super) fn discover_wan_interfaces(ipv6: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }
            let (iface, dest) = (fields[0], fields[1]);
            if dest.bytes().all(|b| b == b'0')
                && iface != "lo"
                && !out.iter().any(|name| name == iface)
            {
                out.push(iface.to_string());
            }
        }
    }

    if ipv6 {
        if let Ok(text) = std::fs::read_to_string("/proc/net/ipv6_route") {
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 11 {
                    continue;
                }
                let (dest, dest_len, iface) = (fields[0], fields[1], fields[10]);
                if dest.bytes().all(|b| b == b'0')
                    && dest_len == "00"
                    && iface != "lo"
                    && !out.iter().any(|name| name == iface)
                {
                    out.push(iface.to_string());
                }
            }
        }
    }

    out.sort();
    out
}

/// `ARPHRD_ETHER` — the L2 variants expect a 14-byte Ethernet header.
fn is_ethernet(iface: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/type"))
        .map(|t| t.trim() == "1")
        .unwrap_or(true)
}

/// Bridge master of `iface` when it is a bridge slave (honk's
/// `bridge_interface`): forwarded L2 traffic never traverses the slave's
/// own TC hooks on a master that already has them, and honk attaches the
/// LAN pair to the master plus every slave.
pub(super) fn bridge_master(iface: &str) -> Option<String> {
    let master_link = format!("/sys/class/net/{iface}/master");
    std::fs::read_link(&master_link)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Bridge slaves of `iface` (empty unless it is a bridge master).
fn bridge_slaves(iface: &str) -> Vec<String> {
    let path = format!("/sys/class/net/{iface}/brif");
    let Ok(entries) = std::fs::read_dir(&path) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// Bond slaves of `iface` (empty unless it is a bond master).
fn bond_slaves(iface: &str) -> Vec<String> {
    let path = format!("/sys/class/net/{iface}/bonding/slaves");
    std::fs::read_to_string(&path)
        .map(|s| {
            s.split_whitespace()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Primary IPv4 address of `iface` as the BPF side stores it: the raw
/// little-endian word of the address octets [a,b,c,d] — the same value
/// `dip.u6_addr32[3]` holds when the program compares a packet destination
/// against `param.local_ip` (honk: `u32::from_ne_bytes(octets)`).
pub(super) fn iface_ipv4(iface: &str) -> Option<u32> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let result = (|| {
            let mut ifa = ifap;
            while !ifa.is_null() {
                let name = CStr::from_ptr((*ifa).ifa_name).to_string_lossy();
                if name == iface {
                    let addr = (*ifa).ifa_addr;
                    if !addr.is_null() && (*addr).sa_family as i32 == libc::AF_INET {
                        let sock = &*(addr as *const libc::sockaddr_in);
                        // `s_addr` is network order; its native-endian byte
                        // image is [a,b,c,d], and the BPF side compares the
                        // LE interpretation of exactly those bytes.
                        return Some(u32::from_le_bytes(sock.sin_addr.s_addr.to_ne_bytes()));
                    }
                }
                ifa = (*ifa).ifa_next;
            }
            None
        })();
        libc::freeifaddrs(ifap);
        result
    }
}

fn ifindex_of(iface: &str) -> u32 {
    let Ok(c) = CString::new(iface) else {
        return 0;
    };
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// Ethernet interfaces, including bridge masters, use L2; others use L3.
fn lan_program_pair(iface: &str) -> (&'static str, &'static str) {
    if is_ethernet(iface) {
        ("lan_ingress_l2", "lan_egress_l2")
    } else {
        ("lan_ingress_l3", "lan_egress_l3")
    }
}

/// Same judgment for the WAN roles.
fn wan_program_pair(iface: &str) -> (&'static str, &'static str) {
    if is_ethernet(iface) {
        ("wan_ingress_l2", "wan_egress_l2")
    } else {
        ("wan_ingress_l3", "wan_egress_l3")
    }
}

/// Attach the full role matrix. Any *attach* failure aborts (a half-covered
/// interface silently leaves its traffic outside the proxy); only the
/// clsact qdisc EEXIST case is tolerated, since another agent (or a
/// previous ant run) may own it.
pub(super) fn attach_roles(
    bpf: &mut Ebpf,
    plan: &AttachPlan<'_>,
    attached: &mut AttachmentSet,
) -> Result<()> {
    // ── LAN masters ───────────────────────────────────────────────────
    for master in plan.lan_masters {
        let (ingress_prog, egress_prog) = lan_program_pair(master);
        attach_one(bpf, ingress_prog, master, TcAttachType::Ingress, attached)
            .map_err(|e| anyhow::anyhow!("attach {ingress_prog} to LAN {master}: {e}"))?;
        if plan.single_homed {
            info!("ebpf: single-homed setup; lan_egress skipped on {master}");
        } else {
            attach_one(bpf, egress_prog, master, TcAttachType::Egress, attached)
                .map_err(|e| anyhow::anyhow!("attach {egress_prog} to LAN {master}: {e}"))?;
        }
    }

    // ── WAN masters ───────────────────────────────────────────────────
    for master in plan.wan_masters {
        if !plan.wan_egress_ok {
            warn!(
                "ebpf: kernel < 5.10 — wan_egress/wan_ingress skipped on {master} \
                 (locally-generated traffic stays unproxied)"
            );
            continue;
        }
        let (ingress_prog, egress_prog) = wan_program_pair(master);
        attach_one(bpf, egress_prog, master, TcAttachType::Egress, attached)
            .map_err(|e| anyhow::anyhow!("attach {egress_prog} to WAN {master}: {e}"))?;
        if plan.single_homed {
            info!("ebpf: single-homed setup; wan_ingress skipped on {master}");
        } else {
            attach_one(bpf, ingress_prog, master, TcAttachType::Ingress, attached)
                .map_err(|e| anyhow::anyhow!("attach {ingress_prog} to WAN {master}: {e}"))?;
        }
    }

    // ── LAN bridge slaves: the LAN pair ───────────────────────────────
    for master in plan.lan_masters {
        for slave in bridge_slaves(master) {
            let slave_prog = lan_program_pair(&slave).0;
            attach_one(bpf, slave_prog, &slave, TcAttachType::Ingress, attached)
                .map_err(|e| anyhow::anyhow!("attach {slave_prog} to bridge slave {slave}: {e}"))?;
            attach_one(bpf, "lan_egress_l2", &slave, TcAttachType::Egress, attached).map_err(
                |e| anyhow::anyhow!("attach lan_egress_l2 to bridge slave {slave}: {e}"),
            )?;
            info!("ebpf: LAN pair attached to bridge slave {slave}");
        }
    }

    // ── LAN bond slaves: lan_ingress + wan_egress ─────────────────────
    // The bond driver builds the Ethernet header before the slave's egress
    // hook, so locally-generated traffic is visible there — that is why
    // the egress role on a bond slave is `wan_egress`, not `lan_egress`.
    let mut wan_egress_slaves: Vec<String> = Vec::new();
    for master in plan.lan_masters {
        for slave in bond_slaves(master) {
            if !plan.wan_egress_ok {
                break;
            }
            let slave_prog = lan_program_pair(&slave).0;
            attach_one(bpf, slave_prog, &slave, TcAttachType::Ingress, attached)
                .map_err(|e| anyhow::anyhow!("attach {slave_prog} to bond slave {slave}: {e}"))?;
            info!("ebpf: lan_ingress attached to bond slave {slave}");
            wan_egress_slaves.push(slave);
        }
    }

    // ── WAN bond slaves (plus the LAN ones from above) ────────────────
    if plan.wan_egress_ok {
        for master in plan.wan_masters {
            for slave in bond_slaves(master) {
                if !wan_egress_slaves.contains(&slave) {
                    wan_egress_slaves.push(slave);
                }
            }
        }
    }
    if !wan_egress_slaves.is_empty() {
        info!(
            "ebpf: attaching wan_egress to bond slaves {:?}",
            wan_egress_slaves
        );
        for slave in &wan_egress_slaves {
            attach_one(bpf, "wan_egress_l2", slave, TcAttachType::Egress, attached)
                .map_err(|e| anyhow::anyhow!("attach wan_egress_l2 to bond slave {slave}: {e}"))?;
        }
    }

    Ok(())
}

/// Attach one program, skipping a hook this run already owns.
fn attach_one(
    bpf: &mut Ebpf,
    program: &str,
    iface: &str,
    direction: TcAttachType,
    attached: &mut AttachmentSet,
) -> Result<()> {
    let ifindex = ifindex_of(iface);
    let is_egress = matches!(direction, TcAttachType::Egress);
    if attached.hooked(ifindex, is_egress) {
        return Ok(());
    }

    if let Err(e) = tc::qdisc_add_clsact(iface) {
        // EEXIST is expected when ant restarts or another agent is present.
        debug!("ebpf: clsact qdisc on {iface}: {e}");
    }

    let prog: &mut SchedClassifier = bpf
        .program_mut(program)
        .with_context(|| format!("program `{program}` missing from eBPF object"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("`{program}` is not a SchedClassifier"))?;
    match prog.load() {
        Ok(()) => {}
        // Re-attaching to another interface reuses the loaded program.
        Err(aya::programs::ProgramError::AlreadyLoaded) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("load {program}: {e}"))
                .with_context(|| format!("load {program} (verifier rejection?)"));
        }
    }
    prog.attach(iface, direction)
        .with_context(|| format!("attach {program} to {iface}"))?;

    attached.mark(ifindex, is_egress, iface);
    debug!("ebpf: {program} attached to {iface} ({direction:?})");
    Ok(())
}

/// Attach the cookie → PID cgroup hooks to `path` (a cgroup v2 directory).
pub(super) fn attach_cgroup(
    bpf: &mut Ebpf,
    path: &Path,
    mode: PnameMode,
    attached: &mut AttachmentSet,
) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open cgroup dir {}", path.display()))?;
    let suffix = match mode {
        PnameMode::Argv0 => "",
        PnameMode::Comm => "_comm",
    };

    // sock_create / sock_release (SockContext) …
    for name in [
        format!("tproxy_cg_sock_create{suffix}"),
        "tproxy_cg_sock_release".to_string(),
    ] {
        let prog: &mut CgroupSock = bpf
            .program_mut(&name)
            .with_context(|| format!("program `{name}` missing"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("`{name}` is not a CgroupSock"))?;
        prog.load().with_context(|| format!("load {name}"))?;
        prog.attach(&file, CgroupAttachMode::Single)
            .with_context(|| format!("attach {name} to {}", path.display()))?;
    }

    // … and connect/sendmsg (SockAddrContext).
    for name in [
        format!("tproxy_cg_connect4{suffix}"),
        format!("tproxy_cg_connect6{suffix}"),
        format!("tproxy_cg_sendmsg4{suffix}"),
        format!("tproxy_cg_sendmsg6{suffix}"),
    ] {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(&name)
            .with_context(|| format!("program `{name}` missing"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("`{name}` is not a CgroupSockAddr"))?;
        prog.load().with_context(|| format!("load {name}"))?;
        prog.attach(&file, CgroupAttachMode::Single)
            .with_context(|| format!("attach {name} to {}", path.display()))?;
    }

    attached.cgroup = Some(path.to_path_buf());
    Ok(())
}
