//! iptables / ip6tables fallback, aligned with **nexa**
//! `internal/netmanager/iptables.go`.
//!
//! Three things this backend cannot do 1:1 with the nft template (the same
//! limitations nexa documents):
//!
//! 1. **`TPROXY` cannot be attached to `OUTPUT`.** The kernel's TPROXY target
//!    only hooks PREROUTING. For locally-generated traffic we therefore *set the
//!    fwmark* and reuse the policy routing installed by `route.rs` — exactly
//!    what the nft `router_tproxy` chain does. LAN traffic (PREROUTING) uses the
//!    real `TPROXY` target when `xt_TPROXY` is present and degrades to MARK +
//!    policy routing when it is not.
//! 2. **No `socket cgroupv2` equivalent.** `-m cgroup --path` is probed and only
//!    emitted when the match is actually compiled in.
//! 3. **No `fib daddr type` match**; destination filtering relies on the
//!    reserved/China CIDR sets and `-m conntrack --ctdir REPLY`.
//!
//! Deviations from nexa, all of which fix real breakage:
//!
//! - **Bypass rules live in the same chain as the action rules.** nexa mounts
//!   `-j NEXA_BYPASS_R` and `-j NEXA_TPROXY_R` as two separate jumps from
//!   `OUTPUT`; but `-j RETURN` inside a user-defined chain resumes at the *next
//!   rule of the calling chain*, i.e. the second jump — so every bypass rule in
//!   nexa is dead code and all traffic gets hijacked. Merging them makes
//!   `RETURN` actually skip the action.
//! - **Argument order.** nexa emits `-j REDIRECT -m comment --comment nexa`;
//!   iptables requires matches before the target, so those rules are always
//!   rejected. Here `-m comment --comment …` precedes `-j`.
//! - **`dport 53` exclusion inside the mark chains.** mangle OUTPUT runs before
//!   nat OUTPUT, so without it DNS gets marked and routed to the tproxy port
//!   instead of being redirected (the nft template has this rule; nexa's
//!   iptables path does not).
//! - **Per-protocol chain membership.** nexa always marks both tcp and udp;
//!   with `tcp-mode: tproxy` + `udp-mode: tun` that applies the wrong mark to
//!   UDP. Here each protocol only joins the chain its mode selects.

use super::{Params, TcpMode, UdpMode, COMMENT};
use anyhow::Result;
use std::cell::RefCell;
use std::collections::HashMap;
use std::process::Command;
use tracing::{info, warn};

/// (table, chain) pairs created by `apply` — `cleanup` removes them symmetrically.
const CHAINS: &[(&str, &str)] = &[
    ("nat", "ANT_NAT_OUT"),
    ("nat", "ANT_NAT_LAN"),
    ("mangle", "ANT_MANGLE_OUT"),
    ("mangle", "ANT_MANGLE_LAN"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Locally generated traffic — uid/gid/cgroup matches available.
    Router,
    /// Forwarded traffic from LAN — only src IP / MAC / mark / dst.
    Lan,
}

/// Thin wrapper: `enabled` mirrors the per-family availability decided after
/// capability probing, so unsupported families are never touched.
struct W {
    bin: &'static str,
    enabled: bool,
}

impl W {
    fn run(&self, args: &[&str]) {
        if !self.enabled {
            return;
        }
        let _ = Command::new(self.bin).args(args).output();
    }
}

/// Capability probe cache (nexa `matchSupportCache`): `-m <mod> -h` /
/// `-j <target> -h` output is grepped for the flag we need, instead of
/// guessing from versions. Refreshed on every `apply`.
struct Caps {
    map: RefCell<HashMap<String, bool>>,
}

impl Caps {
    fn new() -> Self {
        Self {
            map: RefCell::new(HashMap::new()),
        }
    }
    fn probe(&self, key: String, args: &[&str], flag: &str) -> bool {
        if let Some(v) = self.map.borrow().get(&key) {
            return *v;
        }
        let supported = match Command::new(args[0]).args(&args[1..]).output() {
            Ok(o) => {
                let mut buf = String::from_utf8_lossy(&o.stdout).into_owned();
                buf.push_str(&String::from_utf8_lossy(&o.stderr));
                buf.contains(flag)
            }
            Err(_) => false,
        };
        self.map.borrow_mut().insert(key, supported);
        supported
    }
    fn supports_match(&self, bin: &str, module: &str, flag: &str) -> bool {
        let key = format!("{bin}|m|{module}|{flag}");
        self.probe(key, &[bin, "-m", module, "-h"], flag)
    }
    fn supports_target(&self, bin: &str, target: &str, flag: &str) -> bool {
        let key = format!("{bin}|j|{target}|{flag}");
        self.probe(key, &[bin, "-j", target, "-h"], flag)
    }
}

pub fn apply(p: &Params) -> Result<()> {
    cleanup(p);
    if !has_cmd("iptables") && !has_cmd("ip6tables") {
        anyhow::bail!("neither iptables nor ip6tables is available");
    }

    let caps = Caps::new();
    let tproxy = p.needs_tproxy();
    let tun = p.needs_tun();
    let redir = p.needs_redir();
    let mark_dependent = tproxy || tun;

    // Capability probing (nexa ShellCrash-style): never emit a rule we know the
    // kernel/iptables cannot accept.
    if mark_dependent {
        let _ = Command::new("modprobe").arg("xt_MARK").output();
    }
    if tproxy {
        let _ = Command::new("modprobe").arg("xt_TPROXY").output();
    }
    let mark4 = caps.supports_target("iptables", "MARK", "--set-mark");
    let mark6 = caps.supports_target("ip6tables", "MARK", "--set-mark");
    let redirect6 = caps.supports_target("ip6tables", "REDIRECT", "--to-ports");
    let tproxy_target4 = tproxy && caps.supports_target("iptables", "TPROXY", "--on-port");
    let tproxy_target6 = tproxy && caps.supports_target("ip6tables", "TPROXY", "--on-port");
    if mark_dependent && !mark4 {
        warn!("ip-auto-route: iptables MARK target unavailable; IPv4 hijack disabled");
    }
    if mark_dependent && p.ipv6 && !mark6 {
        warn!("ip-auto-route: ip6tables MARK target unavailable; IPv6 hijack disabled");
    }
    if redir && p.ipv6 && !redirect6 {
        warn!("ip-auto-route: ip6tables REDIRECT --to-ports unavailable; IPv6 redirect disabled");
    }
    if tproxy && p.tproxy_port > 0 && !tproxy_target4 && !tproxy_target6 {
        warn!(
            "ip-auto-route: no xt_TPROXY support; LAN tproxy falls back to MARK + policy routing"
        );
    }

    let ipv4_proxy = !mark_dependent || mark4;
    let ipv6_proxy = p.ipv6 && (!mark_dependent || mark6) && (!redir || redirect6);
    let ipv4_dns = true;
    let ipv6_dns = p.ipv6;

    let ipt = W {
        bin: "iptables",
        enabled: ipv4_proxy || ipv4_dns,
    };
    let ip6t = W {
        bin: "ip6tables",
        enabled: ipv6_proxy || ipv6_dns,
    };

    // ── nat OUTPUT (local): DNS hijack + TCP redirect ─────────────────────
    let dns_hijack = p.dns_hijack && p.dns_port > 0;
    let dns_port = p.dns_port.to_string();
    let redir_port = p.redir_port.to_string();
    let tproxy_port = p.tproxy_port.to_string();
    let tproxy_mark = p.tproxy_mark.to_string();
    let tun_mark = p.tun_mark.to_string();

    if p.router_proxy {
        for (table, chain) in [("nat", "ANT_NAT_OUT"), ("mangle", "ANT_MANGLE_OUT")] {
            ipt.run(&["-t", table, "-N", chain]);
            ip6t.run(&["-t", table, "-N", chain]);
        }
        for (w, on, v4) in [
            (&ipt, ipv4_proxy || ipv4_dns, true),
            (&ip6t, ipv6_proxy || ipv6_dns, false),
        ] {
            if !on || !w.enabled {
                continue;
            }
            let table_nat = "nat";
            let table_mangle = "mangle";
            // nat OUTPUT: identity → mark → DNS hijack → [redirect]
            build_bypass(
                w,
                &caps,
                (table_nat, "ANT_NAT_OUT"),
                p,
                Scope::Router,
            );
            if dns_hijack {
                for proto in ["tcp", "udp"] {
                    w.run(&[
                        "-t",
                        table_nat,
                        "-A",
                        "ANT_NAT_OUT",
                        "-p",
                        proto,
                        "--dport",
                        "53",
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        &dns_port,
                    ]);
                }
            }
            if redir && p.redir_port > 0 {
                build_dest_bypass(
                    w,
                    &caps,
                    (table_nat, "ANT_NAT_OUT"),
                    p,
                    Scope::Router,
                    v4,
                );
                w.run(&[
                    "-t",
                    table_nat,
                    "-A",
                    "ANT_NAT_OUT",
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &redir_port,
                ]);
            }
            // mangle OUTPUT: identity → mark → ct reply → dest → dns skip → mark
            if tproxy || tun {
                build_bypass(
                    w,
                    &caps,
                    (table_mangle, "ANT_MANGLE_OUT"),
                    p,
                    Scope::Router,
                );
                build_dest_bypass(
                    w,
                    &caps,
                    (table_mangle, "ANT_MANGLE_OUT"),
                    p,
                    Scope::Router,
                    v4,
                );
                if dns_hijack {
                    for proto in ["tcp", "udp"] {
                        w.run(&[
                            "-t",
                            table_mangle,
                            "-A",
                            "ANT_MANGLE_OUT",
                            "-p",
                            proto,
                            "--dport",
                            "53",
                            "-j",
                            "RETURN",
                        ]);
                    }
                }
                for proto in ["tcp", "udp"] {
                    let is_tproxy = if proto == "tcp" {
                        p.tcp_mode == Some(TcpMode::Tproxy)
                    } else {
                        p.udp_mode == Some(UdpMode::Tproxy)
                    };
                    let is_tun = if proto == "tcp" {
                        p.tcp_mode == Some(TcpMode::Tun)
                    } else {
                        p.udp_mode == Some(UdpMode::Tun)
                    };
                    if is_tproxy {
                        w.run(&[
                            "-t",
                            table_mangle,
                            "-A",
                            "ANT_MANGLE_OUT",
                            "-p",
                            proto,
                            "-j",
                            "MARK",
                            "--set-mark",
                            &tproxy_mark,
                        ]);
                    } else if is_tun {
                        w.run(&[
                            "-t",
                            table_mangle,
                            "-A",
                            "ANT_MANGLE_OUT",
                            "-p",
                            proto,
                            "-j",
                            "MARK",
                            "--set-mark",
                            &tun_mark,
                        ]);
                    }
                }
            }
        }
        // Mount points (OUTPUT).
        for (w, table, chain, on) in [
            (&ipt, "nat", "ANT_NAT_OUT", ipv4_proxy || ipv4_dns),
            (&ip6t, "nat", "ANT_NAT_OUT", ipv6_proxy || ipv6_dns),
            (&ipt, "mangle", "ANT_MANGLE_OUT", ipv4_proxy),
            (&ip6t, "mangle", "ANT_MANGLE_OUT", ipv6_proxy),
        ] {
            if !on || !w.enabled {
                continue;
            }
            if table == "nat" && !dns_hijack && !(redir && p.redir_port > 0) {
                continue;
            }
            if table == "mangle" && !(tproxy || tun) {
                continue;
            }
            w.run(&["-t", table, "-A", "OUTPUT", "-j", chain]);
        }
    }

    // ── LAN: nat/mangle PREROUTING ───────────────────────────────────────
    if p.lan_proxy {
        for (table, chain) in [("nat", "ANT_NAT_LAN"), ("mangle", "ANT_MANGLE_LAN")] {
            ipt.run(&["-t", table, "-N", chain]);
            ip6t.run(&["-t", table, "-N", chain]);
        }
        for (w, on, v4, use_tproxy) in [
            (&ipt, ipv4_proxy || ipv4_dns, true, tproxy_target4),
            (&ip6t, ipv6_proxy || ipv6_dns, false, tproxy_target6),
        ] {
            if !on || !w.enabled {
                continue;
            }
            build_bypass(
                w,
                &caps,
                ("nat", "ANT_NAT_LAN"),
                p,
                Scope::Lan,
            );
            if dns_hijack {
                for proto in ["tcp", "udp"] {
                    w.run(&[
                        "-t",
                        "nat",
                        "-A",
                        "ANT_NAT_LAN",
                        "-p",
                        proto,
                        "--dport",
                        "53",
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        &dns_port,
                    ]);
                }
            }
            if redir && p.redir_port > 0 {
                build_dest_bypass(
                    w,
                    &caps,
                    ("nat", "ANT_NAT_LAN"),
                    p,
                    Scope::Lan,
                    v4,
                );
                w.run(&[
                    "-t",
                    "nat",
                    "-A",
                    "ANT_NAT_LAN",
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &redir_port,
                ]);
            }
            if tproxy || tun {
                build_bypass(w, &caps, ("mangle", "ANT_MANGLE_LAN"), p, Scope::Lan);
                build_dest_bypass(
                    w,
                    &caps,
                    ("mangle", "ANT_MANGLE_LAN"),
                    p,
                    Scope::Lan,
                    v4,
                );
                if dns_hijack {
                    for proto in ["tcp", "udp"] {
                        w.run(&[
                            "-t",
                            "mangle",
                            "-A",
                            "ANT_MANGLE_LAN",
                            "-p",
                            proto,
                            "--dport",
                            "53",
                            "-j",
                            "RETURN",
                        ]);
                    }
                }
                for proto in ["tcp", "udp"] {
                    let is_tproxy = if proto == "tcp" {
                        p.tcp_mode == Some(TcpMode::Tproxy)
                    } else {
                        p.udp_mode == Some(UdpMode::Tproxy)
                    };
                    let is_tun = if proto == "tcp" {
                        p.tcp_mode == Some(TcpMode::Tun)
                    } else {
                        p.udp_mode == Some(UdpMode::Tun)
                    };
                    if is_tproxy && p.tproxy_port > 0 {
                        if use_tproxy {
                            w.run(&[
                                "-t",
                                "mangle",
                                "-A",
                                "ANT_MANGLE_LAN",
                                "-p",
                                proto,
                                "-j",
                                "TPROXY",
                                "--tproxy-mark",
                                &tproxy_mark,
                                "--on-port",
                                &tproxy_port,
                            ]);
                        } else {
                            w.run(&[
                                "-t",
                                "mangle",
                                "-A",
                                "ANT_MANGLE_LAN",
                                "-p",
                                proto,
                                "-j",
                                "MARK",
                                "--set-mark",
                                &tproxy_mark,
                            ]);
                        }
                    } else if is_tun {
                        w.run(&[
                            "-t",
                            "mangle",
                            "-A",
                            "ANT_MANGLE_LAN",
                            "-p",
                            proto,
                            "-j",
                            "MARK",
                            "--set-mark",
                            &tun_mark,
                        ]);
                    }
                }
            }
        }
        for dev in &p.lan_interface {
            for (w, table, chain, on) in [
                (&ipt, "nat", "ANT_NAT_LAN", ipv4_proxy || ipv4_dns),
                (&ip6t, "nat", "ANT_NAT_LAN", ipv6_proxy || ipv6_dns),
                (&ipt, "mangle", "ANT_MANGLE_LAN", ipv4_proxy),
                (&ip6t, "mangle", "ANT_MANGLE_LAN", ipv6_proxy),
            ] {
                if !on || !w.enabled {
                    continue;
                }
                if table == "nat" && !dns_hijack && !(redir && p.redir_port > 0) {
                    continue;
                }
                if table == "mangle" && !(tproxy || tun) {
                    continue;
                }
                w.run(&["-t", table, "-A", "PREROUTING", "-i", dev, "-j", chain]);
            }
        }
    }

    // ── TUN passthrough in the host filter table ─────────────────────────
    if tun && !p.tun_device.is_empty() {
        let dev = p.tun_device.as_str();
        for w in [&ipt, &ip6t] {
            if !w.enabled {
                continue;
            }
            w.run(&[
                "-t",
                "filter",
                "-I",
                "INPUT",
                "-i",
                dev,
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                "ACCEPT",
            ]);
            w.run(&[
                "-t",
                "filter",
                "-I",
                "FORWARD",
                "-o",
                dev,
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                "ACCEPT",
            ]);
            w.run(&[
                "-t",
                "filter",
                "-I",
                "FORWARD",
                "-i",
                dev,
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                "ACCEPT",
            ]);
        }
    }

    // ── fake-ip ping hijack ──────────────────────────────────────────────
    if p.fakeip_ping {
        if let Some(ref r) = p.fakeip_v4 {
            ipt.run(&[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "icmp",
                "--icmp-type",
                "echo-request",
                "-d",
                r,
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                "REDIRECT",
            ]);
        }
        if let Some(ref r) = p.fakeip_v6 {
            if p.ipv6 {
                ip6t.run(&[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    "echo-request",
                    "-d",
                    r,
                    "-m",
                    "comment",
                    "--comment",
                    COMMENT,
                    "-j",
                    "REDIRECT",
                ]);
            }
        }
    }

    info!("ip-auto-route: iptables applied (nexa-style fallback)");
    Ok(())
}

/// Identity + mark bypass: cgroup → gid → uid → SO_MARK. Local scope only for
/// the socket-based matches.
fn build_bypass(w: &W, caps: &Caps, target: (&str, &str), p: &Params, scope: Scope) {
    if !w.enabled {
        return;
    }
    let (table, chain) = target;
    if scope == Scope::Router {
        for cg in &p.bypass_cgroup {
            if caps.supports_match(w.bin, "cgroup", "--path") {
                let path = format!("services/{cg}");
                w.run(&[
                    "-t", table, "-A", chain, "-m", "cgroup", "--path", &path, "-j", "RETURN",
                ]);
            }
        }
        if !p.bypass_gid.is_empty() && caps.supports_match(w.bin, "owner", "--gid-owner") {
            let g = join_u32(&p.bypass_gid);
            w.run(&[
                "-t",
                table,
                "-A",
                chain,
                "-m",
                "owner",
                "--gid-owner",
                &g,
                "-j",
                "RETURN",
            ]);
        }
        if !p.bypass_uid.is_empty() && caps.supports_match(w.bin, "owner", "--uid-owner") {
            let u = join_u32(&p.bypass_uid);
            w.run(&[
                "-t",
                table,
                "-A",
                chain,
                "-m",
                "owner",
                "--uid-owner",
                &u,
                "-j",
                "RETURN",
            ]);
        }
    }
    // Loop prevention: ant's own SO_MARK always bypasses.
    w.run(&[
        "-t",
        table,
        "-A",
        chain,
        "-m",
        "mark",
        "--mark",
        &format!("{}/0xffffffff", p.mark),
        "-j",
        "RETURN",
    ]);
}

/// Destination-based bypass: reply direction → reserved CIDRs → (LAN) source
/// IP / MAC.
fn build_dest_bypass(w: &W, caps: &Caps, target: (&str, &str), p: &Params, scope: Scope, v4: bool) {
    if !w.enabled {
        return;
    }
    let (table, chain) = target;
    if caps.supports_match(w.bin, "conntrack", "--ctdir") {
        w.run(&[
            "-t",
            table,
            "-A",
            chain,
            "-m",
            "conntrack",
            "--ctdir",
            "REPLY",
            "-j",
            "RETURN",
        ]);
    }
    let reserved: &[String] = if v4 { &p.bypass_ip } else { &p.bypass_ip6 };
    let fakeip = if v4 {
        p.fakeip_v4.as_deref()
    } else {
        p.fakeip_v6.as_deref()
    };
    for cidr in reserved {
        let mut args: Vec<&str> = vec!["-t", table, "-A", chain, "-d", cidr];
        if let Some(r) = fakeip {
            args.extend_from_slice(&["!", "-d", r]);
        }
        args.extend_from_slice(&["-j", "RETURN"]);
        w.run(&args);
    }
    if scope == Scope::Lan {
        for ip in &p.lan_bypass_ip {
            w.run(&["-t", table, "-A", chain, "-s", ip, "-j", "RETURN"]);
        }
        for mac in &p.lan_bypass_mac {
            if caps.supports_match(w.bin, "mac", "--mac-source") {
                w.run(&[
                    "-t",
                    table,
                    "-A",
                    chain,
                    "-m",
                    "mac",
                    "--mac-source",
                    mac,
                    "-j",
                    "RETURN",
                ]);
            }
        }
    }
}

fn join_u32(v: &[u32]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Symmetric teardown: commented jump rules + custom chains.
pub fn cleanup(_p: &Params) {
    for bin in ["iptables", "ip6tables"] {
        if !has_cmd(bin) {
            continue;
        }
        for (table, chain) in [
            ("nat", "OUTPUT"),
            ("nat", "PREROUTING"),
            ("mangle", "OUTPUT"),
            ("mangle", "PREROUTING"),
            ("filter", "INPUT"),
            ("filter", "FORWARD"),
        ] {
            delete_commented(bin, table, chain);
        }
        for (table, name) in CHAINS {
            let _ = Command::new(bin).args(["-t", table, "-F", name]).output();
            let _ = Command::new(bin).args(["-t", table, "-X", name]).output();
        }
    }
}

/// Repeatedly delete the first rule carrying our comment (nexa
/// `deleteIptRulesByComment`), capped to avoid pathological loops.
fn delete_commented(bin: &str, table: &str, chain: &str) {
    for _ in 0..128 {
        let Ok(out) = Command::new(bin).args(["-t", table, "-S", chain]).output() else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let spec = String::from_utf8_lossy(&out.stdout);
        let Some(rule) = find_commented(&spec) else {
            return;
        };
        let mut args = vec![
            "-t".to_string(),
            table.to_string(),
            "-D".to_string(),
            chain.to_string(),
        ];
        args.extend(rule);
        let ok = Command::new(bin)
            .args(args.iter().map(|s| s.as_str()))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
}

/// Return the args of the first `-A` line carrying our comment, minus the
/// leading `-A <chain>` (nexa `findCommentedRule`).
fn find_commented(spec: &str) -> Option<Vec<String>> {
    let quoted = format!("--comment \"{COMMENT}\"");
    for line in spec.lines() {
        if !line.contains(&quoted) && !line.contains(&format!("--comment {COMMENT}")) {
            continue;
        }
        let fields = split_args(line);
        if fields.len() < 2 || fields[0] != "-A" {
            continue;
        }
        return Some(fields[2..].to_vec());
    }
    None
}

/// Split `iptables -S` output respecting double quotes (nexa `splitArgs`).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '"' => in_quote = !in_quote,
            ' ' | '\t' if !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn has_cmd(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}
