//! nftables rules aligned with **nexa** `internal/nfttemplate/tmpl.go`.
//!
//! TPROXY local-traffic model (nexa / classic transparent proxy):
//! 1. `mangle_output` (type **route**): only **set mark** — never `tproxy` here
//! 2. policy routing: fwmark → `local default dev lo` (see route.rs)
//! 3. `mangle_prerouting` on **iif lo**: `tproxy to :port` for marked packets
//!
//! LAN traffic: prerouting directly `mark + tproxy to :port`.
//!
//! REDIR / DNS: nat output + prerouting `redirect to :port`.

use super::{Params, TcpMode, UdpMode};
use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;
use tracing::info;

const TABLE: &str = "ant-ip-auto-route";

pub fn apply(p: &Params) -> Result<()> {
    cleanup();
    let script = build_script(p);
    run_nft(&script).with_context(|| format!("nft apply:\n{script}"))?;
    info!(table = TABLE, "ip-auto-route: nftables applied (nexa-style)");
    Ok(())
}

pub fn cleanup() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output();
}

fn run_nft(script: &str) -> Result<()> {
    let out = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            if let Some(mut s) = c.stdin.take() {
                s.write_all(script.as_bytes())?;
            }
            c.wait_with_output()
        })
        .context("spawn nft")?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn mark_hex(p: &Params) -> String {
    format!("0x{:x}", p.mark)
}
fn mask_hex(p: &Params) -> String {
    format!("0x{:x}", p.mark_mask)
}

/// Bypass: own mark + user uid/gid/cgroup lists.
fn bypass_rules(p: &Params) -> String {
    let mut lines = String::new();
    lines.push_str(&format!(
        "\t\tmeta mark and {} == {} return\n",
        mask_hex(p),
        mark_hex(p)
    ));
    if !p.bypass_uid.is_empty() {
        let u = p
            .bypass_uid
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push_str(&format!("\t\tmeta skuid {{ {u} }} return\n"));
    }
    if !p.bypass_gid.is_empty() {
        let g = p
            .bypass_gid
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push_str(&format!("\t\tmeta skgid {{ {g} }} return\n"));
    }
    for cg in &p.bypass_cgroup {
        lines.push_str(&format!(
            "\t\tsocket cgroupv2 level 2 \"{cg}\" return\n"
        ));
    }
    lines
}

fn need_tproxy(p: &Params) -> bool {
    p.tcp_mode == Some(TcpMode::Tproxy) || p.udp_mode == Some(UdpMode::Tproxy)
}
fn need_tun(p: &Params) -> bool {
    p.tcp_mode == Some(TcpMode::Tun) || p.udp_mode == Some(UdpMode::Tun)
}
fn need_redir(p: &Params) -> bool {
    p.tcp_mode == Some(TcpMode::Redir)
}
fn need_nat(p: &Params) -> bool {
    need_redir(p) || (p.dns_hijack && p.dns_port > 0)
}

/// nexa `router_tproxy` / `router_tun`: **mark only** (no tproxy statement).
fn mark_set_accept(p: &Params) -> String {
    format!(
        "\t\tmeta l4proto {{ tcp, udp }} meta mark set meta mark & {} | {} accept\n",
        mask_hex(p),
        mark_hex(p)
    )
}

fn build_script(p: &Params) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE} {{\n"));

    // LAN interface set
    if p.lan_proxy && !p.lan_interface.is_empty() {
        let elems = p
            .lan_interface
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "\tset lan_if {{\n\t\ttype ifname\n\t\telements = {{ {elems} }}\n\t}}\n\n"
        ));
    }

    // ── router_tproxy: mark-only (nexa) ────────────────────────────
    if need_tproxy(p) {
        s.push_str("\tchain router_tproxy {\n");
        s.push_str(&bypass_rules(p));
        // Exclude DNS when NAT owns port 53
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 return\n");
        }
        s.push_str(&mark_set_accept(p));
        s.push_str("\t}\n\n");
    }

    // ── router_tun: mark-only ─────────────────────────────────────
    if need_tun(p) {
        s.push_str("\tchain router_tun {\n");
        s.push_str(&bypass_rules(p));
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 return\n");
        }
        s.push_str(&mark_set_accept(p));
        s.push_str("\t}\n\n");
    }

    // ── lan_tproxy: mark + tproxy (nexa lan_tproxy) ────────────────
    if p.lan_proxy && need_tproxy(p) && p.tproxy_port > 0 {
        s.push_str("\tchain lan_tproxy {\n");
        s.push_str(&bypass_rules(p));
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 return\n");
        }
        // nexa: meta mark set ... tproxy to :port
        s.push_str(&format!(
            "\t\tmeta l4proto {{ tcp, udp }} meta mark set meta mark & {} | {} tproxy to :{} accept\n",
            mask_hex(p),
            mark_hex(p),
            p.tproxy_port
        ));
        s.push_str("\t}\n\n");
    }

    // ── lan_tun: mark only ─────────────────────────────────────────
    if p.lan_proxy && need_tun(p) {
        s.push_str("\tchain lan_tun {\n");
        s.push_str(&bypass_rules(p));
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 return\n");
        }
        s.push_str(&mark_set_accept(p));
        s.push_str("\t}\n\n");
    }

    // ── mangle_output: type route — mark only (nexa mangle_output) ─
    if need_tproxy(p) || need_tun(p) {
        s.push_str("\tchain mangle_output {\n");
        s.push_str("\t\ttype route hook output priority mangle; policy accept;\n");
        s.push_str(&bypass_rules(p));
        // skip reserved / local destinations roughly: daddr type local
        s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } return\n");
        s.push_str("\t\tct direction reply return\n");
        // mode dispatch (simplified vmap)
        let tcp_jump = match p.tcp_mode {
            Some(TcpMode::Tproxy) => "jump router_tproxy",
            Some(TcpMode::Tun) => "jump router_tun",
            _ => "return",
        };
        let udp_jump = match p.udp_mode {
            Some(UdpMode::Tproxy) => "jump router_tproxy",
            Some(UdpMode::Tun) => "jump router_tun",
            _ => "return",
        };
        s.push_str(&format!(
            "\t\tmeta l4proto vmap {{ tcp: {tcp_jump}, udp: {udp_jump} }}\n"
        ));
        s.push_str("\t}\n\n");
    }

    // ── mangle_prerouting_router: lo + marked → tproxy (nexa) ───────
    // This is the actual tproxy for *local* traffic after policy routing to lo.
    if need_tproxy(p) && p.tproxy_port > 0 {
        s.push_str("\tchain mangle_prerouting_router {\n");
        s.push_str("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
        s.push_str(&format!(
            "\t\tiifname \"lo\" meta l4proto {{ tcp, udp }} meta mark and {} == {} tproxy to :{} accept\n",
            mask_hex(p),
            mark_hex(p),
            p.tproxy_port
        ));
        s.push_str("\t}\n\n");
    }

    // ── mangle_prerouting_lan: LAN → lan_tproxy / lan_tun ───────────
    if p.lan_proxy && (need_tproxy(p) || need_tun(p)) {
        s.push_str("\tchain mangle_prerouting_lan {\n");
        s.push_str("\t\ttype filter hook prerouting priority mangle; policy accept;\n");
        s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } return\n");
        s.push_str("\t\tct direction reply return\n");
        s.push_str(&bypass_rules(p));
        let tcp_jump = match p.tcp_mode {
            Some(TcpMode::Tproxy) => "jump lan_tproxy",
            Some(TcpMode::Tun) => "jump lan_tun",
            _ => "return",
        };
        let udp_jump = match p.udp_mode {
            Some(UdpMode::Tproxy) => "jump lan_tproxy",
            Some(UdpMode::Tun) => "jump lan_tun",
            _ => "return",
        };
        s.push_str(&format!(
            "\t\tiifname @lan_if meta l4proto vmap {{ tcp: {tcp_jump}, udp: {udp_jump} }}\n"
        ));
        s.push_str("\t}\n\n");
    }

    // ── NAT: DNS hijack + TCP redirect (nexa dstnat / output_nat) ───
    if need_nat(p) {
        // output NAT (local)
        s.push_str("\tchain output_nat {\n");
        s.push_str("\t\ttype nat hook output priority filter; policy accept;\n");
        s.push_str(&bypass_rules(p));
        s.push_str("\t\tfib daddr type local return\n");
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str(&format!(
                "\t\tmeta l4proto {{ tcp, udp }} th dport 53 redirect to :{}\n",
                p.dns_port
            ));
        }
        if need_redir(p) && p.redir_port > 0 {
            s.push_str(&format!(
                "\t\tmeta l4proto tcp redirect to :{}\n",
                p.redir_port
            ));
        }
        s.push_str("\t}\n\n");

        // prerouting NAT (LAN)
        if p.lan_proxy {
            s.push_str("\tchain dstnat {\n");
            s.push_str("\t\ttype nat hook prerouting priority dstnat; policy accept;\n");
            s.push_str("\t\tiifname @lan_if jump lan_nat\n");
            s.push_str("\t}\n\n");
            s.push_str("\tchain lan_nat {\n");
            s.push_str(&bypass_rules(p));
            if p.dns_hijack && p.dns_port > 0 {
                s.push_str(&format!(
                    "\t\tmeta l4proto {{ tcp, udp }} th dport 53 redirect to :{}\n",
                    p.dns_port
                ));
            }
            if need_redir(p) && p.redir_port > 0 {
                s.push_str(&format!(
                    "\t\tmeta l4proto tcp redirect to :{}\n",
                    p.redir_port
                ));
            }
            s.push_str("\t}\n\n");
        }
    }

    // Fake-IP ping hijack (nexa: icmp echo-request redirect)
    if p.fakeip_ping && (p.fakeip_v4.is_some() || p.fakeip_v6.is_some()) {
        s.push_str("\tchain fakeip_ping {\n");
        s.push_str("\t\ttype nat hook output priority filter - 1; policy accept;\n");
        if let Some(ref r) = p.fakeip_v4 {
            s.push_str(&format!(
                "\t\ticmp type echo-request ip daddr {r} redirect\n"
            ));
        }
        if let Some(ref r) = p.fakeip_v6 {
            s.push_str(&format!(
                "\t\ticmpv6 type echo-request ip6 daddr {r} redirect\n"
            ));
        }
        s.push_str("\t}\n");
    }

    s.push_str("}\n");
    s
}
