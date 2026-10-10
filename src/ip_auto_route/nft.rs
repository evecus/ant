//! nftables ruleset aligned with **nexa** `internal/nfttemplate/tmpl.go`.
//!
//! Chain topology (nexa `table inet nexa`):
//!
//! | nexa chain                 | role                                                  |
//! |----------------------------|-------------------------------------------------------|
//! | `router_dns_hijack`        | local DNS → `redirect to :dns-port`                    |
//! | `router_redirect`          | local TCP → `redirect to :redir-port`                  |
//! | `router_tproxy`            | local TCP/UDP → **set mark only**                      |
//! | `router_tun`               | local TCP/UDP → **set mark only** (tun mark)           |
//! | `lan_dns_hijack`           | LAN DNS → `redirect to :dns-port`                      |
//! | `lan_redirect`             | LAN TCP → `redirect to :redir-port`                    |
//! | `lan_tproxy`               | LAN TCP/UDP → `mark + tproxy to :tproxy-port`          |
//! | `lan_tun`                  | LAN TCP/UDP → set tun mark                             |
//! | `nat_output`               | `type nat hook output priority filter`                 |
//! | `mangle_output`            | `type route hook output priority mangle`               |
//! | `mangle_prerouting_router` | `type filter hook prerouting priority mangle - 1`      |
//! | `dstnat`                   | `type nat hook prerouting priority dstnat - 10`        |
//! | `mangle_prerouting_lan`    | `type filter hook prerouting priority mangle`          |
//!
//! TPROXY local-traffic model: `mangle_output` only **sets the mark**; policy
//! routing sends marked packets to `lo` (see route.rs); `mangle_prerouting_router`
//! then does `tproxy to :port` for `iifname lo`.

use super::{Params, TcpMode, UdpMode};
use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;
use tracing::info;

const TABLE: &str = "ant-ip-auto-route";

/// Which hook family the bypass prefix is generated for: local sockets can be
/// matched on uid/gid/cgroup, forwarded traffic cannot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Router,
    Lan,
}

pub fn apply(p: &Params) -> Result<()> {
    cleanup();
    let script = build_script(p);
    run_nft(&script).with_context(|| format!("nft apply:\n{script}"))?;
    info!(
        table = TABLE,
        "ip-auto-route: nftables applied (nexa-style)"
    );
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

fn mark_hex(v: u32) -> String {
    format!("0x{v:x}")
}

/// Bits to *preserve* when setting the mark (nexa `TproxyFwUmask` = `~mask`).
fn umask_hex(mask: u32) -> String {
    format!("0x{:x}", !mask)
}

/// `meta mark set meta mark & <umask> | <mark>`
fn set_mark(mark: u32, mask: u32) -> String {
    format!(
        "meta mark set meta mark & {} | {}",
        umask_hex(mask),
        mark_hex(mark)
    )
}

fn quoted(elems: &[String]) -> String {
    elems
        .iter()
        .map(|e| format!("\"{e}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn bare(elems: &[String]) -> String {
    elems.join(", ")
}

/// `set <name> { type <ty>; flags interval[, auto-merge]; [elements = { .. }] }`
fn emit_set(s: &mut String, name: &str, ty: &str, auto_merge: bool, elems: &[String], quote: bool) {
    s.push_str(&format!("\tset {name} {{\n\t\ttype {ty}\n"));
    s.push_str("\t\tflags interval\n");
    if auto_merge {
        s.push_str("\t\tauto-merge\n");
    }
    if !elems.is_empty() {
        let list = if quote { quoted(elems) } else { bare(elems) };
        s.push_str(&format!("\t\telements = {{ {list} }}\n"));
    }
    s.push_str("\t}\n\n");
}

/// cgroup / gid / uid bypass — local (output) scope only.
fn identity_bypass(p: &Params, scope: Scope) -> String {
    if scope != Scope::Router {
        return String::new();
    }
    let mut s = String::new();
    for cg in &p.bypass_cgroup {
        // nexa: `socket cgroupv2 level <depth> "<path>"`
        let level = cg.split('/').filter(|x| !x.is_empty()).count().max(1);
        s.push_str(&format!(
            "\t\tsocket cgroupv2 level {level} \"{cg}\" counter return\n"
        ));
    }
    if !p.bypass_gid.is_empty() {
        s.push_str(&format!(
            "\t\tmeta skgid {{ {} }} counter return\n",
            bare(
                &p.bypass_gid
                    .iter()
                    .map(|g| g.to_string())
                    .collect::<Vec<_>>()
            )
        ));
    }
    if !p.bypass_uid.is_empty() {
        s.push_str(&format!(
            "\t\tmeta skuid {{ {} }} counter return\n",
            bare(
                &p.bypass_uid
                    .iter()
                    .map(|u| u.to_string())
                    .collect::<Vec<_>>()
            )
        ));
    }
    s
}

/// Loop prevention: packets already carrying ant's SO_MARK are let through.
fn mark_bypass(p: &Params) -> String {
    format!(
        "\t\tmeta mark & {} == {} counter return\n",
        mark_hex(0xffff_ffff),
        mark_hex(p.mark)
    )
}

/// Destination-based bypass shared by nat/mangle output and the LAN hooks:
/// local/broadcast → reserved → (LAN) source IP/MAC.
fn dest_bypass(p: &Params, scope: Scope) -> String {
    let mut s = String::new();
    s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n");
    s.push_str("\t\tct direction reply counter return\n");
    // Reserved / bypass CIDRs — but never the Fake-IP ranges themselves,
    // otherwise Fake-IP destinations would be treated as local (nexa).
    if !p.bypass_ip.is_empty() {
        let mut line = String::from("\t\tip daddr @reserved_ip");
        if let Some(ref r) = p.fakeip_v4 {
            line.push_str(&format!(" ip daddr != {r}"));
        }
        line.push_str(" counter return\n");
        s.push_str(&line);
    }
    if !p.bypass_ip6.is_empty() {
        let mut line = String::from("\t\tip6 daddr @reserved_ip6");
        if let Some(ref r) = p.fakeip_v6 {
            line.push_str(&format!(" ip6 daddr != {r}"));
        }
        line.push_str(" counter return\n");
        s.push_str(&line);
    }
    // LAN-only: source address / MAC bypass lists.
    if scope == Scope::Lan {
        if !p.lan_bypass_ip.is_empty() {
            s.push_str(&format!(
                "\t\tip saddr {{ {} }} counter return\n",
                bare(&p.lan_bypass_ip)
            ));
        }
        if !p.lan_bypass_mac.is_empty() {
            s.push_str(&format!(
                "\t\tether saddr {{ {} }} counter return\n",
                bare(&p.lan_bypass_mac)
            ));
        }
    }
    s
}

/// Full bypass prefix: identity (local only) → mark → destination.
fn bypass_prefix(p: &Params, scope: Scope) -> String {
    let mut s = identity_bypass(p, scope);
    s.push_str(&mark_bypass(p));
    s.push_str(&dest_bypass(p, scope));
    s
}

fn nfproto_elems(v6: bool) -> Vec<String> {
    let mut v = vec!["ipv4".to_string()];
    if v6 {
        v.push("ipv6".to_string());
    }
    v
}

/// DNS exclusion used inside the tproxy/tun chains when DNS hijack owns :53.
fn dns_skip(p: &Params) -> String {
    if p.dns_hijack && p.dns_port > 0 {
        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return\n"
            .to_string()
    } else {
        String::new()
    }
}

fn mode_jump(p: &Params, tcp: bool, lan: bool) -> String {
    let tproxy = if tcp {
        p.tcp_mode == Some(TcpMode::Tproxy)
    } else {
        p.udp_mode == Some(UdpMode::Tproxy)
    };
    let tun = if tcp {
        p.tcp_mode == Some(TcpMode::Tun)
    } else {
        p.udp_mode == Some(UdpMode::Tun)
    };
    let target = if tproxy {
        // `lan_tproxy` / `router_tproxy` are only emitted when a tproxy port
        // exists — fall back to `continue` so the ruleset still loads.
        if p.tproxy_port > 0 {
            "tproxy"
        } else {
            return "continue".to_string();
        }
    } else if tun {
        "tun"
    } else {
        return "continue".to_string();
    };
    let prefix = if lan { "lan" } else { "router" };
    format!("jump {prefix}_{target}")
}

fn build_script(p: &Params) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE} {{\n"));

    // ── sets ────────────────────────────────────────────────────────────
    emit_set(
        &mut s,
        "dns_hijack_nfproto",
        "nf_proto",
        false,
        &nfproto_elems(p.ipv6),
        false,
    );
    emit_set(
        &mut s,
        "proxy_nfproto",
        "nf_proto",
        false,
        &nfproto_elems(p.ipv6),
        false,
    );
    emit_set(
        &mut s,
        "reserved_ip",
        "ipv4_addr",
        true,
        &p.bypass_ip,
        false,
    );
    emit_set(
        &mut s,
        "reserved_ip6",
        "ipv6_addr",
        true,
        &p.bypass_ip6,
        false,
    );
    if p.lan_proxy {
        emit_set(
            &mut s,
            "lan_inbound_device",
            "ifname",
            true,
            &p.lan_interface,
            true,
        );
    }
    // ── router (local) chains ───────────────────────────────────────────
    if p.router_proxy {
        s.push_str("\tchain router_dns_hijack {\n");
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str(&format!(
                "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :{}\n",
                p.dns_port
            ));
        }
        s.push_str("\t}\n\n");

        if p.needs_redir() && p.redir_port > 0 {
            s.push_str("\tchain router_redirect {\n");
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter redirect to :{}\n",
                p.redir_port
            ));
            s.push_str("\t}\n\n");
        }
        if p.needs_tproxy() {
            s.push_str("\tchain router_tproxy {\n");
            s.push_str(&dns_skip(p));
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} counter accept\n",
                set_mark(p.tproxy_mark, p.tproxy_mask)
            ));
            s.push_str("\t}\n\n");
        }
        if p.needs_tun() {
            s.push_str("\tchain router_tun {\n");
            s.push_str(&dns_skip(p));
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} counter accept\n",
                set_mark(p.tun_mark, p.tun_mask)
            ));
            s.push_str("\t}\n\n");
        }

        // nat_output: DNS hijack (+ TCP redirect when tcp-mode=redir, + fake-ip ping)
        s.push_str("\tchain nat_output {\n");
        s.push_str("\t\ttype nat hook output priority filter; policy accept;\n");
        s.push_str(&bypass_prefix(p, Scope::Router));
        s.push_str("\t\tjump router_dns_hijack\n");
        if p.needs_redir() && p.redir_port > 0 {
            s.push_str(&dest_bypass(p, Scope::Router));
            s.push_str("\t\tjump router_redirect\n");
        }
        s.push_str(&fakeip_ping_rules(p));
        s.push_str("\t}\n\n");

        // mangle_output: mark-only, `type route` so the mark re-runs route lookup
        if p.needs_tproxy() || p.needs_tun() {
            s.push_str("\tchain mangle_output {\n");
            s.push_str("\t\ttype route hook output priority mangle; policy accept;\n");
            s.push_str(&bypass_prefix(p, Scope::Router));
            s.push_str(&format!(
                "\t\tmeta l4proto vmap {{ tcp: {}, udp: {} }}\n",
                mode_jump(p, true, false),
                mode_jump(p, false, false)
            ));
            s.push_str("\t}\n\n");
        }
    }

    // ── mangle_prerouting_router: the actual tproxy for local traffic ────
    if p.needs_tproxy() || p.needs_tun() {
        s.push_str("\tchain mangle_prerouting_router {\n");
        s.push_str("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
        if p.needs_tproxy() && p.tproxy_port > 0 {
            s.push_str(&format!(
                "\t\tiifname \"lo\" meta l4proto {{ tcp, udp }} meta mark & {} == {} tproxy to :{} counter accept\n",
                mark_hex(p.tproxy_mask),
                mark_hex(p.tproxy_mark),
                p.tproxy_port
            ));
        }
        if p.needs_tun() {
            s.push_str(&format!(
                "\t\tiifname \"{}\" meta l4proto {{ icmp, tcp, udp }} counter accept\n",
                p.tun_device
            ));
        }
        s.push_str("\t}\n\n");
    }

    // ── lan chains ─────────────────────────────────────────────────────
    if p.lan_proxy {
        s.push_str("\tchain lan_dns_hijack {\n");
        if p.dns_hijack && p.dns_port > 0 {
            s.push_str(&format!(
                "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :{}\n",
                p.dns_port
            ));
        }
        s.push_str("\t}\n\n");

        if p.needs_redir() && p.redir_port > 0 {
            s.push_str("\tchain lan_redirect {\n");
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter redirect to :{}\n",
                p.redir_port
            ));
            s.push_str("\t}\n\n");
        }
        if p.needs_tproxy() && p.tproxy_port > 0 {
            s.push_str("\tchain lan_tproxy {\n");
            s.push_str(&dns_skip(p));
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} tproxy to :{} counter accept\n",
                set_mark(p.tproxy_mark, p.tproxy_mask),
                p.tproxy_port
            ));
            s.push_str("\t}\n\n");
        }
        if p.needs_tun() {
            s.push_str("\tchain lan_tun {\n");
            s.push_str(&dns_skip(p));
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} counter accept\n",
                set_mark(p.tun_mark, p.tun_mask)
            ));
            s.push_str("\t}\n\n");
        }

        s.push_str("\tchain dstnat {\n");
        s.push_str("\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n");
        s.push_str("\t\tiifname @lan_inbound_device jump lan_dns_hijack\n");
        if p.needs_redir() && p.redir_port > 0 {
            s.push_str(&dest_bypass(p, Scope::Lan));
            s.push_str("\t\tiifname @lan_inbound_device jump lan_redirect\n");
        }
        s.push_str(&fakeip_ping_rules(p));
        s.push_str("\t}\n\n");

        s.push_str("\tchain mangle_prerouting_lan {\n");
        s.push_str("\t\ttype filter hook prerouting priority mangle; policy accept;\n");
        s.push_str(&bypass_prefix(p, Scope::Lan));
        s.push_str(&format!(
            "\t\tiifname @lan_inbound_device meta l4proto vmap {{ tcp: {}, udp: {} }}\n",
            mode_jump(p, true, true),
            mode_jump(p, false, true)
        ));
        s.push_str("\t}\n\n");
    }

    s.push_str("}\n");
    s
}

/// nexa: `icmp type echo-request ip daddr <range> counter redirect` inside
/// `nat_output` (local) and `dstnat` (LAN).
fn fakeip_ping_rules(p: &Params) -> String {
    if !p.fakeip_ping {
        return String::new();
    }
    let mut s = String::new();
    if let Some(ref r) = p.fakeip_v4 {
        s.push_str(&format!(
            "\t\ticmp type echo-request ip daddr {r} counter redirect\n"
        ));
    }
    if let Some(ref r) = p.fakeip_v6 {
        s.push_str(&format!(
            "\t\ticmpv6 type echo-request ip6 daddr {r} counter redirect\n"
        ));
    }
    s
}
