//! nftables rules for ip-auto-route (table `inet ant-ip-auto-route`).

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
    info!(table = TABLE, "ip-auto-route: nftables applied");
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

fn bypass_rules(p: &Params) -> String {
    let mut lines = String::new();
    lines.push_str(&format!(
        "    meta mark and {} == {} return\n",
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
        lines.push_str(&format!("    meta skuid {{ {u} }} return\n"));
    }
    if !p.bypass_gid.is_empty() {
        let g = p
            .bypass_gid
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push_str(&format!("    meta skgid {{ {g} }} return\n"));
    }
    for cg in &p.bypass_cgroup {
        lines.push_str(&format!("    socket cgroupv2 level 2 \"{cg}\" return\n"));
    }
    lines
}

/// Core hijack expressions shared by output + lan chains (filter/tproxy/mark).
fn filter_hijack(p: &Params) -> String {
    let mut s = String::new();
    let mark = mark_hex(p);
    let mask = mask_hex(p);

    // tproxy DNS (when not using pure redirect nat)
    if p.dns_hijack && p.tproxy_port > 0 && p.tcp_mode != Some(TcpMode::Redir) {
        s.push_str(&format!(
            "    meta l4proto {{ tcp, udp }} th dport 53 meta mark set meta mark & {mask} | {mark} tproxy to :{}\n",
            p.tproxy_port
        ));
    }

    match p.tcp_mode {
        Some(TcpMode::Tproxy) if p.tproxy_port > 0 => {
            s.push_str(&format!(
                "    meta l4proto tcp meta mark set meta mark & {mask} | {mark} tproxy to :{}\n",
                p.tproxy_port
            ));
        }
        Some(TcpMode::Tun) => {
            s.push_str(&format!(
                "    meta l4proto tcp meta mark set meta mark & {mask} | {mark}\n"
            ));
        }
        _ => {}
    }

    match p.udp_mode {
        Some(UdpMode::Tproxy) if p.tproxy_port > 0 => {
            s.push_str(&format!(
                "    meta l4proto udp meta mark set meta mark & {mask} | {mark} tproxy to :{}\n",
                p.tproxy_port
            ));
        }
        Some(UdpMode::Tun) => {
            s.push_str(&format!(
                "    meta l4proto udp meta mark set meta mark & {mask} | {mark}\n"
            ));
        }
        _ => {}
    }

    if p.fakeip_ping {
        if let Some(ref r) = p.fakeip_v4 {
            s.push_str(&format!("    ip protocol icmp ip daddr {r} accept\n"));
        }
        if let Some(ref r) = p.fakeip_v6 {
            s.push_str(&format!("    ip6 nexthdr ipv6-icmp ip6 daddr {r} accept\n"));
        }
    }
    s
}

fn nat_hijack(p: &Params) -> String {
    let mut s = String::new();
    if p.dns_hijack && p.dns_port > 0 {
        s.push_str(&format!(
            "    meta l4proto {{ tcp, udp }} th dport 53 redirect to :{}\n",
            p.dns_port
        ));
    }
    if p.tcp_mode == Some(TcpMode::Redir) && p.redir_port > 0 {
        s.push_str(&format!(
            "    meta l4proto tcp redirect to :{}\n",
            p.redir_port
        ));
    }
    s
}

fn build_script(p: &Params) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE} {{\n"));

    if p.lan_proxy && !p.lan_interface.is_empty() {
        let elems = p
            .lan_interface
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  set lan_if {{ type ifname; elements = {{ {elems} }} }}\n"
        ));
    }

    // filter prerouting — tproxy / mark
    s.push_str("  chain prerouting {\n");
    s.push_str("    type filter hook prerouting priority mangle; policy accept;\n");
    if p.lan_proxy {
        s.push_str("    iifname @lan_if jump lan_filter\n");
    }
    s.push_str("  }\n");

    if p.lan_proxy {
        s.push_str("  chain lan_filter {\n");
        s.push_str(&bypass_rules(p));
        s.push_str(&filter_hijack(p));
        s.push_str("  }\n");
    }

    // filter output
    s.push_str("  chain output {\n");
    s.push_str("    type route hook output priority mangle; policy accept;\n");
    s.push_str(&bypass_rules(p));
    s.push_str(&filter_hijack(p));
    s.push_str("  }\n");

    // NAT for redir + DNS redirect-to-port
    let need_nat = p.tcp_mode == Some(TcpMode::Redir) || (p.dns_hijack && p.dns_port > 0);
    if need_nat {
        s.push_str("  chain dstnat {\n");
        s.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
        if p.lan_proxy {
            s.push_str("    iifname @lan_if jump lan_nat\n");
        }
        s.push_str("  }\n");
        if p.lan_proxy {
            s.push_str("  chain lan_nat {\n");
            s.push_str(&bypass_rules(p));
            s.push_str(&nat_hijack(p));
            s.push_str("  }\n");
        }
        s.push_str("  chain output_nat {\n");
        s.push_str("    type nat hook output priority -100; policy accept;\n");
        s.push_str(&bypass_rules(p));
        s.push_str(&nat_hijack(p));
        s.push_str("  }\n");
    }

    s.push_str("}\n");
    s
}
