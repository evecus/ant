//! iptables / ip6tables fallback for ip-auto-route.

use super::{Params, TcpMode, UdpMode};
use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

const COMMENT: &str = "ant-ip-auto-route";

pub fn apply(p: &Params) -> Result<()> {
    cleanup(p);
    apply_family(p, false).context("iptables v4")?;
    if p.ipv6 {
        if let Err(e) = apply_family(p, true) {
            warn!(err = %e, "ip-auto-route: ip6tables apply failed");
            // soft-fail v6 only if v4 succeeded
        }
    }
    info!("ip-auto-route: iptables applied");
    Ok(())
}

pub fn cleanup(p: &Params) {
    cleanup_family(false);
    if p.ipv6 {
        cleanup_family(true);
    }
}

fn bin(v6: bool) -> &'static str {
    if v6 {
        "ip6tables"
    } else {
        "iptables"
    }
}

fn run(v6: bool, args: &[&str]) -> Result<()> {
    let out = Command::new(bin(v6))
        .args(args)
        .output()
        .with_context(|| format!("{} {:?}", bin(v6), args))?;
    if !out.status.success() {
        anyhow::bail!(
            "{} {:?}: {}",
            bin(v6),
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn run_ignore(v6: bool, args: &[&str]) {
    let _ = Command::new(bin(v6)).args(args).output();
}

fn apply_family(p: &Params, v6: bool) -> Result<()> {
    // Create dedicated chains
    for table_chain in [
        ("mangle", "ANT_IAR_PRE"),
        ("mangle", "ANT_IAR_OUT"),
        ("nat", "ANT_IAR_PRE"),
        ("nat", "ANT_IAR_OUT"),
    ] {
        run_ignore(v6, &["-t", table_chain.0, "-N", table_chain.1]);
        run_ignore(v6, &["-t", table_chain.0, "-F", table_chain.1]);
    }

    // Jump from built-in chains
    ensure_jump(v6, "mangle", "PREROUTING", "ANT_IAR_PRE")?;
    ensure_jump(v6, "mangle", "OUTPUT", "ANT_IAR_OUT")?;
    ensure_jump(v6, "nat", "PREROUTING", "ANT_IAR_PRE")?;
    ensure_jump(v6, "nat", "OUTPUT", "ANT_IAR_OUT")?;

    // Bypass mark
    let mark = format!("{}", p.mark);
    let mask = format!("{}", p.mark_mask);
    for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
        run(
            v6,
            &[
                "-t", "mangle", "-A", chain, "-m", "mark", "--mark",
                &format!("{mark}/{mask}"), "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
            ],
        )?;
    }
    for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
        run(
            v6,
            &[
                "-t", "nat", "-A", chain, "-m", "mark", "--mark",
                &format!("{mark}/{mask}"), "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
            ],
        )?;
    }

    // uid/gid bypass
    for uid in &p.bypass_uid {
        let u = uid.to_string();
        for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
            run_ignore(
                v6,
                &[
                    "-t", "mangle", "-A", chain, "-m", "owner", "--uid-owner", &u,
                    "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
                ],
            );
            run_ignore(
                v6,
                &[
                    "-t", "nat", "-A", chain, "-m", "owner", "--uid-owner", &u,
                    "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
                ],
            );
        }
    }
    for gid in &p.bypass_gid {
        let g = gid.to_string();
        for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
            run_ignore(
                v6,
                &[
                    "-t", "mangle", "-A", chain, "-m", "owner", "--gid-owner", &g,
                    "-m", "comment", "--comment", COMMENT, "-j", "RETURN",
                ],
            );
        }
    }

    // LAN interface match helper
    let lan_ifaces: Vec<&str> = if p.lan_proxy {
        p.lan_interface.iter().map(|s| s.as_str()).collect()
    } else {
        Vec::new()
    };

    // DNS + TCP/UDP rules
    add_hijack_rules(p, v6, &lan_ifaces)?;
    Ok(())
}

fn ensure_jump(v6: bool, table: &str, hook: &str, chain: &str) -> Result<()> {
    // Avoid duplicate jumps: try check then add
    let check = Command::new(bin(v6))
        .args(["-t", table, "-C", hook, "-j", chain, "-m", "comment", "--comment", COMMENT])
        .output();
    if check.map(|o| o.status.success()).unwrap_or(false) {
        return Ok(());
    }
    run(
        v6,
        &[
            "-t", table, "-A", hook, "-j", chain, "-m", "comment", "--comment", COMMENT,
        ],
    )
}

fn add_hijack_rules(p: &Params, v6: bool, lan: &[&str]) -> Result<()> {
    let mark = p.mark.to_string();

    // Helper: append to ANT_IAR_PRE only for lan ifaces (or always if no lan restriction on output)
    let apply_pre = |args: &[&str]| -> Result<()> {
        if lan.is_empty() {
            // no lan-proxy: do not touch PREROUTING
            return Ok(());
        }
        for iface in lan {
            let mut full = vec!["-t", "mangle", "-A", "ANT_IAR_PRE", "-i", iface];
            full.extend_from_slice(args);
            full.extend_from_slice(&["-m", "comment", "--comment", COMMENT]);
            // rebuild as owned
            let owned: Vec<String> = full.iter().map(|s| s.to_string()).collect();
            let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
            run(v6, &refs)?;
        }
        Ok(())
    };

    let apply_out = |args: &[&str]| -> Result<()> {
        let mut full = vec!["-t", "mangle", "-A", "ANT_IAR_OUT"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["-m", "comment", "--comment", COMMENT]);
        let owned: Vec<String> = full.iter().map(|s| s.to_string()).collect();
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        run(v6, &refs)
    };

    // TPROXY needs --tproxy-mark and TPROXY target
    let tproxy_port = p.tproxy_port.to_string();
    let redir_port = p.redir_port.to_string();
    let dns_port = p.dns_port.to_string();

    // TCP
    match p.tcp_mode {
        Some(TcpMode::Tproxy) if p.tproxy_port > 0 => {
            let args = [
                "-p", "tcp", "-j", "TPROXY",
                "--on-port", &tproxy_port, "--tproxy-mark", &mark,
            ];
            apply_pre(&args)?;
            apply_out(&args)?;
        }
        Some(TcpMode::Tun) => {
            let args = ["-p", "tcp", "-j", "MARK", "--set-mark", &mark];
            apply_pre(&args)?;
            apply_out(&args)?;
        }
        Some(TcpMode::Redir) if p.redir_port > 0 => {
            // nat REDIRECT
            for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
                if chain == "ANT_IAR_PRE" && lan.is_empty() {
                    continue;
                }
                if chain == "ANT_IAR_PRE" {
                    for iface in lan {
                        run(
                            v6,
                            &[
                                "-t", "nat", "-A", chain, "-i", iface, "-p", "tcp",
                                "-j", "REDIRECT", "--to-ports", &redir_port,
                                "-m", "comment", "--comment", COMMENT,
                            ],
                        )?;
                    }
                } else {
                    run(
                        v6,
                        &[
                            "-t", "nat", "-A", chain, "-p", "tcp",
                            "-j", "REDIRECT", "--to-ports", &redir_port,
                            "-m", "comment", "--comment", COMMENT,
                        ],
                    )?;
                }
            }
        }
        _ => {}
    }

    // UDP
    match p.udp_mode {
        Some(UdpMode::Tproxy) if p.tproxy_port > 0 => {
            let args = [
                "-p", "udp", "-j", "TPROXY",
                "--on-port", &tproxy_port, "--tproxy-mark", &mark,
            ];
            apply_pre(&args)?;
            apply_out(&args)?;
        }
        Some(UdpMode::Tun) => {
            let args = ["-p", "udp", "-j", "MARK", "--set-mark", &mark];
            apply_pre(&args)?;
            apply_out(&args)?;
        }
        _ => {}
    }

    // DNS hijack via REDIRECT when dns port set
    if p.dns_hijack && p.dns_port > 0 {
        for proto in ["tcp", "udp"] {
            for chain in ["ANT_IAR_PRE", "ANT_IAR_OUT"] {
                if chain == "ANT_IAR_PRE" && lan.is_empty() {
                    continue;
                }
                if chain == "ANT_IAR_PRE" {
                    for iface in lan {
                        run(
                            v6,
                            &[
                                "-t", "nat", "-A", chain, "-i", iface, "-p", proto,
                                "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port,
                                "-m", "comment", "--comment", COMMENT,
                            ],
                        )?;
                    }
                } else {
                    run(
                        v6,
                        &[
                            "-t", "nat", "-A", chain, "-p", proto,
                            "--dport", "53", "-j", "REDIRECT", "--to-ports", &dns_port,
                            "-m", "comment", "--comment", COMMENT,
                        ],
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn cleanup_family(v6: bool) {
    // Remove jumps
    for (table, hook, chain) in [
        ("mangle", "PREROUTING", "ANT_IAR_PRE"),
        ("mangle", "OUTPUT", "ANT_IAR_OUT"),
        ("nat", "PREROUTING", "ANT_IAR_PRE"),
        ("nat", "OUTPUT", "ANT_IAR_OUT"),
    ] {
        // delete all matching jumps (loop)
        for _ in 0..8 {
            let out = Command::new(bin(v6))
                .args([
                    "-t", table, "-D", hook, "-j", chain, "-m", "comment", "--comment", COMMENT,
                ])
                .output();
            if !out.map(|o| o.status.success()).unwrap_or(false) {
                break;
            }
        }
        run_ignore(v6, &["-t", table, "-F", chain]);
        run_ignore(v6, &["-t", table, "-X", chain]);
    }
}
