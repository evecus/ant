//! auto-redirect — faithful port of sing-tun `setupNFTables()` **classic mode**
//! (the topology mihomo uses unless route-address-set is configured).
//!
//! TCP is handled by an internal REDIRECT listener, UDP/ICMP keep flowing into
//! the TUN device via the classic auto-route policy rules (see `route.rs`).
//!
//! Output chain (NAT, mangle prio): local-daddr return, MPTCP drop, then
//! `oifname <tun> tcp redirect` (locally-originated traffic routed into TUN).
//!
//! Prerouting chain (NAT, dstnat+1): `iifname <tun> return`, DNS hijack
//! (tcp/udp dport 53 → DNAT to TUN-side DNS), local-daddr return, MPTCP drop,
//! strict-route reject for a disabled family, then `tcp redirect`.
//!
//! Local-address exclude keeps inbound host services reachable (same as sing-tun
//! `inet4/6_local_address_set`).

use crate::app::router::Router;
use crate::outbound::OutboundManager;
use anyhow::{Context, Result};
use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct RedirectParams {
    pub tun_if: String,
    pub has_v4: bool,
    pub has_v6: bool,
    pub strict_route: bool,
    /// `dns-hijack` list non-empty → DNAT tcp/udp dport 53 into the TUN DNS.
    pub dns_hijack: bool,
    /// TUN-side DNS address for DNAT (tun client addr, i.e. server addr + 1).
    pub dns_v4: Option<Ipv4Addr>,
    pub dns_v6: Option<Ipv6Addr>,
}

pub struct RedirectGuard {
    backend: Backend,
    port: u16,
    params: RedirectParams,
    accept: Option<tokio::task::JoinHandle<()>>,
}

enum Backend {
    Nftables,
    Iptables,
    None,
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if let Some(t) = self.accept.take() {
            t.abort();
        }
        match self.backend {
            Backend::Nftables => {
                // sing-tun cleanupNFTables: drop whole table
                let _ = delete_nft_table();
                info!("tun: auto-redirect nftables table removed");
            }
            Backend::Iptables => {
                cleanup_iptables(&self.params, self.port);
                info!("tun: auto-redirect iptables rules removed");
            }
            Backend::None => {}
        }
        info!("tun: auto-redirect cleaned up");
    }
}

pub async fn start_auto_redirect(
    p: RedirectParams,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<RedirectGuard> {
    // mihomo binds the redirect server on the IPv6 unspecified address (dual
    // stack) when IPv6 is enabled — an IPv4-only listener would refuse every
    // redirected IPv6 TCP connection.
    let bind: SocketAddr = if p.has_v6 {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let (listener, bound) = crate::app::sockopt::bind_tcp_listener(bind)
        .context("auto-redirect bind redirect listener")?;
    let port = bound.port();
    info!(port, bound = %bound, "tun: auto-redirect internal listener");

    let accept = {
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            accept_loop(listener, router, outbounds).await;
        })
    };

    let backend = match apply_nftables(&p, port) {
        Ok(()) => Backend::Nftables,
        Err(e) => {
            warn!("tun: nftables setup failed ({e:#}), trying iptables fallback");
            if try_iptables(&p, port) {
                info!(port, "tun: auto-redirect via iptables (classic excludes)");
                Backend::Iptables
            } else {
                warn!("tun: auto-redirect netfilter unavailable — TUN stack only");
                Backend::None
            }
        }
    };

    Ok(RedirectGuard {
        backend,
        port,
        params: p,
        accept: Some(accept),
    })
}

async fn accept_loop(listener: TcpListener, router: Arc<Router>, outbounds: Arc<OutboundManager>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
            Err(e) => {
                warn!("auto-redirect accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let router = router.clone();
        let outbounds = outbounds.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::inbound::handle_redir_connection(stream, peer, router, outbounds).await
            {
                tracing::debug!("auto-redirect {peer}: {e:#}");
            }
        });
    }
}

fn delete_nft_table() -> Result<()> {
    use nftables::batch::Batch;
    use nftables::helper;
    use nftables::schema::{NfListObject, Table};
    use nftables::types::NfFamily;
    use std::borrow::Cow;

    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Borrowed("ant"),
        handle: None,
    }));
    let _ = helper::apply_ruleset(&batch.to_nftables());
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "ant"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    Ok(())
}

/// Collect local address set like sing-tun:
/// `lo` prefixes + any **global unicast** on other interfaces.
fn collect_local_addrs(has_v4: bool, has_v6: bool) -> (Vec<String>, Vec<String>) {
    let mut v4 = vec!["127.0.0.0/8".to_string()];
    let mut v6 = vec!["::1/128".to_string()];

    if has_v4 {
        if let Ok(out) = Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // 2: eth0    inet 1.2.3.4/24 ...
                let ifname = parts.get(1).copied().unwrap_or("");
                if let Some(i) = parts.iter().position(|p| *p == "inet") {
                    if let Some(cidr) = parts.get(i + 1) {
                        if (ifname == "lo" || is_global_unicast_v4(cidr))
                            && !v4.iter().any(|x| x == *cidr)
                        {
                            // store host /32 for global, keep lo as given
                            if ifname == "lo" {
                                v4.push((*cidr).to_string());
                            } else if let Some(ip) = cidr.split('/').next() {
                                v4.push(format!("{ip}/32"));
                            }
                        }
                    }
                }
            }
        }
    }

    if has_v6 {
        if let Ok(out) = Command::new("ip")
            .args(["-6", "-o", "addr", "show"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let ifname = parts.get(1).copied().unwrap_or("");
                if let Some(i) = parts.iter().position(|p| *p == "inet6") {
                    if let Some(cidr) = parts.get(i + 1) {
                        if ifname == "lo" || is_global_unicast_v6(cidr) {
                            if let Some(ip) = cidr.split('/').next() {
                                if !v6.iter().any(|x| x.starts_with(ip)) {
                                    v6.push(format!("{ip}/128"));
                                }
                            }
                        }
                    }
                }
            }
        }
        // Always include link-local block so local LLA traffic is not redirected
        if !v6.iter().any(|x| x.starts_with("fe80:")) {
            v6.push("fe80::/10".into());
        }
    }
    (v4, v6)
}

fn is_global_unicast_v4(cidr: &str) -> bool {
    let ip = cidr.split('/').next().unwrap_or(cidr);
    let Ok(a) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    // Exclude unspecified, loopback, link-local, multicast
    !a.is_unspecified() && !a.is_loopback() && !a.is_link_local() && !a.is_multicast()
}

fn is_global_unicast_v6(cidr: &str) -> bool {
    let ip = cidr.split('/').next().unwrap_or(cidr);
    let Ok(a) = ip.parse::<std::net::Ipv6Addr>() else {
        return false;
    };
    // Go netip.IsGlobalUnicast-ish: not unspecified/loopback/multicast/link-local
    if a.is_unspecified() || a.is_loopback() || a.is_multicast() {
        return false;
    }
    let segs = a.segments();
    if (segs[0] & 0xffc0) == 0xfe80 {
        return false; // link-local
    }
    true
}

/// sing-tun setupNFTables classic mode (AutoRedirectMarkMode == false).
fn apply_nftables(p: &RedirectParams, port: u16) -> Result<()> {
    let _ = delete_nft_table();
    let (v4, v6) = collect_local_addrs(p.has_v4, p.has_v6);
    if v4.is_empty() && v6.is_empty() {
        anyhow::bail!("no local addresses for exclude set");
    }

    let v4_elems = v4.join(", ");
    let v6_elems = v6.join(", ");

    // priority mangle ≈ -150; dstnat+1 ≈ -99. Use numeric form for portability.
    //
    // MPTCP: sing-tun drops packets carrying `tcp option mptcp kind 1 present`
    // (redirect breaks MPTCP JOINs). Some nft builds lack the mptcp match —
    // retry without it before falling back to iptables.
    let with_mptcp = build_nft_script(p, port, &v4_elems, &v6_elems, true);
    let without_mptcp = build_nft_script(p, port, &v4_elems, &v6_elems, false);

    let mut last_err = String::new();
    for (label, script) in [("mptcp-drop", &with_mptcp), ("plain", &without_mptcp)] {
        match run_nft_script(script) {
            Ok(()) => {
                info!(
                    port,
                    tun = %p.tun_if,
                    variant = label,
                    local_v4 = v4.len(),
                    local_v6 = v6.len(),
                    "tun: auto-redirect nftables (sing-tun classic)"
                );
                return Ok(());
            }
            Err(e) => last_err = e,
        }
    }
    anyhow::bail!("nft -f: {last_err}")
}

fn run_nft_script(script: &str) -> Result<(), String> {
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
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

fn build_nft_script(
    p: &RedirectParams,
    port: u16,
    v4_elems: &str,
    v6_elems: &str,
    with_mptcp: bool,
) -> String {
    let mptcp_rule = if with_mptcp {
        "    tcp option mptcp kind 1 present counter drop\n"
    } else {
        ""
    };

    // DNS hijack (prerouting only, like sing-tun classic): tcp/udp dport 53
    // → DNAT to the TUN-side DNS address. The redirected packet lands in the
    // TUN device (dst = tun subnet) and the system-stack hijack answers it.
    let mut dns4 = String::new();
    let mut dns6 = String::new();
    if p.dns_hijack {
        if let Some(d) = p.dns_v4.filter(|_| p.has_v4) {
            dns4 = format!(
                "    meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {d}:53\n"
            );
        }
        if let Some(d) = p.dns_v6.filter(|_| p.has_v6) {
            dns6 = format!("    meta nfproto ipv6 meta l4proto {{ tcp, udp }} th dport 53 dnat ip6 to [{d}]:53\n");
        }
    }

    // strict-route: reject the family the TUN does not cover (sing-tun
    // nftablesCreateUnreachable — only fires when exactly one family enabled).
    let mut reject = String::new();
    if p.strict_route {
        if p.has_v4 && !p.has_v6 {
            reject = "    meta nfproto ipv6 counter reject\n".to_string();
        } else if !p.has_v4 && p.has_v6 {
            reject = "    meta nfproto ipv4 counter reject\n".to_string();
        }
    }

    format!(
        r#"table inet ant {{
  set local_v4 {{
    type ipv4_addr
    flags interval
    elements = {{ {v4_elems} }}
  }}
  set local_v6 {{
    type ipv6_addr
    flags interval
    elements = {{ {v6_elems} }}
  }}

  chain output {{
    type nat hook output priority -150; policy accept;
    ip daddr @local_v4 return
    ip6 daddr @local_v6 return
{mptcp_rule}    oifname "{tun}" meta l4proto tcp counter redirect to :{port}
  }}

  chain prerouting {{
    type nat hook prerouting priority -99; policy accept;
    iifname "{tun}" return
{dns4}{dns6}    ip daddr @local_v4 return
    ip6 daddr @local_v6 return
{mptcp_rule}{reject}    meta l4proto tcp counter redirect to :{port}
  }}
}}
"#,
        tun = p.tun_if,
    )
}

/// iptables fallback with the same classic semantics:
/// OUTPUT only redirects traffic leaving via the TUN; PREROUTING redirects
/// forwarded TCP, excluding the TUN itself and local destinations.
fn try_iptables(p: &RedirectParams, port: u16) -> bool {
    let pt = port.to_string();
    let tun = p.tun_if.as_str();
    let (v4, v6) = collect_local_addrs(p.has_v4, p.has_v6);
    let run = |bin: &str, args: &[&str]| -> bool {
        Command::new(bin)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    let mut ok_any = false;
    if p.has_v4 {
        let bin = "iptables";
        let _ = run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-o",
                tun,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                &pt,
            ],
        );
        // Order mirrors sing-tun: tun return → DNS DNAT → local excludes → REDIRECT.
        let _ = run(
            bin,
            &["-t", "nat", "-A", "PREROUTING", "-i", tun, "-j", "RETURN"],
        );
        if p.dns_hijack {
            if let Some(d) = p.dns_v4 {
                let dst = format!("{d}:53");
                let _ = run(
                    bin,
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-p",
                        "udp",
                        "--dport",
                        "53",
                        "-j",
                        "DNAT",
                        "--to",
                        &dst,
                    ],
                );
                let _ = run(
                    bin,
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "--dport",
                        "53",
                        "-j",
                        "DNAT",
                        "--to",
                        &dst,
                    ],
                );
            }
        }
        for cidr in &v4 {
            let _ = run(
                bin,
                &["-t", "nat", "-A", "PREROUTING", "-d", cidr, "-j", "RETURN"],
            );
        }
        let _ = run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "RETURN",
            ],
        );
        ok_any |= run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                &pt,
            ],
        );
    }
    if p.has_v6 {
        let bin = "ip6tables";
        let _ = run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-o",
                tun,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                &pt,
            ],
        );
        let _ = run(
            bin,
            &["-t", "nat", "-A", "PREROUTING", "-i", tun, "-j", "RETURN"],
        );
        if p.dns_hijack {
            if let Some(d) = p.dns_v6 {
                let dst = format!("[{d}]:53");
                let _ = run(
                    bin,
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-p",
                        "udp",
                        "--dport",
                        "53",
                        "-j",
                        "DNAT",
                        "--to",
                        &dst,
                    ],
                );
                let _ = run(
                    bin,
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "--dport",
                        "53",
                        "-j",
                        "DNAT",
                        "--to",
                        &dst,
                    ],
                );
            }
        }
        for cidr in &v6 {
            let _ = run(
                bin,
                &["-t", "nat", "-A", "PREROUTING", "-d", cidr, "-j", "RETURN"],
            );
        }
        let _ = run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "RETURN",
            ],
        );
        ok_any |= run(
            bin,
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                &pt,
            ],
        );
    }
    ok_any
}

fn cleanup_iptables(p: &RedirectParams, port: u16) {
    let pt = port.to_string();
    let tun = p.tun_if.as_str();
    let (v4, v6) = collect_local_addrs(p.has_v4, p.has_v6);
    // Delete only the rules we installed (repeat deletes until gone).
    let locals_v4: Vec<String> = v4;
    let locals_v6: Vec<String> = v6;
    for _ in 0..8 {
        let mut removed = false;
        if p.has_v4 {
            removed |= del_ipt(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-o",
                    tun,
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &pt,
                ],
            );
            removed |= del_ipt(
                "iptables",
                &["-t", "nat", "-A", "PREROUTING", "-i", tun, "-j", "RETURN"],
            );
            for c in &locals_v4 {
                removed |= del_ipt(
                    "iptables",
                    &["-t", "nat", "-A", "PREROUTING", "-d", c, "-j", "RETURN"],
                );
            }
            removed |= del_ipt(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-m",
                    "addrtype",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    "RETURN",
                ],
            );
            if p.dns_hijack {
                if let Some(d) = p.dns_v4 {
                    let dst = format!("{d}:53");
                    removed |= del_ipt(
                        "iptables",
                        &[
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "udp",
                            "--dport",
                            "53",
                            "-j",
                            "DNAT",
                            "--to",
                            &dst,
                        ],
                    );
                    removed |= del_ipt(
                        "iptables",
                        &[
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "tcp",
                            "--dport",
                            "53",
                            "-j",
                            "DNAT",
                            "--to",
                            &dst,
                        ],
                    );
                }
            }
            removed |= del_ipt(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &pt,
                ],
            );
        }
        if p.has_v6 {
            removed |= del_ipt(
                "ip6tables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-o",
                    tun,
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &pt,
                ],
            );
            removed |= del_ipt(
                "ip6tables",
                &["-t", "nat", "-A", "PREROUTING", "-i", tun, "-j", "RETURN"],
            );
            for c in &locals_v6 {
                removed |= del_ipt(
                    "ip6tables",
                    &["-t", "nat", "-A", "PREROUTING", "-d", c, "-j", "RETURN"],
                );
            }
            removed |= del_ipt(
                "ip6tables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-m",
                    "addrtype",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    "RETURN",
                ],
            );
            if p.dns_hijack {
                if let Some(d) = p.dns_v6 {
                    let dst = format!("[{d}]:53");
                    removed |= del_ipt(
                        "ip6tables",
                        &[
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "udp",
                            "--dport",
                            "53",
                            "-j",
                            "DNAT",
                            "--to",
                            &dst,
                        ],
                    );
                    removed |= del_ipt(
                        "ip6tables",
                        &[
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "tcp",
                            "--dport",
                            "53",
                            "-j",
                            "DNAT",
                            "--to",
                            &dst,
                        ],
                    );
                }
            }
            removed |= del_ipt(
                "ip6tables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-p",
                    "tcp",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &pt,
                ],
            );
        }
        if !removed {
            break;
        }
    }
}

/// Delete one rule given exactly the args used to append it (with -A).
/// Returns true when a rule was actually removed.
fn del_ipt(bin: &str, append_args: &[&str]) -> bool {
    let mut args: Vec<&str> = append_args.to_vec();
    // swap -A for -D ("-t nat -A ..." → "-t nat -D ...")
    if let Some(pos) = args.iter().position(|a| *a == "-A") {
        args[pos] = "-D";
    }
    Command::new(bin)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
