//! Policy routing owned by the eBPF datapath.
//!
//! Deliberately **not** `ip_auto_route`'s tables: that module owns table 80
//! (pref 1024) for the tproxy path and 81 (pref 1025) for TUN. The datapath
//! keeps its own table 82 / pref 1026 so the two control planes can never
//! collide, even transiently (e.g. a rolling restart where the old rules
//! have not been swept yet).
//!
//! Shape mirrors `ip_auto_route::route::install_tproxy`, which is nexa's
//! model:
//!
//! ```text
//! ip rule add pref 1026 fwmark 0x80/0xff table 82
//! ip route add local default dev lo table 82
//! ```
//!
//! A packet the datapath marks (`0x80` in the low byte, action code in bits
//! 16-23) matches the rule, is routed "local default dev lo", and arrives at
//! prerouting with `iifname lo` — where the datapath's own nft chain
//! (`ant-ebpf` `router_prerouting`) assigns the tproxy listener socket.
//!
//! Installation shells out to `ip` (like `ip_auto_route`'s teardown): the
//! datapath has no tokio runtime handle at attach time, and `Drop` must be
//! able to clean up synchronously.

use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, info};

/// Policy-routing table the datapath's fwmark rule points at.
pub(super) const ROUTE_TABLE: u32 = 82;

/// Rule preference. `ip_auto_route` uses 1024 (tproxy) and 1025 (tun).
pub(super) const RULE_PREF: u32 = 1026;

/// fwmark the datapath stamps on hijacked traffic (`TPROXY_MARK` in
/// `ant-ebpf-common`, duplicated here so this module stays self-contained).
pub(super) const TPROXY_FWMARK: u32 = 0x0000_0080;

/// Only the low byte is matched, so the action code in bits 16-23 (and any
/// foreign mark bits) never affects the rule.
pub(super) const FW_MASK: u32 = 0x0000_00ff;

/// Install the rule + local-default route (v4, plus v6 when `ipv6`).
pub(super) fn install(ipv6: bool) -> Result<()> {
    for v6 in [false, true] {
        if v6 && !ipv6 {
            continue;
        }
        let fam: &[&str] = if v6 { &["-6"] } else { &["-4"] };

        let rule = run(
            fam,
            &[
                "rule",
                "add",
                "pref",
                &RULE_PREF.to_string(),
                "fwmark",
                &format!("{TPROXY_FWMARK:#x}/{FW_MASK:#x}"),
                "table",
                &ROUTE_TABLE.to_string(),
            ],
        );
        match rule {
            Ok(()) => {}
            Err(e) if is_exists(&e) => {
                debug!("ebpf: fwmark rule pref {RULE_PREF} already present");
            }
            Err(e) => {
                return Err(e.context(format!(
                    "ip{} rule add pref {RULE_PREF} fwmark table {ROUTE_TABLE}",
                    if v6 { " -6" } else { "" }
                )));
            }
        }

        let route = run(
            fam,
            &[
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                &ROUTE_TABLE.to_string(),
            ],
        );
        match route {
            Ok(()) => {}
            Err(e) if is_exists(&e) => {
                debug!(
                    "ebpf: local default route in table {ROUTE_TABLE} already present"
                );
            }
            Err(e) => {
                return Err(e.context(format!(
                    "ip{} route add local default dev lo table {ROUTE_TABLE}",
                    if v6 { " -6" } else { "" }
                )));
            }
        }
    }
    info!(
        table = ROUTE_TABLE,
        pref = RULE_PREF,
        mark = format!("{TPROXY_FWMARK:#x}/{FW_MASK:#x}"),
        "ebpf: policy routing installed"
    );
    Ok(())
}

/// Remove the rule and flush the table. Safe to call when nothing was
/// installed (every failure is ignored — this is teardown).
pub(super) fn cleanup() {
    for fam in [&["-4"][..], &["-6"][..]] {
        let _ = run(
            fam,
            &[
                "rule",
                "del",
                "pref",
                &RULE_PREF.to_string(),
                "table",
                &ROUTE_TABLE.to_string(),
            ],
        );
        // Sweep anything left that points at our table under another pref.
        let _ = run(fam, &["rule", "del", "table", &ROUTE_TABLE.to_string()]);
        let _ = run(fam, &["route", "flush", "table", &ROUTE_TABLE.to_string()]);
    }
    debug!("ebpf: policy routing cleaned up");
}

fn run(fam: &[&str], args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("ip");
    cmd.args(fam).args(args);
    let out = cmd
        .output()
        .with_context(|| format!("spawn ip {} {}", fam.join(" "), args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("{}", stderr.trim());
    }
    Ok(())
}

/// `ip` reports EEXIST as "File exists" on rule/route add.
fn is_exists(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    s.contains("File exists") || s.contains("EEXIST")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_and_pref_avoid_ip_auto_route() {
        // ip_auto_route owns 80/1024 (tproxy) and 81/1025 (tun).
        assert_eq!(ROUTE_TABLE, 82);
        assert_eq!(RULE_PREF, 1026);
        assert_ne!(ROUTE_TABLE, 80);
        assert_ne!(ROUTE_TABLE, 81);
        assert_ne!(RULE_PREF, 1024);
        assert_ne!(RULE_PREF, 1025);
    }

    #[test]
    fn mark_matches_common_constant() {
        assert_eq!(TPROXY_FWMARK, ant_ebpf_common::TPROXY_MARK);
        assert_eq!(FW_MASK, 0xff);
    }
}
