//! Host-firewall TUN passthrough — nexa `firewall_include.sh`.
//!
//! In `mode: tun` the TUN device carries hijacked traffic, so the host firewall
//! must accept it. nexa inserts `iifname <tun> counter accept` (input) plus
//! `oifname`/`iifname` (forward) into OpenWrt's `inet fw4` table and falls back
//! to a plain `inet filter` table on generic Linux. Every rule carries a
//! comment so cleanup can find it again.
//!
//! The iptables backend does the equivalent with `filter INPUT/FORWARD -I ACCEPT`
//! inside `iptables.rs`, so this module only runs for the nftables backend.

use super::{Params, COMMENT};
use std::process::Command;
use tracing::{info, warn};

fn nft_out(args: &[&str]) -> Option<String> {
    let out = Command::new("nft").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Prefer OpenWrt `fw4`, fall back to generic `filter`.
fn detect_table() -> Option<&'static str> {
    if nft_out(&["list", "table", "inet", "fw4"]).is_some() {
        return Some("fw4");
    }
    if nft_out(&["list", "table", "inet", "filter"]).is_some() {
        return Some("filter");
    }
    warn!(
        "ip-auto-route: no `inet fw4`/`inet filter` table found; skipping TUN firewall passthrough"
    );
    None
}

pub fn apply(p: &Params) {
    if !p.needs_tun() || p.tun_device.is_empty() {
        return;
    }
    let Some(table) = detect_table() else {
        return;
    };
    let dev = p.tun_device.as_str();
    for (chain, dir) in [
        ("input", "iifname"),
        ("forward", "oifname"),
        ("forward", "iifname"),
    ] {
        let _ = Command::new("nft")
            .args([
                "insert", "rule", "inet", table, chain, dir, dev, "counter", "accept", "comment",
                COMMENT,
            ])
            .output();
    }
    info!(table, device = %dev, "ip-auto-route: TUN firewall passthrough installed");
}

/// Delete every rule carrying our comment from `fw4`/`filter` input+forward.
pub fn cleanup(_p: &Params) {
    for table in ["fw4", "filter"] {
        for chain in ["input", "forward"] {
            let Some(text) = nft_out(&["list", "table", "inet", table]) else {
                continue;
            };
            for handle in handles_with_comment(&text, chain, COMMENT) {
                let _ = Command::new("nft")
                    .args([
                        "delete",
                        "rule",
                        "inet",
                        table,
                        chain,
                        "handle",
                        &handle.to_string(),
                    ])
                    .output();
            }
        }
    }
}

/// Extract rule handles for `chain` whose line contains `comment "<tag>"`
/// (nexa `extractHandlesForComment`).
fn handles_with_comment(listing: &str, chain: &str, tag: &str) -> Vec<u64> {
    let needle = format!("comment \"{tag}\"");
    let header = format!("chain {chain} {{");
    let mut out = Vec::new();
    let mut in_chain = false;
    for line in listing.lines() {
        let t = line.trim();
        if t.starts_with(&header) {
            in_chain = true;
            continue;
        }
        if in_chain && t == "}" {
            in_chain = false;
            continue;
        }
        if in_chain && t.contains(&needle) {
            if let Some(i) = t.rfind("handle ") {
                if let Ok(h) = t[i + "handle ".len()..].trim().parse::<u64>() {
                    if h > 0 {
                        out.push(h);
                    }
                }
            }
        }
    }
    out
}
