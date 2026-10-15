//! nftables ruleset owned by the eBPF datapath (`table inet ant-ebpf`).
//!
//! Completely independent of `ip_auto_route`'s table (`ant-ip-auto-route`) —
//! the two control planes are mutually exclusive by config validation, so
//! only one of the two tables ever exists.
//!
//! ## Chains
//!
//! | chain               | hook                                        | job                                        |
//! |---------------------|---------------------------------------------|--------------------------------------------|
//! | `router_prerouting` | filter prerouting priority `mangle - 1`     | `iifname lo` + hijack mark → **tproxy**    |
//! | `lan_prerouting`    | filter prerouting priority `mangle`         | LAN fallback dispatch                      |
//! | `lan_fallback`      | (jumped)                                    | mark LAN traffic the datapath left alone   |
//! | `dstnat`            | nat prerouting priority `dstnat - 10`       | LAN DNS hijack dispatch                    |
//! | `lan_dns_hijack`    | (jumped)                                    | LAN DNS → `redirect to :dns-port`          |
//! | `nat_output`        | nat output priority `filter`                | local DNS hijack dispatch                  |
//! | `router_dns_hijack` | (jumped)                                    | local DNS → `redirect to :dns-port`        |
//!
//! ## The mark contract
//!
//! The datapath encodes its decision in the skb mark:
//!
//! | decision | mark                                | nft sees                                  |
//! |----------|-------------------------------------|-------------------------------------------|
//! | `proxy`  | `0x80` + action code in bits 16-23  | `mark & 0xff == 0x80` → tproxy            |
//! | `direct` | action code only (low byte zero)    | `mark & 0xff0000 != 0` → skipped, native |
//! | `block`  | (dropped in kernel)                 | never reaches nft                         |
//! | none     | unmarked                            | `mark & 0xff0000 == 0` → legacy mark+tproxy|
//!
//! This is what makes the datapath additive *and* decisive: `direct` flows
//! keep off the tproxy path (honk's native-path semantics), while anything
//! the datapath never looked at (not ready yet, map overflow, unattached
//! interface) still gets the legacy treatment from `lan_fallback`.

use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;
use tracing::info;

use super::route::{FW_MASK, TPROXY_FWMARK};

const TABLE: &str = "ant-ebpf";

/// Datapath action-code window in the skb mark (bits 16-23).
const ACTION_WINDOW: u32 = ant_ebpf_common::ACTION_MARK_MASK;

/// Everything the ruleset needs that is not part of [`super::EbpfConfig`].
pub(super) struct NftParams<'a> {
    /// Effective LAN interfaces (resolved masters) — gates the fallback.
    pub lan_interfaces: &'a [String],
    /// tproxy inbound port (`global.tproxy-port`).
    pub tproxy_port: u16,
    /// DNS listener port; `0` disables the DNS hijack chains.
    pub dns_port: u16,
    /// Whether DNS hijack is enabled at all (`ebpf.dns-hijack`).
    pub dns_hijack: bool,
    /// ant's own SO_MARK (`global.mark`) — the output-side loop guard.
    pub socket_mark: u32,
    /// Whether IPv6 rules are emitted at all.
    pub ipv6: bool,
    /// Reserved IPv4 CIDRs (never hijacked), datapath-owned copy.
    pub reserved4: &'a [&'a str],
    /// Reserved IPv6 CIDRs (never hijacked), datapath-owned copy.
    pub reserved6: &'a [&'a str],
}

/// Install the table (replacing any previous incarnation).
pub(super) fn apply(p: &NftParams) -> Result<()> {
    cleanup();
    let script = build_script(p);
    run_nft(&script).with_context(|| format!("nft apply:\n{script}"))?;
    info!(table = TABLE, "ebpf: nftables applied");
    Ok(())
}

/// Drop the table. Failures are ignored — this is teardown.
pub(super) fn cleanup() {
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

/// `meta mark set meta mark & <umask> | <mark>` — only the low byte is
/// touched, so the action code and foreign marks survive.
fn set_mark(mark: u32, mask: u32) -> String {
    format!(
        "meta mark set meta mark & {} | {}",
        mark_hex(!mask),
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

fn bare<S: AsRef<str>>(elems: &[S]) -> String {
    elems
        .iter()
        .map(|e| e.as_ref())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `set <name> { type <ty>; flags interval; auto-merge; [elements] }` —
/// for IPv4/IPv6 CIDR sets.
fn emit_interval_set(s: &mut String, name: &str, ty: &str, elems: &[&str]) {
    s.push_str(&format!("\tset {name} {{\n\t\ttype {ty}\n"));
    s.push_str("\t\tflags interval\n\t\tauto-merge\n");
    if !elems.is_empty() {
        s.push_str(&format!("\t\telements = {{ {} }}\n", bare(elems)));
    }
    s.push_str("\t}\n\n");
}

/// `set <name> { type <ty>; [elements] }` — for ifname / nf_proto sets
/// (interval flags are meaningless — and rejected — for those types).
fn emit_plain_set(s: &mut String, name: &str, ty: &str, elems: &[String], quote: bool) {
    s.push_str(&format!("\tset {name} {{\n\t\ttype {ty}\n"));
    if !elems.is_empty() {
        let list = if quote { quoted(elems) } else { bare(elems) };
        s.push_str(&format!("\t\telements = {{ {list} }}\n"));
    }
    s.push_str("\t}\n\n");
}

fn build_script(p: &NftParams) -> String {
    let dns_on = p.dns_hijack && p.dns_port > 0;
    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE} {{\n"));

    emit_interval_set(&mut s, "reserved_ip", "ipv4_addr", p.reserved4);
    if p.ipv6 {
        emit_interval_set(&mut s, "reserved_ip6", "ipv6_addr", p.reserved6);
    }
    emit_plain_set(
        &mut s,
        "lan_inbound_device",
        "ifname",
        p.lan_interfaces,
        true,
    );
    if dns_on {
        let nfproto: Vec<String> = if p.ipv6 {
            vec!["ipv4".into(), "ipv6".into()]
        } else {
            vec!["ipv4".into()]
        };
        emit_plain_set(&mut s, "dns_hijack_nfproto", "nf_proto", &nfproto, false);
    }

    // ── router_prerouting: assign the tproxy socket ───────────────────
    // Packets carrying the hijack mark arrive here via `lo` — either
    // policy-routed there (LAN side) or `bpf_redirect`ed by `wan_egress`
    // (locally-generated side). Runs at `mangle - 1`, before `lan_prerouting`.
    s.push_str("\tchain router_prerouting {\n");
    s.push_str("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
    s.push_str(&format!(
        "\t\tiifname \"lo\" meta l4proto {{ tcp, udp }} meta mark & {} == {} tproxy to :{} counter accept\n",
        mark_hex(FW_MASK),
        mark_hex(TPROXY_FWMARK),
        p.tproxy_port
    ));
    s.push_str("\t}\n\n");

    // ── lan_prerouting: fallback dispatch ─────────────────────────────
    s.push_str("\tchain lan_prerouting {\n");
    s.push_str("\t\ttype filter hook prerouting priority mangle; policy accept;\n");
    s.push_str("\t\tiifname @lan_inbound_device counter jump lan_fallback\n");
    s.push_str("\t}\n\n");

    s.push_str("\tchain lan_fallback {\n");
    // Replies of connections the host itself initiated toward LAN clients.
    s.push_str("\t\tct direction reply counter return\n");
    s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n");
    s.push_str("\t\tip daddr @reserved_ip counter return\n");
    if p.ipv6 {
        s.push_str("\t\tip6 daddr @reserved_ip6 counter return\n");
    }
    if dns_on {
        // DNS is owned by the dstnat redirect below — never mark it here.
        s.push_str(
            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return\n",
        );
    }
    // No datapath decision (action window zero): legacy mark + tproxy.
    s.push_str(&format!(
        "\t\tmeta l4proto {{ tcp, udp }} meta mark & {} == 0 {} counter accept\n",
        mark_hex(ACTION_WINDOW),
        set_mark(TPROXY_FWMARK, FW_MASK)
    ));
    s.push_str("\t}\n\n");

    // ── DNS hijack ────────────────────────────────────────────────────
    // `redirect` is a NAT statement, so it lives in regular chains jumped
    // from nat base chains (same shape as `ip_auto_route`).
    if dns_on {
        s.push_str("\tchain dstnat {\n");
        s.push_str("\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n");
        s.push_str("\t\tiifname @lan_inbound_device counter jump lan_dns_hijack\n");
        s.push_str("\t}\n\n");

        s.push_str("\tchain lan_dns_hijack {\n");
        s.push_str(&format!(
            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :{}\n",
            p.dns_port
        ));
        s.push_str("\t}\n\n");

        s.push_str("\tchain nat_output {\n");
        s.push_str("\t\ttype nat hook output priority filter; policy accept;\n");
        if p.socket_mark != 0 {
            // ant's own sockets (SO_MARK) must not have their DNS hijacked.
            s.push_str(&format!(
                "\t\tmeta mark & 0xffffffff == {} counter return\n",
                mark_hex(p.socket_mark)
            ));
        }
        s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n");
        s.push_str(
            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter jump router_dns_hijack\n",
        );
        s.push_str("\t}\n\n");

        s.push_str("\tchain router_dns_hijack {\n");
        s.push_str(&format!(
            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :{}\n",
            p.dns_port
        ));
        s.push_str("\t}\n\n");
    }

    s.push_str("}\n");
    s
}
