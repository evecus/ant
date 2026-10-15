//! Translate ant's route table into the datapath's LPM trie.
//!
//! Only `IP-CIDR` / `IP-CIDR6` rules can be decided in kernel (the datapath
//! sees nothing but the packet's destination address). Everything else —
//! domains, regex, rulesets, source-CIDR, sniffing — stays in userspace.
//!
//! ## First-match vs longest-prefix
//!
//! ant (mihomo-style) evaluates rules **in order** and the first match wins;
//! an LPM trie always returns the *longest* prefix. The two agree except
//! when an earlier rule has a shorter prefix that already contains a later,
//! longer one — in that case the later rule can never match under ant's
//! semantics either, so [`build`] simply drops it.
//!
//! ## MATCH
//!
//! The catch-all is only published when **every** rule is an IP-CIDR rule
//! (or `MATCH` itself). As soon as a domain/ruleset/source rule exists, an
//! unmatched flow might still be captured by it, so the datapath's default
//! becomes `proxy`: the flow goes to the tproxy inbound and userspace makes
//! the real call.

use aya::maps::lpm_trie::Key;
use ipnet::IpNet;
use tracing::warn;

use ant_ebpf_common::{RouteAction, RouteDecision, dae_ip::In6Addr};

use crate::app::router::{Outbound, Router};
use crate::config::RuleKind;

/// A publishable routing table for the datapath.
#[derive(Clone)]
pub(super) struct RouteTable {
    pub entries: Vec<(Key<[u32; 4]>, RouteDecision)>,
    pub default: RouteDecision,
}

impl RouteTable {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// rule_id used for the reserved (never-hijacked) destinations ant's nft
/// pipeline returns early for.
const RESERVED_RULE_ID: u32 = u32::MAX;

/// Build the table from the live router. `ipv6` mirrors `global.ipv6`: when
/// disabled, IPv6 CIDRs are dropped so v6 flows fall through to the default
/// (userspace) decision.
///
/// `reserved` entries are published **first**: ant's nft chains start with
/// `ip daddr @reserved_ip return`, so private/special destinations are never
/// hijacked no matter what the rules say. Without them the datapath would
/// happily mark LAN-to-LAN traffic or the replies coming back to LAN clients.
pub(super) fn build(router: &Router, ipv6: bool, reserved: &[&str]) -> RouteTable {
    let mut entries: Vec<(Key<[u32; 4]>, RouteDecision)> = Vec::new();
    let mut published: Vec<IpNet> = Vec::new();
    let mut ip_cidr_only = true;

    for spec in reserved {
        let net = match spec.trim().parse::<IpNet>() {
            Ok(net) => net,
            Err(e) => {
                warn!("ebpf: skipping unparsable reserved CIDR `{spec}`: {e}");
                continue;
            }
        };
        // The v4-mapped block belongs to the IPv4 reserved list; publishing it
        // here would match every IPv4 destination.
        if net.addr().is_ipv6() && is_v4_mapped_block(net) {
            continue;
        }
        if net.addr().is_ipv6() && !ipv6 {
            continue;
        }
        entries.push((
            lpm_key(net),
            RouteDecision {
                action: RouteAction::Direct as u8,
                pad: [0; 3],
                rule_id: RESERVED_RULE_ID,
            },
        ));
        published.push(net);
    }

    for (index, entry) in router.routes().iter().enumerate() {
        // 0 is reserved for "no rule" (the MATCH default).
        let rule_id = index as u32 + 1;
        match &entry.kind {
            RuleKind::IpCidr(spec) => {
                let net = match spec.trim().parse::<IpNet>() {
                    Ok(net) => net,
                    Err(e) => {
                        warn!("ebpf: skipping unparsable IP-CIDR `{spec}`: {e}");
                        ip_cidr_only = false;
                        continue;
                    }
                };
                if net.addr().is_ipv6() && !ipv6 {
                    continue;
                }
                if published.iter().any(|p| prefix_contains(*p, net)) {
                    // Dead rule under first-match semantics (shadowed by an
                    // earlier, shorter prefix).
                    continue;
                }
                entries.push((
                    lpm_key(net),
                    RouteDecision {
                        action: classify(&entry.outbound) as u8,
                        pad: [0; 3],
                        rule_id,
                    },
                ));
                published.push(net);
            }
            RuleKind::Match => {}
            _ => ip_cidr_only = false,
        }
    }

    let default_action = if ip_cidr_only {
        classify(router.final_outbound())
    } else {
        // Rules the datapath cannot see exist: defer to userspace.
        RouteAction::Proxy
    };

    RouteTable {
        entries,
        default: RouteDecision {
            action: default_action as u8,
            pad: [0; 3],
            rule_id: 0,
        },
    }
}

/// Map an ant outbound onto a datapath action. A named node means "this flow
/// belongs to a proxy": the datapath marks it and userspace picks the node.
fn classify(outbound: &Outbound) -> RouteAction {
    match outbound {
        Outbound::Direct => RouteAction::Direct,
        Outbound::Block => RouteAction::Block,
        Outbound::Node(_) => RouteAction::Proxy,
    }
}

/// `p` is a super-prefix of (or equal to) `net`.
fn prefix_contains(p: IpNet, net: IpNet) -> bool {
    p.prefix_len() <= net.prefix_len() && p.contains(&net.network())
}

/// `::ffff:0:0/96` — the IPv4-mapped block, which the unified trie uses to
/// store IPv4 destinations.
fn is_v4_mapped_block(net: IpNet) -> bool {
    match net {
        IpNet::V6(v6) => v6.network().segments()[..5] == [0, 0, 0, 0, 0xffff],
        IpNet::V4(_) => false,
    }
}

/// LPM trie key for a CIDR. IPv4 is stored IPv4-mapped, so its prefix length
/// carries the 96-bit mapping offset.
///
/// The trie compares `data` byte-wise, so each word must hold its four
/// network-order bytes in *memory* order — that is `from_ne_bytes`, not
/// `from_be_bytes`. The datapath builds the same key from
/// `In6Addr::u6_addr32`; the tests pin the two sides together.
fn lpm_key(net: IpNet) -> Key<[u32; 4]> {
    match net {
        IpNet::V4(v4) => {
            // Built through the same helper the datapath uses, so the
            // `::ffff` mapping marker is never forgotten (a key without it
            // can never match an IPv4-mapped lookup key).
            let mapped = In6Addr::from_ipv4_bytes(v4.network().octets());
            Key::new(u32::from(v4.prefix_len()) + 96, unsafe { mapped.u6_addr32 })
        }
        IpNet::V6(v6) => {
            let octets = v6.network().octets();
            Key::new(u32::from(v6.prefix_len()), unsafe {
                In6Addr::from_ipv6_bytes(octets).u6_addr32
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The datapath builds lookup keys by copying `In6Addr::u6_addr32`, so
    /// these two assertions are what keep userspace and BPF in sync.
    #[test]
    fn ipv4_key_matches_datapath_representation() {
        use ant_ebpf_common::dae_ip::In6Addr;

        let net: IpNet = "10.1.2.0/24".parse().unwrap();
        let key = lpm_key(net);
        assert_eq!(key.prefix_len(), 96 + 24);
        let expected = In6Addr::from_ipv4_bytes([10, 1, 2, 0]);
        assert_eq!(key.data(), unsafe { expected.u6_addr32 });
    }

    #[test]
    fn ipv6_key_matches_datapath_representation() {
        use ant_ebpf_common::dae_ip::In6Addr;

        let net: IpNet = "2001:db8::/32".parse().unwrap();
        let key = lpm_key(net);
        assert_eq!(key.prefix_len(), 32);
        let expected = In6Addr::from_ipv6_bytes(net.addr().to_string().parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(key.data(), unsafe { expected.u6_addr32 });
    }

    #[test]
    fn shadowed_rules_are_dropped() {
        let early: IpNet = "10.0.0.0/8".parse().unwrap();
        let late: IpNet = "10.1.0.0/16".parse().unwrap();
        assert!(prefix_contains(early, late));
        assert!(!prefix_contains(late, early));
    }
}
