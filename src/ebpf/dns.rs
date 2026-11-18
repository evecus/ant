//! DNS helpers for the eBPF relay: re-export ant's DNS engine and provide
//! minimal parsing of question names and A/AAAA answers needed to publish
//! per-IP verdicts into the kernel DOMAIN_ROUTE map.

use std::net::IpAddr;

/// Extract the qname (lower-cased, dot-joined) from a DNS query. Mirrors the
/// parser in `crate::dns::mod` but stays local so the eBPF relay does not
/// depend on its visibility.
pub fn extract_qname(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    while i < msg.len() {
        let len = msg[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            break;
        }
        i += 1;
        if i + len > msg.len() {
            return None;
        }
        let label = std::str::from_utf8(&msg[i..i + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Collect all A (type 1) / AAAA (type 28) addresses from the answer section
/// of a DNS response. Handles name compression pointers in the RDATA (RFC 1035
/// allows a pointer there for CNAME chains, but A/AAAA RDATA is a literal).
pub fn answer_addresses(msg: &[u8]) -> Vec<IpAddr> {
    if msg.len() < 12 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12usize;
    // Skip question section.
    for _ in 0..qdcount {
        let Some(next) = skip_name(msg, off) else { return Vec::new() };
        off = next;
        if off + 4 > msg.len() {
            return Vec::new();
        }
        off += 4;
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some(next) = skip_name(msg, off) else { break };
        off = next;
        if off + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlength = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        let rdata = off + 10;
        if rdata + rdlength > msg.len() {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                let bytes: [u8; 4] = msg[rdata..rdata + 4].try_into().unwrap();
                out.push(IpAddr::V4(std::net::Ipv4Addr::from(bytes)));
            }
            (28, 16) => {
                let bytes: [u8; 16] = msg[rdata..rdata + 16].try_into().unwrap();
                out.push(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        off = rdata + rdlength;
    }
    out
}

/// Advance past a (possibly compressed) domain name starting at `off`.
fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        if off >= msg.len() {
            return None;
        }
        let len = msg[off] as usize;
        if len & 0xc0 == 0xc0 {
            // Compressed name: pointer is 2 bytes, nothing follows in this name.
            return Some(off + 2);
        }
        if len == 0 {
            return Some(off + 1);
        }
        off += 1 + len;
        if off > msg.len() {
            return None;
        }
    }
}
