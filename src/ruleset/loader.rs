//! Parse `.ars` binary into raw section data.

use super::format::*;
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default)]
pub struct LoadedRuleSet {
    pub domain_fst: Vec<u8>,
    pub domain_suffix_fst: Vec<u8>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
}

impl LoadedRuleSet {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            bail!("ars truncated header");
        }
        if data[0..4] != MAGIC {
            bail!("bad ars magic (expected ARST)");
        }
        let version = data[4];
        if version != VERSION {
            bail!("unsupported ars version {version}");
        }
        let section_count = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
        let mut off = HEADER_LEN;
        let mut out = Self::default();

        for _ in 0..section_count {
            if off + SECTION_HEADER_LEN > data.len() {
                bail!("ars truncated section header");
            }
            let ty_b = data[off];
            let entry_count =
                u32::from_le_bytes(data[off + 1..off + 5].try_into().unwrap()) as usize;
            let byte_len =
                u32::from_le_bytes(data[off + 5..off + 9].try_into().unwrap()) as usize;
            off += SECTION_HEADER_LEN;
            if off + byte_len > data.len() {
                bail!("ars truncated section data");
            }
            let body = &data[off..off + byte_len];
            off += byte_len;

            let ty = SectionType::try_from(ty_b)
                .map_err(|b| anyhow::anyhow!("unknown ars section type 0x{b:02x}"))?;
            match ty {
                SectionType::DomainFst => out.domain_fst = body.to_vec(),
                SectionType::DomainSuffixFst => out.domain_suffix_fst = body.to_vec(),
                SectionType::DomainKeyword => {
                    out.domain_keywords = decode_strings(body)?;
                }
                SectionType::DomainRegex => {
                    out.domain_regexes = decode_strings(body)?;
                }
                SectionType::IpCidrV4 => {
                    out.ipv4_cidrs = decode_ipv4(body, entry_count)?;
                }
                SectionType::IpCidrV6 => {
                    out.ipv6_cidrs = decode_ipv6(body, entry_count)?;
                }
            }
        }
        Ok(out)
    }
}

fn decode_strings(data: &[u8]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            bail!("ars string section truncated");
        }
        let s = std::str::from_utf8(&data[i..i + len])
            .map_err(|_| anyhow::anyhow!("ars invalid utf8"))?
            .to_string();
        out.push(s);
        i += len;
    }
    Ok(out)
}

fn decode_ipv4(data: &[u8], expected: usize) -> Result<Vec<(Ipv4Addr, u8)>> {
    if data.len() != expected * IPV4_ENTRY_LEN {
        bail!(
            "ipv4 section size mismatch: {} vs {} entries",
            data.len(),
            expected
        );
    }
    let mut out = Vec::with_capacity(expected);
    for c in data.as_chunks::<IPV4_ENTRY_LEN>().0 {
        out.push((Ipv4Addr::new(c[0], c[1], c[2], c[3]), c[4]));
    }
    Ok(out)
}

fn decode_ipv6(data: &[u8], expected: usize) -> Result<Vec<(Ipv6Addr, u8)>> {
    if data.len() != expected * IPV6_ENTRY_LEN {
        bail!(
            "ipv6 section size mismatch: {} vs {} entries",
            data.len(),
            expected
        );
    }
    let mut out = Vec::with_capacity(expected);
    for c in data.as_chunks::<IPV6_ENTRY_LEN>().0 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&c[..16]);
        out.push((Ipv6Addr::from(octets), c[16]));
    }
    Ok(out)
}
