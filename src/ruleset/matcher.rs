//! Match engine for rulesets (binary `.ars` or plaintext-compiled).

use super::compiler::domain_to_fst_key;
use super::loader::LoadedRuleSet;
use anyhow::{anyhow, Result};
use fst::Set;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

struct IpRanges<T: Copy + Ord> {
    ranges: Vec<(T, T)>,
}

impl<T: Copy + Ord> IpRanges<T> {
    fn build(cidrs: impl IntoIterator<Item = (T, T)>) -> Self {
        let mut ranges: Vec<(T, T)> = cidrs.into_iter().collect();
        ranges.sort_unstable_by_key(|&(lo, _)| lo);
        let ranges = merge_ranges(ranges);
        Self { ranges }
    }

    #[inline]
    fn contains(&self, addr: T) -> bool {
        if self.ranges.is_empty() {
            return false;
        }
        match self.ranges.partition_point(|&(lo, _)| lo <= addr) {
            0 => false,
            i => {
                let (_, hi) = self.ranges[i - 1];
                addr <= hi
            }
        }
    }
}

fn merge_ranges<T: Copy + Ord>(ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    out.push(ranges[0]);
    for (lo, hi) in ranges.into_iter().skip(1) {
        let last = out.last_mut().unwrap();
        if lo <= last.1 {
            if hi > last.1 {
                last.1 = hi;
            }
        } else {
            out.push((lo, hi));
        }
    }
    out
}

fn ipv4_cidr_to_range(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let base = u32::from(addr);
    if prefix == 0 {
        return (0, u32::MAX);
    }
    let mask = !0u32 << (32 - prefix);
    let lo = base & mask;
    let hi = lo | !mask;
    (lo, hi)
}

fn ipv6_cidr_to_range(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let base = u128::from(addr);
    if prefix == 0 {
        return (0, u128::MAX);
    }
    let mask = !0u128 << (128 - prefix);
    let lo = base & mask;
    let hi = lo | !mask;
    (lo, hi)
}

pub struct RuleSet {
    #[allow(dead_code)]
    pub name: String,
    /// Approximate number of rules loaded (domains + suffixes + keywords + regexes + CIDRs).
    pub rule_count: usize,
    domain_exact: Option<Set<Arc<[u8]>>>,
    domain_suffix: Option<Set<Arc<[u8]>>>,
    keywords: Vec<String>,
    regexes: Option<regex::RegexSet>,
    ipv4: IpRanges<u32>,
    ipv6: IpRanges<u128>,
}

impl RuleSet {
    pub fn from_bytes(name: &str, data: &[u8]) -> Result<Self> {
        let loaded = LoadedRuleSet::from_bytes(data)?;
        Self::from_loaded(name, loaded)
    }

    pub fn from_loaded(name: &str, loaded: LoadedRuleSet) -> Result<Self> {
        let v4_n = loaded.ipv4_cidrs.len();
        let v6_n = loaded.ipv6_cidrs.len();
        let kw_n = loaded.domain_keywords.len();
        let re_n = loaded.domain_regexes.len();

        let domain_exact = if loaded.domain_fst.is_empty() {
            None
        } else {
            let arc: Arc<[u8]> = Arc::from(loaded.domain_fst);
            Some(Set::new(arc).map_err(|e| anyhow!("domain fst: {e}"))?)
        };
        let domain_suffix = if loaded.domain_suffix_fst.is_empty() {
            None
        } else {
            let arc: Arc<[u8]> = Arc::from(loaded.domain_suffix_fst);
            Some(Set::new(arc).map_err(|e| anyhow!("suffix fst: {e}"))?)
        };

        let regexes = if loaded.domain_regexes.is_empty() {
            None
        } else {
            match regex::RegexSet::new(&loaded.domain_regexes) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("ruleset {name}: regex set error: {e}");
                    None
                }
            }
        };

        let ipv4 = IpRanges::build(
            loaded
                .ipv4_cidrs
                .into_iter()
                .map(|(a, p)| ipv4_cidr_to_range(a, p)),
        );
        let ipv6 = IpRanges::build(
            loaded
                .ipv6_cidrs
                .into_iter()
                .map(|(a, p)| ipv6_cidr_to_range(a, p)),
        );

        let rule_count = domain_exact.as_ref().map(|s| s.len()).unwrap_or(0)
            + domain_suffix.as_ref().map(|s| s.len()).unwrap_or(0)
            + kw_n
            + re_n
            + v4_n
            + v6_n;

        Ok(Self {
            name: name.to_string(),
            rule_count,
            domain_exact,
            domain_suffix,
            keywords: loaded.domain_keywords,
            regexes,
            ipv4,
            ipv6,
        })
    }

    /// Build a matcher directly from a plaintext-compiled ruleset (no `.ars` round-trip).
    pub fn from_compiled(name: &str, compiled: super::compiler::CompiledRuleSet) -> Result<Self> {
        use super::compiler::{build_domain_fst, build_suffix_fst};

        let rule_count = compiled.domains.len()
            + compiled.domain_suffixes.len()
            + compiled.domain_keywords.len()
            + compiled.domain_regexes.len()
            + compiled.ipv4_cidrs.len()
            + compiled.ipv6_cidrs.len();

        let domain_exact = {
            let bytes = build_domain_fst(&compiled.domains)?;
            if bytes.is_empty() {
                None
            } else {
                let arc: Arc<[u8]> = Arc::from(bytes);
                Some(Set::new(arc).map_err(|e| anyhow!("domain fst: {e}"))?)
            }
        };
        let domain_suffix = {
            let bytes = build_suffix_fst(&compiled.domain_suffixes)?;
            if bytes.is_empty() {
                None
            } else {
                let arc: Arc<[u8]> = Arc::from(bytes);
                Some(Set::new(arc).map_err(|e| anyhow!("suffix fst: {e}"))?)
            }
        };

        let regexes = if compiled.domain_regexes.is_empty() {
            None
        } else {
            match regex::RegexSet::new(&compiled.domain_regexes) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("ruleset {name}: regex set error: {e}");
                    None
                }
            }
        };

        let ipv4 = IpRanges::build(
            compiled
                .ipv4_cidrs
                .into_iter()
                .map(|(a, p)| ipv4_cidr_to_range(a, p)),
        );
        let ipv6 = IpRanges::build(
            compiled
                .ipv6_cidrs
                .into_iter()
                .map(|(a, p)| ipv6_cidr_to_range(a, p)),
        );

        Ok(Self {
            name: name.to_string(),
            rule_count,
            domain_exact,
            domain_suffix,
            keywords: compiled.domain_keywords,
            regexes,
            ipv4,
            ipv6,
        })
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return false;
        }

        if let Some(set) = &self.domain_exact {
            let key = domain_to_fst_key(&d);
            if set.contains(key.as_bytes()) {
                return true;
            }
        }

        if let Some(set) = &self.domain_suffix {
            if match_suffix_fst(set, &d) {
                return true;
            }
        }

        for k in &self.keywords {
            if d.contains(k) {
                return true;
            }
        }

        if let Some(re) = &self.regexes {
            if re.is_match(&d) {
                return true;
            }
        }

        false
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.ipv4.contains(u32::from(v4)),
            IpAddr::V6(v6) => self.ipv6.contains(u128::from(v6)),
        }
    }

    /// Drop all IPv6 CIDR ranges (used when top-level `ipv6: false`).
    pub fn drop_ipv6(&mut self) {
        self.ipv6 = IpRanges { ranges: Vec::new() };
    }
}

/// Suffix match: for "a.b.google.com" check FST for "com.", "com.google.", ...
fn match_suffix_fst(set: &Set<Arc<[u8]>>, domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return false;
    }
    let mut buf = Vec::with_capacity(domain.len() + 1);
    for i in (0..labels.len()).rev() {
        buf.extend_from_slice(labels[i].as_bytes());
        buf.push(b'.');
        if set.contains(&buf) {
            return true;
        }
    }
    false
}
