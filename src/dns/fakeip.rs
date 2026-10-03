//! Fake-IP allocator. Blacklist mode: every domain gets a fake address unless
//! it hits an exclude ruleset (then the caller uses real DNS). Whitelist mode:
//! only domains hitting a fakeip-filter ruleset get fake addresses.

use anyhow::{bail, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

pub struct FakeIpPool {
    v4: Option<V4Range>,
    v6: Option<V6Range>,
    by_domain4: Mutex<HashMap<String, Ipv4Addr>>,
    by_domain6: Mutex<HashMap<String, Ipv6Addr>>,
    by_ip: Mutex<HashMap<IpAddr, String>>,
}

struct V4Range {
    start: u32,
    end: u32,
    next: Mutex<u32>,
}

struct V6Range {
    start: u128,
    end: u128,
    next: Mutex<u128>,
}

impl FakeIpPool {
    pub fn new(v4: Option<&str>, v6: Option<&str>) -> Result<Self> {
        let v4 = match v4 {
            Some(s) if !s.is_empty() => Some(parse_v4(s)?),
            _ => None,
        };
        let v6 = match v6 {
            Some(s) if !s.is_empty() => Some(parse_v6(s)?),
            _ => None,
        };
        if v4.is_none() && v6.is_none() {
            bail!("fakeip mode requires fakeip-range and/or fakeip6-range");
        }
        Ok(Self {
            v4,
            v6,
            by_domain4: Mutex::new(HashMap::new()),
            by_domain6: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
        })
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }
    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v) => self
                .v4
                .as_ref()
                .map(|r| {
                    let n = u32::from(v);
                    n >= r.start && n <= r.end
                })
                .unwrap_or(false),
            IpAddr::V6(v) => self
                .v6
                .as_ref()
                .map(|r| {
                    let n = u128::from(v);
                    n >= r.start && n <= r.end
                })
                .unwrap_or(false),
        }
    }

    pub fn domain_of(&self, ip: IpAddr) -> Option<String> {
        self.by_ip.lock().ok()?.get(&ip).cloned()
    }

    /// Allocate (or reuse) a fake address for `domain`. `v6` selects family.
    pub fn allocate(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }
        if v6 {
            let ip = self.alloc6(&domain)?;
            Some(IpAddr::V6(ip))
        } else {
            let ip = self.alloc4(&domain)?;
            Some(IpAddr::V4(ip))
        }
    }

    fn alloc4(&self, domain: &str) -> Option<Ipv4Addr> {
        let range = self.v4.as_ref()?;
        let mut map = self.by_domain4.lock().ok()?;
        if let Some(ip) = map.get(domain) {
            return Some(*ip);
        }
        let mut next = range.next.lock().ok()?;
        let span = range.end.saturating_sub(range.start).saturating_add(1);
        if span == 0 {
            return None;
        }
        for _ in 0..span {
            let n = *next;
            *next = if n >= range.end { range.start } else { n + 1 };
            let ip = Ipv4Addr::from(n);
            let mut by_ip = self.by_ip.lock().ok()?;
            if by_ip.contains_key(&IpAddr::V4(ip)) {
                continue;
            }
            by_ip.insert(IpAddr::V4(ip), domain.to_string());
            map.insert(domain.to_string(), ip);
            return Some(ip);
        }
        None
    }

    fn alloc6(&self, domain: &str) -> Option<Ipv6Addr> {
        let range = self.v6.as_ref()?;
        let mut map = self.by_domain6.lock().ok()?;
        if let Some(ip) = map.get(domain) {
            return Some(*ip);
        }
        let mut next = range.next.lock().ok()?;
        // Don't scan the whole /18; try a bounded number of collisions.
        for _ in 0..4096 {
            let n = *next;
            *next = if n >= range.end { range.start } else { n + 1 };
            let ip = Ipv6Addr::from(n);
            let mut by_ip = self.by_ip.lock().ok()?;
            if by_ip.contains_key(&IpAddr::V6(ip)) {
                continue;
            }
            by_ip.insert(IpAddr::V6(ip), domain.to_string());
            map.insert(domain.to_string(), ip);
            return Some(ip);
        }
        None
    }
}

fn parse_v4(s: &str) -> Result<V4Range> {
    let net: IpNet = s.parse().map_err(|e| anyhow::anyhow!("fakeip-range {s}: {e}"))?;
    let IpNet::V4(net) = net else {
        bail!("fakeip-range must be IPv4 CIDR, got {s}");
    };
    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());
    // Skip network/broadcast when the range is large enough.
    let (start, end) = if net.prefix_len() <= 30 {
        (start + 1, end - 1)
    } else {
        (start, end)
    };
    if start > end {
        bail!("fakeip-range {s} has no usable address");
    }
    Ok(V4Range {
        start,
        end,
        next: Mutex::new(start),
    })
}

fn parse_v6(s: &str) -> Result<V6Range> {
    let net: IpNet = s.parse().map_err(|e| anyhow::anyhow!("fakeip6-range {s}: {e}"))?;
    let IpNet::V6(net) = net else {
        bail!("fakeip6-range must be IPv6 CIDR, got {s}");
    };
    let start = u128::from(net.network()) + 1;
    let end = u128::from(net.broadcast());
    if start > end {
        bail!("fakeip6-range {s} has no usable address");
    }
    Ok(V6Range {
        start,
        end,
        next: Mutex::new(start),
    })
}
