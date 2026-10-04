//! In-memory DNS response cache with LRU eviction.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Entry {
    /// Wire response with transaction ID set to 0; callers patch the ID.
    body: Vec<u8>,
    expires: Instant,
}

pub struct DnsCache {
    inner: Mutex<Inner>,
}

struct Inner {
    map: HashMap<(String, u16), Entry>,
    order: VecDeque<(String, u16)>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                capacity: capacity.max(1),
            }),
        }
    }

    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = (domain.to_ascii_lowercase(), qtype);
        let mut g = self.inner.lock().ok()?;
        let now = Instant::now();
        let entry = g.map.get(&key)?;
        if entry.expires <= now {
            g.map.remove(&key);
            g.order.retain(|k| k != &key);
            return None;
        }
        let body = entry.body.clone();
        // move to most-recently-used
        if let Some(pos) = g.order.iter().position(|k| k == &key) {
            g.order.remove(pos);
        }
        g.order.push_back(key);
        Some(body)
    }

    pub fn put(&self, domain: &str, qtype: u16, mut body: Vec<u8>, ttl: Duration) {
        if domain.is_empty() || body.len() < 12 {
            return;
        }
        // Zero transaction ID so any query ID can be patched in.
        body[0] = 0;
        body[1] = 0;
        let key = (domain.to_ascii_lowercase(), qtype);
        let entry = Entry {
            body,
            expires: Instant::now() + ttl,
        };
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.map.contains_key(&key) {
            g.order.retain(|k| k != &key);
        }
        g.map.insert(key.clone(), entry);
        g.order.push_back(key);
        while g.map.len() > g.capacity {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            } else {
                break;
            }
        }
    }
}

/// Patch transaction ID of a cached response to match the query.
pub fn apply_query_id(resp: &mut [u8], query: &[u8]) {
    if resp.len() >= 2 && query.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
}

/// Minimum TTL among answer RRs (or `default_secs` if none).
pub fn response_ttl_secs(msg: &[u8], default_secs: u32) -> u32 {
    let Some(mut i) = question_end(msg) else {
        return default_secs;
    };
    if msg.len() < 12 {
        return default_secs;
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        let Some(ni) = skip_name(msg, i) else {
            break;
        };
        i = ni;
        if i + 10 > msg.len() {
            break;
        }
        let ttl = u32::from_be_bytes([msg[i + 4], msg[i + 5], msg[i + 6], msg[i + 7]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10 + rdlen;
        if ttl < min_ttl {
            min_ttl = ttl;
        }
    }
    if min_ttl == u32::MAX {
        default_secs
    } else {
        min_ttl.clamp(1, 86400)
    }
}

fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let mut i = 12usize;
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    for _ in 0..qd {
        i = skip_name(msg, i)?;
        if i + 4 > msg.len() {
            return None;
        }
        i += 4;
    }
    Some(i)
}

fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return if i + 2 <= msg.len() {
                Some(i + 2)
            } else {
                None
            };
        }
        i += 1 + len;
    }
}
