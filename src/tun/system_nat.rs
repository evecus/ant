//! TCP NAT table for the system stack (aligned with sing-tun stack_system_nat).
//!
//! Locks are `std::sync::RwLock`: critical sections never await, and this
//! table is touched on EVERY forwarded TCP packet — avoiding tokio's async
//! lock waker machinery is a measurable CPU win on the Linux packet path.
//!
//! Two further differences from the naive table (both mirror sing-tun
//! `stack_system_nat.go`):
//! - `addr_map` stores the `Arc<Entry>` itself (not just the port), so the
//!   hot `Lookup` path needs ONE read lock instead of `addrMap.RLock` +
//!   `portMap.RLock` + a per-session mutex (sing-tun's `refresh(port)`).
//! - `last_active` is an atomic millisecond stamp with a **1-second refresh
//!   throttle**, exactly like `TCPSession.refresh()`: every packet does a
//!   relaxed load, and only one packet per second writes the shared line.
//!   Under high PPS this removes a mutex acquisition and a cache-line
//!   ping-pong on every forwarded TCP segment.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

const NAT_PORT_START: u16 = 10000;
const NAT_PORT_END: u16 = 65535;
/// sing-tun `TCPSession.refresh()` only bumps LastActive once per second.
const REFRESH_INTERVAL_MS: u64 = 1000;

/// Monotonic clock base; lets us store an `Instant` as `AtomicU64` millis.
static CLOCK_BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline]
fn now_ms() -> u64 {
    CLOCK_BASE.elapsed().as_millis() as u64
}

struct Entry {
    port: u16,
    source: SocketAddr,
    destination: SocketAddr,
    /// Milliseconds since `CLOCK_BASE`, monotonic.
    last_active_ms: AtomicU64,
}

impl Entry {
    fn new(port: u16, source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            port,
            source,
            destination,
            last_active_ms: AtomicU64::new(now_ms()),
        }
    }

    /// 1-second throttled refresh (sing-tun `TCPSession.refresh`).
    #[inline]
    fn refresh(&self) {
        let now = now_ms();
        if now.saturating_sub(self.last_active_ms.load(Ordering::Relaxed))
            >= REFRESH_INTERVAL_MS
        {
            self.last_active_ms.store(now, Ordering::Relaxed);
        }
    }

    #[inline]
    fn expired(&self, now: u64, timeout_ms: u64) -> bool {
        now.saturating_sub(self.last_active_ms.load(Ordering::Relaxed)) > timeout_ms
    }
}

pub struct TcpNat {
    /// (src, dst) → entry (also carries the NAT port).
    addr_map: RwLock<HashMap<(SocketAddr, SocketAddr), Arc<Entry>>>,
    /// nat_port → entry
    port_map: RwLock<HashMap<u16, Arc<Entry>>>,
    port_index: AtomicU16,
}

impl TcpNat {
    pub fn new() -> Self {
        Self {
            addr_map: RwLock::new(HashMap::new()),
            port_map: RwLock::new(HashMap::new()),
            port_index: AtomicU16::new(NAT_PORT_START),
        }
    }

    /// Allocate or reuse a NAT port for (src, dst). Returns None if the pool is full.
    pub fn lookup_or_insert(&self, src: SocketAddr, dst: SocketAddr) -> Option<u16> {
        let key = (src, dst);
        {
            let addr_map = self.addr_map.read().unwrap();
            if let Some(e) = addr_map.get(&key) {
                e.refresh();
                return Some(e.port);
            }
        }

        let mut addr_map = self.addr_map.write().unwrap();
        let mut port_map = self.port_map.write().unwrap();
        // Another task may have inserted the same flow while we upgraded.
        if let Some(e) = addr_map.get(&key) {
            e.refresh();
            return Some(e.port);
        }
        let port = self.allocate_port_locked(&port_map)?;
        let entry = Arc::new(Entry::new(port, src, dst));
        addr_map.insert(key, entry.clone());
        port_map.insert(port, entry);
        Some(port)
    }

    /// Return the current index then advance it, wrapping in
    /// [NAT_PORT_START, NAT_PORT_END]. Equivalent to sing-tun
    /// `allocatePortLocked`, but without a separate `portIndex == 0` branch.
    fn allocate_port_locked(&self, port_map: &HashMap<u16, Arc<Entry>>) -> Option<u16> {
        let total = (NAT_PORT_END - NAT_PORT_START) as u32 + 1;
        for _ in 0..total {
            let p = self
                .port_index
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some(if cur >= NAT_PORT_END {
                        NAT_PORT_START
                    } else {
                        cur + 1
                    })
                })
                .unwrap_or(NAT_PORT_START); // closure never returns None
            if !port_map.contains_key(&p) {
                return Some(p);
            }
        }
        None
    }

    pub fn lookup_back(&self, nat_port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let entry = {
            let port_map = self.port_map.read().unwrap();
            port_map.get(&nat_port).cloned()?
        };
        entry.refresh();
        Some((entry.source, entry.destination))
    }

    pub fn gc(&self, timeout: Duration) {
        let now = now_ms();
        let timeout_ms = timeout.as_millis() as u64;
        let expired: Vec<u16> = {
            let port_map = self.port_map.read().unwrap();
            port_map
                .iter()
                .filter(|(_, e)| e.expired(now, timeout_ms))
                .map(|(&p, _)| p)
                .collect()
        };
        if expired.is_empty() {
            return;
        }
        let mut addr_map = self.addr_map.write().unwrap();
        let mut port_map = self.port_map.write().unwrap();
        for port in expired {
            let Some(e) = port_map.get(&port).cloned() else {
                continue;
            };
            // Re-check under the write lock: the flow may have been refreshed
            // between the scan and now.
            if !e.expired(now, timeout_ms) {
                continue;
            }
            port_map.remove(&port);
            let key = (e.source, e.destination);
            // Only drop the forward mapping if it still points at THIS entry —
            // a new connection may already have reused the same (src, dst).
            if addr_map
                .get(&key)
                .is_some_and(|cur| Arc::ptr_eq(cur, &e))
            {
                addr_map.remove(&key);
            }
        }
    }
}
