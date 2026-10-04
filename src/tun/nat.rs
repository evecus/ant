//! TCP NAT table for the system stack (aligned with sing-tun stack_system_nat).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const NAT_PORT_START: u16 = 10000;
const NAT_PORT_END: u16 = 65535;

struct Entry {
    source: SocketAddr,
    destination: SocketAddr,
    last_active: StdMutex<Instant>,
}

pub struct TcpNat {
    /// (src, dst) → nat_port
    addr_map: RwLock<HashMap<(SocketAddr, SocketAddr), u16>>,
    /// nat_port → entry
    port_map: RwLock<HashMap<u16, std::sync::Arc<Entry>>>,
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
    pub async fn lookup_or_insert(&self, src: SocketAddr, dst: SocketAddr) -> Option<u16> {
        let key = (src, dst);
        {
            let addr_map = self.addr_map.read().await;
            if let Some(&p) = addr_map.get(&key) {
                if let Some(e) = self.port_map.read().await.get(&p) {
                    if let Ok(mut la) = e.last_active.lock() {
                        *la = Instant::now();
                    }
                }
                return Some(p);
            }
        }

        let mut addr_map = self.addr_map.write().await;
        let mut port_map = self.port_map.write().await;
        if let Some(&p) = addr_map.get(&key) {
            return Some(p);
        }
        let port = self.allocate_port_locked(&port_map)?;
        let entry = std::sync::Arc::new(Entry {
            source: src,
            destination: dst,
            last_active: StdMutex::new(Instant::now()),
        });
        addr_map.insert(key, port);
        port_map.insert(port, entry);
        Some(port)
    }

    fn allocate_port_locked(&self, port_map: &HashMap<u16, std::sync::Arc<Entry>>) -> Option<u16> {
        let total = (NAT_PORT_END as u32) - (NAT_PORT_START as u32) + 1;
        for _ in 0..total {
            let p = self.port_index.fetch_add(1, Ordering::Relaxed);
            let p = if !(NAT_PORT_START..=NAT_PORT_END).contains(&p) {
                self.port_index
                    .store(NAT_PORT_START.wrapping_add(1), Ordering::Relaxed);
                NAT_PORT_START
            } else {
                p
            };
            if !port_map.contains_key(&p) {
                return Some(p);
            }
        }
        None
    }

    pub async fn lookup_back(&self, nat_port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let entry = {
            let port_map = self.port_map.read().await;
            port_map.get(&nat_port).cloned()?
        };
        if let Ok(mut la) = entry.last_active.lock() {
            let now = Instant::now();
            if now.duration_since(*la) > Duration::from_secs(1) {
                *la = now;
            }
        }
        Some((entry.source, entry.destination))
    }

    pub async fn gc(&self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<(u16, (SocketAddr, SocketAddr))> = {
            let port_map = self.port_map.read().await;
            port_map
                .iter()
                .filter(|(_, e)| {
                    e.last_active
                        .lock()
                        .map(|t| now.duration_since(*t) > timeout)
                        .unwrap_or(false)
                })
                .map(|(&p, e)| (p, (e.source, e.destination)))
                .collect()
        };
        if expired.is_empty() {
            return;
        }
        let mut addr_map = self.addr_map.write().await;
        let mut port_map = self.port_map.write().await;
        for (port, key) in expired {
            if let Some(e) = port_map.get(&port) {
                let still = e
                    .last_active
                    .lock()
                    .map(|t| now.duration_since(*t) > timeout)
                    .unwrap_or(false);
                if !still {
                    continue;
                }
            }
            port_map.remove(&port);
            addr_map.remove(&key);
        }
    }
}
