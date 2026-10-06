//! Active connection tracker for the API panel.
//!
//! Behaviour is controlled by the top-level config key `api-connection-record`
//! (default **true**):
//!
//! - **true** (default / omitted): always record live connections. The map only
//!   holds currently open sessions; closed connections are removed by `ConnGuard`
//!   on Drop, so the UI never shows dead connections.
//! - **false**: opt-in at runtime — entries are only created while the API UI
//!   (or `/connections`) has been requested recently. Closing the browser stops
//!   registration within a few seconds and clears the map so memory is released.

use portable_atomic::{AtomicBool, AtomicU64};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Keep recording while the panel has been hit within this window (only used
/// when `api-connection-record: false`).
/// UI polls every 1.5s, so 8s covers a few missed ticks + tab backgrounding.
const WATCH_TTL_MS: u64 = 8_000;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Set from config (`api-connection-record`). Default true = always record.
static ALWAYS_RECORD: AtomicBool = AtomicBool::new(true);
static TRACKER: once_cell::sync::Lazy<Arc<Tracker>> =
    once_cell::sync::Lazy::new(|| Arc::new(Tracker::new()));

pub fn global() -> Arc<Tracker> {
    TRACKER.clone()
}

/// Called once at startup from `api::set_config`.
pub fn set_always_record(enabled: bool) {
    ALWAYS_RECORD.store(enabled, Ordering::Relaxed);
}

fn always_record() -> bool {
    ALWAYS_RECORD.load(Ordering::Relaxed)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionView {
    pub id: u64,
    /// 流量类型：tcp / udp / quic（QUIC Initial 嗅探命中时）。
    pub network: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_host: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub inbound: String,
    pub rule: String,
    pub outbound: String,
    pub start_ms: u64,
    pub age_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub peer: SocketAddr,
    pub dest: SocketAddr,
    pub dest_host: Option<String>,
    /// 流量类型："tcp" / "udp" / "quic"。
    pub network: &'static str,
    pub inbound: &'static str,
    pub rule: String,
    pub outbound: String,
}

struct Live {
    info: ConnectionInfo,
    start: Instant,
    start_wall: SystemTime,
}

pub struct Tracker {
    map: Mutex<HashMap<u64, Live>>,
    /// Last time the API panel touched us (unix ms). 0 = never.
    last_watch_ms: AtomicU64,
}

impl Tracker {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            last_watch_ms: AtomicU64::new(0),
        }
    }

    /// Called by the API on `/ui` and `/connections` so inbound paths start
    /// (or keep) recording live sessions when `api-connection-record: false`.
    pub fn touch(&self) {
        self.last_watch_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn is_watching(&self) -> bool {
        if always_record() {
            return true;
        }
        let last = self.last_watch_ms.load(Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        now_ms().saturating_sub(last) < WATCH_TTL_MS
    }

    /// Register a live connection.
    ///
    /// - `api-connection-record: true` (default): always records.
    /// - `false`: only while the panel is being watched; otherwise returns a
    ///   no-op guard (zero heap growth) and clears any leftover entries.
    ///
    /// Closed connections are removed by `ConnGuard` on Drop, so the map only
    /// ever contains currently open sessions.
    pub fn register(&self, info: ConnectionInfo) -> ConnGuard {
        if !self.is_watching() {
            // Release any leftover entries once the panel is closed (opt-in mode).
            if let Ok(mut map) = self.map.try_lock() {
                if !map.is_empty() {
                    map.clear();
                }
            }
            return ConnGuard {
                id: 0,
                tracker: global(),
            };
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let live = Live {
            info,
            start: Instant::now(),
            start_wall: SystemTime::now(),
        };
        self.map.lock().unwrap().insert(id, live);
        ConnGuard {
            id,
            tracker: global(),
        }
    }

    pub fn list(&self) -> Vec<ConnectionView> {
        // A list request itself counts as watching (relevant for opt-in mode).
        self.touch();
        let map = self.map.lock().unwrap();
        let mut out: Vec<_> = map
            .iter()
            .map(|(id, live)| {
                let age = live.start.elapsed();
                let start_ms = live
                    .start_wall
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_millis() as u64;
                let host = live
                    .info
                    .dest_host
                    .clone()
                    .unwrap_or_else(|| live.info.dest.ip().to_string());
                ConnectionView {
                    id: *id,
                    network: live.info.network.to_string(),
                    src_ip: live.info.peer.ip().to_string(),
                    src_port: live.info.peer.port(),
                    dest_host: host,
                    dest_ip: live.info.dest.ip().to_string(),
                    dest_port: live.info.dest.port(),
                    inbound: live.info.inbound.to_string(),
                    rule: live.info.rule.clone(),
                    outbound: live.info.outbound.clone(),
                    start_ms,
                    age_ms: age.as_millis() as u64,
                }
            })
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.id));
        out
    }

    fn unregister(&self, id: u64) {
        if id == 0 {
            return;
        }
        self.map.lock().unwrap().remove(&id);
    }
}

/// Drop removes the connection from the live list (no-op when `id == 0`).
pub struct ConnGuard {
    id: u64,
    tracker: Arc<Tracker>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.unregister(self.id);
    }
}
