//! Active connection tracker for the API panel.
//!
//! Compiled only with `--features api`. Without it, a no-op stub keeps inbound
//! call sites compiling without recording anything.

#[cfg(feature = "api")]
mod full {
use portable_atomic::{AtomicBool, AtomicU64};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

/// Keep recording while the panel has been hit within this window (only used
/// when `api-connection-record: false`).
/// UI polls every 1.5s, so 8s covers a few missed ticks + tab backgrounding.
const WATCH_TTL_MS: u64 = 8_000;

/// How often the sweeper reaps cancelled / orphaned entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Absolute age after which an entry is force-reaped even if not cancelled
/// (safety net for tasks that hang without Drop). 30 minutes.
const MAX_AGE: Duration = Duration::from_secs(30 * 60);

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
    /// Signalled on Leave / force-close so the connection task can exit.
    cancel: CancellationToken,
    /// Set when the entry has been left; sweeper uses this as a secondary check.
    closed: AtomicBool,
}

pub struct Tracker {
    map: Mutex<HashMap<u64, Arc<Live>>>,
    /// Last time the API panel touched us (unix ms). 0 = never.
    last_watch_ms: AtomicU64,
    /// Ensure only one background sweeper is spawned.
    sweeper_started: AtomicBool,
}

impl Tracker {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            last_watch_ms: AtomicU64::new(0),
            sweeper_started: AtomicBool::new(false),
        }
    }

    fn ensure_sweeper(&self) {
        if self
            .sweeper_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let weak: Weak<Tracker> = Arc::downgrade(&global());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(t) = weak.upgrade() else { break };
                t.sweep();
            }
        });
    }

    /// Reap cancelled entries and anything older than MAX_AGE (force-cancel).
    fn sweep(&self) {
        let Ok(mut map) = self.map.lock() else {
            return;
        };
        let before = map.len();
        map.retain(|_, live| {
            if live.closed.load(Ordering::Relaxed) || live.cancel.is_cancelled() {
                return false;
            }
            if live.start.elapsed() > MAX_AGE {
                // Hung session: signal cancel so the task can unwind if it is
                // still running, then drop the map entry to free memory.
                live.cancel.cancel();
                live.closed.store(true, Ordering::Relaxed);
                return false;
            }
            true
        });
        let removed = before.saturating_sub(map.len());
        if removed > 0 {
            tracing::debug!("connection tracker sweep: removed {removed} stale entr(y/ies)");
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

    /// Register a live connection (`Join` in mihomo terms).
    ///
    /// Closed connections are removed by `ConnGuard` on Drop (`Leave`), or by
    /// `close` / `close_all` / the background sweeper.
    pub fn register(&self, info: ConnectionInfo) -> ConnGuard {
        if !self.is_watching() {
            // Release any leftover entries once the panel is closed (opt-in mode).
            if let Ok(mut map) = self.map.try_lock() {
                if !map.is_empty() {
                    for live in map.values() {
                        live.cancel.cancel();
                        live.closed.store(true, Ordering::Relaxed);
                    }
                    map.clear();
                }
            }
            return ConnGuard {
                id: 0,
                cancel: CancellationToken::new(),
                tracker: global(),
            };
        }

        self.ensure_sweeper();

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let live = Arc::new(Live {
            info,
            start: Instant::now(),
            start_wall: SystemTime::now(),
            cancel: cancel.clone(),
            closed: AtomicBool::new(false),
        });
        if let Ok(mut map) = self.map.lock() {
            map.insert(id, live);
        }
        ConnGuard {
            id,
            cancel,
            tracker: global(),
        }
    }

    pub fn list(&self) -> Vec<ConnectionView> {
        // A list request itself counts as watching (relevant for opt-in mode).
        self.touch();
        // Opportunistic reap so the panel never shows dead rows.
        self.sweep();
        let Ok(map) = self.map.lock() else {
            return Vec::new();
        };
        let mut out: Vec<_> = map
            .iter()
            .filter(|(_, live)| {
                !live.closed.load(Ordering::Relaxed) && !live.cancel.is_cancelled()
            })
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

    /// Force-close one connection (mihomo `DELETE /connections/{id}`).
    /// Cancels the session token and removes the map entry immediately.
    pub fn close(&self, id: u64) -> bool {
        if id == 0 {
            return false;
        }
        let live = {
            let Ok(mut map) = self.map.lock() else {
                return false;
            };
            map.remove(&id)
        };
        if let Some(live) = live {
            live.cancel.cancel();
            live.closed.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Force-close every tracked connection (mihomo `DELETE /connections`).
    pub fn close_all(&self) -> usize {
        let entries: Vec<_> = {
            let Ok(mut map) = self.map.lock() else {
                return 0;
            };
            map.drain().map(|(_, live)| live).collect()
        };
        let n = entries.len();
        for live in entries {
            live.cancel.cancel();
            live.closed.store(true, Ordering::Relaxed);
        }
        n
    }

    fn leave(&self, id: u64) {
        if id == 0 {
            return;
        }
        let live = {
            let Ok(mut map) = self.map.lock() else {
                return;
            };
            map.remove(&id)
        };
        if let Some(live) = live {
            live.cancel.cancel();
            live.closed.store(true, Ordering::Relaxed);
        }
    }
}

/// Drop removes the connection from the live list (`Leave` in mihomo terms).
/// Also cancels the session token so any `select!` on `cancelled()` exits.
pub struct ConnGuard {
    id: u64,
    cancel: CancellationToken,
    tracker: Arc<Tracker>,
}

impl ConnGuard {
    /// Resolves when this connection is force-closed via the API or Leave.
    /// Only tproxy (Linux/Android) polls cancellation today; on other platforms
    /// this is dead code and would trip `-D warnings`.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub fn cancelled(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }

    /// Run `fut` until it completes or the connection is cancelled.
    /// On cancel, returns `Err` with a short message so callers unwind and Drop.
    pub async fn while_alive<T, E, F>(&self, fut: F) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: From<std::io::Error>,
    {
        if self.id == 0 {
            // Recording disabled — just run the work.
            return fut.await;
        }
        tokio::select! {
            r = fut => r,
            _ = self.cancel.cancelled() => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "connection closed",
                ).into())
            }
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.leave(self.id);
    }
}

}

#[cfg(feature = "api")]
pub use full::*;

#[cfg(not(feature = "api"))]
mod stub {
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[derive(Debug, Clone)]
    pub struct ConnectionInfo {
        pub peer: SocketAddr,
        pub dest: SocketAddr,
        pub dest_host: Option<String>,
        pub network: &'static str,
        pub inbound: &'static str,
        pub rule: String,
        pub outbound: String,
    }

    pub struct ConnGuard;

    impl ConnGuard {
        pub async fn while_alive<T, E, F>(&self, fut: F) -> Result<T, E>
        where
            F: Future<Output = Result<T, E>>,
        {
            fut.await
        }
    }

    pub struct Tracker;

    impl Tracker {
        pub fn register(&self, _info: ConnectionInfo) -> ConnGuard {
            ConnGuard
        }
    }

    pub fn global() -> Arc<Tracker> {
        use once_cell::sync::Lazy;
        static T: Lazy<Arc<Tracker>> = Lazy::new(|| Arc::new(Tracker));
        T.clone()
    }
}

#[cfg(not(feature = "api"))]
pub use stub::*;
