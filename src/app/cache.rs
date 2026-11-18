//! Persistent cache backed by [redb](https://github.com/cberner/redb).
//!
//! Enabled only when top-level `cache: true` (default false).
//!
//! Tables:
//! - `selected` — proxy-group select choices (group → member)
//! - `dns`      — DNS response cache (domain|qtype → body + expiry)
//! - `fakeip`   — domain → ip string, and `ip:`+ip → domain reverse index
//!
//! Rule-providers always use files and are not stored here.

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

const SELECTED: TableDefinition<'_, &str, &str> = TableDefinition::new("selected");
/// value layout: 8-byte BE expiry unix secs + body bytes
const DNS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("dns");
/// key = domain or "ip:<addr>"; value = ip string or domain
const FAKEIP: TableDefinition<'_, &str, &str> = TableDefinition::new("fakeip");

/// How often buffered DNS / fake-IP writes are committed to disk.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Writes waiting for the next batched commit.
#[derive(Default)]
struct Pending {
    /// dns key -> expiry(8B BE) + body
    dns: HashMap<String, Vec<u8>>,
    /// (domain, ip)
    fakeip: Vec<(String, String)>,
}

/// Shared on-disk cache.
///
/// DNS answers and fake-IP allocations are write-behind: they are buffered and
/// committed in ONE redb transaction every [`FLUSH_INTERVAL`]. A redb commit
/// fsyncs, and in eBPF mode every DNS answer of the whole host flows through
/// here, so committing per query burned CPU and flash I/O (and stalled the
/// async workers) for no benefit. Reads that matter (startup load) see the
/// committed data; the in-memory DNS cache sits in front of this anyway.
pub struct AppCache {
    db: Arc<Database>,
    pending: Arc<Mutex<Pending>>,
}

/// Commit everything buffered in a single transaction.
fn flush_pending(db: &Database, pending: &Mutex<Pending>) {
    let batch = match pending.lock() {
        Ok(mut g) => std::mem::take(&mut *g),
        Err(_) => return,
    };
    if batch.dns.is_empty() && batch.fakeip.is_empty() {
        return;
    }
    let res: Result<()> = (|| {
        let txn = db.begin_write().context("redb begin_write (flush)")?;
        {
            if !batch.dns.is_empty() {
                let mut t = txn.open_table(DNS)?;
                for (k, v) in &batch.dns {
                    t.insert(k.as_str(), v.as_slice())?;
                }
            }
            if !batch.fakeip.is_empty() {
                let mut t = txn.open_table(FAKEIP)?;
                for (domain, ip) in &batch.fakeip {
                    t.insert(domain.as_str(), ip.as_str())?;
                    let rev = format!("ip:{ip}");
                    t.insert(rev.as_str(), domain.as_str())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = res {
        debug!(error = %e, "app cache flush");
    }
}

impl Drop for AppCache {
    fn drop(&mut self) {
        flush_pending(&self.db, &self.pending);
    }
}

impl AppCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create cache dir {parent:?}"))?;
            }
        }
        // redb defaults to a 1 GiB page cache; this store holds a few MB of
        // DNS answers / fake-IP rows, so cap it (resident memory on phones).
        let db = Database::builder()
            .set_cache_size(8 * 1024 * 1024)
            .create(path)
            .with_context(|| format!("open redb cache at {path:?}"))?;
        {
            let txn = db.begin_write().context("redb begin_write (init)")?;
            {
                let _ = txn.open_table(SELECTED)?;
                let _ = txn.open_table(DNS)?;
                let _ = txn.open_table(FAKEIP)?;
            }
            txn.commit().context("redb commit (init)")?;
        }
        info!(path = %path.display(), "app cache ready (redb)");
        let db = Arc::new(db);
        let pending = Arc::new(Mutex::new(Pending::default()));
        {
            let db = db.clone();
            let pending = pending.clone();
            std::thread::Builder::new()
                .name("ant-cache-flush".into())
                .spawn(move || loop {
                    std::thread::sleep(FLUSH_INTERVAL);
                    flush_pending(&db, &pending);
                    // Only this thread still holds `pending` once the cache is
                    // dropped (Drop already flushed): stop.
                    if Arc::strong_count(&pending) == 1 {
                        break;
                    }
                })
                .context("spawn cache flush thread")?;
        }
        Ok(Arc::new(Self { db, pending }))
    }

    // ── select ─────────────────────────────────────────────────────

    pub fn get_selected(&self, group: &str) -> Option<String> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(SELECTED).ok()?;
        match table.get(group) {
            Ok(Some(v)) => Some(v.value().to_string()),
            _ => None,
        }
    }

    pub fn put_selected(&self, group: &str, member: &str) -> Result<()> {
        let txn = self.db.begin_write().context("redb begin_write")?;
        {
            let mut table = txn.open_table(SELECTED)?;
            table.insert(group, member)?;
        }
        txn.commit()?;
        debug!(group, selected = %member, "select cache stored");
        Ok(())
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.get_selected(group)
    }

    pub fn put(&self, group: &str, member: &str) -> Result<()> {
        self.put_selected(group, member)
    }

    // ── DNS response cache ─────────────────────────────────────────

    fn dns_key(domain: &str, qtype: u16) -> String {
        format!("{}|{qtype}", domain.to_ascii_lowercase())
    }

    pub fn dns_get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = Self::dns_key(domain, qtype);
        let buffered = self
            .pending
            .lock()
            .ok()
            .and_then(|g| g.dns.get(&key).cloned());
        let committed;
        let data: &[u8] = if let Some(b) = buffered.as_deref() {
            b
        } else {
            let txn = self.db.begin_read().ok()?;
            let table = txn.open_table(DNS).ok()?;
            let v = table.get(key.as_str()).ok()??;
            committed = v.value().to_vec();
            &committed
        };
        if data.len() < 8 {
            return None;
        }
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&data[..8]);
        let exp = u64::from_be_bytes(exp_bytes);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();
        if now >= exp {
            return None;
        }
        Some(data[8..].to_vec())
    }

    pub fn dns_put(&self, domain: &str, qtype: u16, body: &[u8], ttl: Duration) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now.saturating_add(ttl.as_secs().max(1));
        let mut val = Vec::with_capacity(8 + body.len());
        val.extend_from_slice(&exp.to_be_bytes());
        val.extend_from_slice(body);
        let key = Self::dns_key(domain, qtype);
        if let Ok(mut g) = self.pending.lock() {
            g.dns.insert(key, val);
        }
        Ok(())
    }

    // ── Fake-IP ────────────────────────────────────────────────────

    /// Load all domain↔ip mappings. Returns (domain, ip_str) pairs.
    pub fn fakeip_load_all(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return out,
        };
        let table = match txn.open_table(FAKEIP) {
            Ok(t) => t,
            Err(_) => return out,
        };
        let iter = match table.iter() {
            Ok(i) => i,
            Err(_) => return out,
        };
        for item in iter.flatten() {
            let k = item.0.value().to_string();
            if k.starts_with("ip:") {
                continue;
            }
            let v = item.1.value().to_string();
            out.push((k, v));
        }
        out
    }

    pub fn fakeip_put(&self, domain: &str, ip: &str) -> Result<()> {
        if let Ok(mut g) = self.pending.lock() {
            g.fakeip.push((domain.to_string(), ip.to_string()));
        }
        Ok(())
    }
}
