//! Persistent cache backed by [redb](https://github.com/cberner/redb).
//!
//! Enabled only when top-level `cache: true` (default false).
//!
//! Tables:
//! - `selected`     — proxy-group select choices (group → member)
//! - `rulesets`     — rule-provider payloads (name → raw bytes)
//! - `ruleset_meta` — optional metadata
//! - `dns`          — DNS response cache (domain|qtype → body + expiry)
//! - `fakeip`       — domain → ip string, and `ip:`+ip → domain reverse index

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

const SELECTED: TableDefinition<'_, &str, &str> = TableDefinition::new("selected");
const RULESETS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("rulesets");
const RULESET_META: TableDefinition<'_, &str, &str> = TableDefinition::new("ruleset_meta");
/// value layout: 8-byte BE expiry unix secs + body bytes
const DNS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("dns");
/// key = domain or "ip:<addr>"; value = ip string or domain
const FAKEIP: TableDefinition<'_, &str, &str> = TableDefinition::new("fakeip");

/// Shared on-disk cache.
pub struct AppCache {
    db: Database,
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
        let db = Database::create(path)
            .with_context(|| format!("open redb cache at {path:?}"))?;
        {
            let txn = db.begin_write().context("redb begin_write (init)")?;
            {
                let _ = txn.open_table(SELECTED)?;
                let _ = txn.open_table(RULESETS)?;
                let _ = txn.open_table(RULESET_META)?;
                let _ = txn.open_table(DNS)?;
                let _ = txn.open_table(FAKEIP)?;
            }
            txn.commit().context("redb commit (init)")?;
        }
        info!(path = %path.display(), "app cache ready (redb)");
        Ok(Arc::new(Self { db }))
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

    // ── rulesets ───────────────────────────────────────────────────

    pub fn get_ruleset(&self, name: &str) -> Option<Vec<u8>> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(RULESETS).ok()?;
        match table.get(name) {
            Ok(Some(v)) => Some(v.value().to_vec()),
            _ => None,
        }
    }

    pub fn put_ruleset(&self, name: &str, data: &[u8], meta: Option<&str>) -> Result<()> {
        let txn = self.db.begin_write().context("redb begin_write")?;
        {
            let mut table = txn.open_table(RULESETS)?;
            table.insert(name, data)?;
        }
        if let Some(m) = meta {
            let mut table = txn.open_table(RULESET_META)?;
            table.insert(name, m)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── DNS response cache ─────────────────────────────────────────

    fn dns_key(domain: &str, qtype: u16) -> String {
        format!("{}|{qtype}", domain.to_ascii_lowercase())
    }

    pub fn dns_get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(DNS).ok()?;
        let key = Self::dns_key(domain, qtype);
        let v = table.get(key.as_str()).ok()??;
        let data = v.value();
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
        let txn = self.db.begin_write().context("redb begin_write")?;
        {
            let mut table = txn.open_table(DNS)?;
            table.insert(key.as_str(), val.as_slice())?;
        }
        txn.commit()?;
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
        let txn = self.db.begin_write().context("redb begin_write")?;
        {
            let mut table = txn.open_table(FAKEIP)?;
            table.insert(domain, ip)?;
            let rev = format!("ip:{ip}");
            table.insert(rev.as_str(), domain)?;
        }
        txn.commit()?;
        Ok(())
    }
}
