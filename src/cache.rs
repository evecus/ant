//! Persistent cache backed by redb when compiled with `--features cache`.
//!
//! Enabled at runtime only when top-level `cache: true` (default false).
//! Without the `cache` feature, `AppCache` is a no-op stub so call sites compile.

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "cache")]
mod imp {
    use super::*;
    use redb::{Database, ReadableTable, TableDefinition};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{debug, info};

    const SELECTED: TableDefinition<'_, &str, &str> = TableDefinition::new("selected");
    const RULESETS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("rulesets");
    const RULESET_META: TableDefinition<'_, &str, &str> = TableDefinition::new("ruleset_meta");
    const DNS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("dns");
    const FAKEIP: TableDefinition<'_, &str, &str> = TableDefinition::new("fakeip");

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
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let exp = now.saturating_add(ttl.as_secs().max(1));
            let mut buf = Vec::with_capacity(8 + body.len());
            buf.extend_from_slice(&exp.to_be_bytes());
            buf.extend_from_slice(body);
            let key = Self::dns_key(domain, qtype);
            let txn = self.db.begin_write().context("redb begin_write")?;
            {
                let mut table = txn.open_table(DNS)?;
                table.insert(key.as_str(), buf.as_slice())?;
            }
            txn.commit()?;
            Ok(())
        }

        pub fn fakeip_load_all(&self) -> Vec<(String, String)> {
            let mut out = Vec::new();
            let Ok(txn) = self.db.begin_read() else {
                return out;
            };
            let Ok(table) = txn.open_table(FAKEIP) else {
                return out;
            };
            let Ok(iter) = table.iter() else {
                return out;
            };
            for item in iter.flatten() {
                let k = item.0.value();
                if k.starts_with("ip:") {
                    continue;
                }
                out.push((k.to_string(), item.1.value().to_string()));
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
}

#[cfg(not(feature = "cache"))]
mod imp {
    use super::*;

    /// No-op stub when the `cache` feature is disabled.
    pub struct AppCache;

    impl AppCache {
        pub fn open(_path: impl AsRef<Path>) -> Result<Arc<Self>> {
            anyhow::bail!(
                "persistent cache requires compiling with `--features cache` \
                 (or `--features full`)"
            )
        }
        pub fn get_selected(&self, _group: &str) -> Option<String> {
            None
        }
        pub fn put_selected(&self, _group: &str, _member: &str) -> Result<()> {
            Ok(())
        }
        pub fn get(&self, group: &str) -> Option<String> {
            self.get_selected(group)
        }
        pub fn put(&self, group: &str, member: &str) -> Result<()> {
            self.put_selected(group, member)
        }
        pub fn get_ruleset(&self, _name: &str) -> Option<Vec<u8>> {
            None
        }
        pub fn put_ruleset(&self, _name: &str, _data: &[u8], _meta: Option<&str>) -> Result<()> {
            Ok(())
        }
        pub fn dns_get(&self, _domain: &str, _qtype: u16) -> Option<Vec<u8>> {
            None
        }
        pub fn dns_put(
            &self,
            _domain: &str,
            _qtype: u16,
            _body: &[u8],
            _ttl: Duration,
        ) -> Result<()> {
            Ok(())
        }
        pub fn fakeip_load_all(&self) -> Vec<(String, String)> {
            Vec::new()
        }
        pub fn fakeip_put(&self, _domain: &str, _ip: &str) -> Result<()> {
            Ok(())
        }
    }
}

pub use imp::AppCache;
