//! Persistent cache backed by [redb](https://github.com/cberner/redb).
//!
//! Tables:
//! - `selected`  — proxy-group select choices (group → member)
//! - `rulesets`  — rule-provider payloads (name → raw bytes)
//! - `ruleset_meta` — optional metadata JSON (url, format, updated_at)

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

const SELECTED: TableDefinition<'_, &str, &str> = TableDefinition::new("selected");
const RULESETS: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("rulesets");
const RULESET_META: TableDefinition<'_, &str, &str> = TableDefinition::new("ruleset_meta");

/// Shared on-disk cache (select groups + rule-providers).
pub struct AppCache {
    db: Database,
    path: PathBuf,
}

impl AppCache {
    /// Open or create a redb file at `path`. Parent dirs are created if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create cache dir {parent:?}"))?;
            }
        }
        let db = Database::create(&path)
            .with_context(|| format!("open redb cache at {path:?}"))?;
        {
            let txn = db.begin_write().context("redb begin_write (init)")?;
            {
                let _ = txn.open_table(SELECTED)?;
                let _ = txn.open_table(RULESETS)?;
                let _ = txn.open_table(RULESET_META)?;
            }
            txn.commit().context("redb commit (init)")?;
        }
        info!(path = %path.display(), "app cache ready (redb)");
        Ok(Arc::new(Self { db, path }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── select groups ──────────────────────────────────────────────

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

    // ── rule-providers ─────────────────────────────────────────────

    pub fn get_ruleset(&self, name: &str) -> Option<Vec<u8>> {
        let txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "ruleset cache read txn failed");
                return None;
            }
        };
        let table = match txn.open_table(RULESETS) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "ruleset cache open_table failed");
                return None;
            }
        };
        match table.get(name) {
            Ok(Some(v)) => {
                let data = v.value().to_vec();
                debug!(name, bytes = data.len(), "ruleset cache hit");
                Some(data)
            }
            Ok(None) => None,
            Err(e) => {
                warn!(name, error = %e, "ruleset cache get failed");
                None
            }
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
        debug!(name, bytes = data.len(), "ruleset cache stored");
        Ok(())
    }

    pub fn get_ruleset_meta(&self, name: &str) -> Option<String> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(RULESET_META).ok()?;
        match table.get(name) {
            Ok(Some(v)) => Some(v.value().to_string()),
            _ => None,
        }
    }
}

/// Backward-compatible alias used by select-group code.
pub type SelectCache = AppCache;

impl AppCache {
    pub fn get(&self, group: &str) -> Option<String> {
        self.get_selected(group)
    }
    pub fn put(&self, group: &str, member: &str) -> Result<()> {
        self.put_selected(group, member)
    }
}
