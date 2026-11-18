//! Per-cgroup bypass policy (cgroup v2) for host-originated traffic.
//!
//! The eBPF side matches `bpf_skb_ancestor_cgroup_id()` against CGROUP_RULES;
//! a rule value of CGROUP_MODE_BYPASS means "never capture this cgroup's
//! traffic". A cgroup id is the inode number of its directory; a service
//! restart recreates the directory with a new id, so ids are re-resolved
//! every few seconds and stale ones are removed.
//!
//! Config entries may be a full cgroup path (`system.slice/frps.service`) or
//! a short service name (`frpc`), which expands to `system.slice/frpc.service`.

use super::rules::StaticMaps;
use ant_ebpf_common::CGROUP_MODE_BYPASS;
use anyhow::{Context, Result};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

const REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

struct Entry {
    path: PathBuf,
    /// Id currently published for this rule.
    id: Option<u64>,
}

pub struct CgroupWatcher {
    entries: Vec<Entry>,
}

/// cgroup v2 mount: `/sys/fs/cgroup` (unified) or `.../unified` (hybrid).
fn cgroup_root() -> Result<PathBuf> {
    for p in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        if Path::new(p).join("cgroup.controllers").exists() {
            return Ok(PathBuf::from(p));
        }
    }
    anyhow::bail!("cgroup v2 is not mounted (no cgroup.controllers under /sys/fs/cgroup)")
}

/// Expand a config entry to a cgroup path relative to the cgroup2 root.
/// A bare service name expands to `system.slice/<name>.service`; anything
/// containing `/` or an existing unit suffix is taken as a path verbatim.
fn expand_entry(root: &Path, spec: &str) -> PathBuf {
    let spec = spec.trim().trim_start_matches('/');
    let is_unit_path = spec.contains('/')
        || spec.ends_with(".service")
        || spec.ends_with(".scope")
        || spec.ends_with(".slice");
    let rel = if is_unit_path {
        spec.to_string()
    } else {
        format!("system.slice/{spec}.service")
    };
    root.join(rel)
}

impl CgroupWatcher {
    pub fn new(specs: &[String]) -> Result<Self> {
        let root = cgroup_root()?;
        let mut entries = Vec::new();
        for spec in specs {
            let path = expand_entry(&root, spec);
            let shown = path.display().to_string();
            tracing::debug!(spec, path = %shown, "bypass-cgroup rule");
            entries.push(Entry { path, id: None });
        }
        Ok(CgroupWatcher { entries })
    }

    /// Re-resolve every rule and reconcile the map. Missing paths (service
    /// not running yet) are retried on the next round.
    pub async fn sync(&mut self, maps: &Arc<Mutex<StaticMaps>>) {
        let mut maps = maps.lock().await;
        for i in 0..self.entries.len() {
            let now = std::fs::metadata(&self.entries[i].path)
                .ok()
                .filter(|m| m.is_dir())
                .map(|m| m.ino());
            let old = self.entries[i].id;
            if now == old {
                continue;
            }
            let shared = |id: u64, this: usize, es: &[Entry]| {
                es.iter()
                    .enumerate()
                    .any(|(j, e)| j != this && e.id == Some(id))
            };
            if let Some(old_id) = old {
                if !shared(old_id, i, &self.entries) {
                    let _ = maps.cgroup_rules.remove(&old_id);
                }
            }
            match now {
                Some(id) => match maps.cgroup_rules.insert(id, CGROUP_MODE_BYPASS, 0) {
                    Ok(()) => {
                        tracing::info!(
                            path = %self.entries[i].path.display(),
                            id,
                            "bypass-cgroup rule active"
                        );
                        self.entries[i].id = Some(id);
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %self.entries[i].path.display(),
                            error = %e,
                            "bypass-cgroup insert"
                        );
                        self.entries[i].id = None;
                    }
                },
                None => {
                    tracing::debug!(path = %self.entries[i].path.display(), "cgroup gone; rule inactive");
                    self.entries[i].id = None;
                }
            }
        }
    }
}

/// Initial sync, then keep refreshing in the background.
pub fn start(specs: &[String], maps: Arc<Mutex<StaticMaps>>) -> Result<()> {
    let mut w = CgroupWatcher::new(specs).context("bypass-cgroup rules")?;
    tokio::spawn(async move {
        // Do the first sync inside the task to avoid blocking the caller.
        loop {
            w.sync(&maps).await;
            tokio::time::sleep(REFRESH).await;
        }
    });
    Ok(())
}
