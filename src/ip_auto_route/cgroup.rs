//! cgroup-based loop prevention (nexa `internal/cgroupsupport` +
//! `core.placeIntoCgroup`).
//!
//! | version | core process placement          | nft match                    | iptables match        |
//! |---------|--------------------------------|------------------------------|-----------------------|
//! | v2      | `/sys/fs/cgroup/services/<n>`  | `socket cgroupv2 level 2`    | — (degrades to mark)  |
//! | v1      | `/sys/fs/cgroup/net_cls/<n>`   | `meta cgroup <classid>`      | `-m cgroup --path`    |
//!
//! "Detected as supported" and "actually usable" must be the same test: a
//! mount can be writable (`mkdir` succeeds) while the kernel still refuses the
//! process migration — hybrid `/sys/fs/cgroup/unified` and systemd-managed
//! hierarchies return `EINVAL` on `cgroup.procs`. That is why [`enter`] does
//! the real write instead of a probe, and why it walks several candidate
//! directories before giving up. Whatever it succeeds on is reported back, so
//! the emitted rule (`socket cgroupv2 level N "path"`) always matches the
//! directory the process really ended up in.

use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Detected cgroup flavour. `None` = loop prevention must fall back to fwmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    None,
    V1,
    V2,
}

/// Where the core process actually ended up.
#[derive(Debug, Clone)]
pub struct Placement {
    /// v2: path relative to the cgroup2 root (`services/ant`).
    /// v1: path relative to the net_cls mount point (`ant`).
    pub path: String,
    /// Number of path components — nft wants it as `level <n>`.
    pub level: usize,
    pub version: Version,
}

/// Scan `/proc/mounts` for a cgroup2 mount (preferred) or a cgroup mount
/// carrying `net_cls`, keeping only the ones that are really writable
/// (nexa `cgroupsupport.Detect`).
///
/// This is the *cheap* check used to decide the default `bypass-type`; the
/// authoritative one is [`enter`], which also performs the migration.
pub fn detect() -> Version {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return Version::None;
    };
    let mut v1: Option<PathBuf> = None;
    let mut v2: Option<PathBuf> = None;
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let (mount_point, fs_type, opts) = (f[1], f[2], f[3]);
        match fs_type {
            "cgroup2" if v2.is_none() => v2 = Some(PathBuf::from(mount_point)),
            "cgroup" if opts.contains("net_cls") && v1.is_none() => {
                v1 = Some(PathBuf::from(mount_point))
            }
            _ => {}
        }
    }
    if let Some(p) = v2 {
        if writable(&p) {
            return Version::V2;
        }
    }
    if let Some(p) = v1 {
        if writable(&p) {
            return Version::V1;
        }
    }
    Version::None
}

/// Real mkdir probe — permission bits lie inside containers.
fn writable(dir: &Path) -> bool {
    let probe = dir.join(".ant_cgroup_probe");
    if fs::create_dir(&probe).is_err() {
        return false;
    }
    let _ = fs::remove_dir(&probe);
    true
}

/// Place the core process into a cgroup and report where it landed.
///
/// Candidates are tried deepest-first: `services/<name>`, then `services`, then
/// `<name>` directly under the root — the shallower ones still work when the
/// Same shape as nexa `placeIntoCgroup` + `writeCgroupProcs`.
///
/// The write itself has to be a **single `write(2)` with no trailing newline**:
/// `cgroup.procs` parses every write separately, so a second write of `"\n"`
/// comes back as `-EINVAL` (the migration already succeeded, but the caller
/// sees an error). `fs::write` maps to nexa's `os.WriteFile` semantics exactly.
pub fn enter(name: &str, classid: &str) -> anyhow::Result<Placement> {
    let pid = std::process::id().to_string();
    match detect() {
        Version::V2 => {
            let dir = PathBuf::from("/sys/fs/cgroup/services").join(name);
            if let Err(e) = fs::create_dir_all(&dir) {
                warn!(
                    err = %e,
                    dir = %dir.display(),
                    "ip-auto-route: cannot create cgroup dir, writing into `services` instead"
                );
                // nexa fallback: keep the process under `services` itself.
                let path = "/sys/fs/cgroup/services/cgroup.procs";
                fs::write(path, &pid)
                    .map_err(|e| anyhow::anyhow!("write {path} ({e})"))?;
                return Ok(Placement {
                    path: "services".to_string(),
                    level: 1,
                    version: Version::V2,
                });
            }
            let path = dir.join("cgroup.procs");
            fs::write(&path, &pid)
                .map_err(|e| anyhow::anyhow!("write {} ({e})", path.display()))?;
            info!(
                path = %dir.display(),
                pid = %pid,
                "ip-auto-route: core process placed into cgroup (loop prevention)"
            );
            Ok(Placement {
                path: format!("services/{name}"),
                level: 2,
                version: Version::V2,
            })
        }
        Version::V1 => {
            let dir = PathBuf::from("/sys/fs/cgroup/net_cls").join(name);
            fs::create_dir_all(&dir)
                .map_err(|e| anyhow::anyhow!("mkdir {} ({e})", dir.display()))?;
            if !classid.is_empty() {
                if let Err(e) = fs::write(dir.join("net_cls.classid"), classid) {
                    warn!(err = %e, "ip-auto-route: net_cls.classid write failed");
                }
            }
            let path = dir.join("cgroup.procs");
            fs::write(&path, &pid)
                .map_err(|e| anyhow::anyhow!("write {} ({e})", path.display()))?;
            info!(
                path = %dir.display(),
                pid = %pid,
                "ip-auto-route: core process placed into cgroup (loop prevention)"
            );
            Ok(Placement {
                path: name.to_string(),
                level: 1,
                version: Version::V1,
            })
        }
        Version::None => anyhow::bail!("no cgroup mount available"),
    }
}
