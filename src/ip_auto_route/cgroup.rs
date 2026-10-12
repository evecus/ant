//! cgroup-based loop prevention (nexa `internal/cgroupsupport` +
//! `core.placeIntoCgroup`).
//!
//! Two supported flavours, both matching what the nft / iptables rules can
//! express:
//!
//! | version | core process placement          | nft match                    | iptables match        |
//! |---------|--------------------------------|------------------------------|-----------------------|
//! | v2      | `/sys/fs/cgroup/services/<n>`  | `socket cgroupv2 level 2`    | — (degrades to mark)  |
//! | v1      | `/sys/fs/cgroup/net_cls/<n>`   | `meta cgroup <classid>`      | `-m cgroup --path`    |
//!
//! Detection mirrors nexa exactly: the mount must actually be **writable**
//! (a real `mkdir` probe), because containers frequently show correct
//! permission bits while the kernel refuses the write.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Detected cgroup flavour. `None` = loop prevention must fall back to fwmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    None,
    V1,
    V2,
}

/// Scan `/proc/mounts` for a cgroup2 mount (preferred) or a cgroup mount
/// carrying `net_cls`, keeping only the ones that are really writable
/// (nexa `cgroupsupport.Detect`).
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
            "cgroup2" => {
                if v2.is_none() {
                    v2 = Some(PathBuf::from(mount_point));
                }
            }
            "cgroup" => {
                if opts.contains("net_cls") && v1.is_none() {
                    v1 = Some(PathBuf::from(mount_point));
                }
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

/// Place ant's own PID into the cgroup the firewall rules match on
/// (nexa `placeIntoCgroup`). Without this the `socket cgroupv2` /
/// `meta cgroup` match never hits and loop prevention silently does nothing.
pub fn join(name: &str, version: Version, classid: &str) -> anyhow::Result<()> {
    let root = match version {
        Version::V2 => PathBuf::from("/sys/fs/cgroup/services"),
        Version::V1 => PathBuf::from("/sys/fs/cgroup/net_cls"),
        Version::None => anyhow::bail!("cgroup is not available"),
    };
    let dir = root.join(name);
    let pid = std::process::id();

    // Parent may be read-only (e.g. a delegated sub-cgroup); nexa then writes
    // into the parent itself so the match still resolves.
    if let Err(e) = fs::create_dir_all(&dir) {
        warn!(
            err = %e,
            dir = %dir.display(),
            "ip-auto-route: cannot create cgroup dir, writing into the parent instead"
        );
        write_procs(&root, pid)?;
        return Ok(());
    }
    if version == Version::V1 && !classid.is_empty() {
        if let Err(e) = fs::write(dir.join("net_cls.classid"), classid) {
            warn!(err = %e, "ip-auto-route: net_cls.classid write failed");
        }
    }
    write_procs(&dir, pid)?;
    info!(
        path = %dir.display(),
        pid,
        version = ?version,
        "ip-auto-route: core process placed into cgroup (loop prevention)"
    );
    Ok(())
}

fn write_procs(dir: &Path, pid: u32) -> anyhow::Result<()> {
    let path = dir.join("cgroup.procs");
    let mut f = fs::OpenOptions::new().write(true).open(&path)?;
    writeln!(f, "{pid}")?;
    Ok(())
}
