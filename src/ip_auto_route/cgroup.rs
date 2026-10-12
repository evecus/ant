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
/// parent cannot be created (read-only, nested delegation, systemd layout).
pub fn enter(name: &str, classid: &str) -> anyhow::Result<Placement> {
    let pid = std::process::id();
    let mut errors: Vec<String> = Vec::new();

    for root in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        for rel in [
            format!("services/{name}"),
            "services".to_string(),
            name.to_string(),
        ] {
            match try_place(Path::new(root), &rel, pid) {
                Ok(()) => {
                    let level = rel.split('/').filter(|s| !s.is_empty()).count().max(1);
                    return Ok(Placement {
                        path: rel,
                        level,
                        version: Version::V2,
                    });
                }
                Err(e) => errors.push(format!("{root}/{rel}: {e}")),
            }
        }
    }
    // cgroup v1 (net_cls): iptables can express this too, nft uses the classid.
    let v1root = Path::new("/sys/fs/cgroup/net_cls");
    match try_place(v1root, name, pid) {
        Ok(()) => {
            if !classid.is_empty() {
                if let Err(e) = fs::write(v1root.join(name).join("net_cls.classid"), classid) {
                    warn!(err = %e, "ip-auto-route: net_cls.classid write failed");
                }
            }
            return Ok(Placement {
                path: name.to_string(),
                level: 1,
                version: Version::V1,
            });
        }
        Err(e) => errors.push(format!("{}/{name}: {e}", v1root.display())),
    }

    anyhow::bail!("no writable cgroup accepted this process [{}]", errors.join("; "))
}

/// `mkdir -p <root>/<rel>` then write the PID into its `cgroup.procs`.
fn try_place(root: &Path, rel: &str, pid: u32) -> anyhow::Result<()> {
    let dir = root.join(rel);
    fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("mkdir {} ({e})", dir.display()))?;
    write_procs(&dir, pid)?;
    info!(
        path = %dir.display(),
        pid,
        "ip-auto-route: core process placed into cgroup (loop prevention)"
    );
    Ok(())
}

fn write_procs(dir: &Path, pid: u32) -> anyhow::Result<()> {
    let path = dir.join("cgroup.procs");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open {} ({e})", path.display()))?;
    writeln!(f, "{pid}").map_err(|e| anyhow::anyhow!("write {} ({e})", path.display()))?;
    Ok(())
}
