//! Proxy namespace (`antns`) ownership.
//!
//! Android reality (AOSP iproute2):
//! - `/run` and `/var/run` usually do not exist or are unusable.
//! - Android's `ip` is compiled with NETNS_RUN_DIR=/mnt/run (or vendor path).
//! - `ip netns add NAME` creates the file under that directory and bind-mounts
//!   the new netns onto it. That is the only reliable way to get a *name*
//!   that later `ip link set ... netns NAME` accepts.
//! - We must discover the real path after `ip netns add` and open that file
//!   for our setns fd.

use anyhow::{Context, Result};
use libc::{CLONE_NEWNET, MSG_CMSG_CLOEXEC};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockProtocol, UnixAddr, recvmsg, sendmsg,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static ANTNS: OnceLock<OwnedFd> = OnceLock::new();
static ENTER_LOCK: Mutex<()> = Mutex::new(());

pub const NETNS_NAME: &str = "antns";

/// Best-effort Android detection (root daemon on phone).
pub fn is_android() -> bool {
    std::path::Path::new("/system/build.prop").exists()
        || std::path::Path::new("/system/bin/app_process").exists()
        || std::env::var_os("ANDROID_ROOT").is_some()
}

/// A fresh fd referring to the proxy namespace (for aya `SkLookup::attach`).
pub fn antns_fd() -> Result<OwnedFd> {
    let ns = ANTNS.get().context("antns not created")?;
    Ok(ns.try_clone()?)
}

/// Create the proxy namespace and retain its fd for the process lifetime.
/// Android keeps the namespace by fd only (its `ip` can't resolve netns names);
/// every other Linux uses the standard named netns (`ip netns add antns`).
pub fn create_antns() -> Result<()> {
    if is_android() {
        create_antns_fd()
    } else {
        create_antns_named()
    }
}

/// Linux: original behaviour, registered by name under /run/netns.
fn create_antns_named() -> Result<()> {
    let _ = run_cmd(&["ip", "netns", "del", NETNS_NAME]);

    // Always use `ip netns add` so the *name* is registered in the way this
    // device's `ip` binary understands. Without it, `ip link set ... netns
    // antns` returns "Invalid netns value" on Android.
    run_cmd(&["ip", "netns", "add", NETNS_NAME]).context(
        "ip netns add antns failed (Android needs a working ip netns)",
    )?;
    tracing::info!("ip netns add {NETNS_NAME} ok");

    // Now find the file that `ip` actually created and open it.
    let path = find_netns_file(NETNS_NAME).context(
        "ip netns add succeeded but the netns file could not be found. \
         Run `find /mnt /data -name antns 2>/dev/null` and report the path.",
    )?;
    tracing::info!(path = %path.display(), "found netns file");

    let f = std::fs::File::open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let fd: OwnedFd = f.into();

    // Sanity: must not be the host netns.
    if is_host_ns(fd.as_raw_fd())? {
        anyhow::bail!(
            "opened {} but it is the host netns (inode match). \
             Android ip netns bind-mount may have failed.",
            path.display()
        );
    }

    ANTNS.set(fd).ok().context("antns already created")?;
    if is_android() {
        tracing::info!("antns ready (android, path={})", path.display());
    }
    Ok(())
}


/// Android: fd-based namespace.
fn create_antns_fd() -> Result<()> {
    // Do NOT rely on a netns *name*: Android's `ip` uses a NETNS_RUN_DIR that
    // varies per ROM, so `ip ... netns antns` / `ip -n antns` fail with
    // "Invalid netns value". An open nsfs fd keeps the namespace alive, and
    // every later operation addresses it by fd / pid (see run_in_antns and
    // move_link_to_antns), never by name.
    let _ = run_cmd(&["ip", "netns", "del", NETNS_NAME]); // stale leftovers, best effort
    let fd = unshare_netns_fd().context("unshare(CLONE_NEWNET) failed")?;

    if is_host_ns(fd.as_raw_fd())? {
        anyhow::bail!("unshare produced the host netns (inode match)");
    }
    ANTNS.set(fd).ok().context("antns already created")?;
    tracing::info!("antns ready (fd-based, no netns name)");
    Ok(())
}

/// Spawn `args` as a child process whose network namespace is `antns`.
fn antns_command(args: &[&str]) -> Result<std::process::Command> {
    use std::os::unix::process::CommandExt;
    let raw = ANTNS.get().context("antns not created")?.as_raw_fd();
    let mut cmd = std::process::Command::new(args[0]);
    cmd.args(&args[1..]);
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(raw, CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

/// Run a command (e.g. `ip ...`, `sysctl ...`) inside antns, by fd.
pub fn run_in_antns(args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = %args.join(" "), "exec in antns");
    let out = antns_command(args)?
        .output()
        .with_context(|| format!("spawn {} in antns", args[0]))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{}` (in antns) failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Move an existing host link into antns using `ip link set DEV netns <pid>`.
/// A numeric pid is accepted by every iproute2 build (it opens /proc/<pid>/ns/net),
/// so this works on Android where the name form does not.
pub fn move_link_to_antns(dev: &str) -> Result<()> {
    if !is_android() {
        return run_cmd(&["ip", "link", "set", dev, "netns", NETNS_NAME])
            .with_context(|| format!("ip link set {dev} netns {NETNS_NAME}"));
    }
    let mut child = antns_command(&["sleep", "30"])?
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn helper process inside antns")?;
    let pid = child.id().to_string();
    let res = run_cmd(&["ip", "link", "set", dev, "netns", &pid]);
    let _ = child.kill();
    let _ = child.wait();
    res.with_context(|| format!("ip link set {dev} netns <pid {pid}>"))
}

/// Locate the file created by `ip netns add <name>` on this device.
fn find_netns_file(name: &str) -> Result<PathBuf> {
    // Paths known to be used by Android / Magisk / KernelSU / AOSP.
    let candidates = [
        format!("/mnt/run/netns/{name}"),
        format!("/mnt/vendor/netns/{name}"),
        format!("/data/vendor/var/run/netns/{name}"),
        format!("/data/adb/netns/{name}"),
        format!("/data/local/tmp/netns/{name}"),
        format!("/run/netns/{name}"),
        format!("/var/run/netns/{name}"),
    ];

    for p in &candidates {
        let path = Path::new(p);
        if path.exists() {
            // Quick check it looks like a netns bind-mount (nsfs).
            if let Ok(meta) = std::fs::metadata(path) {
                // nsfs files are usually small / special; just accept existence.
                let _ = meta;
            }
            return Ok(path.to_path_buf());
        }
    }

    // Slow path: search a few top-level trees (Android root is small).
    for root in ["/mnt", "/data", "/run", "/var"] {
        if let Ok(Some(p)) = walk_for_name(Path::new(root), name, 4) {
            return Ok(p);
        }
    }

    anyhow::bail!("netns file for {name} not found under known Android locations")
}

fn walk_for_name(dir: &Path, name: &str, depth: u32) -> Result<Option<PathBuf>> {
    if depth == 0 || !dir.is_dir() {
        return Ok(None);
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.file_name().and_then(|s| s.to_str()) == Some(name) {
            // Prefer paths that look like .../netns/<name>
            if p.parent()
                .and_then(|par| par.file_name())
                .and_then(|s| s.to_str())
                == Some("netns")
            {
                return Ok(Some(p));
            }
        }
        if p.is_dir() {
            if let Some(found) = walk_for_name(&p, name, depth - 1)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn is_host_ns(fd: RawFd) -> Result<bool> {
    let host = ns_inode_of_current()?;
    let this = ns_inode(fd)?;
    Ok(this == host)
}

fn ns_inode_of_current() -> Result<u64> {
    let f = std::fs::File::open("/proc/thread-self/ns/net")?;
    ns_inode(f.as_raw_fd())
}

fn ns_inode(fd: RawFd) -> Result<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        anyhow::bail!("fstat ns: {}", std::io::Error::last_os_error());
    }
    Ok(st.st_ino)
}

// ---------- helpers kept for with_antns / run_cmd ----------

/// Run `f` inside `antns`, restoring the caller's namespace on all paths.
/// Never call this around an `.await` point: setns(2) is per-thread.
pub fn with_antns<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let ns = ANTNS.get().context("antns not created")?.as_raw_fd();
    let _guard = ENTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let saved = open_current_ns()?;
    let restore = |fd: &OwnedFd| {
        let rc = unsafe { libc::setns(fd.as_raw_fd(), CLONE_NEWNET) };
        rc == 0
    };
    let rc = unsafe { libc::setns(ns, CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!("setns antns: {}", std::io::Error::last_os_error());
    }
    let out = f();
    if !restore(&saved) {
        tracing::error!("failed to restore host netns; aborting");
        std::process::abort();
    }
    out
}

fn open_current_ns() -> Result<OwnedFd> {
    let fd = std::fs::File::open("/proc/thread-self/ns/net").context("open current ns")?;
    Ok(fd.into())
}

pub fn run_cmd(args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = %args.join(" "), "exec");
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("spawn {}", args[0]))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

pub fn run_ip_netns(args: &[&str]) -> Result<()> {
    if is_android() {
        let mut full: Vec<&str> = vec!["ip"];
        full.extend_from_slice(args);
        run_in_antns(&full)
    } else {
        let mut full: Vec<&str> = vec!["ip", "-n", NETNS_NAME];
        full.extend_from_slice(args);
        run_cmd(&full)
    }
}

/// Run an arbitrary command (sysctl, tc, ...) inside antns on either platform.
pub fn exec_in_antns(args: &[&str]) -> Result<()> {
    if is_android() {
        run_in_antns(args)
    } else {
        let mut full: Vec<&str> = vec!["ip", "netns", "exec", NETNS_NAME];
        full.extend_from_slice(args);
        run_cmd(&full)
    }
}

pub fn cleanup(lan: Option<&str>, wan: Option<&str>, proxy_link: &str) {
    for ifc in [lan, wan, Some(proxy_link)].into_iter().flatten() {
        if let Err(e) = run_cmd(&["tc", "qdisc", "del", "dev", ifc, "clsact"]) {
            tracing::debug!("cleanup tc {ifc}: {e:#}");
        }
    }
    if let Err(e) = run_cmd(&["ip", "link", "del", proxy_link]) {
        tracing::debug!("cleanup link {proxy_link}: {e:#}");
    }
    if let Err(e) = run_cmd(&["ip", "netns", "del", NETNS_NAME]) {
        tracing::debug!("cleanup netns: {e:#}");
    }
    let cm = format!("{:#x}/0xffffffff", ant_ebpf_common::CONTROL_MARK);
    for fam in [None, Some("-6")] {
        let mut a: Vec<&str> = vec!["ip"];
        if let Some(f) = fam { a.push(f); }
        a.extend(["rule", "del", "fwmark", &cm, "priority", "40"]);
        while run_cmd(&a).is_ok() {}
    }
    let _ = run_cmd(&["ip", "rule", "del", "to", "169.254.0.0/16", "lookup", "101"]);
    let _ = run_cmd(&["ip", "route", "flush", "table", "101"]);
}

fn unshare_netns_fd() -> Result<OwnedFd> {
    let (a, b) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None::<SockProtocol>,
        nix::sys::socket::SockFlag::empty(),
    )?;
    let handle = std::thread::spawn(move || {
        let rc = unsafe { libc::unshare(CLONE_NEWNET) };
        if rc != 0 {
            anyhow::bail!("unshare(CLONE_NEWNET): {}", std::io::Error::last_os_error());
        }
        let ns_path = std::path::Path::new("/proc/thread-self/ns/net");
        let fd = std::fs::File::open(ns_path).context("open thread-self ns/net")?;
        let fd = fd.as_raw_fd();
        sendmsg::<UnixAddr>(
            b.as_raw_fd(),
            &[std::io::IoSlice::new(&[1u8])],
            &[ControlMessage::ScmRights(&[fd])],
            MsgFlags::empty(),
            None,
        )?;
        anyhow::Ok(())
    });
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("unshare thread panicked"))??;

    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<UnixAddr>(
        a.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::from_bits_truncate(MSG_CMSG_CLOEXEC),
    )?;
    let fd = msg
        .cmsgs()?
        .find_map(|c| match c {
            ControlMessageOwned::ScmRights(fds) => fds.into_iter().next(),
            _ => None,
        })
        .context("no SCM_RIGHTS fd from unshare thread")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
