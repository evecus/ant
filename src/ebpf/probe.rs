//! Kernel capability probing for the eBPF datapath.
//!
//! Nothing here is fatal: every probe failure degrades the datapath instead
//! of aborting startup (argv0 → comm fallback, no cgroup hooks, and finally
//! "datapath unavailable" → ant keeps running on its nft pipeline).

use std::path::PathBuf;

use super::btf::Btf;

const VMLINUX_BTF_PATHS: [&str; 2] = ["/sys/kernel/btf/vmlinux", "/usr/lib/debug/boot/vmlinux"];
const VMLINUX_BTF_ENV: &str = "ANT_VMLINUX_BTF";

/// Struct offsets needed by the kernel-side argv[0] reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessNameOffsets {
    pub task_mm: u32,
    pub mm_arg_start: u32,
}

/// Everything `EbpfManager::start` needs to know about the running kernel.
#[derive(Debug, Clone, Default)]
pub(super) struct Support {
    pub process_name: Option<ProcessNameOffsets>,
    pub cgroup2: Option<PathBuf>,
    pub kernel: Option<(u32, u32)>,
}

impl Support {
    pub fn detect() -> Self {
        Self {
            process_name: detect_offsets(),
            cgroup2: cgroup2_mount(),
            kernel: kernel_version(),
        }
    }

    /// Minimum bar for the datapath: a modern kernel with BTF. `cgroup`
    /// hooks and argv0 capture are optional extras.
    ///
    /// 5.10 is the hard floor because `wan_egress` reads
    /// `__sk_buff.ingress_ifindex` (added in 5.10); without the WAN egress
    /// role locally-generated traffic would silently escape the datapath,
    /// which is exactly what the four-role layout must prevent.
    pub fn datapath_ok(&self) -> bool {
        matches!(self.kernel, Some((major, minor)) if (major, minor) >= (5, 10))
    }

    /// Whether the `wan_egress`/`wan_ingress` roles may attach (same 5.10
    /// gate as [`Self::datapath_ok`], kept separate so the role matrix can
    /// degrade the WAN half alone on older kernels).
    pub fn wan_egress_ok(&self) -> bool {
        self.datapath_ok()
    }
}

pub(super) fn detect_offsets() -> Option<ProcessNameOffsets> {
    if let Some(path) = std::env::var_os(VMLINUX_BTF_ENV) {
        return find_offsets(&std::fs::read(path).ok()?);
    }
    VMLINUX_BTF_PATHS
        .iter()
        .find_map(|path| find_offsets(&std::fs::read(path).ok()?))
}

fn find_offsets(data: &[u8]) -> Option<ProcessNameOffsets> {
    let btf = Btf::parse(data)?;
    Some(ProcessNameOffsets {
        task_mm: btf.member_offset("task_struct", "mm")?,
        mm_arg_start: btf.member_offset("mm_struct", "arg_start")?,
    })
}

/// First cgroup v2 mount point from `/proc/self/mounts`.
pub(super) fn cgroup2_mount() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[0] == "cgroup2" && fields[2] == "cgroup2" {
            return Some(PathBuf::from(fields[1]));
        }
    }
    None
}

pub(super) fn kernel_version() -> Option<(u32, u32)> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let mut parts = release.trim().split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Raise `RLIMIT_MEMLOCK` so the kernel will accept BPF maps on kernels
/// without memcg-backed accounting (< 5.11).
pub(super) fn bump_memlock_rlimit() {
    // SAFETY: stack-allocated rlimit, libc documented as safe for this use.
    unsafe {
        let mut rlimit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlimit) != 0 {
            return;
        }
        // Leave an already-generous limit alone.
        if rlimit.rlim_cur >= 128 << 20 {
            return;
        }
        rlimit.rlim_cur = 128 << 20;
        rlimit.rlim_max = rlimit.rlim_max.max(rlimit.rlim_cur);
        let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit);
    }
}

/// Current `bpf_ktime_get_ns()` value, approximated from `/proc/uptime`.
///
/// The datapath stamps map entries with the monotonic ktime clock; userspace
/// cannot read that clock directly, so the janitor compares against uptime.
/// Sub-second accuracy is irrelevant next to the one-second refresh interval
/// and the multi-second expiry windows.
pub(super) fn ktime_now_ns() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
        .map(|secs| (secs * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}
