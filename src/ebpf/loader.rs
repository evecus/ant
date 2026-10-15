//! Object embedding and loading.
//!
//! `build.rs` compiles `src/ebpf/program` with the nightly BPF toolchain and
//! exports its path as `ANT_EBPF_OBJECT`; the ELF is embedded in the ant
//! binary so a single file is all that gets deployed.

use aya::{Ebpf, EbpfLoader};
use std::convert::TryInto;

use super::probe::ProcessNameOffsets;
use ant_ebpf_common::AntParam;

/// The BPF ELF produced by `build.rs` (with `.BTF`, `classifier` and
/// `cgroup/*` sections).
pub(super) const EBPF_OBJECT: &[u8] = include_bytes!(env!("ANT_EBPF_OBJECT"));

/// Which cgroup program family the kernel accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PnameMode {
    /// `tproxy_cg_*` — reads argv[0] through `current->mm->arg_start`.
    Argv0,
    /// `tproxy_cg_*_comm` — 16-byte thread comm fallback.
    Comm,
}

/// Pick a mode by actually loading the programs, not by trusting a helper
/// probe: some kernels accept the helpers globally but reject them for
/// cgroup programs during verification (same trick honk uses).
pub(super) fn select_pname_mode(offsets: Option<ProcessNameOffsets>) -> PnameMode {
    if offsets.is_some() && probe_pair(offsets, "tproxy_cg_sock_create", "tproxy_cg_connect4") {
        return PnameMode::Argv0;
    }
    PnameMode::Comm
}

fn probe_pair(
    offsets: Option<ProcessNameOffsets>,
    sock_name: &str,
    sock_addr_name: &str,
) -> bool {
    let param = AntParam {
        has_bpf_get_current_task: 1,
        ..AntParam::DEFAULT
    };
    let task_mm_offset = offsets.map(|value| value.task_mm).unwrap_or_default();
    let mm_arg_start_offset = offsets.map(|value| value.mm_arg_start).unwrap_or_default();
    let mut loader = EbpfLoader::new();
    loader
        .override_global("PARAM", &param, true)
        .override_global("TASK_MM_OFFSET", &task_mm_offset, true)
        .override_global("MM_ARG_START_OFFSET", &mm_arg_start_offset, true);
    let mut bpf = match loader.load(EBPF_OBJECT) {
        Ok(bpf) => bpf,
        Err(_) => return false,
    };
    let sock_ok = bpf
        .program_mut(sock_name)
        .and_then(|program| {
            let program: &mut aya::programs::CgroupSock = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some();
    if !sock_ok {
        return false;
    }
    bpf.program_mut(sock_addr_name)
        .and_then(|program| {
            let program: &mut aya::programs::CgroupSockAddr = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some()
}

/// Load the object with the resolved parameters patched into its globals.
pub(super) fn load(
    param: AntParam,
    offsets: Option<ProcessNameOffsets>,
    mode: PnameMode,
) -> anyhow::Result<Ebpf> {
    let has_task = u8::from(matches!(mode, PnameMode::Argv0));
    let param = AntParam {
        has_bpf_get_current_task: has_task,
        ..param
    };
    let task_mm_offset = offsets.map(|value| value.task_mm).unwrap_or_default();
    let mm_arg_start_offset = offsets.map(|value| value.mm_arg_start).unwrap_or_default();

    let mut loader = EbpfLoader::new();
    loader
        .override_global("PARAM", &param, true)
        .override_global("TASK_MM_OFFSET", &task_mm_offset, true)
        .override_global("MM_ARG_START_OFFSET", &mm_arg_start_offset, true);

    let bpf = loader
        .load(EBPF_OBJECT)
        .map_err(|e| anyhow::anyhow!("load eBPF object: {e}"))?;
    Ok(bpf)
}
