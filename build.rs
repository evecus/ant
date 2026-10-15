//! Build script.
//!
//! With `--features ebpf` this compiles `src/ebpf/program` with the pinned
//! nightly toolchain (the `bpfel-unknown-none` target needs
//! `-Zbuild-std=core`), verifies the object really carries a `.BTF` section
//! (aya refuses objects without one), and exports its path as
//! `ANT_EBPF_OBJECT` so `src/ebpf/loader.rs` can `include_bytes!` it.
//!
//! Mirrors honk's strategy; the object is cached and only rebuilt when the
//! BPF sources, the common crate or the pinned toolchain change.

fn main() {
    #[cfg(feature = "ebpf")]
    embed_ebpf_object();
}

#[cfg(feature = "ebpf")]
fn embed_ebpf_object() {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    // Escape hatch for environments without the pinned nightly toolchain or
    // the bpfel-unknown-none target (e.g. a plain `cargo check` on a dev
    // box): emit an empty placeholder object so the userspace crate still
    // typechecks. Loading it at runtime fails loudly — by design, this is
    // only ever used for compile-time verification.
    if std::env::var_os("ANT_EBPF_SKIP_BUILD").is_some() {
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let dest = out_dir.join("ant-ebpf.o");
        std::fs::write(&dest, []).expect("failed to write placeholder eBPF object");
        println!("cargo:warning=ANT_EBPF_SKIP_BUILD set: skipping eBPF object build (placeholder)");
        println!("cargo:rustc-env=ANT_EBPF_OBJECT={}", dest.display());
        return;
    }

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must provide CARGO_MANIFEST_DIR"),
    );
    let ebpf_crate = manifest_dir.join("src/ebpf/program");
    let common_crate = manifest_dir.join("src/ebpf/common");
    let ebpf_target = ebpf_crate.join("target/bpfel-unknown-none/release/ant-ebpf");
    let toolchain_file = ebpf_crate.join("rust-toolchain.toml");
    println!("cargo:rerun-if-changed={}", toolchain_file.display());

    let toolchain =
        std::fs::read_to_string(&toolchain_file).expect("failed to read eBPF rust-toolchain.toml");
    let channel = toolchain
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim() == "channel")
        .and_then(|(_, value)| value.trim().strip_prefix('"')?.strip_suffix('"'))
        .filter(|channel| !channel.is_empty())
        .expect("eBPF rust-toolchain.toml must contain a quoted channel");

    /// aya refuses objects without a `.BTF` section ("no BTF parsed for
    /// object"). Cheap guard: section names live verbatim in the section
    /// header string table.
    fn object_has_btf(path: &Path) -> bool {
        std::fs::read(path)
            .map(|data| {
                data.windows(5).any(|w| w == b".BTF\0") || data.windows(5).any(|w| w == b".BTF.")
            })
            .unwrap_or(false)
    }

    /// Newest mtime under `dir` (recursive). The object is built by a
    /// separate cargo invocation, so cargo's own change tracking never
    /// rebuilds it.
    fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
        if dir.is_file() {
            return dir.metadata().ok()?.modified().ok();
        }
        let mut newest = None;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = path.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if newest.is_none_or(|n| mtime > n) {
                            newest = Some(mtime);
                        }
                    }
                }
            }
        }
        newest
    }

    fn object_stale(obj: &Path, src_dirs: &[&Path]) -> bool {
        let Ok(obj_mtime) = obj.metadata().and_then(|m| m.modified()) else {
            return true;
        };
        src_dirs
            .iter()
            .filter_map(|d| newest_mtime(d))
            .any(|src_mtime| src_mtime > obj_mtime)
    }

    let src_dirs = [
        ebpf_crate.join("src"),
        common_crate.join("src"),
        toolchain_file.clone(),
    ];
    let src_dirs: Vec<&Path> = src_dirs.iter().map(|p| p.as_path()).collect();

    let obj = if ebpf_target.exists()
        && object_has_btf(&ebpf_target)
        && std::fs::read_to_string(ebpf_target.with_extension("toolchain"))
            .is_ok_and(|built| built == channel)
        && !object_stale(&ebpf_target, &src_dirs)
    {
        ebpf_target.clone()
    } else {
        println!("cargo:warning=Building eBPF object with {channel}...");
        let status = Command::new("cargo")
            .arg(format!("+{channel}"))
            .args([
                "build",
                "--release",
                "-Zbuild-std=core",
                "--target",
                "bpfel-unknown-none",
            ])
            // Let the selected nightly resolve its own compiler and sysroot.
            .env_remove("RUSTC")
            // An inherited RUSTFLAGS would override the crate's
            // .cargo/config.toml rustflags (--btf, debuginfo) and silently
            // produce a BTF-less object.
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CLIPPY_ARGS")
            .env("CARGO_TARGET_DIR", ebpf_crate.join("target"))
            .current_dir(&ebpf_crate)
            .status()
            .expect("failed to build eBPF object");

        if !status.success() {
            panic!(
                "eBPF build failed. Build it manually:\n  \
                 cd src/ebpf/program && cargo +{channel} build --release \
                 -Zbuild-std=core --target bpfel-unknown-none"
            );
        }
        if !object_has_btf(&ebpf_target) {
            panic!(
                "eBPF object at {} has no .BTF section — aya cannot load it.\n  \
                 cd src/ebpf/program && cargo +{channel} build --release \
                 -Zbuild-std=core --target bpfel-unknown-none",
                ebpf_target.display()
            );
        }
        std::fs::write(ebpf_target.with_extension("toolchain"), channel)
            .expect("failed to record eBPF object toolchain");
        ebpf_target.clone()
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("ant-ebpf.o");
    std::fs::copy(&obj, &dest)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {}", obj.display(), dest.display(), e));

    println!(
        "cargo:rerun-if-changed={}",
        ebpf_crate.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        common_crate.join("src").display()
    );
    println!("cargo:rustc-env=ANT_EBPF_OBJECT={}", dest.display());
}
