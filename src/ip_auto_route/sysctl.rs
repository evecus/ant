//! `net.bridge.bridge-nf-call-iptables` handling (nexa `proxy.init:170-185`).
//!
//! When tproxy is used on a machine that also bridges LAN traffic, the bridge
//! netfilter hook re-injects frames into iptables/nftables and breaks the
//! fwmark → policy-routing path. nexa turns the sysctl off while the proxy
//! runs and restores it on cleanup; we do the same, guarded by flag files so a
//! crash does not permanently leave the sysctl disabled.

use super::Params;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;

fn flag_path(key: &str) -> PathBuf {
    let name = format!("ant-{key}.flag");
    std::env::temp_dir().join(name)
}

fn sysctl_get(key: &str) -> Option<String> {
    let out = Command::new("sysctl")
        .args(["-e", "-n", key])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn sysctl_set(key: &str, val: &str) {
    let _ = Command::new("sysctl")
        .args(["-q", "-w", &format!("{key}={val}")])
        .output();
}

fn has_bridge() -> bool {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return false;
    };
    entries.flatten().any(|e| e.path().join("bridge").is_dir())
}

fn module_loaded(name: &str) -> bool {
    match fs::read_to_string("/proc/modules") {
        Ok(s) => s
            .lines()
            .any(|l| l.split_once(' ').map(|(a, _)| a) == Some(name)),
        Err(_) => false,
    }
}

/// Disable bridge-nf while tproxy hijack is active (nexa proxy.init:170-185).
pub fn prepare(p: &Params) {
    if !p.needs_tproxy() || !has_bridge() || !module_loaded("br_netfilter") {
        return;
    }
    for (key, enabled) in [
        ("net.bridge.bridge-nf-call-iptables", true),
        ("net.bridge.bridge-nf-call-ip6tables", p.ipv6),
    ] {
        if !enabled {
            continue;
        }
        if sysctl_get(key).as_deref() != Some("1") {
            continue;
        }
        let flag = flag_path(key);
        if fs::write(&flag, b"1").is_err() {
            continue;
        }
        sysctl_set(key, "0");
        info!(key, "ip-auto-route: temporarily disabled (bridge + tproxy)");
    }
}

/// Restore anything `prepare` turned off. Safe to call unconditionally.
pub fn restore() {
    if !has_bridge() {
        return;
    }
    for key in [
        "net.bridge.bridge-nf-call-iptables",
        "net.bridge.bridge-nf-call-ip6tables",
    ] {
        let flag = flag_path(key);
        if flag.exists() {
            let _ = fs::remove_file(&flag);
            sysctl_set(key, "1");
            info!(key, "ip-auto-route: restored");
        }
    }
}
