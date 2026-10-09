//! Detect nftables vs iptables backend (generic Linux; no OpenWrt/fw4 special path).

use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Nftables,
    Iptables,
    None,
}

pub fn detect() -> Backend {
    if has_cmd("nft") {
        // Probe that nft can talk to the kernel.
        let ok = Command::new("nft")
            .args(["list", "tables"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Backend::Nftables;
        }
    }
    if has_cmd("iptables") {
        return Backend::Iptables;
    }
    Backend::None
}

fn has_cmd(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
