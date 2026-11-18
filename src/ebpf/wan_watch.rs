//! Dynamic WAN capture (`auto_wan`), ported from silk's `wan_watch`.
//!
//! A phone switches between wlan0 and rmnet_data*/ccmni* at will, so a single
//! fixed `wan_egress` attachment only works on one of them. This watcher polls
//! the routing tables (default routes on Android live in per-network tables),
//! attaches `wan_egress` to every interface that currently has a default route,
//! detaches from ones that vanished or were re-created (new ifindex), and keeps
//! the control-socket policy rule pointed at the primary network's table.
//!
//! Enabled by `ebpf.wan: dynamic`, or `ebpf.wan: auto` on Android (desktop
//! Linux keeps the fixed default-route interface, matching silk's semantics).

use super::datapath::setup_android_control_route;
use anyhow::{Context, Result};
use aya::programs::{tc::SchedClassifierLinkId, SchedClassifier, TcAttachType};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct WanWatcher {
    ebpf: Arc<Mutex<aya::Ebpf>>,
    attached: HashMap<String, (u32, SchedClassifierLinkId)>,
    primary: Option<String>,
}

impl WanWatcher {
    pub fn new(ebpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { ebpf, attached: HashMap::new(), primary: None }
    }

    /// Reconcile attachments with the interfaces that currently have a default route.
    pub fn sync(&mut self) {
        let ifaces = active_interfaces();

        let stale: Vec<String> = self
            .attached
            .iter()
            .filter(|(n, (idx, _))| !ifaces.iter().any(|(m, j)| m == *n && j == idx))
            .map(|(n, _)| n.clone())
            .collect();
        for n in stale {
            if let Some((_, id)) = self.attached.remove(&n) {
                self.detach_link(id);
                tracing::info!(iface = %n, "wan_egress detached (interface gone or re-created)");
            }
        }

        for (name, idx) in &ifaces {
            if self.attached.contains_key(name) {
                continue;
            }
            match self.attach(name) {
                Ok(id) => {
                    tracing::info!(iface = %name, ifindex = idx, "wan_egress attached");
                    self.attached.insert(name.clone(), (*idx, id));
                }
                Err(e) => tracing::warn!(iface = %name, "attach wan_egress failed: {e:#}"),
            }
        }

        let primary = pick_primary(&ifaces);
        if primary != self.primary {
            tracing::info!(from = ?self.primary, to = ?primary, "primary network changed");
            self.primary = primary.clone();
            setup_android_control_route(primary.as_deref());
        }
    }

    fn attach(&self, name: &str) -> Result<SchedClassifierLinkId> {
        let mut ebpf = self.ebpf.lock().unwrap_or_else(|e| e.into_inner());
        let p: &mut SchedClassifier = ebpf
            .program_mut("wan_egress")
            .context("wan_egress missing")?
            .try_into()?;
        Ok(p.attach(name, TcAttachType::Egress)?)
    }

    fn detach_link(&self, id: SchedClassifierLinkId) {
        let mut ebpf = self.ebpf.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prog) = ebpf.program_mut("wan_egress") {
            if let Ok(p) = TryInto::<&mut SchedClassifier>::try_into(prog) {
                let _ = p.detach(id);
            }
        }
    }

    /// Remove our filters on shutdown (netlink-attached filters outlive the process).
    pub fn detach_all(&mut self) {
        let all: Vec<_> = self.attached.drain().collect();
        for (_, (_, id)) in all {
            self.detach_link(id);
        }
    }
}

pub fn spawn(w: Arc<Mutex<WanWatcher>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let w2 = w.clone();
            let _ = tokio::task::spawn_blocking(move || {
                w2.lock().unwrap_or_else(|e| e.into_inner()).sync();
            })
            .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}

/// Interfaces (name, ifindex) that currently carry a default route in any table.
fn active_interfaces() -> Vec<(String, u32)> {
    let Ok(out) = std::process::Command::new("ip")
        .args(["route", "show", "table", "all"])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        if !line.starts_with("default") {
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = w.iter().position(|x| *x == "dev") {
            if let Some(n) = w.get(i + 1) {
                let n = n.to_string();
                if n == "lo"
                    || ["ant0", "tun", "dummy", "docker", "veth", "br-", "virbr"]
                        .iter()
                        .any(|p| n.starts_with(p))
                {
                    continue;
                }
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    names
        .into_iter()
        .filter_map(|n| {
            let c = std::ffi::CString::new(n.clone()).ok()?;
            let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
            (idx != 0).then_some((n, idx))
        })
        .collect()
}

/// Android prefers Wi-Fi/ethernet over cellular; mirror that.
fn pick_primary(ifaces: &[(String, u32)]) -> Option<String> {
    for prefix in ["wlan", "eth"] {
        if let Some((n, _)) = ifaces.iter().find(|(n, _)| n.starts_with(prefix)) {
            return Some(n.clone());
        }
    }
    ifaces.first().map(|(n, _)| n.clone())
}
