//! Default interface monitor.
//!
//! Linux/Android: event-driven via `ip monitor` with periodic fallback
//! (sing-tun uses netlink; we approximate with iproute2).
//! Windows: IpHelper API — `GetIpForwardTable2` for lowest-metric default
//! route (same algorithm as sing-tun `monitor_windows.go`), notified by
//! `NotifyRouteChange2` / `NotifyIpInterfaceChange` (same as sing-tun
//! `networkUpdateMonitor`).

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::{Command, Stdio};
use std::sync::RwLock;
use tracing::{info, warn};

static BIND_IFACE: RwLock<Option<String>> = RwLock::new(None);
#[cfg(target_os = "windows")]
static BIND_IF_INDEX: RwLock<Option<u32>> = RwLock::new(None);

pub fn bind_interface() -> Option<String> {
    BIND_IFACE.read().ok().and_then(|g| g.clone())
}

/// Windows only: interface index of the detected default interface, for
/// `IP_UNICAST_IF` / `IPV6_UNICAST_IF` binding (mihomo `bind_windows.go`).
#[cfg(target_os = "windows")]
pub fn bind_interface_index() -> Option<u32> {
    BIND_IF_INDEX.read().ok().and_then(|g| *g)
}

pub fn set_bind_interface(name: Option<String>) {
    if let Ok(mut g) = BIND_IFACE.write() {
        *g = name;
    }
}

#[cfg(target_os = "windows")]
fn set_bind_if_index(idx: Option<u32>) {
    if let Ok(mut g) = BIND_IF_INDEX.write() {
        *g = idx;
    }
}

pub fn detect_default_interface(exclude: &str) -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        detect_linux(exclude)
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows(exclude)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = exclude;
        None
    }
}

pub fn start_monitor(exclude: String, enable: bool) {
    if !enable {
        return;
    }
    refresh(&exclude);
    // Fast poll fallback (also the only path on Windows if callbacks misfire;
    // detection itself is a few API calls, ~microseconds).
    let ex = exclude.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            refresh(&ex);
        }
    });
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let ex2 = exclude;
        tokio::task::spawn_blocking(move || {
            // Blocks; each line triggers refresh.
            let child = Command::new("ip")
                .args(["-o", "monitor", "route", "link"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let Ok(mut child) = child else {
                return;
            };
            use std::io::{BufRead, BufReader};
            if let Some(out) = child.stdout.take() {
                let reader = BufReader::new(out);
                for line in reader.lines().map_while(Result::ok) {
                    if line.contains("default") || line.contains("link") {
                        refresh(&ex2);
                    }
                }
            }
            let _ = child.wait();
        });
    }
    #[cfg(target_os = "windows")]
    {
        // sing-tun networkUpdateMonitor: route + interface change callbacks
        // set a dirty flag; a worker drains it and refreshes. Callbacks run on
        // system threads — never touch the runtime there.
        let ex2 = exclude;
        win_monitor::start();
        tokio::task::spawn_blocking(move || {
            let mut last = win_monitor::dirty();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let now = win_monitor::dirty();
                if now != last {
                    last = now;
                    refresh(&ex2);
                }
            }
        });
    }
}

fn refresh(exclude: &str) {
    match detect_default_interface(exclude) {
        Some(name) => {
            let prev = bind_interface();
            if prev.as_deref() != Some(name.as_str()) {
                info!(interface = %name, "tun: default interface => {name}");
                set_bind_interface(Some(name));
            }
        }
        None => {
            if bind_interface().is_some() {
                warn!("tun: default interface lost");
                set_bind_interface(None);
                #[cfg(target_os = "windows")]
                set_bind_if_index(None);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect_linux(exclude: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        while let Some(p) = parts.next() {
            if p == "dev" {
                if let Some(d) = parts.next() {
                    if d != exclude && !d.starts_with("tun") && d != "lo" {
                        return Some(d.to_string());
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Windows — IpHelper API (sing-tun monitor_windows.go alignment)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod win_monitor {
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIRTY: AtomicU64 = AtomicU64::new(0);

    pub fn dirty() -> u64 {
        DIRTY.load(Ordering::Relaxed)
    }

    // Callback signatures differ per notification kind (row type):
    // route → MIB_IPFORWARD_ROW2, interface → MIB_IPINTERFACE_ROW.
    unsafe extern "system" fn on_route_change(
        _ctx: *const std::ffi::c_void,
        _row: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
        _ty: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
    ) {
        DIRTY.fetch_add(1, Ordering::Relaxed);
    }

    unsafe extern "system" fn on_iface_change(
        _ctx: *const std::ffi::c_void,
        _row: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
        _ty: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
    ) {
        DIRTY.fetch_add(1, Ordering::Relaxed);
    }

    /// Register route + interface change callbacks (never unregistered —
    /// process lifetime, same as the previous spawn-based monitor).
    pub fn start() {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            NotifyIpInterfaceChange, NotifyRouteChange2,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        static ROUTE_HANDLE: std::sync::Mutex<Option<HANDLE>> = std::sync::Mutex::new(None);
        static IFACE_HANDLE: std::sync::Mutex<Option<HANDLE>> = std::sync::Mutex::new(None);

        let mut h: HANDLE = 0;
        let rc = unsafe {
            NotifyRouteChange2(AF_INET, Some(on_route_change), std::ptr::null(), 0, &mut h)
        };
        if rc == 0 {
            *ROUTE_HANDLE.lock().unwrap() = Some(h);
        } else {
            tracing::warn!("tun: NotifyRouteChange2 failed (err={rc}); falling back to polling");
        }

        let mut h2: HANDLE = 0;
        let rc = unsafe {
            NotifyIpInterfaceChange(AF_INET, Some(on_iface_change), std::ptr::null(), 0, &mut h2)
        };
        if rc == 0 {
            *IFACE_HANDLE.lock().unwrap() = Some(h2);
        } else {
            tracing::warn!("tun: NotifyIpInterfaceChange failed (err={rc}); falling back to polling");
        }
    }
}

#[cfg(target_os = "windows")]
fn detect_windows(exclude: &str) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry,
        MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    const IF_OPER_STATUS_UP: i32 = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_PROP_VIRTUAL: u32 = 53; // proprietary virtual/internal
    /// ZeroTier fake gateway — sing-tun skips it when picking the default if.
    const ZEROTIER_FAKE_GATEWAY: u32 = u32::from_be_bytes([25, 255, 255, 254]);

    unsafe fn ipv4_next_hop(row: &MIB_IPFORWARD_ROW2) -> Option<u32> {
        // SOCKADDR_INET union: si_family at offset 0; SOCKADDR_IN.sin_addr
        // (4 bytes) at offset 4.
        let base = std::ptr::addr_of!(row.NextHop) as *const u8;
        let family = (base as *const u16).read_unaligned();
        if family != AF_INET {
            return None;
        }
        Some((base.add(4) as *const u32).read_unaligned())
    }

    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return None;
        }

        let mut lowest_metric = u32::MAX;
        let mut best_luid: u64 = 0;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            if ipv4_next_hop(row) == Some(ZEROTIER_FAKE_GATEWAY) {
                continue;
            }

            // NET_LUID_LH is Copy; read the raw 64-bit value via the union.
            let luid_union: NET_LUID_LH = row.InterfaceLuid;
            if luid_union.Value == 0 {
                continue;
            }

            let mut if_row = std::mem::zeroed::<MIB_IF_ROW2>();
            if_row.InterfaceLuid = luid_union;
            if GetIfEntry2(&mut if_row) != 0 {
                continue;
            }
            if if_row.OperStatus != IF_OPER_STATUS_UP {
                continue;
            }
            if if_row.Type == IF_TYPE_PROP_VIRTUAL || if_row.Type == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }

            let mut ip_if = std::mem::zeroed::<MIB_IPINTERFACE_ROW>();
            ip_if.Family = AF_INET;
            ip_if.InterfaceLuid = luid_union;
            if GetIpInterfaceEntry(&mut ip_if) != 0 {
                continue;
            }
            if ip_if.Connected == 0 {
                continue;
            }

            let metric = row.Metric.wrapping_add(ip_if.Metric);
            if metric < lowest_metric {
                lowest_metric = metric;
                best_luid = luid_union.Value;
            }
        }
        FreeMibTable(table as *const _);

        if best_luid == 0 {
            return None;
        }

        // LUID → alias (this is the name netsh shows and expects).
        let mut if_row = std::mem::zeroed::<MIB_IF_ROW2>();
        let mut luid_union: NET_LUID_LH = std::mem::zeroed();
        luid_union.Value = best_luid;
        if_row.InterfaceLuid = luid_union;
        if GetIfEntry2(&mut if_row) != 0 {
            return None;
        }
        let len = if_row.Alias.iter().position(|&c| c == 0).unwrap_or(257);
        let alias = String::from_utf16_lossy(&if_row.Alias[..len]);
        if alias.is_empty() || alias == exclude {
            return None;
        }

        // Cache index for IP_UNICAST_IF binding.
        let idx = if_row.InterfaceIndex;
        match BIND_IF_INDEX.read() {
            Ok(g) if *g == Some(idx) => {}
            _ => set_bind_if_index(Some(idx)),
        }
        Some(alias)
    }
}
