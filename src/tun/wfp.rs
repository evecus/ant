//! Windows Filtering Platform (WFP) strict-route — **port of sing-tun
//! `tun_windows.go` strict-route block** (the engine behind mihomo
//! `strict-route: true` on Windows).
//!
//! A **dynamic** FWP engine session is opened at install time and closed on
//! drop; every filter added in a dynamic session disappears when the session
//! closes, so no cleanup of individual filters is needed.
//!
//! Filters (weights mirror sing-tun exactly):
//! - `13` PERMIT own process (ALE_APP_ID)            — v4 + v6
//! - `13` PERMIT NDP RS/NS/NA (only when no TUN v6)  — v6
//! - `12` BLOCK all IPv6          (only when no TUN v6)
//! - `11` PERMIT traffic through the TUN interface  — v4 (if v4 addr) + v6 (if v6 addr)
//! - `10` BLOCK remote port 53   (dns-hijack force) — v4 + v6
//!
//! Net effect: only our process and traffic through the TUN device may
//! connect; system DNS to physical adapters is blocked so it can only be
//! hijacked through the TUN.

#![allow(clippy::upper_case_acronyms)]
#![allow(non_snake_case)]

use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use tracing::info;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_BYTE_ARRAY16_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0,
};

/// GUIDs missing from windows-sys 0.52 (values from fwpmu.h / sing-tun
/// `internal/winsys/constants.go`).
mod guid {
    const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> windows_sys::core::GUID {
        windows_sys::core::GUID { data1: d1, data2: d2, data3: d3, data4: d4 }
    }
    // ICMP type/code reuse the local/remote port GUIDs on ALE layers
    // (sing-tun: FWPM_CONDITION_ICMP_TYPE = FWPM_CONDITION_IP_LOCAL_PORT).
    pub const ICMP_TYPE: windows_sys::core::GUID =
        guid(0x0c1ba1af, 0x5765, 0x453f, [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b]);
    pub const ICMP_CODE: windows_sys::core::GUID =
        guid(0xc35a604d, 0xd22b, 0x4e1a, [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b]);
    pub const LOCAL_INTERFACE_INDEX: windows_sys::core::GUID =
        guid(0x667fd755, 0xd695, 0x434a, [0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc]);
    // ff02::2 — all-routers multicast (NDP RS destination).
    pub const IPV6_ALL_ROUTERS: [u8; 16] = {
        let mut b = [0u8; 16];
        b[0] = 0xff;
        b[1] = 0x02;
        b[15] = 0x02;
        b
    };
}

/// Filled-in filter set held until the dynamic session closes.
pub struct WfpGuard {
    engine: HANDLE,
}

unsafe impl Send for WfpGuard {}
unsafe impl Sync for WfpGuard {}

impl Drop for WfpGuard {
    fn drop(&mut self) {
        unsafe {
            // Dynamic session: closing the engine removes all filters and the
            // sublayer atomically (sing-tun FwpmEngineClose0 on Close()).
            FwpmEngineClose0(self.engine);
        }
        info!("tun: strict-route WFP filters removed");
    }
}

struct FilterCtx<'a> {
    engine: HANDLE,
    sublayer: &'a windows_sys::core::GUID,
    filter_id: &'a mut u64,
}

impl FilterCtx<'_> {
    /// Add one filter. Conditions must live until this call returns.
    unsafe fn add(
        &mut self,
        layer: windows_sys::core::GUID,
        name: &str,
        weight: u8,
        action: u32,
        clear_action_right: bool,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<()> {
        let mut display_name = to_wide(name);
        let mut filter = zeroed_filter();
        filter.displayData.name = display_name.as_mut_ptr();
        filter.flags = if clear_action_right {
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
        } else {
            0
        };
        filter.layerKey = layer;
        filter.subLayerKey = *self.sublayer;
        filter.weight = uint8_value(weight);
        filter.numFilterConditions = conditions.len() as u32;
        if !conditions.is_empty() {
            filter.filterCondition = conditions.as_mut_ptr();
        }
        filter.action.r#type = action;
        let rc = FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), self.filter_id);
        if rc != 0 {
            return Err(anyhow!("FwpmFilterAdd0 `{name}` failed (err={rc})"));
        }
        Ok(())
    }
}

fn zeroed_filter() -> FWPM_FILTER0 {
    // FWPM_FILTER0 contains unions and pointers — zero-init is the documented
    // "empty" state (filterKey all-zero → auto-generate).
    unsafe { std::mem::zeroed() }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn uint8_value(v: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        // SAFETY: union field init is safe in Rust; only reads are unsafe.
        Anonymous: FWP_VALUE0_0 { uint8: v },
    }
}

fn cond_uint8(field: windows_sys::core::GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: v },
        },
    }
}

fn cond_uint16(field: windows_sys::core::GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v },
        },
    }
}

fn cond_uint32(field: windows_sys::core::GUID, v: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: v },
        },
    }
}

/// Install the sing-tun strict-route filter set.
///
/// * `tun_if_index` — index of the TUN interface (LOCAL_INTERFACE_INDEX permit).
/// * `has_v4` / `has_v6` — whether the TUN has a v4 / v6 address; the missing
///   family is blocked entirely (v6 additionally gets NDP pass-through).
/// * `dns_hijack` — when true, remote port 53 is BLOCKED outside the TUN
///   (sing-tun adds these whenever DNS hijack is not explicitly disabled).
pub fn install(tun_if_index: u32, has_v4: bool, has_v6: bool, dns_hijack: bool) -> Result<WfpGuard> {
    unsafe {
        // --- dynamic engine session ---
        let mut session = std::mem::zeroed::<FWPM_SESSION0>();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = 0;
        let rc = FwpmEngineOpen0(
            std::ptr::null(),
            0xFFFFFFFF, // RPC_C_AUTHN_DEFAULT
            std::ptr::null(),
            &session,
            &mut engine,
        );
        if rc != 0 {
            return Err(anyhow!("FwpmEngineOpen0 failed (err={rc})"));
        }
        if engine == 0 {
            return Err(anyhow!("FwpmEngineOpen0 returned null engine handle"));
        }

        // --- sublayer (weight = max, above default sublayers) ---
        let sublayer_key = random_guid();
        let mut sub_name = to_wide("ant strict-route");
        let mut sublayer = std::mem::zeroed::<FWPM_SUBLAYER0>();
        sublayer.subLayerKey = sublayer_key;
        sublayer.displayData.name = sub_name.as_mut_ptr();
        sublayer.weight = u16::MAX;
        let rc = FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut());
        if rc != 0 {
            FwpmEngineClose0(engine);
            return Err(anyhow!("FwpmSubLayerAdd0 failed (err={rc})"));
        }

        let mut filter_id: u64 = 0;
        let mut ctx = FilterCtx { engine, sublayer: &sublayer_key, filter_id: &mut filter_id };

        // --- 13: permit own process (both families) ---
        let app_blob = current_process_app_id()?;
        let app_blob_ptr: *mut FWP_BYTE_BLOB = app_blob;
        let mut permit_conditions = [cond_app_id(app_blob_ptr)];
        ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ant strict-route: protect ipv4", 13,
                FWP_ACTION_PERMIT, true, &mut permit_conditions)
            .context("add protect ipv4 filter")?;
        ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ant strict-route: protect ipv6", 13,
                FWP_ACTION_PERMIT, true, &mut permit_conditions)
            .context("add protect ipv6 filter")?;

        // --- 12: block IPv6 entirely when the TUN has no v6 address
        //         (NDP must stay permitted or the LAN breaks) ---
        if !has_v6 {
            let mut ndp_addr16 = FWP_BYTE_ARRAY16 { byteArray16: guid::IPV6_ALL_ROUTERS };
            let ndp_addr_ptr: *mut FWP_BYTE_ARRAY16 = &mut ndp_addr16;

            // [protocol=ICMPv6, icmp type, icmp code, remote=ff02::2]
            let mut conditions4 = [
                cond_uint8(ip_proto_guid(), 58), // IPPROTO_ICMPV6
                cond_uint16(guid::ICMP_TYPE, 0),
                cond_uint16(guid::ICMP_CODE, 0),
                cond_byte_array16(ip_remote_addr_guid(), ndp_addr_ptr),
            ];
            for (name, icmp_type, num) in [
                ("allow ipv6 router solicitation", 133u16, 4usize),
                ("allow ipv6 neighbor solicitation", 135, 3),
                ("allow ipv6 neighbor advertisement", 136, 3),
            ] {
                conditions4[1] = cond_uint16(guid::ICMP_TYPE, icmp_type);
                ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, &format!("ant strict-route: {name}"),
                        13, FWP_ACTION_PERMIT, false, &mut conditions4[..num])
                    .with_context(|| format!("add {name} filter"))?;
            }

            let mut block_conditions = [];
            ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ant strict-route: block ipv6", 12,
                    FWP_ACTION_BLOCK, false, &mut block_conditions)
                .context("add block ipv6 filter")?;
        }

        // --- 11: permit everything through the TUN device ---
        let mut tun_conditions = [cond_uint32(guid::LOCAL_INTERFACE_INDEX, tun_if_index)];
        if has_v4 {
            ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ant strict-route: allow ipv4 (tun)", 11,
                    FWP_ACTION_PERMIT, false, &mut tun_conditions)
                .context("add allow tun ipv4 filter")?;
        }
        if has_v6 {
            ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ant strict-route: allow ipv6 (tun)", 11,
                    FWP_ACTION_PERMIT, false, &mut tun_conditions)
                .context("add allow tun ipv6 filter")?;
        }

        // --- 10: block remote port 53 outside the TUN (DNS hijack force) ---
        if dns_hijack {
            let mut dns_conditions = [cond_uint16(remote_port_guid(), 53)];
            ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ant strict-route: block ipv4 dns", 10,
                    FWP_ACTION_BLOCK, false, &mut dns_conditions)
                .context("add block ipv4 dns filter")?;
            ctx.add(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ant strict-route: block ipv6 dns", 10,
                    FWP_ACTION_BLOCK, false, &mut dns_conditions)
                .context("add block ipv6 dns filter")?;
        }

        info!(
            tun_if_index,
            has_v4,
            has_v6,
            dns_hijack,
            "tun: strict-route WFP filters installed (dynamic session)"
        );
        Ok(WfpGuard { engine })
    }
}

// --- condition field GUIDs (FWPM_CONDITION_* from fwpmu.h) ------------------

fn ip_proto_guid() -> windows_sys::core::GUID {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL
}
fn ip_remote_addr_guid() -> windows_sys::core::GUID {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_ADDRESS
}
fn remote_port_guid() -> windows_sys::core::GUID {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT
}
fn app_id_guid() -> windows_sys::core::GUID {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_APP_ID
}

unsafe fn cond_app_id(blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: app_id_guid(),
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
        },
    }
}

unsafe fn cond_byte_array16(
    field: windows_sys::core::GUID,
    value: *mut FWP_BYTE_ARRAY16,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: value },
        },
    }
}

/// sing-tun GetCurrentProcessAppID: current exe path → FWP_BYTE_BLOB.
unsafe fn current_process_app_id() -> Result<*mut FWP_BYTE_BLOB> {
    let exe = std::env::current_exe().context("resolve current exe")?;
    let wide = to_wide(&exe.as_os_str().to_string_lossy());
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let rc = FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob);
    if rc != 0 {
        return Err(anyhow!("FwpmGetAppIdFromFileName0 failed (err={rc})"));
    }
    Ok(blob)
}

/// Random sublayer GUID (rand is already a dependency). Dynamic-session
/// objects collide across processes without a random key.
fn random_guid() -> windows_sys::core::GUID {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    // RFC 4122-ish version/variant bits — cosmetic, any non-zero GUID works.
    b[7] = (b[7] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    windows_sys::core::GUID {
        data1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_be_bytes([b[4], b[5]]),
        data3: u16::from_be_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}
