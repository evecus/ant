//! Mark scheme aligned with sing-tun / mihomo classic mode.
//!
//! Outbound dialer sockets get SO_MARK so their packets can be excluded from
//! policy routing if the user adds fwmark rules; loop prevention itself relies
//! on SO_BINDTODEVICE (`auto-detect-interface`), same as mihomo.
//!
//! mihomo only enables dual-mark (AutoRedirectMarkMode) when route-address-set
//! rule providers are configured; ant has no such feature, so auto-redirect
//! always uses the classic topology and a single mark.

pub const DEFAULT_ROUTE_MARK: u32 = 255;
// iproute2 policy-routing constants — Linux/Android only.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const DEFAULT_TABLE: i32 = 2022;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const DEFAULT_RULE_PRIORITY: i32 = 9000;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const DEFAULT_FALLBACK_RULE_PRIORITY: i32 = 32768;

#[derive(Clone, Copy, Debug)]
pub struct TunMarks {
    pub output: u32,
}

impl TunMarks {
    /// Resolve the dialer mark from user config + feature flags.
    pub fn resolve(
        user_mark: u32,
        auto_route: bool,
        auto_redirect: bool,
        auto_detect: bool,
    ) -> Self {
        let output = if auto_route || auto_redirect || auto_detect {
            if user_mark != 0 {
                user_mark
            } else {
                DEFAULT_ROUTE_MARK
            }
        } else {
            user_mark
        };
        Self { output }
    }
}
