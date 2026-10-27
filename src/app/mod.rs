//! Application core: API server, socket options, protocol sniffer, traffic stats, router.

pub mod api;
pub mod cache;
pub mod http;
pub mod log_buffer;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod protect;
pub mod provider_link;
pub mod provider_parse;
pub mod proxy_provider;
pub mod router;
pub mod sniffer;
pub mod sockopt;
pub mod stats;
pub mod ui;
