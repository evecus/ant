mod mixed;

// Transparent inbounds (TPROXY / REDIRECT) rely on Linux netfilter socket
// options (IP_TRANSPARENT, SO_ORIGINAL_DST, ...). Android kernel is Linux and
// supports them all, so these inbounds are built on linux + android only;
// Windows builds exclude them entirely.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod redir;
mod target;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod tproxy;

pub use mixed::run_mixed;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use redir::run_redir;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use tproxy::run_tproxy;

