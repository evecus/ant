//! Logging shim: compiles to no-ops. The datapath reports anomalies to
//! userspace via `EVENT_RINGBUF` instead of aya-log, so no BPF-side logging
//! dependency is needed.

#[macro_export]
macro_rules! noop_log {
    ($ctx:expr, target: $target:expr, $($arg:tt)*) => {};
    (target: $target:expr, $($arg:tt)*) => {};
    ($ctx:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

pub use noop_log as debug;
pub use noop_log as error;
pub use noop_log as info;
pub use noop_log as trace;
pub use noop_log as warn;
