//! `EVENT_RINGBUF` consumer: datapath observability.
//!
//! Events are advisory only — the datapath never blocks on them. Logging is
//! rate-limited so a conntrack-overflow burst cannot flood the log.

use std::time::{Duration, Instant};

use aya::maps::{MapData, RingBuf};
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use ant_ebpf_common::{
    AntEvent, AntEventType,
    event as common_event,
};

/// Max events logged per second; the rest are aggregated into one warning.
const EVENT_LOG_MAX_PER_SEC: u32 = 32;

pub(super) fn spawn(ring: RingBuf<MapData>, shutdown: broadcast::Receiver<()>) {
    tokio::spawn(async move {
        if let Err(e) = consume(ring, shutdown).await {
            warn!("ebpf: event consumer stopped: {e}");
        }
    });
}

async fn consume(
    ring: RingBuf<MapData>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let mut async_fd = AsyncFd::new(ring)?;
    let mut window = Instant::now();
    let mut emitted = 0u32;
    let mut suppressed = 0u64;

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            readable = async_fd.readable_mut() => {
                let mut guard = readable?;
                {
                    let ring_buf = guard.get_inner_mut();
                    while let Some(item) = ring_buf.next() {
                        let bytes: &[u8] = &item;
                        if bytes.len() < std::mem::size_of::<AntEvent>() {
                            continue;
                        }
                        // SAFETY: the ring buffer carries the exact POD layout.
                        let ev: AntEvent =
                            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const AntEvent) };

                        if window.elapsed() >= Duration::from_secs(1) {
                            if suppressed > 0 {
                                warn!("ebpf: {suppressed} datapath events suppressed in the last second");
                            }
                            window = Instant::now();
                            emitted = 0;
                            suppressed = 0;
                        }
                        if emitted >= EVENT_LOG_MAX_PER_SEC {
                            suppressed += 1;
                            continue;
                        }
                        emitted += 1;
                        log_event(&ev);
                    }
                }
                guard.clear_ready();
            }
        }
    }
    Ok(())
}

fn log_event(ev: &AntEvent) {
    let sip = common_event::event_ip(&ev.sip);
    let dip = common_event::event_ip(&ev.dip);
    let kind = match ev.type_ {
        t if t == AntEventType::NewFlow as u32 => "new_flow",
        t if t == AntEventType::MapOverflow as u32 => "map_overflow",
        t if t == AntEventType::Blocked as u32 => "blocked",
        _ => "unknown",
    };
    let action = match ant_ebpf_common::RouteAction::from_u8(ev.action) {
        Some(a) => format!("{a:?}"),
        None => format!("{}", ev.action),
    };
    let l4 = if ev.l4proto == 6 { "tcp" } else { "udp" };
    if ev.type_ == AntEventType::MapOverflow as u32 {
        warn!(
            target: "ant::ebpf",
            event = kind, action = %action, l4proto = l4, rule = ev.rule_id,
            %sip, sport = ev.sport, %dip, dport = ev.dport,
            "datapath map overflow — flow handed to the nft pipeline"
        );
    } else {
        debug!(
            target: "ant::ebpf",
            event = kind, action = %action, l4proto = l4, rule = ev.rule_id,
            %sip, sport = ev.sport, %dip, dport = ev.dport,
            "datapath event"
        );
    }
}
