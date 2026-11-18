//! Spectre Brutal 拥塞控制（从 spectre-master `src/protocol/brutal.rs` 移植）。
//!
//! 设计对齐 Hysteria2 Brutal，适配到 quinn 的 `congestion::Controller`：
//!
//! * 发送端被告知一个**目标速率**（字节/秒），不像 Cubic/BBR 那样一丢包就退让。
//! * 丢包率用 5 个 1 秒槽的滑动窗口度量（`acked / (acked + lost)`，下限 0.8）。
//! * `cwnd = 目标速率 * RTT * CWND_GAIN / ack_rate`。丢包由 QUIC 重传补回，
//!   除以 ack_rate 使有效吞吐贴近目标速率。
//! * quinn 从窗口推导 pacing（`window * 1.25 / srtt`），无需独立 pacer。
//! * 目标速率 `0` = 关闭 Brutal，交回 quinn 的 BBR。
//!
//! 与参考实现的差异：不移植 `bind_udp` —— ant 的出站 UDP socket 统一走
//! `app::sockopt::bind_udp`（SO_MARK + 绑定物理网卡，防 TUN 回环），与
//! tuic / hysteria2 / shadowquic 一致。
//!
//! `quinn-jls` 不重新导出 `RttEstimator`（`Controller::on_ack` 的签名需要它），
//! 因此这里直接依赖 `quinn-proto-jls`（Cargo.toml 中的直接依赖）。

use quinn_jls::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto_jls::RttEstimator;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ack-rate 窗口的 1 秒槽数量（与 Hysteria 相同）。
const SLOT_COUNT: u64 = 5;
/// 观测字节数少于此值前忽略丢包估计（约 50 个满尺寸包，同 Hysteria 的
/// `minSampleCount`）。
const MIN_SAMPLE_BYTES: u64 = 50 * 1200;
/// ack rate 下限。补偿上限 1/0.8 = 1.25x。
const MIN_ACK_RATE: f64 = 0.8;
/// 窗口在目标速率一个 BDP 之上的余量。
///
/// quinn 按 `window * 1.25 / srtt` pacing，实际 pacing 速率约为
/// `CWND_GAIN * 1.25 * 目标 / ack_rate`。Hysteria 用自己的 pacer 取 2.0；
/// quinn 的 pacer 下取更小的值，否则发送端会超出声明速率 2.5x 并自造丢包。
const CWND_GAIN: f64 = 1.2;
/// 窗口下限（包数）。
const MIN_WINDOW_PACKETS: u64 = 16;
/// 窗口上限（字节）。
const MAX_WINDOW: u64 = 128 * 1024 * 1024;
/// 首个样本到达前使用的 RTT。
const DEFAULT_RTT: Duration = Duration::from_millis(150);

/// 每 stream 流控窗口（字节）。
const STREAM_RECV_WINDOW: u32 = 16 * 1024 * 1024;
/// 每连接流控窗口（字节）。
const CONN_RECV_WINDOW: u32 = 64 * 1024 * 1024;
/// 每连接发送窗口上限（字节）。
const SEND_WINDOW: u64 = 64 * 1024 * 1024;

// ── 共享速率句柄 ─────────────────────────────────────────────────────────────

/// 共享、线程安全的目标速率（**字节/秒**，0 = Brutal 关闭）。
///
/// 客户端在连接建立时一次性设定（`up` → tx_bps），运行期不再变更 ——
/// 参考实现里服务端才需要在 AUTH 之后改写速率，客户端用不到 `set`。
#[derive(Clone, Debug)]
pub struct BrutalHandle(Arc<AtomicU64>);

impl BrutalHandle {
    pub fn new(bps: u64) -> Self {
        Self(Arc::new(AtomicU64::new(bps)))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ── ack-rate 追踪 ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug)]
struct Slot {
    sec: u64,
    acked: u64,
    lost: u64,
}

#[derive(Clone, Debug)]
struct AckTracker {
    start: Instant,
    slots: [Slot; SLOT_COUNT as usize],
}

impl AckTracker {
    fn new(start: Instant) -> Self {
        Self {
            start,
            slots: [Slot::default(); SLOT_COUNT as usize],
        }
    }

    fn sec(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs()
    }

    fn add(&mut self, now: Instant, acked: u64, lost: u64) {
        let sec = self.sec(now);
        let slot = &mut self.slots[(sec % SLOT_COUNT) as usize];
        if slot.sec != sec {
            *slot = Slot {
                sec,
                acked: 0,
                lost: 0,
            };
        }
        slot.acked += acked;
        slot.lost += lost;
    }

    /// 最近 `SLOT_COUNT` 秒的 `acked / (acked + lost)`，钳在
    /// `[MIN_ACK_RATE, 1.0]`。样本不足时返回 1.0。
    fn ack_rate(&self, now: Instant) -> f64 {
        let sec = self.sec(now);
        let (mut acked, mut lost) = (0u64, 0u64);
        for s in &self.slots {
            if s.sec <= sec && sec - s.sec < SLOT_COUNT {
                acked += s.acked;
                lost += s.lost;
            }
        }
        let total = acked + lost;
        if total < MIN_SAMPLE_BYTES {
            return 1.0;
        }
        (acked as f64 / total as f64).clamp(MIN_ACK_RATE, 1.0)
    }
}

// ── 控制器 ──────────────────────────────────────────────────────────────────

pub struct BrutalController {
    handle: BrutalHandle,
    /// 目标速率为 0 时使用。
    fallback: Box<dyn Controller>,
    tracker: AckTracker,
    ack_rate: f64,
    srtt: Duration,
    mtu: u16,
}

impl BrutalController {
    fn new(handle: BrutalHandle, now: Instant, mtu: u16) -> Self {
        Self {
            handle,
            fallback: Arc::new(BbrConfig::default()).build(now, mtu),
            tracker: AckTracker::new(now),
            ack_rate: 1.0,
            srtt: DEFAULT_RTT,
            mtu,
        }
    }

    fn min_window(&self) -> u64 {
        MIN_WINDOW_PACKETS * u64::from(self.mtu)
    }
}

impl std::fmt::Debug for BrutalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrutalController")
            .field("target_bps", &self.handle.get())
            .field("ack_rate", &self.ack_rate)
            .field("srtt", &self.srtt)
            .finish()
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.tracker.add(now, bytes, 0);
        self.ack_rate = self.tracker.ack_rate(now);
        self.srtt = rtt.get().max(Duration::from_millis(1));
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
    ) {
        // ECN 标记携带 lost_bytes == 0，Brutal 忽略。
        if lost_bytes > 0 {
            self.tracker.add(now, 0, lost_bytes);
            self.ack_rate = self.tracker.ack_rate(now);
        }
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, is_ecn, lost_bytes);
    }

    fn on_spurious_congestion_event(&mut self) {
        self.fallback.on_spurious_congestion_event();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let bps = self.handle.get();
        if bps == 0 {
            return self.fallback.window();
        }
        let w = bps as f64 * self.srtt.as_secs_f64() * CWND_GAIN / self.ack_rate;
        (w as u64).clamp(self.min_window(), MAX_WINDOW)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(BrutalController {
            handle: self.handle.clone(),
            fallback: self.fallback.clone_box(),
            tracker: self.tracker.clone(),
            ack_rate: self.ack_rate,
            srtt: self.srtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        if self.handle.get() == 0 {
            self.fallback.initial_window()
        } else {
            self.window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

// ── 工厂与传输参数调优 ───────────────────────────────────────────────────────

pub struct BrutalFactory {
    handle: BrutalHandle,
}

impl BrutalFactory {
    pub fn new(handle: BrutalHandle) -> Arc<Self> {
        Arc::new(Self { handle })
    }
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.handle.clone(), now, current_mtu))
    }
}

/// 安装 Brutal 控制器并抬高 QUIC 流控上限。
///
/// quinn 默认流控窗口（每 stream 约 1.2 MB）会把吞吐卡在 `window / RTT`，
/// 与拥塞控制算法无关，因此 Brutal 要跑满速率必须先抬高它们。
pub fn tune_transport(transport: &mut quinn_jls::TransportConfig, handle: BrutalHandle) {
    transport
        .congestion_controller_factory(BrutalFactory::new(handle))
        .stream_receive_window(quinn_jls::VarInt::from_u32(STREAM_RECV_WINDOW))
        .receive_window(quinn_jls::VarInt::from_u32(CONN_RECV_WINDOW))
        .send_window(SEND_WINDOW);
}

// ── 速率解析 ────────────────────────────────────────────────────────────────

/// 把速率字符串解析为**字节/秒**。
///
/// * `100mbps` / `1gbps` / `512kbps` / `8000bps`：比特率（同 Hysteria）。
/// * 裸整数：字节/秒。
/// * `0`：关闭（交回 BBR）。
///
/// 与 hysteria2 出站的 `up`/`down`（裸数字按 Mbps）语义不同 —— spectre 采用
/// 参考协议自己的语法，配置示例中显式使用单位后缀。
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult): (&str, f64) = if let Some(n) = t.strip_suffix("gbps") {
        (n, 1e9 / 8.0)
    } else if let Some(n) = t.strip_suffix("mbps") {
        (n, 1e6 / 8.0)
    } else if let Some(n) = t.strip_suffix("kbps") {
        (n, 1e3 / 8.0)
    } else if let Some(n) = t.strip_suffix("bps") {
        (n, 1.0 / 8.0)
    } else {
        (t.as_str(), 1.0)
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid rate '{s}' (examples: 100mbps, 20mbps, 12500000)"))?;
    if v < 0.0 || !v.is_finite() {
        return Err(format!("invalid rate '{s}'"));
    }
    Ok((v * mult) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_parse() {
        assert_eq!(parse_rate("100mbps").unwrap(), 100_000_000 / 8);
        assert_eq!(parse_rate("1gbps").unwrap(), 1_000_000_000 / 8);
        assert_eq!(parse_rate("512kbps").unwrap(), 512_000 / 8);
        assert_eq!(parse_rate("8000bps").unwrap(), 1000);
        assert_eq!(parse_rate("12500000").unwrap(), 12_500_000);
        assert_eq!(parse_rate("0").unwrap(), 0);
        // 大小写 / 空白容忍
        assert_eq!(parse_rate(" 50Mbps ").unwrap(), 50_000_000 / 8);
        // 非法值 fail-fast
        assert!(parse_rate("abc").is_err());
        assert!(parse_rate("-5").is_err());
        assert!(parse_rate("").is_err());
    }

    #[test]
    fn handle_roundtrip() {
        let h = BrutalHandle::new(0);
        assert_eq!(h.get(), 0);
        let h2 = BrutalHandle::new(1234);
        assert_eq!(h2.get(), 1234);
        // Clone 共享同一个 AtomicU64。
        let h3 = h2.clone();
        assert_eq!(h3.get(), 1234);
    }

    #[test]
    fn brutal_off_falls_back_to_bbr() {
        // 速率 0 时窗口走 BBR fallback；只需验证不 panic 且 clone 保留句柄。
        let handle = BrutalHandle::new(0);
        let factory = BrutalFactory::new(handle.clone());
        let now = Instant::now();
        let c = factory.build(now, 1200);
        assert!(c.window() > 0);
        let c2 = c.clone_box();
        assert!(c2.window() > 0);
        // 设置速率后窗口随速率增长
        let handle = BrutalHandle::new(100 * 1024 * 1024);
        let c = BrutalFactory::new(handle).build(Instant::now(), 1200);
        assert!(c.window() > 0);
    }

    #[test]
    fn brutal_window_scales_with_rate() {
        let handle = BrutalHandle::new(100 * 1024 * 1024);
        let factory = BrutalFactory::new(handle);
        let c = factory.build(Instant::now(), 1200);
        // 初始窗口 = rate * 150ms * 1.2 / 1.0
        let expected = (100.0 * 1024.0 * 1024.0 * 0.15 * CWND_GAIN) as u64;
        assert_eq!(c.initial_window(), expected.max(16 * 1200));
        assert_eq!(c.window(), expected.max(16 * 1200));
    }
}
