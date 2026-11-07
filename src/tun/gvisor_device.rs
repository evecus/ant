use super::{stack::IfaceEvent, Packet};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

/// smoltcp phy Device 实现（clash-rs NetstackDevice + mtu 参数化）。
///
/// rx/tx 均经 mpsc channel 桥接：
/// - rx：TUN 读循环 → `create_injector()` → `rx_queue` → iface poll 消费；
/// - tx：iface poll 产出的回包 → `tx_sender`（bounded）→ 栈外读走写 TUN。
pub struct NetstackDevice {
    rx_sender: mpsc::UnboundedSender<Packet>,
    rx_queue: mpsc::UnboundedReceiver<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

    iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl NetstackDevice {
    /// `mtu` 为 TUN 设备 MTU，必须与上层一致，否则大于设备 MTU 的出站包
    /// 会被 smoltcp 丢弃。
    pub fn new(
        tx_sender: mpsc::Sender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
        mtu: usize,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = mtu;
        capabilities.medium = Medium::Ip;

        let (rx_sender, rx_queue) = mpsc::unbounded_channel::<Packet>();

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
            iface_notifier,
        }
    }

    pub fn create_injector(&self) -> mpsc::UnboundedSender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve a tx slot FIRST before touching rx_queue.
        // If we checked rx_queue first, a successful try_recv() would consume
        // the inbound packet even when try_reserve() subsequently fails,
        // silently dropping ACKs and preventing smoltcp from advancing
        // its send window.
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.try_recv().ok()?;

        let rx_token = RxTokenImpl { packet };
        let tx_token = TxTokenImpl { tx_sender: permit };
        // 栈关闭期 notifier 接收端可能已 drop（clash-rs 原版 expect 会 panic），
        // 忽略即可。
        let _ = self.iface_notifier.send(IfaceEvent::DeviceReady);
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        let packet = Packet::new(buffer);
        self.tx_sender.send(packet);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    /// 复现 ACK 丢弃 bug：tx channel 满（模拟下游消费慢）时，`receive()`
    /// 若先 `try_recv()` 再 `try_reserve()`，会把入站 ACK 消费掉后因
    /// `try_reserve()` 失败而静默丢弃；没有 ACK，smoltcp 发送窗口永不前进，
    /// 下载停摆。当前实现先 reserve tx slot，packet 留在 rx_queue。
    #[tokio::test]
    async fn test_receive_keeps_inbound_packet_when_tx_channel_full() {
        let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel::<Packet>(1);
        let (iface_notifier, _iface_rx) =
            tokio::sync::mpsc::unbounded_channel::<IfaceEvent<'static>>();
        let mut device = NetstackDevice::new(tx_sender, iface_notifier, 1500);
        let injector = device.create_injector();

        device
            .tx_sender
            .try_send(Packet::new(vec![0u8; 60]))
            .expect("should fit in empty channel");
        // tx channel: FULL (capacity = 1)

        injector
            .send(Packet::new(vec![0u8; 60]))
            .expect("unbounded, should not fail");
        // rx_queue: [ack_packet]

        {
            let result = device.receive(smoltcp::time::Instant::now());
            assert!(
                result.is_none(),
                "receive() must return None when tx channel is full"
            );
        }

        // Drain the tx channel to make space
        tx_receiver.recv().await.expect("should have a packet");

        let result2 = device.receive(smoltcp::time::Instant::now());
        assert!(
            result2.is_some(),
            "BUG: inbound ACK was silently dropped when tx channel was full; \
             smoltcp will never advance its send window → download stalls to 0"
        );
    }
}
