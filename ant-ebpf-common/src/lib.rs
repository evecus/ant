//! Kernel/userspace shared ABI types for ant.
//!
//! Mirrors honk's `honk-ebpf-common` discipline: every type here is `#[repr(C)]`
//! and must move together with the eBPF crate and the userspace map writers.
#![cfg_attr(not(feature = "std"), no_std)]

/// Skb mark reserved for traffic entering the proxy namespace (`antns`).
/// The `antns` policy routing rule `fwmark TPROXY_MARK table 100` sends these
/// packets to the local transparent listener table.
pub const TPROXY_MARK: u32 = 0x2027;

/// Socket mark for control-plane dials (SOCKS5, DNS upstream). Seen on
/// egress as skb->mark, letting the datapath pass the proxy's own traffic.
pub const CONTROL_MARK: u32 = 0x6d696e69;

/// 已由本数据面判为 DIRECT 的 skb 打上的高位标记。同一个 skb 若再次进入
/// 另一个 capture hook（LAN ingress -> 内核转发 -> WAN egress），看到该位
/// 就直接放行，不再重复判决，沿用 honk 的 CLASSIFIED_MARK 思路。取高位是
/// 为了避开 Android netd 把低 16 位 fwmark 当 netId 用的约定。
pub const CLASSIFIED_MARK: u32 = 0x1000_0000;

/// 每个地址族最多几个并行 UDP 监听 socket。sk_lookup 用五元组哈希取模把
/// 一条流固定到同一个槽位；eBPF 与用户态共用此常量，SockMap 容量按
/// `2 + 2 * UDP_LISTENER_MAX` 展开。
pub const UDP_LISTENER_MAX: u32 = 4;

/// LISTEN_SOCKETS 槽位布局，内核与用户态共用，避免两处各写一份而漂移。
pub const KEY_TCP4: u32 = 0;
pub const KEY_TCP6: u32 = 1;
pub const KEY_UDP4_BASE: u32 = 2;
pub const KEY_UDP6_BASE: u32 = KEY_UDP4_BASE + UDP_LISTENER_MAX;
pub const LISTEN_SLOTS: u32 = 2 + 2 * UDP_LISTENER_MAX;

/// Routing verdicts shared by every decision surface.
///
/// DIRECT and BLOCK are fully handled in the kernel. Every other verdict
/// enters userspace: `VERDICT_NODE_BASE + i` selects outbound node `i` (the
/// index in the config's `nodes` list), while the bare `VERDICT_PROXY` means
/// "userspace, no node chosen" (DNS hijack; userspace picks the default).
pub const VERDICT_DIRECT: u8 = 1;
pub const VERDICT_PROXY: u8 = 2;
pub const VERDICT_BLOCK: u8 = 3;
/// First node verdict: node `i` is `VERDICT_NODE_BASE + i`.
pub const VERDICT_NODE_BASE: u8 = 4;

/// True when the verdict sends the flow into userspace (any node).
#[inline(always)]
pub const fn verdict_is_proxy(v: u8) -> bool {
    v == VERDICT_PROXY || v >= VERDICT_NODE_BASE
}

/// Per-cgroup (cgroup v2) policy for host-originated traffic. The map value
/// is either `CGROUP_MODE_BYPASS` (the cgroup's traffic is never captured,
/// always direct) or a node verdict (`>= VERDICT_NODE_BASE`): everything
/// except local/private destinations is then forced through that node,
/// whatever the CIDR/domain/port rules say (block wins).
pub const CGROUP_MODE_BYPASS: u8 = 1;
/// Deepest cgroup hierarchy level searched for a matching ancestor rule.
pub const CGROUP_MAX_DEPTH: i32 = 12;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// IPv6 扩展头号（下一头部字段），方案四的解析器需要逐条跳过它们。
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_DSTOPTS: u8 = 60;

/// 首片判决被后续分片继承的有效期（30 s）。IP ID 会被复用，超时后记录
/// 自然失效，不会把新数据报的分片误判成旧数据报的命运。
pub const FRAGMENT_VERDICT_TTL_NS: u64 = 30_000_000_000;

/// FLOW_TRACK 条目的空闲回收阈值与刷新节流。内核按单调时钟写
/// `last_seen_ns`，用户态 janitor 用 CLOCK_MONOTONIC 读同一个基准。
pub const FLOW_TRACK_IDLE_NS: u64 = 120_000_000_000;
pub const FLOW_TRACK_REFRESH_NS: u64 = 30_000_000_000;

/// [方案八] UDP/53 短流的 FLOW_TRACK 空闲回收阈值。DNS 查询每次换源端口，
/// 一条查询就占一条 track；用 120 s 的统一阈值会在高 QPS 下把 65536 条表
/// 灌满，导致 track_insert_failed、正常代理流的回程 framing 丢失。对齐
/// honk `is_short_lived_udp_traffic()` 跳过 conntrack 的意图，但 ant 的
/// FLOW_TRACK 同时承担 UDP 应答的 L2 framing，不能跳过，只能短回收。
/// 只按 FlowKey 判定，不占 TrackEntry 的 ABI 位；TCP/53 不受影响（长连接）。
pub const DNS_TRACK_IDLE_NS: u64 = 10_000_000_000;

/// [方案八] TCP/53（DNS over TCP, RFC 7766）同样劫持到用户态 DNS 引擎。
/// 内核只判 VERDICT_PROXY，长度前缀帧由 relay 在已 accept 的连接上处理。
pub const DNS_PORT: u16 = 53;

/// [方案七] TCP 首部 flags 字节（偏移 13）里的相关位。TC 层只读这一字节，
/// 不解析完整 TCP 状态机：SYN 用来声明"同一五元组的新 incarnation"，
/// FIN/RST 用来把流提前送入短回收窗口（对齐 honk 的 forward-SYN
/// publication 与 Closing 标记，但不需要 conntrack / sock_ops 全套）。
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_ACK: u8 = 0x10;

/// FLOW_TRACK 条目的 TCP 生命周期状态。放进原 `_pad` 里，结构体大小不变。
pub const TCP_STATE_OPEN: u8 = 0;
/// 见过 FIN/RST：janitor 用 TCP_CLOSE_GRACE_NS 而不是 120 s 回收。
pub const TCP_STATE_CLOSING: u8 = 1;
/// 只有 SYN 能把 CLOSING 重置回 OPEN（真正的新连接）。
/// 短窗口只对"彻底静默"的流生效：CLOSING 期间每个正向/回程包都强制刷新
/// last_seen_ns，所以半关闭（client FIN 后 server 继续推数据）不会被误删。
/// janitor 每 30 s 扫一次，实际回收落在静默后的下一轮扫描。
pub const TCP_CLOSE_GRACE_NS: u64 = 5_000_000_000;

/// 每源每秒新流预算的默认值（0 = 关闭）。实际限额是该值乘以 CPU 数，
/// 因为计数表是 LRU per-CPU hash。
pub const NEW_FLOW_LIMIT_DEFAULT: u32 = 0;

/// Immutable parameters written by userspace before programs attach.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Param {
    /// Host-side end of the veth pair bridging into `antns`.
    pub ant0_ifindex: u32,
    /// LAN capture interface (0 = disabled).
    pub lan_ifindex: u32,
    /// WAN capture interface (0 = disabled).
    pub wan_ifindex: u32,
    /// Verdict applied when no rule matches (VERDICT_*).
    pub default_verdict: u8,
    /// Set when UDP port 53 should be steered into the userspace DNS engine.
    pub dns_hijack: u8,
    /// Non-zero when any cgroup rule is configured (skips the per-packet
    /// cgroup lookup otherwise).
    pub cgroup_rules: u8,
    /// 1 = 启用每流判决缓存（FLOW_DECISION）；0 = 每包重判，便于排查规则问题。
    pub flow_cache: u8,
    /// 每族并行 UDP 监听 socket 数（1..=UDP_LISTENER_MAX）。sk_lookup 用它
    /// 作五元组哈希的模数，必须与用户态实际发布的槽位数一致。
    pub udp_workers: u8,
    /// 每源每秒新流预算（0 = 关闭）。仅作用于 LAN ingress 的缓存未命中
    /// 包，豁免 DNS 与分片；对齐 honk 的 NEW_FLOW_LIMIT_PER_CPU_SECOND。
    pub new_flow_limit: u32,
}

impl Param {
    pub const DEFAULT: Param = Param {
        ant0_ifindex: 0,
        lan_ifindex: 0,
        wan_ifindex: 0,
        default_verdict: VERDICT_PROXY,
        dns_hijack: 1,
        cgroup_rules: 0,
        flow_cache: 1,
        udp_workers: UDP_LISTENER_MAX as u8,
        new_flow_limit: NEW_FLOW_LIMIT_DEFAULT,
    };
}

/// Five-tuple flow key, addresses always stored as 16 bytes
/// (IPv4 uses the v4-mapped form `::ffff:a.b.c.d`, network byte order).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    /// 从报文端口字节解析出的**数值**（`(hi << 8) | lo`），不是网络字节序
    /// 存储。内核 `Pkt::flow_key()` 与用户态 `StaticMaps::flow_verdict()`
    /// 必须用同一个数值：写成 `port.to_be()` 会在小端机上把 53 变成
    /// 13568，导致 FLOW_TRACK 永远查不中、内核按规则选出的节点被静默丢弃。
    pub sport: u16,
    /// 同上：端口数值。
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 7],
}

impl FlowKey {
    pub const fn zeroed() -> FlowKey {
        FlowKey {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            sport: 0,
            dport: 0,
            proto: 0,
            _pad: [0; 7],
        }
    }

    pub fn reverse(&self) -> FlowKey {
        FlowKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            sport: self.dport,
            dport: self.sport,
            proto: self.proto,
            _pad: [0; 7],
        }
    }

    /// Map an IPv4 address into the v4-mapped IPv6 form (network byte order in/out).
    pub fn to_v6_mapped(v4: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[10] = 0xff;
        out[11] = 0xff;
        out[12..16].copy_from_slice(&v4);
        out
    }
}

/// Track entry published by the capture hooks (`lan_ingress`, `wan_egress`)
/// for every flow steered into the proxy. Consumed by `ant0_ingress` to
/// restore the original framing on replies.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrackEntry {
    /// Interface the flow was captured on (LAN TX / WAN RX-inject).
    pub ifindex: u32,
    /// 0 = flow originated from LAN (reply: restore MACs, TX).
    /// 1 = host-originated (reply: inject into WAN RX with BPF_F_INGRESS).
    pub from_wan: u8,
    /// The kernel verdict that sent this flow to userspace (VERDICT_NODE_BASE
    /// plus node index, or VERDICT_PROXY). Userspace reads it to pick the node.
    pub verdict: u8,
    /// [方案七] TCP_STATE_*；非 TCP 流恒为 OPEN。占用原来的 pad，ABI 大小不变。
    pub tcp_state: u8,
    pub _pad: [u8; 1],
    /// Captured framing: LAN client MAC (src) and router MAC (dst).
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    /// [方案五] 最近一次该流有包经过的时间（bpf_ktime_get_ns，单调时钟）。
    /// 用户态 janitor 按 CLOCK_MONOTONIC 比对后回收空闲条目，避免
    /// LruHashMap 静默驱逐活跃长连接导致回程丢帧。
    /// [方案七] 回程方向也会刷新它，单向长流（只有 server→client 数据）
    /// 不会因为正向 120 s 无包被误删。
    pub last_seen_ns: u64,
}

impl TrackEntry {
    pub const fn zeroed() -> TrackEntry {
        TrackEntry {
            ifindex: 0,
            from_wan: 0,
            verdict: 0,
            tcp_state: TCP_STATE_OPEN,
            _pad: [0; 1],
            smac: [0; 6],
            dmac: [0; 6],
            last_seen_ns: 0,
        }
    }
}

/// Per-IP verdict resolved by the userspace DNS engine from domain rules.
/// DNS 条目是运行时持续发布的，故意不参与规则换代：换规则后由
/// `publish_domain_ip` 发现 verdict 变化时递增 ROUTE_GENERATION，让每流
/// 缓存整体失效即可。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainRouteEntry {
    /// VERDICT_* value.
    pub verdict: u8,
    pub _pad: [u8; 7],
}

/// 静态规则表（PORT_ROUTE / CIDR_V4 / CIDR_V6）的 value。
///
/// `generation == 0` 是通配（启动时的初始规则永远生效）；正数只在
/// ROUTE_GENERATION 等于它时生效。这是 honk "ArrayOfMaps 两代原子切换"的
/// 轻量替代：用户态先把整套新规则以新世代写入（此时数据面仍读旧世代，
/// 看不见新条目、旧条目照旧服务），全部写完后再用一次 map update 翻转
/// ROUTE_GENERATION，瞬间切换。无需重载 hook，也不存在半新半旧的中间态。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RouteEntry {
    pub verdict: u8,
    pub _pad: [u8; 3],
    pub generation: u32,
}

impl RouteEntry {
    pub const fn new(verdict: u8, generation: u32) -> RouteEntry {
        RouteEntry {
            verdict,
            _pad: [0; 3],
            generation,
        }
    }
}

/// 每流判决缓存的 value：首包判一次写进去，后续包按五元组命中即用，
/// 直到 ROUTE_GENERATION 变化（规则热重载）或被 LRU 驱逐。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowDecisionEntry {
    pub verdict: u8,
    pub _pad: [u8; 3],
    pub generation: u32,
}

impl FlowDecisionEntry {
    pub const fn new(verdict: u8, generation: u32) -> FlowDecisionEntry {
        FlowDecisionEntry {
            verdict,
            _pad: [0; 3],
            generation,
        }
    }
}

/// [方案四] 一个 IP 数据报在重组期间的身份：源/目的地址、identification
/// 以及上层协议。IPv4 的 ID 只有 16 位，IPv6 Fragment header 的是 32 位，
/// 统一存成 u32。RFC 8200 只按 (src, dst, id) 重组，IPv6 后续片解析不到
/// 上层协议，所以 v6 的 l4proto 固定为 0，避免与首片不匹配。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragmentKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub id: u32,
    pub l4proto: u8,
    pub _pad: [u8; 3],
}

impl FragmentKey {
    pub const fn new(src_ip: [u8; 16], dst_ip: [u8; 16], id: u32, l4proto: u8) -> FragmentKey {
        FragmentKey {
            src_ip,
            dst_ip,
            id,
            l4proto,
            _pad: [0; 3],
        }
    }
}

const _: () = assert!(core::mem::size_of::<FragmentKey>() == 40);

/// [方案四] 首片判决被后续片继承的记录。`verdict == 0` 表示"首片放行"
///（用于清除 ID 复用留下的旧记录），其余为 VERDICT_* 值。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragmentVerdict {
    pub verdict: u8,
    pub _pad: [u8; 7],
    pub ktime_ns: u64,
}

/// [方案六] per-CPU 数据面计数。放在 PerCpuArray 里，每包的累加只写
/// 本 CPU 的槽位，零原子操作、零跨核缓存行竞争（honk OUTBOUND_STATS
/// 的同一手法）。用户态按 CPU 聚合后输出。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatsCounters {
    pub direct_pkts: u64,
    pub direct_bytes: u64,
    pub proxy_pkts: u64,
    pub proxy_bytes: u64,
    pub reply_pkts: u64,
    pub reply_bytes: u64,
    pub block_pkts: u64,
    pub frag_inherited: u64,
    pub new_flow_limited: u64,
    /// [方案七] FLOW_TRACK 是普通 HashMap，表满时 insert 会失败。以前这个
    /// 失败被静默丢弃，只表现为"某条流回程无记录"；现在计数可观测。
    pub track_insert_failed: u64,
    /// 新 SYN 复用五元组、覆盖了旧 incarnation 的 FLOW_TRACK 条目次数。
    pub tcp_syn_reset: u64,
    /// 被 FIN/RST 标记为 CLOSING 的流数量。
    pub tcp_closing: u64,
    /// [方案八] 命中 TCP/53 DNS-over-TCP 劫持、送进用户态 DNS 引擎的包数。
    /// 用来确认新路径真的生效（而不只是 UDP/53）。
    pub dns_tcp_pkts: u64,
}

impl StatsCounters {
    pub const fn zeroed() -> StatsCounters {
        StatsCounters {
            direct_pkts: 0,
            direct_bytes: 0,
            proxy_pkts: 0,
            proxy_bytes: 0,
            reply_pkts: 0,
            reply_bytes: 0,
            block_pkts: 0,
            frag_inherited: 0,
            new_flow_limited: 0,
            track_insert_failed: 0,
            tcp_syn_reset: 0,
            tcp_closing: 0,
            dns_tcp_pkts: 0,
        }
    }
}

/// [方案六] 每源每秒的新流窗口。LruPerCpuHashMap 让每个 CPU 独立计数，
/// 有效限额 = count 上限 × CPU 数，且窗口切换只是一次就地写。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewFlowWindow {
    pub second: u32,
    pub count: u32,
}

// Pod impls are only needed on the userspace side (aya map writes).
// The BPF side (aya-ebpf) has no Pod trait requirement for btf_maps.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for Param {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FlowKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TrackEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DomainRouteEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RouteEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FlowDecisionEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentVerdict {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for StatsCounters {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for NewFlowWindow {}
