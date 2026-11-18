//! eBPF map definitions. Contract shared with `ant-ebpf-common` and the
//! userspace writers in `ant`.
//!
//! Trimmed from honk's 40+ maps down to seven surfaces:
//! FLOW_TRACK (reply framing), DOMAIN_ROUTE (DNS-derived per-IP verdicts),
//! CIDR tries, PORT_ROUTE, LISTEN_SOCKETS, SK_IDENTITY (loop prevention).

use aya_ebpf::btf_maps::{
    HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray, SkStorage, SockMap,
};
use aya_ebpf::helpers::bpf_sk_storage_get;
use aya_ebpf::macros::{btf_map, map};
use aya_ebpf::maps::lpm_trie::LpmTrie;
use aya_ebpf::Global;
use aya_ebpf_bindings::helpers::bpf_skb_ancestor_cgroup_id;
use ant_ebpf_common::{
    CGROUP_MAX_DEPTH, DomainRouteEntry, FlowDecisionEntry, FlowKey, FragmentKey, FragmentVerdict,
    NewFlowWindow, Param, RouteEntry, StatsCounters, TrackEntry, CONTROL_MARK,
};
pub use ant_ebpf_common::{KEY_TCP4, KEY_TCP6, KEY_UDP4_BASE, KEY_UDP6_BASE, LISTEN_SLOTS};

#[unsafe(no_mangle)]
pub static PARAM: Global<Param> = Global::new(Param::DEFAULT);

/// Forward-direction flow -> captured framing, for reply restoration in
/// `ant0_ingress` (mirrors honk's REDIRECT_TRACK / CLIENT_REPLY_TRACK).
///
/// [方案五] 从 LruHashMap 换成普通 HashMap + BPF_F_NO_PREALLOC：这张表是
/// 回程能否送回客户端的唯一依据，内核 LRU 在接近容量时会静默驱逐一条
/// 仍然活跃的长连接，直接导致回程丢帧。普通表满时 insert 只是失败（可
/// 观测、可重试），内存按需分配；由用户态 janitor 按 last_seen_ns 回收
/// 空闲条目。这正是 honk 对 CONN_STATE_MAP 的取舍。
/// 注意 FLOW_DECISION 仍保留 LRU：它只是判决缓存，被驱逐最多退化成
/// 重判一次，不影响正确性（对应 honk 保留 LRU 的 CLIENT_REPLY_TRACK）。
#[btf_map]
pub static FLOW_TRACK: HashMap<FlowKey, TrackEntry, 65536, 1> = HashMap::new();

/// [方案四] 首片判为 PROXY / BLOCK 的数据报，后续分片继承同一命运。
/// 小容量 + 30s TTL 足够覆盖重组窗口；LRU 驱逐只会让后续片退回原来的
/// 地址级判决，不会破坏已有连接。
#[btf_map]
pub static FRAG_VERDICT: LruHashMap<FragmentKey, FragmentVerdict, 4096> = LruHashMap::new();

/// [方案六] per-CPU 计数槽，单条目打包全部计数器。
#[btf_map]
pub static DATAPATH_STATS: PerCpuArray<StatsCounters, 1> = PerCpuArray::new();

/// [方案六] 每源每秒新流预算。per-CPU 值让各 CPU 无需原子就能计数，
/// LRU 满时只遗忘某个源最近的计数，不影响已有流。
#[btf_map]
pub static NEW_FLOW_RATE: LruPerCpuHashMap<[u8; 16], NewFlowWindow, 4096> =
    LruPerCpuHashMap::new();

/// [方案一] 每流判决缓存：FlowKey -> (verdict, generation)。首包跑完
/// decide() 后写入，同流后续包只查这一张表，省掉 4~5 次规则表查找。
/// 缓存值带 generation，ROUTE_GENERATION 一变即整体失效，规则热重载后
/// 不会出现"旧判决一直粘在流上"的正确性问题。
#[btf_map]
pub static FLOW_DECISION: LruHashMap<FlowKey, FlowDecisionEntry, 65536> = LruHashMap::new();

/// [方案三] 当前生效的规则世代，由用户态在整套静态规则写完后一次性翻转。
/// 单槽 HashMap 是为了运行时可写（Global/.rodata 只在 load 时可设）。
#[btf_map]
pub static ROUTE_GENERATION: HashMap<u32, u32, 1, 0> = HashMap::new();

#[inline(always)]
pub fn route_generation() -> u32 {
    ROUTE_GENERATION
        .get_ptr(0u32)
        .map(|p| unsafe { *p })
        .unwrap_or(0)
}

/// [方案七] 数据面准入门控，对应 honk 的 DATAPATH_STATE_MAP /
/// `datapath_ready()`（.agents/rules/datapath.md "Datapath admission"）：
/// 所有内部 hook、规则表、监听器 FD 与 recv 循环就绪之后才置 1，退出时
/// 先清 0 再拆监听器。
///
/// ant 的 `load_and_attach()` 一返回 TC hook 就已经在收包，而此时
/// CIDR/PORT/DOMAIN_ROUTE 全空、LISTEN_SOCKETS 还没发布：包会按
/// default_verdict 判成 PROXY 被 redirect 进 ant0，再在 sk_lookup 里
/// SK_DROP。以前这个窗口只能靠"启动够快"掩盖。未就绪时直接 TC_ACT_OK
/// 让包走原栈（fail-open），既不误代理也不丢包。
/// 用单槽 HashMap（与 ROUTE_GENERATION 同款）而非 Array，避免引入 aya-ebpf
/// 0.2 里未在本 crate 验证过的 Array 泛型签名。
#[btf_map]
pub static DATAPATH_STATE: HashMap<u32, u32, 1, 0> = HashMap::new();

#[inline(always)]
pub fn datapath_ready() -> bool {
    DATAPATH_STATE
        .get_ptr(0u32)
        .map(|p| unsafe { *p } != 0)
        .unwrap_or(false)
}

/// dst IP -> verdict, published by the userspace DNS engine whenever a DNS
/// answer resolves a domain that carries a routing decision
/// (mirrors dae's routing_map idea: eBPF never inspects domain strings).
/// DNS 表不参与换代：它本来就是按每次 DNS 应答动态发布的。
#[btf_map]
pub static DOMAIN_ROUTE: LruHashMap<[u8; 16], DomainRouteEntry, 65536> = LruHashMap::new();

/// Destination port -> verdict. value 带 generation，见 RouteEntry 说明。
#[btf_map]
pub static PORT_ROUTE: HashMap<u16, RouteEntry, 1024, 1> = HashMap::new();

/// CIDR -> verdict, longest prefix match. Legacy maps: LpmTrie is not yet a
/// BTF map in aya-ebpf. Key data is raw network-byte-order address bytes.
#[map]
pub static CIDR_V4: LpmTrie<[u8; 4], RouteEntry> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static CIDR_V6: LpmTrie<[u8; 16], RouteEntry> = LpmTrie::with_max_entries(65536, 0);

/// Transparent listeners published by userspace inside `antns`.
/// [方案二] 槽位布局：0 = TCP4, 1 = TCP6,
/// 2..2+UDP_LISTENER_MAX-1 = 并行 UDP4，其后 UDP_LISTENER_MAX 个 = 并行 UDP6。
/// sk_lookup 按五元组哈希取模 udp_workers 选槽位，保证同一条流的所有
/// 数据报落到同一个 socket（用户态每个 socket 有独立的 flow 表）。
/// 2 TCP + 2 * UDP_LISTENER_MAX UDP = 10。SockMap 的容量是编译期常量，
/// 必须等于 common 里的 LISTEN_SLOTS；这里写成字面量并留一个静态断言。
#[btf_map]
pub static LISTEN_SOCKETS: SockMap<10> = SockMap::new();

const _: () = assert!(LISTEN_SLOTS == 10);

/// cgroup v2 id -> CGROUP_MODE_* for host-originated traffic. Filled and kept
/// fresh by userspace (`cgroup.rs`); an ancestor's rule covers its whole
/// subtree and the deepest matching rule wins.
#[btf_map]
pub static CGROUP_RULES: HashMap<u64, u8, 1024, 0> = HashMap::new();

/// Userspace marks every control-plane dial socket (SOCKS5, DNS upstream)
/// both with skb mark CONTROL_MARK (SO_MARK, reflected on egress) and with
/// this sk_storage flag; `wan_egress` passes marked sockets so the proxy
/// never captures its own outbound traffic (loop prevention).
#[btf_map]
pub static SK_IDENTITY: SkStorage<u32> = SkStorage::new();

#[inline(always)]
pub fn is_control_plane_socket(skb: *mut aya_ebpf_bindings::bindings::__sk_buff) -> bool {
    // Cheap check first: SO_MARK on the dial socket shows up as skb->mark.
    if unsafe { (*skb).mark } == CONTROL_MARK {
        return true;
    }
    let sk = unsafe { (*skb).__bindgen_anon_2.sk };
    if sk.is_null() {
        return false;
    }
    let map = (&raw const SK_IDENTITY).cast_mut().cast();
    !unsafe { bpf_sk_storage_get(map, sk.cast(), core::ptr::null_mut(), 0) }.is_null()
}

/// CGROUP_MODE_* for the socket that owns this skb (0 = no rule). Walks the
/// cgroup ancestry root-first so the deepest rule overrides its parents.
/// Sockets without a full socket (timewait, request socks) report cgroup 0.
#[inline(always)]
pub fn cgroup_mode(skb: *mut aya_ebpf_bindings::bindings::__sk_buff) -> u8 {
    let mut mode = 0u8;
    for level in 0..CGROUP_MAX_DEPTH {
        let id = unsafe { bpf_skb_ancestor_cgroup_id(skb, level) };
        if id == 0 {
            break;
        }
        if let Some(m) = CGROUP_RULES.get_ptr(id) {
            mode = unsafe { *m };
        }
    }
    mode
}
