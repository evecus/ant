# ant eBPF datapath (Linux only)

把路由规则里的 **IP-CIDR 部分**下沉到内核：四个 TC 分类程序（honk 的四角色布局）对
转发流量与**本机产生的流量**直接判 `proxy` / `direct` / `block`，只把需要代理的流交给
tproxy inbound。域名规则、sniffing、策略组选择仍然在用户态完成。

参考实现：[honk](https://github.com/)（dae 血统，aya + cgroup/TC）。本实现按 ant 的
架构做了裁剪，详见下面的「与 honk 的差异」。

## 目录结构

```
src/ebpf/
├── common/          共享 ABI crate（ant-ebpf-common），no_std，BPF 与用户态共用
│   └── src/{lib,conn,dae_ip,event,redirect}.rs
├── program/         BPF 程序（独立 package，bpfel-unknown-none）
│   └── src/{main,maps,transport,decide,ingress,egress,contrack,cgroup,process_name,
│            action,event,stats,errno,log_shim}.rs
├── mod.rs           EbpfManager：加载 / 挂载 / 路由同步 / 统计
├── config.rs        `ebpf:` YAML 段
├── loader.rs        对象嵌入 + override_global（PARAM / task_struct 偏移量）
├── attach.rs        四角色 TC + cgroup 挂载、网卡发现
├── nft.rs           数据面自有的 nft 表 `inet ant-ebpf`
├── route.rs         数据面自有的策略路由（表 82 / pref 1026 / fwmark 0x80）
├── maps.rs          类型化 map 句柄
├── route_sync.rs    ant 路由表 → LPM trie
├── events.rs        ringbuf 事件消费
├── janitor.rs       过期流清理 + 路由表失效刷新
├── probe.rs         内核能力探测（BTF 偏移量、cgroup2、ktime）
└── btf.rs           极简 BTF 解析器（只取结构体成员偏移）
```

## 构建

BPF 程序需要 nightly + `bpf-linker`（`bpfel-unknown-none` 是 Tier-3 目标，必须
`-Zbuild-std=core`）：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release --features ebpf
```

`build.rs` 会读取 `src/ebpf/program/rust-toolchain.toml` 里 pin 的 nightly 版本，
自动编译 BPF 目标、校验产物带 `.BTF` 段（aya 拒绝没有 BTF 的对象），然后把 ELF
拷进 `OUT_DIR` 并以 `ANT_EBPF_OBJECT` 暴露给 `include_bytes!`。

没有 nightly / bpf-linker 时设 `ANT_EBPF_SKIP_BUILD=1`：build.rs 写一个占位对象，
用户态代码照常完整 typecheck（BPF 对象在真机上另行编译）。

不开 `ebpf` feature 时，aya 与整个 `src/ebpf` 都不参与编译 —— macOS / Windows 与
纯 stable 的 Linux 构建完全不受影响。

## 四角色布局（honk parity）

| 角色          | 挂载点    | 覆盖流量                              |
|---------------|-----------|---------------------------------------|
| `lan_ingress` | LAN ingress | 转发（客户端）流量                   |
| `lan_egress`  | LAN egress  | LAN 劫持流的回复侧统计               |
| `wan_ingress` | WAN ingress | 本机劫持流的回复侧统计               |
| `wan_egress`  | WAN egress  | **本机产生的流量**                   |

单宿主（LAN 与 WAN 同一网卡）只挂 `lan_ingress` + `wan_egress`：`lan_egress` 会与
本机出向流量打架，`wan_ingress` 与 `lan_ingress` 重复。bridge slave 挂 L2 变体；
bond slave 的 egress 角色是 `wan_egress`（bond 驱动在 slave egress hook 之前就构造好了
以太头，本机流量在那里可见）。

`wan_egress` 用 `bpf_redirect(lo, BPF_F_INGRESS)` 把本机流量打到回环口：内核
`skb_scrub_packet` 丢掉原 dst（xnet=false 保留 mark），零化 dst MAC 后 input 路由重新
求值，命中 `ip rule fwmark 0x80 table 82` → 本地 tproxy 端口。纯 egress 语义
（flags=0）保留 dst、跳过查找，因此不用。

## 数据面行为

| 判定     | 动作                                                              |
|----------|-------------------------------------------------------------------|
| `proxy`  | mark `0x80` + 动作码（bits 16-23）→ 自有 nft tproxy → tproxy inbound |
| `direct` | 只打动作码（低字节为 0）→ 内核正常转发，ant 完全看不到这条流         |
| `block`  | `TC_ACT_SHOT`，L3 直接丢                                           |

`direct` 必须打动作码：自有 nft 的兜底链 `meta mark & 0x00ff0000 == 0` 据此跳过 direct
流，否则它们会被重新劫持（honk 的 `fast_path_decision` 对 direct 同样是
`set_mark` + 原生路径，这是该语义在 ant nft 架构下的忠实移植）。

跳过（原样放行）的情况：

- 数据面未 ready（路由表发布前）
- 已带 hijack fwmark（低 8 位 = 0x80）：防回环
- ant 自身 socket 的 SO_MARK（`global.mark`，精确相等比较）—— 出站连接、tproxy
  listener / accepted stream、UDP 回复 raw socket 全部带此 mark
- 广播 / 组播、DHCP / mDNS / SSDP / LLMNR（`dst_is_special`）
- 目的端口 53：DNS 走自有 nft `dstnat` redirect 与 DNS hijack
- 目的地址是本机（`bpf_fib_lookup` 返回 `NOT_FWDED`）：本机服务、回给 ant 自身
  socket 的应答，以及 `param.local_ip`（ant 管理地址，防环）
- 保留目的地址（`RESERVED_IP4/6`，含 10/8、192.168/16、224/4 …）—— 与 nft
  `ip daddr @reserved_ip return` 完全对齐，以 `direct` 身份**先于**用户规则发布，
  因此 LAN→LAN、入站端口映射、回到 LAN 客户端的应答都不会被劫持
- `wan_egress` 上 `ingress_ifindex != 0` 的包：已被 `lan_ingress` 判过，
  `TC_ACT_UNSPEC` 交还其它分类程序
- 非 TCP/UDP、分片包、ICMPv6、解析失败（负 errno → 丢，其它 → 放行）

TCP 只对 **纯 SYN**（`SYN && !ACK`）做判定，其余报文走 conntrack 缓存；已建连的
proxy 流必须重新打标，否则会被内核按普通路由转发出去，连接会断。

## 与 ip_auto_route 完全独立

两套控制面**互斥**（`Config::validate` 同时开启直接拒绝）：它们会在同一批包上安装
不同的 nft 表与策略路由，互相覆盖对方的 direct 决策。

| 资源          | 数据面                        | `ip_auto_route`        |
|---------------|-------------------------------|------------------------|
| nft 表        | `inet ant-ebpf`               | `inet ant-ip-auto-route` |
| 策略路由      | 表 82, pref 1026              | 表 80/81, pref 1024/1025 |
| 接口配置      | `ebpf.lan-interfaces` / `-wan-` | `ip-auto-route.lan-interface` |
| 保留 IP       | 本模块内的自有副本            | `RESERVED_IP4/6`       |

因此 `ebpf.enabled` 不再要求 `ip-auto-route.enable`；数据面启动失败是 **fatal**
（此模式下它是唯一的透明代理控制面，没有 nft 管道可以退回）。

## 与 nft 的配合（重要）

数据面把动作码写进 mark 16-23 位；自有 nft 表 `inet ant-ebpf` 的链序
（`mangle - 1` → `mangle` → `dstnat - 10`）：

```
router_prerouting: iifname "lo" … meta mark & 0xff == 0x80   tproxy to :<port>
lan_prerouting:    iifname @lan_inbound_device … jump lan_fallback
lan_fallback:      ct direction reply / fib local / reserved / :53 → return
                   meta mark & 0x00ff0000 == 0 → set mark 0x80 + accept（兜底）
dstnat:            iifname @lan_inbound_device jump lan_dns_hijack（redirect :53）
nat_output:        ant 自身 socket mark → return；fib local → return；DNS hijack
```

`router_prerouting` 先于 `lan_prerouting`：经 `lo` 到达的包（LAN 策略路由来，或
`wan_egress` redirect 来）直接拿监听 socket。DNS skip 必须置于 `lan_fallback` 标记
规则之前，否则 dstnat 前的 DNS 会被打上 0x80。

不装 output 回退 mark 链：`mangle_output`（priority mangle = -150）先于 TC egress
执行，装了它 `wan_egress` 永远看不到未标记的本机流量，形同虚设（honk 同款语义：
not-ready 窗口内本机流量不代理）。

## 运行要求

- Linux ≥ 5.10 且 `/sys/kernel/btf/vmlinux` 可读（BTF-defined map；
  `wan_egress` 需要 5.10 的 `__sk_buff.ingress_ifindex`）
- `CAP_BPF` + `CAP_NET_ADMIN`（通常 root）
- `global.tproxy-port > 0`（数据面把 proxy 流交给 tproxy inbound）
- 非零 `global.mark`，且低字节不是 0x80/0x81、bits 16-23 为 0
- 老内核（< 5.11）需要提高 `RLIMIT_MEMLOCK`，`EbpfManager::start` 会自动尝试

## 配置

```yaml
ebpf:
  enabled: true
  lan-interfaces: []       # 空 = 自动发现（所有非 lo 的 up 网卡，排除 WAN）；
                           # 配置的 bridge slave 会解析成它的 master
  wan-interfaces: []       # 空 = 自动发现（持有默认路由的网卡）
  dns-hijack: true         # :53 redirect 到 ant 的 DNS listener
  cgroup: true             # cookie → PID/进程名（仅可观测性）
  cgroup-path: /sys/fs/cgroup
  interface-rescan-secs: 30 # 0 = 关闭热插拔重扫
```

## 可调/已知限制

- **只同步 IP-CIDR / IP-CIDR6 规则**：`RULE-SET`、域名、源 IP、端口规则全部留在
  用户态。只要规则表里存在任何非 IP-CIDR 规则，MATCH 兜底就固定为 `proxy`
  （交给用户态裁决），否则才会用 MATCH 的真实 outbound。
- **首匹配语义 vs 最长前缀**：ant 是「按序首匹配」，LPM 是「最长前缀」。被前面更
  短前缀覆盖的规则会被丢弃（首匹配下它本来也不会命中）。
- **not-ready 窗口**：路由表发布前、以及主动 `suspend` 期间，数据面不打标，
  流量走自有 nft 兜底链（未标记 → 打 0x80 → tproxy）。
- 沙箱内无法做真实加载验证（seccomp 拦截 `bpf()`），请在目标机器上用
  `bpftool prog list` / `bpftool map dump` 复核。
