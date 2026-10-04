//! IPv4/IPv6 分片重组（对齐 sing-tun / smoltcp 的 reassembly 语义）。
//!
//! system 栈此前对 IPv4 分片直接丢弃（mod.rs 中 TCP/UDP 分片分支），
//! 导致 DNS over TCP 大响应、Kerberos / NFS 等依赖分片的流量黑洞；
//! IPv6 分片同样被直接丢弃（T2 修复）。本模块在 TUN 读循环入口处
//! 对分片做重组，重组完成后按普通包继续走 NAT / dispatch 路径
//! （TCP/UDP/ICMP 统一覆盖）。
//!
//! 语义参照 RFC 791（IPv4）/ RFC 8200 §4.5（IPv6）：
//! - IPv4 以 (src, dst, id, proto) 标识一个数据报；
//! - IPv6 以 (src, dst, identification) 标识一个数据报；
//! - 非末片的 payload 长度必须为 8 字节对齐；
//! - 末片（MF=0）给出总长度，各片段连续覆盖 [0, total) 即完成；
//! - 重组超时（30s，RFC 791 建议 ≥15s）后丢弃并回收资源；
//! - IPv6 重组输出 = 不可分片部分（固定头 + 前置扩展头，其中指向
//!   fragment 头的 Next Header 字段被替换为 fragment 头的 Next Header）
//!   + 各片段拼接。

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// IPv6 Next Header：Fragment Header（RFC 8200）。
const IPV6_NH_FRAGMENT: u8 = 44;
/// IPv6 Next Header：Hop-by-Hop Options。
const IPV6_NH_HOPOPT: u8 = 0;
/// IPv6 Next Header：Routing。
const IPV6_NH_ROUTING: u8 = 43;
/// IPv6 Next Header：Destination Options。
const IPV6_NH_DSTOPTS: u8 = 60;

/// 单个数据报的重组超时。
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
/// 最大并发重组条目数（防膨胀；超出时淘汰最旧条目）。
const MAX_ENTRIES: usize = 1024;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct FragmentKey {
    src: u32,
    dst: u32,
    id: u16,
    proto: u8,
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct FragmentKeyV6 {
    src: [u8; 16],
    dst: [u8; 16],
    id: u32,
}

struct FragmentEntry {
    /// offset（字节）→ 分片 payload
    frags: std::collections::BTreeMap<usize, Vec<u8>>,
    /// 总长度：IPv4 为含 IP 头的完整数据报长度；IPv6 为可分片部分
    /// 总长（不含头部）。由末片（MF=0）给出。
    total_len: Option<usize>,
    /// 首个片段的头部模板（用于重组输出）
    header: Vec<u8>,
    created: Instant,
}

/// IPv4/IPv6 分片重组器。
#[derive(Default)]
pub(crate) struct IpDefragmenter {
    entries: HashMap<FragmentKey, FragmentEntry>,
    v6_entries: HashMap<FragmentKeyV6, FragmentEntry>,
}

impl IpDefragmenter {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            v6_entries: HashMap::new(),
        }
    }

    /// 喂入一个 IPv4 分片。重组完成时返回完整数据报（MF/offset 清零、
    /// 总长度与校验和已修正），否则返回 None。
    ///
    /// 非分片包（offset==0 且 MF=0）不做处理，由调用方走正常路径。
    pub(crate) fn feed(&mut self, raw: &[u8], now: Instant) -> Option<Vec<u8>> {
        if raw.len() < 20 {
            return None;
        }
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if ihl < 20 || ihl >= raw.len() {
            return None;
        }
        // DF 置位的分片是非法的（RFC 6864 禁止），丢弃
        let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
        if flags_frag & 0x4000 != 0 {
            return None;
        }
        let total_len_field = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        // TUN 读到的包可能带链路层 padding，按 total_len 截断
        let pkt_len = total_len_field.min(raw.len());
        if pkt_len < ihl {
            return None;
        }
        let more_fragments = flags_frag & 0x2000 != 0;
        let offset = (flags_frag & 0x1fff) as usize * 8;
        let payload = raw[ihl..pkt_len].to_vec();
        // R4：RFC 791 要求非末片载荷长度必须为 8 字节对齐（分片偏移以 8 字节
        // 为单位），否则无法保证后续分片无重叠/空洞。旧实现未校验，恶意
        // 构造的非对齐分片可导致错误重组。直接丢弃该分片（条目超时回收）。
        if more_fragments && !payload.len().is_multiple_of(8) {
            return None;
        }
        let frag_data = payload;
        let key = FragmentKey {
            src: u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]),
            dst: u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]),
            id: u16::from_be_bytes([raw[4], raw[5]]),
            proto: raw[9],
        };

        // GC：超时 / 超量回收
        self.gc(now);

        let entry = self.entries.entry(key).or_insert_with(|| FragmentEntry {
            frags: std::collections::BTreeMap::new(),
            total_len: None,
            header: Vec::new(),
            created: now,
        });
        // R4：仅首个分片（offset==0）的头部作为重组输出模板。RFC 791：重组
        // 结果的头部取自首片。旧实现每次 feed 都覆盖 header，异构路径分片
        // 的 IHL/ToS/TTL 不一致（或恶意构造）时重组输出错误头部。
        if offset == 0 {
            entry.header = raw[..ihl].to_vec();
        }
        // 空载荷分片（pkt_len == ihl）没有覆盖意义，跳过插入
        if !frag_data.is_empty() {
            entry.frags.insert(offset, frag_data);
        }
        if !more_fragments {
            // 末片自身的 IP total_len 只是它自己的长度（ihl + 本片载荷）；
            // 整个数据报总长 = 载荷偏移 + 末片自身长度（offset 含义为
            // 载荷内字节偏移，ihl 抵消）。
            entry.total_len = Some(offset + pkt_len);
        }

        // 尝试重组
        let total = entry.total_len?;
        let ihl = entry.header.len();
        // R4：尚未收到首片（header 为空）时无法重组，等待首片到达
        if ihl == 0 {
            return None;
        }
        if total <= ihl {
            self.entries.remove(&key);
            return None;
        }
        // 连续性检查：分片偏移是载荷相对偏移，需无空洞地覆盖
        // [0, total - ihl)（BTreeMap 按偏移有序，逐段比较即可）
        let payload_total = total - ihl;
        let mut expected = 0usize;
        for (&off, data) in entry.frags.iter() {
            if off != expected {
                return None; // 仍有空洞，等待更多分片
            }
            expected = off + data.len();
        }
        if expected != payload_total {
            return None;
        }
        // 重组输出
        let entry = self.entries.remove(&key)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&entry.header);
        for (_, data) in entry.frags {
            out.extend_from_slice(&data);
        }
        out.truncate(total);
        // 修正：总长度 / 清零 MF 与 offset / 重算头部校验和
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[6..8].copy_from_slice(&[0x00, 0x00]);
        let csum = !crate::tun::packet::internet_checksum(&out[..ihl]);
        out[10] = (csum >> 8) as u8;
        out[11] = (csum & 0xff) as u8;
        Some(out)
    }

    fn gc(&mut self, now: Instant) {
        gc_map(&mut self.entries, now);
        gc_map(&mut self.v6_entries, now);
    }
}

/// 判断是否为 IPv6 分片包（扩展头链中含 fragment header）。
/// 非分片包返回 false，由调用方走正常路径。
pub(crate) fn ipv6_is_fragment(raw: &[u8]) -> bool {
    split_ipv6_fragment_parts(raw).is_some()
}

/// `split_ipv6_fragment_parts` 的返回结果：
/// `(prev_nh_pos, next_header, frag_offset, more_fragments, ident, frag_data)`。
type Ipv6FragmentParts<'a> = (usize, u8, usize, bool, u32, &'a [u8]);

/// 解析 IPv6 扩展头链，定位 fragment header。
///
/// 返回值各字段见 [`Ipv6FragmentParts`]：
/// - `prev_nh_pos`：指向 fragment 头的那个 Next Header 字段的字节偏移
///   （固定头为 6，或前置扩展头的 NH 字段位置），重组输出时需将
///   该字节替换为 fragment 头的 Next Header（RFC 8200 §4.5）；
/// - `frag_data`：fragment 头之后的可分片部分。
///
/// 非分片包 / 扩展头链畸形时返回 None。
fn split_ipv6_fragment_parts(raw: &[u8]) -> Option<Ipv6FragmentParts<'_>> {
    if raw.len() < 40 {
        return None;
    }
    let mut nh = raw[6];
    let mut prev_nh_pos = 6usize;
    let mut off = 40usize;
    loop {
        match nh {
            IPV6_NH_HOPOPT | IPV6_NH_ROUTING | IPV6_NH_DSTOPTS => {
                let ext = raw.get(off..)?;
                if ext.len() < 2 {
                    return None;
                }
                // 扩展头长度 = (Hdr Ext Len 字段 + 1) * 8 字节
                let ext_len = (ext[1] as usize + 1) * 8;
                if ext.len() < ext_len {
                    return None;
                }
                nh = ext[0];
                prev_nh_pos = off;
                off += ext_len;
            }
            IPV6_NH_FRAGMENT => {
                let frag = raw.get(off..)?;
                if frag.len() < 8 {
                    return None;
                }
                let off16 = u16::from_be_bytes([frag[2], frag[3]]);
                // 偏移以 8 字节为单位（高 13 位），最低位为 M 标志
                let frag_offset = (off16 >> 3) as usize * 8;
                let more = off16 & 1 != 0;
                let ident = u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]);
                let data = raw.get(off + 8..)?;
                return Some((prev_nh_pos, frag[0], frag_offset, more, ident, data));
            }
            _ => return None, // 到达传输层头，无 fragment 头
        }
    }
}

impl IpDefragmenter {
    /// 喂入一个 IPv6 分片。重组完成时返回完整数据报（不可分片部分的
    /// Next Header 已修正、payload length 已重算），否则返回 None。
    ///
    /// 非分片包返回 None，由调用方走正常路径。
    pub(crate) fn feed_ipv6(&mut self, raw: &[u8], now: Instant) -> Option<Vec<u8>> {
        let (prev_nh_pos, nh, frag_offset, more, ident, frag_data) =
            split_ipv6_fragment_parts(raw)?;
        // R4 同款校验：非末片载荷必须 8 字节对齐
        if more && frag_data.len() % 8 != 0 {
            return None;
        }
        let key = FragmentKeyV6 {
            src: raw[8..24].try_into().ok()?,
            dst: raw[24..40].try_into().ok()?,
            id: ident,
        };

        // GC：超时 / 超量回收（与 v4 共用限制）
        self.gc(now);

        let entry = self
            .v6_entries
            .entry(key)
            .or_insert_with(|| FragmentEntry {
                frags: std::collections::BTreeMap::new(),
                total_len: None,
                header: Vec::new(),
                created: now,
            });
        // 头部模板仅取首片（R4 同语义）：不可分片部分（固定头 +
        // 前置扩展头），并把指向 fragment 头的 Next Header 修正为
        // fragment 头的 Next Header。尚未收到首片时 header 为空。
        if frag_offset == 0 {
            let hdr_start = raw.len() - frag_data.len() - 8;
            let mut header = raw[..hdr_start].to_vec();
            if let Some(slot) = header.get_mut(prev_nh_pos) {
                *slot = nh;
            }
            entry.header = header;
        }
        if !frag_data.is_empty() {
            entry.frags.insert(frag_offset, frag_data.to_vec());
        }
        if !more {
            // v6 条目的 total_len 语义为「可分片部分总长」（不含头部）
            entry.total_len = Some(frag_offset + frag_data.len());
        }

        // 尝试重组：无空洞地覆盖 [0, total)
        let total = entry.total_len?;
        if entry.header.is_empty() {
            // 尚未收到首片，等待
            return None;
        }
        let mut expected = 0usize;
        for (&off, data) in entry.frags.iter() {
            if off != expected {
                return None; // 仍有空洞，等待更多分片
            }
            expected = off + data.len();
        }
        if expected != total {
            return None;
        }
        let entry = self.v6_entries.remove(&key)?;
        let mut out = Vec::with_capacity(entry.header.len() + total);
        out.extend_from_slice(&entry.header);
        for (_, data) in entry.frags {
            out.extend_from_slice(&data);
        }
        // 重算 payload length（RFC 8200：固定头长度之外的字节数）
        if out.len() >= 40 {
            let payload_len = (out.len() - 40) as u16;
            out[4..6].copy_from_slice(&payload_len.to_be_bytes());
        }
        Some(out)
    }
}

/// GC 共享实现：超时回收 + 按创建时间淘汰最旧条目（防膨胀）。
fn gc_map<K: Ord + Copy + std::hash::Hash>(map: &mut HashMap<K, FragmentEntry>, now: Instant) {
    map.retain(|_, e| now.duration_since(e.created) < REASSEMBLY_TIMEOUT);
    if map.len() > MAX_ENTRIES {
        let mut by_age: Vec<(Instant, K)> = map.iter().map(|(k, e)| (e.created, *k)).collect();
        by_age.sort_unstable();
        let evict = by_age.len() - MAX_ENTRIES;
        for (_, k) in by_age.into_iter().take(evict) {
            map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_fragment(id: u16, offset_units: u16, more: bool, payload: &[u8]) -> Vec<u8> {
        let ihl = 20usize;
        let mut pkt = vec![0u8; ihl + payload.len()];
        let total_len = pkt.len() as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        let mut flags_frag = offset_units;
        if more {
            flags_frag |= 0x2000;
        }
        pkt[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[ihl..].copy_from_slice(payload);
        let csum = !crate::tun::packet::internet_checksum(&pkt[..ihl]);
        pkt[10] = (csum >> 8) as u8;
        pkt[11] = (csum & 0xff) as u8;
        pkt
    }

    #[test]
    fn reassembles_two_fragments() {
        let mut d = IpDefragmenter::new();
        let now = Instant::now();
        let p1 = [0xa5u8; 16];
        let p2 = [0x5a; 8];
        // 乱序：先喂末片（offset=16，载荷 8 字节），应仍为 None
        assert!(d
            .feed(&build_fragment(7, 2, false, &p2[..]), now)
            .is_none());
        // 再喂首片（offset=0，载荷 16 字节，MF=1），重组完成
        let done = d.feed(&build_fragment(7, 0, true, &p1[..]), now).unwrap();
        assert_eq!(done.len(), 20 + 16 + 8);
        assert_eq!(&done[20..36], &p1[..]);
        assert_eq!(&done[36..44], &p2[..]);
        // flags/offset 清零、总长正确
        assert_eq!(u16::from_be_bytes([done[6], done[7]]), 0);
        assert_eq!(u16::from_be_bytes([done[2], done[3]]), 44);
    }

    #[test]
    fn times_out_stale_entry() {
        let mut d = IpDefragmenter::new();
        let now = Instant::now();
        let p1 = vec![1u8; 8];
        assert!(d.feed(&build_fragment(9, 0, true, &p1), now).is_none());
        // 超时后新 id 同 key？不同 id → 不同条目；超时条目被回收
        let later = now + REASSEMBLY_TIMEOUT * 2;
        let p2 = vec![2u8; 8];
        assert!(d.feed(&build_fragment(9, 2, false, &p2), later).is_none());
    }

    /// 构造 IPv6 分片包：固定头(40B) + fragment 头(8B) + payload。
    /// `nh` 为 fragment 头的 Next Header（重组后应出现在固定头 [6]）。
    fn build_v6_fragment(
        ident: u32,
        offset_units: u16,
        more: bool,
        nh: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + 8 + payload.len()];
        pkt[0] = 0x60;
        let payload_len = (8 + payload.len()) as u16;
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt[6] = IPV6_NH_FRAGMENT; // 固定头 NH → fragment
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40]
            .copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // fragment 头
        pkt[40] = nh;
        let mut off_more = offset_units << 3;
        if more {
            off_more |= 1;
        }
        pkt[42..44].copy_from_slice(&off_more.to_be_bytes());
        pkt[44..48].copy_from_slice(&ident.to_be_bytes());
        pkt[48..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn reassembles_two_v6_fragments_out_of_order() {
        let mut d = IpDefragmenter::new();
        let now = Instant::now();
        let p1 = vec![0xa5u8; 16];
        let p2 = vec![0x5a; 8];
        // 乱序：先喂末片（offset=16，MF=0），应为 None
        assert!(d
            .feed_ipv6(&build_v6_fragment(42, 2, false, 17, &p2), now)
            .is_none());
        // 再喂首片（offset=0，MF=1），重组完成
        let done = d
            .feed_ipv6(&build_v6_fragment(42, 0, true, 17, &p1), now)
            .unwrap();
        // 40B 固定头 + 16 + 8 载荷
        assert_eq!(done.len(), 40 + 16 + 8);
        // 固定头 NH 已从 44 修正为 17（UDP）
        assert_eq!(done[6], 17);
        // payload length 已重算
        assert_eq!(u16::from_be_bytes([done[4], done[5]]), 24);
        assert_eq!(&done[40..56], &p1[..]);
        assert_eq!(&done[56..64], &p2[..]);
        // 原子分片（offset=0, M=0）：立即重组为自身，NH 同样被修正
        let atomic = d
            .feed_ipv6(&build_v6_fragment(43, 0, false, 17, &p1), now)
            .unwrap();
        assert_eq!(atomic[6], 17);
        assert_eq!(&atomic[40..], &p1[..]);
    }
}
