//! HY2 UDP packet codec (aligned with clash-rs / official protocol).

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::time::Duration;

#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl HysUdpPacket {
    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 8 {
            bail!("packet too short");
        }
        let session_id = buf.get_u32();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let addr_len = decode_varint_buf(buf)? as usize;
        if buf.remaining() < addr_len {
            bail!("addr length out of bounds");
        }
        let addr_bytes = buf.split_to(addr_len);
        let addr = String::from_utf8_lossy(&addr_bytes).to_string();
        let data = buf.split().to_vec();
        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}

pub fn fragment_packet(
    session_id: u32,
    pkt_id: u16,
    addr: &str,
    max_pkt_size: usize,
    payload: &[u8],
) -> Vec<Bytes> {
    let addr_bytes = addr.as_bytes();
    let mut addr_var = BytesMut::new();
    encode_varint(&mut addr_var, addr_bytes.len() as u64);
    let fixed = 4 + 2 + 1 + 1 + addr_var.len() + addr_bytes.len();
    let max_data = max_pkt_size.saturating_sub(fixed).max(1);
    let frag_total = payload.len().div_ceil(max_data) as u8;
    let frag_total = frag_total.max(1);

    let mut out = Vec::new();
    let mut start = 0usize;
    for frag_id in 0..frag_total {
        let end = (start + max_data).min(payload.len());
        let mut buf = BytesMut::with_capacity(fixed + end - start);
        buf.put_u32(session_id);
        buf.put_u16(pkt_id);
        buf.put_u8(frag_id);
        buf.put_u8(frag_total);
        buf.extend_from_slice(&addr_var);
        buf.extend_from_slice(addr_bytes);
        buf.extend_from_slice(&payload[start..end]);
        out.push(buf.freeze());
        start = end;
    }
    out
}

/// Partial reassembly older than this is discarded (fragments lost on the
/// wire); matches sing-quic tuic LRU semantics, prevents stale buffers.
const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<HysUdpPacket>>,
    cnt: u16,
    started: Option<std::time::Instant>,
}

impl Defragger {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count <= 1 {
            return Some(pkt);
        }
        if pkt.frag_count <= pkt.frag_id {
            return None;
        }
        // Discard a stale partial assembly instead of holding its buffers
        // until a matching packet_id happens to arrive.
        if self.cnt > 0 {
            if let Some(t0) = self.started {
                if t0.elapsed() > FRAG_REASSEMBLY_TIMEOUT {
                    self.frags.clear();
                    self.cnt = 0;
                }
            }
        }
        let frag_id = pkt.frag_id as usize;
        if pkt.pkt_id != self.pkt_id || pkt.frag_count as usize != self.frags.len() {
            self.pkt_id = pkt.pkt_id;
            self.frags.clear();
            self.frags.resize(pkt.frag_count as usize, None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt = 1;
            self.started = Some(std::time::Instant::now());
        } else if frag_id < self.frags.len() && self.frags[frag_id].is_none() {
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            if self.cnt as usize == self.frags.len() {
                let frags = std::mem::take(&mut self.frags);
                let mut iters = frags.into_iter().map(|x| x.unwrap());
                let mut pkt0 = iters.next().unwrap();
                pkt0.frag_count = 1;
                pkt0.frag_id = 0;
                for p in iters {
                    pkt0.data.extend_from_slice(&p.data);
                }
                return Some(pkt0);
            }
        }
        None
    }
}

pub fn encode_varint(buf: &mut BytesMut, v: u64) {
    if v <= 63 {
        buf.put_u8(v as u8);
    } else if v <= 16383 {
        buf.put_u16((v as u16) | 0x4000);
    } else if v <= 1_073_741_823 {
        buf.put_u32((v as u32) | 0x8000_0000);
    } else {
        buf.put_u64(v | 0xc000_0000_0000_0000);
    }
}

pub fn decode_varint_buf(buf: &mut BytesMut) -> Result<u64> {
    if buf.is_empty() {
        bail!("empty varint");
    }
    let b0 = buf.get_u8();
    let prefix = b0 >> 6;
    let mut v = (b0 & 0x3f) as u64;
    let rest = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        _ => 7,
    };
    if buf.remaining() < rest {
        bail!("short varint");
    }
    for _ in 0..rest {
        v = (v << 8) | (buf.get_u8() as u64);
    }
    Ok(v)
}
