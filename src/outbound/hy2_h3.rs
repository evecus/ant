//! Minimal raw HTTP/3 primitives for the Hysteria2 handshake (client side).
//!
//! Ported from reflex `src/protocol/hysteria2.rs` (which follows sing-box
//! `protocol/hysteria2`). Replaces the `h3`/`h3-quinn` crates: the full HTTP/3
//! client stack costs a driver task + extra binary size, while the handshake
//! only needs SETTINGS/QPACK uni streams, one HEADERS frame out, one back.

use bytes::{BufMut, BytesMut};
use quinn::RecvStream;
use tokio::io::AsyncReadExt;

// ── HTTP/3 frame types (RFC 9114 §7.2) ───────────────────────────────────────

pub const H3_FRAME_DATA: u64 = 0x0;
pub const H3_FRAME_HEADERS: u64 = 0x1;
pub const H3_FRAME_SETTINGS: u64 = 0x4;

// ── QUIC varint (RFC 9000 §16) ───────────────────────────────────────────────

pub fn write_varint(buf: &mut BytesMut, i: u64) {
    if i <= 63 {
        buf.put_u8(i as u8);
    } else if i <= 16383 {
        buf.put_u16((i as u16) | 0x4000);
    } else if i <= 1_073_741_823 {
        buf.put_u32((i as u32) | 0x8000_0000);
    } else {
        buf.put_u64(i | 0xc000_0000_0000_0000);
    }
}

/// Read a QUIC varint from a stream (`quinn::RecvStream` implements AsyncRead).
pub async fn read_varint_async(r: &mut RecvStream) -> anyhow::Result<u64> {
    let first = r.read_u8().await?;
    let tag = first >> 6;
    let val = match tag {
        0 => (first & 0x3f) as u64,
        1 => {
            let b1 = r.read_u8().await?;
            (((first & 0x3f) as u64) << 8) | (b1 as u64)
        }
        2 => {
            let mut rest = [0u8; 3];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 24)
                | ((rest[0] as u64) << 16)
                | ((rest[1] as u64) << 8)
                | (rest[2] as u64)
        }
        _ => {
            let mut rest = [0u8; 7];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 56)
                | ((rest[0] as u64) << 48)
                | ((rest[1] as u64) << 40)
                | ((rest[2] as u64) << 32)
                | ((rest[3] as u64) << 24)
                | ((rest[4] as u64) << 16)
                | ((rest[5] as u64) << 8)
                | (rest[6] as u64)
        }
    };
    Ok(val)
}

// ── HTTP/3 frames ────────────────────────────────────────────────────────────

/// Write one HTTP/3 frame: `[type varint][len varint][payload]`.
pub fn write_h3_frame(buf: &mut BytesMut, frame_type: u64, payload: &[u8]) {
    write_varint(buf, frame_type);
    write_varint(buf, payload.len() as u64);
    buf.put_slice(payload);
}

/// Read one HTTP/3 frame, returning `(frame_type, payload)`.
pub async fn read_h3_frame(recv: &mut RecvStream) -> anyhow::Result<(u64, Vec<u8>)> {
    let frame_type = read_varint_async(recv).await?;
    let payload_len = read_varint_async(recv).await?;
    anyhow::ensure!(
        payload_len <= 1024 * 1024,
        "h3 frame too large: {payload_len}"
    );
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        recv.read_exact(&mut payload).await?;
    }
    Ok((frame_type, payload))
}

// ── QPACK encoding (RFC 9204) ────────────────────────────────────────────────

/// Write a single literal header (RFC 9204 §4.5.6: Literal Header Field Without
/// Name Reference, no Huffman, no dynamic table).
pub fn put_literal_header(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
    let nlen = name.len();
    if nlen < 7 {
        buf.put_u8(0x20 | nlen as u8);
    } else {
        buf.put_u8(0x27); // 0x20 | 0x07: 3-bit prefix saturated
        let mut rem = nlen - 7;
        while rem >= 128 {
            buf.put_u8((rem as u8) | 0x80);
            rem >>= 7;
        }
        buf.put_u8(rem as u8);
    }
    buf.put_slice(name);
    // value string literal: H=0 (bit7=0), 7-bit prefix length
    let vlen = value.len();
    if vlen < 128 {
        buf.put_u8(vlen as u8);
    } else {
        buf.put_u8(0x7f);
        let mut rem = vlen - 127;
        while rem >= 128 {
            buf.put_u8((rem as u8) | 0x80);
            rem >>= 7;
        }
        buf.put_u8(rem as u8);
    }
    buf.put_slice(value);
}

/// QPACK integer decode (RFC 7541 §5.1), returns `(value, bytes_consumed)`.
fn qpack_read_int(data: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let mask = (1u8 << prefix_bits) - 1;
    let first = (data[0] & mask) as u64;
    if first < mask as u64 {
        return Some((first, 1));
    }
    let mut val = first;
    let mut m = 0u32;
    let mut i = 1usize;
    loop {
        if i >= data.len() {
            return None;
        }
        let b = data[i];
        val += ((b & 0x7f) as u64) << m;
        m += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    Some((val, i))
}

/// QPACK static table entries (RFC 9204 Appendix A) that can appear in an
/// auth response.
fn qpack_static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    match idx {
        0 => Some((":authority", "")),
        1 => Some((":path", "/")),
        2 => Some(("age", "0")),
        3 => Some(("content-disposition", "")),
        4 => Some(("content-length", "0")),
        5 => Some(("cookie", "")),
        6 => Some(("date", "")),
        7 => Some(("etag", "")),
        8 => Some(("if-modified-since", "")),
        9 => Some(("if-none-match", "")),
        10 => Some(("last-modified", "")),
        11 => Some(("link", "")),
        12 => Some(("location", "")),
        13 => Some(("referer", "")),
        14 => Some(("set-cookie", "")),
        15 => Some((":method", "CONNECT")),
        16 => Some((":method", "DELETE")),
        17 => Some((":method", "GET")),
        18 => Some((":method", "HEAD")),
        19 => Some((":method", "OPTIONS")),
        20 => Some((":method", "POST")),
        21 => Some((":method", "PUT")),
        22 => Some((":scheme", "http")),
        23 => Some((":scheme", "https")),
        24 => Some((":status", "103")),
        25 => Some((":status", "200")),
        26 => Some((":status", "304")),
        27 => Some((":status", "404")),
        28 => Some((":status", "503")),
        _ => None,
    }
}

fn qpack_static_name(idx: u64) -> Option<&'static str> {
    qpack_static_entry(idx).map(|(name, _)| name)
}

/// Parse all headers from a QPACK header block, returning `Vec<(name, value)>`.
///
/// Supports the encodings quic-go/http3 actually emits (RFC 9204):
/// Indexed Header Field (static), Literal With Name Reference (static),
/// Literal Without Name Reference.
pub fn parse_headers_from_qpack(payload: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    if payload.len() < 2 {
        anyhow::bail!("qpack payload too short");
    }
    let mut headers = Vec::new();
    let mut i = 2usize; // skip Required Insert Count + Delta Base

    while i < payload.len() {
        let b = payload[i];

        if b & 0x80 != 0 {
            // Indexed Header Field (static table): 0b1xxxxxxx
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 6) else {
                break;
            };
            i += consumed;
            if let Some((name, value)) = qpack_static_entry(idx) {
                if !name.is_empty() {
                    headers.push((name.to_string(), value.to_string()));
                }
            }
        } else if b & 0xc0 == 0x40 {
            // Literal Field With Name Reference: 0b01xx_xxxx
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 4) else {
                break;
            };
            i += consumed;
            if i >= payload.len() {
                break;
            }
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            let name = qpack_static_name(idx).unwrap_or("").to_string();
            headers.push((name, value));
        } else if b & 0xe0 == 0x20 {
            // Literal Without Name Reference: 0b001x_xxxx
            let name_huffman = b & 0x08 != 0;
            let Some((name_len, nc)) = qpack_read_int(&payload[i..], 3) else {
                break;
            };
            i += nc;
            let name_len = name_len as usize;
            if i + name_len > payload.len() {
                break;
            }
            let name = if name_huffman {
                huffman_decode(&payload[i..i + name_len])
            } else {
                String::from_utf8_lossy(&payload[i..i + name_len]).into_owned()
            };
            i += name_len;
            if i >= payload.len() {
                break;
            }
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            headers.push((name, value));
        } else {
            // Unsupported instruction (post-base variants etc.) — skip 1 byte.
            i += 1;
        }
    }
    Ok(headers)
}

/// HTTP/2 / QPACK Huffman decode (RFC 7541 Appendix B, shared with RFC 9204).
///
/// quic-go may Huffman-encode short response values ("233", "true"); without
/// this every header value would be garbled.
fn huffman_decode(data: &[u8]) -> String {
    #[rustfmt::skip]
    static TABLE: [(u32, u8); 257] = [
        (0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),
        (0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),
        (0x3fffffff,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffe,30),(0xfffffeb,28),
        (0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),
        (0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),
        (0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
        (0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),
        (0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),
        (0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),(0x0,5),(0x1,5),(0x2,5),
        (0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),
        (0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),(0x1ffa,13),(0x21,6),
        (0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),
        (0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),(0x6b,7),(0x6c,7),
        (0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),
        (0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),
        (0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),
        (0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),
        (0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),
        (0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),(0x1ffd,13),
        (0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),
        (0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),
        (0x7fffda,23),(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),
        (0xffffeb,24),(0x7fffdf,23),(0xffffec,24),(0xffffed,24),(0x3fffd7,22),
        (0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),
        (0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),
        (0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),
        (0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),
        (0x1fffde,21),(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),
        (0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),(0x7fffec,23),(0x1fffe0,21),
        (0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),(0x3fffe1,22),
        (0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),
        (0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),
        (0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),
        (0x7ffff2,23),(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),
        (0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),
        (0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),(0x7ffffe0,27),
        (0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),
        (0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),
        (0x7ffffe4,27),(0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),
        (0x1fffe6,21),(0x3fffe9,22),(0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),
        (0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),(0x1ffffef,25),(0xfffff4,24),
        (0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),(0x3ffffeb,26),(0x7ffffe6,27),
        (0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),(0x7ffffe9,27),
        (0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),
        (0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),(0x3fffffff,30),
    ];

    let total_bits = data.len() * 8;
    let mut out = Vec::new();
    let mut bit_pos = 0usize;

    while bit_pos < total_bits {
        let remaining = total_bits - bit_pos;
        let try_bits = remaining.min(30);

        let mut window: u64 = 0;
        let mut fetched = 0u32;
        let mut bp = bit_pos;
        while fetched < try_bits as u32 && bp < total_bits {
            let byte_idx = bp / 8;
            let bit_idx = 7 - (bp % 8);
            let bit = ((data[byte_idx] >> bit_idx) & 1) as u64;
            window = (window << 1) | bit;
            fetched += 1;
            bp += 1;
        }

        let mut matched = false;
        for len in 5u8..=30u8 {
            if len as usize > try_bits {
                break;
            }
            let shift = fetched - len as u32;
            let candidate = (window >> shift) as u32;

            for (sym, &(code, code_len)) in TABLE.iter().enumerate() {
                if code_len == len && code == candidate {
                    if sym == 256 {
                        // EOS
                        return String::from_utf8_lossy(&out).into_owned();
                    }
                    out.push(sym as u8);
                    bit_pos += len as usize;
                    matched = true;
                    break;
                }
            }
            if matched {
                break;
            }
        }

        if !matched {
            break;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ── H3 connection init (control / QPACK uni streams) ─────────────────────────

/// Open the 3 uni streams HTTP/3 requires (RFC 9114 §6.2 + RFC 9204 §4.2):
/// control (with empty SETTINGS), QPACK encoder, QPACK decoder.
///
/// quic-go's H3 layer refuses requests from a peer missing these streams
/// (H3_QPACK_DECOMPRESSION_FAILED 0x200). Streams must not be finished;
/// park them on a task until the connection closes.
pub async fn open_h3_control_streams(conn: &quinn::Connection) -> anyhow::Result<()> {
    let mut ctrl = conn.open_uni().await?;
    ctrl.write_all(&[0x00]).await?;
    let mut settings = BytesMut::new();
    write_h3_frame(&mut settings, H3_FRAME_SETTINGS, &[]);
    ctrl.write_all(&settings).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(ctrl);
    });

    let mut enc = conn.open_uni().await?;
    enc.write_all(&[0x02]).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(enc);
    });

    let mut dec = conn.open_uni().await?;
    dec.write_all(&[0x03]).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(dec);
    });

    Ok(())
}

// ── Padding ──────────────────────────────────────────────────────────────────

/// Random printable-ASCII padding in `[min, max)`, matching the official
/// hysteria `internal/protocol/padding.go` character set.
pub fn random_padding(min: usize, max: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: usize = rng.gen_range(min..max);
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..n)
        .map(|_| {
            let idx: usize = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}
