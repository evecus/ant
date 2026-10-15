//! IPv6-sized address storage with IPv4-mapped support.
//!
//! Ported from honk (dae lineage): the datapath uses one 16-byte address type
//! for both families so map keys stay family-agnostic. IPv4 addresses are
//! stored IPv4-mapped (`::ffff:a.b.c.d`) in network byte order.

use aya_ebpf_bindings::bindings::{__be16, __be32, __u8};

#[repr(C)]
#[derive(Copy, Clone)]
pub union In6Addr {
    pub u6_addr8: [__u8; 16],
    pub u6_addr16: [__be16; 8],
    pub u6_addr32: [__be32; 4],
    pub u6_addr64: [u64; 2],
}

impl In6Addr {
    /// The all-zeros address `::`.
    pub const fn zero() -> Self {
        Self { u6_addr64: [0, 0] }
    }

    /// Build an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
    ///
    /// `ipv4` must be in network byte order (big-endian), i.e. the `__be32`
    /// form. If you have a `[u8; 4]`, convert with `u32::from_be_bytes` first.
    pub const fn from_ipv4_mapped(ipv4_be: __be32) -> Self {
        Self {
            u6_addr32: [
                0,
                0,
                0x0000FFFF_u32.to_be(), // ::ffff stored as network-order bytes
                ipv4_be.to_be(),        // store IPv4 bytes in network order
            ],
        }
    }

    /// Build from a 4-byte array (big-endian bytes, e.g. `[192, 168, 1, 1]`).
    pub const fn from_ipv4_bytes(octets: [__u8; 4]) -> Self {
        Self::from_ipv4_mapped(u32::from_be_bytes(octets))
    }

    /// Returns `true` if this is an IPv4-mapped address (`::ffff/96`).
    pub fn is_v4_mapped(&self) -> bool {
        unsafe {
            self.u6_addr32[0] == 0
                && self.u6_addr32[1] == 0
                && self.u6_addr16[4] == 0
                && self.u6_addr16[5] == u16::to_be(0xffff)
        }
    }

    /// Get a reference to the 16-byte array.
    pub fn as_bytes(&self) -> &[__u8; 16] {
        // Valid: all union variants cover the same memory, and [u8; 16] is
        // the underlying memory representation of the union.
        unsafe { &self.u6_addr8 }
    }

    /// Build from 16 raw bytes in network order (BPF-safe counterpart of
    /// [`Self::from_ipv6_addr`]).
    pub const fn from_ipv6_bytes(octets: [__u8; 16]) -> Self {
        Self { u6_addr8: octets }
    }

    /// Construct from a standard `core::net::Ipv6Addr`.
    #[cfg(not(target_arch = "bpf"))]
    pub fn from_ipv6_addr(ipv6: core::net::Ipv6Addr) -> Self {
        Self {
            u6_addr8: ipv6.octets(),
        }
    }
}

impl Default for In6Addr {
    fn default() -> Self {
        Self::zero()
    }
}

/// Indexing delegates to the underlying `u6_addr8` byte array.
impl core::ops::Index<usize> for In6Addr {
    type Output = u8;
    fn index(&self, i: usize) -> &u8 {
        unsafe { &self.u6_addr8[i] }
    }
}

impl core::ops::IndexMut<usize> for In6Addr {
    fn index_mut(&mut self, i: usize) -> &mut u8 {
        unsafe { &mut self.u6_addr8[i] }
    }
}

impl In6Addr {
    /// Copy bytes from `src` into the address (up to 16 bytes).
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        unsafe {
            self.u6_addr8[..src.len()].copy_from_slice(src);
        }
    }
}

impl core::ops::Index<core::ops::Range<usize>> for In6Addr {
    type Output = [u8];
    fn index(&self, r: core::ops::Range<usize>) -> &[u8] {
        unsafe { &self.u6_addr8[r] }
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for In6Addr {
    fn index_mut(&mut self, r: core::ops::Range<usize>) -> &mut [u8] {
        unsafe { &mut self.u6_addr8[r] }
    }
}

/// Debug output in `::ffff:192.168.1.1` style.
impl core::fmt::Debug for In6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            if self.is_v4_mapped() {
                let bytes = self.u6_addr32[3].to_be_bytes();
                write!(
                    f,
                    "::ffff:{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )
            } else {
                write!(
                    f,
                    "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                    u16::from_be(self.u6_addr16[0]),
                    u16::from_be(self.u6_addr16[1]),
                    u16::from_be(self.u6_addr16[2]),
                    u16::from_be(self.u6_addr16[3]),
                    u16::from_be(self.u6_addr16[4]),
                    u16::from_be(self.u6_addr16[5]),
                    u16::from_be(self.u6_addr16[6]),
                    u16::from_be(self.u6_addr16[7]),
                )
            }
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for In6Addr {}
