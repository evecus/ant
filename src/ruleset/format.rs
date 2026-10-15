//! `.ars` on-disk layout (compatible idea with reflex RRST, magic = ARST).

/// File magic: b"ARST"
pub const MAGIC: [u8; 4] = *b"ARST";

/// Format version
pub const VERSION: u8 = 0x01;

/// [magic 4][version 1][flags 1][section_count 4][reserved 4]
pub const HEADER_LEN: usize = 14;

/// [type 1][entry_count 4][byte_len 4]
pub const SECTION_HEADER_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    DomainKeyword = 0x03,
    DomainRegex = 0x04,
    /// Exact domain FST; keys = reversed labels ("com.google")
    DomainFst = 0x05,
    /// Suffix FST; keys = reversed labels + trailing '.' ("com.google.")
    DomainSuffixFst = 0x06,
    IpCidrV4 = 0x10,
    IpCidrV6 = 0x11,
}

impl TryFrom<u8> for SectionType {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x03 => Ok(Self::DomainKeyword),
            0x04 => Ok(Self::DomainRegex),
            0x05 => Ok(Self::DomainFst),
            0x06 => Ok(Self::DomainSuffixFst),
            0x10 => Ok(Self::IpCidrV4),
            0x11 => Ok(Self::IpCidrV6),
            other => Err(other),
        }
    }
}

pub const IPV4_ENTRY_LEN: usize = 5; // 4 octets + prefix
pub const IPV6_ENTRY_LEN: usize = 17; // 16 octets + prefix
