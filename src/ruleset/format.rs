//! .drs 二进制格式常量定义（v2，section-based）。
//!
//! ## v2 布局
//!
//! ```text
//! 文件头（54 字节）：
//!   [4]  magic: b"DRS\0"
//!   [1]  version: u8 = 2
//!   [1]  flags: u8                  (保留，v2 暂未使用)
//!   [8]  build_time: u64            (unix timestamp)
//!   [32] source_hash: sha256        (源文件指纹)
//!   [4]  section_count: u32         (section 数量)
//!   [4]  reserved: u32              (保留，未来扩展)
//!
//! Section 头（9 字节 × N）：
//!   [1]  section_type: u8           (见 SectionType)
//!   [4]  entry_count: u32           (条目数，仅用于 stats，加载侧可忽略)
//!   [4]  byte_len: u32              (section 数据字节数)
//!
//! Section 数据（变长）：
//!   - 变长字符串 section（Domain/DomainSuffix/DomainKeyword/DomainRegex）：
//!     每条 `[len: u8][utf8 bytes]`，len 上限 255。
//!     注意：DomainSuffix 的 key 在写入前必须做反转 label + 加尾点（见 drs.rs::suffix_to_fst_key）。
//!   - 定长 section：
//!     - IpCidrV4：每条 5 字节 `[addr: u32][prefix_len: u8]`
//!     - IpCidrV6：每条 17 字节 `[addr: 16 bytes][prefix_len: u8]`
//!     - Port：每条 4 字节 `[start: u16][end: u16]`
//!   - FST section（DomainFst/DomainSuffixFst）：直接是 fst::Set 的序列化字节，
//!     比变长字符串 section 更紧凑、加载即用、无需二次构建。
//!     entry_count 字段对 FST section 等于 key 数量。
//! ```
//!
//! ## v1 兼容
//!
//! v1（54 字节定长头部 + domain_fst_len + suffix_fst_len + 两段 Map FST）通过
//! `from_bytes_v1` 单独加载。`from_bytes` 入口根据 `data[4]` 分派版本。

use super::error::{DrsError, Result};

pub const MAGIC: &[u8; 4] = b"DRS\0";

pub const VERSION_V1: u8 = 1;
pub const VERSION_V2: u8 = 2;
/// 当前默认写出版本。
#[allow(dead_code)]
pub const VERSION: u8 = VERSION_V2;

/// v1 头部固定长度。
pub const V1_HEADER_LEN: usize = 54;
/// v2 头部固定长度。
pub const V2_HEADER_LEN: usize = 54;

/// Section 类型枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    /// 变长字符串：精确域名（未反转）。
    Domain = 0x01,
    /// 变长字符串：域名后缀（未反转，匹配时由调用方处理子域）。
    DomainSuffix = 0x02,
    /// 变长字符串：域名关键词（子串匹配）。
    DomainKeyword = 0x03,
    /// 变长字符串：域名正则（regex crate 语法）。
    DomainRegex = 0x04,
    /// FST：精确域名 FST（key = 原域名）。
    DomainFst = 0x05,
    /// FST：后缀 FST（key = 反转 label + 尾点）。
    DomainSuffixFst = 0x06,
    /// FST：例外精确域名 FST。
    ExcludeDomainFst = 0x07,
    /// FST：例外后缀 FST（key = 反转 label + 尾点）。
    ExcludeSuffixFst = 0x08,
    /// 变长字符串：例外域名正则。
    ExcludeDomainRegex = 0x09,
    /// 定长 5 字节：IPv4 CIDR。
    IpCidrV4 = 0x10,
    /// 定长 17 字节：IPv6 CIDR。
    IpCidrV6 = 0x11,
    /// 定长 4 字节：端口范围。
    Port = 0x20,
}

impl SectionType {
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            0x01 => SectionType::Domain,
            0x02 => SectionType::DomainSuffix,
            0x03 => SectionType::DomainKeyword,
            0x04 => SectionType::DomainRegex,
            0x05 => SectionType::DomainFst,
            0x06 => SectionType::DomainSuffixFst,
            0x07 => SectionType::ExcludeDomainFst,
            0x08 => SectionType::ExcludeSuffixFst,
            0x09 => SectionType::ExcludeDomainRegex,
            0x10 => SectionType::IpCidrV4,
            0x11 => SectionType::IpCidrV6,
            0x20 => SectionType::Port,
            other => return Err(DrsError::UnknownSection(other)),
        })
    }

    /// 该 section 是否为定长条目，如果是返回每条字节数。
    #[allow(dead_code)]
    pub fn fixed_entry_len(self) -> Option<usize> {
        Some(match self {
            SectionType::IpCidrV4 => 5,
            SectionType::IpCidrV6 => 17,
            SectionType::Port => 4,
            _ => return None,
        })
    }
}

/// 写入 section 头。
pub fn write_section_header<W: std::io::Write>(
    w: &mut W,
    ty: SectionType,
    entry_count: u32,
    byte_len: u32,
) -> Result<()> {
    w.write_all(&[ty as u8])?;
    w.write_all(&entry_count.to_le_bytes())?;
    w.write_all(&byte_len.to_le_bytes())?;
    Ok(())
}

/// 从 `data[offset..]` 读取一个 section 头，返回 `(type, entry_count, byte_len, header_len)`。
pub fn read_section_header(data: &[u8], offset: usize) -> Result<(SectionType, u32, u32, usize)> {
    if data.len() < offset + 9 {
        return Err(DrsError::Truncated {
            expected: offset + 9,
            got: data.len(),
        });
    }
    let ty = SectionType::from_u8(data[offset])?;
    let entry_count = u32::from_le_bytes(data[offset + 1..offset + 5].try_into().unwrap());
    let byte_len = u32::from_le_bytes(data[offset + 5..offset + 9].try_into().unwrap());
    Ok((ty, entry_count, byte_len, 9))
}

/// 校验域名长度（≤253 字节）。
pub fn validate_domain_len(domain: &str) -> Result<()> {
    if domain.len() > 253 {
        return Err(DrsError::DomainTooLong {
            domain: domain.to_string(),
            len: domain.len(),
        });
    }
    Ok(())
}
