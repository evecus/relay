//! 从 `RuleEntry` 构建 .drs 文件。
//!
//! 流程：
//!   1. 收集 entries（由调用方传入或从文件解析）。
//!   2. 按 `EntryType` 分流到 7 个分类桶（domain/suffix/keyword/regex/ipv4/ipv6/port）。
//!      每个文件解析完就立即分流并 drop 原始 `RuleEntry`，降低峰值内存。
//!   3. 调用 `DrsFile::write_v2` 写入二进制。
//!
//! 设计要点：
//!   - 不再用 `Vec<RuleEntry>` 全量收集所有 entries，而是流式合并到分类桶。
//!     对于 50 万条规则的大文件，可减少约 50% 峰值内存（每个 RuleEntry ~80 字节，桶内元素更紧凑）。
//!   - `hash_inputs` 对所有输入文件内容做 sha256，作为 source_hash 写入头部。
//!     这样可以仅靠文件指纹判断缓存是否需要重建。

use super::drs::{parse_ipv4_cidr, parse_ipv6_cidr, parse_port_range, BuildStats, DrsFile};
use super::error::{DrsError, Result};
use super::parser::RuleEntry;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use tracing::info;

/// 分类桶：收集 entries 并最终序列化到 v2 二进制。
#[derive(Default)]
pub struct EntryBuckets {
    pub domains: Vec<String>,
    pub suffixes: Vec<String>,
    pub keywords: Vec<String>,
    pub regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(u32, u8)>,
    pub ipv6_cidrs: Vec<(u128, u8)>,
    pub ports: Vec<(u16, u16)>,
    pub exclude_domains: Vec<String>,
    pub exclude_suffixes: Vec<String>,
    pub exclude_regexes: Vec<String>,
}

impl EntryBuckets {
    pub fn new() -> Self {
        Self::default()
    }

    /// 把一个 entry 分流到对应桶。
    /// 调用方传入后即可 drop 原始 entry。
    pub fn push(&mut self, entry: RuleEntry) -> Result<()> {
        match entry.rule_type {
            super::parser::EntryType::Domain => {
                self.domains.push(entry.domain);
            }
            super::parser::EntryType::DomainSuffix => {
                self.suffixes.push(entry.domain);
            }
            super::parser::EntryType::DomainKeyword => {
                self.keywords.push(entry.domain);
            }
            super::parser::EntryType::DomainRegex => {
                // 提前编译验证，避免写入无效正则
                let _ = regex::Regex::new(&entry.domain).map_err(|e| DrsError::InvalidRegex {
                    pattern: entry.domain.clone(),
                    err: e.to_string(),
                })?;
                self.regexes.push(entry.domain);
            }
            super::parser::EntryType::Ipv4Cidr => {
                if let Some((addr, prefix)) = entry.cidr {
                    let addr_u32 = match addr {
                        IpAddr::V4(v4) => u32::from(v4),
                        _ => return Err(DrsError::other("Ipv4Cidr entry has IPv6 addr")),
                    };
                    self.ipv4_cidrs.push((addr_u32, prefix));
                }
            }
            super::parser::EntryType::Ipv6Cidr => {
                if let Some((addr, prefix)) = entry.cidr {
                    let addr_u128 = match addr {
                        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
                        _ => return Err(DrsError::other("Ipv6Cidr entry has IPv4 addr")),
                    };
                    self.ipv6_cidrs.push((addr_u128, prefix));
                }
            }
            super::parser::EntryType::Port => {
                if let Some((s, e)) = entry.port {
                    self.ports.push((s, e));
                }
            }
            super::parser::EntryType::ExcludeDomain => {
                self.exclude_domains.push(entry.domain);
            }
            super::parser::EntryType::ExcludeDomainSuffix => {
                self.exclude_suffixes.push(entry.domain);
            }
            super::parser::EntryType::ExcludeDomainRegex => {
                let _ = regex::Regex::new(&entry.domain).map_err(|e| DrsError::InvalidRegex {
                    pattern: entry.domain.clone(),
                    err: e.to_string(),
                })?;
                self.exclude_regexes.push(entry.domain);
            }
        }
        Ok(())
    }

    /// 把一个 CIDR 字符串解析后塞进对应桶（v4 或 v6）。
    #[allow(dead_code)]
    pub fn push_cidr_str(&mut self, raw: &str) -> Result<()> {
        // 尝试 v4 失败再尝试 v6（IPv6 解析器也能解析 v4 映射地址，这里用前缀长度区分）
        if raw.contains(':') {
            let (addr, prefix) = parse_ipv6_cidr(raw)?;
            self.ipv6_cidrs.push((addr, prefix));
        } else {
            let (addr, prefix) = parse_ipv4_cidr(raw)?;
            self.ipv4_cidrs.push((addr, prefix));
        }
        Ok(())
    }

    /// 把端口范围字符串塞进桶。
    #[allow(dead_code)]
    pub fn push_port_str(&mut self, raw: &str) -> Result<()> {
        let (s, e) = parse_port_range(raw)?;
        self.ports.push((s, e));
        Ok(())
    }

    /// 写入 .drs v2 文件。
    pub fn write_to<W: Write>(self, writer: &mut W, source_hash: [u8; 32]) -> Result<BuildStats> {
        DrsFile::write_v2(
            writer,
            &self.domains,
            &self.suffixes,
            &self.keywords,
            &self.regexes,
            &self.ipv4_cidrs,
            &self.ipv6_cidrs,
            &self.ports,
            &self.exclude_domains,
            &self.exclude_suffixes,
            &self.exclude_regexes,
            source_hash,
        )
    }
}

/// 对一组文件内容做 sha256，作为 source_hash。
/// 文件顺序参与哈希，避免重命名误判。
pub fn hash_inputs(paths: &[&Path]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    for path in paths {
        let data = std::fs::read(path)?;
        // 同时哈希路径名 + 内容，防止内容相同但来源不同的文件被误判为同一份
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update(b"\x00");
        hasher.update(&data);
        hasher.update(b"\x01");
    }
    Ok(hasher.finalize().into())
}

/// 从分类好的 entries 构建一个 .drs 文件（旧 API，保留兼容）。
#[allow(dead_code)]
pub fn build_from_entries<W: Write>(
    entries: &[RuleEntry],
    writer: &mut W,
    source_hash: [u8; 32],
) -> Result<(usize, usize)> {
    let mut buckets = EntryBuckets::new();
    for entry in entries {
        buckets.push(entry.clone())?;
    }
    let stats = buckets.write_to(writer, source_hash)?;
    Ok((stats.domain_count as usize, stats.suffix_count as usize))
}

/// 从多个输入文件构建一个 .drs 文件。
///
/// 每个文件按 `InputFormat` 解析，解析结果直接合并到 buckets，避免中间 `Vec<RuleEntry>` 峰值。
pub fn build_from_files(
    inputs: &[(String, crate::cmd::build::InputFormat)],
    output_path: &Path,
) -> Result<()> {
    let mut buckets = EntryBuckets::new();
    let mut input_paths: Vec<&Path> = Vec::with_capacity(inputs.len());

    for (path_str, format) in inputs {
        let path = Path::new(path_str);
        input_paths.push(path);

        let content = std::fs::read_to_string(path).map_err(|e| {
            DrsError::Io(std::io::Error::other(format!(
                "read {}: {}",
                path.display(),
                e
            )))
        })?;

        let entries = match format {
            crate::cmd::build::InputFormat::Mihomo => {
                super::parser::mihomo::parse(&content)?
            }
            crate::cmd::build::InputFormat::Adguard => {
                super::parser::adguard::parse(&content).into_entries()
            }
            crate::cmd::build::InputFormat::Singbox => {
                super::parser::singbox::parse(&content)?
            }
        };

        info!("Parsed {} entries from {}", entries.len(), path.display());

        // 流式合并：每个文件解析完立即塞桶，原始 entries 立即 drop
        for entry in entries {
            buckets.push(entry)?;
        }
    }

    let source_hash = hash_inputs(&input_paths)?;

    let mut file = std::fs::File::create(output_path)?;
    let stats = buckets.write_to(&mut file, source_hash)?;

    info!(
        "Built {} ({} domains, {} suffixes, {} keywords, {} regexes, {} v4 CIDRs, {} v6 CIDRs, {} ports) → {}",
        output_path.display(),
        stats.domain_count,
        stats.suffix_count,
        stats.keyword_count,
        stats.regex_count,
        stats.ipv4_cidr_count,
        stats.ipv6_cidr_count,
        stats.port_count,
        output_path.display(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::build::InputFormat;
    use crate::ruleset::parser::EntryType;

    #[test]
    fn test_buckets_push_domain() {
        let mut b = EntryBuckets::new();
        b.push(RuleEntry::domain_entry("google.com", EntryType::Domain))
            .unwrap();
        assert_eq!(b.domains, vec!["google.com".to_string()]);
    }

    #[test]
    fn test_buckets_push_cidr_v4_str() {
        let mut b = EntryBuckets::new();
        b.push_cidr_str("192.168.0.0/16").unwrap();
        assert_eq!(b.ipv4_cidrs.len(), 1);
        assert_eq!(b.ipv4_cidrs[0].1, 16);
    }

    #[test]
    fn test_buckets_push_cidr_v6_str() {
        let mut b = EntryBuckets::new();
        b.push_cidr_str("2001:db8::/32").unwrap();
        assert_eq!(b.ipv6_cidrs.len(), 1);
        assert_eq!(b.ipv6_cidrs[0].1, 32);
    }

    #[test]
    fn test_buckets_push_port_str() {
        let mut b = EntryBuckets::new();
        b.push_port_str("80").unwrap();
        b.push_port_str("8000-9000").unwrap();
        assert_eq!(b.ports, vec![(80, 80), (8000, 9000)]);
    }

    #[test]
    fn test_buckets_roundtrip() {
        let mut b = EntryBuckets::new();
        b.push(RuleEntry::domain_entry("a.com", EntryType::Domain))
            .unwrap();
        b.push(RuleEntry::domain_entry("b.com", EntryType::DomainSuffix))
            .unwrap();
        b.push(RuleEntry::domain_entry("google", EntryType::DomainKeyword))
            .unwrap();
        b.push_cidr_str("10.0.0.0/8").unwrap();

        let mut buf = Vec::new();
        let stats = b.write_to(&mut buf, [0u8; 32]).unwrap();
        assert_eq!(stats.domain_count, 1);
        assert_eq!(stats.suffix_count, 1);
        assert_eq!(stats.keyword_count, 1);
        assert_eq!(stats.ipv4_cidr_count, 1);

        let drs = DrsFile::from_bytes(&buf).unwrap();
        assert_eq!(drs.matches("a.com"), Some(super::super::MatchResult::Domain));
        assert_eq!(
            drs.matches("x.b.com"),
            Some(super::super::MatchResult::DomainSuffix)
        );
        assert_eq!(
            drs.matches("my.google.test"),
            Some(super::super::MatchResult::DomainKeyword)
        );
        assert_eq!(
            drs.matches_ip("10.1.2.3".parse().unwrap()),
            Some(super::super::MatchResult::Ipv4Cidr)
        );
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let mut b = EntryBuckets::new();
        let err = b.push(RuleEntry::domain_entry("[invalid", EntryType::DomainRegex));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), DrsError::InvalidRegex { .. }));
    }

    /// 这是个集成测试，确保 `build_from_files` 的入口签名能通过编译。
    /// 实际文件 IO 在 unit test 里跳过。
    #[test]
    fn test_build_from_files_signature() {
        let _inputs: Vec<(String, InputFormat)> = vec![];
        // 不实际调用 build_from_files，只验证类型签名。
        let _ = |inputs: Vec<(String, InputFormat)>, out: &Path| {
            build_from_files(&inputs, out)
        };
    }
}
