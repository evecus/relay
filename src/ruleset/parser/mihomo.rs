//! mihomo YAML 规则解析。
//!
//! 支持 mihomo 的三种 payload 写法：
//!
//! 1. **behavior: domain** —— 全部当作 DOMAIN（精确域名）
//! 2. **behavior: ipcidr** —— 全部当作 IP CIDR
//! 3. **behavior: classical** —— 每行带类型前缀（`DOMAIN,`/`DOMAIN-SUFFIX,`/`DOMAIN-KEYWORD,`/`DOMAIN-REGEX,`/`IP-CIDR,`/`IP-CIDR6,`/`PORT,`/`GEOIP,`/`MATCH,` 等）
//! 4. **未指定 behavior** —— 自动判别（按行内容识别）
//!
//! 简写语法：
//!   - `+.example.com` → DOMAIN-SUFFIX
//!   - `*.example.com` → DOMAIN-SUFFIX（mihomo 兼容写法）
//!   - `.example.com`  → DOMAIN-SUFFIX（前导点）
//!   - `example.com`   → DOMAIN（自动判别模式下）或按 behavior
//!   - `keyword:xxx`   → DOMAIN-KEYWORD（mihomo 扩展）
//!
//! classical 行的附加修饰符（如 `no-resolve`）会被剥除后处理。
//! 不识别的 classical 类型（如 `GEOIP,`/`MATCH,`/`RULE-SET,`）会被跳过并记录。

use super::{EntryType, RuleEntry};
use crate::ruleset::drs::looks_like_domain;
use crate::ruleset::error::{DrsError, Result};
use std::net::IpAddr;

/// mihomo 的 behavior 模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// 全部按精确域名处理
    Domain,
    /// 全部按 IP CIDR 处理
    IpCidr,
    /// classical：每行带类型前缀
    Classical,
    /// 未指定，自动判别
    Auto,
}

impl Behavior {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "domain" => Ok(Behavior::Domain),
            "ipcidr" => Ok(Behavior::IpCidr),
            "classical" => Ok(Behavior::Classical),
            "" => Ok(Behavior::Auto),
            other => Err(DrsError::ParseError {
                line: 0,
                msg: format!("unknown behavior: {}", other),
            }),
        }
    }
}

/// 解析 mihomo YAML 规则。
///
/// 默认 behavior = Auto，调用方可通过 `parse_with_behavior` 指定。
pub fn parse(input: &str) -> Result<Vec<RuleEntry>> {
    parse_with_behavior(input, Behavior::Auto)
}

/// 按指定 behavior 解析。
pub fn parse_with_behavior(input: &str, behavior: Behavior) -> Result<Vec<RuleEntry>> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(input).map_err(|e| DrsError::ParseError {
            line: 0,
            msg: format!("YAML parse: {}", e),
        })?;

    // 从 YAML 中读取 behavior 字段（如果存在则覆盖传入值）
    let effective_behavior = if let Some(b) = doc.get("behavior").and_then(|v| v.as_str()) {
        Behavior::parse(b)?
    } else {
        behavior
    };

    let payload = doc.get("payload").and_then(|v| v.as_sequence()).ok_or_else(|| {
        DrsError::ParseError {
            line: 0,
            msg: "missing or invalid 'payload' list in YAML".to_string(),
        }
    })?;

    let mut entries = Vec::new();
    for (idx, item) in payload.iter().enumerate() {
        let line_no = idx + 1;
        let s = match item.as_str() {
            Some(s) => s.trim(),
            None => {
                tracing::warn!("mihomo: skipping non-string payload at line {}", line_no);
                continue;
            }
        };
        if s.is_empty() {
            continue;
        }

        match effective_behavior {
            Behavior::Domain => push_domain_entry(s, line_no, &mut entries),
            Behavior::IpCidr => push_ipcidr_entry(s, line_no, &mut entries)?,
            Behavior::Classical | Behavior::Auto => {
                push_classical_or_auto(s, line_no, effective_behavior, &mut entries)?
            }
        }
    }

    Ok(entries)
}

fn push_domain_entry(s: &str, line_no: usize, out: &mut Vec<RuleEntry>) {
    let s = s.trim();
    if s.is_empty() {
        return;
    }
    // behavior=domain 下，所有行当作精确域名
    let trimmed = s.trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();
    if looks_like_domain(&lower) {
        out.push(RuleEntry::domain_entry(lower, EntryType::Domain));
    } else {
        tracing::warn!("mihomo[domain]: invalid domain at line {}: {}", line_no, s);
    }
}

fn push_ipcidr_entry(s: &str, line_no: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    // behavior=ipcidr 下，所有行当作 CIDR
    let s = s.trim();
    if s.is_empty() {
        return Ok(());
    }
    push_cidr_str(s, line_no, out)
}

fn push_classical_or_auto(
    s: &str,
    line_no: usize,
    behavior: Behavior,
    out: &mut Vec<RuleEntry>,
) -> Result<()> {
    // classical 类型前缀
    if let Some((ty, rest)) = s.split_once(',') {
        let ty = ty.trim();
        let rest = rest.trim();
        // 剥除 no-resolve 等修饰符：`192.168.0.0/16,no-resolve`
        let value = rest.split(',').next().unwrap_or(rest).trim();
        return push_typed_line(ty, value, line_no, out);
    }

    // 简写语法
    // `+.foo.com` / `*.foo.com` / `.foo.com` → DOMAIN-SUFFIX
    if let Some(rest) = s.strip_prefix("+.").or_else(|| s.strip_prefix("*.")).or_else(|| s.strip_prefix(".")) {
        let trimmed = rest.trim_end_matches('.');
        let lower = trimmed.to_ascii_lowercase();
        if looks_like_domain(&lower) {
            out.push(RuleEntry::domain_entry(lower, EntryType::DomainSuffix));
            return Ok(());
        }
        tracing::warn!("mihomo: invalid suffix at line {}: {}", line_no, s);
        return Ok(());
    }

    // `keyword:xxx` → DOMAIN-KEYWORD
    if let Some(rest) = s.strip_prefix("keyword:") {
        if !rest.is_empty() {
            out.push(RuleEntry::domain_entry(
                rest.to_ascii_lowercase(),
                EntryType::DomainKeyword,
            ));
            return Ok(());
        }
    }

    // 自动判别模式：根据内容猜测
    if behavior == Behavior::Auto {
        // 跳过无参数的 classical 关键字（MATCH / DIRECT / REJECT 等）
        if is_bare_classical_keyword(s) {
            tracing::debug!("mihomo[auto]: skipping bare keyword at line {}: {}", line_no, s);
            return Ok(());
        }
        // IPv4 CIDR
        if s.contains('/') && s.parse::<std::net::Ipv4Addr>().is_ok() || looks_like_ipv4_cidr(s) {
            return push_cidr_str(s, line_no, out);
        }
        // IPv6 CIDR
        if s.contains(':') && s.contains('/') {
            return push_cidr_str(s, line_no, out);
        }
        // 域名
        let trimmed = s.trim_end_matches('.');
        let lower = trimmed.to_ascii_lowercase();
        if looks_like_domain(&lower) {
            out.push(RuleEntry::domain_entry(lower, EntryType::Domain));
            return Ok(());
        }
        tracing::warn!("mihomo[auto]: unrecognized at line {}: {}", line_no, s);
        return Ok(());
    }

    // classical 模式下不带 `,` 的行：跳过
    tracing::warn!("mihomo[classical]: invalid line {}: {}", line_no, s);
    Ok(())
}

/// 处理 classical 类型的单行。
fn push_typed_line(ty: &str, value: &str, line_no: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    match ty.to_ascii_uppercase().as_str() {
        "DOMAIN" => {
            let lower = value.trim_end_matches('.').to_ascii_lowercase();
            if looks_like_domain(&lower) {
                out.push(RuleEntry::domain_entry(lower, EntryType::Domain));
            } else {
                tracing::warn!("mihomo: DOMAIN invalid at line {}: {}", line_no, value);
            }
        }
        "DOMAIN-SUFFIX" => {
            let lower = value.trim_end_matches('.').to_ascii_lowercase();
            if looks_like_domain(&lower) {
                out.push(RuleEntry::domain_entry(lower, EntryType::DomainSuffix));
            } else {
                tracing::warn!("mihomo: DOMAIN-SUFFIX invalid at line {}: {}", line_no, value);
            }
        }
        "DOMAIN-KEYWORD" => {
            if !value.is_empty() {
                out.push(RuleEntry::domain_entry(
                    value.to_ascii_lowercase(),
                    EntryType::DomainKeyword,
                ));
            }
        }
        "DOMAIN-REGEX" => {
            // 提前编译验证
            if regex::Regex::new(value).is_ok() {
                out.push(RuleEntry::domain_entry(value.to_string(), EntryType::DomainRegex));
            } else {
                tracing::warn!("mihomo: DOMAIN-REGEX invalid at line {}: {}", line_no, value);
            }
        }
        "IP-CIDR" => push_cidr_str(value, line_no, out)?,
        "IP-CIDR6" => push_cidr_str(value, line_no, out)?,
        "PORT" => push_port_str(value, line_no, out)?,
        // 不处理的类型：GEOIP / MATCH / RULE-SET / SUB-RULE / etc.
        _ => {
            tracing::debug!("mihomo: skipping {} rule at line {}", ty, line_no);
        }
    }
    Ok(())
}

fn push_cidr_str(s: &str, line_no: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(());
    }
    if s.contains(':') {
        let (addr, prefix) = crate::ruleset::drs::parse_ipv6_cidr(s).map_err(|e| {
            DrsError::ParseError {
                line: line_no,
                msg: e.to_string(),
            }
        })?;
        let v6 = std::net::Ipv6Addr::from(addr.to_be_bytes());
        out.push(RuleEntry::cidr_entry(IpAddr::V6(v6), prefix, EntryType::Ipv6Cidr));
    } else {
        let (addr, prefix) = crate::ruleset::drs::parse_ipv4_cidr(s).map_err(|e| {
            DrsError::ParseError {
                line: line_no,
                msg: e.to_string(),
            }
        })?;
        let v4 = std::net::Ipv4Addr::from(addr);
        out.push(RuleEntry::cidr_entry(IpAddr::V4(v4), prefix, EntryType::Ipv4Cidr));
    }
    Ok(())
}

fn push_port_str(s: &str, line_no: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    let (start, end) = crate::ruleset::drs::parse_port_range(s).map_err(|e| DrsError::ParseError {
        line: line_no,
        msg: e.to_string(),
    })?;
    out.push(RuleEntry::port_entry(start, end));
    Ok(())
}

/// 简单判断是否像 IPv4 CIDR（数字.数字.数字.数字/数字）。
fn looks_like_ipv4_cidr(s: &str) -> bool {
    if !s.contains('/') {
        return false;
    }
    let (addr, prefix) = s.split_once('/').unwrap();
    addr.parse::<std::net::Ipv4Addr>().is_ok() && prefix.parse::<u8>().is_ok()
}

/// 判断是否为无参数的 classical 关键字（MATCH / DIRECT / REJECT / PASS 等）。
/// 这些关键字在 mihomo 中不带逗号分隔的值，Auto 模式下应跳过。
fn is_bare_classical_keyword(s: &str) -> bool {
    // 必须不含 `.` / `:` / `/` / `,`（这些字符表明是域名/CIDR/带参数行）
    if s.bytes().any(|b| matches!(b, b'.' | b':' | b'/' | b',')) {
        return false;
    }
    // 已知无参数关键字
    matches!(s, "MATCH" | "DIRECT" | "REJECT" | "PASS" | "REJECT-DROP" | "COMPATIBLE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_simple_domain() {
        let yaml = r#"
payload:
  - google.com
  - '+.youtube.com'
  - '*.example.com'
  - '.sub.example.com'
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0], RuleEntry::domain_entry("google.com", EntryType::Domain));
        assert_eq!(entries[1], RuleEntry::domain_entry("youtube.com", EntryType::DomainSuffix));
        assert_eq!(entries[2], RuleEntry::domain_entry("example.com", EntryType::DomainSuffix));
        assert_eq!(entries[3], RuleEntry::domain_entry("sub.example.com", EntryType::DomainSuffix));
    }

    #[test]
    fn test_classical_typed_lines() {
        let yaml = r#"
payload:
  - DOMAIN,exact.com
  - DOMAIN-SUFFIX,suffix.com
  - DOMAIN-KEYWORD,kw
  - DOMAIN-REGEX,^ads-\d+
  - IP-CIDR,192.168.0.0/16,no-resolve
  - IP-CIDR6,2001:db8::/32
  - PORT,80
  - PORT,8000-9000
  - GEOIP,CN
  - MATCH
"#;
        let entries = parse(yaml).unwrap();
        // GEOIP / MATCH 应被跳过
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[0].rule_type, EntryType::Domain);
        assert_eq!(entries[1].rule_type, EntryType::DomainSuffix);
        assert_eq!(entries[2].rule_type, EntryType::DomainKeyword);
        assert_eq!(entries[3].rule_type, EntryType::DomainRegex);
        assert_eq!(entries[4].rule_type, EntryType::Ipv4Cidr);
        assert_eq!(entries[5].rule_type, EntryType::Ipv6Cidr);
        assert_eq!(entries[6].rule_type, EntryType::Port);
        assert_eq!(entries[6].port, Some((80, 80)));
        assert_eq!(entries[7].rule_type, EntryType::Port);
        assert_eq!(entries[7].port, Some((8000, 9000)));
    }

    #[test]
    fn test_behavior_domain() {
        let yaml = r#"
behavior: domain
payload:
  - google.com
  - example.com
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rule_type, EntryType::Domain);
        assert_eq!(entries[1].rule_type, EntryType::Domain);
    }

    #[test]
    fn test_behavior_ipcidr() {
        let yaml = r#"
behavior: ipcidr
payload:
  - 10.0.0.0/8
  - 192.168.0.0/16
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rule_type, EntryType::Ipv4Cidr);
        assert_eq!(entries[1].rule_type, EntryType::Ipv4Cidr);
    }

    #[test]
    fn test_behavior_classical() {
        let yaml = r#"
behavior: classical
payload:
  - DOMAIN,a.com
  - DOMAIN-SUFFIX,b.com
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rule_type, EntryType::Domain);
        assert_eq!(entries[1].rule_type, EntryType::DomainSuffix);
    }

    #[test]
    fn test_auto_recognize_cidr() {
        let yaml = r#"
payload:
  - 10.0.0.0/8
  - 2001:db8::/32
  - example.com
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].rule_type, EntryType::Ipv4Cidr);
        assert_eq!(entries[1].rule_type, EntryType::Ipv6Cidr);
        assert_eq!(entries[2].rule_type, EntryType::Domain);
    }

    #[test]
    fn test_keyword_prefix() {
        let yaml = r#"
payload:
  - keyword:google
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_type, EntryType::DomainKeyword);
        assert_eq!(entries[0].domain, "google");
    }

    #[test]
    fn test_trailing_dot_normalized() {
        let yaml = r#"
payload:
  - example.com.
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
    }

    #[test]
    fn test_case_insensitive() {
        let yaml = r#"
payload:
  - EXAMPLE.COM
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
    }

    #[test]
    fn test_no_resolve_modifier_stripped() {
        let yaml = r#"
payload:
  - IP-CIDR,192.168.0.0/16,no-resolve
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_type, EntryType::Ipv4Cidr);
    }

    #[test]
    fn test_invalid_behavior() {
        let yaml = r#"
behavior: unknown
payload: []
"#;
        let err = parse(yaml);
        assert!(err.is_err());
    }

    #[test]
    fn test_missing_payload() {
        let yaml = "behavior: domain";
        let err = parse(yaml);
        assert!(err.is_err());
    }

    #[test]
    fn test_empty_payload() {
        let yaml = r#"
payload: []
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries.len(), 0);
    }
}
