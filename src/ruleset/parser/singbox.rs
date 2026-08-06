//! sing-box JSON 规则解析。
//!
//! 支持 sing-box 1.x 的 rule-set JSON 格式：
//!
//! ```json
//! {
//!   "version": 1,
//!   "rules": [
//!     {
//!       "domain": ["example.com", "exact.test"],
//!       "domain_suffix": ["google.com"],
//!       "domain_keyword": ["ads"],
//!       "domain_regex": ["^ads-\\d+\\.example\\.com$"],
//!       "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
//!       "port": [80, "8000-9000"]
//!     }
//!   ]
//! }
//! ```
//!
//! 同时兼容「单 rule」扁平写法（顶层就是 `domain`/`domain_suffix`/...）。
//! 未识别的字段（`source_ip_cidr`/`process_name`/`network`/`protocol` 等）会被跳过并记录。

use super::{EntryType, RuleEntry};
use crate::ruleset::drs::{looks_like_domain, parse_ipv4_cidr, parse_ipv6_cidr, parse_port_range};
use crate::ruleset::error::{DrsError, Result};
use std::net::IpAddr;

/// 解析 sing-box JSON 规则集。
///
/// 自动识别两种写法：
///   - 顶层有 `rules` 数组（标准 rule-set 格式）
///   - 顶层直接是单条 rule（扁平写法）
pub fn parse(input: &str) -> Result<Vec<RuleEntry>> {
    let doc: serde_json::Value = serde_json::from_str(input).map_err(|e| DrsError::ParseError {
        line: 0,
        msg: format!("JSON parse: {}", e),
    })?;

    let mut out = Vec::new();

    if let Some(rules) = doc.get("rules").and_then(|v| v.as_array()) {
        for (i, rule) in rules.iter().enumerate() {
            parse_one_rule(rule, i + 1, &mut out)?;
        }
    } else if doc.is_object() {
        // 扁平写法：顶层就是 rule
        parse_one_rule(&doc, 1, &mut out)?;
    } else {
        return Err(DrsError::ParseError {
            line: 0,
            msg: "expected JSON object with `rules` array or flat rule fields".to_string(),
        });
    }

    Ok(out)
}

/// 解析单条 rule 对象，把识别到的字段 push 到 `out`。
fn parse_one_rule(rule: &serde_json::Value, rule_idx: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    let obj = rule.as_object().ok_or_else(|| DrsError::ParseError {
        line: rule_idx,
        msg: format!("rule #{} is not an object", rule_idx),
    })?;

    for (key, val) in obj {
        match key.as_str() {
            "domain" => push_string_array(val, rule_idx, "domain", |s| {
                push_domain(s, EntryType::Domain, out)
            })?,
            "domain_suffix" => push_string_array(val, rule_idx, "domain_suffix", |s| {
                // sing-box 习惯写法可以带前导点（`.example.com`），我们剥掉后按 suffix 处理
                let s = s.strip_prefix('.').unwrap_or(s);
                push_domain(s, EntryType::DomainSuffix, out)
            })?,
            "domain_keyword" => push_string_array(val, rule_idx, "domain_keyword", |s| {
                if !s.is_empty() {
                    out.push(RuleEntry::domain_entry(
                        s.to_ascii_lowercase(),
                        EntryType::DomainKeyword,
                    ));
                }
                Ok(())
            })?,
            "domain_regex" => push_string_array(val, rule_idx, "domain_regex", |s| {
                // 提前编译验证，避免写入无效正则
                if regex::Regex::new(s).is_ok() {
                    out.push(RuleEntry::domain_entry(s.to_string(), EntryType::DomainRegex));
                } else {
                    tracing::warn!("singbox: invalid domain_regex `{}` in rule #{}", s, rule_idx);
                }
                Ok(())
            })?,
            "ip_cidr" => push_string_array(val, rule_idx, "ip_cidr", |s| {
                push_cidr_str(s, rule_idx, out)
            })?,
            "port" => parse_port_value(val, rule_idx, out)?,
            // 不识别的字段：source_ip_cidr / source_port / process_name / network / protocol / outbound / action 等
            _ => {
                tracing::debug!(
                    "singbox: skipping unknown field `{}` in rule #{}",
                    key,
                    rule_idx
                );
            }
        }
    }

    Ok(())
}

/// 把 JSON 数组里的每个字符串元素依次喂给 `cb`。
/// 也兼容单字符串（非数组）写法。
fn push_string_array<F>(val: &serde_json::Value, rule_idx: usize, field: &str, mut cb: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    if let Some(arr) = val.as_array() {
        for (i, v) in arr.iter().enumerate() {
            let s = v.as_str().ok_or_else(|| DrsError::ParseError {
                line: rule_idx,
                msg: format!("rule #{} `{}`[{}] is not a string", rule_idx, field, i),
            })?;
            cb(s)?;
        }
    } else if let Some(s) = val.as_str() {
        cb(s)?;
    } else {
        return Err(DrsError::ParseError {
            line: rule_idx,
            msg: format!("rule #{} `{}` must be array or string", rule_idx, field),
        });
    }
    Ok(())
}

/// 域名类规则 push：trim 末尾点 + ASCII 小写 + 合法性校验。
fn push_domain(s: &str, ty: EntryType, out: &mut Vec<RuleEntry>) -> Result<()> {
    let trimmed = s.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(());
    }
    let lower = trimmed.to_ascii_lowercase();
    if !looks_like_domain(&lower) {
        tracing::warn!("singbox: invalid domain `{}`", s);
        return Ok(());
    }
    out.push(RuleEntry::domain_entry(lower, ty));
    Ok(())
}

/// CIDR 字符串 push：自动判断 v4 / v6。
fn push_cidr_str(s: &str, rule_idx: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(());
    }
    if s.contains(':') {
        let (addr, prefix) = parse_ipv6_cidr(s).map_err(|e| DrsError::ParseError {
            line: rule_idx,
            msg: e.to_string(),
        })?;
        let v6 = std::net::Ipv6Addr::from(addr.to_be_bytes());
        out.push(RuleEntry::cidr_entry(IpAddr::V6(v6), prefix, EntryType::Ipv6Cidr));
    } else {
        let (addr, prefix) = parse_ipv4_cidr(s).map_err(|e| DrsError::ParseError {
            line: rule_idx,
            msg: e.to_string(),
        })?;
        let v4 = std::net::Ipv4Addr::from(addr);
        out.push(RuleEntry::cidr_entry(IpAddr::V4(v4), prefix, EntryType::Ipv4Cidr));
    }
    Ok(())
}

/// 解析 sing-box 的 `port` 字段：可以是数字数组，也可以是字符串范围 `"8000-9000"`。
pub fn parse_port_value(val: &serde_json::Value, rule_idx: usize, out: &mut Vec<RuleEntry>) -> Result<()> {
    let push_str_port = |s: &str, out: &mut Vec<RuleEntry>| -> Result<()> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(());
        }
        let (start, end) = parse_port_range(s).map_err(|e| DrsError::ParseError {
            line: rule_idx,
            msg: e.to_string(),
        })?;
        out.push(RuleEntry::port_entry(start, end));
        Ok(())
    };

    if let Some(arr) = val.as_array() {
        for v in arr {
            match v {
                serde_json::Value::Number(n) => {
                    let p = n.as_u64().and_then(|u| u16::try_from(u).ok()).ok_or_else(|| {
                        DrsError::ParseError {
                            line: rule_idx,
                            msg: format!("invalid port number `{}`", n),
                        }
                    })?;
                    out.push(RuleEntry::port_entry(p, p));
                }
                serde_json::Value::String(s) => push_str_port(s, out)?,
                _ => return Err(DrsError::ParseError {
                    line: rule_idx,
                    msg: format!("port array element must be number or string, got {:?}", v),
                }),
            }
        }
    } else if let Some(s) = val.as_str() {
        push_str_port(s, out)?;
    } else if let Some(n) = val.as_u64() {
        let p = u16::try_from(n).map_err(|_| DrsError::ParseError {
            line: rule_idx,
            msg: format!("port number out of range: {}", n),
        })?;
        out.push(RuleEntry::port_entry(p, p));
    } else {
        return Err(DrsError::ParseError {
            line: rule_idx,
            msg: "port field must be array, string, or number".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_ruleset() {
        let json = r#"
{
  "version": 1,
  "rules": [
    {
      "domain": ["example.com", "exact.test"],
      "domain_suffix": ["google.com", ".youtube.com"],
      "domain_keyword": ["ads"],
      "domain_regex": ["^ads-\\d+\\.example\\.com$"],
      "ip_cidr": ["10.0.0.0/8", "2001:db8::/32"],
      "port": [80, "8000-9000"]
    }
  ]
}
"#;
        let entries = parse(json).unwrap();
        // domain 2 + suffix 2 + keyword 1 + regex 1 + ipcidr 2 + port 2 = 10
        assert_eq!(entries.len(), 10);

        // 字段处理顺序由 serde_json::Map 决定（BTreeMap，按字母序），
        // 不保证与 JSON 输入顺序一致，所以用集合成员检查代替位置断言。
        use std::collections::HashSet;

        let domain_set: HashSet<&str> = entries
            .iter()
            .filter(|e| e.rule_type == EntryType::Domain)
            .map(|e| e.domain.as_str())
            .collect();
        assert!(domain_set.contains("example.com"));
        assert!(domain_set.contains("exact.test"));

        let suffix_set: HashSet<&str> = entries
            .iter()
            .filter(|e| e.rule_type == EntryType::DomainSuffix)
            .map(|e| e.domain.as_str())
            .collect();
        assert!(suffix_set.contains("google.com"));
        assert!(suffix_set.contains("youtube.com")); // 前导点剥除

        let keyword_set: HashSet<&str> = entries
            .iter()
            .filter(|e| e.rule_type == EntryType::DomainKeyword)
            .map(|e| e.domain.as_str())
            .collect();
        assert!(keyword_set.contains("ads"));

        assert_eq!(
            entries.iter().filter(|e| e.rule_type == EntryType::DomainRegex).count(),
            1
        );

        assert_eq!(
            entries.iter().filter(|e| e.rule_type == EntryType::Ipv4Cidr).count(),
            1
        );
        assert_eq!(
            entries.iter().filter(|e| e.rule_type == EntryType::Ipv6Cidr).count(),
            1
        );

        let ports: Vec<(u16, u16)> = entries
            .iter()
            .filter(|e| e.rule_type == EntryType::Port)
            .filter_map(|e| e.port)
            .collect();
        assert_eq!(ports.len(), 2);
        assert!(ports.contains(&(80, 80)));
        assert!(ports.contains(&(8000, 9000)));
    }

    #[test]
    fn test_flat_rule() {
        let json = r#"
{
  "domain": ["a.com"],
  "domain_suffix": ["b.com"]
}
"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], RuleEntry::domain_entry("a.com", EntryType::Domain));
        assert_eq!(entries[1], RuleEntry::domain_entry("b.com", EntryType::DomainSuffix));
    }

    #[test]
    fn test_unknown_fields_skipped() {
        let json = r#"
{
  "rules": [
    {
      "domain": ["keep.com"],
      "source_ip_cidr": ["192.168.0.0/16"],
      "process_name": ["chrome"],
      "network": ["tcp"]
    }
  ]
}
"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "keep.com");
    }

    #[test]
    fn test_trailing_dot_normalized() {
        let json = r#"
{
  "domain": ["example.com."]
}
"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
    }

    #[test]
    fn test_case_insensitive() {
        let json = r#"
{
  "domain": ["EXAMPLE.COM"]
}
"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
    }

    #[test]
    fn test_invalid_json() {
        let json = "{not valid json";
        assert!(parse(json).is_err());
    }

    #[test]
    fn test_invalid_rule_not_object() {
        let json = r#"
{
  "rules": ["not_an_object"]
}
"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn test_domain_not_string_array() {
        let json = r#"
{
  "rules": [
    {
      "domain": [123]
    }
  ]
}
"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn test_invalid_cidr_reports_error() {
        let json = r#"
{
  "rules": [
    {
      "ip_cidr": ["not-a-cidr"]
    }
  ]
}
"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn test_empty_rules_array() {
        let json = r#"
{
  "rules": []
}
"#;
        let entries = parse(json).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_multiple_rules_concat() {
        let json = r#"
{
  "rules": [
    { "domain": ["a.com"] },
    { "domain_suffix": ["b.com"] },
    { "domain_keyword": ["c"] }
  ]
}
"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].rule_type, EntryType::Domain);
        assert_eq!(entries[1].rule_type, EntryType::DomainSuffix);
        assert_eq!(entries[2].rule_type, EntryType::DomainKeyword);
    }
}
