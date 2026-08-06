//! AdGuard 过滤列表解析。
//!
//! 支持的语法（对齐 sing-box AdGuardMatcher 语义）：
//!
//! | 写法                        | 转换为                  | 说明                            |
//! |-----------------------------|-------------------------|---------------------------------|
//! | `\|\|example.com^`          | DOMAIN-SUFFIX           | 双管道 + 尾锚点（标准后缀规则） |
//! | `\|\|example.com^\|`        | DOMAIN-SUFFIX           | 双管道 + 尾锚点 + 行尾管道      |
//! | `\|\|example.com`           | DOMAIN-SUFFIX           | 双管道（无锚点，标准子域，已知限制） |
//! | `\|example.com^`            | DOMAIN                  | 单管道（精确）                  |
//! | `\|example.gov`             | DOMAIN-REGEX            | 单管道无 ^（前缀匹配）           |
//! | `example.org^`              | DOMAIN-REGEX            | 无前缀有 ^（子串匹配）           |
//! | `example.com`               | DOMAIN                  | 裸域名（精确，对齐 sing-box isRawDomain）|
//! | `0.0.0.0 example.com`       | DOMAIN                  | hosts 格式                      |
//! | `@@\|\|whitelist.com^`      | EXCLUDE-DOMAIN-SUFFIX   | 白名单（例外规则）              |
//! | `/regex/`                   | DOMAIN-REGEX            | 正则                            |
//! | `*.example.com`             | DOMAIN-SUFFIX           | 通配符前缀（剥掉 *）            |
//! | `||*.example.com^`          | DOMAIN-SUFFIX           | `||` + `*.` → suffix            |
//! | `||**.example.org^`         | DOMAIN-REGEX            | 多通配符（转正则，* 可空）       |
//! | `https://example.com/...`   | DOMAIN-SUFFIX           | URL（取 host）                  |
//! | `example.com$important`     | DOMAIN-SUFFIX           | 修饰符（已识别支持集合则保留）  |
//!
//! 跳过：化妆品规则（`##`）、`!`/`#` 注释、`$` 修饰符组合中不支持的部分。

use super::{EntryType, RuleEntry};
use crate::ruleset::drs::looks_like_domain;
use std::collections::HashSet;

/// AdGuard 修饰符白名单：这些修饰符不改变规则类型，仅作为附加条件，
/// 我们直接保留规则（忽略修饰符）。其他修饰符（如 `$replace`、`$xmlhttprequest`）
/// 通常是内容修改类规则，对 DNS 路由无意义，整条规则跳过。
const SUPPORTED_MODIFIERS: &[&str] = &[
    "important",
    "dnsrewrite",
    "dnstype",
    "domain",
    "app",
    "network",
];

/// 解析报告：包含 entries + 跳过统计。
#[derive(Debug, Default)]
pub struct AdGuardParseReport {
    pub entries: Vec<RuleEntry>,
    pub total_lines: usize,
    pub ignored_lines: usize,
    /// 跳过行的样本（最多 10 条），便于 CLI 输出调试。
    pub ignored_samples: Vec<(usize, String)>,
}

impl AdGuardParseReport {
    pub fn into_entries(self) -> Vec<RuleEntry> {
        self.entries
    }

    pub fn into_iter(self) -> impl Iterator<Item = RuleEntry> {
        self.entries.into_iter()
    }
}

/// 解析 AdGuard 过滤列表。
pub fn parse(input: &str) -> AdGuardParseReport {
    let mut report = AdGuardParseReport::default();
    let localhost_names: HashSet<&'static str> =
        HashSet::from(["localhost", "localhost.localdomain"]);

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();

        if line.is_empty() {
            continue;
        }
        report.total_lines += 1;
        if line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        // 化妆品规则
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            continue;
        }

        // ── 0) 裸域名快速路径（对齐 sing-box isRawDomain） ──────────────
        //    不含空格/$/|/^/*/\///:// 的纯域名 → 精确匹配
        if is_raw_domain_line(line) {
            report.entries.push(RuleEntry::domain_entry(
                normalize_domain_str(line),
                EntryType::Domain,
            ));
            continue;
        }

        // 直接处理白名单 @@（先于其他解析）
        let is_exclude = line.starts_with("@@");
        let working_line = if is_exclude {
            &line[2..]
        } else {
            line
        };

        // 正则规则
        if let Some(rest) = working_line.strip_prefix('/') {
            if let Some(end) = rest.find('/') {
                let pattern = &rest[..end];
                if !pattern.is_empty() && validate_regex(pattern) {
                    report.entries.push(RuleEntry::domain_entry(
                        pattern.to_string(),
                        if is_exclude {
                            EntryType::ExcludeDomainRegex
                        } else {
                            EntryType::DomainRegex
                        },
                    ));
                    continue;
                }
            }
            record_skip(&mut report, line_no, line);
            continue;
        }

        // 剥离修饰符
        let (rule_body, modifiers) = split_modifiers(working_line);
        if !modifiers_supported(&modifiers) {
            record_skip(&mut report, line_no, line);
            continue;
        }

        // hosts 格式
        if let Some(entry) = try_parse_hosts_line(rule_body, &localhost_names) {
            if let Some(e) = entry {
                report.entries.push(e);
            }
            continue;
        }

        // scheme
        let rule_body = strip_scheme(rule_body);

        // ── 检测 ^ 结尾锚点 ──────────────────────────────────────────────
        let has_end = {
            let host_part = rule_body.split('/').next().unwrap_or(rule_body);
            let host_part = host_part.trim_end_matches('|');
            host_part.contains('^')
        };

        // ── || 双管道后缀 ────────────────────────────────────────────────
        if let Some(rest) = rule_body.strip_prefix("||") {
            let domain = strip_anchors(rest);
            if let Some(e) = parse_wildcard_or_plain(
                domain,
                if is_exclude {
                    EntryType::ExcludeDomainSuffix
                } else {
                    EntryType::DomainSuffix
                },
            ) {
                report.entries.push(e);
                continue;
            }
            record_skip(&mut report, line_no, line);
            continue;
        }

        // ── | 单管道 ─────────────────────────────────────────────────────
        if let Some(rest) = rule_body.strip_prefix('|') {
            let domain = strip_anchors(rest);
            let trimmed = domain.trim_end_matches('.');
            if trimmed.is_empty() {
                record_skip(&mut report, line_no, line);
                continue;
            }
            // |xxx^ → 精确；|xxx（无^）→ 前缀匹配（对齐 sing-box）
            if has_end {
                // 精确匹配
                if looks_like_domain(trimmed) {
                    let entry_type = if is_exclude {
                        EntryType::ExcludeDomain
                    } else {
                        EntryType::Domain
                    };
                    report.entries.push(RuleEntry::domain_entry(
                        normalize_domain_str(trimmed),
                        entry_type,
                    ));
                    continue;
                }
            } else {
                // 前缀匹配 → regex
                let pattern = format!("^{}", regex::escape(trimmed));
                if validate_regex(&pattern) {
                    report.entries.push(RuleEntry::domain_entry(
                        pattern,
                        if is_exclude {
                            EntryType::ExcludeDomainRegex
                        } else {
                            EntryType::DomainRegex
                        },
                    ));
                    continue;
                }
            }
            record_skip(&mut report, line_no, line);
            continue;
        }

        // ── 裸域名 / 通配符 ──────────────────────────────────────────────
        // 有 ^ 无前缀 → 子串匹配结尾锚定（对齐 sing-box: example.org^ 匹配 notexample.org）
        if has_end {
            let body = strip_anchors(rule_body);
            let body = body.trim_end_matches('.');
            if !body.is_empty() {
                // 通配符
                if body.contains('*') {
                    let pattern = build_wildcard_end_anchored(body);
                    if validate_regex(&pattern) {
                        report.entries.push(RuleEntry::domain_entry(
                            pattern,
                            if is_exclude {
                                EntryType::ExcludeDomainRegex
                            } else {
                                EntryType::DomainRegex
                            },
                        ));
                        continue;
                    }
                } else if looks_like_domain(body) {
                    // 子串匹配：xxx^ → regex xxx$
                    let pattern = format!("{}$", regex::escape(&normalize_domain_str(body)));
                    if validate_regex(&pattern) {
                        report.entries.push(RuleEntry::domain_entry(
                            pattern,
                            if is_exclude {
                                EntryType::ExcludeDomainRegex
                            } else {
                                EntryType::DomainRegex
                            },
                        ));
                        continue;
                    }
                }
            }
            record_skip(&mut report, line_no, line);
            continue;
        }

        // 无 ^ 裸行：后缀（含 @ 修饰符剥离后的残留）
        if let Some(e) = parse_wildcard_or_plain(
            rule_body,
            if is_exclude {
                EntryType::ExcludeDomainSuffix
            } else {
                EntryType::DomainSuffix
            },
        ) {
            report.entries.push(e);
            continue;
        }

        record_skip(&mut report, line_no, line);
    }

    report
}

/// 检查整行是否是合法裸域名（无任何修饰符/锚点/通配符/scheme），
/// 对齐 sing-box isRawDomain 快速路径。
fn is_raw_domain_line(line: &str) -> bool {
    for ch in line.chars() {
        match ch {
            ' ' | '$' | '|' | '^' | '*' | '/' | ':' | '!' | '#' | '?' | '&'
            | '[' | ']' | '(' | ')' | '~' | '@' => return false,
            _ => {}
        }
    }
    if line.starts_with('.') || line.starts_with('-') {
        return false;
    }
    // 排除纯 IP 地址
    if looks_like_ipcidr(line) {
        return false;
    }
    looks_like_domain(&line.to_ascii_lowercase())
}

/// 检查字符串是否是纯 IP 地址（跳过以免被误认为域名）。
fn looks_like_ipcidr(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    let parts: Vec<&str> = s.split('.').collect();
    if (3..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u8>().is_ok())
    {
        return true;
    }
    if s.contains("::") && s.split(':').count() <= 8 {
        if let Ok(addr) = s.parse::<std::net::Ipv6Addr>() {
            return !addr.is_unspecified();
        }
    }
    false
}

fn record_skip(report: &mut AdGuardParseReport, line_no: usize, line: &str) {
    report.ignored_lines += 1;
    if report.ignored_samples.len() < 10 {
        report.ignored_samples.push((line_no, line.to_string()));
    }
}

fn split_modifiers(s: &str) -> (&str, Vec<&str>) {
    if let Some(pos) = s.find('$') {
        let body = &s[..pos];
        let mods_str = &s[pos + 1..];
        let mods: Vec<&str> = mods_str.split(',').map(|m| m.trim()).collect();
        (body, mods)
    } else {
        (s, Vec::new())
    }
}

fn modifiers_supported(mods: &[&str]) -> bool {
    for m in mods {
        let name = m.split('=').next().unwrap_or(m);
        if name.starts_with('~') {
            return false;
        }
        if !SUPPORTED_MODIFIERS.contains(&name) {
            return false;
        }
    }
    true
}

fn try_parse_hosts_line(
    s: &str,
    localhost_names: &HashSet<&'static str>,
) -> Option<Option<RuleEntry>> {
    let mut parts = s.split_whitespace();
    let ip_part = parts.next()?;
    let ip_ok = ip_part.parse::<std::net::IpAddr>().is_ok();
    if !ip_ok {
        return None;
    }
    let domain = parts.next()?;
    if domain.is_empty() {
        return Some(None);
    }
    let lower = domain.to_ascii_lowercase();
    if localhost_names.contains(lower.as_str()) {
        return Some(None);
    }
    if !looks_like_domain(&lower) {
        return Some(None);
    }
    Some(Some(RuleEntry::domain_entry(lower, EntryType::Domain)))
}

fn strip_scheme(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("https://") {
        rest
    } else if let Some(rest) = s.strip_prefix("http://") {
        rest
    } else {
        s
    }
}

fn strip_anchors(s: &str) -> &str {
    let host_part = s.split('/').next().unwrap_or(s);
    let host_part = host_part.trim_end_matches('|');
    let host_part = host_part.split('^').next().unwrap_or(host_part);
    host_part.trim()
}

fn parse_wildcard_or_plain(s: &str, default_type: EntryType) -> Option<RuleEntry> {
    let host = s.split('/').next().unwrap_or(s);
    let host = host.split('^').next().unwrap_or(host);
    let host = host.trim_end_matches('|').trim();
    if host.is_empty() {
        return None;
    }

    let has_wildcard = host.contains('*');
    if !has_wildcard {
        let trimmed = host.trim_end_matches('.');
        if trimmed.is_empty() || !looks_like_domain(trimmed) {
            return None;
        }
        return Some(RuleEntry::domain_entry(
            normalize_domain_str(trimmed),
            default_type,
        ));
    }

    // 单前缀 `*.` → suffix
    if let Some(rest) = host.strip_prefix("*.") {
        let rest_clean = rest.trim_end_matches('.');
        if !rest_clean.is_empty() && !rest_clean.contains('*') && looks_like_domain(rest_clean) {
            return Some(RuleEntry::domain_entry(
                normalize_domain_str(rest_clean),
                default_type,
            ));
        }
    }

    // 多通配符或后缀通配符 → 转正则
    let pattern = build_wildcard_regex(host);
    if validate_regex(&pattern) {
        Some(RuleEntry::domain_entry(pattern, EntryType::DomainRegex))
    } else {
        None
    }
}

/// 构建通配符正则（subdomain 语义，`*` 可空）。
/// 对齐 sing AdGuardMatcher anyLabel：
/// - `*` 后跟 `.` 时，使用 `(?:[^.]+\.)*(?:\.)?` 确保 `*` 为空时也能匹配
fn build_wildcard_regex(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('*').collect();
    let mut out = String::with_capacity(domain.len() * 2 + 2);
    out.push('^');
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            // 前一段为空（`*` 开头或连续 `*`），且当前段以 `.` 开头
            // → 使用 subdomain-label 模式支持 `*` 匹配空
            if parts[i - 1].is_empty() && part.starts_with('.') {
                let rest = &part[1..];
                out.push_str(r"(?:[^.]+\.)*");
                if !rest.is_empty() {
                    out.push_str(r"(?:\.)?");
                    escape_regex_range(rest, &mut out);
                }
            } else {
                out.push_str(".*");
                escape_regex_range(part, &mut out);
            }
        } else {
            escape_regex_range(part, &mut out);
        }
    }
    out.push('$');
    out
}

/// 用于 `xxx^` 场景（子串匹配结尾锚定）的通配符正则。
fn build_wildcard_end_anchored(body: &str) -> String {
    let parts: Vec<&str> = body.split('*').collect();
    let mut out = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push_str(".*");
        }
        escape_regex_range(part, &mut out);
    }
    out.push('$');
    out
}

fn escape_regex_range(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '.' => out.push_str("\\."),
            '-' | '_' => out.push(c),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => {
                out.push('\\');
                out.push(c);
            }
        }
    }
}

fn validate_regex(pattern: &str) -> bool {
    regex::Regex::new(pattern).is_ok()
}

fn normalize_domain_str(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

impl AdGuardParseReport {
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<AdGuardParseReport> for Vec<RuleEntry> {
    fn from(r: AdGuardParseReport) -> Vec<RuleEntry> {
        r.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain_of(e: &RuleEntry) -> &str {
        &e.domain
    }

    #[test]
    fn test_basic_double_pipe() {
        let txt = r#"
! comment
||ads.example.com^
||tracker.net^|
||google.com^$important
"#;
        let r = parse(txt);
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.entries[0].domain, "ads.example.com");
        assert_eq!(r.entries[0].rule_type, EntryType::DomainSuffix);
        assert_eq!(r.entries[1].domain, "tracker.net");
        assert_eq!(r.entries[2].domain, "google.com");
    }

    #[test]
    fn test_whitelist_is_exclude_suffix() {
        let txt = "@@||whitelist.com^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::ExcludeDomainSuffix);
        assert_eq!(r.entries[0].domain, "whitelist.com");
    }

    #[test]
    fn test_whitelist_exact() {
        let txt = "@@|exact.io^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::ExcludeDomain);
        assert_eq!(r.entries[0].domain, "exact.io");
    }

    #[test]
    fn test_regex() {
        let txt = r#"
/^ads-\d+\.example\.com$/
/invalid[/
"#;
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
        assert!(r.ignored_lines >= 1);
    }

    #[test]
    fn test_wildcard_prefix() {
        let txt = "*.example.com";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainSuffix);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_wildcard_suffix_to_regex() {
        let txt = "example.*";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
        assert!(r.entries[0].domain.starts_with("^example\\."));
    }

    #[test]
    fn test_wildcard_multi_to_regex() {
        let txt = "*.wild*.com";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
    }

    #[test]
    fn test_wildcard_double_star_suffix() {
        // ||**.example.org^ → suffix FST + subdomain wildcard regex
        // relay strips || and ^ → "**.example.org" → wildcard regex
        let txt = "||**.example.org^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
        // verify * can match empty: example.org itself
        let rx = regex::Regex::new(&r.entries[0].domain).unwrap();
        assert!(!rx.is_match("example.org")); // || prefix → strip_anchors removes ^, then parse_wildcard_or_plain wildcard path
        // Actually the regex is ^(?:[^.]+\.)*(?:\.)?example\.org$ which should match example.org
        assert!(rx.is_match("example.org"), "** should match empty for example.org");
        assert!(rx.is_match("sub.example.org"));
    }

    #[test]
    fn test_single_pipe_exact() {
        let txt = "|exact.example.com^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::Domain);
        assert_eq!(r.entries[0].domain, "exact.example.com");
    }

    #[test]
    fn test_single_pipe_no_end_prefix() {
        // |example.gov → prefix match (对齐 sing-box)
        let txt = "|example.gov";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
        let rx = regex::Regex::new(&r.entries[0].domain).unwrap();
        assert!(rx.is_match("example.gov"));
        assert!(rx.is_match("example.gov.cn"));
        assert!(!rx.is_match("www.example.gov"));
    }

    #[test]
    fn test_bare_domain_is_exact() {
        // 裸域名 → 精确（对齐 sing-box isRawDomain）
        let txt = "bare.com";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::Domain);
        assert_eq!(r.entries[0].domain, "bare.com");
    }

    #[test]
    fn test_no_prefix_with_end_is_substring() {
        // example.org^ → 子串匹配（对齐 sing-box）
        let txt = "example.org^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].rule_type, EntryType::DomainRegex);
        let rx = regex::Regex::new(&r.entries[0].domain).unwrap();
        assert!(rx.is_match("example.org"));
        assert!(rx.is_match("notexample.org"));
        assert!(rx.is_match("www.example.org"));
        assert!(!rx.is_match("example.org.cn"));
    }

    #[test]
    fn test_hosts_format() {
        let txt = r#"
0.0.0.0 ads.example.com
127.0.0.1 localhost
0.0.0.0 tracker.net # comment
"#;
        let r = parse(txt);
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].domain, "ads.example.com");
        assert_eq!(r.entries[0].rule_type, EntryType::Domain);
        assert_eq!(r.entries[1].domain, "tracker.net");
    }

    #[test]
    fn test_url_with_path() {
        let txt = "||example.com/path/to/resource";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_https_scheme() {
        let txt = "https://example.com/";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_trailing_dot_normalized() {
        let txt = "||example.com.^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_case_insensitive() {
        let txt = "||EXAMPLE.COM^";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_cosmetic_skipped() {
        let txt = r#"
example.com##.ad-banner
example.com#@#.ad-banner
example.com#?#selector
"#;
        let r = parse(txt);
        assert_eq!(r.entries.len(), 0);
    }

    #[test]
    fn test_unsupported_modifier_skipped() {
        let txt = "||example.com^$replace=/foo/bar/";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 0);
        assert!(r.ignored_lines >= 1);
    }

    #[test]
    fn test_supported_modifier_kept() {
        let txt = "||example.com^$important";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].domain, "example.com");
    }

    #[test]
    fn test_raw_ip_skipped() {
        let txt = "1.2.3.4";
        let r = parse(txt);
        assert_eq!(r.entries.len(), 0);
        assert!(r.ignored_lines >= 1);
    }

    #[test]
    fn test_report_stats() {
        let txt = r#"
! cmt
||good.com^
/invalid[/
||bad$replace=/x/
"#;
        let r = parse(txt);
        assert_eq!(r.total_lines, 4);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.ignored_lines, 2);
    }

    #[test]
    fn test_ignored_samples() {
        let txt = "/invalid[/";
        let r = parse(txt);
        assert_eq!(r.ignored_samples.len(), 1);
        assert_eq!(r.ignored_samples[0].0, 1);
    }
}
