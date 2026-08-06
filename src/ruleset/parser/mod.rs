//! 解析后的规则条目。
//!
//! `RuleEntry` 是 parser 的统一输出，builder 把它分流到各 section 写入 .drs。
//! 设计上把「变长字符串」和「定长二进制」两类规则分开存：
//!   - 变长字符串类（Domain/DomainSuffix/DomainKeyword/DomainRegex）放 `domain` 字段
//!   - 定长类（IpCidrV4/IpCidrV6/Port）放 `cidr` / `port` 字段
//!
//! 这样 builder 不用做额外内存分配就能直接序列化。

pub mod adguard;
pub mod mihomo;
pub mod singbox;

use std::net::IpAddr;

/// 解析后的规则条目。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleEntry {
    pub rule_type: EntryType,
    /// 变长字符串类规则用此字段：精确域名 / 后缀域名 / 关键词 / 正则 pattern。
    /// 写入 DomainSuffix FST 前会经 `suffix_to_fst_key` 反转 label + 加尾点。
    pub domain: String,
    /// IP CIDR 类规则用此字段（已规范化网络地址 + 前缀长度）。
    pub cidr: Option<(IpAddr, u8)>,
    /// 端口范围类规则用此字段（start..=end 闭区间）。
    pub port: Option<(u16, u16)>,
}

impl RuleEntry {
    /// 构造一个域名类 entry（Domain/DomainSuffix/DomainKeyword/DomainRegex）。
    pub fn domain_entry(domain: impl Into<String>, rule_type: EntryType) -> Self {
        Self {
            rule_type,
            domain: domain.into(),
            cidr: None,
            port: None,
        }
    }

    /// 构造一个 IP CIDR entry。
    pub fn cidr_entry(addr: IpAddr, prefix: u8, rule_type: EntryType) -> Self {
        Self {
            rule_type,
            domain: String::new(),
            cidr: Some((addr, prefix)),
            port: None,
        }
    }

    /// 构造一个端口 entry。
    pub fn port_entry(start: u16, end: u16) -> Self {
        Self {
            rule_type: EntryType::Port,
            domain: String::new(),
            cidr: None,
            port: Some((start, end)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    Ipv4Cidr,
    Ipv6Cidr,
    Port,
    /// 例外（@@ 白名单）精确域名
    ExcludeDomain,
    /// 例外域名后缀
    ExcludeDomainSuffix,
    /// 例外域名正则
    ExcludeDomainRegex,
}
