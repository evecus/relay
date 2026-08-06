//! 配置定义（YAML，mihomo DNS 风格）。
//!
//! 用户写的 YAML 格式由 `ConfigYaml` 反序列化，再通过 `into_config()`
//! 规范化为 `Config`（router/run 用的结构）。规范化包括：
//!   - `rules` 的数组 key（`[a, b]: ...`）展开为多个独立名字指向同一 group
//!   - `nameserver` 转为 "default" group
//!   - `rulesets` 的 map / list 两种写法统一为 `Vec<RulesetEntry>`
//!   - `default-nameserver` 解析为 `Vec<SocketAddr>`（必须 IP 字面量）

use anyhow::{bail, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

// ============================================================
// IP 策略
// ============================================================

/// Controls which IP address families are queried and returned.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    /// Query both A and AAAA, return whatever the upstream returns (default).
    #[default]
    Default,
    /// Only query A records. AAAA queries receive an empty NOERROR response.
    OnlyIpv4,
    /// Only query AAAA records. A queries receive an empty NOERROR response.
    OnlyIpv6,
    /// Query both A and AAAA, but move A records before AAAA in the answer section.
    PreferIpv4,
    /// Query both A and AAAA, but move AAAA records before A in the answer section.
    PreferIpv6,
}

// ============================================================
// 日志等级
// ============================================================

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_filter(&self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

// ============================================================
// 上游选择策略
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    RoundRobin,
    Fastest,
}

// ============================================================
// 规范化后的上游组（router 用）
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamGroup {
    /// Server URLs: udp://, tcp://, tls://, https://, quic://, dhcp://iface,
    /// rcode://refused | nxdomain | servfail | succeed
    pub servers: Vec<String>,

    #[serde(default)]
    pub strategy: Strategy,

    /// 是否跳过 TLS 证书验证（DoT/DoH/DoQ）。默认 false。
    #[serde(default)]
    pub insecure: bool,

    /// EDNS Client Subnet (RFC 7871)，格式如 "1.2.3.0/24" 或 "2001:db8::/32"。
    #[serde(default)]
    pub client_subnet: Option<String>,
}

// ============================================================
// 规则集条目（规范化后）
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesetEntry {
    pub path: PathBuf,
    pub upstream: String,
}

// ============================================================
// 规范化后的 Config（router/run 用）
// ============================================================

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: LogLevel,
    pub listen: SocketAddr,
    pub manage_resolv_conf: bool,
    pub strategy: IpStrategy,

    /// 解析上游 DNS 服务器域名用的递归 DNS（已解析为 SocketAddr，UDP/53）。
    /// 空 Vec 表示用系统 resolver（仅 manage_resolv_conf=false 时安全）。
    pub default_nameserver: Vec<SocketAddr>,

    /// 所有上游组，包含 "default"（来自 nameserver）。
    pub groups: IndexMap<String, UpstreamGroup>,

    /// 规则集列表（按顺序匹配，首个命中生效）。
    pub rulesets: Vec<RulesetEntry>,

    pub hosts: IndexMap<String, std::net::IpAddr>,
    pub cache: CacheConfig,
    pub firewall: Option<FirewallConfig>,
    pub dhcp: DhcpConfig,
    pub web: WebConfig,
}

// ============================================================
// YAML 反序列化结构（用户写的格式）
// ============================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigYaml {
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,

    pub listen: SocketAddr,

    #[serde(default)]
    pub manage_resolv_conf: bool,

    #[serde(default)]
    pub strategy: IpStrategy,

    /// 解析上游 DNS 服务器域名用的递归 DNS。
    /// 必须是 IP 字面量（不带协议前缀），默认端口 53。
    #[serde(default)]
    pub default_nameserver: Vec<String>,

    /// 保底 DNS（走完 rules 后用）。简写：list of url；完整写法见 UpstreamGroupSerde。
    pub nameserver: UpstreamGroupSerde,

    /// 命名上游组（被 rulesets 引用）。
    /// 支持 String key 或 [a, b] 数组 key（展开为多个别名共享同一 group）。
    #[serde(default)]
    pub rules: IndexMap<RuleKey, UpstreamGroupSerde>,

    /// 域名规则集 → 上游组。
    /// 支持 map（1:1）或 list（多对一）两种写法。
    #[serde(default)]
    pub rulesets: RulesetsSerde,

    #[serde(default)]
    pub hosts: IndexMap<String, std::net::IpAddr>,

    #[serde(default)]
    pub cache: CacheConfig,

    pub firewall: Option<FirewallConfig>,

    #[serde(default)]
    pub dhcp: DhcpConfig,

    #[serde(default)]
    pub web: WebConfig,
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

/// 上游组的两种写法：简写（list of url）或完整对象。
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum UpstreamGroupSerde {
    Simple(Vec<String>),
    Full(UpstreamGroup),
}

impl UpstreamGroupSerde {
    fn into_group(self) -> Result<UpstreamGroup> {
        match self {
            UpstreamGroupSerde::Simple(servers) => Ok(UpstreamGroup {
                servers,
                strategy: Strategy::default(),
                insecure: false,
                client_subnet: None,
            }),
            UpstreamGroupSerde::Full(g) => Ok(g),
        }
    }
}

/// rules 的 key：单个名字或数组（多个别名）。
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum RuleKey {
    Single(String),
    Multi(Vec<String>),
}

/// rulesets 的两种写法：map（1:1）或 list（多对一）。
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RulesetsSerde {
    /// 简写：map of upstream_name → path
    Map(IndexMap<String, PathBuf>),
    /// 完整：list of {path, upstream}
    List(Vec<RulesetEntry>),
}

impl Default for RulesetsSerde {
    fn default() -> Self {
        RulesetsSerde::Map(IndexMap::new())
    }
}

// ============================================================
// Cache / Firewall 配置（不变）
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheConfig {
    #[serde(default = "default_cache_enable")]
    pub enable: bool,
    #[serde(default = "default_cache_size")]
    pub size: usize,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enable: true,
            size: 4096,
            min_ttl: 60,
            max_ttl: 86400,
        }
    }
}

fn default_cache_enable() -> bool {
    true
}
fn default_cache_size() -> usize {
    4096
}
fn default_min_ttl() -> u32 {
    60
}
fn default_max_ttl() -> u32 {
    86400
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirewallConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_true")]
    pub localhost_hijack: bool,
    #[serde(default)]
    pub lan_hijack: bool,
    pub lan_cidr: Option<String>,
    pub lan_interface: Option<String>,
}

fn default_backend() -> String {
    "auto".into()
}
fn default_true() -> bool {
    true
}

// ============================================================
// Config 加载与规范化
// ============================================================

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path.display(), e))?;
        let yaml: ConfigYaml = serde_yaml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Failed to parse YAML config: {}", e))?;
        let config = yaml.into_config()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // 必须有 "default" group（来自 nameserver）
        if !self.groups.contains_key("default") {
            bail!("Config must have 'nameserver' section (becomes default group)");
        }

        // resolv.conf 只支持 bare IP，manage-resolv-conf 仅在 port 53 时有效
        let port = self.listen.port();
        if self.manage_resolv_conf && port != 53 {
            bail!(
                "manage-resolv-conf=true requires listen port 53, \
                 because /etc/resolv.conf does not support custom ports. \
                 Listening on port {} — set manage-resolv-conf=false or change listen to port 53.",
                port
            );
        }

        // 如果启用 firewall + manage_resolv_conf，default_nameserver 不能为空
        // （否则上游域名无法解析，且系统 resolver 指向自己会循环）
        let firewall_enabled = self.firewall.as_ref().map(|f| f.enable).unwrap_or(false);
        if (firewall_enabled || self.manage_resolv_conf) && self.default_nameserver.is_empty() {
            // 检查是否有域名形式的上游
            let has_domain_upstream = self.groups.values().any(|g| {
                g.servers.iter().any(|s| {
                    s.starts_with("tls://") || s.starts_with("https://") || s.starts_with("quic://")
                }) && g.servers.iter().any(|s| {
                    let host = s.split("://").nth(1).unwrap_or("");
                    let host = host.split('/').next().unwrap_or("");
                    let host = host.split(':').next().unwrap_or("");
                    host.parse::<std::net::IpAddr>().is_err()
                })
            });
            if has_domain_upstream {
                bail!(
                    "default-nameserver is required when manage-resolv-conf or firewall is enabled \
                     and upstreams contain domain names (tls://, https://, quic://). \
                     Without it, resolving upstream domains would loop back to relay itself."
                );
            }
        }

        // 校验 rulesets 引用的 upstream 存在
        for entry in &self.rulesets {
            if !self.groups.contains_key(&entry.upstream) {
                bail!(
                    "ruleset '{}' references unknown upstream group '{}'",
                    entry.path.display(),
                    entry.upstream
                );
            }
        }

        // Web 面板：若启用 auth 必须提供 password_hash
        if self.web.enable && self.web.auth.enable {
            if self.web.auth.password_hash.is_empty() {
                bail!(
                    "web.auth.enable=true but web.auth.password-hash is empty. \
                     Generate one with: relay hash-password"
                );
            }
            if self.web.auth.username.is_empty() {
                bail!("web.auth.enable=true but web.auth.username is empty");
            }
        }
        if self.web.enable && self.web.query_log_size == 0 {
            bail!("web.query-log-size must be > 0");
        }

        Ok(())
    }
}

impl ConfigYaml {
    fn into_config(self) -> Result<Config> {
        // 1. default_nameserver 解析为 SocketAddr（必须 IP 字面量）
        let default_ns = self
            .default_nameserver
            .iter()
            .map(|s| parse_default_nameserver(s))
            .collect::<Result<Vec<_>>>()?;

        // 2. nameserver 转为 "default" group
        let default_group = self.nameserver.into_group()?;
        let mut groups = IndexMap::new();
        groups.insert("default".to_string(), default_group);

        // 3. rules 展开（数组 key → 多个 String key）
        for (key, group_serde) in self.rules {
            let group = group_serde.into_group()?;
            match key {
                RuleKey::Single(name) => {
                    if groups.contains_key(&name) {
                        bail!("duplicate upstream group name: {}", name);
                    }
                    groups.insert(name, group);
                }
                RuleKey::Multi(names) => {
                    if names.is_empty() {
                        bail!("rules has empty array key");
                    }
                    for name in names {
                        if groups.contains_key(&name) {
                            bail!("duplicate upstream group name: {}", name);
                        }
                        groups.insert(name.clone(), group.clone());
                    }
                }
            }
        }

        // 4. rulesets 规范化
        let rulesets = match self.rulesets {
            RulesetsSerde::Map(m) => m
                .into_iter()
                .map(|(upstream, path)| RulesetEntry { path, upstream })
                .collect(),
            RulesetsSerde::List(l) => l,
        };

        Ok(Config {
            log_level: self.log_level,
            listen: self.listen,
            manage_resolv_conf: self.manage_resolv_conf,
            strategy: self.strategy,
            default_nameserver: default_ns,
            groups,
            rulesets,
            hosts: self.hosts,
            cache: self.cache,
            firewall: self.firewall,
            dhcp: self.dhcp,
            web: self.web,
        })
    }
}

/// 解析 default-nameserver 条目。
///
/// 必须是 IP 字面量（不带协议前缀），默认端口 53。
/// 域名形式被拒绝（否则又陷入循环依赖）。
fn parse_default_nameserver(s: &str) -> Result<SocketAddr> {
    if s.contains("://") {
        bail!(
            "default-nameserver entry must be plain IP, got '{}' (protocol prefix not allowed)",
            s
        );
    }
    // 尝试解析为 SocketAddr 或 IpAddr
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    bail!(
        "default-nameserver entry must be IP literal, got '{}' (domain names are not allowed here)",
        s
    )
}

// ============================================================
// Web 面板配置
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WebConfig {
    #[serde(default)]
    pub enable: bool,

    /// HTTP 监听地址，如 "127.0.0.1:8080" 或 "0.0.0.0:8080"。
    #[serde(default = "default_web_listen")]
    pub listen: SocketAddr,

    /// 查询日志 ring buffer 容量（内存中保留的最近查询条数）。
    #[serde(default = "default_query_log_size")]
    pub query_log_size: usize,

    /// SQLite 数据库路径（持久化统计与查询日志）。
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: PathBuf,

    /// 静态资源目录（可选）。若设置则从该目录读取前端文件；
    /// 若未设置则用内嵌资源（include_dir!）。
    pub web_dir: Option<PathBuf>,

    #[serde(default)]
    pub auth: WebAuthConfig,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: default_web_listen(),
            query_log_size: default_query_log_size(),
            sqlite_path: default_sqlite_path(),
            web_dir: None,
            auth: WebAuthConfig::default(),
        }
    }
}

fn default_web_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
fn default_query_log_size() -> usize {
    5000
}
fn default_sqlite_path() -> PathBuf {
    PathBuf::from("/var/lib/relay/stats.db")
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct WebAuthConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_web_username")]
    pub username: String,
    /// bcrypt 哈希（推荐用 `relay hash-password` 生成）。
    /// 若为空且 enable=true，启动时拒绝启动并提示。
    #[serde(default)]
    pub password_hash: String,
}

fn default_web_username() -> String {
    "admin".to_string()
}

// ============================================================
// DHCP 配置（不变）
// ============================================================

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpConfig {
    pub v4: Option<DhcpV4Config>,
    pub v6: Option<DhcpV6Config>,
    pub ra: Option<RaConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpV4Config {
    #[serde(default)]
    pub enable: bool,
    pub interface: String,
    pub range: [std::net::Ipv4Addr; 2],
    #[serde(default = "default_lease_time")]
    pub lease_time: String,
    #[serde(default = "default_subnet")]
    pub subnet: std::net::Ipv4Addr,
    pub gateway: std::net::Ipv4Addr,
    pub dns: Vec<std::net::Ipv4Addr>,
    pub domain: Option<String>,
    #[serde(default = "default_v4_lease_file")]
    pub lease_file: String,
    #[serde(default = "default_true")]
    pub arp_probe: bool,
    #[serde(default)]
    pub static_leases: Vec<StaticLease>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StaticLease {
    pub mac: String,
    pub ip: std::net::Ipv4Addr,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DhcpV6Config {
    #[serde(default)]
    pub enable: bool,
    pub interface: String,
    #[serde(default = "default_v6_mode")]
    pub mode: DhcpV6Mode,
    pub prefix: Option<String>,
    pub dns: Vec<std::net::Ipv6Addr>,
    pub domain: Option<String>,
    #[serde(default = "default_v6_lease_file")]
    pub lease_file: String,
    #[serde(default = "default_lease_time")]
    pub lease_time: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DhcpV6Mode {
    #[default]
    Stateless,
    Stateful,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RaConfig {
    #[serde(default)]
    pub enable: bool,
    pub interface: String,
    #[serde(default = "default_ra_preference")]
    pub preference: String,
    #[serde(default = "default_ra_interval")]
    pub interval: u32,
    #[serde(default)]
    pub managed: bool,
    #[serde(default = "default_true")]
    pub other: bool,
    #[serde(default = "default_router_lifetime")]
    pub router_lifetime: u16,
    pub rdnss: Vec<std::net::Ipv6Addr>,
    #[serde(default = "default_router_lifetime")]
    pub dns_lifetime: u16,
    #[serde(default)]
    pub suppress_other_routers: bool,
}

fn default_lease_time() -> String {
    "24h".into()
}
fn default_subnet() -> std::net::Ipv4Addr {
    "255.255.255.0".parse().unwrap()
}
fn default_v4_lease_file() -> String {
    "/var/lib/relay/dhcp4.leases".into()
}
fn default_v6_lease_file() -> String {
    "/var/lib/relay/dhcp6.leases".into()
}
fn default_v6_mode() -> DhcpV6Mode {
    DhcpV6Mode::Stateless
}
fn default_ra_preference() -> String {
    "high".into()
}
fn default_ra_interval() -> u32 {
    30
}
fn default_router_lifetime() -> u16 {
    1800
}
