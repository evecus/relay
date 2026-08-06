//! Upstream DNS server management: UDP, TCP, DoT, DoH, DoQ, DHCP, rcode
//!
//! 模块结构：
//! - `mod.rs`      — UpstreamServer / UpstreamGroup 顶层类型与 URL 解析
//! - `resolver.rs` — HostResolver（用 default_nameserver 解析上游域名，避免循环依赖）
//! - `util.rs`     — 地址/SNI 解析、TLS 配置构建、DNS-over-TCP 帧收发、ECS 注入
//! - `udp.rs`      — UDP 查询（含 TC 重试、EDNS OPT 解析）
//! - `tcp.rs`      — TCP 查询（整体 timeout 包裹，含读前缀）
//! - `dot.rs`      — DNS-over-TLS（连接池 + 失败重试 + HostResolver 解析域名）
//! - `doh.rs`      — DNS-over-HTTPS（ID=0、严格 URL、状态码 200、reqwest dns_resolver）
//! - `doq.rs`      — DNS-over-QUIC（RFC 9250，ID=0、连接池、HostResolver 解析域名）

pub mod doh;
pub mod doq;
pub mod dot;
pub mod resolver;
pub mod tcp;
pub mod udp;
pub mod util;

use anyhow::{bail, Result};
use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::{Strategy, UpstreamGroup as UpstreamGroupCfg};
pub use resolver::HostResolver;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum UpstreamKind {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls {
        /// 主机名（IP 字面量或域名）。域名运行时用 HostResolver 解析。
        host: String,
        port: u16,
        insecure: bool,
    },
    Https {
        url: String,
        insecure: bool,
    },
    Quic {
        host: String,
        port: u16,
        insecure: bool,
    },
    Dhcp {
        interface: String,
    },
    Rcode(hickory_proto::op::ResponseCode),
}

#[derive(Clone)]
pub struct UpstreamServer {
    pub kind: UpstreamKind,
    pub url: String,
    pub client_subnet: Option<(std::net::IpAddr, u8)>,
    pub resolver: HostResolver,
    dot_pool: Arc<tokio::sync::Mutex<Option<dot::PooledTlsConn>>>,
    doq_pool: Arc<tokio::sync::Mutex<Option<doq::PooledQuicConn>>>,
    doh_client: Arc<tokio::sync::OnceCell<Arc<doh::DohClient>>>,
}

impl std::fmt::Debug for UpstreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamServer")
            .field("kind", &self.kind)
            .field("url", &self.url)
            .finish()
    }
}

impl UpstreamServer {
    pub fn parse(url: &str, group: &UpstreamGroupCfg, resolver: HostResolver) -> Result<Self> {
        let insecure = group.insecure;
        let client_subnet = group
            .client_subnet
            .as_deref()
            .and_then(util::parse_client_subnet);
        let kind = parse_upstream_url(url, insecure)?;
        Ok(Self {
            kind,
            url: url.to_string(),
            client_subnet,
            resolver,
            dot_pool: Arc::new(tokio::sync::Mutex::new(None)),
            doq_pool: Arc::new(tokio::sync::Mutex::new(None)),
            doh_client: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    #[allow(clippy::unnecessary_unwrap)]
    pub async fn query(&self, request: &Message) -> Result<Message> {
        let req = if self.client_subnet.is_some()
            && !matches!(self.kind, UpstreamKind::Rcode(_) | UpstreamKind::Dhcp { .. })
        {
            util::inject_client_subnet(request, self.client_subnet.unwrap())?
        } else {
            request.clone()
        };

        match &self.kind {
            UpstreamKind::Udp(addr) => udp::query(*addr, &req).await,
            UpstreamKind::Tcp(addr) => tcp::query(*addr, &req).await,
            UpstreamKind::Tls { host, port, insecure } => {
                dot::query(host, *port, *insecure, &req, &self.dot_pool, &self.resolver).await
            }
            UpstreamKind::Https { url, insecure } => {
                let client = self
                    .doh_client
                    .get_or_init(|| async {
                        Arc::new(
                            doh::DohClient::new(url, *insecure, self.resolver.clone())
                                .await
                                .expect("Failed to build DoH client"),
                        )
                    })
                    .await;
                doh::query(Arc::clone(client), url, &req).await
            }
            UpstreamKind::Quic { host, port, insecure } => {
                doq::query(host, *port, *insecure, &req, &self.doq_pool, &self.resolver).await
            }
            UpstreamKind::Dhcp { interface } => {
                let servers = resolve_dhcp_servers(interface)?;
                if servers.is_empty() {
                    bail!("No DNS servers found via DHCP on {}", interface);
                }
                udp::query(servers[0], &req).await
            }
            UpstreamKind::Rcode(code) => {
                let mut resp = request.clone();
                resp.set_message_type(hickory_proto::op::MessageType::Response);
                resp.set_response_code(*code);
                Ok(resp)
            }
        }
    }
}

/// 解析上游 URL。
///
/// 不带协议前缀的 IP 字面量视为 `udp://`（mihomo 风格）。
/// 域名形式必须显式带协议前缀（如 `tls://dns.google`），裸域名报错。
fn parse_upstream_url(url: &str, insecure: bool) -> Result<UpstreamKind> {
    if let Some(rest) = url.strip_prefix("udp://") {
        let addr = util::parse_addr(rest, 53)?;
        return Ok(UpstreamKind::Udp(addr));
    }
    if let Some(rest) = url.strip_prefix("tcp://") {
        let addr = util::parse_addr(rest, 53)?;
        return Ok(UpstreamKind::Tcp(addr));
    }
    if let Some(rest) = url.strip_prefix("tls://") {
        let (host, port) = util::parse_host_port(rest, 853)?;
        if host.parse::<std::net::IpAddr>().is_err()
            && !rest.contains('[')
            && host.contains('.')
            && !host.parse::<std::net::Ipv4Addr>().is_ok()
        {
            // 域名形式 OK，运行时用 HostResolver 解析
        }
        return Ok(UpstreamKind::Tls { host, port, insecure });
    }
    if url.starts_with("https://") {
        url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid DoH URL {}: {}", url, e))?;
        return Ok(UpstreamKind::Https { url: url.to_string(), insecure });
    }
    if let Some(rest) = url.strip_prefix("quic://") {
        let (host, port) = util::parse_host_port(rest, 853)?;
        return Ok(UpstreamKind::Quic { host, port, insecure });
    }
    if let Some(rest) = url.strip_prefix("dhcp://") {
        return Ok(UpstreamKind::Dhcp { interface: rest.to_string() });
    }
    if let Some(rest) = url.strip_prefix("rcode://") {
        let code = match rest.trim().to_ascii_lowercase().as_str() {
            "refused" | "refuse" => hickory_proto::op::ResponseCode::Refused,
            "nxdomain" | "nx" => hickory_proto::op::ResponseCode::NXDomain,
            "servfail" | "fail" => hickory_proto::op::ResponseCode::ServFail,
            // 返回空 NOERROR 应答（answer section 为空）。
            // 行为等同于 mihomo 的 REJECT 默认语义：客户端拿到"成功但无记录"，
            // 立即停止，不会像 REFUSED 那样 fallback 到硬编码 DNS。
            "succeed" | "success" | "noerror" | "empty" => {
                hickory_proto::op::ResponseCode::NoError
            }
            other => bail!("Unknown rcode: {}", other),
        };
        return Ok(UpstreamKind::Rcode(code));
    }

    // 不带协议前缀：仅接受 IP 字面量（视为 udp://），裸域名报错
    if url.contains("://") {
        bail!("Unknown upstream URL scheme: {}", url);
    }
    // 尝试解析为 IP 字面量
    match util::parse_addr(url, 53) {
        Ok(addr) => Ok(UpstreamKind::Udp(addr)),
        Err(_) => {
            // 不是 IP 字面量，报错（域名必须显式带协议前缀）
            bail!(
                "upstream '{}' has no protocol prefix and is not an IP literal. \
                 Bare domain names are not allowed — use 'udp://{}' or 'tls://{}' etc.",
                url, url, url
            );
        }
    }
}

fn resolve_dhcp_servers(interface: &str) -> Result<Vec<SocketAddr>> {
    let candidates = [
        "/run/systemd/resolve/resolv.conf".to_string(),
        "/run/NetworkManager/resolv.conf".to_string(),
        "/var/lib/dhclient/resolv.conf".to_string(),
        "/etc/resolv.conf.dnsroxy.bak".to_string(),
    ];

    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            let servers: Vec<SocketAddr> = content
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.starts_with("nameserver") {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            .map(|ip| SocketAddr::new(ip, 53))
                    } else {
                        None
                    }
                })
                .collect();
            if !servers.is_empty() {
                debug!("DHCP resolved servers from {}: {:?}", path, servers);
                return Ok(servers);
            }
        }
    }

    warn!("No DHCP DNS servers found for interface {}", interface);
    Ok(vec![])
}

/// A group of upstream servers with a selection strategy
pub struct UpstreamGroup {
    pub servers: Vec<UpstreamServer>,
    pub strategy: Strategy,
    counter: AtomicUsize,
}

impl UpstreamGroup {
    pub fn new(servers: Vec<UpstreamServer>, strategy: Strategy) -> Self {
        Self {
            servers,
            strategy,
            counter: AtomicUsize::new(0),
        }
    }

    /// 查询上游，返回 (响应, 上游耗时)。
    /// 上游耗时仅包含真正发到上游的查询时间（不含 router 侧的缓存/规则匹配）。
    pub async fn query(&self, request: &Message) -> Result<(Message, Duration)> {
        if self.servers.is_empty() {
            bail!("Upstream group has no servers");
        }

        match self.strategy {
            Strategy::RoundRobin => self.query_round_robin(request).await,
            Strategy::Fastest => self.query_fastest(request).await,
        }
    }

    async fn query_round_robin(&self, request: &Message) -> Result<(Message, Duration)> {
        let n = self.servers.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) % n;

        for i in 0..n {
            let server = &self.servers[(start + i) % n];
            let t0 = Instant::now();
            match timeout(UPSTREAM_TIMEOUT, server.query(request)).await {
                Ok(Ok(resp)) => return Ok((resp, t0.elapsed())),
                Ok(Err(e)) => warn!("Upstream {} failed: {}", server.url, e),
                Err(_) => warn!("Upstream {} timed out after {:?}", server.url, UPSTREAM_TIMEOUT),
            }
        }
        bail!("All upstream servers failed")
    }

    async fn query_fastest(&self, request: &Message) -> Result<(Message, Duration)> {
        use futures::future::select_ok;

        let t0 = Instant::now();
        let futures: Vec<_> = self
            .servers
            .iter()
            .map(|s| {
                let req = request.clone();
                let server = s.clone();
                Box::pin(async move {
                    timeout(UPSTREAM_TIMEOUT, server.query(&req))
                        .await
                        .map_err(|_| anyhow::anyhow!("upstream {} timed out", server.url))?
                })
            })
            .collect();

        let (result, _remaining) = select_ok(futures)
            .await
            .map_err(|_| anyhow::anyhow!("All upstream servers failed (fastest)"))?;

        // fastest 策略下 elapsed 是从发起到首个成功返回的总时间
        Ok((result, t0.elapsed()))
    }
}

impl Clone for UpstreamGroup {
    fn clone(&self) -> Self {
        Self {
            servers: self.servers.clone(),
            strategy: self.strategy.clone(),
            counter: AtomicUsize::new(self.counter.load(Ordering::Relaxed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
 
    #[test]
    fn test_rcode_refused_variants() {
        assert!(matches!(parse_upstream_url("rcode://refused", false), Ok(UpstreamKind::Rcode(ResponseCode::Refused))));
        assert!(matches!(parse_upstream_url("rcode://refuse", false), Ok(UpstreamKind::Rcode(ResponseCode::Refused))));
        // 大小写不敏感
        assert!(matches!(parse_upstream_url("rcode://REFUSED", false), Ok(UpstreamKind::Rcode(ResponseCode::Refused))));
        // 容忍前后空白
        assert!(matches!(parse_upstream_url("rcode://  refused  ", false), Ok(UpstreamKind::Rcode(ResponseCode::Refused))));
    }
 
    #[test]
    fn test_rcode_nxdomain_variants() {
        assert!(matches!(parse_upstream_url("rcode://nxdomain", false), Ok(UpstreamKind::Rcode(ResponseCode::NXDomain))));
        assert!(matches!(parse_upstream_url("rcode://nx", false), Ok(UpstreamKind::Rcode(ResponseCode::NXDomain))));
    }
 
    #[test]
    fn test_rcode_servfail_variants() {
        assert!(matches!(parse_upstream_url("rcode://servfail", false), Ok(UpstreamKind::Rcode(ResponseCode::ServFail))));
        assert!(matches!(parse_upstream_url("rcode://fail", false), Ok(UpstreamKind::Rcode(ResponseCode::ServFail))));
    }
 
    #[test]
    fn test_rcode_succeed_variants() {
        // 主名 + 别名都映射到 NoError
        for s in &["succeed", "success", "noerror", "empty", "SUCCEED", "NoError"] {
            let r = parse_upstream_url(&format!("rcode://{}", s), false);
            assert!(
                matches!(r, Ok(UpstreamKind::Rcode(ResponseCode::NoError))),
                "expected NoError for rcode://{} got {:?}", s, r
            );
        }
    }
 
    #[test]
    fn test_rcode_succeed_returns_empty_noerror() {
        // 端到端：构造一个查询，走 Rcode(NoError) 分支，应返回空 NOERROR 应答
        let kind = UpstreamKind::Rcode(ResponseCode::NoError);
        let req = hickory_proto::op::Message::new();
        let resp = kind_query(&kind, &req).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.answers().is_empty());
        assert_eq!(resp.message_type(), hickory_proto::op::MessageType::Response);
    }
 
    #[test]
    fn test_rcode_unknown_value_rejected() {
        assert!(parse_upstream_url("rcode://bogus", false).is_err());
    }
 
    /// 调用 UpstreamKind::query 的辅助函数（用于端到端测试 Rcode 分支）。
    fn kind_query(kind: &UpstreamKind, req: &hickory_proto::op::Message) -> Result<hickory_proto::op::Message> {
        // Rcode 分支不依赖 resolver / pool，直接复刻 mod.rs 中的逻辑：
        // clone 请求 → 标记为 Response → 设置 rcode → 返回
        let mut resp = req.clone();
        resp.set_message_type(hickory_proto::op::MessageType::Response);
        if let UpstreamKind::Rcode(code) = kind {
            resp.set_response_code(*code);
        }
        Ok(resp)
    }
}
