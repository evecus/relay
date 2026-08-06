//! HostResolver：用 default_nameserver 解析上游域名（lazy + 缓存）。
//!
//! 解决循环依赖问题：relay 接管 /etc/resolv.conf 后，系统 resolver 指向
//! 127.0.0.1:53（relay 自己）。如果上游是 `tls://dns.google`，用系统
//! resolver 解析 dns.google 会查到 relay，relay 又要查 dns.google，
//! 形成无限循环。
//!
//! HostResolver 直接用 default_nameserver（UDP/53 IP 字面量）发 DNS 查询，
//! 绕过系统 resolver，避免循环。结果缓存在进程级 HashMap 中。
//!
//! 同时实现 `reqwest::dns::Resolve` trait，让 DoH 的 reqwest::Client 也用
//! default_nameserver 解析域名，而不是系统 resolver。

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_TTL: Duration = Duration::from_secs(300); // 缓存 5 分钟

#[derive(Clone)]
pub struct HostResolver {
    default_ns: Vec<SocketAddr>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[derive(Clone)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    inserted_at: std::time::Instant,
}

impl HostResolver {
    pub fn new(default_ns: Vec<SocketAddr>) -> Self {
        Self {
            default_ns,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 解析 host 为 IP 列表。
    ///
    /// - IP 字面量直接返回单元素列表
    /// - 域名先查缓存（未过期），未命中则用 default_nameserver 查 A/AAAA
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        // IP 字面量直接返回
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // 查缓存
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(host) {
                if entry.inserted_at.elapsed() < CACHE_TTL {
                    debug!("host resolver cache hit: {} → {:?}", host, entry.addrs);
                    return Ok(entry.addrs.clone());
                }
            }
        }

        if self.default_ns.is_empty() {
            anyhow::bail!(
                "cannot resolve '{}': no default-nameserver configured \
                 (required when upstreams use domain names)",
                host
            );
        }

        // 用 default_nameserver 查询
        for ns in &self.default_ns {
            match query_a_aaaa(*ns, host).await {
                Ok(ips) if !ips.is_empty() => {
                    debug!("resolved {} via {}: {:?}", host, ns, ips);
                    let mut cache = self.cache.lock().await;
                    cache.insert(
                        host.to_string(),
                        CacheEntry {
                            addrs: ips.clone(),
                            inserted_at: std::time::Instant::now(),
                        },
                    );
                    return Ok(ips);
                }
                Ok(_) => debug!("resolve {} via {} returned no answers", host, ns),
                Err(e) => warn!("resolve {} via {} failed: {}", host, ns, e),
            }
        }

        anyhow::bail!("failed to resolve host '{}' via all default-nameserver entries", host)
    }

    /// 解析 host 为单个 SocketAddr（取第一个 IP + 指定 port）。
    pub async fn resolve_socket_addr(&self, host: &str, port: u16) -> Result<SocketAddr> {
        let ips = self.resolve(host).await?;
        let ip = ips
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve {} returned empty IP list", host))?;
        Ok(SocketAddr::new(ip, port))
    }
}

/// 用 UDP/53 查询 A + AAAA 记录。
async fn query_a_aaaa(ns: SocketAddr, host: &str) -> Result<Vec<IpAddr>> {
    let name = Name::from_ascii(host)?;
    let mut ips = Vec::new();

    // 查 A
    if let Ok(a_ips) = query_record(ns, name.clone(), RecordType::A).await {
        ips.extend(a_ips);
    }
    // 查 AAAA
    if let Ok(aaaa_ips) = query_record(ns, name, RecordType::AAAA).await {
        ips.extend(aaaa_ips);
    }

    Ok(ips)
}

/// DNS 查询 ID 计数器（避免引入 rand 依赖）。
static QUERY_ID: AtomicU16 = AtomicU16::new(0);

/// 发单个 DNS 查询，返回 IP 列表。
async fn query_record(ns: SocketAddr, name: Name, rtype: RecordType) -> Result<Vec<IpAddr>> {
    let mut query = Query::query(name, rtype);
    query.set_query_class(hickory_proto::rr::DNSClass::IN);

    let mut msg = Message::new();
    msg.set_id(QUERY_ID.fetch_add(1, Ordering::Relaxed));
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.add_query(query);

    let wire = msg.to_vec()?;

    let bind = match ns {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("Failed to bind UDP for host resolution")?;
    socket.connect(ns).await?;
    socket.send(&wire).await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(RESOLVE_TIMEOUT, socket.recv(&mut buf))
        .await
        .context("host resolve UDP recv timed out")??;

    let resp = Message::from_bytes(&buf[..n])?;
    let ips: Vec<IpAddr> = resp
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
            Some(RData::AAAA(aaaa)) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect();

    Ok(ips)
}

// ============================================================
// reqwest::dns::Resolve 实现（让 DoH 的 reqwest::Client 用 default_nameserver）
// ============================================================

impl reqwest::dns::Resolve for HostResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = self.clone();
        Box::pin(async move {
            let host = name.as_str();
            match this.resolve(host).await {
                Ok(ips) => {
                    // reqwest 0.12 期望 Iterator<Item = SocketAddr>。
                    // port=0 会被 reqwest 替换为 scheme 默认端口（https→443）。
                    let iter: Box<dyn Iterator<Item = SocketAddr> + Send> =
                        Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
                    Ok(iter)
                }
                Err(e) => {
                    let err: Box<dyn std::error::Error + Send + Sync> =
                        Box::new(std::io::Error::other(e.to_string()));
                    Err(err)
                }
            }
        })
    }
}
