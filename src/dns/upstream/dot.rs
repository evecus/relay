//! DNS-over-TLS upstream。
//!
//! DoT 上游的 host 可以是 IP 字面量或域名。域名在运行时用 HostResolver
//! 解析（用 default_nameserver，避免循环依赖），结果缓存复用。
//!
//! SNI 用 host 原文：IP 字面量 → IP SAN，域名 → 域名 SNI。
//!
//! ## 连接池设计
//!
//! 旧实现只维护单条 TLS 连接（`Option<TlsConn>`），并发查询时后来者拿不到
//! 池里的连接会额外新建一条，用完后两者互相抢着放回池子，多余的连接被直接
//! 丢弃关闭——高并发下连接池形同虚设，且反复握手开销大。
//!
//! 现在改为容量有限的连接池（`Vec` + 信号量控制并发）：
//! - 池中最多保留 `POOL_CAPACITY` 条空闲连接，取用时优先复用，没有空闲
//!   连接才新建。
//! - 一条连接同一时刻只服务一个查询（不做 DoT pipelining，避免引入按
//!   query ID 匹配响应的复杂状态机），但允许多条连接并发工作，从根本上
//!   解决"同时只有一条连接"的瓶颈。
//! - 新建连接失败会重试一次（区分"复用连接失败重建"与"新建连接失败"两种
//!   路径，避免无限重试风暴）。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use super::resolver::HostResolver;
use super::util;

/// 复用连接时的超时：连接已建立，只需一次 TCP 帧收发，可以给较紧的超时。
const DOT_REUSE_TIMEOUT: Duration = Duration::from_secs(3);
/// 新建连接时的超时：包含 TCP 连接 + TLS 握手 + 一次帧收发，给更宽松的超时。
const DOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 连接池最多保留的空闲连接数。
const POOL_CAPACITY: usize = 8;

type TlsConn = tokio_rustls::client::TlsStream<TcpStream>;

/// 每个上游一个连接池实例，`UpstreamServer` 持有 `Arc<DotPool>`。
pub struct DotPool {
    idle: Mutex<VecDeque<TlsConn>>,
    /// 限制同时在用的连接数（含新建中的），避免瞬时高并发下无限制建连。
    permits: Semaphore,
}

impl DotPool {
    pub fn new() -> Self {
        Self {
            idle: Mutex::new(VecDeque::with_capacity(POOL_CAPACITY)),
            permits: Semaphore::new(POOL_CAPACITY),
        }
    }
}

impl Default for DotPool {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn query(
    host: &str,
    port: u16,
    insecure: bool,
    request: &Message,
    pool: &Arc<DotPool>,
    resolver: &HostResolver,
) -> Result<Message> {
    let wire = request.to_vec()?;

    // 首次调用时把阻塞的证书加载挪到 spawn_blocking 完成，之后的调用直接
    // 命中缓存（几乎零开销），不会再阻塞 tokio 工作线程。
    util::ensure_tls_config_ready().await;

    // 限制并发在用连接数：拿不到许可证就排队等，而不是无限制建连。
    let _permit = pool
        .permits
        .acquire()
        .await
        .context("DoT connection pool closed")?;

    // 优先复用空闲连接。
    if let Some(mut conn) = pool.idle.lock().await.pop_front() {
        match timeout(DOT_REUSE_TIMEOUT, util::tcp_framed_exchange(&mut conn, &wire)).await {
            Ok(Ok(resp_bytes)) => {
                put_back(pool, conn).await;
                return Message::from_bytes(&resp_bytes)
                    .context("Failed to parse DoT DNS response");
            }
            Ok(Err(e)) => debug!("DoT pooled conn failed, will rebuild: {}", e),
            Err(_) => debug!("DoT pooled conn timed out, will rebuild"),
        }
        // 复用失败：连接已不可用，直接丢弃（不放回池），下面走新建连接路径。
    }

    // 新建连接并查询，失败重试一次（例如偶发 TCP RST / 握手瞬时失败）。
    let mut last_err = None;
    for attempt in 0..2 {
        match connect_and_exchange(host, port, insecure, &wire, resolver).await {
            Ok((resp_bytes, conn)) => {
                put_back(pool, conn).await;
                return Message::from_bytes(&resp_bytes)
                    .context("Failed to parse DoT DNS response");
            }
            Err(e) => {
                debug!("DoT new connection attempt {} failed: {}", attempt + 1, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoT query failed with no error recorded")))
}

async fn connect_and_exchange(
    host: &str,
    port: u16,
    insecure: bool,
    wire: &[u8],
    resolver: &HostResolver,
) -> Result<(Vec<u8>, TlsConn)> {
    let cfg = util::build_rustls_client_config(insecure)?;
    let connector = TlsConnector::from(cfg);

    // SNI 用 host 原文（IP 字面量 → IpAddress，域名 → DNS name）
    let server_name: ServerName<'static> = if let Ok(std_ip) = host.parse::<std::net::IpAddr>() {
        let ip: rustls::pki_types::IpAddr = std_ip.into();
        ServerName::IpAddress(ip)
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|e| anyhow::anyhow!("invalid SNI '{}': {}", host, e))?
    };

    // 运行时解析域名为 SocketAddr（lazy + 缓存）
    let addr = resolver.resolve_socket_addr(host, port).await?;

    timeout(DOT_CONNECT_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await.context("DoT TCP connect failed")?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .context("DoT TLS handshake failed")?;
        let resp_bytes = util::tcp_framed_exchange(&mut tls, wire).await?;
        Ok::<_, anyhow::Error>((resp_bytes, tls))
    })
    .await
    .context("DoT exchange timed out")?
}

/// 把用完的连接放回空闲池；若池已满则直接丢弃（让其 Drop 自然关闭）。
async fn put_back(pool: &Arc<DotPool>, conn: TlsConn) {
    let mut idle = pool.idle.lock().await;
    if idle.len() < POOL_CAPACITY {
        idle.push_back(conn);
    }
    // 否则 conn 在此处被 drop，TLS 连接自然关闭。
}
