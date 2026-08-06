//! DNS-over-TLS upstream。
//!
//! DoT 上游的 host 可以是 IP 字面量或域名。域名在运行时用 HostResolver
//! 解析（用 default_nameserver，避免循环依赖），结果缓存复用。
//!
//! SNI 用 host 原文：IP 字面量 → IP SAN，域名 → 域名 SNI。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use super::resolver::HostResolver;
use super::util;

const DOT_TIMEOUT: Duration = Duration::from_secs(5);

/// 复用的 TLS 连接（take/put 模式）。
pub type PooledTlsConn = tokio_rustls::client::TlsStream<TcpStream>;

pub async fn query(
    host: &str,
    port: u16,
    insecure: bool,
    request: &Message,
    pool: &Arc<tokio::sync::Mutex<Option<PooledTlsConn>>>,
    resolver: &HostResolver,
) -> Result<Message> {
    let wire = request.to_vec()?;
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

    // 先尝试用池里的连接
    if let Some(mut conn) = pool.lock().await.take() {
        match timeout(DOT_TIMEOUT, util::tcp_framed_exchange(&mut conn, &wire)).await {
            Ok(Ok(resp_bytes)) => {
                let mut guard = pool.lock().await;
                *guard = Some(conn);
                return Message::from_bytes(&resp_bytes)
                    .context("Failed to parse DoT DNS response");
            }
            Ok(Err(e)) => debug!("DoT pooled conn failed, will rebuild: {}", e),
            Err(_) => debug!("DoT pooled conn timed out, will rebuild"),
        }
    }

    // 运行时解析域名为 SocketAddr（lazy + 缓存）
    let addr = resolver.resolve_socket_addr(host, port).await?;

    // 建立新连接并查询
    let (resp_bytes, conn) = timeout(DOT_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await.context("DoT TCP connect failed")?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .context("DoT TLS handshake failed")?;
        let resp_bytes = util::tcp_framed_exchange(&mut tls, &wire).await?;
        Ok::<_, anyhow::Error>((resp_bytes, tls))
    })
    .await
    .context("DoT exchange timed out")??;

    // 放回池供下次复用
    let mut guard = pool.lock().await;
    *guard = Some(conn);

    Message::from_bytes(&resp_bytes).context("Failed to parse DoT DNS response")
}
