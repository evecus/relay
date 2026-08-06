//! DNS-over-QUIC upstream (RFC 9250)。
//!
//! DoQ 上游的 host 可以是 IP 字面量或域名。域名在运行时用 HostResolver
//! 解析（用 default_nameserver，避免循环依赖），结果缓存复用。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

use super::resolver::HostResolver;
use super::util;

const DOQ_TIMEOUT: Duration = Duration::from_secs(5);
const DOQ_ALPN: &[u8] = b"doq";

/// 复用的 QUIC 连接。
pub type PooledQuicConn = Connection;

pub async fn query(
    host: &str,
    port: u16,
    insecure: bool,
    request: &Message,
    pool: &Arc<tokio::sync::Mutex<Option<PooledQuicConn>>>,
    resolver: &HostResolver,
) -> Result<Message> {
    let original_id = request.id();
    // RFC 9250 §4.2: Query ID 必须为 0
    let mut req_to_send = request.clone();
    req_to_send.set_id(0);
    let wire = req_to_send.to_vec()?;

    // 先尝试用池里的连接
    if let Some(conn) = pool.lock().await.take() {
        match timeout(DOQ_TIMEOUT, query_with_conn(&conn, &wire)).await {
            Ok(Ok(resp_bytes)) => {
                let mut guard = pool.lock().await;
                *guard = Some(conn);
                let mut msg = Message::from_bytes(&resp_bytes)
                    .context("Failed to parse DoQ DNS response")?;
                msg.set_id(original_id);
                return Ok(msg);
            }
            Ok(Err(e)) => debug!("DoQ pooled conn failed, will rebuild: {}", e),
            Err(_) => debug!("DoQ pooled conn timed out, will rebuild"),
        }
    }

    // 运行时解析域名为 SocketAddr
    let addr = resolver.resolve_socket_addr(host, port).await?;

    // 建立新连接并查询
    let (resp_bytes, conn) = timeout(DOQ_TIMEOUT, async {
        let conn = connect(addr, host, insecure).await?;
        let resp_bytes = query_with_conn(&conn, &wire).await?;
        Ok::<_, anyhow::Error>((resp_bytes, conn))
    })
    .await
    .context("DoQ exchange timed out")??;

    // 放回池
    let mut guard = pool.lock().await;
    *guard = Some(conn);

    let mut msg = Message::from_bytes(&resp_bytes).context("Failed to parse DoQ DNS response")?;
    msg.set_id(original_id);
    Ok(msg)
}

async fn query_with_conn(conn: &Connection, wire: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.context("DoQ open_bi failed")?;

    use tokio::io::AsyncReadExt;
    // 2 字节长度前缀
    let len = wire.len() as u16;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(wire).await?;
    // quinn 0.11 SendStream::finish 返回 Result<(), ClosedStream>，不是 Future
    send.finish()?;

    let resp_len = recv.read_u16().await? as usize;
    if resp_len < 12 {
        anyhow::bail!("DoQ response too short: {}", resp_len);
    }
    let mut buf = vec![0u8; resp_len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn connect(addr: SocketAddr, hostname: &str, insecure: bool) -> Result<Connection> {
    // 构建 rustls ClientConfig，附加 ALPN=doq
    let cfg = util::build_rustls_client_config(insecure)?;
    let mut rustls_cfg = (*cfg).clone();
    rustls_cfg.alpn_protocols = vec![DOQ_ALPN.to_vec()];

    // quinn 0.11 需要用 QuicClientConfig 包装 rustls::ClientConfig
    let quic_cfg = ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .context("Failed to build QuicClientConfig")?,
    ));

    // 绑定本地端点
    let bind: SocketAddr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let mut endpoint = Endpoint::client(bind).context("Failed to bind QUIC client endpoint")?;
    endpoint.set_default_client_config(quic_cfg);

    // quinn 0.11 connect 接受 server_name: &str
    // IP 字符串会被识别为 IpAddress SAN，域名为 DNS name SNI
    let conn = endpoint
        .connect(addr, hostname)
        .map_err(|e| anyhow::anyhow!("QUIC connect error: {}", e))?
        .await
        .context("DoQ QUIC connect failed")?;

    Ok(conn)
}
