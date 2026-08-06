//! UDP and TCP DNS listeners

use crate::dns::router::Router;
use crate::stats::{QueryEntry, StatsCollector};
use anyhow::Result;
use chrono::Utc;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, warn};

pub async fn serve(
    addr: SocketAddr,
    router: Arc<Router>,
    stats: Option<Arc<StatsCollector>>,
) -> Result<()> {
    let udp_router = router.clone();
    let tcp_router = router.clone();
    let udp_stats = stats.clone();
    let tcp_stats = stats.clone();

    let udp_handle = tokio::spawn(async move {
        if let Err(e) = serve_udp(addr, udp_router, udp_stats).await {
            error!("UDP listener error: {}", e);
        }
    });

    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = serve_tcp(addr, tcp_router, tcp_stats).await {
            error!("TCP listener error: {}", e);
        }
    });

    tracing::info!("DNS server listening on {}", addr);

    tokio::select! {
        _ = udp_handle => {}
        _ = tcp_handle => {}
    }

    Ok(())
}

async fn serve_udp(
    addr: SocketAddr,
    router: Arc<Router>,
    stats: Option<Arc<StatsCollector>>,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!("UDP listener on {}", addr);

#[allow(clippy::while_let_loop)]
    loop {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await?;
        buf.truncate(n);

        let socket = socket.clone();
        let router = router.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            match handle_request(&buf, peer, &router, stats.as_deref()).await {
                Ok(response_bytes) => {
                    if let Err(e) = socket.send_to(&response_bytes, peer).await {
                        warn!("Failed to send UDP response to {}: {}", peer, e);
                    }
                }
                Err(e) => {
                    debug!("Failed to handle UDP request from {}: {}", peer, e);
                }
            }
        });
    }
}

async fn serve_tcp(
    addr: SocketAddr,
    router: Arc<Router>,
    stats: Option<Arc<StatsCollector>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("TCP listener on {}", addr);

#[allow(clippy::while_let_loop)]
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, peer, router, stats).await {
                debug!("TCP connection error from {}: {}", peer, e);
            }
        });
    }
}

async fn handle_tcp_conn(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    stats: Option<Arc<StatsCollector>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(clippy::while_let_loop)]
    loop {
        // DNS over TCP: 2-byte length prefix
        let len = match stream.read_u16().await {
            Ok(l) => l as usize,
            Err(_) => break, // client disconnected
        };

        if len == 0 || len > 65535 {
            break;
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        match handle_request(&buf, peer, &router, stats.as_deref()).await {
            Ok(resp) => {
                let resp_len = resp.len() as u16;
                stream.write_all(&resp_len.to_be_bytes()).await?;
                stream.write_all(&resp).await?;
            }
            Err(e) => {
                debug!("Failed to handle TCP request from {}: {}", peer, e);
                break;
            }
        }
    }
    Ok(())
}

/// 处理单条 DNS 请求，记录统计。
async fn handle_request(
    buf: &[u8],
    peer: SocketAddr,
    router: &Router,
    stats: Option<&StatsCollector>,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    let request = Message::from_bytes(buf)?;

    // 解析失败时也记一条（若开启了 stats）
    let result = router.resolve_with_meta(&request).await;
    let latency_ms = start.elapsed().as_secs_f32() * 1000.0;

    match result {
        Ok((response, meta)) => {
            if let Some(stats) = stats {
                let entry = QueryEntry {
                    id: String::new(), // record_query 会补 UUID
                    time: Utc::now(),
                    client: peer.ip(),
                    domain: meta.domain,
                    qtype: meta.qtype,
                    upstream: meta.upstream,
                    original_upstream: meta.original_upstream,
                    rcode: meta.rcode,
                    latency_ms,
                    upstream_latency_ms: meta.upstream_latency_ms,
                    rule: meta.rule,
                    cached: meta.cached,
                    blocked: meta.blocked,
                };
                stats.record_query(entry);
            }
            let bytes = response.to_bytes()?;
            Ok(bytes)
        }
        Err(e) => {
            // 解析失败也记录一条 failed（仅统计，不影响响应）
            if let Some(stats) = stats {
                let domain = request
                    .queries()
                    .first()
                    .map(|q| q.name().to_string())
                    .unwrap_or_default();
                let qtype = request
                    .queries()
                    .first()
                    .map(|q| crate::stats::qtype_name(q.query_type()))
                    .unwrap_or_default();
                let entry = QueryEntry {
                    id: String::new(),
                    time: Utc::now(),
                    client: peer.ip(),
                    domain,
                    qtype,
                    upstream: "error".to_string(),
                    original_upstream: "error".to_string(),
                    rcode: "SERVFAIL".to_string(),
                    latency_ms,
                    upstream_latency_ms: None,
                    rule: None,
                    cached: false,
                    blocked: false,
                };
                stats.record_query(entry);
            }
            Err(e)
        }
    }
}
