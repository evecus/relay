//! TCP upstream：完整的 exchange（含读 2 字节长度前缀）都包在 timeout 内。
//!
//! 修复 Bug 7：旧实现只在 connect 和 read_exact 上加 timeout，但
//! `stream.read_u16()`（读 2 字节长度前缀）无 timeout，恶意/慢速上游
//! 连上后不发数据会一直挂起，直到 TCP keepalive（默认 2 小时）。
//! 现整体包在 timeout 内，含 connect + read_u16 + read_exact。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::util;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn query(addr: SocketAddr, request: &Message) -> Result<Message> {
    let wire = request.to_vec()?;

    // 整体超时，含 connect + 写请求 + 读长度前缀 + 读 body
    let resp_bytes = timeout(TCP_TIMEOUT, async {
        let mut stream = TcpStream::connect(addr).await.context("TCP connect failed")?;
        util::tcp_framed_exchange(&mut stream, &wire).await
    })
    .await
    .context("TCP exchange timed out")??;

    let resp = Message::from_bytes(&resp_bytes).context("Failed to parse TCP DNS response")?;
    Ok(resp)
}
