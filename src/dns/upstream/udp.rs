//! UDP upstream: send query, receive response, fallback to TCP on TC bit.
//!
//! 修复 Bug 5：旧实现直接返回 UDP 响应，未检查 TC（Truncated）位，
//! 导致大响应被静默截断。现按 RFC 2181 §9 检测 TC 后自动回退到 TCP。
//!
//! 修复 Bug 6：旧实现固定 4KB 缓冲区，不解析 EDNS OPT UDPSize。
//! 现解析请求 OPT 中的最大 UDPSize，按需扩展接收缓冲区（上限 65535）。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::tcp;

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_UDP_BUF: usize = 4096;
const MAX_UDP_BUF: usize = 65535;

pub async fn query(addr: SocketAddr, request: &Message) -> Result<Message> {
    // 修复 Bug 6：解析请求中的 EDNS OPT UDPSize，按需扩展缓冲区
    let wire = request.to_vec()?;
    let buf_size = extract_edns_udp_size(&wire)
        .map(|s| (s as usize).clamp(DEFAULT_UDP_BUF, MAX_UDP_BUF))
        .unwrap_or(DEFAULT_UDP_BUF);

    // 选择本机出站地址族匹配的源地址
    let bind = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("Failed to bind UDP socket for upstream")?;
    socket.connect(addr).await.context("Failed to connect UDP")?;

    socket.send(&wire).await.context("UDP send failed")?;

    let mut buf = vec![0u8; buf_size];
    let n = timeout(UDP_TIMEOUT, socket.recv(&mut buf))
        .await
        .context("UDP recv timed out")??;

    let resp_bytes = &buf[..n];
    let resp = Message::from_bytes(resp_bytes).context("Failed to parse UDP DNS response")?;

    // 修复 Bug 5：检测 TC 位，自动回退到 TCP 重查
    if resp.truncated() {
        tracing::debug!(
            "UDP response from {} has TC bit set, retrying over TCP",
            addr
        );
        return tcp::query(addr, request).await;
    }

    Ok(resp)
}

/// 从 DNS 报文字节中解析 EDNS OPT 记录的 UDP payload size。
///
/// OPT 记录位于 Additional 段，TYPE=41。CLASS 字段（位置在 TYPE 之后 2 字节）
/// 在 OPT 中重定义为 UDP payload size。
///
/// 返回 None 表示无 OPT 或解析失败。
fn extract_edns_udp_size(msg: &[u8]) -> Option<u16> {
    if msg.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;

    let mut pos = 12usize;
    // 跳过 Question 段
    for _ in 0..qdcount {
        if !skip_qname(msg, &mut pos) {
            return None;
        }
        pos += 4;
    }
    // 跳过 Answer + Authority
    for _ in 0..(ancount + nscount) {
        if !skip_rr(msg, &mut pos) {
            return None;
        }
    }
    // 扫描 Additional 找 OPT
    for _ in 0..arcount {
        if !skip_qname(msg, &mut pos) {
            return None;
        }
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        // OPT 的 CLASS 字段 = UDP payload size
        let class = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if rtype == 41 {
            return Some(class);
        }
    }
    None
}

fn skip_qname(msg: &[u8], pos: &mut usize) -> bool {
    loop {
        if *pos >= msg.len() {
            return false;
        }
        let len = msg[*pos];
        if len == 0 {
            *pos += 1;
            return true;
        }
        if (len & 0xC0) == 0xC0 {
            *pos += 2;
            return true;
        }
        *pos += 1 + len as usize;
    }
}

fn skip_rr(msg: &[u8], pos: &mut usize) -> bool {
    if !skip_qname(msg, pos) {
        return false;
    }
    if *pos + 10 > msg.len() {
        return false;
    }
    let rdlength = u16::from_be_bytes([msg[*pos + 8], msg[*pos + 9]]) as usize;
    *pos += 10 + rdlength;
    true
}
