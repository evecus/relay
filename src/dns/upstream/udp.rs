//! UDP upstream: send query, receive response, fallback to TCP on TC bit.
//!
//! 修复 Bug 5：旧实现直接返回 UDP 响应，未检查 TC（Truncated）位，
//! 导致大响应被静默截断。现按 RFC 2181 §9 检测 TC 后自动回退到 TCP。
//!
//! 修复 Bug 6：旧实现固定 4KB 缓冲区，不解析 EDNS OPT UDPSize。
//! 现解析请求 OPT 中的最大 UDPSize，按需扩展接收缓冲区（上限 65535）。
//!
//! ## 连接复用（UdpPool）
//!
//! 旧实现每次查询都 bind 一个新 socket、用完即弃。UDP 本身无连接状态，
//! 但反复 bind/drop socket fd 在高并发下仍有系统调用开销，且无法在同一条
//! "会话"上 pipeline 多个并发查询。
//!
//! 对齐 sing-box `udp.go` 的做法：同一个上游地址共享一条已 connect 的
//! UDP socket，用 DNS message ID 做请求-响应匹配（因为可能多个查询并发
//! 挂在同一条 socket 上），配合一个常驻的 recv loop 任务把收到的响应
//! 分发给等待中的调用者。`UdpPool` 是这套机制的封装，`query()` 函数本身
//! 保留（单次、无池化），继续给 DHCP fallback 等低频场景使用。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::tcp;
use crate::firewall::apply_protect_mark;

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
    apply_protect_mark(&socket);
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

/// 共享 UDP socket 连接池：一个上游地址对应一条常驻 socket + recv loop。
///
/// 用法：`UdpPool::new(addr)` 后调用 `query()`，多个并发调用安全地共享
/// 同一条底层 socket，靠 DNS message ID 区分各自的响应。
pub struct UdpPool {
    addr: SocketAddr,
    /// 懒初始化的 socket + recv loop 句柄；连接失效（recv 出错）时整体重建。
    inner: tokio::sync::RwLock<Option<Arc<PoolInner>>>,
}

struct PoolInner {
    socket: Arc<UdpSocket>,
    next_id: AtomicU16,
    /// 等待响应的调用者：query id -> 一次性回复通道。
    /// 用 std::sync::Mutex 而非 tokio Mutex：临界区只是 HashMap 增删，
    /// 不跨 await point，用标准库锁开销更低。与 recv loop 共享同一个 Arc。
    pending: Arc<StdMutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>,
    /// recv loop 任务句柄，Drop 时中止，避免 socket 失效后 loop 空转。
    recv_task: tokio::task::JoinHandle<()>,
}

impl Drop for PoolInner {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

impl UdpPool {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            inner: tokio::sync::RwLock::new(None),
        }
    }

    async fn get_or_create(&self) -> Result<Arc<PoolInner>> {
        if let Some(inner) = self.inner.read().await.as_ref() {
            return Ok(inner.clone());
        }
        let mut guard = self.inner.write().await;
        if let Some(inner) = guard.as_ref() {
            return Ok(inner.clone());
        }

        let bind = match self.addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind)
            .await
            .context("Failed to bind UDP socket for upstream pool")?;
        apply_protect_mark(&socket);
        socket
            .connect(self.addr)
            .await
            .context("Failed to connect UDP")?;
        let socket = Arc::new(socket);
        // pending 表必须在 recv loop 和 PoolInner 之间共享同一份，否则响应
        // 永远匹配不到等待者。用 Arc 包一层，PoolInner::pending 直接持有
        // 这个 Arc 的 clone。
        let pending: Arc<StdMutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        let recv_socket = socket.clone();
        let recv_pending = pending.clone();
        let addr = self.addr;
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_BUF];
            loop {
                match recv_socket.recv(&mut buf).await {
                    Ok(n) => {
                        // 只需要 DNS header 里的 ID（前 2 字节）就能路由，
                        // 不需要在这里做完整解析。
                        if n < 2 {
                            continue;
                        }
                        let id = u16::from_be_bytes([buf[0], buf[1]]);
                        let sender = recv_pending.lock().unwrap().remove(&id);
                        if let Some(sender) = sender {
                            let _ = sender.send(buf[..n].to_vec());
                        }
                        // 找不到对应 id：可能是超时后调用方已放弃等待，静默丢弃。
                    }
                    Err(e) => {
                        warn!("UDP pool recv loop for {} exiting: {}", addr, e);
                        // socket 层面出错，唤醒所有等待者返回错误（发送端 drop 会让
                        // 对应的 oneshot::Receiver 收到 RecvError）。
                        recv_pending.lock().unwrap().clear();
                        return;
                    }
                }
            }
        });

        let inner = Arc::new(PoolInner {
            socket,
            next_id: AtomicU16::new(0),
            pending,
            recv_task,
        });
        *guard = Some(inner.clone());
        Ok(inner)
    }

    pub async fn query(&self, request: &Message) -> Result<Message> {
        let wire = request.to_vec()?;
        let original_id = request.id();

        for attempt in 0..2 {
            let inner = self.get_or_create().await?;
            let (tx, rx) = oneshot::channel();

            // 找一个当前未被占用的 query id 并原子地插入 pending 表——必须
            // 在同一次加锁内完成"查找空闲 id + 插入"，否则两次加锁之间存在
            // 竞态窗口：两个并发调用可能选中同一个 id，后插入的会覆盖前一个
            // 等待者的 sender，导致前一个查询永久挂起直到超时。
            // （对齐 sing-box nextAvailableQueryId 的思路：找到未占用 id 为止，
            // 最多尝试 65536 次覆盖整个 ID 空间。）
            let qid = {
                let mut pending = inner.pending.lock().unwrap();
                let mut candidate = inner.next_id.fetch_add(1, Ordering::Relaxed);
                let mut tries = 0u32;
                while pending.contains_key(&candidate) && tries < u16::MAX as u32 {
                    candidate = inner.next_id.fetch_add(1, Ordering::Relaxed);
                    tries += 1;
                }
                pending.insert(candidate, tx);
                candidate
            };

            let mut wire_with_id = wire.clone();
            if wire_with_id.len() >= 2 {
                wire_with_id[0] = (qid >> 8) as u8;
                wire_with_id[1] = (qid & 0xff) as u8;
            }

            if let Err(e) = inner.socket.send(&wire_with_id).await {
                inner.pending.lock().unwrap().remove(&qid);
                // 发送失败：socket 可能已损坏，丢弃重建后重试一次。
                self.invalidate(&inner).await;
                if attempt == 0 {
                    debug!("UDP pool send failed, rebuilding socket: {}", e);
                    continue;
                }
                return Err(e).context("UDP send failed");
            }

            let recv_result = timeout(UDP_TIMEOUT, rx).await;
            match recv_result {
                Ok(Ok(mut resp_bytes)) => {
                    if resp_bytes.len() >= 2 {
                        resp_bytes[0] = (original_id >> 8) as u8;
                        resp_bytes[1] = (original_id & 0xff) as u8;
                    }
                    let resp = Message::from_bytes(&resp_bytes)
                        .context("Failed to parse UDP DNS response")?;

                    if resp.truncated() {
                        debug!(
                            "UDP response from {} has TC bit set, retrying over TCP",
                            self.addr
                        );
                        return tcp::query(self.addr, request).await;
                    }
                    return Ok(resp);
                }
                Ok(Err(_recv_error)) => {
                    // 发送端被 drop（recv loop 因 socket 错误退出）：重建重试。
                    inner.pending.lock().unwrap().remove(&qid);
                    self.invalidate(&inner).await;
                    if attempt == 0 {
                        debug!("UDP pool socket broken, rebuilding");
                        continue;
                    }
                    anyhow::bail!("UDP pool socket broken for {}", self.addr);
                }
                Err(_timeout_elapsed) => {
                    inner.pending.lock().unwrap().remove(&qid);
                    anyhow::bail!("UDP recv timed out for {}", self.addr);
                }
            }
        }
        unreachable!("loop always returns within 2 attempts")
    }

    /// 使当前连接失效，下次查询会重新 bind + connect。
    async fn invalidate(&self, stale: &Arc<PoolInner>) {
        let mut guard = self.inner.write().await;
        if let Some(current) = guard.as_ref() {
            if Arc::ptr_eq(current, stale) {
                *guard = None;
            }
        }
    }
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
