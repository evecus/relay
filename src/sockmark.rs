//! 上游 DNS socket 的 fwmark 标记（Linux `SO_MARK`）。
//!
//! 防火墙 DNS 劫持用「socket 带有本程序的 fwmark 就放行」代替「uid 0 放行」，
//! 这样 root 用户下其它进程的 53 流量依然会被劫持，只有 relay 自己发往上游的
//! 53 流量（打了 mark）才不会被重定向回自己，避免回环。
//!
//! - 打 mark 需要 `CAP_NET_ADMIN`（root 默认具备）。
//! - 防火墙启用（strict 模式）时，打 mark 失败会直接报错，否则会形成回环；
//!   防火墙未启用时失败则忽略，保证非 root 运行也能正常工作。
//! - 非 Linux 平台（macOS/pf）为 no-op。

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// 默认 fwmark，可通过 `firewall.fwmark` 修改。
pub const DEFAULT_FWMARK: u32 = 0x7d53;

static MARK: AtomicU32 = AtomicU32::new(DEFAULT_FWMARK);
static STRICT: AtomicBool = AtomicBool::new(false);

pub fn set_mark(mark: u32) {
    MARK.store(mark, Ordering::SeqCst);
}

pub fn mark() -> u32 {
    MARK.load(Ordering::SeqCst)
}

/// strict = 防火墙劫持已启用：打 mark 失败视为错误。
pub fn set_strict(strict: bool) {
    STRICT.store(strict, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn apply_fd(fd: i32, mark: u32) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(not(target_os = "linux"))]
fn apply_fd(_fd: i32, _mark: u32) -> io::Result<()> {
    Ok(())
}

/// 给 socket 打上 fwmark。
pub fn apply<S: AsRawFd>(sock: &S) -> io::Result<()> {
    let mark = mark();
    if mark == 0 {
        return Ok(());
    }
    match apply_fd(sock.as_raw_fd(), mark) {
        Ok(()) => Ok(()),
        Err(e) if STRICT.load(Ordering::SeqCst) => Err(io::Error::new(
            e.kind(),
            format!("failed to set SO_MARK 0x{:x} (need root/CAP_NET_ADMIN): {}", mark, e),
        )),
        Err(e) => {
            tracing::debug!("SO_MARK not applied (firewall hijack disabled): {}", e);
            Ok(())
        }
    }
}

/// 创建已打 mark、地址族与 `peer` 匹配的 UDP socket（未 connect）。
pub fn bind_udp(peer: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = match peer {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let std_sock = std::net::UdpSocket::bind(bind)?;
    apply(&std_sock)?;
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

/// 建立已打 mark 的 TCP 连接（mark 在 connect 之前设置，SYN 即带 mark）。
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    apply(&sock)?;
    sock.connect(addr).await
}
