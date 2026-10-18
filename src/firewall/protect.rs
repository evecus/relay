//! Mark outbound sockets so firewall rules can skip them (avoid DNS redirect loops).
//!
//! Using SO_MARK is reliable on Android: system DNS (netd) runs as uid 0 and must
//! still be redirected. Excluding by `skuid 0` would skip netd as well.
//! Only sockets that carry this mark (relay upstream / bootstrap DNS) are exempt.

use std::os::fd::AsRawFd;

/// fwmark applied to relay's own upstream DNS sockets.
/// Firewall rules return early on this mark before redirecting port 53.
pub const PROTECT_MARK: u32 = 0x646e_7378; // 'dnsx'

/// Set SO_MARK on a socket (Linux/Android). No-op on other platforms.
pub fn apply_protect_mark<S: AsRawFd>(sock: &S) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = sock.as_raw_fd();
        let mark = PROTECT_MARK;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            tracing::debug!(
                "SO_MARK(0x{:x}) failed: {}",
                PROTECT_MARK,
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = sock;
    }
}
