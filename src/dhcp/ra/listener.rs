//! Listen for upstream router RAs to learn IPv6 prefixes

use anyhow::Result;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LearnedPrefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

pub type SharedPrefixes = Arc<RwLock<Vec<LearnedPrefix>>>;

/// Listen on a raw ICMPv6 socket for incoming RA packets (type=134)
/// and extract Prefix Information options.
pub async fn listen_for_prefixes(iface: &str, prefixes: SharedPrefixes) -> Result<()> {
    // Open raw ICMPv6 socket via libc (avoids socket2 version issues)
    let fd = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)
    };
    if fd < 0 {
        anyhow::bail!("socket(AF_INET6, SOCK_RAW): {}", std::io::Error::last_os_error());
    }

    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    bind_to_device_v6_fd(fd, iface)?;
    join_multicast_v6_fd(fd, iface, "ff02::2")?;

    // Wrap into tokio UdpSocket for async reads
    use std::os::unix::io::FromRawFd;
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let sock = tokio::net::UdpSocket::from_std(std_sock)?;

    info!("RA listener on {} watching for upstream router advertisements", iface);

    loop {
        let mut buf = vec![0u8; 1500];
        let (n, _from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("RA listener recv error: {}", e);
                continue;
            }
        };

        if n < 16 {
            continue;
        }

        // ICMPv6 type byte is at offset 0 in the ICMPv6 payload
        // (kernel strips IP header for raw IPPROTO_ICMPV6 sockets)
        if buf[0] != 134 {
            // Not an RA
            continue;
        }

        // Parse prefix information options starting at offset 16 (after RA header)
        let mut learned = Vec::new();
        let mut i = 16usize;
        while i + 2 <= n {
            let opt_type = buf[i];
            let opt_len = buf[i + 1] as usize * 8;
            if opt_len == 0 || i + opt_len > n {
                break;
            }

            if opt_type == 3 && opt_len == 32 {
                // Prefix Information option
                let prefix_len = buf[i + 2];
                let valid_lt = u32::from_be_bytes(buf[i+4..i+8].try_into().unwrap());
                let pref_lt  = u32::from_be_bytes(buf[i+8..i+12].try_into().unwrap());
                let prefix_bytes: [u8; 16] = buf[i+16..i+32].try_into().unwrap();
                let prefix = Ipv6Addr::from(prefix_bytes);

                // Skip link-local and loopback prefixes
                if !prefix.is_loopback() && !is_link_local(prefix) {
                    learned.push(LearnedPrefix {
                        prefix,
                        prefix_len,
                        valid_lifetime: valid_lt,
                        preferred_lifetime: pref_lt,
                    });
                    debug!("Learned prefix {}/{} from upstream RA", prefix, prefix_len);
                }
            }

            i += opt_len;
        }

        if !learned.is_empty() {
            let mut p = prefixes.write().await;
            for lp in learned {
                // Update or insert
                if let Some(existing) = p.iter_mut().find(|x| x.prefix == lp.prefix) {
                    *existing = lp;
                } else {
                    info!("New IPv6 prefix learned: {}/{}", lp.prefix, lp.prefix_len);
                    p.push(lp);
                }
            }
        }
    }
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.octets()[0] == 0xfe && (ip.octets()[1] & 0xc0) == 0x80
}

fn bind_to_device_v6_fd(fd: libc::c_int, iface: &str) -> Result<()> {
    let idx = crate::dhcp::v4::pool::get_iface_index_pub(iface)?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &(idx as u32) as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        anyhow::bail!("IPV6_MULTICAST_IF: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn join_multicast_v6_fd(fd: libc::c_int, iface: &str, group: &str) -> Result<()> {
    let idx = crate::dhcp::v4::pool::get_iface_index_pub(iface)?;
    let group: Ipv6Addr = group.parse()?;
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr { s6_addr: group.octets() },
        ipv6mr_interface: idx as u32,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        anyhow::bail!("IPV6_ADD_MEMBERSHIP {}: {}", group, std::io::Error::last_os_error());
    }
    Ok(())
}
