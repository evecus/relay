//! IPv4 address pool with state machine and ARP conflict detection

use super::lease::{Lease, LeaseStore};
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, warn};

fn ip_to_u32(ip: Ipv4Addr) -> u32 { u32::from(ip) }
fn u32_to_ip(n: u32) -> Ipv4Addr { Ipv4Addr::from(n) }

pub struct AddressPool {
    start: u32,
    end: u32,
    /// IPs currently in OFFER state (not yet ACKed), with timeout
    offered: Mutex<Vec<(Ipv4Addr, std::time::Instant)>>,
    pub leases: Mutex<LeaseStore>,
    lease_duration: Duration,
    arp_probe: bool,
    interface: String,
}

impl AddressPool {
    pub fn new(
        start: Ipv4Addr,
        end: Ipv4Addr,
        lease_duration: Duration,
        arp_probe: bool,
        interface: String,
        lease_store: LeaseStore,
    ) -> Self {
        Self {
            start: ip_to_u32(start),
            end: ip_to_u32(end),
            offered: Mutex::new(Vec::new()),
            leases: Mutex::new(lease_store),
            lease_duration,
            arp_probe,
            interface,
        }
    }

    /// Find or allocate an IP for a given MAC address.
    /// Returns None if pool is exhausted.
    pub async fn allocate(&self, mac: &[u8; 6], requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        // Clean up expired offers
        self.expire_offers().await;

        let leases = self.leases.lock().await;

        // 1. Static binding takes priority
        if let Some(lease) = leases.get_by_mac(mac) {
            if lease.is_static {
                return Some(lease.ip);
            }
            // Existing active lease — renew same IP
            if !lease.is_expired() {
                return Some(lease.ip);
            }
        }

        // 2. Honor requested IP if it's free
        if let Some(req_ip) = requested {
            if self.is_in_range(req_ip) && self.is_free(&leases, req_ip).await {
                return Some(req_ip);
            }
        }

        // 3. Scan pool for a free IP
        let offered = self.offered.lock().await;
        let offered_ips: HashSet<Ipv4Addr> = offered.iter().map(|(ip, _)| *ip).collect();
        drop(offered);

        for n in self.start..=self.end {
            let ip = u32_to_ip(n);
            let used_in_lease = leases.get_by_ip(ip).map(|l| !l.is_expired()).unwrap_or(false);
            if !used_in_lease && !offered_ips.contains(&ip) {
                return Some(ip);
            }
        }

        None
    }

    /// Record an OFFER (tentative allocation, 30s timeout)
    pub async fn offer(&self, ip: Ipv4Addr) {
        let mut offered = self.offered.lock().await;
        offered.push((ip, std::time::Instant::now()));
    }

    /// Confirm allocation (REQUEST → ACK). Returns the lease.
    pub async fn confirm(
        &self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        hostname: Option<String>,
    ) -> Result<Lease> {
        // ARP probe before confirming
        if self.arp_probe {
            if let Err(e) = self.arp_probe_ip(ip).await {
                warn!("ARP probe for {} failed: {}", ip, e);
                bail!("IP {} appears to be in use (ARP probe failed)", ip);
            }
        }

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.lease_duration.as_secs();

        let lease = Lease {
            mac,
            ip,
            hostname: hostname.clone(),
            expires_at,
            is_static: false,
        };

        // Remove from offered set
        let mut offered = self.offered.lock().await;
        offered.retain(|(o_ip, _)| *o_ip != ip);
        drop(offered);

        let mut leases = self.leases.lock().await;
        leases.insert(lease.clone())?;

        debug!("DHCPv4 lease confirmed: {} → {}", LeaseStore::mac_key(&mac), ip);
        Ok(lease)
    }

    pub async fn release(&self, mac: &[u8; 6]) -> Result<Option<Lease>> {
        let mut leases = self.leases.lock().await;
        let lease = leases.get_by_mac(mac).cloned();
        if lease.is_some() {
            leases.remove_by_mac(mac)?;
        }
        Ok(lease)
    }

    pub fn lease_seconds(&self) -> u32 {
        self.lease_duration.as_secs() as u32
    }

    fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let n = ip_to_u32(ip);
        n >= self.start && n <= self.end
    }

    async fn is_free(&self, leases: &LeaseStore, ip: Ipv4Addr) -> bool {
        let in_lease = leases.get_by_ip(ip).map(|l| !l.is_expired()).unwrap_or(false);
        if in_lease {
            return false;
        }
        let offered = self.offered.lock().await;
        !offered.iter().any(|(o, _)| *o == ip)
    }

    async fn expire_offers(&self) {
        let mut offered = self.offered.lock().await;
        let cutoff = Duration::from_secs(30);
        offered.retain(|(_, t)| t.elapsed() < cutoff);
    }

    /// Send an ARP request and wait briefly to see if anyone replies.
    /// Returns Ok(()) if the IP appears free, Err if it's in use.
    async fn arp_probe_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let iface_idx = get_iface_index(&self.interface)?;
        let src_mac   = get_iface_mac(&self.interface)?;

        // Open AF_PACKET/SOCK_RAW socket via libc directly (avoids socket2 version issues)
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ARP as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            bail!("socket(AF_PACKET): {}", std::io::Error::last_os_error());
        }

        // Build ARP probe packet (14 Ethernet + 28 ARP = 42 bytes)
        let mut pkt = [0u8; 42];
        pkt[0..6].fill(0xff);                          // dst: broadcast
        pkt[6..12].copy_from_slice(&src_mac);          // src: our MAC
        pkt[12] = 0x08; pkt[13] = 0x06;               // ethertype: ARP
        pkt[14] = 0x00; pkt[15] = 0x01;               // hw type: Ethernet
        pkt[16] = 0x08; pkt[17] = 0x00;               // proto: IPv4
        pkt[18] = 6; pkt[19] = 4;                     // hw/proto addr len
        pkt[20] = 0x00; pkt[21] = 0x01;               // op: request
        pkt[22..28].copy_from_slice(&src_mac);         // sender MAC
        pkt[28..32].fill(0x00);                        // sender IP: 0.0.0.0 (probe)
        pkt[32..38].fill(0x00);                        // target MAC: unknown
        pkt[38..42].copy_from_slice(&ip.octets());     // target IP

        let sll = libc::sockaddr_ll {
            sll_family:   libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ARP as u16).to_be(),
            sll_ifindex:  iface_idx,
            sll_hatype:   0,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
        };

        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            unsafe { libc::close(fd) };
            bail!("sendto ARP probe: {}", std::io::Error::last_os_error());
        }

        // Wait up to 500ms for ARP reply using select()
        let result = unsafe {
            let mut tv = libc::timeval { tv_sec: 0, tv_usec: 500_000 };
            let mut fds: libc::fd_set = std::mem::zeroed();
            libc::FD_SET(fd, &mut fds);
            libc::select(fd + 1, &mut fds, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv)
        };

        if result > 0 {
            let mut buf = [0u8; 60];
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            unsafe { libc::close(fd) };

            if n >= 42
                && buf[20] == 0x00 && buf[21] == 0x02   // ARP reply
                && buf[28..32] == ip.octets()
            {
                bail!("IP {} is already in use (ARP reply received)", ip);
            }
        } else {
            unsafe { libc::close(fd) };
        }

        Ok(()) // No reply within 500ms → IP is free
    }
}

pub fn get_iface_index_pub(name: &str) -> anyhow::Result<i32> { get_iface_index(name) }
fn get_iface_index(name: &str) -> Result<i32> {
    let name_cstr = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if idx == 0 {
        bail!("Interface not found: {}", name);
    }
    Ok(idx as i32)
}

fn get_iface_mac(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Cannot read MAC for {}", name))?;
    let parts: Vec<u8> = content.trim().split(':')
        .map(|s| u8::from_str_radix(s, 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if parts.len() != 6 {
        bail!("Invalid MAC address for {}", name);
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

use anyhow::Context;
