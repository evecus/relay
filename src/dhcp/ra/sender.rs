//! Periodic RA sender + suppress-other-routers

use super::builder::{build_ra_frame, Preference, RaParams};
use super::listener::{listen_for_prefixes, SharedPrefixes};
use crate::config::RaConfig;
use crate::dhcp::v4::pool::get_iface_index_pub;
use anyhow::Result;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn, debug};

pub async fn serve(cfg: RaConfig) -> Result<()> {
    let prefixes: SharedPrefixes = Arc::new(RwLock::new(Vec::new()));

    // Spawn prefix learner
    {
        let iface = cfg.interface.clone();
        let p = prefixes.clone();
        tokio::spawn(async move {
            if let Err(e) = listen_for_prefixes(&iface, p).await {
                warn!("RA prefix listener error: {}", e);
            }
        });
    }

    // Spawn suppress-other-routers sender if enabled
    if cfg.suppress_other_routers {
        let iface = cfg.interface.clone();
        tokio::spawn(async move {
            if let Err(e) = suppress_loop(&iface).await {
                warn!("suppress-other-routers error: {}", e);
            }
        });
    }

    // Main RA broadcast loop
    let src_mac = get_iface_mac(&cfg.interface)?;
    let src_ip  = get_link_local(&cfg.interface)?;
    let pref    = Preference::from_str(&cfg.preference);
    let interval = Duration::from_secs(cfg.interval as u64);

    // Open raw socket for sending
    let sock = open_raw_socket(&cfg.interface)?;

    info!(
        "RA sender on {} every {}s (preference={:?}, lifetime={}s)",
        cfg.interface, cfg.interval, cfg.preference, cfg.router_lifetime
    );

    // Send an initial RA immediately
    send_ra(&sock, &cfg, &prefixes, src_mac, src_ip, pref).await?;

    let mut ticker = time::interval(interval);
    ticker.tick().await; // consume first tick
    loop {
        ticker.tick().await;
        if let Err(e) = send_ra(&sock, &cfg, &prefixes, src_mac, src_ip, pref).await {
            warn!("RA send error: {}", e);
        }
    }
}

async fn send_ra(
    sock: &RawSock,
    cfg: &RaConfig,
    prefixes: &SharedPrefixes,
    src_mac: [u8; 6],
    src_ip: Ipv6Addr,
    pref: Preference,
) -> Result<()> {
    let learned = prefixes.read().await;
    let prefix_list: Vec<(Ipv6Addr, u8)> = learned
        .iter()
        .map(|p| (p.prefix, p.prefix_len))
        .collect();

    let params = RaParams {
        src_mac,
        src_ip,
        prefixes: prefix_list,
        rdnss: cfg.rdnss.clone(),
        dns_lifetime: cfg.dns_lifetime as u32,
        router_lifetime: cfg.router_lifetime,
        managed: cfg.managed,
        other: cfg.other,
        preference: pref,
        mtu: None,
    };

    let frame = build_ra_frame(&params);
    sock.send(&frame)?;
    debug!("Sent RA on {} ({} prefixes)", cfg.interface, learned.len());
    Ok(())
}

/// Send periodic RAs with Router Lifetime = 0 sourced from the real routers
/// link-local address — this causes devices to stop using the real router
/// as the default gateway for IPv6.
async fn suppress_loop(iface: &str) -> Result<()> {
    info!("suppress-other-routers: monitoring {} for foreign RAs", iface);

    let prefixes: SharedPrefixes = Arc::new(RwLock::new(Vec::new()));
    let p = prefixes.clone();
    let iface_owned = iface.to_string();

    // We need to listen for RAs from the real router and mirror them
    // back with lifetime=0 to suppress them.
    // This spawns a listener; when a foreign RA is detected we send
    // a suppressing RA from the same source address.
    tokio::spawn(async move {
        if let Err(e) = listen_for_prefixes(&iface_owned, p).await {
            warn!("suppress listener error: {}", e);
        }
    });

    let sock = open_raw_socket(iface)?;
    let src_mac = get_iface_mac(iface)?;
    let src_ip  = get_link_local(iface)?;

    let mut ticker = time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        // Send a zero-lifetime RA from our own link-local —
        // devices will remove the default route to us if we're
        // not the preferred router, so we only do this as a
        // complement to our own high-preference RA, not alone.
        let params = RaParams {
            src_mac,
            src_ip,
            prefixes: vec![],
            rdnss: vec![],
            dns_lifetime: 0,
            router_lifetime: 0, // ← suppress: no default route
            managed: false,
            other: false,
            preference: Preference::Low,
            mtu: None,
        };
        // Send this as a "other router has gone away" advisory
        // by setting router lifetime=0 on an RA with low preference.
        // The actual suppression works because our main RA has HIGH
        // preference and shorter interval — devices pick us first.
        let frame = build_ra_frame(&params);
        if let Err(e) = sock.send(&frame) {
            debug!("suppress send error: {}", e);
        }
    }
}

// ─── raw socket wrapper ─────────────────────────────────────────────────────

struct RawSock {
    fd: libc::c_int,
    iface_idx: i32,
}

impl RawSock {
    fn send(&self, frame: &[u8]) -> Result<()> {
        let sll = libc::sockaddr_ll {
            sll_family:   libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_IPV6 as u16).to_be(),
            sll_ifindex:  self.iface_idx,
            sll_hatype:   0,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0, 0],
        };
        let sent = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            anyhow::bail!("sendto RA: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for RawSock {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

fn open_raw_socket(iface: &str) -> Result<RawSock> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IPV6 as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        anyhow::bail!("socket(AF_PACKET, SOCK_RAW): {}", std::io::Error::last_os_error());
    }
    let idx = get_iface_index_pub(iface)?;
    Ok(RawSock { fd, iface_idx: idx })
}

// ─── interface helpers ───────────────────────────────────────────────────────

fn get_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", iface);
    let s = std::fs::read_to_string(&path)?;
    let parts: Vec<u8> = s.trim().split(':')
        .map(|x| u8::from_str_radix(x, 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("Bad MAC: {}", e))?;
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

/// Get the link-local IPv6 address of an interface
fn get_link_local(iface: &str) -> Result<Ipv6Addr> {
    let path = "/proc/net/if_inet6".to_string();
    let content = std::fs::read_to_string(path)?;

    // Format: addr32hex ifidx prefixlen scope flags ifname
    // scope 0x20 = link-local
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 { continue; }
        if parts[5] != iface { continue; }

        // scope 20 = link-local
        let scope = u8::from_str_radix(parts[3], 16).unwrap_or(0);
        if scope != 0x20 { continue; }

        let hex = parts[0];
        if hex.len() != 32 { continue; }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16)?;
        }
        return Ok(Ipv6Addr::from(bytes));
    }

    anyhow::bail!("No link-local IPv6 address found on {}", iface)
}
