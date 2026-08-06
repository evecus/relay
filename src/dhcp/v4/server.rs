//! DHCPv4 server: UDP socket on port 67, handles DISCOVER/REQUEST/RELEASE/INFORM

use super::lease::{parse_lease_time, LeaseStore};
use super::pool::AddressPool;
use crate::config::DhcpV4Config;
use crate::dns::hosts::DynamicHosts;
use anyhow::{bail, Result};
use dhcproto::v4::{
    Decodable, DhcpOption, Encodable, Message, MessageType, OptionCode,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

pub async fn serve(cfg: DhcpV4Config, dynamic_hosts: Arc<DynamicHosts>) -> Result<()> {
    let lease_duration = parse_lease_time(&cfg.lease_time)?;

    // Load static leases first
    let mut store = LeaseStore::load(&cfg.lease_file)?;
    let _now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for s in &cfg.static_leases {
        let mac = parse_mac(&s.mac)?;
        let lease = super::lease::Lease {
            mac,
            ip: s.ip,
            hostname: s.hostname.clone(),
            expires_at: u64::MAX,
            is_static: true,
        };
        store.insert(lease)?;
        // Register static hostnames in DNS immediately
        if let Some(ref hn) = s.hostname {
            dynamic_hosts.insert(hn, IpAddr::V4(s.ip));
        }
    }

    // Re-register active leases from disk into DNS
    for lease in store.all_active().filter(|l| !l.is_static).collect::<Vec<_>>() {
        if let Some(ref hn) = lease.hostname {
            dynamic_hosts.insert(hn, IpAddr::V4(lease.ip));
        }
    }

    let pool = Arc::new(AddressPool::new(
        cfg.range[0],
        cfg.range[1],
        lease_duration,
        cfg.arp_probe,
        cfg.interface.clone(),
        store,
    ));

    // Bind to 0.0.0.0:67 with SO_BROADCAST and SO_BINDTODEVICE
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_broadcast(true)?;
    sock.set_reuse_address(true)?;
    bind_to_device(&sock, &cfg.interface)?;
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_SERVER_PORT)).into())?;
    sock.set_nonblocking(true)?;

    let socket = Arc::new(UdpSocket::from_std(std::net::UdpSocket::from(sock))?);
    info!("DHCPv4 listening on {}:67", cfg.interface);

    let server_ip = cfg.gateway; // We advertise ourselves as gateway
    let subnet = cfg.subnet;
    let dns_servers = cfg.dns.clone();
    let domain = cfg.domain.clone();
    let lease_secs = pool.lease_seconds();

    loop {
        let mut buf = vec![0u8; 1500];
        let (n, _peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { warn!("DHCPv4 recv error: {}", e); continue; }
        };
        buf.truncate(n);

        let socket = socket.clone();
        let pool = pool.clone();
        let dynamic_hosts = dynamic_hosts.clone();
        let dns_servers = dns_servers.clone();
        let domain = domain.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_packet(
                &buf, &socket, &pool, &dynamic_hosts,
                server_ip, subnet, &dns_servers, domain.as_deref(), lease_secs,
            ).await {
                debug!("DHCPv4 packet error: {}", e);
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
    async fn handle_packet(
    buf: &[u8],
    socket: &UdpSocket,
    pool: &AddressPool,
    dynamic_hosts: &DynamicHosts,
    server_ip: Ipv4Addr,
    subnet: Ipv4Addr,
    dns_servers: &[Ipv4Addr],
    domain: Option<&str>,
    lease_secs: u32,
) -> Result<()> {
    let msg = Message::decode(&mut dhcproto::decoder::Decoder::new(buf))?;

    let msg_type = msg.opts()
        .get(OptionCode::MessageType)
        .and_then(|o| if let DhcpOption::MessageType(t) = o { Some(*t) } else { None })
        .ok_or_else(|| anyhow::anyhow!("No message type"))?;

    let mac: [u8; 6] = msg.chaddr()[..6].try_into()?;

    let hostname = msg.opts()
        .get(OptionCode::Hostname)
        .and_then(|o| if let DhcpOption::Hostname(h) = o { Some(h.clone()) } else { None });

    debug!("DHCPv4 {:?} from {}", msg_type, LeaseStore::mac_key(&mac));

    match msg_type {
        MessageType::Discover => {
            let requested = msg.opts()
                .get(OptionCode::RequestedIpAddress)
                .and_then(|o| if let DhcpOption::RequestedIpAddress(ip) = o { Some(*ip) } else { None });

            if let Some(offered_ip) = pool.allocate(&mac, requested).await {
                pool.offer(offered_ip).await;
                let reply = build_reply(
                    &msg, MessageType::Offer, offered_ip, server_ip,
                    subnet, dns_servers, domain, lease_secs,
                );
                send_reply(socket, reply, msg.giaddr(), msg.ciaddr()).await?;
            } else {
                warn!("DHCPv4 pool exhausted, cannot offer to {}", LeaseStore::mac_key(&mac));
            }
        }

        MessageType::Request => {
            let requested_ip = msg.opts()
                .get(OptionCode::RequestedIpAddress)
                .and_then(|o| if let DhcpOption::RequestedIpAddress(ip) = o { Some(*ip) } else { None })
                .unwrap_or(msg.ciaddr());

            // Verify this request is for us
            let server_id = msg.opts()
                .get(OptionCode::ServerIdentifier)
                .and_then(|o| if let DhcpOption::ServerIdentifier(ip) = o { Some(*ip) } else { None });

            if let Some(sid) = server_id {
                if sid != server_ip {
                    // Client chose another server; silently ignore
                    return Ok(());
                }
            }

            match pool.confirm(mac, requested_ip, hostname.clone()).await {
                Ok(lease) => {
                    // Update dynamic DNS
                    if let Some(ref hn) = lease.hostname {
                        dynamic_hosts.insert(hn, IpAddr::V4(lease.ip));
                    }
                    let reply = build_reply(
                        &msg, MessageType::Ack, lease.ip, server_ip,
                        subnet, dns_servers, domain, lease_secs,
                    );
                    send_reply(socket, reply, msg.giaddr(), msg.ciaddr()).await?;
                    info!("DHCPv4 ACK: {} → {} ({})",
                        LeaseStore::mac_key(&mac), requested_ip,
                        hostname.as_deref().unwrap_or("?"));
                }
                Err(e) => {
                    warn!("DHCPv4 NAK: {}", e);
                    let nak = build_nak(&msg, server_ip);
                    send_reply(socket, nak, msg.giaddr(), msg.ciaddr()).await?;
                }
            }
        }

        MessageType::Release => {
            if let Ok(Some(lease)) = pool.release(&mac).await {
                if let Some(ref hn) = lease.hostname {
                    dynamic_hosts.remove(hn);
                }
                info!("DHCPv4 RELEASE: {} ({})", LeaseStore::mac_key(&mac), lease.ip);
            }
        }

        MessageType::Inform => {
            // Client has a static IP, just wants config options
            let reply = build_reply(
                &msg, MessageType::Ack, msg.ciaddr(), server_ip,
                subnet, dns_servers, domain, lease_secs,
            );
            send_reply(socket, reply, msg.giaddr(), msg.ciaddr()).await?;
        }

        _ => {}
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_reply(
    req: &Message,
    msg_type: MessageType,
    your_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    subnet: Ipv4Addr,
    dns: &[Ipv4Addr],
    domain: Option<&str>,
    lease_secs: u32,
) -> Message {
    let mut reply = Message::default();
    reply.set_opcode(dhcproto::v4::Opcode::BootReply);
    reply.set_htype(req.htype());
    reply.set_xid(req.xid());
    reply.set_flags(req.flags());
    reply.set_giaddr(req.giaddr());
    reply.set_chaddr(req.chaddr());
    reply.set_yiaddr(your_ip);
    reply.set_siaddr(server_ip);

    reply.opts_mut().insert(DhcpOption::MessageType(msg_type));
    reply.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
    reply.opts_mut().insert(DhcpOption::SubnetMask(subnet));
    reply.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
    reply.opts_mut().insert(DhcpOption::DomainNameServer(dns.to_vec()));
    reply.opts_mut().insert(DhcpOption::AddressLeaseTime(lease_secs));
    reply.opts_mut().insert(DhcpOption::Renewal(lease_secs / 2));
    reply.opts_mut().insert(DhcpOption::Rebinding(lease_secs * 7 / 8));

    if let Some(d) = domain {
        reply.opts_mut().insert(DhcpOption::DomainName(d.to_string()));
    }

    reply
}

fn build_nak(req: &Message, server_ip: Ipv4Addr) -> Message {
    let mut nak = Message::default();
    nak.set_opcode(dhcproto::v4::Opcode::BootReply);
    nak.set_htype(req.htype());
    nak.set_xid(req.xid());
    nak.set_chaddr(req.chaddr());
    nak.opts_mut().insert(DhcpOption::MessageType(MessageType::Nak));
    nak.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
    nak
}

async fn send_reply(
    socket: &UdpSocket,
    reply: Message,
    giaddr: Ipv4Addr,
    ciaddr: Ipv4Addr,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut enc = dhcproto::encoder::Encoder::new(&mut buf);
    reply.encode(&mut enc)?;

    // Routing: unicast to relay agent, or broadcast
    let dst = if !giaddr.is_unspecified() {
        SocketAddr::V4(SocketAddrV4::new(giaddr, DHCP_SERVER_PORT))
    } else if !ciaddr.is_unspecified() {
        SocketAddr::V4(SocketAddrV4::new(ciaddr, DHCP_CLIENT_PORT))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT))
    };

    socket.send_to(&buf, dst).await?;
    Ok(())
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<u8> = s.split(':')
        .map(|x| u8::from_str_radix(x, 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid MAC '{}': {}", s, e))?;
    if parts.len() != 6 {
        bail!("Invalid MAC address: {}", s);
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

#[cfg(target_os = "linux")]
fn bind_to_device(sock: &Socket, iface: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let iface_cstr = std::ffi::CString::new(iface)?;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            iface.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        bail!("SO_BINDTODEVICE failed for {}: {}", iface, std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_to_device(_sock: &Socket, _iface: &str) -> Result<()> { Ok(()) }
