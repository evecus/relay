//! DHCPv6 server: UDP on [::]:547, handles SOLICIT/REQUEST/RENEW/RELEASE/INFO-REQUEST

use super::lease::{parse_lease_time_v6, parse_v6_prefix, V6LeaseStore, V6Pool};
use crate::config::{DhcpV6Config, DhcpV6Mode};
use crate::dns::hosts::DynamicHosts;
use anyhow::Result;
use dhcproto::v6::{
    DhcpOption as V6Opt, DhcpOptions, IAAddr, IANA,
    Message as V6Msg, MessageType as V6MsgType, OptionCode as V6OC,
};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const DHCPV6_SERVER_PORT: u16 = 547;
const DHCPV6_CLIENT_PORT: u16 = 546;

pub async fn serve(cfg: DhcpV6Config, dynamic_hosts: Arc<DynamicHosts>) -> Result<()> {
    let lease_duration = parse_lease_time_v6(&cfg.lease_time)?;

    let pool = if cfg.mode == DhcpV6Mode::Stateful {
        let store = V6LeaseStore::load(&cfg.lease_file)?;
        for lease in store.all_active().collect::<Vec<_>>() {
            if let Some(ref hn) = lease.hostname {
                dynamic_hosts.insert(hn, IpAddr::V6(lease.ip));
            }
        }
        let (prefix, prefix_len) = cfg.prefix.as_deref()
            .map(parse_v6_prefix)
            .transpose()?
            .unwrap_or(("fd00::".parse().unwrap(), 64));
        Some(Arc::new(V6Pool::new(prefix, prefix_len, lease_duration, store)))
    } else {
        None
    };

    let socket = Arc::new(
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DHCPV6_SERVER_PORT))
            .await?,
    );

    join_multicast_group(&socket, &cfg.interface)?;
    info!("DHCPv6 listening on {}:547 (mode: {:?})", cfg.interface, cfg.mode);

    loop {
        let mut buf = vec![0u8; 1500];
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { warn!("DHCPv6 recv: {}", e); continue; }
        };
        buf.truncate(n);

        let socket = socket.clone();
        let pool = pool.clone();
        let dynamic_hosts = dynamic_hosts.clone();
        let dns = cfg.dns.clone();
        let domain = cfg.domain.clone();
        let mode = cfg.mode.clone();
        let lease_secs = lease_duration.as_secs() as u32;

        tokio::spawn(async move {
            if let Err(e) = handle_packet(
                &buf, peer, &socket, pool.as_deref(),
                &dns, domain.as_deref(), &mode,
                &dynamic_hosts, lease_secs,
            ).await {
                debug!("DHCPv6 error: {}", e);
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
    async fn handle_packet(
    buf: &[u8],
    peer: SocketAddr,
    socket: &UdpSocket,
    pool: Option<&V6Pool>,
    dns_servers: &[Ipv6Addr],
    domain: Option<&str>,
    mode: &DhcpV6Mode,
    dynamic_hosts: &DynamicHosts,
    lease_secs: u32,
) -> Result<()> {
    use dhcproto::v6::Decodable;
    let msg = V6Msg::decode(&mut dhcproto::decoder::Decoder::new(buf))?;
    let msg_type = msg.msg_type();
    let xid = msg.xid();

    debug!("DHCPv6 {:?} from {}", msg_type, peer);

    // ClientId is raw bytes in dhcproto 0.12
    let client_id: Option<Vec<u8>> = msg.opts()
        .get(V6OC::ClientId)
        .and_then(|o| if let V6Opt::ClientId(d) = o { Some(d.clone()) } else { None });

    match msg_type {
        // Stateless: just return DNS config
        V6MsgType::InformationRequest => {
            let reply = build_reply(xid, client_id.as_deref(), None, dns_servers, domain, 0);
            send_reply(socket, reply, peer).await?;
        }

        V6MsgType::Solicit if mode == &DhcpV6Mode::Stateful => {
            let (Some(pool), Some(ref duid)) = (pool, &client_id) else { return Ok(()) };
            if let Some(ip) = pool.allocate(duid).await {
                let reply = build_reply(xid, Some(duid), Some(ip), dns_servers, domain, lease_secs);
                send_reply(socket, reply, peer).await?;
            }
        }

        V6MsgType::Request | V6MsgType::Renew if mode == &DhcpV6Mode::Stateful => {
            let (Some(pool), Some(ref duid)) = (pool, &client_id) else { return Ok(()) };

            // Extract requested IP from IA_NA > IAAddr
            let requested = msg.opts().get(V6OC::IANA)
                .and_then(|o| if let V6Opt::IANA(iana) = o {
                    iana.opts.get(V6OC::IAAddr)
                        .and_then(|a| if let V6Opt::IAAddr(ia) = a {
                            Some(ia.addr)
                        } else { None })
                } else { None });

            let ip = match requested.or(pool.allocate(duid).await) {
                Some(ip) => ip,
                None => { warn!("DHCPv6 pool exhausted"); return Ok(()); }
            };

            match pool.confirm(duid.clone(), ip, None).await {
                Ok(lease) => {
                    if let Some(ref hn) = lease.hostname {
                        dynamic_hosts.insert(hn, IpAddr::V6(lease.ip));
                    }
                    let reply = build_reply(xid, Some(duid), Some(ip), dns_servers, domain, lease_secs);
                    send_reply(socket, reply, peer).await?;
                    info!("DHCPv6 confirmed: {}", ip);
                }
                Err(e) => warn!("DHCPv6 confirm error: {}", e),
            }
        }

        V6MsgType::Release if mode == &DhcpV6Mode::Stateful => {
            let (Some(pool), Some(ref duid)) = (pool, &client_id) else { return Ok(()) };
            pool.release(duid).await?;
        }

        _ => {}
    }

    Ok(())
}

fn build_reply(
    xid: [u8; 3],
    client_id: Option<&[u8]>,
    ip: Option<Ipv6Addr>,
    dns: &[Ipv6Addr],
    domain: Option<&str>,
    lease_secs: u32,
) -> V6Msg {
    let mut msg = V6Msg::new_with_id(V6MsgType::Reply, xid);

    if let Some(cid) = client_id {
        msg.opts_mut().insert(V6Opt::ClientId(cid.to_vec()));
    }

    // Server DUID (minimal link-layer placeholder)
    msg.opts_mut().insert(V6Opt::ServerId(vec![0x00, 0x03, 0x00, 0x01,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]));

    if let Some(addr) = ip {
        let ia_addr = IAAddr {
            addr,
            preferred_life: lease_secs,
            valid_life: lease_secs,
            opts: DhcpOptions::default(),
        };
        let mut inner = DhcpOptions::default();
        inner.insert(V6Opt::IAAddr(ia_addr));
        let iana = IANA {
            id: 1,
            t1: lease_secs / 2,
            t2: lease_secs * 7 / 8,
            opts: inner,
        };
        msg.opts_mut().insert(V6Opt::IANA(iana));
    }

    if !dns.is_empty() {
        msg.opts_mut().insert(V6Opt::DomainNameServers(dns.to_vec()));
    }

    if let Some(d) = domain {
        // DomainSearchList expects Vec<Name> — use bytes for simplicity
        // dhcproto uses hickory_dns Name type; just skip if unavailable
        let _ = d; // domain search list omitted for now
    }

    msg
}

async fn send_reply(socket: &UdpSocket, msg: V6Msg, peer: SocketAddr) -> Result<()> {
    use dhcproto::v6::Encodable;
    let mut buf = Vec::new();
    let mut enc = dhcproto::encoder::Encoder::new(&mut buf);
    msg.encode(&mut enc)?;
    let dst = SocketAddr::new(peer.ip(), DHCPV6_CLIENT_PORT);
    socket.send_to(&buf, dst).await?;
    Ok(())
}

fn join_multicast_group(socket: &UdpSocket, iface: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let idx = crate::dhcp::v4::pool::get_iface_index_pub(iface)?;
    let group: Ipv6Addr = "ff02::1:2".parse().unwrap();
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr { s6_addr: group.octets() },
        ipv6mr_interface: idx as u32,
    };
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        anyhow::bail!("join ff02::1:2 failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}
