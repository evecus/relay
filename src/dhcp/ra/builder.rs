//! Build ICMPv6 Router Advertisement packets

use std::net::Ipv6Addr;

/// Router preference values (RFC 4191)
#[derive(Debug, Clone, Copy)]
pub enum Preference { Low = 0x18, Medium = 0x00, High = 0x08 }

impl Preference {
    pub fn from_str(s: &str) -> Self {
        match s {
            "low"  => Self::Low,
            "high" => Self::High,
            _      => Self::Medium,
        }
    }
}

pub struct RaParams {
    pub src_mac:        [u8; 6],
    pub src_ip:         Ipv6Addr,   // link-local of this interface
    pub prefixes:       Vec<(Ipv6Addr, u8)>, // learned from upstream router
    pub rdnss:          Vec<Ipv6Addr>,
    pub dns_lifetime:   u32,
    pub router_lifetime: u16,       // 0 = suppress (for other-router RA)
    pub managed:        bool,       // M flag
    pub other:          bool,       // O flag
    pub preference:     Preference,
    pub mtu:            Option<u32>,
}

/// Build a complete RA ethernet frame (Ethernet + IPv6 + ICMPv6)
pub fn build_ra_frame(p: &RaParams) -> Vec<u8> {
    let mut icmp = build_ra_icmpv6(p);
    let checksum = icmpv6_checksum(&p.src_ip, &ALL_NODES, &icmp);
    icmp[2] = (checksum >> 8) as u8;
    icmp[3] = (checksum & 0xff) as u8;

    let mut ip = build_ipv6_header(p.src_ip, ALL_NODES, icmp.len() as u16);
    ip.extend_from_slice(&icmp);

    let mut eth = build_eth_header(p.src_mac);
    eth.extend_from_slice(&ip);
    eth
}

/// Build just the ICMPv6 RA body (checksum bytes left as 0x0000)
fn build_ra_icmpv6(p: &RaParams) -> Vec<u8> {
    let mut buf = Vec::new();

    // ICMPv6 type=134 (RA), code=0
    buf.push(134u8);
    buf.push(0u8);
    buf.extend_from_slice(&[0u8; 2]); // checksum placeholder

    // Cur Hop Limit=64
    buf.push(64u8);

    // Flags byte: M(7) O(6) H(5) Prf(4:3) P(2) R(1)
    let mut flags = 0u8;
    if p.managed    { flags |= 0x80; }
    if p.other      { flags |= 0x40; }
    flags |= p.preference as u8;
    buf.push(flags);

    // Router Lifetime
    buf.extend_from_slice(&p.router_lifetime.to_be_bytes());

    // Reachable Time = 0 (unspecified)
    buf.extend_from_slice(&0u32.to_be_bytes());

    // Retrans Timer = 0 (unspecified)
    buf.extend_from_slice(&0u32.to_be_bytes());

    // Option: Source Link-Layer Address (type=1)
    buf.push(1u8);
    buf.push(1u8); // len in 8-byte units
    buf.extend_from_slice(&p.src_mac);

    // Option: MTU (type=5) if provided
    if let Some(mtu) = p.mtu {
        buf.push(5u8);
        buf.push(1u8);
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&mtu.to_be_bytes());
    }

    // Options: Prefix Information (type=3), one per prefix
    for (prefix, prefix_len) in &p.prefixes {
        buf.push(3u8);
        buf.push(4u8); // len = 4 × 8 = 32 bytes
        buf.push(*prefix_len);
        // L=1 (on-link), A=1 (autonomous address config)
        buf.push(0xC0u8);
        // Valid lifetime = 86400s (1 day)
        buf.extend_from_slice(&86400u32.to_be_bytes());
        // Preferred lifetime = 14400s (4 hours)
        buf.extend_from_slice(&14400u32.to_be_bytes());
        // Reserved
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&prefix.octets());
    }

    // Option: RDNSS (type=25, RFC 8106)
    if !p.rdnss.is_empty() {
        buf.push(25u8);
        // len = 1 + (number of addresses)
        buf.push((1 + p.rdnss.len()) as u8);
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&p.dns_lifetime.to_be_bytes());
        for dns in &p.rdnss {
            buf.extend_from_slice(&dns.octets());
        }
    }

    buf
}

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

fn build_eth_header(src_mac: [u8; 6]) -> Vec<u8> {
    let mut h = Vec::with_capacity(14);
    // dst: 33:33:00:00:00:01 (IPv6 all-nodes multicast)
    h.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    h.extend_from_slice(&src_mac);
    h.extend_from_slice(&[0x86, 0xdd]); // IPv6 ethertype
    h
}

fn build_ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, payload_len: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(40);
    h.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, TC=0, flow=0
    h.extend_from_slice(&payload_len.to_be_bytes());
    h.push(58u8);  // next header = ICMPv6
    h.push(255u8); // hop limit = 255 (required for RA)
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

/// RFC 2460 / RFC 4443 ICMPv6 checksum over pseudo-header
fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src, dst, length (u32), zeros, next-header=58
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += icmp.len() as u32;
    sum += 58u32; // next header

    // ICMPv6 body
    let mut i = 0;
    while i + 1 < icmp.len() {
        sum += u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp.len() {
        sum += (icmp[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
