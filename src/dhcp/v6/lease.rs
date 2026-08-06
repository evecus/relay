//! DHCPv6 lease persistence (stateful mode)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V6Lease {
    /// DUID of the client
    pub duid: Vec<u8>,
    pub ip: Ipv6Addr,
    pub hostname: Option<String>,
    pub expires_at: u64,
}

impl V6Lease {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }
}

pub struct V6LeaseStore {
    leases: HashMap<String, V6Lease>, // duid hex → lease
    path: String,
}

impl V6LeaseStore {
    pub fn load(path: &str) -> Result<Self> {
        let leases = if Path::new(path).exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Ok(Self { leases, path: path.to_string() })
    }

    pub fn duid_key(duid: &[u8]) -> String {
        duid.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }

    pub fn get_by_duid(&self, duid: &[u8]) -> Option<&V6Lease> {
        self.leases.get(&Self::duid_key(duid))
    }

    #[allow(dead_code)]
    pub fn get_by_ip(&self, ip: Ipv6Addr) -> Option<&V6Lease> {
        self.leases.values().find(|l| l.ip == ip)
    }

    pub fn insert(&mut self, lease: V6Lease) -> Result<()> {
        let key = Self::duid_key(&lease.duid);
        self.leases.insert(key, lease);
        self.flush()
    }

    pub fn remove(&mut self, duid: &[u8]) -> Result<()> {
        self.leases.remove(&Self::duid_key(duid));
        self.flush()
    }

    pub fn all_active(&self) -> impl Iterator<Item = &V6Lease> {
        self.leases.values().filter(|l| !l.is_expired())
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.leases)?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }
}

/// IPv6 address pool for stateful DHCPv6
pub struct V6Pool {
    /// Base prefix, e.g. fd00:: with /64
    prefix: std::net::Ipv6Addr,
    prefix_len: u8,
    next_host: std::sync::atomic::AtomicU64,
    pub leases: tokio::sync::Mutex<V6LeaseStore>,
    lease_duration: Duration,
}

impl V6Pool {
    pub fn new(prefix: Ipv6Addr, prefix_len: u8, duration: Duration, store: V6LeaseStore) -> Self {
        // Start allocating from host part 0x100 to avoid well-known addresses
        Self {
            prefix,
            prefix_len,
            next_host: std::sync::atomic::AtomicU64::new(0x100),
            leases: tokio::sync::Mutex::new(store),
            lease_duration: duration,
        }
    }

    #[allow(dead_code)]
    pub fn lease_seconds(&self) -> u32 {
        self.lease_duration.as_secs() as u32
    }

    pub async fn allocate(&self, duid: &[u8]) -> Option<Ipv6Addr> {
        let leases = self.leases.lock().await;

        // Return existing active lease
        if let Some(l) = leases.get_by_duid(duid) {
            if !l.is_expired() {
                return Some(l.ip);
            }
        }
        drop(leases);

        // Allocate next host address
        let host = self.next_host.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(self.make_addr(host))
    }

    pub async fn confirm(&self, duid: Vec<u8>, ip: Ipv6Addr, hostname: Option<String>) -> Result<V6Lease> {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.lease_duration.as_secs();

        let lease = V6Lease { duid, ip, hostname, expires_at };
        let mut leases = self.leases.lock().await;
        leases.insert(lease.clone())?;
        Ok(lease)
    }

    pub async fn release(&self, duid: &[u8]) -> Result<()> {
        let mut leases = self.leases.lock().await;
        leases.remove(duid)
    }

    fn make_addr(&self, host: u64) -> Ipv6Addr {
        let p = u128::from(self.prefix);
        let mask = !((1u128 << (128 - self.prefix_len)) - 1);
        let addr = (p & mask) | (host as u128);
        Ipv6Addr::from(addr)
    }
}

pub fn parse_v6_prefix(s: &str) -> anyhow::Result<(std::net::Ipv6Addr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid IPv6 prefix: {}", s);
    }
    let addr: std::net::Ipv6Addr = parts[0].parse()?;
    let len: u8 = parts[1].parse()?;
    Ok((addr, len))
}

pub fn parse_lease_time_v6(s: &str) -> anyhow::Result<std::time::Duration> {
    super::super::v4::lease::parse_lease_time(s)
}
