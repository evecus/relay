//! DHCPv4 lease persistence

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub expires_at: u64, // unix timestamp
    pub is_static: bool,
}

impl Lease {
    pub fn is_expired(&self) -> bool {
        if self.is_static {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }

    #[allow(dead_code)]
    pub fn remaining(&self) -> Duration {
        if self.is_static {
            return Duration::from_secs(u32::MAX as u64);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            Duration::from_secs(self.expires_at - now)
        }
    }
}

pub fn parse_lease_time(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        return Ok(Duration::from_secs(h.parse::<u64>()? * 3600));
    }
    if let Some(m) = s.strip_suffix('m') {
        return Ok(Duration::from_secs(m.parse::<u64>()? * 60));
    }
    if let Some(sec) = s.strip_suffix('s') {
        return Ok(Duration::from_secs(sec.parse::<u64>()?));
    }
    Ok(Duration::from_secs(s.parse::<u64>()?))
}

pub struct LeaseStore {
    /// mac (as hex string) → Lease
    leases: HashMap<String, Lease>,
    path: String,
}

impl LeaseStore {
    pub fn load(path: &str) -> Result<Self> {
        let leases = if Path::new(path).exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Self {
            leases,
            path: path.to_string(),
        })
    }

    pub fn mac_key(mac: &[u8; 6]) -> String {
        mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    pub fn get_by_mac(&self, mac: &[u8; 6]) -> Option<&Lease> {
        self.leases.get(&Self::mac_key(mac))
    }

    #[allow(dead_code)]
    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&Lease> {
        self.leases.values().find(|l| l.ip == ip)
    }

    pub fn insert(&mut self, lease: Lease) -> Result<()> {
        let key = Self::mac_key(&lease.mac);
        self.leases.insert(key, lease);
        self.flush()
    }

    pub fn remove_by_mac(&mut self, mac: &[u8; 6]) -> Result<()> {
        self.leases.remove(&Self::mac_key(mac));
        self.flush()
    }

    pub fn all_active(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values().filter(|l| !l.is_expired())
    }

    pub fn flush(&self) -> Result<()> {
        if let Some(parent) = Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.leases)?;
        std::fs::write(&self.path, data)
            .with_context(|| format!("Failed to write lease file {}", self.path))
    }
}
