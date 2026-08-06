pub mod iptables;
pub mod nftables;
pub mod pf;

use anyhow::{bail, Result};
use crate::config::FirewallConfig;
use tracing::info;

pub struct FirewallGuard {
    backend: Box<dyn FirewallBackend + Send + Sync>,
}

impl FirewallGuard {
    pub fn setup(config: &FirewallConfig, listen_port: u16, uid: u32) -> Result<Self> {
        let backend: Box<dyn FirewallBackend + Send + Sync> = match detect_backend(&config.backend)? {
            BackendKind::Nftables => Box::new(nftables::NftablesBackend::new()),
            BackendKind::Iptables => Box::new(iptables::IptablesBackend::new()),
            BackendKind::Pf => Box::new(pf::PfBackend::new()),
        };

        backend.setup(config, listen_port, uid)?;
        info!("Firewall rules installed (port 53 → {})", listen_port);

        Ok(Self { backend })
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if let Err(e) = self.backend.cleanup() {
            tracing::error!("Failed to clean up firewall rules: {}", e);
        } else {
            info!("Firewall rules removed");
        }
    }
}

pub trait FirewallBackend {
    fn setup(&self, config: &FirewallConfig, listen_port: u16, uid: u32) -> Result<()>;
    fn cleanup(&self) -> Result<()>;
}

#[derive(Debug)]
enum BackendKind {
    Nftables,
    Iptables,
    Pf,
}

fn detect_backend(preference: &str) -> Result<BackendKind> {
    match preference {
        "nftables" => return Ok(BackendKind::Nftables),
        "iptables" => return Ok(BackendKind::Iptables),
        "pf" => return Ok(BackendKind::Pf),
        "auto" => {}
        other => bail!("Unknown firewall backend: {}", other),
    }

    // Auto-detect
    if cfg!(target_os = "macos") {
        return Ok(BackendKind::Pf);
    }

    // Linux: prefer nftables, fall back to iptables
    if which_exists("nft") {
        return Ok(BackendKind::Nftables);
    }
    if which_exists("iptables") {
        return Ok(BackendKind::Iptables);
    }

    bail!("No supported firewall backend found (tried nftables, iptables)")
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
