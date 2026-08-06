//! macOS pf-based DNS redirect

use super::FirewallBackend;
use crate::config::FirewallConfig;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::info;

const ANCHOR_NAME: &str = "dnsroxy";
const ANCHOR_FILE: &str = "/etc/pf.anchors/dnsroxy";

pub struct PfBackend;

impl PfBackend {
    pub fn new() -> Self { Self }
}

impl FirewallBackend for PfBackend {
    fn setup(&self, config: &FirewallConfig, listen_port: u16, _uid: u32) -> Result<()> {
        let _ = self.cleanup();

        let mut rules = String::new();

        if config.localhost_hijack {
            rules.push_str(&format!(
                "rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port {}\n",
                listen_port
            ));
            rules.push_str(&format!(
                "rdr pass on lo0 proto tcp from any to any port 53 -> 127.0.0.1 port {}\n",
                listen_port
            ));
            info!("pf: localhost DNS hijack enabled");
        }

        if config.lan_hijack {
            let iface = config.lan_interface.as_deref().unwrap_or("en0");
            rules.push_str(&format!(
                "rdr pass on {} proto udp from any to any port 53 -> 127.0.0.1 port {}\n",
                iface, listen_port
            ));
            rules.push_str(&format!(
                "rdr pass on {} proto tcp from any to any port 53 -> 127.0.0.1 port {}\n",
                iface, listen_port
            ));
            info!("pf: LAN DNS hijack enabled on {}", iface);
        }

        std::fs::write(ANCHOR_FILE, &rules)
            .context("Failed to write pf anchor file")?;

        // Load the anchor
        Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-f", ANCHOR_FILE])
            .output()
            .context("Failed to load pf anchor")?;

        // Enable pf if not already
        let _ = Command::new("pfctl").args(["-e"]).output();

        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        // Flush the anchor
        let _ = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-F", "all"])
            .output();

        let _ = std::fs::remove_file(ANCHOR_FILE);
        Ok(())
    }
}
