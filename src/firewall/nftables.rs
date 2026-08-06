//! nftables-based DNS redirect

use super::FirewallBackend;
use crate::config::FirewallConfig;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, info};

const TABLE_NAME: &str = "dnsroxy";

pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self { Self }

    fn run_nft(&self, script: &str) -> Result<()> {
        debug!("nft script:\n{}", script);
        let output = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn nft")?
            .wait_with_output_from_stdin(script.as_bytes())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft failed: {}", stderr);
        }
        Ok(())
    }
}

// Helper trait to pipe stdin
trait WaitWithInput {
    fn wait_with_output_from_stdin(self, input: &[u8]) -> Result<std::process::Output>;
}

impl WaitWithInput for std::process::Child {
    fn wait_with_output_from_stdin(mut self, input: &[u8]) -> Result<std::process::Output> {
        use std::io::Write;
        if let Some(ref mut stdin) = self.stdin {
            stdin.write_all(input)?;
        }
        Ok(self.wait_with_output()?)
    }
}

impl FirewallBackend for NftablesBackend {
    fn setup(&self, config: &FirewallConfig, listen_port: u16, uid: u32) -> Result<()> {
        // Clean up any existing rules first
        let _ = self.cleanup();

        let mut script = format!(
            "table ip {table} {{\n",
            table = TABLE_NAME
        );
        script.push_str("    chain nat_output {\n");
        script.push_str("        type nat hook output priority -100;\n");

        if config.localhost_hijack {
            // Exclude our own process by UID to prevent routing loops
            script.push_str(&format!(
                "        meta skuid {uid} return\n",
                uid = uid
            ));
            // Redirect UDP port 53 → listen_port
            script.push_str(&format!(
                "        udp dport 53 redirect to :{port}\n",
                port = listen_port
            ));
            // Redirect TCP port 53 → listen_port
            script.push_str(&format!(
                "        tcp dport 53 redirect to :{port}\n",
                port = listen_port
            ));
            info!("nftables: localhost DNS hijack enabled (uid {} excluded)", uid);
        }

        script.push_str("    }\n");

        if config.lan_hijack {
            script.push_str("    chain nat_prerouting {\n");
            script.push_str("        type nat hook prerouting priority -100;\n");

            // Optionally restrict to specific CIDR
            let cidr_match = if let Some(ref cidr) = config.lan_cidr {
                format!("ip saddr {} ", cidr)
            } else {
                String::new()
            };

            // Optionally restrict to specific interface
            let iface_match = if let Some(ref iface) = config.lan_interface {
                format!("iifname {} ", iface)
            } else {
                String::new()
            };

            script.push_str(&format!(
                "        {iface}{cidr}udp dport 53 redirect to :{port}\n",
                iface = iface_match,
                cidr = cidr_match,
                port = listen_port
            ));
            script.push_str(&format!(
                "        {iface}{cidr}tcp dport 53 redirect to :{port}\n",
                iface = iface_match,
                cidr = cidr_match,
                port = listen_port
            ));

            info!("nftables: LAN DNS hijack enabled");
        }

        script.push_str("}\n");

        self.run_nft(&script)
    }

    fn cleanup(&self) -> Result<()> {
        let output = Command::new("nft")
            .args(["delete", "table", "ip", TABLE_NAME])
            .output();

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(_) => Ok(()), // Table didn't exist, that's fine
            Err(e) => {
                tracing::warn!("Failed to run nft cleanup: {}", e);
                Ok(()) // Best effort
            }
        }
    }
}
