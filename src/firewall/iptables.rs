//! iptables-based DNS redirect fallback

use super::FirewallBackend;
use crate::config::FirewallConfig;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::info;

const CHAIN_NAME: &str = "DNSROXY";

pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self { Self }

    fn ipt(&self, args: &[&str]) -> Result<bool> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .context("Failed to run iptables")?;
        Ok(output.status.success())
    }
}

impl FirewallBackend for IptablesBackend {
    fn setup(&self, config: &FirewallConfig, listen_port: u16, uid: u32) -> Result<()> {
        let _ = self.cleanup();

        // Create our chain
        self.ipt(&["-t", "nat", "-N", CHAIN_NAME])?;

        if config.localhost_hijack {
            // Skip our own UID to avoid routing loops
            self.ipt(&[
                "-t", "nat", "-A", CHAIN_NAME,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ])?;

            // Redirect UDP 53
            self.ipt(&[
                "-t", "nat", "-A", CHAIN_NAME,
                "-p", "udp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", &listen_port.to_string(),
            ])?;

            // Redirect TCP 53
            self.ipt(&[
                "-t", "nat", "-A", CHAIN_NAME,
                "-p", "tcp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", &listen_port.to_string(),
            ])?;

            // Hook into OUTPUT chain
            self.ipt(&["-t", "nat", "-A", "OUTPUT", "-j", CHAIN_NAME])?;
            info!("iptables: localhost DNS hijack enabled (uid {} excluded)", uid);
        }

        if config.lan_hijack {
            let prerouting_args = vec![
                "-t", "nat", "-A", "PREROUTING",
            ];

            let cidr_str;
            let iface_str;

            let mut extra: Vec<&str> = vec![];

            if let Some(ref iface) = config.lan_interface {
                iface_str = iface.clone();
                extra.extend(["-i", &iface_str]);
            }
            if let Some(ref cidr) = config.lan_cidr {
                cidr_str = cidr.clone();
                extra.extend(["-s", &cidr_str]);
            }

            let port_str = listen_port.to_string();
            let mut udp_args = prerouting_args.clone();
            udp_args.extend(extra.clone());
            udp_args.extend(["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &port_str]);
            self.ipt(&udp_args)?;

            let mut tcp_args = prerouting_args.clone();
            tcp_args.extend(extra.clone());
            tcp_args.extend(["-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", &port_str]);
            self.ipt(&tcp_args)?;

            info!("iptables: LAN DNS hijack enabled");
        }

        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        // Remove references from OUTPUT/PREROUTING
        let _ = self.ipt(&["-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAME]);
        let _ = self.ipt(&["-t", "nat", "-D", "PREROUTING", "-j", CHAIN_NAME]);
        // Flush and delete our chain
        let _ = self.ipt(&["-t", "nat", "-F", CHAIN_NAME]);
        let _ = self.ipt(&["-t", "nat", "-X", CHAIN_NAME]);
        Ok(())
    }
}
