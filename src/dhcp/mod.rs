pub mod ra;
pub mod v4;
pub mod v6;

use crate::config::DhcpConfig;
use crate::dns::hosts::DynamicHosts;
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

/// Start all enabled DHCP/RA services.
///
/// If no DHCP/RA service is enabled in the config, this future parks
/// forever instead of returning immediately. Otherwise the caller
/// (run.rs) uses `tokio::select!` on this future and would tear down
/// the whole process the moment it completes — an empty config must
/// not be able to kill the DNS server.
pub async fn serve(config: DhcpConfig, dynamic_hosts: Arc<DynamicHosts>) -> Result<()> {
    let mut handles = Vec::new();

    if config.v4.as_ref().map(|c| c.enable).unwrap_or(false) {
        let cfg = config.v4.clone().unwrap();
        let hosts = dynamic_hosts.clone();
        info!("Starting DHCPv4 on interface {}", cfg.interface);
        handles.push(tokio::spawn(async move {
            if let Err(e) = v4::server::serve(cfg, hosts).await {
                tracing::error!("DHCPv4 server error: {}", e);
            }
        }));
    }

    if config.v6.as_ref().map(|c| c.enable).unwrap_or(false) {
        let cfg = config.v6.clone().unwrap();
        let hosts = dynamic_hosts.clone();
        info!("Starting DHCPv6 on interface {}", cfg.interface);
        handles.push(tokio::spawn(async move {
            if let Err(e) = v6::server::serve(cfg, hosts).await {
                tracing::error!("DHCPv6 server error: {}", e);
            }
        }));
    }

    if config.ra.as_ref().map(|c| c.enable).unwrap_or(false) {
        let cfg = config.ra.clone().unwrap();
        info!("Starting RA daemon on interface {}", cfg.interface);
        handles.push(tokio::spawn(async move {
            if let Err(e) = ra::sender::serve(cfg).await {
                tracing::error!("RA daemon error: {}", e);
            }
        }));
    }

    if handles.is_empty() {
        // Nothing to do. Park forever so the caller's tokio::select!
        // only fires on shutdown signal or DNS server exit, not on
        // an empty DHCP config.
        info!("No DHCP/RA services enabled — parking");
        std::future::pending::<()>().await;
    } else {
        futures::future::join_all(handles).await;
    }
    Ok(())
}
