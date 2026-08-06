use crate::config::Config;
use crate::dns::hosts::DynamicHosts;
use crate::dns::router::Router;
use crate::firewall::FirewallGuard;
use crate::stats::{persistence::StatsPersistence, StatsCollector};
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const RESOLV_CONF:     &str = "/etc/resolv.conf";
const RESOLV_CONF_BAK: &str = "/etc/resolv.conf.dnsroxy.bak";
/// 查询日志保留时长（秒），约 30 天。
const QUERY_LOG_RETENTION_SECS: u64 = 30 * 24 * 3600;
/// 计数器 flush 间隔。
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Parser, Debug)]
pub struct RunArgs {
    #[arg(short, long, default_value = "/etc/relay/config.yaml")]
    pub config: PathBuf,
}

pub async fn run(args: RunArgs) -> Result<()> {
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config.display()))?;

    // 根据配置文件 log-level 重新初始化日志（环境变量 RUST_LOG 优先）。
    crate::init_logging(config.log_level);

    info!("Starting relay on {}", config.listen);

    // Warn if plain UDP upstreams are used with firewall redirect
    if config.firewall.as_ref().map(|f| f.enable).unwrap_or(false) {
        let has_plain = config.groups.values()
            .any(|g| g.servers.iter().any(|s| s.starts_with("udp://")));
        if has_plain {
            warn!(
                "Firewall redirect enabled with UDP upstreams — \
                 this may cause routing loops. Use DoT/DoH upstreams instead."
            );
        }
    }

    // Firewall redirect
    let _firewall_guard = if let Some(ref fw) = config.firewall {
        if fw.enable {
            let port = config.listen.port();
            let uid  = unsafe { libc::getuid() };
            Some(FirewallGuard::setup(fw, port, uid)
                .context("Failed to set up firewall redirect")?)
        } else { None }
    } else { None };

    // resolv.conf management
    let _resolv_guard = if config.manage_resolv_conf {
        Some(ResolvConfGuard::install()?)
    } else { None };

    // Shared dynamic hosts (populated by DHCP leases)
    let dhcp_domain = config.dhcp
        .v4.as_ref().and_then(|v| v.domain.clone())
        .or_else(|| config.dhcp.v6.as_ref().and_then(|v| v.domain.clone()));
    let dynamic_hosts = Arc::new(DynamicHosts::new(dhcp_domain));

    // 初始化 StatsCollector + 持久化
    let stats_collector = if config.web.enable {
        let mut collector = StatsCollector::new(config.web.query_log_size);
        let persistence = if config.web.sqlite_path.as_os_str().is_empty() {
            None
        } else {
            match StatsPersistence::open(&config.web.sqlite_path, QUERY_LOG_RETENTION_SECS) {
                Ok(p) => {
                    // 启动时加载历史 totals
                    let totals = p.load_totals();
                    info!(
                        "Restored totals: queries={} blocked={} failed={} cache={} hosts={}",
                        totals.total_queries, totals.total_blocked,
                        totals.total_failed, totals.cache_hits, totals.hosts_hits
                    );
                    collector.restore_totals(
                        totals.total_queries,
                        totals.total_blocked,
                        totals.total_failed,
                        totals.cache_hits,
                        totals.hosts_hits,
                    );
                    Some(p)
                }
                Err(e) => {
                    warn!("Failed to open SQLite {}: {}. Stats will not persist.",
                          config.web.sqlite_path.display(), e);
                    None
                }
            }
        };

        // 若有持久化，绑定 channel + 启动后台 worker（attach_persistence 需要 &mut）
        if let Some(p) = persistence.clone() {
            let rx = collector.attach_persistence(p.clone());
            tokio::spawn(persistence_worker(rx, p));
        }

        // 包成 Arc 后再 clone 给后台任务（StatsCollector 内部全是 Arc/DashMap，
        // 但未实现 Clone，直接共享 Arc 即可）
        let collector: Arc<StatsCollector> = Arc::new(collector);

        // 启动定时 flush + cleanup 任务
        tokio::spawn(periodic_flush(collector.clone()));

        Some(collector)
    } else {
        None
    };

    // Build DNS router
    let router = Arc::new(
        Router::from_config(&config, dynamic_hosts.clone(), stats_collector.clone())
            .context("Failed to build DNS router")?
    );

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        wait_for_signal().await;
        let _ = shutdown_tx.send(());
    });

    // Start DNS server
    let listen_addr = config.listen;
    let dns_stats = stats_collector.clone();
    let dns_handle = tokio::spawn(async move {
        if let Err(e) = crate::dns::serve(listen_addr, router, dns_stats).await {
            tracing::error!("DNS server error: {}", e);
        }
    });

    // Start DHCP/RA if configured
    let dhcp_cfg = config.dhcp.clone();
    let dhcp_hosts = dynamic_hosts.clone();
    let dhcp_handle = tokio::spawn(async move {
        if let Err(e) = crate::dhcp::serve(dhcp_cfg, dhcp_hosts).await {
            tracing::error!("DHCP/RA error: {}", e);
        }
    });

    // Start Web panel if configured
    let web_handle = if config.web.enable {
        let web_cfg = config.web.clone();
        let web_stats = stats_collector.clone();
        // 持久化句柄也需要传给 API（用于 /api/querylog?history=true）
        let web_persistence = if web_cfg.sqlite_path.as_os_str().is_empty() {
            None
        } else {
            StatsPersistence::open(&web_cfg.sqlite_path, QUERY_LOG_RETENTION_SECS).ok()
        };
        Some(tokio::spawn(async move {
            if let Err(e) = crate::web::serve(web_cfg, web_stats.unwrap(), web_persistence).await {
                tracing::error!("Web panel error: {}", e);
            }
        }))
    } else {
        None
    };

    info!("relay running. Press Ctrl+C to stop.");

    tokio::select! {
        _ = &mut shutdown_rx => { info!("Shutdown signal received"); }
        _ = dns_handle  => { info!("DNS server exited"); }
        _ = dhcp_handle => { info!("DHCP/RA exited"); }
    }

    // 退出前 flush 一次统计到 SQLite
    if let Some(s) = &stats_collector {
        s.flush_to_persistence();
    }

    if let Some(h) = web_handle {
        h.abort();
    }

    info!("Shutting down...");
    Ok(())
}

/// 后台 worker：消费 QueryEntry channel，批量写入 SQLite。
async fn persistence_worker(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<crate::stats::QueryEntry>,
    persistence: Arc<StatsPersistence>,
) {
    while let Some(entry) = rx.recv().await {
        if let Err(e) = persistence.insert_query(&entry) {
            tracing::debug!("insert query to sqlite failed: {}", e);
        }
    }
}

/// 定时任务：每 30s flush 计数器 + 清理旧查询日志。
async fn periodic_flush(stats: Arc<StatsCollector>) {
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    // 第一次 tick 立即返回（启动时不需要立刻 flush），跳过
    ticker.tick().await;
    loop {
        ticker.tick().await;
        stats.flush_to_persistence();
        stats.cleanup_query_log();
    }
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => { info!("SIGTERM"); }
        _ = sigint.recv()  => { info!("SIGINT"); }
    }
}

struct ResolvConfGuard;

impl ResolvConfGuard {
    fn install() -> Result<Self> {
        if std::path::Path::new(RESOLV_CONF_BAK).exists() {
            warn!("Backup {} already exists (previous unclean shutdown?)", RESOLV_CONF_BAK);
        }
        if std::path::Path::new(RESOLV_CONF).exists() {
            std::fs::copy(RESOLV_CONF, RESOLV_CONF_BAK)
                .context("Failed to backup /etc/resolv.conf")?;
            info!("Backed up {} → {}", RESOLV_CONF, RESOLV_CONF_BAK);
        }
        std::fs::write(RESOLV_CONF,
            "# Generated by relay\n\
             # Original backed up at /etc/resolv.conf.dnsroxy.bak\n\
             nameserver 127.0.0.1\n")
            .context("Failed to write /etc/resolv.conf")?;
        info!("Wrote {}", RESOLV_CONF);
        Ok(Self)
    }
}

impl Drop for ResolvConfGuard {
    fn drop(&mut self) {
        if std::path::Path::new(RESOLV_CONF_BAK).exists() {
            match std::fs::copy(RESOLV_CONF_BAK, RESOLV_CONF) {
                Ok(_) => {
                    let _ = std::fs::remove_file(RESOLV_CONF_BAK);
                    info!("Restored {}", RESOLV_CONF);
                }
                Err(e) => tracing::error!("Failed to restore {}: {}", RESOLV_CONF, e),
            }
        }
    }
}
