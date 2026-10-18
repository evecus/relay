//! 运行时可变状态：支持配置热更新，不重启进程。
//!
//! 设计：
//!   - `RuntimeHandle` 是所有可热更新子系统的唯一入口，由 web API 持有。
//!   - `config`/`router`/`dynamic_hosts` 用 `ArcSwap` 做无锁读、写时替换。
//!     `dynamic_hosts` 是唯一权威实例：DHCP 任务、Router 都从
//!     `self.dynamic_hosts.load_full()` 拿同一份 Arc，保证租约表在热更新前后
//!     不丢失（除非 DHCP 的 search domain 变化，此时才重建一份新的）。
//!   - DNS 监听 (`listen`)、防火墙 (`firewall`)、DHCP/RA (`dhcp`) 涉及系统资源
//!     （socket bind / nftables 规则 / raw socket）。这三者都用
//!     `crate::dns::serve_abortable` / `crate::dhcp::serve_abortable`，返回真正
//!     可以逐个 abort 子任务的句柄——早期实现中曾把子任务包进一个
//!     `select!`/`join_all` future 整体返回，但 abort 外层并不会连带 abort
//!     内部 `tokio::spawn` 出来的子任务，会导致旧 socket / 网卡监听泄漏，
//!     因此热更新路径必须用这种可精确 abort 子任务的版本。
//!   - `web.listen` 与 `web.auth.{username,password_hash}`（密码单独走改密码接口）
//!     不在这里处理：apply() 中会强制沿用旧值并记录进 `ignored`，
//!     必须手动改配置文件+重启进程才生效，UI 侧标注为只读。
//!   - `base_dir`：配置中相对路径（规则集等）的解析基准，来自 `-d` 或配置文件所在目录。

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::config::{Config, DhcpConfig, FirewallConfig};
use crate::dhcp::AbortableDhcpServices;
use crate::dns::hosts::DynamicHosts;
use crate::dns::router::Router;
use crate::dns::AbortableDnsListener;
use crate::firewall::FirewallGuard;
use crate::stats::StatsCollector;

/// 一次 apply() 的结果：哪些子系统被重新应用了，供 API 返回给前端展示。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    /// 被忽略、未生效的字段（只读字段被改动，或该字段本身不支持热更新）。
    pub ignored: Vec<String>,
}

pub struct RuntimeHandle {
    pub config_path: PathBuf,
    /// 相对路径基准目录（-d 或配置文件父目录）
    pub base_dir: PathBuf,
    pub config: ArcSwap<Config>,
    pub router: ArcSwap<Router>,
    pub dynamic_hosts: ArcSwap<DynamicHosts>,
    pub stats: Arc<StatsCollector>,

    dns_listener: AsyncMutex<AbortableDnsListener>,
    firewall_guard: AsyncMutex<Option<FirewallGuard>>,
    dhcp_services: AsyncMutex<AbortableDhcpServices>,
}

impl RuntimeHandle {
    /// 启动阶段构造：绑定 DNS 监听、安装防火墙规则（若启用）、启动 DHCP/RA，
    /// 返回持有一切句柄的 RuntimeHandle。
    pub async fn start(
        config_path: PathBuf,
        base_dir: PathBuf,
        config: Config,
        stats: Arc<StatsCollector>,
    ) -> Result<Arc<Self>> {
        let dynamic_hosts = Arc::new(DynamicHosts::new(dhcp_domain_of(&config.dhcp)));

        // 上游 socket 的 fwmark 必须在任何查询发生前就位（防火墙之后才安装）
        if let Some(fw) = &config.firewall {
            crate::sockmark::set_mark(fw.fwmark);
        }

        let router = Arc::new(
            Router::from_config(&config, dynamic_hosts.clone(), Some(stats.clone()), &base_dir)
                .context("Failed to build initial DNS router")?,
        );

        let listen_addr = config.listen;
        let dns_listener = crate::dns::serve_abortable(listen_addr, router.clone(), Some(stats.clone()))
            .await
            .context("Failed to bind DNS listener")?;

        let firewall_guard = match &config.firewall {
            Some(fw) if fw.enable => {
                Some(
                    FirewallGuard::setup(fw, listen_addr.port())
                        .context("Failed to set up firewall redirect")?,
                )
            }
            _ => None,
        };

        let dhcp_services = crate::dhcp::serve_abortable(config.dhcp.clone(), dynamic_hosts.clone()).await;

        let handle = Arc::new(RuntimeHandle {
            config_path,
            base_dir,
            config: ArcSwap::from_pointee(config.clone()),
            router: ArcSwap::from(router),
            dynamic_hosts: ArcSwap::from(dynamic_hosts),
            stats,
            dns_listener: AsyncMutex::new(dns_listener),
            firewall_guard: AsyncMutex::new(firewall_guard),
            dhcp_services: AsyncMutex::new(dhcp_services),
        });

        Ok(handle)
    }

    /// 应用一份新配置：写盘 + diff + 热更新受影响的子系统。
    /// `web.listen` 与 `web.auth.{username,password_hash}` 会被忽略（沿用旧值），
    /// 并出现在返回值的 `ignored` 里。
    pub async fn apply(&self, mut new_config: Config) -> Result<ApplyReport> {
        let old_config = self.config.load_full();
        let mut report = ApplyReport::default();

        // web.listen / web.auth 只读：强制沿用旧值，即使前端传了新值也不生效。
        if new_config.web.listen != old_config.web.listen {
            report.ignored.push("web.listen".to_string());
            new_config.web.listen = old_config.web.listen;
        }
        if new_config.web.auth.username != old_config.web.auth.username
            || new_config.web.auth.password_hash != old_config.web.auth.password_hash
        {
            report.ignored.push("web.auth (use change-password API)".to_string());
            new_config.web.auth.username = old_config.web.auth.username.clone();
            new_config.web.auth.password_hash = old_config.web.auth.password_hash.clone();
        }

        new_config
            .validate()
            .context("New config failed validation")?;

        // 1. DHCP search-domain 变化 → 需要一份新的 DynamicHosts（旧租约映射会
        //    在 DHCP 重启后随续租逐步重新写入，短暂缺失可接受）。
        let dhcp_domain_changed = dhcp_domain_of(&old_config.dhcp) != dhcp_domain_of(&new_config.dhcp);
        if dhcp_domain_changed {
            let fresh = Arc::new(DynamicHosts::new(dhcp_domain_of(&new_config.dhcp)));
            self.dynamic_hosts.store(fresh);
        }

        // 2. DNS 路由相关字段变化 → 重建 Router，原子替换
        let dns_routing_changed = old_config.default_nameserver != new_config.default_nameserver
            || old_config.groups != new_config.groups
            || old_config.rulesets != new_config.rulesets
            || old_config.hosts != new_config.hosts
            || old_config.cache != new_config.cache
            || old_config.strategy != new_config.strategy;

        if dns_routing_changed || dhcp_domain_changed {
            let dynamic_hosts = self.dynamic_hosts.load_full();
            let new_router = Router::from_config(
                &new_config,
                dynamic_hosts,
                Some(self.stats.clone()),
                &self.base_dir,
            )
            .context("Failed to build new DNS router")?;
            self.router.store(Arc::new(new_router));
            report.applied.push("dns-routing".to_string());
        }

        // 3. listen 地址变化 → 重新 bind DNS 监听
        if old_config.listen != new_config.listen {
            self.rebind_dns_listener(new_config.listen).await?;
            report.applied.push("dns-listen".to_string());
        }

        // 4. firewall 变化 → 撤销旧规则，安装新规则（失败则报错，旧规则已被撤销，
        //    这是唯一无法做到"零窗口期"的地方——见前面讨论）。
        if old_config.firewall != new_config.firewall {
            self.reapply_firewall(new_config.firewall.clone(), new_config.listen.port())
                .await?;
            report.applied.push("firewall".to_string());
        }

        // 5. dhcp/ra 配置变化（含仅 search-domain 变化，因为 router 也要用新 dynamic_hosts）
        //    → 重启 DHCP/RA 任务
        if old_config.dhcp != new_config.dhcp {
            self.restart_dhcp(new_config.dhcp.clone()).await;
            report.applied.push("dhcp".to_string());
        }

        // 6. 无运行时组件可重建的字段：记录但不处理。
        if old_config.manage_resolv_conf != new_config.manage_resolv_conf {
            report.ignored.push("manage-resolv-conf (requires restart)".to_string());
        }
        if old_config.log_level != new_config.log_level {
            report.ignored.push("log-level (requires restart)".to_string());
        }

        // 落盘 + 更新内存中的"当前配置"快照
        new_config
            .save_to(&self.config_path)
            .context("Failed to save config to disk")?;
        self.config.store(Arc::new(new_config));

        Ok(report)
    }

    /// 提供给 API：读取当前生效配置的一份快照（Arc clone，便宜）。
    pub fn current_config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    async fn rebind_dns_listener(&self, new_addr: SocketAddr) -> Result<()> {
        let mut ctrl = self.dns_listener.lock().await;
        let router = self.router.load_full();
        let stats = self.stats.clone();

        // serve_abortable 内部会先 bind 再返回句柄；bind 失败直接返回 Err，
        // 此时旧监听完全没被动过，不存在"新地址绑不上导致 DNS 彻底不可用"的中间态。
        let new_listener = crate::dns::serve_abortable(new_addr, router, Some(stats))
            .await
            .with_context(|| format!("Cannot bind new DNS listen address {}", new_addr))?;

        ctrl.abort();
        *ctrl = new_listener;
        info!("DNS listener rebound to {}", new_addr);
        Ok(())
    }

    async fn reapply_firewall(&self, new_fw: Option<FirewallConfig>, listen_port: u16) -> Result<()> {
        let mut guard_slot = self.firewall_guard.lock().await;
        // take() 触发旧 guard 的 Drop（cleanup 旧规则），若新配置 enable=false 也到此为止。
        let _old_guard = guard_slot.take();

        let new_guard = match new_fw {
            Some(fw) if fw.enable => {
                Some(
                    FirewallGuard::setup(&fw, listen_port)
                        .context("Failed to apply new firewall rules (old rules already removed)")?,
                )
            }
            _ => None,
        };
        *guard_slot = new_guard;
        Ok(())
    }

    async fn restart_dhcp(&self, new_dhcp: DhcpConfig) {
        let mut ctrl = self.dhcp_services.lock().await;
        ctrl.abort();
        let dynamic_hosts = self.dynamic_hosts.load_full();
        let new_services = crate::dhcp::serve_abortable(new_dhcp, dynamic_hosts).await;
        *ctrl = new_services;
        info!("DHCP/RA services restarted with new config");
    }
}

fn dhcp_domain_of(cfg: &DhcpConfig) -> Option<String> {
    cfg.v4
        .as_ref()
        .and_then(|v| v.domain.clone())
        .or_else(|| cfg.v6.as_ref().and_then(|v| v.domain.clone()))
}
