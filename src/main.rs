mod cmd;
mod config;
mod dhcp;
mod dns;
mod firewall;
mod ruleset;
mod stats;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(name = "relay", version, about = "A full-featured DNS proxy with DHCP/RA support")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the DNS proxy (and optional DHCP/RA) server
    Run(cmd::run::RunArgs),
    /// Build a .drs ruleset from mihomo yaml or AdGuard txt
    Build(cmd::build::BuildArgs),
    /// Lookup a domain in a .drs ruleset
    Lookup(cmd::lookup::LookupArgs),
    /// Show info about a .drs ruleset
    Info(cmd::info::InfoArgs),
    /// Generate a bcrypt password hash for web auth
    HashPassword(cmd::hash_password::HashPasswordArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires an explicit CryptoProvider. Enable the `ring`
    // feature in Cargo.toml AND install it process-wide here, so that
    // ClientConfig::builder() works in the DoT/DoH upstream paths.
    // Using `ok()` because a second install() returns Err (already installed),
    // which is harmless when multiple subcommands run in the same process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // 仅对非 run 子命令使用默认 info 级别初始化日志。
    // run 子命令在加载配置后会根据 log-level 重新初始化（环境变量优先）。
    let needs_reinit = matches!(cli.command, Command::Run(_));
    if !needs_reinit {
        init_logging(config::LogLevel::Info);
    }

    match cli.command {
        Command::Run(args)         => cmd::run::run(args).await,
        Command::Build(args)       => cmd::build::build(args),
        Command::Lookup(args)      => cmd::lookup::lookup(args),
        Command::Info(args)        => cmd::info::info(args),
        Command::HashPassword(args) => cmd::hash_password::hash_password(args),
    }
}

/// 初始化 tracing subscriber。
///
/// 优先级：
/// 1. 环境变量 `RUST_LOG`（若存在且非空）
/// 2. 配置文件中的 `log-level`
///
/// 该函数只能被调用一次；若需要再次调用（如 run 子命令加载配置后覆盖默认初始化），
/// 调用方应确保 try_init 的失败被忽略。
pub fn init_logging(level: config::LogLevel) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level.as_filter()))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    // try_init 在已初始化的全局 subscriber 上返回 Err，忽略即可
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
