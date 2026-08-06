//! SQLite 持久化：计数器累加表 + 查询日志表。
//!
//! 表结构：
//!   - totals(key TEXT PRIMARY KEY, value INTEGER)
//!       存总查询数、被拦截数、失败数、缓存命中数、hosts 命中数。
//!       重启后累加恢复。
//!   - query_log(id TEXT PRIMARY KEY, time TEXT, client TEXT, domain TEXT,
//!               qtype TEXT, upstream TEXT, rcode TEXT, latency_ms REAL,
//!               rule TEXT, cached INTEGER, blocked INTEGER)
//!       按时间倒序查询，支持 domain/client 筛选。
//!       定期清理超过 retention 的旧记录。
//!
//! 并发：rusqlite::Connection 不是 Sync，所以用 Mutex 包一层。
//! 后台 worker 单线程消费 channel，写入压力可控。

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::{QueryEntry, StatsSnapshot};

/// SQLite 持久化句柄。线程安全（Mutex 包 Connection）。
pub struct StatsPersistence {
    conn: Mutex<Connection>,
    /// 查询日志保留时长（秒）。超过则定期清理。
    retention_secs: u64,
}

impl StatsPersistence {
    /// 打开/创建数据库，初始化表与索引。
    pub fn open(path: &Path, retention_secs: u64) -> Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("create sqlite dir {}", parent.display())
                })?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open sqlite {}", path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS totals (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS query_log (
                id                TEXT PRIMARY KEY,
                time              TEXT NOT NULL,
                client            TEXT NOT NULL,
                domain            TEXT NOT NULL,
                qtype             TEXT NOT NULL,
                upstream          TEXT NOT NULL,
                original_upstream TEXT NOT NULL DEFAULT '',
                rcode             TEXT NOT NULL,
                latency_ms        REAL NOT NULL,
                rule              TEXT,
                cached            INTEGER NOT NULL DEFAULT 0,
                blocked           INTEGER NOT NULL DEFAULT 0
             );
             -- 兼容旧表：若 original_upstream 列不存在则添加（ALTER TABLE 忽略已存在的列）
             CREATE INDEX IF NOT EXISTS idx_query_log_time   ON query_log(time DESC);
             CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
             CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client);
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )
        .context("init sqlite schema")?;
        // 兼容旧库：尝试添加 original_upstream 列（已存在时会报错，忽略即可）
        let _ = conn.execute_batch(
            "ALTER TABLE query_log ADD COLUMN original_upstream TEXT NOT NULL DEFAULT '';"
        );

        info!(
            "SQLite stats DB opened at {} (retention={}s)",
            path.display(),
            retention_secs
        );

        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
            retention_secs,
        }))
    }

    /// 启动时加载历史 totals。
    pub fn load_totals(&self) -> TotalsSnapshot {
        let conn = self.conn.lock();
        let get = |key: &str| -> u64 {
            conn.query_row(
                "SELECT value FROM totals WHERE key = ?1",
                params![key],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| v as u64)
            .unwrap_or(0)
        };
        TotalsSnapshot {
            total_queries: get("total_queries"),
            total_blocked: get("total_blocked"),
            total_failed: get("total_failed"),
            cache_hits: get("cache_hits"),
            hosts_hits: get("hosts_hits"),
        }
    }

    /// 把内存计数器 flush 到 SQLite（覆盖写：当前内存值即累计值）。
    pub fn flush_totals(&self, snap: StatsSnapshot) -> Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let upsert = |key: &str, value: u64| -> rusqlite::Result<()> {
            tx.execute(
                "INSERT INTO totals(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value as i64],
            )?;
            Ok(())
        };
        upsert("total_queries", snap.total_queries)?;
        upsert("total_blocked", snap.total_blocked)?;
        upsert("total_failed", snap.total_failed)?;
        upsert("cache_hits", snap.cache_hits)?;
        upsert("hosts_hits", snap.hosts_hits)?;
        tx.commit()?;
        Ok(())
    }

    /// 写入一条查询日志。
    pub fn insert_query(&self, e: &QueryEntry) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO query_log
                (id, time, client, domain, qtype, upstream, original_upstream, rcode, latency_ms, rule, cached, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                e.id,
                e.time.to_rfc3339(),
                e.client.to_string(),
                e.domain,
                e.qtype,
                e.upstream,
                e.original_upstream,
                e.rcode,
                e.latency_ms as f64,
                e.rule,
                e.cached as i64,
                e.blocked as i64,
            ],
        )?;
        Ok(())
    }

    /// 查询日志（倒序，limit 上限）。
    pub fn query_log(
        &self,
        limit: usize,
        domain_filter: Option<&str>,
        client_filter: Option<&str>,
    ) -> Result<Vec<QueryEntry>> {
        let conn = self.conn.lock();
        let mut sql = String::from(
            "SELECT id, time, client, domain, qtype, upstream, original_upstream, rcode, latency_ms, rule, cached, blocked
             FROM query_log WHERE 1=1",
        );
        if domain_filter.is_some() {
            sql.push_str(" AND domain LIKE ?d");
        }
        if client_filter.is_some() {
            sql.push_str(" AND client = ?c");
        }
        sql.push_str(" ORDER BY time DESC LIMIT ?l");

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![domain_filter.map(|d| format!("%{}%", d)), client_filter, limit as i64],
            |row| {
                let id: String = row.get(0)?;
                let time_str: String = row.get(1)?;
                let client_str: String = row.get(2)?;
                let domain: String = row.get(3)?;
                let qtype: String = row.get(4)?;
                let upstream: String = row.get(5)?;
                let original_upstream: String = row.get(6)?;
                let rcode: String = row.get(7)?;
                let latency_ms: f64 = row.get(8)?;
                let rule: Option<String> = row.get(9)?;
                let cached: i64 = row.get(10)?;
                let blocked: i64 = row.get(11)?;
                let client: std::net::IpAddr = client_str
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let time = DateTime::parse_from_rfc3339(&time_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                Ok(QueryEntry {
                    id,
                    time,
                    client,
                    domain,
                    qtype,
                    upstream,
                    original_upstream,
                    rcode,
                    latency_ms: latency_ms as f32,
                    // 历史日志不持久化上游专属延迟（仅内存 EMA 用），读回时为 None
                    upstream_latency_ms: None,
                    rule,
                    cached: cached != 0,
                    blocked: blocked != 0,
                })
            },
        )?;

        let mut out = Vec::new();
        for r in rows {
            match r {
                Ok(e) => out.push(e),
                Err(e) => warn!("parse query_log row failed: {}", e),
            }
        }
        Ok(out)
    }

    /// 清理超过 retention 的旧查询日志。
    pub fn cleanup_old(&self) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - self.retention_secs as i64;
        let cutoff_dt = DateTime::<Utc>::from_timestamp(cutoff, 0).unwrap_or(Utc::now());
        let conn = self.conn.lock();
        let n = conn.execute(
            "DELETE FROM query_log WHERE time < ?1",
            params![cutoff_dt.to_rfc3339()],
        )?;
        if n > 0 {
            debug!("cleanup {} old query_log rows", n);
        }
        Ok(n)
    }
}

/// 启动时从 SQLite 加载的累计计数器。
#[derive(Debug, Clone, Default)]
pub struct TotalsSnapshot {
    pub total_queries: u64,
    pub total_blocked: u64,
    pub total_failed: u64,
    pub cache_hits: u64,
    pub hosts_hits: u64,
}
