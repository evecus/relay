//! DNS 查询统计与查询日志采集。
//!
//! 设计目标：
//!   - 采集路径零阻塞（AtomicU64 / DashMap 细粒度锁）
//!   - 查询日志写入 ring buffer（内存），同时异步落 SQLite
//!   - 计数器定期 flush 到 SQLite，重启后累加保留
//!
//! 数据流：
//!   listener ─► record_query(QueryEntry)
//!                  ├─► atomic 计数器 + dashmap 分桶（实时）
//!                  └─► ring buffer + 异步 channel ─► SQLite（持久化）
//!
//! 暴露：
//!   - snapshot_stats() / snapshot_upstreams() / ... 给 JSON API
//!   - prometheus_text() 给 /metrics

pub mod persistence;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// 单条查询日志记录。
#[derive(Debug, Clone, Serialize)]
pub struct QueryEntry {
    pub id: String,
    pub time: DateTime<Utc>,
    pub client: IpAddr,
    pub domain: String,
    pub qtype: String,
    /// 本次命中的处理来源（cache / hosts / strategy / 规则upstream名 / default）。
    pub upstream: String,
    /// 首次解析时使用的上游名，用于 upstream_stats 归因。
    /// 缓存命中时 upstream="cache"，但 original_upstream 仍为真实上游。
    pub original_upstream: String,
    pub rcode: String,
    /// 端到端延迟（含缓存/规则匹配/上游），用于查询日志展示。
    pub latency_ms: f32,
    /// 仅上游 DNS 查询耗时（毫秒）。None 表示未走上游（cache/hosts/strategy/rcode拦截）。
    /// 用于 upstream_stats 的延迟统计，比 latency_ms 更准确。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_latency_ms: Option<f32>,
    pub rule: Option<String>,
    pub cached: bool,
    /// true 表示被主动拦截（rcode:// 类上游），与 failed（真正网络失败）完全区分。
    pub blocked: bool,
}

/// 单个上游的统计快照。
#[derive(Debug, Clone, Serialize, Default)]
pub struct UpstreamStat {
    pub queries: u64,
    pub success: u64,
    pub failed: u64,
    /// 延迟 EMA（毫秒），便于排序"最快上游"。
    pub latency_ema_ms: f64,
    /// 最近一次延迟（毫秒）。
    pub last_latency_ms: f64,
}

/// 总览计数器（用于仪表盘卡片）。
#[derive(Debug, Clone, Serialize, Default)]
pub struct StatsSnapshot {
    pub total_queries: u64,
    pub total_blocked: u64,
    pub total_failed: u64,
    pub cache_hits: u64,
    pub hosts_hits: u64,
    /// 全局平均延迟（毫秒，EMA）。
    pub avg_latency_ms: f64,
    pub started_at: DateTime<Utc>,
    pub by_type: Vec<(String, u64)>,
    pub by_rcode: Vec<(String, u64)>,
}

/// 全局统计采集器。注入到 Router，由 listener 调用 record_query。
pub struct StatsCollector {
    // 总览原子计数器
    total_queries: AtomicU64,
    total_blocked: AtomicU64,
    total_failed: AtomicU64,
    cache_hits: AtomicU64,
    hosts_hits: AtomicU64,
    /// 延迟 EMA ×1000（用 AtomicU64 模拟浮点累加，避免浮点原子缺失）。
    latency_ema_micros_x1000: AtomicU64,

    started_at: DateTime<Utc>,

    // 分桶
    by_type: DashMap<String, AtomicU64>,
    by_rcode: DashMap<String, AtomicU64>,
    upstream_stats: DashMap<String, UpstreamStatInner>,
    rule_stats: DashMap<String, AtomicU64>,
    client_stats: DashMap<IpAddr, AtomicU64>,

    // 查询日志 ring buffer（读多写少，用 RwLock 保护 VecDeque）
    query_log: RwLock<VecDeque<QueryEntry>>,
    query_log_capacity: usize,

    // 持久化：异步 channel 把 QueryEntry 发给后台 worker 写 SQLite
    log_tx: Option<mpsc::UnboundedSender<QueryEntry>>,
    persistence: Option<Arc<persistence::StatsPersistence>>,
}

#[derive(Default)]
struct UpstreamStatInner {
    queries: AtomicU64,
    success: AtomicU64,
    failed: AtomicU64,
    /// 延迟 EMA（微秒×1000）。
    latency_ema_micros_x1000: AtomicU64,
    last_latency_micros: AtomicU64,
}

impl StatsCollector {
    pub fn new(query_log_capacity: usize) -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            hosts_hits: AtomicU64::new(0),
            latency_ema_micros_x1000: AtomicU64::new(0),
            started_at: Utc::now(),
            by_type: DashMap::new(),
            by_rcode: DashMap::new(),
            upstream_stats: DashMap::new(),
            rule_stats: DashMap::new(),
            client_stats: DashMap::new(),
            query_log: RwLock::new(VecDeque::with_capacity(query_log_capacity)),
            query_log_capacity,
            log_tx: None,
            persistence: None,
        }
    }

    /// 绑定持久化层：启动后台 worker，把查询日志异步写入 SQLite。
    pub fn attach_persistence(
        &mut self,
        persistence: Arc<persistence::StatsPersistence>,
    ) -> mpsc::UnboundedReceiver<QueryEntry> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.log_tx = Some(tx);
        self.persistence = Some(persistence);
        rx
    }

    /// 记录一次 DNS 查询。必须在 router.resolve 之后调用。
    pub fn record_query(&self, mut entry: QueryEntry) {
        // 1. 总览计数器
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // blocked（主动拦截）与 failed（真正失败）完全互斥：
        //   blocked = true  → 命中 rcode:// 类上游，计入 total_blocked，不计入 total_failed
        //   blocked = false，rcode 非正常 → 真正失败，计入 total_failed
        if entry.blocked {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
        } else if entry.rcode != "NOERROR" && entry.rcode != "Empty" {
            self.total_failed.fetch_add(1, Ordering::Relaxed);
        }

        if entry.cached {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        if entry.upstream == "hosts" || entry.upstream == "dynamic-hosts" {
            self.hosts_hits.fetch_add(1, Ordering::Relaxed);
        }

        // 2. 全局平均延迟 EMA（α=0.1）。
        //    只计入真实 DNS 查询的延迟：有 upstream_latency_ms 且不是拦截/strategy 的条目。
        //    缓存命中（0ms）、rcode 拦截、strategy 抑制均不参与全局延迟统计，避免拉低均值。
        if let Some(up_lat) = entry.upstream_latency_ms {
            if !entry.blocked {
                let latency_micros_x1000 = (up_lat * 1000.0 * 1000.0) as u64;
                update_ema(&self.latency_ema_micros_x1000, latency_micros_x1000);
            }
        }

        // 3. 分桶
        bump(&self.by_type, entry.qtype.clone());
        bump(&self.by_rcode, entry.rcode.clone());
        bump(&self.client_stats, entry.client);

        // 4. 上游统计：始终用 original_upstream 归因，而不是 "cache"。
        //    这样缓存命中的条目仍归属到首次解析时的真实上游（如 "ads"、"default"）。
        //    strategy / hosts / dynamic-hosts 等非 DNS 来源也如实记录。
        //
        //    成功判定：
        //      - 拦截（blocked）: 不算 success 也不算 failed（单独由 total_blocked 统计）
        //      - 真实查询：rcode == NOERROR 算 success，其余算 failed
        //
        //    延迟：只对非拦截、有 upstream_latency_ms 的条目计入上游延迟 EMA。
        let upstream_key = entry.original_upstream.clone();
        if !upstream_key.is_empty()
            && upstream_key != "strategy"
            && upstream_key != "hosts"
            && upstream_key != "dynamic-hosts"
        {
            let success = !entry.blocked && entry.rcode == "NOERROR";
            // 拦截类不参与 failed 计数，传 None 表示"中性"；真实失败才 failed+1
            let record_as_failed = !entry.blocked && entry.rcode != "NOERROR" && entry.rcode != "Empty";
            // 延迟：仅真实 DNS 查询（非拦截，有 upstream_latency_ms）
            let latency_micros = if !entry.blocked {
                entry.upstream_latency_ms.map(|ms| (ms * 1000.0) as u64)
            } else {
                None
            };
            self.upstream_stats
                .entry(upstream_key)
                .or_default()
                .record(success, record_as_failed, latency_micros);
        }

        // 5. 规则命中
        if let Some(rule) = &entry.rule {
            bump(&self.rule_stats, rule.clone());
        }

        // 6. ring buffer
        {
            let mut log = self.query_log.write();
            if log.len() >= self.query_log_capacity {
                log.pop_front();
            }
            if entry.id.is_empty() {
                entry.id = uuid::Uuid::new_v4().to_string();
            }
            log.push_back(entry.clone());
        }

        // 7. 异步落 SQLite
        if let Some(tx) = &self.log_tx {
            if tx.send(entry).is_err() {
                debug!("stats persistence channel closed");
            }
        }
    }

    /// 取总览快照。
    pub fn snapshot_stats(&self) -> StatsSnapshot {
        let by_type = self
            .by_type
            .iter()
            .map(|r| (r.key().clone(), r.value().load(Ordering::Relaxed)))
            .collect::<Vec<_>>();
        let by_rcode = self
            .by_rcode
            .iter()
            .map(|r| (r.key().clone(), r.value().load(Ordering::Relaxed)))
            .collect::<Vec<_>>();

        StatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            total_failed: self.total_failed.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            hosts_hits: self.hosts_hits.load(Ordering::Relaxed),
            avg_latency_ms: self.latency_ema_micros_x1000.load(Ordering::Relaxed) as f64
                / 1000.0
                / 1000.0,
            started_at: self.started_at,
            by_type,
            by_rcode,
        }
    }

    /// 取所有上游统计快照（按查询数降序）。
    pub fn snapshot_upstreams(&self) -> Vec<(String, UpstreamStat)> {
        let mut v: Vec<(String, UpstreamStat)> = self
            .upstream_stats
            .iter()
            .map(|r| {
                let inner = r.value();
                (
                    r.key().clone(),
                    UpstreamStat {
                        queries: inner.queries.load(Ordering::Relaxed),
                        success: inner.success.load(Ordering::Relaxed),
                        failed: inner.failed.load(Ordering::Relaxed),
                        latency_ema_ms: inner.latency_ema_micros_x1000.load(Ordering::Relaxed)
                            as f64
                            / 1000.0
                            / 1000.0,
                        last_latency_ms: inner.last_latency_micros.load(Ordering::Relaxed) as f64
                            / 1000.0,
                    },
                )
            })
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1.queries));
        v
    }

    /// 取规则命中排行（降序）。
    pub fn snapshot_rules(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .rule_stats
            .iter()
            .map(|r| (r.key().clone(), r.value().load(Ordering::Relaxed)))
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v
    }

    /// 取客户端排行（降序，Top N）。
    pub fn snapshot_clients(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let mut v: Vec<(IpAddr, u64)> = self
            .client_stats
            .iter()
            .map(|r| (*r.key(), r.value().load(Ordering::Relaxed)))
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(limit);
        v
    }

    /// 取查询日志（最新 limit 条，倒序）。
    pub fn snapshot_query_log(&self, limit: usize) -> Vec<QueryEntry> {
        let log = self.query_log.read();
        let take = limit.min(log.len());
        log.iter().rev().take(take).cloned().collect()
    }

    /// 累加历史计数器（启动时从 SQLite 加载）。
    pub fn restore_totals(
        &self,
        total_queries: u64,
        total_blocked: u64,
        total_failed: u64,
        cache_hits: u64,
        hosts_hits: u64,
    ) {
        self.total_queries.store(total_queries, Ordering::Relaxed);
        self.total_blocked.store(total_blocked, Ordering::Relaxed);
        self.total_failed.store(total_failed, Ordering::Relaxed);
        self.cache_hits.store(cache_hits, Ordering::Relaxed);
        self.hosts_hits.store(hosts_hits, Ordering::Relaxed);
    }

    /// 把内存计数器 flush 到 SQLite（用于退出时与定时 flush）。
    pub fn flush_to_persistence(&self) {
        if let Some(p) = &self.persistence {
            if let Err(e) = p.flush_totals(self.snapshot_stats()) {
                warn!("flush totals to sqlite failed: {}", e);
            }
        }
    }

    /// 清理 SQLite 中超过保留期的旧查询日志。
    pub fn cleanup_query_log(&self) {
        if let Some(p) = &self.persistence {
            if let Err(e) = p.cleanup_old() {
                debug!("cleanup old query_log failed: {}", e);
            }
        }
    }
}

impl UpstreamStatInner {
    /// - `success`: true → success+1
    /// - `record_as_failed`: true → failed+1（拦截时两者都 false，仅 queries+1）
    /// - `latency_micros`: Some → 计入延迟 EMA；None → 不更新延迟（拦截/缓存等情况）
    fn record(&self, success: bool, record_as_failed: bool, latency_micros: Option<u64>) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success.fetch_add(1, Ordering::Relaxed);
        } else if record_as_failed {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(lat) = latency_micros {
            self.last_latency_micros.store(lat, Ordering::Relaxed);
            update_ema(&self.latency_ema_micros_x1000, lat * 1000);
        }
    }
}

/// 通用分桶自增。
fn bump<K: std::hash::Hash + Eq + Clone>(map: &DashMap<K, AtomicU64>, key: K) {
    map.entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// EMA 原子更新（α=0.1）。
fn update_ema(slot: &AtomicU64, observed_x1000: u64) {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
        let next = if current == 0 {
            observed_x1000
        } else {
            // α=0.1：EMA_new = 0.1·x + 0.9·EMA_old
            // 都乘了 1000，所以：0.1·observed + 0.9·current
            (observed_x1000 / 10) + (current * 9 / 10)
        };
        match slot.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

/// 把 hickory ResponseCode 转成可读字符串（用于日志与统计）。
pub fn rcode_name(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::YXDomain => "YXDOMAIN",
        ResponseCode::YXRRSet => "YXRRSET",
        ResponseCode::NXRRSet => "NXRRSET",
        ResponseCode::NotAuth => "NOTAUTH",
        ResponseCode::NotZone => "NOTZONE",
        _ => "OTHER",
    }
}

/// 把 RecordType 转成可读字符串。
pub fn qtype_name(t: RecordType) -> String {
    format!("{:?}", t).to_uppercase()
}
