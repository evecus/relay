//! Web API 端点。
//!
//! 路由：
//!   GET /api/stats      总览计数器
//!   GET /api/upstreams  上游延迟/成功率
//!   GET /api/rules      规则命中排行
//!   GET /api/clients    客户端 Top N
//!   GET /api/querylog   查询日志（?limit=&domain=&client=）
//!   GET /api/dashboard  一次返回全部门面数据
//!   GET /metrics        Prometheus 文本格式

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::stats::{QueryEntry, StatsCollector, StatsSnapshot, UpstreamStat};

/// API 共享状态：Arc<StatsCollector> + 可选持久化句柄。
#[derive(Clone)]
pub struct ApiState {
    pub stats: Arc<StatsCollector>,
    pub persistence: Option<Arc<crate::stats::persistence::StatsPersistence>>,
}

#[derive(Debug, Deserialize)]
pub struct QueryLogParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub domain: Option<String>,
    pub client: Option<String>,
    /// 是否从 SQLite 查询历史（默认只查内存 ring buffer）。
    #[serde(default)]
    pub history: bool,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct ClientsParams {
    #[serde(default = "default_clients_limit")]
    pub limit: usize,
}

fn default_clients_limit() -> usize {
    20
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub stats: StatsSnapshot,
    pub upstreams: Vec<(String, UpstreamStat)>,
    pub rules: Vec<(String, u64)>,
    pub clients: Vec<(String, u64)>,
    pub recent_queries: Vec<QueryEntry>,
}

/// GET /api/stats
pub async fn stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.stats.snapshot_stats())
}

/// GET /api/upstreams
pub async fn upstreams(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.stats.snapshot_upstreams())
}

/// GET /api/rules
pub async fn rules(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.stats.snapshot_rules())
}

/// GET /api/clients?limit=20
pub async fn clients(
    State(state): State<ApiState>,
    Query(params): Query<ClientsParams>,
) -> impl IntoResponse {
    let rows = state.stats.snapshot_clients(params.limit);
    // IpAddr 不直接 serde 成字符串方便前端，转成 (String, u64)
    let out: Vec<(String, u64)> = rows.into_iter().map(|(ip, n)| (ip.to_string(), n)).collect();
    Json(out)
}

/// GET /api/querylog?limit=100&domain=&client=&history=false
pub async fn querylog(
    State(state): State<ApiState>,
    Query(params): Query<QueryLogParams>,
) -> impl IntoResponse {
    if params.history {
        // 从 SQLite 查询历史
        match &state.persistence {
            Some(p) => match p.query_log(params.limit, params.domain.as_deref(), params.client.as_deref()) {
                Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response(),
            },
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "persistence not configured"})),
            )
                .into_response(),
        }
    } else {
        // 只查内存 ring buffer（不支持 domain/client 筛选，前端自己过滤）
        let rows = state.stats.snapshot_query_log(params.limit);
        (StatusCode::OK, Json(rows)).into_response()
    }
}

/// GET /api/dashboard
pub async fn dashboard(State(state): State<ApiState>) -> impl IntoResponse {
    let stats = state.stats.snapshot_stats();
    let upstreams = state.stats.snapshot_upstreams();
    let rules = state.stats.snapshot_rules();
    let clients_raw = state.stats.snapshot_clients(20);
    let clients: Vec<(String, u64)> = clients_raw
        .into_iter()
        .map(|(ip, n)| (ip.to_string(), n))
        .collect();
    let recent_queries = state.stats.snapshot_query_log(50);

    Json(DashboardResponse {
        stats,
        upstreams,
        rules,
        clients,
        recent_queries,
    })
}

/// GET /metrics  (Prometheus 文本格式)
pub async fn metrics(State(state): State<ApiState>) -> impl IntoResponse {
    let snap = state.stats.snapshot_stats();
    let mut out = String::new();

    out.push_str("# HELP relay_queries_total Total DNS queries received.\n");
    out.push_str("# TYPE relay_queries_total counter\n");
    out.push_str(&format!("relay_queries_total {}\n", snap.total_queries));

    out.push_str("# HELP relay_blocked_total Total blocked queries.\n");
    out.push_str("# TYPE relay_blocked_total counter\n");
    out.push_str(&format!("relay_blocked_total {}\n", snap.total_blocked));

    out.push_str("# HELP relay_failed_total Total failed queries.\n");
    out.push_str("# TYPE relay_failed_total counter\n");
    out.push_str(&format!("relay_failed_total {}\n", snap.total_failed));

    out.push_str("# HELP relay_cache_hits_total Total cache hits.\n");
    out.push_str("# TYPE relay_cache_hits_total counter\n");
    out.push_str(&format!("relay_cache_hits_total {}\n", snap.cache_hits));

    out.push_str("# HELP relay_latency_ms_avg Average query latency in ms (EMA).\n");
    out.push_str("# TYPE relay_latency_ms_avg gauge\n");
    out.push_str(&format!("relay_latency_ms_avg {}\n", snap.avg_latency_ms));

    // 按 rcode 分桶
    out.push_str("# HELP relay_by_rcode Queries by response code.\n");
    out.push_str("# TYPE relay_by_rcode counter\n");
    for (rcode, n) in &snap.by_rcode {
        out.push_str(&format!(
            "relay_by_rcode{{rcode=\"{}\"}} {}\n",
            rcode, n
        ));
    }

    // 按 qtype 分桶
    out.push_str("# HELP relay_by_qtype Queries by query type.\n");
    out.push_str("# TYPE relay_by_qtype counter\n");
    for (qtype, n) in &snap.by_type {
        out.push_str(&format!(
            "relay_by_qtype{{qtype=\"{}\"}} {}\n",
            qtype, n
        ));
    }

    // 上游统计
    out.push_str("# HELP relay_upstream_queries Total queries per upstream.\n");
    out.push_str("# TYPE relay_upstream_queries counter\n");
    out.push_str("# HELP relay_upstream_latency_ms_avg Average latency per upstream (EMA, ms).\n");
    out.push_str("# TYPE relay_upstream_latency_ms_avg gauge\n");
    for (name, s) in state.stats.snapshot_upstreams() {
        out.push_str(&format!(
            "relay_upstream_queries{{upstream=\"{}\"}} {}\n",
            name, s.queries
        ));
        out.push_str(&format!(
            "relay_upstream_success{{upstream=\"{}\"}} {}\n",
            name, s.success
        ));
        out.push_str(&format!(
            "relay_upstream_failed{{upstream=\"{}\"}} {}\n",
            name, s.failed
        ));
        out.push_str(&format!(
            "relay_upstream_latency_ms_avg{{upstream=\"{}\"}} {}\n",
            name, s.latency_ema_ms
        ));
    }

    // 规则命中
    out.push_str("# HELP relay_rule_hits Total matches per rule.\n");
    out.push_str("# TYPE relay_rule_hits counter\n");
    for (rule, n) in state.stats.snapshot_rules() {
        out.push_str(&format!(
            "relay_rule_hits{{rule=\"{}\"}} {}\n",
            rule, n
        ));
    }

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        out,
    )
}
