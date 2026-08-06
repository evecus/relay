//! DNS-over-HTTPS upstream。
//!
//! DoH 用 reqwest::Client，通过 `dns_resolver` 配置 HostResolver，让
//! reqwest 解析 DoH URL 中的域名时用 default_nameserver，而非系统
//! resolver（避免循环依赖）。
//!
//! 每个 DoH 上游一个 DohClient（持有独立的 reqwest::Client），首次
//! 查询时 lazy 构建并缓存。

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use super::resolver::HostResolver;

const DOH_TIMEOUT: Duration = Duration::from_secs(5);
const DOH_MEDIA_TYPE: &str = "application/dns-message";

/// DoH 客户端：持有 reqwest::Client（内置 H2 连接池 + 自定义 DNS resolver）。
pub struct DohClient {
    client: Client,
}

impl DohClient {
    pub async fn new(_url: &str, insecure: bool, resolver: HostResolver) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(DOH_TIMEOUT)
            .connect_timeout(DOH_TIMEOUT)
            .pool_max_idle_per_host(4)
            .https_only(true)
            // 关键：用 HostResolver 解析域名，绕过系统 resolver（避免循环依赖）
            .dns_resolver(Arc::new(resolver));

        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder
            .build()
            .context("Failed to build reqwest Client for DoH")?;
        Ok(Self { client })
    }
}

pub async fn query(client: Arc<DohClient>, url: &str, request: &Message) -> Result<Message> {
    let original_id = request.id();

    // RFC 8484 §4.2: 请求 message ID 应为 0
    let mut req_to_send = request.clone();
    req_to_send.set_id(0);
    let wire = req_to_send.to_vec()?;

    // 严格 URL 解析，缺路径补 /dns-query
    let doh_url = normalize_doh_url(url)?;

    let resp = client
        .client
        .post(doh_url.as_str())
        .header(reqwest::header::CONTENT_TYPE, DOH_MEDIA_TYPE)
        .header(reqwest::header::ACCEPT, DOH_MEDIA_TYPE)
        .body(wire)
        .send()
        .await
        .context("DoH POST failed")?;

    // RFC 8484 §4.2.1: 严格 200
    let status = resp.status();
    if status != reqwest::StatusCode::OK {
        anyhow::bail!("DoH {} returned non-200 status: {}", url, status);
    }

    let bytes = resp.bytes().await.context("DoH response body read failed")?;
    if bytes.is_empty() {
        anyhow::bail!("DoH {} returned empty body", url);
    }

    let mut msg = Message::from_bytes(&bytes).context("Failed to parse DoH DNS response")?;
    // 恢复原始 queryId
    msg.set_id(original_id);

    debug!(
        "DoH query to {} succeeded, original_id={}, answers={}",
        url,
        original_id,
        msg.answer_count()
    );

    Ok(msg)
}

/// 严格解析 DoH URL，缺路径时补 `/dns-query`。
fn normalize_doh_url(url: &str) -> Result<String> {
    let mut parsed = url::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid DoH URL {}: {}", url, e))?;

    if parsed.path() == "/" || parsed.path().is_empty() {
        parsed.set_path("/dns-query");
    }

    Ok(parsed.to_string())
}
