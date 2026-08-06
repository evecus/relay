//! Rule-based DNS router: hosts → ruleset rules → default upstream

use crate::config::{Config, IpStrategy};
use crate::dns::cache::DnsCache;
use crate::dns::hosts::{DynamicHosts, HostsTable};
use crate::dns::upstream::{HostResolver, UpstreamGroup};
use crate::ruleset::DrsFile;
use crate::stats::StatsCollector;
use anyhow::{bail, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use indexmap::IndexMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct LoadedRule {
    pub ruleset: DrsFile,
    pub upstream: String,
}

/// 单次 resolve 的元信息，供 listener 记录统计。
/// 由 router 在各分支填好，listener 补 client/latency 后调用 stats.record_query。
#[derive(Debug, Clone, Default)]
pub struct ResolveMeta {
    pub domain: String,
    pub qtype: String,
    /// 本次命中的处理来源（cache / hosts / dynamic-hosts / strategy / 规则upstream名 / default）。
    pub upstream: String,
    /// 缓存命中时，记录原始上游名称（即首次解析时用的上游），用于 upstream_stats 归因。
    /// 非缓存命中时与 upstream 相同。
    pub original_upstream: String,
    pub rcode: String,
    pub rule: Option<String>,
    pub cached: bool,
    /// true 表示该查询被主动拦截（命中 rcode:// 类上游，如 refused/nxdomain/servfail）。
    /// 与 failed（真正网络/解析失败）完全区分。
    pub blocked: bool,
    /// 真正花在上游 DNS 上的延迟（毫秒）。
    /// None 表示没走上游（cache/hosts/strategy 短路 或 rcode 拦截）。
    pub upstream_latency_ms: Option<f32>,
}

#[allow(dead_code)]
pub struct Router {
    hosts: HostsTable,
    rules: Vec<LoadedRule>,
    upstreams: IndexMap<String, Arc<UpstreamGroup>>,
    cache: Option<Arc<DnsCache>>,
    strategy: IpStrategy,
    dynamic_hosts: Arc<DynamicHosts>,
    stats: Option<Arc<StatsCollector>>,
}

impl Router {
    pub fn from_config(
        config: &Config,
        dynamic_hosts: Arc<DynamicHosts>,
        stats: Option<Arc<StatsCollector>>,
    ) -> Result<Self> {
        // 构造 HostResolver（用 default_nameserver 解析上游域名）
        let resolver = HostResolver::new(config.default_nameserver.clone());

        // Build upstream groups
        let mut upstreams = IndexMap::new();
        for (name, group_cfg) in &config.groups {
            let servers = group_cfg
                .servers
                .iter()
                .map(|url| crate::dns::upstream::UpstreamServer::parse(url, group_cfg, resolver.clone()))
                .collect::<Result<Vec<_>>>()?;
            let group = UpstreamGroup::new(servers, group_cfg.strategy.clone());
            upstreams.insert(name.clone(), Arc::new(group));
        }

        // Load rulesets（每个 entry 是一个 (path, upstream) 对）
        let mut rules = Vec::new();
        for entry in &config.rulesets {
            let drs = DrsFile::load(&entry.path).map_err(|e| {
                anyhow::anyhow!("Failed to load ruleset {}: {}", entry.path.display(), e)
            })?;
            info!(
                "Loaded ruleset {} ({} domains, {} suffixes) → upstream {}",
                entry.path.display(),
                drs.domain_count,
                drs.suffix_count,
                entry.upstream
            );
            rules.push(LoadedRule {
                ruleset: drs,
                upstream: entry.upstream.clone(),
            });
        }

        let hosts = HostsTable::new(&config.hosts);

        let cache = if config.cache.enable {
            Some(Arc::new(DnsCache::new(
                config.cache.size,
                config.cache.min_ttl,
                config.cache.max_ttl,
            )))
        } else {
            None
        };

        let strategy = config.strategy.clone();
        if strategy != IpStrategy::Default {
            info!("IP strategy: {:?}", strategy);
        }

        Ok(Self { hosts, rules, upstreams, cache, strategy, dynamic_hosts, stats })
    }

    pub async fn resolve(&self, request: &Message) -> Result<Message> {
    #[allow(dead_code)]
        let (msg, _meta) = self.resolve_with_meta(request).await?;
        Ok(msg)
    }

    /// 解析并返回元信息（供 listener 记录统计）。
    pub async fn resolve_with_meta(&self, request: &Message) -> Result<(Message, ResolveMeta)> {
    #[allow(dead_code)]
        let query = match request.queries().first() {
            Some(q) => q,
            None => bail!("Empty DNS query"),
        };

        let name = query.name().to_string();
        let qtype = query.query_type();
        let id = request.id();
        let qtype_str = crate::stats::qtype_name(qtype);

        debug!("Query: {} {:?}", name, qtype);

        // Apply IP strategy: intercept A/AAAA queries before any processing
        match self.strategy {
            IpStrategy::OnlyIpv4 if qtype == RecordType::AAAA => {
                debug!("Strategy only_ipv4: suppressing AAAA query for {}", name);
                let meta = ResolveMeta {
                    domain: name.clone(),
                    qtype: qtype_str,
                    upstream: "strategy".to_string(),
                    original_upstream: "strategy".to_string(),
                    rcode: "Empty".to_string(),
                    ..Default::default()
                };
                return Ok((empty_noerror(request), meta));
            }
            IpStrategy::OnlyIpv6 if qtype == RecordType::A => {
                debug!("Strategy only_ipv6: suppressing A query for {}", name);
                let meta = ResolveMeta {
                    domain: name.clone(),
                    qtype: qtype_str,
                    upstream: "strategy".to_string(),
                    original_upstream: "strategy".to_string(),
                    rcode: "Empty".to_string(),
                    ..Default::default()
                };
                return Ok((empty_noerror(request), meta));
            }
            _ => {}
        }

        // 1. Check cache
        if let Some(ref cache) = self.cache {
            if let Some((mut resp, orig_upstream)) = cache.get(&name, u16::from(qtype)) {
                debug!("Cache hit: {}", name);
                resp.set_id(id);
                let rcode = rcode_str(&resp);
                // 拦截类结果（rcode:// 上游）被缓存后，命中时仍标记 blocked
                let blocked = orig_upstream.starts_with("rcode:");
                let meta = ResolveMeta {
                    domain: name.clone(),
                    qtype: qtype_str,
                    upstream: "cache".to_string(),
                    original_upstream: orig_upstream,
                    rcode,
                    cached: true,
                    blocked,
                    ..Default::default()
                };
                return Ok((resp, meta));
            }
        }

        // 2. Check static hosts table
        if let Some(resp) = self.hosts.lookup(&name, qtype, id) {
            debug!("Static hosts hit: {}", name);
            let meta = ResolveMeta {
                domain: name.clone(),
                qtype: qtype_str,
                upstream: "hosts".to_string(),
                original_upstream: "hosts".to_string(),
                rcode: rcode_str(&resp),
                ..Default::default()
            };
            return Ok((resp, meta));
        }

        // 2b. Check dynamic hosts (DHCP leases)
        if let Some(resp) = self.dynamic_hosts.lookup(&name, qtype, id) {
            debug!("Dynamic hosts hit: {}", name);
            let meta = ResolveMeta {
                domain: name.clone(),
                qtype: qtype_str,
                upstream: "dynamic-hosts".to_string(),
                original_upstream: "dynamic-hosts".to_string(),
                rcode: rcode_str(&resp),
                ..Default::default()
            };
            return Ok((resp, meta));
        }

        // 3. Match rules（按顺序遍历 rulesets，首个命中生效）
        // 归一化一次：trim 末尾点 + ASCII 小写。已小写时零分配（Cow::Borrowed）。
        let domain = crate::ruleset::drs::normalize_domain(&name);
        for rule in &self.rules {
            // 调用方已归一化，直接走 matches_normalized 热路径，跳过 matches() 内部的重复检查
            if rule.ruleset.matches_normalized(&domain).is_some() {
                if let Some(upstream) = self.upstreams.get(&rule.upstream) {
                    debug!("Rule match: {} → upstream {}", name, rule.upstream);
                    // 判断是否是 rcode:// 类拦截上游（所有 server 都是 Rcode 类型才算）
                    let is_rcode_upstream = upstream
                        .servers
                        .iter()
                        .all(|s| matches!(s.kind, crate::dns::upstream::UpstreamKind::Rcode(_)));
                    let (resp, dur) = self.query_with_strategy(upstream, request, &name, qtype).await?;
                    // rcode:// 拦截上游：写缓存（命中时能还原 original_upstream），但不计入上游延迟
                    // 真实 DNS 上游：正常写缓存
                    // 缓存 key 存入 original_upstream，以便缓存命中时能正确归因
                    let orig_upstream_key = if is_rcode_upstream {
                        format!("rcode:{}", rule.upstream)
                    } else {
                        rule.upstream.clone()
                    };
                    if let Some(ref cache) = self.cache {
                        cache.insert(&name, u16::from(qtype), &resp, &orig_upstream_key);
                    }
                    let rcode = rcode_str(&resp);
                    // 拦截上游：blocked=true，不记延迟（没走真实 DNS）
                    let (blocked, latency) = if is_rcode_upstream {
                        (true, None)
                    } else {
                        (false, Some(dur.as_secs_f32() * 1000.0))
                    };
                    let meta = ResolveMeta {
                        domain: name.clone(),
                        qtype: qtype_str,
                        upstream: rule.upstream.clone(),
                        original_upstream: orig_upstream_key,
                        rcode,
                        rule: Some(rule.upstream.clone()),
                        blocked,
                        upstream_latency_ms: latency,
                        ..Default::default()
                    };
                    return Ok((resp, meta));
                }
            }
        }

        // 4. Default upstream
        let default = self
            .upstreams
            .get("default")
            .ok_or_else(|| anyhow::anyhow!("No default upstream configured"))?;

        debug!("Default upstream: {}", name);
        let (resp, dur) = self.query_with_strategy(default, request, &name, qtype).await?;
        if let Some(ref cache) = self.cache {
            cache.insert(&name, u16::from(qtype), &resp, "default");
        }
        let meta = ResolveMeta {
            domain: name.clone(),
            qtype: qtype_str,
            upstream: "default".to_string(),
            original_upstream: "default".to_string(),
            rcode: rcode_str(&resp),
            upstream_latency_ms: Some(dur.as_secs_f32() * 1000.0),
            ..Default::default()
        };
        Ok((resp, meta))
    }

    /// For prefer_ipv4/prefer_ipv6: send both A and AAAA in parallel,
    /// merge into a single response with preferred family sorted first.
    /// For all other strategies, forward the request as-is.
    ///
    /// 返回 (响应, 上游耗时)。并行 prefer 策略下耗时取较慢的那个（两个都完成才能合并）。
    async fn query_with_strategy(
        &self,
        upstream: &UpstreamGroup,
        request: &Message,
        _name: &str,
        qtype: RecordType,
    ) -> Result<(Message, std::time::Duration)> {
        match self.strategy {
            IpStrategy::PreferIpv4 if qtype == RecordType::A => {
                let alt = rewrite_qtype(request, RecordType::AAAA);
                let (a_resp, aaaa_resp) =
                    tokio::join!(upstream.query(request), upstream.query(&alt));
                let (a_resp, a_dur) = a_resp?;
                let aaaa_dur = aaaa_resp.as_ref().ok().map(|(_, d)| *d).unwrap_or_default();
                let resp = merge_responses(request, a_resp, aaaa_resp.ok().map(|(m, _)| m), true);
                Ok((resp, a_dur.max(aaaa_dur)))
            }
            IpStrategy::PreferIpv4 if qtype == RecordType::AAAA => {
                let alt = rewrite_qtype(request, RecordType::A);
                let (a_resp, aaaa_resp) =
                    tokio::join!(upstream.query(&alt), upstream.query(request));
                let (aaaa_resp, aaaa_dur) = aaaa_resp?;
                let a_dur = a_resp.as_ref().ok().map(|(_, d)| *d).unwrap_or_default();
                let resp = merge_responses(request, aaaa_resp, a_resp.ok().map(|(m, _)| m), false);
                Ok((resp, aaaa_dur.max(a_dur)))
            }
            IpStrategy::PreferIpv6 if qtype == RecordType::AAAA => {
                let alt = rewrite_qtype(request, RecordType::A);
                let (aaaa_resp, a_resp) =
                    tokio::join!(upstream.query(request), upstream.query(&alt));
                let (aaaa_resp, aaaa_dur) = aaaa_resp?;
                let a_dur = a_resp.as_ref().ok().map(|(_, d)| *d).unwrap_or_default();
                let resp = merge_responses(request, aaaa_resp, a_resp.ok().map(|(m, _)| m), true);
                Ok((resp, aaaa_dur.max(a_dur)))
            }
            IpStrategy::PreferIpv6 if qtype == RecordType::A => {
                let alt = rewrite_qtype(request, RecordType::AAAA);
                let (aaaa_resp, a_resp) =
                    tokio::join!(upstream.query(&alt), upstream.query(request));
                let (a_resp, a_dur) = a_resp?;
                let aaaa_dur = aaaa_resp.as_ref().ok().map(|(_, d)| *d).unwrap_or_default();
                let resp = merge_responses(request, a_resp, aaaa_resp.ok().map(|(m, _)| m), false);
                Ok((resp, a_dur.max(aaaa_dur)))
            }
            // Default / OnlyIpv4 / OnlyIpv6 / non-A/AAAA queries
            _ => upstream.query(request).await,
        }
    }
}

/// Build a new request with a different qtype (used for parallel prefer queries)
fn rewrite_qtype(original: &Message, new_type: RecordType) -> Message {
    let mut msg = original.clone();
    if let Some(q) = msg.queries_mut().first_mut() {
        q.set_query_type(new_type);
    }
    msg
}

/// Merge two responses: primary answers go first, secondary appended after.
/// `primary_first = true`  → primary records before secondary
/// `primary_first = false` → primary records only (secondary was the "extra" fetch)
fn merge_responses(
    request: &Message,
    mut primary: Message,
    secondary: Option<Message>,
    primary_first: bool,
) -> Message {
    primary.set_id(request.id());

    if let Some(sec) = secondary {
        if primary_first {
            // Append secondary answers after primary
            for record in sec.answers() {
                primary.add_answer(record.clone());
            }
        } else {
            // Prepend secondary answers before primary
            let original_answers: Vec<Record> = primary.answers().to_vec();
            let sec_answers: Vec<Record> = sec.answers().to_vec();
            // Rebuild answer section: secondary first, then original
            primary.take_answers();
            for r in sec_answers {
                primary.add_answer(r);
            }
            for r in original_answers {
                primary.add_answer(r);
            }
        }
    }

    primary
}

fn empty_noerror(request: &Message) -> Message {
    let mut resp = Message::new();
    resp.set_id(request.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(true);
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);
    for q in request.queries() {
        resp.add_query(q.clone());
    }
    resp
}

/// 把响应的 ResponseCode 转成可读字符串（给统计用）。
fn rcode_str(resp: &Message) -> String {
    crate::stats::rcode_name(resp.response_code()).to_string()
}
