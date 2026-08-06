//! LRU DNS response cache with TTL awareness

use hickory_proto::op::Message;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone)]
struct CacheEntry {
    message: Message,
    inserted_at: Instant,
    ttl: u32,
    /// 首次解析时命中的上游名称（如 "ads"、"default"），用于 upstream_stats 归因。
    original_upstream: String,
}

impl CacheEntry {
    fn remaining_ttl(&self) -> Option<u32> {
        let elapsed = self.inserted_at.elapsed().as_secs() as u32;
        if elapsed >= self.ttl {
            None
        } else {
            Some(self.ttl - elapsed)
        }
    }
}

pub struct DnsCache {
    inner: Mutex<LruCache<String, CacheEntry>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(size: usize, min_ttl: u32, max_ttl: u32) -> Self {
        let cap = NonZeroUsize::new(size.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            min_ttl,
            max_ttl,
        }
    }

    fn cache_key(name: &str, qtype: u16) -> String {
        format!("{}:{}", name.to_lowercase(), qtype)
    }

    /// 返回 (Message, original_upstream)，其中 original_upstream 是首次解析时使用的上游名。
    pub fn get(&self, name: &str, qtype: u16) -> Option<(Message, String)> {
        let key = Self::cache_key(name, qtype);
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.get(&key) {
            if let Some(remaining) = entry.remaining_ttl() {
                let mut msg = entry.message.clone();
                let orig = entry.original_upstream.clone();
                for record in msg.answers_mut().iter_mut() {
                    record.set_ttl(remaining);
                }
                for record in msg.additionals_mut().iter_mut() {
                    record.set_ttl(remaining);
                }
                return Some((msg, orig));
            } else {
                inner.pop(&key);
            }
        }
        None
    }

    /// 插入缓存。`original_upstream` 为本次解析使用的上游名，随条目一起存储。
    pub fn insert(&self, name: &str, qtype: u16, message: &Message, original_upstream: &str) {
        let min_record_ttl = message
            .answers()
            .iter()
            .chain(message.additionals().iter())
            .map(|r| r.ttl())
            .min()
            .unwrap_or(self.min_ttl);

        let ttl = min_record_ttl
            .max(self.min_ttl)
            .min(self.max_ttl);

        if ttl == 0 {
            return;
        }

        let key = Self::cache_key(name, qtype);
        let entry = CacheEntry {
            message: message.clone(),
            inserted_at: Instant::now(),
            ttl,
            original_upstream: original_upstream.to_string(),
        };
        self.inner.lock().unwrap().put(key, entry);
    }
}
