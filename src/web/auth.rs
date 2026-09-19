//! Session Cookie 鉴权（替代旧版 Basic Auth）。
//!
//! 流程：
//!   1. POST /api/auth/login { username, password } → 校验（bcrypt）→
//!      生成随机 token，存入内存 session 表，Set-Cookie: relay_session=<token>
//!      (HttpOnly, SameSite=Lax, Max-Age=86400)
//!   2. 后续请求带该 cookie，中间件校验 token 是否存在且未过期
//!      （24 小时不活动过期；每次成功校验会刷新过期时间——即"活动"续期）
//!   3. POST /api/auth/logout → 删除 session
//!
//! 若配置中 auth.enable=false，中间件直接放行（不校验），行为与旧版一致。
//!
//! 密码修改（POST /api/auth/password）在 api.rs 里实现，会更新
//! RuntimeHandle 内存中的 auth 配置副本（不走 apply() 热更新，因为
//! web.auth 被 apply() 显式排除）并落盘。

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bcrypt::verify as bcrypt_verify;
use dashmap::DashMap;
use rand::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::WebAuthConfig;

/// session 24 小时不活动即过期。
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
pub const SESSION_COOKIE_NAME: &str = "relay_session";

#[derive(Clone)]
pub struct AuthState {
    /// 当前生效的用户名/密码哈希，随"改密码"接口更新（用 ArcSwap 简化为 parking_lot RwLock 也可，
    /// 这里用 arc_swap 保持与 runtime 模块风格一致）。
    pub config: Arc<arc_swap::ArcSwap<WebAuthConfig>>,
    sessions: Arc<DashMap<String, Instant>>,
}

impl AuthState {
    pub fn new(config: WebAuthConfig) -> Self {
        Self {
            config: Arc::new(arc_swap::ArcSwap::from_pointee(config)),
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.load().enable
    }

    /// 校验用户名密码，成功则创建 session，返回 token。
    pub fn login(&self, username: &str, password: &str) -> Option<String> {
        let cfg = self.config.load();
        if !constant_time_eq(username.as_bytes(), cfg.username.as_bytes()) {
            return None;
        }
        if cfg.password_hash.is_empty() {
            return None;
        }
        if !bcrypt_verify(password, &cfg.password_hash).unwrap_or(false) {
            return None;
        }
        let token = generate_token();
        self.sessions.insert(token.clone(), Instant::now());
        Some(token)
    }

    pub fn logout(&self, token: &str) {
        self.sessions.remove(token);
    }

    /// 校验 token 是否有效（存在且未过期）；有效则刷新其活动时间。
    fn touch(&self, token: &str) -> bool {
        // 顺带清理过期 session，避免 map 无限增长
        self.cleanup_expired();
        if let Some(mut entry) = self.sessions.get_mut(token) {
            if entry.elapsed() > SESSION_TTL {
                drop(entry);
                self.sessions.remove(token);
                return false;
            }
            *entry = Instant::now();
            true
        } else {
            false
        }
    }

    /// 清理所有过期 session。
    fn cleanup_expired(&self) {
        self.sessions
            .retain(|_, last| last.elapsed() <= SESSION_TTL);
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{}=", name)) {
            return Some(v.to_string());
        }
    }
    None
}

/// axum middleware：校验 session cookie。auth.enable=false 时直接放行。
pub async fn require_auth(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.is_enabled() {
        return next.run(request).await;
    }

    let token = extract_cookie(request.headers(), SESSION_COOKIE_NAME);
    let authorized = match token {
        Some(t) => state.touch(&t),
        None => false,
    };

    if authorized {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

/// 构造 Set-Cookie 头（登录成功时用）。
pub fn session_cookie_header(token: &str) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_COOKIE_NAME,
        token,
        SESSION_TTL.as_secs()
    )
}

/// 构造清除 Cookie 的 Set-Cookie 头（登出时用）。
pub fn clear_session_cookie_header() -> String {
    format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", SESSION_COOKIE_NAME)
}
