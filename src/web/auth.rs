//! Basic Auth 中间件（bcrypt 校验）。
//!
//! 校验流程：
//!   1. 从 Authorization 头取 "Basic <base64(user:pass)>"
//!   2. base64 解码，拆出 user / pass
//!   3. user 与配置的 username 比较
//!   4. pass 用 bcrypt::verify 校验 password_hash
//!
//! 通过则放行；否则返回 401 + WWW-Authenticate 头。

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use bcrypt::verify as bcrypt_verify;

use crate::config::WebAuthConfig;

/// 构造 Basic Auth 中间件所需的状态。
#[derive(Clone)]
pub struct AuthState {
    pub config: WebAuthConfig,
}

impl AuthState {
    pub fn new(config: WebAuthConfig) -> Self {
        Self { config }
    }
}

/// axum middleware：校验 Basic Auth。
/// 通过 from_fn_with_state 注入 AuthState。
pub async fn require_auth(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {

    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let authorized = match header {
        Some(h) if h.starts_with("Basic ") => {
            let encoded = &h[6..];
            match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => {
                        if let Some((user, pass)) = s.split_once(':') {
                            check_credentials(&state.config, user, pass)
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                },
                Err(_) => false,
            }
        }
        _ => false,
    };

    if authorized {
        next.run(request).await
    } else {
        let mut resp = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        resp.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            "Basic realm=\"relay\"".parse().unwrap(),
        );
        resp
    }
}

/// 校验用户名 + 密码。
fn check_credentials(cfg: &WebAuthConfig, user: &str, pass: &str) -> bool {
    // 常量时间比较用户名（避免 timing attack，简单场景可接受）
    if !constant_time_eq(user.as_bytes(), cfg.username.as_bytes()) {
        return false;
    }
    // bcrypt 校验
    bcrypt_verify(pass, &cfg.password_hash).unwrap_or(false)
}

/// 简单的常量时间字节比较。
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
