//! Web 面板：axum HTTP 服务 + 静态资源 + Basic Auth + JSON API。
//!
//! 路由树：
//!   /api/*        JSON API（若 auth.enable 则挂 Basic Auth 中间件）
//!   /metrics      Prometheus 文本
//!   /             静态资源（前端 dist/，内嵌或外置目录）
//!
//! 静态资源优先级：
//!   1. 配置了 web-dir → 用 tower_http::services::ServeDir
//!   2. 未配置 → 用内嵌资源（include_dir!）
//!
//! SPA 回退：访问非 /api、非 /metrics、非 /static 的路径，
//!   若文件不存在则回退到 index.html（前端路由）。

pub mod api;
pub mod auth;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, HeaderValue, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use include_dir::{include_dir, Dir};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

use crate::config::WebConfig;
use crate::stats::StatsCollector;

/// 内嵌的前端静态资源（编译时打包）。
/// 来源：src/web/static/（占位 index.html 或前端构建产物 dist/）。
/// 前端构建时把 dist/ 内容复制到 src/web/static/ 即可。
static EMBEDDED_STATIC: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/src/web/static");

/// 启动 web 服务。返回时表示服务已退出。
pub async fn serve(
    config: WebConfig,
    stats: Arc<StatsCollector>,
    persistence: Option<Arc<crate::stats::persistence::StatsPersistence>>,
) -> Result<()> {
    let addr: SocketAddr = config.listen;
    let api_state = api::ApiState {
        stats,
        persistence,
    };

    // /metrics 单独路由（不带 auth，方便 Prometheus 抓取；
    // 若需保护可在配置里加 metrics_auth 开关，这里先简化）
    let metrics_router = Router::new()
        .route("/metrics", get(api::metrics))
        .with_state(api_state.clone());

    // 构建 API 路由
    let api_routes = Router::new()
        .route("/stats", get(api::stats))
        .route("/upstreams", get(api::upstreams))
        .route("/rules", get(api::rules))
        .route("/clients", get(api::clients))
        .route("/querylog", get(api::querylog))
        .route("/dashboard", get(api::dashboard))
        .route_layer(CorsLayer::permissive())
        .with_state(api_state);

    // 若启用 auth，对 /api/* 与 /metrics 都加 Basic Auth
    let need_auth = config.auth.enable;
    let auth_state = auth::AuthState::new(config.auth.clone());

    let api_routes = if need_auth {
        api_routes.layer(middleware::from_fn_with_state(
            auth_state.clone(),
            auth::require_auth,
        ))
    } else {
        api_routes
    };

    // 静态资源服务
    let static_service = build_static_service(&config);

    // 完整路由
    let app = Router::new()
        .nest("/api", api_routes)
        .merge(metrics_router)
        .fallback_service(static_service);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind web listen {}", addr))?;
    info!("Web panel listening on http://{}", addr);

    axum::serve(listener, app.into_make_service())
        .await
        .context("axum serve web")?;
    Ok(())
}

/// 构造静态资源服务。
///   - 配置了 web_dir：ServeDir（支持 SPA 回退）
///   - 未配置：内嵌资源 fallback handler
fn build_static_service(config: &WebConfig) -> Router {
    if let Some(dir) = &config.web_dir {
        let serve_dir = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        Router::new().fallback_service(serve_dir)
    } else {
        // 用内嵌资源：fallback handler 处理所有非 /api /metrics 路径
        Router::new().fallback(embedded_static_handler)
    }
}

/// 处理内嵌静态资源请求。
///
/// - 路径为 "/" → 返回 index.html
/// - 路径为 "/xxx" → 查找 embedded/xxx，找不到则返回 index.html（SPA 回退）
async fn embedded_static_handler(req: Request<Body>) -> Response {
    let uri = req.uri();
    let path = uri.path().trim_start_matches('/');

    // 默认首页
    let target = if path.is_empty() {
        "index.html"
    } else {
        path
    };

    // 先精确匹配文件
    if let Some(file) = EMBEDDED_STATIC.get_file(target) {
        return serve_embedded_file(target, file.contents());
    }

    // SPA 回退：返回 index.html（让前端路由处理）
    if let Some(file) = EMBEDDED_STATIC.get_file("index.html") {
        return serve_embedded_file("index.html", file.contents());
    }

    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// 返回内嵌文件内容，根据扩展名设置 Content-Type。
fn serve_embedded_file(path: &str, contents: &[u8]) -> Response {
    let mime = mime_for_ext(path);
    let mut resp = Response::new(Body::from(contents.to_vec()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if path == "index.html" {
            "no-cache"
        } else {
            "public, max-age=86400"
        }),
    );
    resp
}

/// 根据扩展名返回 MIME 类型。
fn mime_for_ext(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.ends_with(".html") || p.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if p.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if p.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if p.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if p.ends_with(".svg") {
        "image/svg+xml"
    } else if p.ends_with(".png") {
        "image/png"
    } else if p.ends_with(".jpg") || p.ends_with(".jpeg") {
        "image/jpeg"
    } else if p.ends_with(".gif") {
        "image/gif"
    } else if p.ends_with(".ico") {
        "image/x-icon"
    } else if p.ends_with(".woff") {
        "font/woff"
    } else if p.ends_with(".woff2") {
        "font/woff2"
    } else if p.ends_with(".ttf") {
        "font/ttf"
    } else if p.ends_with(".map") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}
