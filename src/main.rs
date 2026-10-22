//! browsercheck-rust — all-in-one browser & network environment self-check tool.
//!
//! Rust/axum rewrite of andrewji8/browsercheck (Flask).

mod dns;
mod geo;
mod rules;
mod routes;
mod state;
mod ua;
mod util;

use axum::Router;
use std::net::SocketAddr;

fn build_router() -> Router {
    let state = state::AppState::new();
    Router::new()
        .route("/", axum::routing::get(routes::index))
        .route("/api/ping", axum::routing::get(routes::api_ping))
        .route("/api/ip", axum::routing::get(routes::api_ip))
        .route("/api/webrtc", axum::routing::get(routes::api_webrtc))
        .route("/api/dns", axum::routing::get(routes::api_dns))
        .route("/api/multi-geo", axum::routing::get(routes::api_multi_geo))
        .route("/api/headers", axum::routing::get(routes::api_headers))
        .route("/api/engine-probe", axum::routing::get(routes::api_engine_probe))
        .route(
            "/api/validate",
            axum::routing::get(routes::api_validate_get).post(routes::api_validate_post),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() {
    // With the `env-filter` feature, `fmt()` already installs an EnvFilter
    // driven by the RUST_LOG environment variable.
    tracing_subscriber::fmt().init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5000);
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    tracing::info!("browsercheck-rust listening on http://0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(
        listener,
        build_router().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}
