extern crate puffersecuresigner;

use axum::middleware;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use puffersecuresigner::middlewares;
use puffersecuresigner::{eth2::eth_types::Version, strip_0x_prefix};

#[tokio::main]
async fn main() {
    let trace_filter = middlewares::tracing_filter::get_trace_filter();
    tracing_subscriber::registry()
        .with(trace_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port = std::env::args()
        .nth(1)
        .unwrap_or("3031".into())
        .parse::<u16>()
        .expect("BAD PORT");
    let genesis_fork_version_str: String =
        std::env::args().nth(2).unwrap_or("00000000".to_string());
    let genesis_fork_version_str: String = strip_0x_prefix!(genesis_fork_version_str);
    let mut genesis_fork_version = Version::default();
    genesis_fork_version.copy_from_slice(
        &hex::decode(&genesis_fork_version_str).expect("Bad genesis_fork_version"),
    );

    log::info!(
        "Starting SGX Validator: localhost:{}, using genesis_fork_version: {:?}",
        port,
        genesis_fork_version
    );

    let app = axum::Router::new()
        // Endpoint to check health
        .route(
            "/health",
            axum::routing::get(puffersecuresigner::enclave::shared::handlers::health::handler),
        )
        .route(
            "/bls/v1/keygen",
            axum::routing::post(
                puffersecuresigner::enclave::validator::handlers::attest_fresh_bls_key::handler,
            ),
        )
        .route(
            "/eth/v1/keystores",
            axum::routing::get(
                puffersecuresigner::enclave::shared::handlers::list_bls_keys::handler,
            ),
        )
        .layer(middleware::from_fn(
            middlewares::terminal_logger::terminal_logger,
        ));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    _ = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await;
}
