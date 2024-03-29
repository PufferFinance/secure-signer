extern crate puffersecuresigner;
use puffersecuresigner::{eth2::eth_types::Version, strip_0x_prefix};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

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

    println!(
        "Starting SGX Guardian: localhost:{}, using genesis_fork_version: {:?}",
        port, genesis_fork_version
    );

    let app = axum::Router::new()
        // Endpoint to check health
        .route(
            "/upcheck",
            axum::routing::get(puffersecuresigner::enclave::shared::handlers::health::handler),
        )
        // Endpoint generated a new ETH key
        .route(
            "/eth/v1/keygen",
            axum::routing::post(
                puffersecuresigner::enclave::guardian::handlers::attest_fresh_eth_key_with_blockhash::handler,
            ),
        )
        // Endpoint to list the pks of all the generated ETH keys
        .route(
            "/eth/v1/keygen",
            axum::routing::get(
                puffersecuresigner::enclave::shared::handlers::list_eth_keys::handler,
            ),
        )
        // Endpoint to validate and receive BLS keyshare custody
        .route(
            "/guardian/v1/validate-custody",
            axum::routing::post(
                puffersecuresigner::enclave::guardian::handlers::validate_custody::handler,
            ),
        )
        // Endpoint to sign a VoluntaryExitMessage
        .route(
            "/guardian/v1/sign-exit",
            axum::routing::post(
                puffersecuresigner::enclave::guardian::handlers::sign_exit::handler,
            ),
        )
        ;

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    _ = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await;
}
