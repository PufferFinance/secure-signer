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
        "Starting SGX Secure-Signer: localhost:{}, using genesis_fork_version: {:?}",
        port, genesis_fork_version
    );

    let app_state = puffersecuresigner::enclave::shared::handlers::AppState {
        genesis_fork_version,
    };

    let eth_v1 = axum::Router::new()
        // Endpoint to securely generate and save an ETH sk
        .route(
            "/keygen/secp256k1",
            axum::routing::post(
                puffersecuresigner::enclave::secure_signer::handlers::eth_keygen::handler,
            ),
        )
        // Endpoint to securely generate and save a BLS sk
        .route(
            "/keygen/bls",
            axum::routing::post(
                puffersecuresigner::enclave::secure_signer::handlers::bls_keygen::handler,
            ),
        )
        // Endpoint to list the pks of all the generated ETH keys
        .route(
            "/keygen/secp256k1",
            axum::routing::get(
                puffersecuresigner::enclave::shared::handlers::list_eth_keys::handler,
            ),
        )
        // Endpoint to list all pks of saved bls keys in the enclave
        .route(
            "/keystores",
            axum::routing::get(
                puffersecuresigner::enclave::shared::handlers::list_bls_keys::handler,
            ),
        );

    let app = axum::Router::new()
        // Endpoint to check health
        .route(
            "/upcheck",
            axum::routing::get(puffersecuresigner::enclave::shared::handlers::health::handler),
        )
        .nest("/eth/v1", eth_v1)
        // Endpoint to sign DepositData message for registering validator on beacon chain
        .route(
            "/api/v1/eth2/deposit",
            axum::routing::post(
                puffersecuresigner::enclave::secure_signer::handlers::validator_deposit::handler,
            ),
        )
        // Endpoint to request a signature using BLS sk
        .route(
            "/api/v1/eth2/sign/:bls_pk_hex",
            axum::routing::post(
                puffersecuresigner::enclave::shared::handlers::secure_sign_bls::handler,
            ),
        )
        .with_state(app_state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    _ = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await;
}
