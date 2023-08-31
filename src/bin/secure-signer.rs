extern crate puffersecuresigner;
use puffersecuresigner::{eth2::eth_types::Version, run, strip_0x_prefix};
use warp::Filter;

#[tokio::main]
async fn main() {
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

    // Upcheck route returns 200 if the server is running
    let routes = puffersecuresigner::api::upcheck_route()
        // Endpoint to securely generate and save a BLS sk
        .or(puffersecuresigner::api::bls_keygen_route::bls_keygen_route())
        // Endpoint to securely import an eip-2335 BLS keystore and eip-3076 slash protection db
        .or(puffersecuresigner::api::bls_import_route::bls_key_import_route())
        // Endpoint to list all pks of saved bls keys in the enclave
        .or(puffersecuresigner::api::getter_routes::list_bls_keys_route())
        // Endpoint to securely generate and save an ETH sk
        .or(puffersecuresigner::api::eth_keygen_route::eth_keygen_route())
        // Endpoint to list the pks of all the generated ETH keys
        .or(puffersecuresigner::api::getter_routes::list_eth_keys_route())
        // Endpoint to sign DepositData message for registering validator on beacon chain
        .or(puffersecuresigner::api::deposit_route::validator_deposit_route());

    // Endpoint to request a signature using BLS sk
    // Wrapped in a log filter
    let bls_sign_route_with_log =
        puffersecuresigner::api::signing_route::bls_sign_route(genesis_fork_version)
            .with(warp::log("bls_sign_route"));

    // Combine the routes
    let all_routes = routes.or(bls_sign_route_with_log);

    run(port, all_routes).await;
}
