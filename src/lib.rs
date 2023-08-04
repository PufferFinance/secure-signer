// #[macro_use]
extern crate anyhow;
extern crate env_logger;
extern crate libc;

pub mod api;
pub mod constants;
pub mod crypto;
pub mod eth2;
pub mod io;

use eth2::eth_types::Version;
use warp::Filter;

#[macro_export]
macro_rules! strip_0x_prefix {
    ($hex:expr) => {
        $hex.strip_prefix("0x").unwrap_or(&$hex).into()
    };
}

pub async fn run(port: u16, genesis_fork_version: Version) {
    env_logger::init();

    let routes = 

        // Returns 200 if the server is running
        api::upcheck_route()

        // Endpoint to securely generate and save a BLS sk 
        .or(api::bls_keygen_route::bls_keygen_route())

        // Endpoint to securely import an eip-2335 BLS keystore and eip-3076 slash protection db
        .or(api::bls_import_route::bls_key_import_route())

        // Endpoint to list all pks of saved bls keys in the enclave
        .or(api::getter_routes::list_bls_keys_route())

        // Endpoint to securely generate and save an ETH sk 
        .or(api::eth_keygen_route::eth_keygen_route())

        // Endpoint to list the pks of all the generated ETH keys
        .or(api::getter_routes::list_eth_keys_route())

        // Endpoint to sign DepositData message for registering validator on beacon chain
        .or(api::deposit_route::validator_deposit_route());

    // Endpoint to request a signature using BLS sk
    // Wrapped in a log filter
    let bls_sign_route_with_log =
        api::signing_route::bls_sign_route(genesis_fork_version).with(warp::log("bls_sign_route"));

    // Combine the routes
    let all_routes = routes.or(bls_sign_route_with_log);

    // Start the server with the all_routes
    warp::serve(all_routes).run(([127, 0, 0, 1], port)).await;
}
