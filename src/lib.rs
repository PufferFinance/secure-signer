// #[macro_use]
extern crate anyhow;
extern crate libc;
extern crate env_logger;

pub mod constants;
pub mod eth2;
pub mod crypto;
pub mod io;
pub mod api;

use warp::Filter;

#[macro_export]
macro_rules! strip_0x_prefix {
    ($hex:expr) => {
        $hex.strip_prefix("0x").unwrap_or(&$hex).into()
    };
}

pub async fn run(port: u16) {

    env_logger::init();

    let routes = 

        // --------- Compatible with Web3Signer ---------
        // https://consensys.github.io/web3signer/web3signer-eth2.html
        api::upcheck_route()

        // Endpoint to securely generate and save a BLS sk 
        .or(api::bls_keygen_route::bls_keygen_route())

        // Endpoint to securely import an eip-2335 BLS keystore and eip-3076 slash protection db
        .or(api::bls_import_route::bls_key_import_route())

        // Endpoint to list all pks of saved bls keys in the enclave
        .or(api::getter_routes::list_bls_keys_route())

        // Endpoint to request a signature using BLS sk 
        .or(api::signing_route::bls_sign_route())

        // Endpoint to securely generate and save an ETH sk 
        .or(api::eth_keygen_route::eth_keygen_route())

        // Endpoint to list the pks of all the generated ETH keys
        .or(api::getter_routes::list_eth_keys_route());

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
}