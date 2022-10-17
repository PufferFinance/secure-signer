#[macro_use]
extern crate anyhow;

mod keys;
mod datafeed;
mod attest;
mod routes;
mod worker_api;
mod common_api;
mod leader_api;

use warp::Filter;

const WORKER_PORT: u16 = 3031;

#[tokio::main]
async fn main() {
    println!("Starting worker enclave HTTP server on port {}", WORKER_PORT);
    let routes = routes::epid_remote_attestation_route()
        // Request to securely generate and save an ETH sk 
        .or(routes::eth_key_gen_route())
        // Request to list pks of saved bls keys that were generated in the enclave
        .or(routes::list_generated_bls_keys_route())
        // Request to list pks of saved bls keys that were imported into the enclave
        .or(routes::list_imported_bls_keys_route())
        // Request to list pks of saved bls keys 
        .or(routes::list_eth_keys_route())
        .or(routes::request_bls_key_import_route())
        .or(routes::btc_pricefeed_route())
        .or(routes::request_bls_key_provision_route());

    warp::serve(routes).run(([127, 0, 0, 1], WORKER_PORT)).await;
}