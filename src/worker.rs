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
        // Endpoint to securely generate and save an ETH sk 
        // curl -X POST localhost:3031/portal/v1/keygen/eth
        .or(routes::eth_key_gen_route())

        // Endpoint to list the pks of all the generated ETH keys
        // curl -X GET localhost:3031/portal/v1/keygen/eth
        .or(routes::list_generated_eth_keys_route())

        // Endpoint to securely generate and save a BLS sk 
        // curl -X POST localhost:3031/portal/v1/keygen/bls
        .or(routes::bls_key_gen_route())

        // Endpoint to list pks of saved bls keys that were generated in the enclave
        // curl -X GET localhost:3031/portal/v1/keygen/bls
        .or(routes::list_generated_bls_keys_route())

        // Endpoint to securely import a BLS sk 
        // curl -X POST localhost:3031/portal/v1/keystores -H "Content-Type: application/json"  -d '{"ct_bls_sk_hex": "0x123123", "bls_pk_hex": "0x123", "encrypting_pk_hex": "0x123"}'  
        .or(routes::bls_key_import_route())

        // Endpoint to list pks of saved bls keys that were imported into the enclave
        // curl -X GET localhost:3031/portal/v1/keystores
        .or(routes::list_imported_bls_keys_route())

        // Endpoint to list pks of saved bls keys 
        // .or(routes::request_bls_key_import_route())
        // .or(routes::btc_pricefeed_route())
        .or(routes::request_bls_key_provision_route());

    warp::serve(routes).run(([127, 0, 0, 1], WORKER_PORT)).await;
}