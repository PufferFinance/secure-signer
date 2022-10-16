#[macro_use]
extern crate anyhow;

mod keys;
mod datafeed;
mod attest;
mod worker_api;
mod common_api;
mod leader_api;

use warp::Filter;

const WORKER_PORT: u16 = 3031;

#[tokio::main]
async fn main() {
    println!("Starting worker enclave HTTP server on port {}", WORKER_PORT);
    let routes = common_api::epid_remote_attestation_route()
        .or(common_api::eth_key_gen_route())
        .or(common_api::list_bls_keys_route())
        .or(worker_api::btc_pricefeed_route())
        .or(worker_api::request_bls_key_provision_route());

    warp::serve(routes).run(([127, 0, 0, 1], WORKER_PORT)).await;
}