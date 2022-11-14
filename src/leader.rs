mod attest;
mod keys;
mod routes;
mod leader_api;
mod worker_api;
mod common_api;
mod datafeed;
mod beacon;

// deps
use std::os::raw::c_char;
use warp::Filter;


//#[link(name = "epid")]
//extern "C" {
//    /// The cpp function for epid remote attestation with IAS defined in src/ra_wrapper.cpp
//    fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char);
//}

const LEADER_PORT: u16 = 3030;


#[tokio::main]
async fn main() {
    println!("Starting leader enclave HTTP server on port {}", LEADER_PORT);
    let routes = routes::epid_remote_attestation_route()
        // Request to securely generate and save an ETH sk 
        .or(routes::eth_key_gen_route())

        // Request to list pks of saved bls keys that were generated in the enclave
        .or(routes::list_generated_bls_keys_route())

        // Request to list pks of saved bls keys that were imported into the enclave
        .or(routes::list_imported_bls_keys_route())

        // Request to list pks of saved bls keys 
        .or(routes::list_generated_eth_keys_route())

        .or(routes::bls_key_import_route())

        // Endpoint to provision a new bls key
        // curl -X POST localhost:3030/portal/v1/provision -H "Content-Type: application/json"  -d '{"eth_pk_hex": "deadbeef", "evidence": "{}"}' 
        .or(routes::bls_key_provision_route())
        .or(routes::bls_key_aggregator_route());

    warp::serve(routes).run(([127, 0, 0, 1], LEADER_PORT)).await


    // let url = "https://api.coindesk.com/v1/bpi/currentprice.json";
    // let res = datafeed::coindesk_usd_feed(url.into()).await;
    // println!("got res: {:?}", res);
}