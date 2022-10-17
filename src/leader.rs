mod attest;
mod keys;
mod leader_api;
mod common_api;

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
    let routes = common_api::epid_remote_attestation_route()
        // Request to securely generate and save an ETH sk 
        .or(common_api::eth_key_gen_route())

        // Request to list pks of saved bls keys that were generated in the enclave
        .or(common_api::list_generated_bls_keys_route())

        // Request to list pks of saved bls keys that were imported into the enclave
        .or(common_api::list_imported_bls_keys_route())

        // Request to list pks of saved bls keys 
        .or(common_api::list_eth_keys_route())

        .or(common_api::bls_key_import_route())
        .or(leader_api::bls_key_provision_route())
        .or(leader_api::bls_key_aggregator_route());

    warp::serve(routes).run(([127, 0, 0, 1], LEADER_PORT)).await
}