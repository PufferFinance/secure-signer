mod attest;
mod keys;
mod common_api;

// deps
use std::os::raw::c_char;
use serde_derive::{Deserialize, Serialize};
use warp::{Filter, http::Response};


//#[link(name = "epid")]
//extern "C" {
//    /// The cpp function for epid remote attestation with IAS defined in src/ra_wrapper.cpp
//    fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char);
//}

const LEADER_PORT: u16 = 3030;


#[tokio::main]
async fn main() {
    println!("Starting leader enclave HTTP server on port {}", LEADER_PORT);
    let routes = common_api::bls_key_gen_route()
        .or(common_api::list_bls_keys_route())
        .or(common_api::epid_remote_attestation_route());
    warp::serve(routes).run(([127, 0, 0, 1], LEADER_PORT)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_key_gen_route() {
        // let keys = k::list_keys();
        //todo
        assert!(false);
    }

    #[test]
    fn test_list_keys_route() {
        //todo

    }

    // #[test]
    // fn test_epid_ra() {
    //     let keys = keys::list_keys();
    //     let pk_hex = &keys[0];
    //     epid_remote_attestation(pk_hex);
    //     assert!(false);
    // }
}