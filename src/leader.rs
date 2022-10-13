mod attest;
mod keys;

// deps
use std::os::raw::c_char;
use keys::list_keys;
use serde_derive::{Deserialize, Serialize};
use warp::{Filter, http::Response};
use blst::min_pk::{SecretKey, PublicKey, Signature};
use blst::BLST_ERROR;


//#[link(name = "epid")]
//extern "C" {
//    /// The cpp function for epid remote attestation with IAS defined in src/ra_wrapper.cpp
//    fn do_epid_ra(data: *const u8, report: *mut c_char, signature: *mut c_char, signing_cert: *mut c_char);
//}



#[tokio::main]
async fn main() {
    let port = 3030;
    println!("Starting leader enclave HTTP server");
    let routes = keys::key_gen_route()
        .or(keys::list_keys_route())
        .or(attest::epid_remote_attestation_route());
    warp::serve(routes).run(([127, 0, 0, 1], port)).await

    // let url = String::from("http://google.com");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_key_gen_route() {
        let keys = keys::list_keys();
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