// #[macro_use]
extern crate anyhow;
extern crate libc;
extern crate env_logger;

pub mod constants;
pub mod eth2;
pub mod crypto;
pub mod io;
pub mod api;
pub mod eth_signing;
pub mod eth_types;
pub mod slash_protection;
pub mod keys;
pub mod remote_attestation;
pub mod routes;
pub mod route_handlers;

use warp::Filter;

#[macro_export]
macro_rules! strip_0x_prefix {
    ($hex:expr) => {
        $hex.strip_prefix("0x").unwrap_or(&$hex).into()
    };
}

pub async fn run(port: u16) {
    println!("Starting SGX Secure-Signer: localhost:{}", port);

    env_logger::init();

    let routes = 

        // --------- Compatible with Web3Signer ---------
        // https://consensys.github.io/web3signer/web3signer-eth2.html
        routes::upcheck_route()

        // Endpoint to securely import a BLS sk 
        // curl -X POST localhost:3031/eth/v1/keystores -H "Content-Type: application/json"  -d '{"ct_bls_sk_hex": "0x123123", "bls_pk_hex": "0x123", "encrypting_pk_hex": "0x123"}'  
        .or(routes::bls_key_import_route())

        // Endpoint to list pks of saved bls keys that were imported into the enclave
        // curl -X GET localhost:3031/eth/v1/keystores
        .or(routes::list_imported_bls_keys_route())

        // Endpoint to request a signature using BLS sk 
        // curl -X POST localhost:3031/eth/v1/sign/bls -H "Content-Type: application/json"  -d '{"msg_hex": "0xdeadbeef", "bls_pk_hex": "0x123"}'  
        .or(routes::bls_sign_route())

        // --------- Addition to Web3Signer ---------

        // Endpoint to perform remote attestation with intel using a supplied PK
        // curl -X POST localhost:3031/eth/v1/remote-attestation -H "Content-Type: application/json"  -d '{"pub_key": "123123"}'
        .or(routes::epid_remote_attestation_route())

        // Endpoint to securely generate and save an ETH sk 
        // curl -X POST localhost:3031/eth/v1/keygen/eth
        .or(routes::eth_key_gen_route())

        // Endpoint to list the pks of all the generated ETH keys
        // curl -X GET localhost:3031/eth/v1/keygen/eth
        .or(routes::list_generated_eth_keys_route())

        // Endpoint to securely generate and save a BLS sk 
        // curl -X POST localhost:3031/eth/v1/keygen/bls
        .or(routes::bls_key_gen_route())

        // Endpoint to list pks of saved bls keys that were generated in the enclave
        // curl -X GET localhost:3031/eth/v1/keygen/bls
        .or(routes::list_generated_bls_keys_route());


    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
}