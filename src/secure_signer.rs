// #[macro_use]
extern crate anyhow;
extern crate libc;
extern crate env_logger;

mod eth_signing;
mod eth_types;
mod slash_protection;
mod keys;
mod remote_attestation;
mod routes;
mod route_handlers;

use warp::Filter;
use std::fs;

#[tokio::main]
async fn main() {
    let port = std::env::args().nth(1).unwrap_or("3031".into()).parse::<u16>().expect("BAD PORT");
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