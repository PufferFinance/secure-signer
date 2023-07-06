use super::read_secure_signer_port;

use anyhow::{Context, Result};
use blsttc::PublicKey;
use puffersecuresigner::{
    api::{bls_keygen_route::bls_keygen_route, KeyGenResponse},
    constants::BLS_PUB_KEY_BYTES, strip_0x_prefix,
};
use reqwest::{Client, Response, StatusCode};
use serde_json;
use std::env;

pub async fn mock_bls_keygen_route() -> warp::http::Response<bytes::Bytes> {
    let filter = bls_keygen_route();
    let res = warp::test::request()
        .method("POST")
        .path("/eth/v1/keygen/bls")
        .reply(&filter)
        .await;
    res
}

pub async fn request_bls_keygen_route(port: u16) -> Result<Response, reqwest::Error> {
    let client = Client::new();
    let url = format!("http://localhost:{}/eth/v1/keygen/bls", port);
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .send()
        .await;

    response
}

pub async fn make_bls_keygen_request(port: Option<u16>) -> (StatusCode, Result<KeyGenResponse>) {
    match port {
        // Make the actual http req to a running Secure-Aggregator instance
        Some(p) => {
            let resp = match request_bls_keygen_route(p).await {
                Ok(resp) => resp,
                Err(_) => panic!("Failed request_eth_keygen_route"),
            };
            dbg!(&resp);
            let status = resp.status();
            let sig: Result<KeyGenResponse> = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to KeyGenResponse"));
            (status, sig)
        }
        // Mock an http request
        None => {
            let resp = mock_bls_keygen_route().await;
            dbg!(&resp);
            let sig: Result<KeyGenResponse> = serde_json::from_slice(resp.body())
                .with_context(|| "Failed to parse to KeyGenResponse");
            (resp.status().into(), sig)
        }
    }
}

pub async fn register_new_bls_key(port: Option<u16>) -> KeyGenResponse {
    let (status, resp) = make_bls_keygen_request(port).await;
    assert_eq!(status, 200);
    resp.unwrap()
}

#[tokio::test]
async fn test_register_new_bls_key() {
    let port = read_secure_signer_port();
    let resp = register_new_bls_key(port).await;
    dbg!(resp.pk_hex);
}

#[tokio::test]
async fn test_bls_key_in_remote_attestation_evidence() {
    match env::var("LOCAL_DEV") {
        // Disable test if local dev is set.
        Ok(_e) => {

        },

        // Local dev is not set so use SGX.
        Err(_e) => {
            let port = read_secure_signer_port();
            let resp = register_new_bls_key(port).await;
            dbg!(&resp.pk_hex);
        
            // Verify the report is valid
            resp.evidence.verify_intel_signing_certificate().unwrap();
        
            // Verify the payload
            let pk_hex: String = strip_0x_prefix!(&resp.pk_hex);
            let pk = PublicKey::from_hex(&pk_hex).unwrap();
        
            let got_payload: [u8; 64] = resp.evidence.get_report_data().unwrap();
            assert_eq!(hex::encode(&got_payload[0..BLS_PUB_KEY_BYTES]), pk.to_hex());
        },
    }
}