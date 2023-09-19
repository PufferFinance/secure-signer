use super::read_secure_signer_port;

use anyhow::{Context, Result};
use blsttc::PublicKey;
use puffersecuresigner::{constants::BLS_PUB_KEY_BYTES, strip_0x_prefix};
use reqwest::{Client, Response, StatusCode};
use serde_json;
use std::env;

pub async fn mock_bls_keygen_route() -> Result<axum_test::TestResponse> {
    let test_app = axum::Router::new()
        .route(
            "/eth/v1/keygen/bls",
            axum::routing::post(
                puffersecuresigner::enclave::secure_signer::handlers::bls_keygen::handler,
            ),
        )
        .into_make_service();

    let server = axum_test::TestServer::new(test_app)?;

    Ok(server.post("/eth/v1/keygen/bls").await)
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

pub async fn make_bls_keygen_request(
    port: Option<u16>,
) -> Result<(
    puffersecuresigner::enclave::types::KeyGenResponse,
    StatusCode,
)> {
    match port {
        // Make the actual http req to a running Secure-Aggregator instance
        Some(p) => {
            let resp = request_bls_keygen_route(p).await?;
            dbg!(&resp);
            let status = resp.status();
            let sig: puffersecuresigner::enclave::types::KeyGenResponse = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to KeyGenResponse"))?;
            Ok((sig, status))
        }
        // Mock an http request
        None => {
            let resp = mock_bls_keygen_route().await?;
            let sig: puffersecuresigner::enclave::types::KeyGenResponse =
                serde_json::from_slice(resp.as_bytes())
                    .with_context(|| "Failed to parse to KeyGenResponse")?;
            Ok((sig, resp.status_code().into()))
        }
    }
}

pub async fn register_new_bls_key(
    port: Option<u16>,
) -> puffersecuresigner::enclave::types::KeyGenResponse {
    let (resp, status) = make_bls_keygen_request(port).await.unwrap();
    assert_eq!(status, 201);
    resp
}

#[tokio::test]
async fn test_register_new_bls_key() {
    let port = read_secure_signer_port();
    let _ = register_new_bls_key(port).await;
}

#[tokio::test]
async fn test_bls_key_in_remote_attestation_evidence() {
    if env::var("SECURE_SIGNER_PORT").is_ok() {
        // Local dev is not set so use SGX.

        let port = read_secure_signer_port();
        let resp = register_new_bls_key(port).await;
        dbg!(&resp.pk_hex);
        dbg!(&port);

        // Verify the report is valid
        resp.evidence.verify_intel_signing_certificate().unwrap();

        // Verify the payload
        let pk_hex: String = strip_0x_prefix!(&resp.pk_hex);
        let pk = PublicKey::from_hex(&pk_hex).unwrap();

        let got_payload: [u8; 64] = resp.evidence.get_report_data().unwrap();
        assert_eq!(hex::encode(&got_payload[0..BLS_PUB_KEY_BYTES]), pk.to_hex());
    }
}
