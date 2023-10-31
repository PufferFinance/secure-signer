use super::bls_keygen_helper::register_new_bls_key;

use super::read_secure_signer_port;

use anyhow::{Context, Result};
use puffersecuresigner::eth2::{eth_signing::BLSSignMsg, eth_types::GENESIS_FORK_VERSION};
use reqwest::{Client, Response, StatusCode};
use serde_json;

pub async fn mock_secure_sign_route(
    bls_pk: &String,
    signing_data: BLSSignMsg,
) -> Result<axum_test::TestResponse> {
    let uri = format!("/api/v1/eth2/sign/{}", bls_pk);
    let test_app = axum::Router::new()
        .route(
            "/api/v1/eth2/sign/:bls_pk_hex",
            axum::routing::post(
                puffersecuresigner::enclave::shared::handlers::secure_sign_bls::handler,
            ),
        )
        .with_state(
            puffersecuresigner::enclave::shared::handlers::AppState {
                genesis_fork_version: GENESIS_FORK_VERSION,
                password_file: Some("password.txt".to_string())
            },
        )
        .into_make_service();

    let server = axum_test::TestServer::new(test_app)?;

    Ok(server.post(&uri).json(&signing_data).await)
}

/// Makes a request to Secure-Aggregator aggregate_route on the specified port
pub async fn request_secure_sign_route(
    bls_pk: &String,
    sign_msg: &BLSSignMsg,
    port: u16,
) -> Result<Response, reqwest::Error> {
    let json_req = serde_json::to_string(sign_msg).unwrap();
    // Create a Reqwest client
    let client = Client::new();

    // Build the URL
    let url = format!("http://localhost:{}/api/v1/eth2/sign/{}", port, bls_pk);

    // Make the HTTP request
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(json_req.clone())
        .send()
        .await;

    response
}
/// The aggregate_route_requester function is a utility function that allows you to make an HTTP request to the aggregate route of the Secure-Aggregator service, either by mocking the request or by sending a real HTTP request to a running Secure-Aggregator instance on a specified port.
pub async fn make_signing_route_request(
    signing_data: BLSSignMsg,
    bls_pk_hex: &String,
    port: Option<u16>,
) -> Result<(
    Option<puffersecuresigner::enclave::types::SignatureResponse>,
    StatusCode,
)> {
    match port {
        // Make the actual http req to a running Secure-Signer instance
        Some(p) => {
            let resp = request_secure_sign_route(&bls_pk_hex, &signing_data, p).await?;
            let status = resp.status();
            let sig = resp
                .json::<puffersecuresigner::enclave::types::SignatureResponse>()
                .await
                .with_context(|| format!("Failed to parse to SignatureResposne"));

            Ok((sig.ok(), status))
        }
        // Mock an http request
        None => {
            let resp = mock_secure_sign_route(&bls_pk_hex, signing_data).await?;
            let status = resp.status_code();
            let sig: Option<puffersecuresigner::enclave::types::SignatureResponse> =
                serde_json::from_slice(resp.as_bytes()).ok();

            Ok((sig, status))
        }
    }
}

#[tokio::test]
async fn test_sign_route() {
    let port = read_secure_signer_port();
    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;

    let req = format!(
        r#"
        {{
            "type": "ATTESTATION",
            "fork_info":{{
                "fork":{{
                   "previous_version":"0x00000001",
                   "current_version":"0x00000001",
                   "epoch":"0"
                }},
                "genesis_validators_root":"0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
            }},
            "signingRoot": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
            "attestation": {{
                "slot": "255",
                "index": "65535",
                "beacon_block_root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69",
                "source": {{
                    "epoch": "10",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }},
                "target": {{
                    "epoch": "11",
                    "root": "0x270d43e74ce340de4bca2b1936beca0f4f5408d9e78aec4850920baf659d5b69"
                }}
            }}
        }}"#
    );

    let req: BLSSignMsg = serde_json::from_str(&req).unwrap();
    let (resp, status) = make_signing_route_request(req, &bls_pk_hex.to_string(), port)
        .await
        .unwrap();
    _ = resp.unwrap();
    assert_eq!(status, 200);
}
