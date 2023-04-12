use super::bls_keygen_helper::register_new_bls_key;

use super::read_secure_signer_port;

use anyhow::{Context, Result};
use blsttc::{PublicKey, Signature};
use puffersecuresigner::{
    api::{signing_route::bls_sign_route, helpers::SignatureResponse},
    constants::BLS_PUB_KEY_BYTES, eth2::eth_signing::BLSSignMsg, strip_0x_prefix,
};
use reqwest::{Client, Response, StatusCode};
use serde_json;

pub async fn mock_secure_sign_route(
    bls_pk: &String,
    json_req: &String,
) -> warp::http::Response<bytes::Bytes> {
    let filter = bls_sign_route();

    let uri = format!("/api/v1/eth2/sign/{}", bls_pk);
    dbg!(format!("mocking request to: {uri}"));
    let res = warp::test::request()
        .method("POST")
        .path(&uri)
        .body(&json_req)
        .reply(&filter)
        .await;
    res
}

/// Makes a request to Secure-Aggregator aggregate_route on the specified port
pub async fn request_secure_sign_route(
    bls_pk: &String,
    json_req: &String,
    port: u16,
) -> Result<Response, reqwest::Error> {
    // Create a Reqwest client
    let client = Client::new();

    // Build the URL
    let url = format!("http://localhost:{}/api/v1/eth2/sign/{}", port, bls_pk);

    // Make the HTTP request
    let response = client.post(&url)
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
) -> (StatusCode, Result<SignatureResponse>) {
    let json_req = serde_json::to_string(&signing_data).unwrap();
    dbg!(&json_req);

    match port {
        // Make the actual http req to a running Secure-Signer instance
        Some(p) => {
            let resp = match request_secure_sign_route(&bls_pk_hex, &json_req, p).await {
                Ok(resp) => resp,
                Err(e) => panic!("Failed request_secure_sign_route"),
            };
            dbg!(&resp);
            let status = resp.status();
            let sig: Result<SignatureResponse> = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to SignatureResposne"));
            (status, sig)
        }
        // Mock an http request
        None => {
            let resp = mock_secure_sign_route(&bls_pk_hex, &json_req).await;
            dbg!(&resp);
            let sig: Result<SignatureResponse> = serde_json::from_slice(resp.body())
                .with_context(|| "Failed to parse to SignatureResponse");
            (resp.status().into(), sig)
        }
    }
}

pub fn validate_response(resp: SignatureResponse, exp_sig: Signature) -> Result<bool> {
    let got_sig: &str = strip_0x_prefix!(resp.signature);
    let got_bytes = hex::decode(got_sig)?;
    Ok(got_bytes == exp_sig.to_bytes().to_vec())
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
    let (status, resp) = make_signing_route_request(req, &bls_pk_hex.to_string(), port).await;
    assert_eq!(status, 200);
    dbg!(resp.unwrap().signature);
}

