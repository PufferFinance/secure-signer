use super::eth_keygen_helper::register_new_eth_key;
use super::read_secure_signer_port;

use anyhow::{Context, Result};
use puffersecuresigner::{
    api::{bls_import_route::bls_key_import_route, KeyImportRequest, KeyImportResponse},
    crypto::eth_keys, strip_0x_prefix, eth2::slash_protection::{SlashingProtectionData, SignedBlockSlot, SignedAttestationEpochs, SlashingProtectionDB},
};
use reqwest::{Client, Response, StatusCode};
use serde_json;

pub async fn mock_bls_import_route(json_req: &String) -> warp::http::Response<bytes::Bytes> {
    let filter = bls_key_import_route();
    let res = warp::test::request()
        .method("POST")
        .path("/eth/v1/keystores")
        .body(&json_req)
        .reply(&filter)
        .await;
    res
}

/// Makes a request to Secure-Aggregator aggregate_route on the specified port
pub async fn request_bls_import_route(
    json_req: &String,
    port: u16,
) -> Result<Response, reqwest::Error> {
    // Create a Reqwest client
    let client = Client::new();

    // Build the URL
    let url = format!("http://localhost:{}/eth/v1/keystores/", port);

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
pub async fn make_bls_import_request(
    req: KeyImportRequest,
    port: Option<u16>,
) -> (StatusCode, Result<KeyImportResponse>) {
    let json_req = serde_json::to_string(&req).unwrap();
    dbg!(&json_req);

    match port {
        // Make the actual http req to a running Secure-Signer instance
        Some(p) => {
            let resp = match request_bls_import_route(&json_req, p).await {
                Ok(resp) => resp,
                Err(e) => panic!("Failed request_bls_import_route"),
            };
            dbg!(&resp);
            let status = resp.status();
            let resp: Result<KeyImportResponse> = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse to KeyImportResponse"));
            (status, resp)
        }
        // Mock an http request
        None => {
            let resp = mock_bls_import_route(&json_req).await;
            dbg!(&resp);
            let out: Result<KeyImportResponse> = serde_json::from_slice(resp.body())
                .with_context(|| "Failed to parse to KeyImportResponse");
            (resp.status().into(), out)
        }
    }
}

pub async fn import_bls_key(req: KeyImportRequest, port: Option<u16>) -> KeyImportResponse {
    let (status, resp) = make_bls_import_request(req, port).await;
    assert_eq!(status, 200);
    resp.unwrap()
}

pub async fn import_bls_key_with_slash_protection(slot: u64, src: u64, tgt: u64, port: Option<u16>) -> String {
    let keystore = r#"
    {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }"#.to_string();

    let expected_pk = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string();
    // Generate a new eth keypair in enclave
    let encrypting_pk_hex = register_new_eth_key(port).await.pk_hex;
    let eth_pk = eth_keys::eth_pk_from_hex(&encrypting_pk_hex).unwrap();

    // Envelope encrypt the keystore password
    let encoded_pw = hex::decode("7465737470617373776f7264f09f9491").unwrap();
    let ct_pw = eth_keys::envelope_encrypt(&eth_pk, &encoded_pw).unwrap();
    let ct_password_hex = hex::encode(&ct_pw);

    // Prep a slash protection db
    let mut db = SlashingProtectionDB::new();
    dbg!("here");
    let mut slashing_protection = SlashingProtectionData::from_pk_hex(&expected_pk).unwrap();
    slashing_protection.new_block(SignedBlockSlot {
        slot,
        signing_root: None
    }, false).unwrap();
    dbg!("here");
    slashing_protection.new_attestation(SignedAttestationEpochs {
        source_epoch: src,
        target_epoch: tgt,
        signing_root: None
    }, false).unwrap();
    slashing_protection.write().unwrap();
    db.data.push(slashing_protection);

    dbg!("here");

    // serialize to string
    let sp = Some(serde_json::to_string(&db).unwrap());

    // build the request
    let req = KeyImportRequest {
        keystore,
        ct_password_hex,
        slashing_protection: sp,
        encrypting_pk_hex: eth_keys::eth_pk_to_hex(&eth_pk)
    };

    // make the request
    let resp = import_bls_key(req, port).await;

    // verify we imported the expected key
    let imported_bls_pk: String = strip_0x_prefix!(resp.data[0].message);
    assert_eq!(
        imported_bls_pk,
        expected_pk,
    );

    imported_bls_pk
}


#[tokio::test]
async fn test_import_bls_key() {
    let port = read_secure_signer_port();
    let got_pk = import_bls_key_with_slash_protection(1, 2, 3, port).await;
    dbg!(got_pk);
}
