use crate::common::{
    bls_keygen_helper::register_new_bls_key, eth_keygen_helper::register_new_eth_key,
};
use puffersecuresigner::api::getter_routes::{
    list_bls_keys_route, list_eth_keys_route, ListKeysResponse,
};

use super::read_secure_signer_port;

use puffersecuresigner::strip_0x_prefix;

use anyhow::{Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde_json;

pub async fn mock_list_eth_keys_route() -> warp::http::Response<bytes::Bytes> {
    let filter = list_eth_keys_route();
    let res = warp::test::request()
        .method("GET")
        .path("/eth/v1/keygen/secp256k1")
        .reply(&filter)
        .await;
    res
}

pub async fn request_list_eth_keys_route(port: u16) -> Result<Response, reqwest::Error> {
    let client = Client::new();
    let url = format!("http://localhost:{}/eth/v1/keygen/secp256k1", port);
    let response = client.get(&url).send().await;

    response
}

pub async fn mock_list_bls_keys_route() -> warp::http::Response<bytes::Bytes> {
    let filter = list_bls_keys_route();
    let res = warp::test::request()
        .method("GET")
        .path("/eth/v1/keystores")
        .reply(&filter)
        .await;
    res
}

pub async fn request_list_bls_keys_route(port: u16) -> Result<Response, reqwest::Error> {
    let client = Client::new();
    let url = format!("http://localhost:{}/eth/v1/keystores", port);
    let response = client.get(&url).send().await;

    response
}
pub enum ListRequestKind {
    BLS,
    ETH,
}

pub async fn make_list_request(
    t: ListRequestKind,
    port: Option<u16>,
) -> (StatusCode, Result<ListKeysResponse>) {
    match port {
        // Make the actual http req to a running Secure-Signer instance
        Some(p) => match t {
            ListRequestKind::BLS => {
                let resp = match request_list_bls_keys_route(p).await {
                    Ok(resp) => resp,
                    Err(_) => panic!("Failed request_list_bls_keys_route"),
                };
                dbg!(&resp);
                let status = resp.status();
                let keys: Result<ListKeysResponse> = resp
                    .json()
                    .await
                    .with_context(|| format!("Failed to parse to ListKeysResponse"));
                (status, keys)
            }
            ListRequestKind::ETH => {
                let resp = match request_list_eth_keys_route(p).await {
                    Ok(resp) => resp,
                    Err(_) => panic!("Failed request_list_eth_keys_route"),
                };

                let status = resp.status();
                let keys: Result<ListKeysResponse> = resp
                    .json()
                    .await
                    .with_context(|| format!("Failed to parse to ListKeysResponse"));

                (status, keys)
            }
        },
        // Mock an http request
        None => match t {
            ListRequestKind::BLS => {
                let resp = mock_list_bls_keys_route().await;
                dbg!(&resp);
                let keys: Result<ListKeysResponse> = serde_json::from_slice(resp.body())
                    .with_context(|| "Failed to parse to ListKeysResponse");
                (resp.status().into(), keys)
            }
            ListRequestKind::ETH => {
                let resp = mock_list_eth_keys_route().await;
                dbg!(&resp);
                let keys: Result<ListKeysResponse> = serde_json::from_slice(resp.body())
                    .with_context(|| "Failed to parse to ListKeysResponse");
                (resp.status().into(), keys)
            }
        },
    }
}

/// Verifies the supplied bls_pk_hex is one of the returned keys when querying the Secure-Signer's known bls keys
pub async fn bls_key_exists(bls_pk_hex: &str, port: Option<u16>) -> bool {
    let bls_pk_hex: String = strip_0x_prefix!(bls_pk_hex);
    let (status, keys) = make_list_request(ListRequestKind::BLS, port).await;
    assert_eq!(status, 200);
    let keys = keys.unwrap().data;
    dbg!(&keys);
    keys.iter().any(|k| {
        let pk: String = strip_0x_prefix!(k.pubkey);
        pk == bls_pk_hex
    })
}

/// Verifies the supplied eth_pk_hex is one of the returned keys when querying the Secure-Signer's known eth keys
pub async fn eth_key_exists(eth_pk_hex: &str, port: Option<u16>) -> bool {
    let eth_pk_hex: String = strip_0x_prefix!(eth_pk_hex);
    let (status, keys) = make_list_request(ListRequestKind::ETH, port).await;
    assert_eq!(status, 200);
    let keys = keys.unwrap().data;
    dbg!(&keys);
    keys.iter().any(|k| {
        let pk: String = strip_0x_prefix!(k.pubkey);
        pk == eth_pk_hex
    })
}

#[tokio::test]
async fn verify_list_bls_keys_works() {
    let port = read_secure_signer_port();
    let (status, keys) = make_list_request(ListRequestKind::BLS, port).await;
    assert_eq!(status, 200);
    let num_exist = keys.unwrap().data.len();

    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    assert!(bls_key_exists(&bls_pk_hex, port).await);

    let bls_pk_hex = register_new_bls_key(port).await.pk_hex;
    assert!(bls_key_exists(&bls_pk_hex, port).await);

    let (status, keys) = make_list_request(ListRequestKind::BLS, port).await;
    assert_eq!(status, 200);

    assert_eq!(keys.unwrap().data.len(), num_exist + 2);
}

#[tokio::test]
async fn verify_list_eth_keys_works() {
    let port = read_secure_signer_port();
    let (status, keys) = make_list_request(ListRequestKind::ETH, port).await;
    assert_eq!(status, 200);
    let num_exist = keys.unwrap().data.len();

    let eth_pk_hex = register_new_eth_key(port).await.pk_hex;
    assert!(eth_key_exists(&eth_pk_hex, port).await);

    let eth_pk_hex = register_new_eth_key(port).await.pk_hex;
    assert!(eth_key_exists(&eth_pk_hex, port).await);

    let (status, keys) = make_list_request(ListRequestKind::ETH, port).await;
    assert_eq!(status, 200);

    assert_eq!(keys.unwrap().data.len(), num_exist + 2);
}
