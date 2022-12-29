// #[macro_use]
extern crate anyhow;

mod eth_signing;
mod eth_types;
mod keys;
mod remote_attesation;
mod route_handlers;
mod routes;

use anyhow::{bail, Context, Result};
use blst::min_pk::SecretKey;
use ecies::{decrypt, encrypt};
use reqwest;
use serde::Serialize;
use std::fs;
use warp::Filter;
use warp::{http::StatusCode, reply};
// use crate::remote_attesation::{fetch_dummy_evidence, epid_remote_attestation};
use crate::route_handlers::{KeyGenResponse, KeyImportRequest, KeyImportResponse};
// use crate::keys::{eth_key_gen, pk_to_eth_addr, read_eth_key, new_eth_key, write_key};

pub async fn post_request<T: Serialize>(url: &String, body: T) -> Result<reqwest::Response> {
    let client = reqwest::Client::new();
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| "Failed POST reqwest with body")
}

/// Makes a Reqwest POST request to the /eth/v1/keystores API endpoint to get a KeyImportResponse
pub async fn bls_key_import_post_request(
    req: KeyImportRequest,
    host: String,
) -> Result<KeyImportResponse> {
    let url = format!("{host}/eth/v1/keystores");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyImportResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

/// Makes a Reqwest POST request to the /eth/v1/kegen/secp256k1 API endpoint to get a KeyGenResponse
pub async fn eth_keygen_post_request(host: String) -> Result<KeyGenResponse> {
    let url = format!("{host}/eth/v1/keygen/secp256k1");
    let resp = post_request(&url, {})
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<KeyGenResponse>()
        .await
        .with_context(|| format!("could not parse json response from  URL: {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

async fn get_new_pk(host: String) -> Result<String> {
    let resp = eth_keygen_post_request(host).await?;
    Ok(resp.pk_hex)
}

async fn import_bls_key(
    host: String,
    client_bls_sk_hex: String,
    ss_eth_pk_hex: String,
) -> Result<KeyImportResponse> {
    // Compute bls pk
    let client_bls_sk = keys::bls_sk_from_hex(client_bls_sk_hex)?;
    let client_bls_pk_hex: String =
        "0x".to_string() + &hex::encode(client_bls_sk.sk_to_pk().compress());

    // ECDH envelope encrypt client BLS key with Secure-Signer's SECP256K1 public key
    let ss_eth_pk_hex_stripped: String = ss_eth_pk_hex
        .strip_prefix("0x")
        .unwrap_or(&ss_eth_pk_hex)
        .into();
    let ss_eth_pk_bytes = hex::decode(&ss_eth_pk_hex_stripped)?;
    let client_ct_bls_sk_bytes = encrypt(&ss_eth_pk_bytes, &client_bls_sk.serialize())?;
    let client_ct_bls_sk_hex = "0x".to_string() + &hex::encode(client_ct_bls_sk_bytes);

    // Bundle together
    let req = KeyImportRequest {
        ct_bls_sk_hex: client_ct_bls_sk_hex,
        bls_pk_hex: client_bls_pk_hex,
        encrypting_pk_hex: ss_eth_pk_hex,
    };

    println!("{:#?}", req);
    let resp = bls_key_import_post_request(req, host).await?;
    Ok(resp)
}


#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .unwrap_or("3031".into())
        .parse::<u16>()
        .expect("BAD PORT");

    println!("client connecting to Secure-Signer on port {}", port);

    // future - get from password protected keystore
    let client_bls_sk_hex = std::env::args()
        .nth(2)
        .unwrap_or("0x5528f51154c1ea9b18eab53aabc1d1a478930aaebde47730b51375df02f0076c".into());
    println!("DEBUG: using sk: {client_bls_sk_hex}");

    // check the status of Secure-Signer
    // assert!(upcheck(host)) // TODO

    // todo get from cli
    let require_remote_attestation = false;

    // request a new ETH key from Secure-Signer
    let host = format!("http://localhost:{port}");
    let ss_eth_pk_hex = get_new_pk(host.clone()).await.unwrap();
    println!("Secure-Signer ETH public key: {ss_eth_pk_hex}");

    if require_remote_attestation {
        // todo
    }

    // securely import BLS private key into Secure-Signer
    let returned_bls_pk = import_bls_key(host, client_bls_sk_hex, ss_eth_pk_hex)
        .await
        .unwrap();
    println!("Secure-Signer registered BLS pk: {:?}", returned_bls_pk);
}
