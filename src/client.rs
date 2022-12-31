// #[macro_use]
extern crate anyhow;

mod eth_signing;
mod eth_types;
mod keys;
mod remote_attesation;
mod route_handlers;
mod routes;

use eth_types::{DepositResponse};
use route_handlers::SecureSignerSig;

use anyhow::{bail, Context, Result};
use blst::min_pk::{PublicKey, SecretKey};
use ecies::{decrypt, encrypt};
use reqwest;
use serde::Serialize;

use eth_keystore::{decrypt_key, new};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// use crate::remote_attesation::{fetch_dummy_evidence, epid_remote_attestation};
use crate::route_handlers::{KeyGenResponse, KeyImportRequest, KeyImportResponse};

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

fn new_bls_keystore(dir: &Path, name: Option<&str>, password: &str) -> Result<PublicKey> {
    let mut rng = rand::thread_rng();
    let (private_key, fname) = new(&dir, &mut rng, password, name)?;
    println!("New keystore: {fname}");
    // get the public key
    let pk = match keys::bls_sk_from_hex(hex::encode(&private_key)) {
        Ok(sk) => sk.sk_to_pk(),
        Err(e) => {
            // sometimes generates bad encoded bls key, keep trying
            fs::remove_file(dir.join(&fname))?;
            new_bls_keystore(dir, name, password)?
        }
    };

    // println!("New keystore: {fname}");
    println!(
        "DEBUG new keystore: public key: {:?}, private_key: {:?}",
        hex::encode(pk.compress()),
        hex::encode(private_key)
    );
    Ok(pk)
}

fn new_withdrawal_key(dir: &Path, password: &str) -> Result<(String, String)> {
    let pk = new_bls_keystore(dir, None, password)?;
    let withdrawal_bls_pk_hex = "0x".to_string() + &hex::encode(pk.compress());
    let withdrawal_credentials = "0x".to_string() + &hex::encode(&keys::keccak(&pk.compress())?);
    Ok((withdrawal_bls_pk_hex, withdrawal_credentials))
}

/// Makes a Reqwest POST request to the /eth/v1/keystores API endpoint to get a KeyImportResponse
pub async fn deposit_post_request(
    pk_hex: String,
    req: String,
    host: String,
) -> Result<DepositResponse> {
    let req: serde_json::Value = serde_json::from_str(&req).unwrap();
    println!("{:#?}", req);
    let url = format!("{host}/api/v1/eth2/sign/{pk_hex}");
    let resp = post_request(&url, req)
        .await
        .with_context(|| format!("failed POST request to URL: {}", url))?
        .json::<DepositResponse>()
        .await
        .with_context(|| format!("could not parse json response from : {}", url))?;
    println!("{:#?}", resp);
    Ok(resp)
}

fn build_deposit_msg(validator_pk_hex: &str, withdrawal_credentials: &str, fork_version: &str) -> Result<String> {
    let amount: u64 = 32000000000;

    let req = format!(
        r#"
    {{
        "type": "DEPOSIT",  
        "signingRoot": "0x139d59dbb1770fdc582ff75193720352ccc76131e37ac69d0c10e7416f3f3050",
        "deposit": {{
            "pubkey": "{validator_pk_hex}",
            "withdrawal_credentials": "{withdrawal_credentials}",
            "amount":"{amount}"
        }},
        "genesis_fork_version": "{fork_version}"
    }}"#
    );
    Ok(req)
}

pub async fn get_deposit_signature(
    pk_hex: String,
    req: String,
    host: &str,
) -> Result<DepositResponse> {
    deposit_post_request(pk_hex, req, host.to_string()).await
}

const KEYSTORE_DIR: &str = "keys";

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .unwrap_or("3031".into())
        .parse::<u16>()
        .expect("BAD PORT");

    println!("Connecting to Secure-Signer on port {}", port);
    let host = format!("http://localhost:{port}");
    let keystore_path = std::env::args().nth(2).unwrap();
    let keystore_password = std::env::args().nth(3).unwrap();

    // ------- for importing -------
    // Load validator keys
    let (client_bls_sk_hex, client_bls_pk_hex) =
        keys::load_keystore(keystore_path, keystore_password.clone()).unwrap();

    // request a new ETH key from Secure-Signer
    let ss_eth_pk_hex = get_new_pk(host.clone()).await.unwrap();
    println!("Secure-Signer ETH public key: {ss_eth_pk_hex}");

    // if require_remote_attestation {
    //     // todo
    // }

    // securely import BLS private key into Secure-Signer
    let returned_bls_pk = import_bls_key(host.clone(), client_bls_sk_hex, ss_eth_pk_hex)
        .await
        .unwrap();
    println!("Secure-Signer registered BLS pk: {:?}", returned_bls_pk);
    // ------- for importing -------

    // ------- for deposit -------
    // Create withdrawal credentials
    let dir = Path::new(KEYSTORE_DIR);
    let (withdrawal_pk_hex, withdrawal_credentials) =
        new_withdrawal_key(dir, &keystore_password).unwrap();
    println!(
        "Created withdrawal key {:?} with credentials {:?}",
        withdrawal_pk_hex, withdrawal_credentials
    );

    // Send DEPOSIT message
    let fork_version = "00001020";
    let deposit_msg = build_deposit_msg(&client_bls_pk_hex, &withdrawal_credentials, fork_version).unwrap();
    println!("{:?}", deposit_msg);
    let deposit_resp = get_deposit_signature(client_bls_pk_hex.clone(), deposit_msg, &host)
        .await
        .unwrap();
    
    let pubkey = deposit_resp.pubkey;
    let withdrawal_credentials = deposit_resp.withdrawal_credentials;
    let amount = deposit_resp.amount;
    let signature = deposit_resp.signature;
    let deposit_message_root = deposit_resp.deposit_message_root;
    let deposit_data_root = deposit_resp.deposit_data_root;

    // Build deposit JSON that works with https://goerli.launchpad.ethereum.org/en/upload-deposit-data
    let dd = format!(
        r#"
    [{{
        "pubkey": "{pubkey}",
        "withdrawal_credentials": "{withdrawal_credentials}",
        "amount": {amount},
        "signature": "{signature}",
        "deposit_message_root": "{deposit_message_root}",
        "deposit_data_root": "{deposit_data_root}",
        "fork_version": "{fork_version}",
        "network_name": "goerli",
        "deposit_cli_version": "2.3.0"
    }}]"#
    );

    fs::write(dir.join("deposit_data.json"), dd).unwrap();
    // ------- for deposit -------
}
