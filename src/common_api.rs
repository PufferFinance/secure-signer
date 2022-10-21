use crate::keys::{bls_key_gen, eth_key_gen, read_eth_key, pk_to_eth_addr, write_key, list_eth_keys, list_imported_bls_keys, list_generated_bls_keys, read_bls_key, bls_sign};
use crate::attest::{epid_remote_attestation, AttestationEvidence};

use anyhow::{Result, Context, bail};
use blst::min_pk::SecretKey;
use serde::{Deserialize, Serialize};
// use serde_derive::{Deserialize, Serialize};
use warp::{reply, Filter, http::Response, http::StatusCode};
use std::collections::HashMap;
use ecies::PublicKey as EthPublicKey;
use ecies::decrypt;

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn epid_remote_attestation_service(req: AttestationRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let from_file = true;
    match epid_remote_attestation(&req.pub_key, from_file) {
        Ok(evidence) => {
            // TODO can embed AttestationEvidence into parent data structure
            Ok(reply::with_status(reply::json(&evidence), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    pub pub_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyProvisionRequest {
    pub eth_pk_hex: String,
    pub evidence: AttestationEvidence,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyProvisionResponse {
    pub ct_bls_sk_hex: String,
    pub bls_pk_hex: String,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys.iter().map(|pk| {
            // Strip leading 0x if included
            let pubkey = match pk[0..2].into() {
                "0x" => pk[2..].to_string(),
                _ => pk.to_string(),
            };
            ListKeysResponseInner {
                pubkey: pubkey.into()
            }
        }).collect();

        ListKeysResponse {
            data: inners
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyGenResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyGenResponse {
    pub data: [KeyGenResponseInner; 1],
}

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn bls_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    let save_key = true;
    match bls_key_gen(save_key) {
        Ok(pk) => {
            let pk_hex = hex::encode(pk.compress());
            let data = KeyGenResponseInner { status: "generated".to_string(), message: pk_hex};
            let resp = KeyGenResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


/// Runs all the logic to generate and save a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn eth_key_gen_service() -> Result<impl warp::Reply, warp::Rejection> {
    match eth_key_gen() {
        Ok(pk) => {
            let pk_hex = hex::encode(pk.serialize());
            let data = KeyGenResponseInner { status: "generated".to_string(), message: pk_hex};
            let resp = KeyGenResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_imported_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_imported_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_generated_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_generated_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


pub async fn list_eth_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_eth_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlsSignRequest {
    pub msg_hex: String,
    pub bls_pk_hex: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BlsSignResponse {
    pub msg_hex: String,
    pub bls_sig_hex: String,
}

pub async fn bls_sign_data(req: BlsSignRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let msg = match hex::decode(&req.msg_hex) {
        Ok(msg) => msg,
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            return Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    };

    // Possible verify something about the msg first
    // ...

    match bls_sign(&req.bls_pk_hex, &msg) {
        Ok(sig) => {
            let resp = BlsSignResponse {
                msg_hex: req.msg_hex,
                bls_sig_hex: hex::encode(sig.serialize())
            };
            Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::OK))
        },
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            return Ok(reply::with_status(reply::json(&resp), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportRequest {
    pub ct_bls_sk_hex: String,
    pub bls_pk_hex: String,
    /// The SECP256K1 public key (hex) safeguarded in TEE
    pub encrypting_pk_hex: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponse {
    pub data: [KeyImportResponseInner; 1],
}

pub fn decrypt_and_save_imported_bls_key(req: &KeyImportRequest) -> Result<()> {
    println!("DEBUG: servicing req: {:?}", req);
    println!("reading eth key with pk: {}", req.encrypting_pk_hex);
    let sk = read_eth_key(&req.encrypting_pk_hex)?;
    let ct_bls_sk_bytes = hex::decode(&req.ct_bls_sk_hex)?;
    let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk_bytes)?;
    let bls_sk = match SecretKey::from_bytes(&bls_sk_bytes) {
        Ok(sk) => sk,
        Err(e) => bail!("decrypt_and_save_imported_bls_key() couldn't recover bls sk from import request: {:?}", e),
    };
    if hex::encode(bls_sk.sk_to_pk().serialize()) != req.bls_pk_hex {
        bail!("The imported bls sk doesn't match the expected bls pk")
    }
    let fname = format!("bls_keys/imported/{}", req.bls_pk_hex);
    let bls_sk_hex = hex::encode(bls_sk.serialize());
    // save the bls key  
    write_key(&fname, &bls_sk_hex)
}

/// Decrypts and saves an incoming encrypted BLS key. Returns a `KeyImportResponse` on success.
pub async fn bls_key_import_service(req: KeyImportRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match decrypt_and_save_imported_bls_key(&req) {
        Ok(()) => {
            // The key has successfully been saved, formulate http response
            let data = KeyImportResponseInner { status: "imported".to_string(), message: req.bls_pk_hex};
            let resp = KeyImportResponse { data: [data] };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}
