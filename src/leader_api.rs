use crate::keys::{bls_key_gen, list_bls_keys, bls_key_provision};
use crate::attest::{epid_remote_attestation, AttestationEvidence};

use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize, Serialize};
use warp::{reply, Filter, http::Response, http::StatusCode};
use std::collections::HashMap;



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
            let data = KeyGenResponseInner { status: "imported".to_string(), message: pk_hex};
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

/// Generates a new BLS private key in Enclave. To remain compatible with web3signer POST /eth/v1/keystores, the JSON body is not parsed. The BLS public key is returned 
pub fn bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(bls_key_gen_service)
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
            ListKeysResponseInner {
                pubkey: format!("0x{}", pk),
            }
        }).collect();

        ListKeysResponse {
            data: inners
        }
    }
}

pub async fn list_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    match list_bls_keys() {
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

/// Returns the hex-encoded BLS public keys that have their corresponding secret keys safeguarded in Enclave memory. 
pub fn list_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_bls_keys_service)
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
    pub evidence: AttestationEvidence,
}

/// Given a `KeyProvisionRequest`, the server will generate a new
/// BLS secret key, encrypt it via ECDH and the requester's Eth pub key,
/// then return the ciphertext bls secret key and plaintext bls public key
/// in a `KeyProvisionResponse`. This will only succeed if the server can
/// successfully verify the `AttestationEvidence`, and the committed to
/// public key matches the supplied `eth_pk_hex`.
pub async fn bls_key_provision_service(req: KeyProvisionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // TODO: verify req.evidence is valid before continuing
    // ...

    // generate bls sk, encrypt it, respond
    match bls_key_provision(&req.eth_pk_hex) {
        Ok((ct_bls_sk_hex, bls_pk)) => {
            // TODO the leader should save this bls_pk

            let bls_pk_hex = hex::encode(bls_pk.compress());
            let resp = KeyProvisionResponse {
                ct_bls_sk_hex: ct_bls_sk_hex,
                bls_pk_hex: bls_pk_hex,
                evidence: req.evidence,
            };
            Ok(reply::with_status(reply::json(&resp), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// the route to call `bls_key_provision_service`
pub fn bls_key_provision_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("provision"))
        .and(warp::body::json())
        .and_then(bls_key_provision_service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{new_bls_key, new_eth_key, CIPHER_SUITE};
    use crate::attest::{AttestationEvidence};
    use ecies::{decrypt};
    use blst::min_pk::{SecretKey, PublicKey, Signature};

    #[tokio::test]
    async fn test_bls_key_provision_route() {
        let filter = bls_key_provision_route();

        // simulate a requester who knows sk
        let (sk, pk) = new_eth_key().unwrap();

        let eth_pk_hex = hex::encode(pk.serialize());

        let evidence = AttestationEvidence::default();

        let req = KeyProvisionRequest {
            eth_pk_hex,
            evidence
        };

        // mock the request
        let res = warp::test::request()
            .method("POST")
            .header("accept", "application/json")
            .path("/portal/v1/provision")
            .json(&req)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        // parse the resp
        let resp: KeyProvisionResponse = serde_json::from_slice(&res.body()).unwrap();

        // hex decode the ciphertext bls key
        let ct_bls_sk = hex::decode(resp.ct_bls_sk_hex).unwrap();

        // requester can decrypt ct_bls_sk
        let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk).unwrap();

        // the BLS sk can be recovered from bytes
        let bls_sk = SecretKey::from_bytes(&bls_sk_bytes).unwrap();

        // test 1: assert this recovered bls sk derives the expected bls pk
        let exp_pk = PublicKey::from_bytes(&hex::decode(resp.bls_pk_hex).unwrap()).unwrap();

        assert_eq!(bls_sk.sk_to_pk(), exp_pk);

        // test 2: try signing something and verifying with expected pk
        let msg = b"something to sign!";
        let sig = bls_sk.sign(msg, CIPHER_SUITE, &[]);
        assert_eq!(sig.verify(false, msg, CIPHER_SUITE, &[], &exp_pk, false), blst::BLST_ERROR::BLST_SUCCESS);
    }
}