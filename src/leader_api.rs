use crate::keys::{bls_key_gen, bls_key_provision};
use crate::attest::{epid_remote_attestation, AttestationEvidence};
use crate::common_api::{KeyProvisionRequest, KeyProvisionResponse, ListKeysResponse, KeyGenResponse, KeyGenResponseInner, ListKeysResponseInner};

use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize, Serialize};
use warp::{reply, Filter, http::Response, http::StatusCode};
use std::collections::HashMap;



/// Given a `KeyProvisionRequest`, the server will generate a new
/// BLS secret key, encrypt it via ECDH and the requester's Eth pub key,
/// then return the ciphertext bls secret key and plaintext bls public key
/// in a `KeyProvisionResponse`. This will only succeed if the server can
/// successfully verify the `AttestationEvidence`, and the committed to
/// public key matches the supplied `eth_pk_hex`.
pub async fn bls_key_provision_service(req: KeyProvisionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // Verify attestation evidence is from IAS
    match req.evidence.verify_intel_signing_certificate() {
        Ok(()) => {},
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            return Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR));
        }
    }
    
    // TODO verify the req.bls_pk is the same committed in the attestation evidence
    let exp_pk = match req.evidence.get_eth_pk() {
        Ok(pk) => pk,
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            return Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST));
        }
    };

    // TODO uncomment this when sending real attestation reports
    if req.eth_pk_hex != hex::encode(exp_pk.serialize()) {
    //     let mut resp = HashMap::new();
    //     resp.insert("error", "eth_pk_hex does not match pk embedded in attestation evidence");
    //     return Ok(reply::with_status(reply::json(&resp), StatusCode::BAD_REQUEST));
    }

    // generate bls sk, encrypt it, respond
    match bls_key_provision(&req.eth_pk_hex) {
        Ok((ct_bls_sk_hex, bls_pk)) => {
            // TODO the leader should save this bls_pk

            let bls_pk_hex = hex::encode(bls_pk.compress());
            let resp = KeyProvisionResponse {
                ct_bls_sk_hex: ct_bls_sk_hex,
                bls_pk_hex: bls_pk_hex,
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
    use std::fs;

    fn fetch_dummy_evidence() -> AttestationEvidence {
        let data = fs::read_to_string("./attestation_evidence.json").expect("Unable to read file");

        let evidence: AttestationEvidence = serde_json::from_slice(data.as_bytes()).unwrap();

        println!("{:?}", evidence);
        evidence
    }

    #[tokio::test]
    async fn test_bls_key_provision_route() {
        let filter = bls_key_provision_route();

        // simulate a requester who knows sk
        let (sk, pk) = new_eth_key().unwrap();

        let eth_pk_hex = hex::encode(pk.serialize());

        // let evidence = AttestationEvidence::default();
        let evidence = fetch_dummy_evidence();

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