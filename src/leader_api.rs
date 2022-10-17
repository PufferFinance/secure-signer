use crate::keys::{bls_key_provision, list_keys, bls_pk_from_hex};
use crate::common_api::{KeyProvisionRequest, KeyProvisionResponse};

use anyhow::{Result, Context, bail};
use blst::BLST_ERROR;
use blst::min_pk::{PublicKey, AggregatePublicKey};
use serde_derive::{Deserialize, Serialize};
use sha3::digest::typenum::Gr;
use warp::{reply, http::StatusCode};
use std::collections::HashMap;



pub fn bls_key_provision_verifier(req: KeyProvisionRequest) -> Result<KeyProvisionResponse> {
    // Verify attestation evidence is from IAS
    req.evidence.verify_intel_signing_certificate().with_context(|| "bls_key_provision_verifier(): failed to verify intel sig in attestation evidence")?;
    
    // Extract bls pk from attestation evidence
    let exp_pk = req.evidence.get_eth_pk().with_context(|| "bls_key_provision_verifier(): failed to extract bls pk from attestation evidence")?;

    // TODO uncomment this when sending real attestation reports
    // TODO verify the pk is the same committed in the attestation evidence
    if req.eth_pk_hex != hex::encode(exp_pk.serialize()) {
        // bail!("Error, supplied pk {} does not match pk in attestation evidence")
    }

    // generate bls sk, encrypt it, respond
    match bls_key_provision(&req.eth_pk_hex) {
        Ok((ct_bls_sk_hex, bls_pk_hex)) => {
            Ok(KeyProvisionResponse {
                ct_bls_sk_hex: ct_bls_sk_hex,
                bls_pk_hex: bls_pk_hex,
            })
        },
        Err(e) => bail!("bls_key_provision() failed")
    }
}

/// Given a `KeyProvisionRequest`, the server will generate a new
/// BLS secret key, encrypt it via ECDH and the requester's Eth pub key,
/// then return the ciphertext bls secret key and plaintext bls public key
/// in a `KeyProvisionResponse`. This will only succeed if the server can
/// successfully verify the `AttestationEvidence`, and the committed to
/// public key matches the supplied `eth_pk_hex`.
pub async fn bls_key_provision_service(req: KeyProvisionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match bls_key_provision_verifier(req) {
        Ok(resp) => Ok(reply::with_status(reply::json(&resp), StatusCode::OK)),
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct BLSKeyAggregatorResponse {
    pub bls_agg_key_hex: String,
    pub bls_pks_hexs: Vec<String>,
}

pub fn bls_key_aggregator() -> Result<(AggregatePublicKey, Vec<String>)> {
    // Read the public keys of each member as hex strings
    let pk_hexs = list_keys("./etc/keys/provisioned")?;

    // convert the hex pks to pks
    let mut pks: Vec<PublicKey> = Vec::new();
    for pk_hex in pk_hexs.clone() {
        match bls_pk_from_hex(pk_hex.clone()) {
            Ok(pk) => pks.push(pk),
            Err(e) => bail!("bls_key_aggregator() could not convert pk_hex: {} to bls pk, e: {:?}", pk_hex, e),
        }
    }

    let pks_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();

    let agg_pk_res = AggregatePublicKey::aggregate(&pks_refs, true);
    match agg_pk_res.err() {
        Some(BLST_ERROR::BLST_SUCCESS) | None => {
            let agg_pk = agg_pk_res.unwrap();
            println!("agg_pk: {:?}", hex::encode(agg_pk.to_public_key().to_bytes()));
            Ok((agg_pk, pk_hexs))
        },
        _ => bail!("Failed to aggregate BLS pub keys"),
    }

}


// get aggregate pk
pub async fn bls_key_aggregator_service() -> Result<impl warp::Reply, warp::Rejection> {
    match bls_key_aggregator() {
        Ok((agg_pk, bls_pks_hexs)) => {

            let bls_agg_key_hex = hex::encode(agg_pk.to_public_key().compress());
            let resp = BLSKeyAggregatorResponse {
                bls_agg_key_hex,
                bls_pks_hexs
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

#[derive(Deserialize, Serialize, Debug)]
pub struct GroupFormationRequest {
    pub provision_reqs: Vec<KeyProvisionRequest>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GroupFormationResponse {
    pub bls_agg_key_hex: String,
    pub provisions: Vec<KeyProvisionResponse>
}

pub async fn batch_provision(req: GroupFormationRequest) -> Result<GroupFormationResponse> {
    let mut resps = Vec::new();
    // Verify attestation evidence and generate encrypted bls sk for each req
    for r in req.provision_reqs.into_iter() {
        match bls_key_provision_verifier(r) {
            Ok(resp) => resps.push(resp),
            Err(e) => bail!("batch_provision() fail: {:?}", e),
        }
    }

    // convert the hex bls pks to pks
    let mut bls_pks: Vec<PublicKey> = Vec::new();
    for resp in resps.iter() {
        match bls_pk_from_hex(resp.bls_pk_hex.clone()) {
            Ok(pk) => bls_pks.push(pk),
            Err(e) => bail!("bls_key_aggregator() could not convert pk_hex: {} to bls pk, e: {:?}", resp.bls_pk_hex, e),
        }
    }
    let pks_refs: Vec<&PublicKey> = bls_pks.iter().map(|pk| pk).collect();

    // create the bls aggregate pub key
    let agg_pk_res = AggregatePublicKey::aggregate(&pks_refs, true);
    match agg_pk_res.err() {
        Some(BLST_ERROR::BLST_SUCCESS) | None => {
            let agg_pk = agg_pk_res.unwrap();
            let bls_agg_key_hex = hex::encode(agg_pk.to_public_key().to_bytes());
            println!("agg_pk: {:?}", bls_agg_key_hex);
            Ok(GroupFormationResponse { 
                bls_agg_key_hex,
                provisions: resps,
            })
        },
        _ => bail!("Failed to aggregate BLS pub keys"),
    }
}

pub async fn batch_provision_service(req: GroupFormationRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match batch_provision(req).await {
        Ok(resp) => Ok(reply::with_status(reply::json(&resp), StatusCode::OK)),
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{new_bls_key, new_eth_key, CIPHER_SUITE, aggregate_uniform_bls_sigs};
    use crate::attest::{AttestationEvidence, fetch_dummy_evidence};
    use crate::routes::*;
    use ecies::{decrypt};
    use blst::min_pk::{SecretKey, PublicKey, Signature};
    use ecies::PublicKey as EthPublicKey;
    use ecies::SecretKey as EthSecretKey;
    use std::fs;

    async fn call_bls_key_provision_route() -> (EthSecretKey, KeyProvisionResponse) {
        let filter = bls_key_provision_route();

        // simulate a requester who knows sk
        let (sk, pk) = new_eth_key().unwrap();

        let eth_pk_hex = hex::encode(pk.serialize());

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

        (sk, resp)
    }

    #[tokio::test]
    async fn test_bls_key_provision_route() {
        let (sk, resp) = call_bls_key_provision_route().await;

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


    async fn call_bls_key_aggregator_route() -> BLSKeyAggregatorResponse {
        let filter = bls_key_aggregator_route();

        // mock the request
        let res = warp::test::request()
            .method("GET")
            .header("accept", "application/json")
            .path("/portal/v1/aggregate")
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        // parse the resp
        let resp: BLSKeyAggregatorResponse = serde_json::from_slice(&res.body()).unwrap();

        resp
    }

    #[tokio::test]
    async fn test_bls_key_aggregator_route() {
        fs::remove_dir_all("./etc/keys/provisioned").unwrap();
        let n = 5;
        let mut sks = Vec::new();
        let mut resps = Vec::new();

        // Provision n keys
        for _ in 0..n {
            let (sk, resp) = call_bls_key_provision_route().await;
            sks.push(sk);
            resps.push(resp);
        }

        let resp = call_bls_key_aggregator_route().await;
        println!("{:?}", resp);
    }

    async fn call_bls_key_batch_provisioner_route(req: GroupFormationRequest) -> GroupFormationResponse {
        let filter = bls_key_batch_provisioner_route();

        // mock the request
        let res = warp::test::request()
            .method("POST")
            .header("accept", "application/json")
            .path("/portal/v1/provision/batch")
            .json(&req)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 200);

        // parse the resp
        let resp: GroupFormationResponse = serde_json::from_slice(&res.body()).unwrap();

        resp
    }

 #[tokio::test]
    async fn test_bls_key_batch_provisioner_route() {
        fs::remove_dir_all("./etc/keys/provisioned").unwrap();
        let n = 5;
        let mut sks = Vec::new();
        let mut reqs = Vec::new();

        // prepare n KeyProvisionRequest 
        for _ in 0..n {
            let (sk, pk) = new_eth_key().unwrap();
            sks.push(sk.clone());

            reqs.push(KeyProvisionRequest {
                eth_pk_hex: hex::encode(pk.serialize()),
                evidence: fetch_dummy_evidence(),
            });
        }

        let group_req = GroupFormationRequest {
            provision_reqs: reqs
        };

        let resp = call_bls_key_batch_provisioner_route(group_req).await;
        println!("{:?}", resp);

        let provisions = resp.provisions;

        let mut sigs = Vec::new();
        let msg = b"something to sign!";
        for (prov, sk) in provisions.into_iter().zip(sks.into_iter()) {
            // hex decode the ciphertext bls key
            let ct_bls_sk = hex::decode(prov.ct_bls_sk_hex).unwrap();

            // requester can decrypt ct_bls_sk
            let bls_sk_bytes = decrypt(&sk.serialize(), &ct_bls_sk).unwrap();

            // the BLS sk can be recovered from bytes
            let bls_sk = SecretKey::from_bytes(&bls_sk_bytes).unwrap();

            // test 1: assert this recovered bls sk derives the expected bls pk
            let exp_pk = PublicKey::from_bytes(&hex::decode(prov.bls_pk_hex).unwrap()).unwrap();

            assert_eq!(bls_sk.sk_to_pk(), exp_pk);

            // test 2: try signing something and verifying with expected pk
            let sig = bls_sk.sign(msg, CIPHER_SUITE, &[]);
            sigs.push(sig);
            assert_eq!(sig.verify(false, msg, CIPHER_SUITE, &[], &exp_pk, false), blst::BLST_ERROR::BLST_SUCCESS);
        }

        let sigs_ref: Vec<&Signature> = sigs.iter().map(|sig| sig).collect();
        let agg_pk_dec = PublicKey::from_bytes(&hex::decode(resp.bls_agg_key_hex).unwrap()).unwrap();
        let agg_pk = AggregatePublicKey::from_public_key(&agg_pk_dec);

        // aggregate all of the signatures and verify with group sig
        assert!(aggregate_uniform_bls_sigs(agg_pk, sigs_ref, msg).is_ok());
    }
}