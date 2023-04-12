use super::helpers::{error_response, success_response};
use super::KeyGenResponse;
use crate::{crypto::bls_keys, io::remote_attestation::AttestationEvidence};
use anyhow::Result;
use blsttc::PublicKey;
use log::info;
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// Generates a new BLS private key in Enclave.
pub fn bls_keygen_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(bls_keygen_service)
}

fn attest_new_bls_key() -> Result<(AttestationEvidence, PublicKey)> {
    // Generate a fresh BLS keypair (saving BLS private key)
    let sk = bls_keys::new_bls_key(0);
    let pk = sk.public_keys().public_key();

    // Commit to the payload
    let proof = AttestationEvidence::new(&pk.to_bytes())?;
    Ok((proof, pk))
}

/// Generates, saves, and performs remote attestation on a new BLS key. Returns a `KeyGenResponse` on success.
async fn bls_keygen_service() -> Result<impl Reply, Rejection> {
    info!("eth_key_gen_service()");
    match attest_new_bls_key() {
        Ok((evidence, bls_pk)) => {
            let resp = KeyGenResponse::from_bls_key(bls_pk, evidence);
            Ok(success_response(&resp))
        }
        Err(e) => {
            return Ok(error_response(
                &format!("bls_keygen_service failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}
