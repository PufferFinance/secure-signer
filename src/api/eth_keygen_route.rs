use super::helpers::{error_response, success_response};
use super::KeyGenResponse;
use crate::{crypto::eth_keys, io::remote_attestation::AttestationEvidence};
use anyhow::Result;
use ecies::PublicKey as EthPublicKey;
use log::info;
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned
/// Route added by Secure-Signer
pub fn eth_keygen_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(eth_keygen_service)
}

fn attest_new_eth_key() -> Result<(AttestationEvidence, EthPublicKey)> {
    // Generate a fresh SECP256K1 ETH keypair (saving ETH private key)
    let pk = eth_keys::eth_key_gen()?;

    // Commit to the payload
    let proof = AttestationEvidence::new(&pk.serialize_compressed())?;
    Ok((proof, pk))
}

/// Generates, saves, and performs remote attestation on a new ETH key. Returns a `KeyGenResponse` on success.
async fn eth_keygen_service() -> Result<impl Reply, Rejection> {
    info!("eth_key_gen_service()");
    match attest_new_eth_key() {
        Ok((evidence, eth_pk)) => {
            let resp = KeyGenResponse::from_eth_key(eth_pk, evidence);
            Ok(success_response(&resp))
        }
        Err(e) => {
            return Ok(error_response(
                &format!("eth_keygen_service failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}
