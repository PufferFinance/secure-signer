use super::helpers::{error_response, success_response};
use super::KeyGenResponse;
use crate::strip_0x_prefix;
use crate::{crypto::eth_keys, io::remote_attestation::AttestationEvidence};
use anyhow::Result;
use ecies::PublicKey as EthPublicKey;
use log::info;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use warp::{http::StatusCode, Filter, Rejection, Reply};

#[derive(Debug, Deserialize, Serialize)]
pub struct KeygenWithBlockhashRequest {
    pub blockhash: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeygenWithBlockhashRequestDebug {
    pub blockhash: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
}

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned
/// Route added by Guardian
pub fn eth_keygen_route_with_blockhash(
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and(warp::body::json::<KeygenWithBlockhashRequest>())
        .and_then(eth_keygen_service_with_blockhash)
}

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned
/// Route added by Guardian
pub fn eth_keygen_route_with_blockhash_debug(
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen_debug"))
        .and(warp::path("secp256k1"))
        .and(warp::body::json::<KeygenWithBlockhashRequestDebug>())
        .and_then(eth_keygen_service_with_blockhash_debug)
}

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

pub fn attest_new_eth_key_with_blockhash(
    blockhash: &str,
) -> Result<(AttestationEvidence, EthPublicKey)> {
    // Generate a fresh SECP256K1 ETH keypair (saving ETH private key)
    let pk = eth_keys::eth_key_gen()?;
    let blockhash: String = strip_0x_prefix!(blockhash);
    let blockhash = hex::decode(blockhash)?;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(&pk.serialize());
    hasher.update(&blockhash);
    let digest_bytes = hasher.finalize();

    // Commit to the payload
    let proof = AttestationEvidence::new(&digest_bytes)?;
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

/// Generates, saves, and performs remote attestation on a new ETH key. Returns a `KeyGenResponse` on success.
async fn eth_keygen_service_with_blockhash(
    request_data: KeygenWithBlockhashRequest,
) -> Result<impl Reply, Rejection> {
    info!("eth_key_gen_service()");
    match attest_new_eth_key_with_blockhash(&request_data.blockhash) {
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

/// Generates, saves, and performs remote attestation on a new ETH key. Returns a `KeyGenResponse` on success.
async fn eth_keygen_service_with_blockhash_debug(
    request_data: KeygenWithBlockhashRequestDebug,
) -> Result<impl Reply, Rejection> {
    info!("eth_key_gen_service_debug()");

    let pk = crate::crypto::eth_keys::eth_pk_from_hex_uncompressed(&request_data.public_key_hex)
        .unwrap();
    let sk = crate::crypto::eth_keys::eth_sk_from_bytes(
        hex::decode(request_data.private_key_hex).unwrap(),
    )
    .unwrap();

    eth_keys::save_eth_key(sk, pk).unwrap();
    let blockhash: String = strip_0x_prefix!(request_data.blockhash);
    let blockhash = hex::decode(blockhash).unwrap();

    let mut hasher = sha3::Keccak256::new();
    hasher.update(&pk.serialize());
    hasher.update(&blockhash);
    let digest_bytes = hasher.finalize();

    // Commit to the payload
    let proof = AttestationEvidence::new(&digest_bytes).unwrap();
    let resp = KeyGenResponse::from_eth_key(pk, proof);
    Ok(success_response(&resp))
}
