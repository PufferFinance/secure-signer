use super::helpers::{error_response, success_response};
use crate::io::key_management;

use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, Filter};

#[derive(Debug, Deserialize, Serialize)]
pub struct ListKeysResponseInner {
    pub pubkey: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub data: Vec<ListKeysResponseInner>,
}

impl ListKeysResponse {
    pub fn new(keys: Vec<String>) -> ListKeysResponse {
        let inners = keys
            .iter()
            .map(|pk| {
                // Prepend leading 0x if needed
                let pubkey = match pk[0..2].into() {
                    "0x" => pk.to_string(),
                    _ => "0x".to_owned() + &pk.to_string(),
                };
                ListKeysResponseInner {
                    pubkey: pubkey.into(),
                }
            })
            .collect();

        ListKeysResponse { data: inners }
    }
}

/// Lists the public keys of the generated BLS secret keys
async fn list_bls_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    info!("list_bls_keys_service()");
    match key_management::list_bls_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(success_response(&resp))
        }
        Err(e) => {
            return Ok(error_response(
                &format!("Failed to lookup bls keys: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}

/// Returns all hex-encoded BLS public keys, where the private keys are currently in the Enclave's custody
pub fn list_bls_keys_route(
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_bls_keys_service)
}

/// Lists the public keys of the generated ETH secret keys
async fn list_eth_keys_service() -> Result<impl warp::Reply, warp::Rejection> {
    info!("list_eth_keys_service()");
    match key_management::list_eth_keys() {
        Ok(pks) => {
            let resp = ListKeysResponse::new(pks);
            Ok(success_response(&resp))
        }
        Err(e) => {
            return Ok(error_response(
                &format!("Failed to lookup eth keys: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
}

/// Returns all hex-encoded ETH public keys, where the private keys were generated and saved in the Enclave.
pub fn list_eth_keys_route(
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(list_eth_keys_service)
}
