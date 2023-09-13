use log::info;
use reqwest::StatusCode;
use warp::{reject::Rejection, reply::Reply};

use crate::api::{
    eth_keygen_route::{attest_new_eth_key_with_blockhash, KeygenWithBlockhashRequest},
    helpers::{error_response, success_response},
    KeyGenResponse,
};

/// Generates, saves, and performs remote attestation on a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn eth_keygen_service_with_blockhash(
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
