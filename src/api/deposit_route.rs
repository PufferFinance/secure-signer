use super::helpers::{error_response, success_response};
use crate::crypto::bls_keys;
use crate::eth2::eth_signing::*;
use crate::eth2::eth_types::*;
use crate::io::key_management;
use anyhow::Result;
use log::info;
use ssz::Encode;
use warp::{http::StatusCode, Filter, Rejection, Reply};

/// BLS signs an Eth2 deposit message to register a validator
pub fn validator_deposit_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("v1"))
        .and(warp::path("eth2"))
        .and(warp::path("deposit"))
        .and(warp::body::json::<DepositRequest>())
        .and_then(sign_deposit_data)
}

/// Signs the DepositMessage inside the DepositRequest and returns a DepositResponse
async fn sign_deposit_data(req: DepositRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let bls_pk_hex = hex::encode(req.deposit.pubkey.as_ssz_bytes());
    // Sanitize the input bls_pk_hex
    let bls_pk_hex = match bls_keys::sanitize_bls_pk_hex(&bls_pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(error_response(
                &format!("Bad bls_pk_hex, {:?}", e),
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    if !key_management::bls_key_exists(&bls_pk_hex) {
        return Ok(error_response(
            &format!("This validator key does not exist"),
            StatusCode::PRECONDITION_FAILED,
        ));
    }

    info!("Deposit request for validator pubkey: {bls_pk_hex}");
    info!("Request:\n{:#?}", req);

    match get_deposit_signature(bls_pk_hex, req.deposit, req.genesis_fork_version) {
        Ok(resp) => Ok(success_response(resp)),
        Err(e) => {
            return Ok(error_response(
                &format!("Deposit signing operation failed: {:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}
