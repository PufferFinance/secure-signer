use axum::{response::IntoResponse, Json};
use log::info;
use ssz::Encode;

/// Signs the DepositMessage inside the DepositRequest and returns a DepositResponse
pub async fn handler(
    Json(req): Json<crate::eth2::eth_types::DepositRequest>,
) -> axum::response::Response {
    let bls_pk_hex = hex::encode(req.deposit.pubkey.as_ssz_bytes());
    // Sanitize the input bls_pk_hex
    let bls_pk_hex = match crate::crypto::bls_keys::sanitize_bls_pk_hex(&bls_pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return (
                axum::http::status::StatusCode::BAD_REQUEST,
                format!("Bad bls_pk_hex, {:?}", e),
            )
                .into_response();
        }
    };

    if !crate::io::key_management::bls_key_exists(&bls_pk_hex) {
        return (
            axum::http::status::StatusCode::PRECONDITION_FAILED,
            format!("This validator key does not exist"),
        )
            .into_response();
    }

    info!("Deposit request for validator pubkey: {bls_pk_hex}");
    info!("Request:\n{:#?}", req);

    match crate::eth2::eth_signing::get_deposit_signature(
        bls_pk_hex,
        req.deposit,
        req.genesis_fork_version,
    ) {
        Ok(resp) => (axum::http::status::StatusCode::OK, Json(resp)).into_response(),
        Err(e) => {
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Deposit signing operation failed: {:?}", e),
            )
                .into_response();
        }
    }
}
