use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use log::{error, info};

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub async fn handler(
    Path(bls_pk_hex): Path<String>,
    State(state): State<super::AppState>,
    Json(req): Json<crate::eth2::eth_signing::BLSSignMsg>,
) -> axum::response::Response {
    info!("secure_sign_bls()");

    // Sanitize the input bls_pk_hex
    let bls_pk_hex = match crate::crypto::bls_keys::sanitize_bls_pk_hex(&bls_pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Bad BLS public key format: {bls_pk_hex}");
            return (
                axum::http::status::StatusCode::BAD_REQUEST,
                format!("Bad bls_pk_hex, {:?}", e),
            )
                .into_response();
        }
    };

    info!("Request for validator pubkey: {bls_pk_hex}");
    info!("Request:\n{:#?}", serde_json::to_string_pretty(&req));

    // Verify not a slashable msg
    match crate::enclave::secure_signer::is_slashable(&bls_pk_hex, &req) {
        Ok(b) => match b {
            true => {
                return (
                    axum::http::status::StatusCode::PRECONDITION_FAILED,
                    format!("Signing operation failed due to slashing protection rules"),
                )
                    .into_response()
            }
            false => {}
        },
        Err(e) => {
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response()
        }
    };

    // Compute the msg to be signed
    let signing_root: crate::eth2::eth_types::Root =
        req.to_signing_root(Some(state.genesis_fork_version));
    info!("signing_root: {}", hex::encode(signing_root));

    // Update the slash protection DB if msg was a block or attestation
    if req.can_be_slashed() {
        if let Err(e) = crate::enclave::secure_signer::update_slash_protection_db(&bls_pk_hex, &req)
        {
            error!("Failed trying to update slash protection database");
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response();
        }
    }

    // Sign the message
    match crate::crypto::bls_keys::bls_agg_sign_from_saved_sk(&bls_pk_hex, &signing_root) {
        Ok(sig) => {
            info!("signature: {:?}", hex::encode(sig.to_bytes()));
            let response = crate::enclave::types::SignatureResponse::new(&sig.to_bytes());
            (axum::http::status::StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed trying to sign");
            return (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing operation failed: {:?}", e),
            )
                .into_response();
        }
    }
}
