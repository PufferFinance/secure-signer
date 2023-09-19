use axum::response::IntoResponse;
use axum::Json;
use log::{error, info};

/// Generates, saves, and performs remote attestation on a new ETH key. Returns a `KeyGenResponse` on success.
pub async fn handler() -> axum::response::Response {
    info!("eth_key_gen_service()");
    match crate::enclave::secure_signer::attest_new_eth_key() {
        Ok((evidence, eth_pk)) => {
            let resp = crate::enclave::types::KeyGenResponse::from_eth_key(eth_pk, evidence);
            (axum::http::status::StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => {
            error!("eth_key_gen_service() failed with: {}", e);
            (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("eth_key_gen_service failed: {:?}", e),
            )
                .into_response()
        }
    }
}
