use axum::{extract::State, response::IntoResponse, Json};
use log::{error, info};

pub async fn handler(
    State(state): State<crate::enclave::shared::handlers::AppState>,
    Json(keygen_payload): Json<crate::enclave::types::AttestFreshBlsKeyPayload>,
) -> axum::response::Response {
    info!("attest_fresh_bls_key()");
    match crate::enclave::validator::attest_fresh_bls_key(
        keygen_payload.withdrawal_credentials,
        keygen_payload.guardian_pubkeys,
        keygen_payload.threshold,
        crate::eth2::eth_types::GENESIS_FORK_VERSION,
        keygen_payload.do_remote_attestation,
        state.read_password()
    ) {
        Ok(keygen_result) => {
            (axum::http::status::StatusCode::CREATED, Json(keygen_result)).into_response()
        }
        Err(e) => {
            error!("attest_fresh_bls_key() failed with: {:?}", e);
            axum::http::status::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
