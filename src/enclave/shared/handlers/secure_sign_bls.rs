use axum::{
    extract::{Path, State},
    Json,
};
use log::info;

/// Signs the specific type of request
/// Maintains compatibility with https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub async fn handler(
    Path(bls_pk_hex): Path<String>,
    State(state): State<crate::enclave::shared::handlers::AppState>,
    Json(req): Json<crate::eth2::eth_signing::BLSSignMsg>,
) -> axum::response::Response {
    info!("secure_sign_bls()");
    crate::enclave::shared::sign_validator_message(Path(bls_pk_hex), State(state), Json(req))
}
