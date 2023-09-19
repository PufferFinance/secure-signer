use axum::{response::IntoResponse, Json};
use log::{error, info};

use crate::io::key_management;

pub async fn handler() -> axum::response::Response {
    info!("list_bls_keys()");
    match key_management::list_bls_keys() {
        Ok(list_res) => {
            let resp = crate::enclave::types::ListKeysResponse::new(list_res);
            (axum::http::status::StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            error!("list_bls_keys() failed with: {:?}", e);
            axum::http::status::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
