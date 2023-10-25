use axum::{response::IntoResponse, Json};
use log::{error, info};

use crate::io::key_management;

pub async fn handler() -> axum::response::Response {
    info!("list_eth_keys()");
    match key_management::list_eth_keys() {
        Ok(list_res) => {
            let resp = crate::enclave::types::ListKeysResponse::new(list_res);
            (axum::http::status::StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            error!("list_eth_keys() failed with: {:?}", e);
            axum::http::status::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
