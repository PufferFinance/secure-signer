use axum::{response::IntoResponse, Json};
use log::{error, info};

use crate::{io::key_management, strip_0x_prefix};

pub async fn handler() -> axum::response::Response {
    info!("list_bls_keys_for_vc()");
    match key_management::list_bls_keys() {
        Ok(list_res) => {
            // safely prepend the response with "0x" to match the expected format
            let list_res = list_res.iter().map(|x| {
                let stripped: &str = strip_0x_prefix!(x);
                format!("0x{}", stripped)
            }).collect::<Vec<String>>();
            (axum::http::status::StatusCode::OK, Json(list_res)).into_response()
        }
        Err(e) => {
            error!("list_bls_keys_for_vc() failed with: {:?}", e);
            axum::http::status::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
