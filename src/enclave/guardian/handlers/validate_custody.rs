use axum::response::IntoResponse;
use axum::Json;
use log::{error, info};

pub async fn handler(
    Json(request): Json<crate::enclave::types::ValidateCustodyRequest>,
) -> axum::response::Response {
    info!("validate_custody()");
    match crate::enclave::guardian::verify_and_sign_custody_received(request) {
        Ok(resp) => {
            (axum::http::status::StatusCode::OK, Json(resp)).into_response()
        }

        Err(e) => {
            error!("{:?}", e);
            (
                axum::http::status::StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}", e),
            )
                .into_response()
        }
    }
}
