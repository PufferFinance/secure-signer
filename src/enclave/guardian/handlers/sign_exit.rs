use axum::response::IntoResponse;
use axum::Json;
use log::{error, info};

pub async fn handler(
    Json(request): Json<crate::enclave::types::SignExitRequest>,
) -> axum::response::Response {
    info!("sign_exit()");
    match crate::enclave::guardian::sign_voluntary_exit_message(request) {
        Ok(resp) => (axum::http::status::StatusCode::OK, Json(resp)).into_response(),

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
