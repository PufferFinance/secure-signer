use axum::response::IntoResponse;

pub async fn handler() -> axum::response::Response {
    (axum::http::status::StatusCode::OK).into_response()
}
