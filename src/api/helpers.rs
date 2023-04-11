use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply};
use std::collections::HashMap;

pub fn success_response<T: Serialize>(payload: T) -> warp::reply::WithStatus<reply::Json> {
    reply::with_status(
        reply::json(&payload),
        StatusCode::OK,
    )
}

pub fn error_response(message: &str, status: StatusCode) -> warp::reply::WithStatus<reply::Json> {
    let mut resp = HashMap::new();
    resp.insert("error", message.to_string());
    reply::with_status(reply::json(&resp), status)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SignatureResponse {
    pub signature: String,
}

impl SignatureResponse {
    pub fn new(sig: &[u8]) -> Self {
        SignatureResponse {
            signature: format!("0x{}", hex::encode(sig)),
        }
    }
}

/// Return hex-encoded signature for easy JSON response
pub fn signature_success_response(sig: &[u8]) -> warp::reply::WithStatus<reply::Json> {
    let agg_sig = SignatureResponse::new(sig);
    success_response(agg_sig)
}
