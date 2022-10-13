use crate::keys::{bls_key_gen, list_bls_keys};
use crate::attest::{epid_remote_attestation};

use anyhow::{Result, Context, bail};
use serde_derive::{Deserialize, Serialize};
use warp::{reply, Filter, http::Response, http::StatusCode};
use std::collections::HashMap;

/// Runs all the logic to generate and save a new BLS key. Returns a `KeyGenResponse` on success.
pub async fn epid_remote_attestation_service(req: AttestationRequest) -> Result<impl warp::Reply, warp::Rejection> {
    match epid_remote_attestation(&req.wallet_address) {
        Ok(evidence) => {
            // TODO can embed AttestationEvidence into parent data structure
            Ok(reply::with_status(reply::json(&evidence), StatusCode::OK))
        }
        Err(e) => {
            let mut resp = HashMap::new();
            resp.insert("error", e.to_string());
            Ok(reply::with_status(reply::json(&resp), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    pub wallet_address: String,
}

/// TODO
pub fn epid_remote_attestation_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("remote-attestation"))
        .and(warp::body::json::<AttestationRequest>())
        .and_then(epid_remote_attestation_service)
}