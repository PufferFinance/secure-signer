use anyhow::{Result, Context, bail};
use blst::min_pk::SecretKey;
use ecies::decrypt;
use warp::{reply, Filter, http::Response, http::StatusCode};
use crate::attest::fetch_dummy_evidence;
use crate::datafeed::{get_btc_price_feed, get_request, post_request, post_request_no_body};
use crate::common_api::{KeyProvisionRequest, KeyProvisionResponse, ListKeysResponse, KeyGenResponse, KeyImportRequest, KeyImportResponse, epid_remote_attestation_service, AttestationRequest, eth_key_gen_service, list_eth_keys_service, bls_key_gen_service, list_generated_bls_keys_service, bls_key_import_service, list_imported_bls_keys_service};
use crate::keys::{eth_key_gen, pk_to_eth_addr, read_eth_key, new_eth_key, write_key};
use crate::leader_api::{bls_key_provision_service, bls_key_aggregator_service};
use crate::worker_api::{list_generated_bls_keys_request, bls_key_gen_request, bls_key_gen_provision_request, bls_key_import_request};


/// TODO
pub fn epid_remote_attestation_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("remote-attestation"))
        .and(warp::body::json::<AttestationRequest>())
        .and_then(epid_remote_attestation_service)
}

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned 
pub fn eth_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("eth"))
        .and_then(eth_key_gen_service)
}

/// Returns the hex-encoded BLS public keys that have their corresponding secret keys safeguarded in Enclave memory. 
pub fn list_generated_eth_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("eth"))
        .and_then(list_eth_keys_service)
}

/// Generates a new BLS private key in Enclave. To remain compatible with web3signer POST /eth/v1/keystores, the JSON body is not parsed. The BLS public key is returned 
pub fn bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(bls_key_gen_service)
}

/// Returns the hex-encoded BLS public keys that have their corresponding secret keys safeguarded in Enclave memory. 
pub fn list_generated_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(list_generated_bls_keys_service)
}

/// Imports a BLS private key to the Enclave. 
pub fn bls_key_import_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and(warp::body::json())
        .and_then(bls_key_import_service)
}

/// Returns the hex-encoded BLS public keys that have their corresponding secret keys safeguarded in Enclave memory. 
pub fn list_imported_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_imported_bls_keys_service)
}

/// @WORKER ROUTE
pub fn request_list_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_generated_bls_keys_request)
}


/// @WORKER ROUTE
pub fn request_bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(bls_key_gen_request)
}

/// @WORKER ROUTE
/// Sample worker route for getting a specific datafeed
pub fn btc_pricefeed_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("datafeed"))
        .and_then(get_btc_price_feed)
}


/// @WORKER ROUTE
/// Worker generates ephemeral ETH key for envelope encryption, commits it to quote, 
/// performs remote attestation, then requests the Leader to provision a new BLS key. The 
/// Leader will only provision if RA evidence is valid, then will encrypt the BLS SK using
/// ephemeral ETH key and respond to the Worker.
pub fn request_bls_key_provision_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("provision"))
        .and_then(bls_key_gen_provision_request)
}


/// Asks the server Sample client route for getting a specific datafeed
pub fn request_bls_key_import_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and(warp::path("import"))
        .and(warp::body::json())
        .and_then(bls_key_import_request)
}

/// @WORKER ROUTE
/// the route to call `bls_key_provision_service`
pub fn bls_key_provision_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("provision"))
        .and(warp::body::json())
        .and_then(bls_key_provision_service)
}


/// @LEADER ROUTE
/// the route to call `bls_key_aggregator_service`
pub fn bls_key_aggregator_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("portal"))
        .and(warp::path("v1"))
        .and(warp::path("aggregate"))
        .and_then(bls_key_aggregator_service)
}