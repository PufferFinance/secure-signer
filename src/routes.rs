use crate::route_handlers::{
    KeyImportRequest, RemoteAttestationRequest, epid_remote_attestation_service, eth_key_gen_service, 
    list_eth_keys_service, bls_key_gen_service, list_generated_bls_keys_service, 
    bls_key_import_service, list_imported_bls_keys_service, secure_sign_bls, 
};
use warp::Filter;


/// Signs off on validator duty.
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing
pub fn bls_sign_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("v1"))
        .and(warp::path("eth2"))
        .and(warp::path("sign"))
        .and(warp::path::param())
        .and(warp::body::bytes())
        .and_then(secure_sign_bls)
}

/// Imports a BLS private key to the Enclave. 
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager
pub fn bls_key_import_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and(warp::body::json::<KeyImportRequest>())
        .and_then(bls_key_import_service)
}

/// Returns all hex-encoded BLS public keys, where the private keys were imported and saved in the Enclave.
/// https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager
pub fn list_imported_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keystores"))
        .and_then(list_imported_bls_keys_service)
}

/// Performs EPID remote attestation, committing to a public key
/// Route added by Secure-Signer
pub fn epid_remote_attestation_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("remote-attestation"))
        .and(warp::body::json::<RemoteAttestationRequest>())
        .and_then(epid_remote_attestation_service)
}

/// Generates a new ETH (SECP256K1) private key in Enclave. The ETH public key is returned 
/// Route added by Secure-Signer
pub fn eth_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(eth_key_gen_service)
}

/// Returns all hex-encoded ETH public keys, where the private keys were generated and saved in the Enclave.
/// Route added by Secure-Signer
pub fn list_generated_eth_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("secp256k1"))
        .and_then(list_eth_keys_service)
}

/// Generates a new BLS private key in Enclave. To remain compatible with web3signer POST /eth/v1/keystores, the JSON body is not parsed. The BLS public key is returned 
/// Route added by Secure-Signer
pub fn bls_key_gen_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(bls_key_gen_service)
}

/// Returns all hex-encoded BLS public keys, where the private keys were generated and saved in the Enclave.
/// Route added by Secure-Signer
pub fn list_generated_bls_keys_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("eth"))
        .and(warp::path("v1"))
        .and(warp::path("keygen"))
        .and(warp::path("bls"))
        .and_then(list_generated_bls_keys_service)
}