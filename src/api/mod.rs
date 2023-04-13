pub mod helpers;
pub mod signing_route;
pub mod bls_keygen_route;
pub mod eth_keygen_route;
pub mod bls_import_route;
pub mod getter_routes;

use crate::{crypto::eth_keys, io::remote_attestation::AttestationEvidence, strip_0x_prefix};
use serde::{Deserialize, Serialize};
use ecies::PublicKey as EthPublicKey;
use blsttc::PublicKey as BlsPublicKey;
use warp::{Filter,Reply, Rejection};


/// Returns a 200 status code if server is alive
pub fn upcheck_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::get()
        .and(warp::path("upcheck"))
        .and(warp::any().map(warp::reply))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyGenResponse {
    pub pk_hex: String,
    pub evidence: AttestationEvidence,
}

impl KeyGenResponse {
    pub fn from_eth_key(pk: EthPublicKey, evidence: AttestationEvidence) -> Self {
        KeyGenResponse {
            pk_hex: format!("0x{}", eth_keys::eth_pk_to_hex(&pk)),
            evidence
        }
    }

    pub fn from_bls_key(pk: BlsPublicKey, evidence: AttestationEvidence) -> Self {
        KeyGenResponse {
            pk_hex: format!("0x{}", &pk.to_hex()),
            evidence
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportRequest {
    /// The BLS keystore to import
    pub keystore: String,
    /// The encrypted keystore password
    pub ct_password_hex: String,
    /// The SECP256K1 public key safeguarded in TEE that encrypted ct_password
    pub encrypting_pk_hex: String,
    /// JSON serialized representation of the slash protection data in format defined in EIP-3076
    pub slashing_protection: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponseInner {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyImportResponse {
    pub data: [KeyImportResponseInner; 1],
}

impl KeyImportResponse {
    pub fn new(pk_hex: String) -> Self {
        // prepend 0x
        let message: String = strip_0x_prefix!(pk_hex);
        let message: String = "0x".to_string() + &message;
        let data = KeyImportResponseInner {
            status: "imported".to_string(),
            message,
        };

        KeyImportResponse { data: [data] }
    }
}