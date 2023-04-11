pub mod helpers;
pub mod signing_route;
pub mod bls_keygen_route;
pub mod eth_keygen_route;

use crate::{crypto::eth_keys, io::remote_attestation::AttestationEvidence};
use serde::{Deserialize, Serialize};
use ecies::PublicKey as EthPublicKey;
use blsttc::PublicKey as BlsPublicKey;


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