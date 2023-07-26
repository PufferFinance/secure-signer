pub mod helpers;
pub mod signing_route;
pub mod bls_keygen_route;
pub mod eth_keygen_route;
pub mod bls_import_route;
pub mod deposit_route;
pub mod getter_routes;

use crate::{crypto::eth_keys, io::remote_attestation::AttestationEvidence, strip_0x_prefix, constants::{ETH_COMPRESSED_PK_BYTES, BLS_PUB_KEY_BYTES}};
use anyhow::{bail, Result};
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

    pub fn validate_eth_ra(&self, mrenclave: &String) -> Result<EthPublicKey> {
        // Verify the report is valid
        self.evidence.verify_intel_signing_certificate()?;

        // Verify the MRENCLAVE measurement is valid
        let mrenclave: String = strip_0x_prefix!(mrenclave);
        let got_mrenclave = self.evidence.get_mrenclave()?;
        if mrenclave != got_mrenclave {
            bail!("Received MRENCLAVE {mrenclave} does not match expected {got_mrenclave}")
        }
    
        // Get the expected public key from payload
        let pk = eth_keys::eth_pk_from_hex(&self.pk_hex)?;
    
        // Read the 64B payload from RA report
        let got_payload: [u8; 64] = self.evidence.get_report_data()?;
    
        // Verify the first ETH_COMPRESSED_PK_BYTES of report contains the expected ETH comporessed public key
        if &got_payload[0..ETH_COMPRESSED_PK_BYTES] != pk.serialize_compressed() {
            bail!("Remote attestation payload does not match the expected")
        }
        Ok(pk)
    }

    pub fn validate_bls_ra(&self, mrenclave: &String) -> Result<BlsPublicKey> {
        // Verify the report is valid
        self.evidence.verify_intel_signing_certificate()?;

        // Verify the MRENCLAVE measurement is valid
        let mrenclave: String = strip_0x_prefix!(mrenclave);
        let got_mrenclave = self.evidence.get_mrenclave()?;
        if mrenclave != got_mrenclave {
            bail!("Received MRENCLAVE {mrenclave} does not match expected {got_mrenclave}")
        }
    
        // Verify the payload
        let pk_hex: String = strip_0x_prefix!(&self.pk_hex);
        let pk = BlsPublicKey::from_hex(&pk_hex).unwrap();
    
        // Read the 64B payload from RA report
        let got_payload: [u8; 64] = self.evidence.get_report_data()?;
    
        // Verify the first BLS_PUB_KEY_BYTES of report contains the expected BLS comporessed public key
        if &got_payload[0..BLS_PUB_KEY_BYTES] != pk.to_bytes() {
            bail!("Remote attestation payload does not match the expected")
        }
        Ok(pk)
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
