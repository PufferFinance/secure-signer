use anyhow::Result;
use log::info;
use serde_derive::{Deserialize, Serialize};

use crate::io::cvm_agent::CvmAgentClient;

/// Attestation evidence from the CVM Agent.
///
/// In the atakit/TDX model, attestation is workload-level (registered on-chain
/// via `SessionRegistry`) rather than per-request. The CVM Agent signs each
/// payload with the session key, and clients verify the signature on-chain via
/// `SessionRegistry.verifySessionSignature()`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub session_id: String,
    pub signature: String,
    pub session_public_key: String,
}

impl AttestationEvidence {
    /// Create new attestation evidence by signing `data` with the CVM session key.
    ///
    /// `data` is the payload to commit to (e.g. a public key). The CVM Agent
    /// signs it and returns the session ID, signature, and session public key.
    ///
    /// When `CVM_AGENT_STUB=true` is set (local dev/testing without a CVM Agent),
    /// returns default empty evidence — analogous to the old non-SGX stub.
    pub async fn new(data: &[u8]) -> Result<Self> {
        if std::env::var("CVM_AGENT_STUB").unwrap_or_default() == "true" {
            info!("CVM_AGENT_STUB=true, returning stub attestation evidence");
            return Ok(AttestationEvidence::default());
        }
        info!("Requesting CVM Agent attestation signature");
        let client = CvmAgentClient::new();
        let resp = client.sign(data).await?;
        Ok(AttestationEvidence {
            session_id: resp.session_id,
            signature: resp.signature,
            session_public_key: resp.session_public_key,
        })
    }
}
