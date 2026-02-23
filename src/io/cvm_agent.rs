use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// CVM Agent sign request body
#[derive(Serialize)]
pub struct SignRequest {
    pub message: String,
}

/// CVM Agent sign response body
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SignResponse {
    pub session_id: String,
    pub signature: String,
    pub session_public_key: String,
}

/// HTTP client for the CVM Agent running inside the Confidential VM.
///
/// In production, `cvm-agent` runs as a daemon on the CVM and listens on port 7999.
/// For local development, use `atakit sim-agent` which provides a mock implementation.
pub struct CvmAgentClient {
    base_url: String,
    client: reqwest::Client,
}

impl CvmAgentClient {
    pub fn new() -> Self {
        let base_url = std::env::var("CVM_AGENT_URL")
            .unwrap_or_else(|_| "http://localhost:7999".to_string());
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Sign a message using the CVM session key.
    ///
    /// The session key is registered on-chain via `SessionRegistry` and can be
    /// verified by calling `SessionRegistry.verifySessionSignature()`.
    pub async fn sign(&self, message: &[u8]) -> Result<SignResponse> {
        let hex_msg = format!("0x{}", hex::encode(message));
        let resp = self
            .client
            .post(format!("{}/sign", self.base_url))
            .json(&SignRequest { message: hex_msg })
            .send()
            .await
            .context("Failed to call cvm-agent /sign")?
            .error_for_status()
            .context("cvm-agent /sign returned error")?
            .json::<SignResponse>()
            .await
            .context("Failed to parse cvm-agent /sign response")?;
        Ok(resp)
    }
}
