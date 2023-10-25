use std::sync::Arc;
pub struct ValidatorClient {
    pub url: String,
    pub client: Arc<reqwest::Client>,
}

impl ValidatorClient {
    pub async fn health(&self) -> bool {
        let Ok(resp) = self.client.get(format!("{}/health", self.url)).send().await else {
            return false;
        };
        resp.status() == reqwest::StatusCode::OK
    }

    pub async fn attest_fresh_bls_key(
        &self,
        payload: &crate::enclave::types::AttestFreshBlsKeyPayload,
    ) -> anyhow::Result<crate::enclave::types::BlsKeygenPayload> {
        let resp = self
            .client
            .post(format!("{}/bls/v1/keygen", self.url))
            .json(payload)
            .send()
            .await?;
        Ok(resp
            .json::<crate::enclave::types::BlsKeygenPayload>()
            .await?)
    }

    pub async fn list_bls_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        Ok(self
            .client
            .get(format!("{}/eth/v1/keystores", self.url))
            .send()
            .await?
            .json::<crate::enclave::types::ListKeysResponse>()
            .await?)
    }
}
