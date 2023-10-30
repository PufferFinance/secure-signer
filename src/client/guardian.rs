use std::sync::Arc;

pub struct GuardianClient {
    pub url: String,
    pub client: Arc<reqwest::Client>,
}

impl GuardianClient {
    pub async fn health(&self) -> bool {
        let Ok(resp) = self.client.get(format!("{}/health", self.url)).send().await else {
            return false;
        };
        resp.status() == reqwest::StatusCode::OK
    }

    pub async fn attest_fresh_eth_key(
        &self,
        blockhash: &str,
    ) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        let data = crate::enclave::guardian::KeygenWithBlockhashRequest {
            blockhash: blockhash.to_string(),
        };

        Ok(dbg!(
            self.client
                .post(format!("{}/eth/v1/keygen", self.url))
                .json(&data)
                .send()
                .await?
        )
        .json()
        .await?)
    }

    pub async fn validate_custody(
        &self,
        request: crate::enclave::types::ValidateCustodyRequest,
    ) -> anyhow::Result<crate::enclave::types::ValidateCustodyResponse> {
        Ok(dbg!(
            self.client
                .post(format!("{}/eth/v1/validate-custody", self.url))
                .json(&request)
                .send()
                .await?
        )
        .json()
        .await?)
    }
}
