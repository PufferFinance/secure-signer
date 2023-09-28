use crate::enclave::types::KeyGenResponse;
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

    pub async fn attest_fresh_eth_key(&self, blockhash: &str) -> anyhow::Result<KeyGenResponse> {
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
}
