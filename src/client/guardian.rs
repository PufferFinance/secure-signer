use std::sync::Arc;

use async_trait::async_trait;

use crate::client::traits::GuardianClientTrait;

pub struct GuardianClient {
    pub url: String,
    pub client: Arc<reqwest::Client>,
}

#[async_trait]
impl GuardianClientTrait for GuardianClient {
    async fn health(&self) -> bool {
        let Ok(resp) = self
            .client
            .get(format!("{}/upcheck", self.url))
            .send()
            .await
        else {
            return false;
        };
        resp.status() == reqwest::StatusCode::OK
    }

    async fn attest_fresh_eth_key(
        &self,
        blockhash: &str,
    ) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        let data = crate::enclave::guardian::KeygenWithBlockhashRequest {
            blockhash: blockhash.to_string(),
        };

        let resp = self
            .client
            .post(format!("{}/eth/v1/keygen", self.url))
            .json(&data)
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }

    async fn list_eth_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        let resp = self
            .client
            .get(format!("{}/eth/v1/keygen", self.url))
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }

    async fn validate_custody(
        &self,
        request: crate::enclave::types::ValidateCustodyRequest,
    ) -> anyhow::Result<crate::enclave::types::ValidateCustodyResponse> {
        let resp = self
            .client
            .post(format!("{}/guardian/v1/validate-custody", self.url))
            .json(&request)
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }

    async fn sign_exit(
        &self,
        request: crate::enclave::types::SignExitRequest,
    ) -> anyhow::Result<crate::enclave::types::SignExitResponse> {
        let resp = self
            .client
            .post(format!("{}/guardian/v1/sign-exit", self.url))
            .json(&request)
            .send()
            .await?;

        let resp_status = resp.status();
        if !resp_status.is_success() {
            let body = resp.text().await?;
            return Err(anyhow::anyhow!(body));
        }

        let resp_json = resp.json().await?;
        Ok(resp_json)
    }
}
