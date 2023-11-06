use std::sync::Arc;

pub struct SecureSignerClient {
    pub url: String,
    pub client: Arc<reqwest::Client>,
}

impl SecureSignerClient {
    pub async fn health(&self) -> bool {
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

    pub async fn list_eth_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        Ok(self
            .client
            .get(format!("{}/eth/v1/keygen/secp256k1", self.url))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn list_bls_keys(&self) -> anyhow::Result<crate::enclave::types::ListKeysResponse> {
        Ok(self
            .client
            .get(format!("{}/eth/v1/keystores", self.url))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn generate_eth_key(&self) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        Ok(self
            .client
            .post(format!("{}/eth/v1/keygen/secp256k1", self.url))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn generate_bls_key(&self) -> anyhow::Result<crate::enclave::types::KeyGenResponse> {
        Ok(self
            .client
            .post(format!("{}/eth/v1/keygen/bls", self.url))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn secure_sign_bls(
        &self,
        public_key_hex: &str,
        signing_data: crate::eth2::eth_signing::BLSSignMsg,
    ) -> anyhow::Result<crate::enclave::types::SignatureResponse> {
        Ok(self
            .client
            .post(format!("{}/api/v1/eth2/sign/{public_key_hex}", self.url))
            .json(&signing_data)
            .send()
            .await?
            .json()
            .await?)
    }
}
