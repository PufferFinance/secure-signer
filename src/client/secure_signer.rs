use anyhow::anyhow;
use async_trait::async_trait;

#[derive(Debug)]
pub enum SecureSignerMethod {
    Health,
    GenerateEthKey,
    GenerateBlsKey,
    ListEthKeys,
    ListBlsKeys,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecureSignerResponse {
    Health(reqwest::StatusCode),
    GenerateEthKey(crate::enclave::types::KeyGenResponse),
    GenerateBlsKey(crate::enclave::types::KeyGenResponse),
    ListEthKeys(crate::enclave::types::ListKeysResponse),
    ListBlsKeys(crate::enclave::types::ListKeysResponse),
}

struct T {}
impl T {
    const TEST: &'static str = "asd";
}

#[async_trait]
impl super::Method for SecureSignerMethod {
    type Response = SecureSignerResponse;

    async fn handle<'a>(self, client: &'a super::Client) -> anyhow::Result<Self::Response> {
        let url = &client.secure_signer_url;
        match self {
            SecureSignerMethod::Health => {
                let status = client
                    .http_client
                    .get(format!("{}/health", url))
                    .send()
                    .await?
                    .status();
                Ok(SecureSignerResponse::Health(status))
            }
            SecureSignerMethod::ListEthKeys => {
                let resp: crate::enclave::types::ListKeysResponse = client
                    .http_client
                    .get(format!("{}/eth/v1/keygen/secp256k1", url))
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(SecureSignerResponse::ListEthKeys(resp))
            }
            SecureSignerMethod::ListBlsKeys => {
                let resp: crate::enclave::types::ListKeysResponse = client
                    .http_client
                    .get(format!("{}/eth/v1/keystores", url))
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(SecureSignerResponse::ListBlsKeys(resp))
            }
            SecureSignerMethod::GenerateEthKey => {
                let resp: crate::enclave::types::KeyGenResponse = client
                    .http_client
                    .post(format!("{}/eth/v1/keygen/secp256k1", url))
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(SecureSignerResponse::GenerateEthKey(resp))
            }
            SecureSignerMethod::GenerateBlsKey => {
                let resp: crate::enclave::types::KeyGenResponse = client
                    .http_client
                    .post(format!("{}/eth/v1/keygen/secp256k1", url))
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(SecureSignerResponse::GenerateBlsKey(resp))
            }
            //TODO: Remove this
            _ => Err(anyhow!("Failed to recognize the method")),
        }
    }
}
